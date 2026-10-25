// Cloudflare Worker: VLESS -> TCP (Cloudflare Sockets)
// Dua jalur, token = UUID VLESS di bawah (jangan dibagikan):
//  1) WebSocket (jalur standar, untuk klien langsung tanpa proxy MITM)
//  2) POST HTTP (jalur XHTTP stream-one, untuk Xray di VM yang lewat proxy Hatch:
//     proxy itu mengubah Connection: Upgrade menjadi close sehingga handshake WS ditolak,
//     sedangkan POST HTTP biasa diteruskan dengan benar)
// Batasan v1: hanya TCP. UDP tidak lewat Worker ini; DNS di VM tetap lewat TCP DNS.
// Batasan Sockets: koneksi langsung ke IP Cloudflare (104.x) diblokir runtime Worker;
// tujuan utama (Google/YouTube/dll, bukan Cloudflare) tidak kena batasan ini.
const UUID = "b453a35b-95c4-4dc7-835c-0b3753e2bbf1";

function uuidToBytes(s) {
  const h = s.replace(/-/g, '');
  const b = new Uint8Array(16);
  for (let i = 0; i < 16; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return b;
}
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < 16; i++) if (a[i] !== b[i]) return false;
  return true;
}
// Parse header VLESS dari buffer. Kembalikan null kalau buffer belum cukup,
// atau objek {headerLen, command, port, host, firstPayload} kalau sudah lengkap.
function parseVless(buf, want) {
  if (buf.length < 18) return null;
  if (buf[0] !== 0) return null;
  if (!bytesEqual(buf.slice(1, 17), want)) return null;
  const addonLen = buf[17];
  let off = 18 + addonLen;
  if (buf.length < off + 4) return null;
  const cmd = buf[off]; off += 1;
  if (cmd !== 1) return null; // hanya TCP di v1
  const port = (buf[off] << 8) | buf[off + 1]; off += 2;
  const atype = buf[off]; off += 1;
  let host = '';
  if (atype === 1) {
    if (buf.length < off + 4) return null;
    host = Array.from(buf.slice(off, off + 4)).join('.'); off += 4;
  } else if (atype === 2) {
    if (buf.length < off + 1) return null;
    const n = buf[off]; off += 1;
    if (buf.length < off + n) return null;
    host = new TextDecoder().decode(buf.slice(off, off + n)); off += n;
  } else if (atype === 3) {
    if (buf.length < off + 16) return null;
    const p = [];
    for (let i = 0; i < 16; i += 2) p.push(buf.slice(off + i, off + i + 2).reduce((a, v) => a * 256 + v, 0).toString(16));
    host = p.join(':'); off += 16;
  } else return null;
  return { headerLen: off, command: cmd, port, host, firstPayload: buf.slice(off) };
}
// Strip framing gRPC (5 byte: 0 + BE length) kalau chunk diawali frame gRPC yang valid,
// kalau tidak, kembalikan chunk apa adanya (mode raw).
function stripGrpcFrames(chunk) {
  const out = [];
  let i = 0;
  while (i + 5 <= chunk.length) {
    if (chunk[i] === 0 && chunk[i + 1] === 0 && chunk[i + 2] === 0 && chunk[i + 3] === 0) {
      const len = chunk[i + 4];
      if (len > 0 && i + 5 + len <= chunk.length) {
        out.push(chunk.slice(i + 5, i + 5 + len));
        i += 5 + len;
        continue;
      }
    }
    break;
  }
  if (i === 0) return chunk;
  const rest = chunk.slice(i);
  const total = out.reduce((a, v) => a + v.length, 0) + rest.length;
  const merged = new Uint8Array(total);
  let o = 0;
  for (const p of out) { merged.set(p, o); o += p.length; }
  merged.set(rest, o);
  return merged;
}
function wrapGrpcFrame(data) {
  const out = new Uint8Array(data.length + 5);
  out[0] = 0; out[1] = 0; out[2] = 0; out[3] = 0; out[4] = data.length > 255 ? 255 : data.length;
  // NB: frame >255 byte tidak dipakai di jalur ini karena chunk TCP dipecah kecil oleh runtime;
  // kalau data lebih besar, pemanggil memotongnya dulu.
  out.set(data.length > 255 ? data.slice(0, 255) : data, 5);
  return out;
}


async function resolveIP(host) {
  try {
    const r = await fetch('https://dns.google/resolve?name=' + encodeURIComponent(host) + '&type=A');
    const j = await r.json();
    if (!j.Answer) return null;
    for (const a of j.Answer) {
      if (a.type === 1 && typeof a.data === 'string') {
        const ip = a.data;
        // Lewati IP Cloudflare (sockets ke IP Cloudflare diblokir runtime)
        if (ip.startsWith('104.') || ip.startsWith('172.64.') || ip.startsWith('172.65.') || ip.startsWith('172.66.') || ip.startsWith('172.67.') || ip.startsWith('173.245.')) continue;
        return ip;
      }
    }
  } catch {}
  return null;
}
async function connectWithFallback(connect, host, port) {
  let lastErr = null;
  try {
    const s = connect({ hostname: host, port });
    await s.opened;
    return s;
  } catch (e) { lastErr = e; }
  // Fallback: resolve hostname ke IP, konek langsung ke IP (server tujuan tetap lihat SNI dari payload TLS klien)
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    const ip = await resolveIP(host);
    if (ip) {
      try {
        const s2 = connect({ hostname: ip, port });
        await s2.opened;
        return s2;
      } catch (e2) { lastErr = e2; }
    }
  }
  throw lastErr || new Error('connect failed');
}

export default {
  async fetch(request) {
    try {
      const u = new URL(request.url);
      if (u.pathname === '/__test2__') {
        const { connect } = await import('cloudflare:sockets');
        const targets = [
          { name: 'example.com:443', host: 'example.com', port: 443 },
          { name: 'www.google.com:443', host: 'www.google.com', port: 443 },
          { name: '1.1.1.1:443', host: '1.1.1.1', port: 443 },
          { name: '8.8.8.8:53', host: '8.8.8.8', port: 53 },
        ];
        const lines = [];
        for (const t of targets) {
          try {
            const s = connect({ hostname: t.host, port: t.port });
            await s.opened;
            try { s.close(); } catch {}
            lines.push(t.name + ': ok');
          } catch (e) {
            lines.push(t.name + ': fail: ' + (e && e.message ? String(e.message).slice(0, 100) : 'unknown'));
          }
        }
        return new Response(lines.join('\n'), { status: 200 });
      }
      if (u.pathname === '/__test__') {
        try {
          const { connect } = await import('cloudflare:sockets');
          const s = connect({ hostname: 'example.com', port: 443 });
          await s.opened;
          try { s.close(); } catch {}
          return new Response('sockets ok (443 opened, no data sent)', { status: 200 });
        } catch (e) {
          return new Response('sockets fail: ' + (e && e.message ? e.message : String(e)), { status: 500 });
        }
      }
    } catch {}

    const upgrade = request.headers.get('Upgrade');
    if (upgrade && upgrade.toLowerCase() === 'websocket') {
      const [client, server] = Object.values(new WebSocketPair());
      server.accept();
      handleWsSession(server).catch(() => { try { server.close(); } catch {} });
      return new Response(null, { status: 101, webSocket: client });
    }
    if (request.method === 'POST') {
      return handleHttpSession(request);
    }
    return new Response('Not a WebSocket request', { status: 404 });
  }
};

async function handleWsSession(ws) {
  const want = uuidToBytes(UUID);
  let tcp = null, writer = null, connected = false, closed = false;
  const closeAll = () => {
    if (closed) return; closed = true;
    try { writer && writer.releaseLock(); } catch {}
    try { tcp && tcp.close(); } catch {}
    try { ws.close(); } catch {}
  };
  ws.addEventListener('close', closeAll);
  ws.addEventListener('error', closeAll);
  ws.addEventListener('message', async (event) => {
    if (closed) return;
    const data = event.data instanceof ArrayBuffer ? new Uint8Array(event.data) : new Uint8Array(await event.data.arrayBuffer());
    if (!connected) {
      console.log('ws first msg len ' + data.length);
      try {
        const h = parseVless(data, want);
        if (!h) { console.error('ws vless parse fail'); closeAll(); return; }
        const { connect } = await import('cloudflare:sockets');
        try { tcp = await connectWithFallback(connect, h.host.replace(/^\[|\]$/g, ''), h.port); console.log('ws connected to ' + h.host + ':' + h.port); } catch (ce) { console.error('ws connect fail ' + h.host + ':' + h.port + ' ' + (ce && ce.message ? String(ce.message).slice(0,120) : 'unknown')); throw ce; }
        writer = tcp.writable.getWriter();
        connected = true;
        const reader = tcp.readable.getReader();
        (async () => {
          try {
            while (true) {
              const r = await reader.read();
              if (r.done || closed) break;
              try { ws.send(r.value); } catch { break; }
            }
          } catch {} finally { closeAll(); }
        })();
        if (h.firstPayload.length) await writer.write(h.firstPayload);
      } catch { closeAll(); }
      return;
    }
    try { await writer.write(data); } catch { closeAll(); }
  });
}

async function handleHttpSession(request) {
  const want = uuidToBytes(UUID);
  if (!request.body) return new Response('empty body', { status: 400 });
  const reader = request.body.getReader();
  let raw = new Uint8Array(0);
  let header = null;
  let vlessBuf = null; // buffer VLESS setelah strip frame gRPC (kalau ada)
  // Fungsi: dari raw buffer, coba ekstrak buffer VLESS (strip 1 frame gRPC kalau lengkap,
  // kalau frame belum lengkap, kembalikan null = tunggu data lagi; kalau bukan frame gRPC, pakai raw apa adanya)
  const extractVlessBuf = (r) => {
    if (r.length >= 5 && r[0] === 0 && r[1] === 0 && r[2] === 0 && r[3] === 0) {
      const len = (r[4] | 0);
      // Frame gRPC valid hanya kalau panjangnya masuk akal dan frame-nya lengkap atau
      // setidaknya header VLESS sudah lengkap di dalam frame (frame bisa lebih panjang dari chunk pertama)
      if (len > 0 && r.length >= 5 + len) return r.slice(5);
      if (len > 0 && r.length >= 5 + 18) {
        // Frame belum lengkap tapi VLESS header sudah ada di dalamnya: strip header frame saja
        return r.slice(5);
      }
      return null; // frame belum lengkap, tunggu data lagi
    }
    return r;
  };
  while (!header) {
    const r = await reader.read();
    if (r.done) return new Response('incomplete vless header', { status: 400 });
    const merged = new Uint8Array(raw.length + r.value.length);
    merged.set(raw, 0); merged.set(r.value, raw.length); raw = merged;
    const vb = extractVlessBuf(raw);
    if (vb === null) continue;
    vlessBuf = vb;
    const h = parseVless(vlessBuf, want);
    if (h) header = h;
    else if (vlessBuf.length > 2048) return new Response('bad vless header', { status: 403 });
    // kalau belum cukup, loop baca chunk berikutnya (raw tetap terakumulasi, extract diulang)
  }
  let tcp;
  try {
    const { connect } = await import('cloudflare:sockets');
    tcp = await connectWithFallback(connect, header.host.replace(/^\[|\]$/g, ''), header.port);
  } catch { return new Response('connect failed', { status: 502 }); }
  const writer = tcp.writable.getWriter();
  const grpcMode = request.headers.get('Content-Type') === 'application/grpc';
  // Sisa buffer VLESS setelah header (firstPayload) + sisa raw yang belum diproses:
  // raw sudah termasuk frame gRPC pertama; firstPayload dari parse adalah data setelah header VLESS.
  // Untuk arah naik berikutnya, kita proses chunk baru dengan strip frame yang sama (akumulasi).
  let pending = new Uint8Array(0);
  (async () => {
    try {
      if (header.firstPayload.length) await writer.write(header.firstPayload);
      while (true) {
        const r = await reader.read();
        if (r.done) break;
        const merged = new Uint8Array(pending.length + r.value.length);
        merged.set(pending, 0); merged.set(r.value, pending.length); pending = merged;
        // Strip frame gRPC lengkap dari pending, tulis payload-nya; simpan sisa frame tak lengkap
        let out = new Uint8Array(0);
        let rest = pending;
        if (grpcMode) {
          let buf2 = pending;
          let collected = [];
          let total = 0;
          while (buf2.length >= 5 && buf2[0] === 0 && buf2[1] === 0 && buf2[2] === 0 && buf2[3] === 0) {
            const len = buf2[4];
            if (buf2.length < 5 + len) break;
            collected.push(buf2.slice(5, 5 + len)); total += len; buf2 = buf2.slice(5 + len);
          }
          if (collected.length) {
            out = new Uint8Array(total);
            let o = 0; for (const c of collected) { out.set(c, o); o += c.length; }
          }
          rest = buf2;
          // Kalau pending diawali frame tak lengkap, jangan tulis apa-apa dulu, tunggu chunk berikutnya
          if (!collected.length && buf2.length >= 5 && buf2[0] === 0 && buf2[1] === 0 && buf2[2] === 0 && buf2[3] === 0) {
            pending = buf2; continue;
          }
          if (collected.length) pending = rest;
          else { out = pending; pending = new Uint8Array(0); }
        } else { out = pending; pending = new Uint8Array(0); }
        if (out.length) await writer.write(out);
      }
      try { await writer.close(); } catch {}
    } catch { try { tcp.close(); } catch {} }
  })();
  const tcpReader = tcp.readable.getReader();
  const body = new ReadableStream({
    async pull(controller) {
      try {
        const r = await tcpReader.read();
        if (r.done) { controller.close(); return; }
        let data = r.value;
        if (grpcMode) {
          for (let i = 0; i < data.length; i += 255) controller.enqueue(wrapGrpcFrame(data.slice(i, i + 255)));
        } else {
          controller.enqueue(data);
        }
      } catch { try { controller.close(); } catch {} }
    },
    cancel() { try { tcp.close(); } catch {} }
  });
  return new Response(body, {
    status: 200,
    headers: { 'Content-Type': grpcMode ? 'application/grpc' : 'application/octet-stream', 'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no' }
  });
}
