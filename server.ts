// Minimal Wisp relay (v1 + v2) for Scramjet, targeting Deno Deploy.
//
// It multiplexes TCP streams over one WebSocket, following the Wisp protocol:
//   https://github.com/MercuryWorkshop/wisp-protocol
//
// Deploy (Deno Deploy): create a project, drop this file in as the entrypoint,
// and it listens on the platform port. Locally:
//     deno run --allow-net --allow-env server.ts
//
// Then set the Flask app's BROWSER_WISP_URL to the relay's wss:// URL, e.g.
//     BROWSER_WISP_URL=wss://my-relay.deno.dev/
//
// Heads-up: this is an open TCP proxy. It is intended to sit behind the
// login-gated /browser page. Set the WISP_TOKEN secret to require a token in
// the query string (?token=...) if you want to keep the URL private.

const WISP_TOKEN = Deno.env.get("WISP_TOKEN") ?? "";

const PACKET_CONNECT = 0x01;
const PACKET_DATA = 0x02;
const PACKET_CONTINUE = 0x03;
const PACKET_CLOSE = 0x04;
const PACKET_INFO = 0x05;

const STREAM_TCP = 0x01;

const CLOSE_VOLUNTARY = 0x02;
const CLOSE_NETWORK = 0x03;
const CLOSE_INVALID = 0x41;
const CLOSE_UNREACHABLE = 0x42;

const BUFFER_SIZE = 128;

const CONNECT_TIMEOUT_MS = 10000;

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("connect timeout")), ms);
    p.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}

// Deno.TcpConn.write may perform a short write (it resolves to the number of
// bytes actually written). A short write here would silently corrupt the
// upstream TCP stream and eventually surface as a broken pipe on the client, so
// loop until every byte is flushed.
async function writeAll(conn: Deno.TcpConn, data: Uint8Array): Promise<void> {
  let offset = 0;
  while (offset < data.length) {
    const n = await conn.write(data.subarray(offset));
    if (n === 0) throw new Error("tcp write returned 0");
    offset += n;
  }
}

function makePacket(type: number, streamId: number, payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(5 + payload.length);
  const view = new DataView(out.buffer);
  view.setUint8(0, type);
  view.setUint32(1, streamId >>> 0, true);
  if (payload.length) out.set(payload, 5);
  return out;
}

function continuePacket(streamId: number, remaining: number): Uint8Array {
  const p = new Uint8Array(4);
  new DataView(p.buffer).setUint32(0, remaining >>> 0, true);
  return makePacket(PACKET_CONTINUE, streamId, p);
}

function closePacket(streamId: number, reason: number): Uint8Array {
  return makePacket(PACKET_CLOSE, streamId, new Uint8Array([reason]));
}

function infoPacket(): Uint8Array {
  return makePacket(PACKET_INFO, 0, new Uint8Array([2, 0]));
}

const DIAG_HOSTS = [
  "www.google.com",
  "www.bing.com",
  "play.geforcenow.com",
  "pcs.geforcenow.com",
  "github.com",
];

// GET /diag — attempts outbound TCP connects from *this* Deno Deploy region so we
// can tell whether the relay's egress can reach a host (both via hostname and via
// the host's first IPv4 address). Useful when a client fails with a 10s connect
// timeout that the relay itself cannot reproduce from other regions.
async function diagConnect(hostname: string, port: number, viaIp: boolean) {
  const t0 = Date.now();
  try {
    let target = hostname;
    let via = "hostname";
    if (viaIp) {
      const a = await Deno.resolveDns(hostname, "A").catch(() => [] as string[]);
      if (!a.length) return { via: "ipv4", ok: false, ms: Date.now() - t0, err: "no A record" };
      target = a[0];
      via = `ipv4:${target}`;
    }
    const conn = await withTimeout(Deno.connect({ hostname: target, port }), 8000);
    try {
      conn.close();
    } catch {
      // ignore
    }
    return { via, ok: true, ms: Date.now() - t0 };
  } catch (e) {
    return { via: viaIp ? "ipv4" : "hostname", ok: false, ms: Date.now() - t0, err: String((e as Error)?.message ?? e) };
  }
}

async function diagResponse(url: URL): Promise<Response> {
  const one = url.searchParams.get("host");
  const hosts = one ? [one] : DIAG_HOSTS;
  const out: Record<string, unknown> = {};
  await Promise.all(hosts.map(async (h) => {
    out[h] = await Promise.all([
      diagConnect(h, 443, false),
      diagConnect(h, 443, true),
    ]);
  }));
  out["_region"] = Deno.env.get("DENO_REGION") ?? Deno.env.get("DENO_DEPLOYMENT_ID") ?? "unknown";
  return new Response(JSON.stringify(out, null, 2), {
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

interface Stream {
  id: number;
  conn?: Deno.TcpConn;
  queue: Uint8Array[];
  writing: boolean;
  closed: boolean;
  sent: number;
}

Deno.serve(async (req: Request): Promise<Response> => {
  const url = new URL(req.url);
  if (req.headers.get("upgrade")?.toLowerCase() !== "websocket") {
    if (url.pathname === "/diag") return await diagResponse(url);
    return new Response("Wisp relay is running.\n", { status: 200 });
  }
  if (WISP_TOKEN) {
    const token = url.searchParams.get("token");
    if (token !== WISP_TOKEN) return new Response("Forbidden", { status: 403 });
  }

  // wisp-js sends a Sec-WebSocket-Protocol header to negotiate wisp v2.
  const requested = req.headers.get("sec-websocket-protocol");
  const options: Deno.UpgradeWebSocketOptions = {};
  if (requested) options.protocol = requested.split(",")[0].trim();
  const { socket, response } = Deno.upgradeWebSocket(req, options);
  handleSocket(socket, Boolean(requested));
  return response;
});

function handleSocket(ws: WebSocket, isV2: boolean) {
  const streams = new Map<number, Stream>();
  let handshakeDone = false;

  (ws as unknown as { binaryType: string }).binaryType = "arraybuffer";

  const send = (data: Uint8Array) => {
    if (ws.readyState === WebSocket.OPEN) ws.send(data);
  };

  ws.onopen = () => {
    if (isV2) {
      send(infoPacket());
    } else {
      send(continuePacket(0, BUFFER_SIZE));
      handshakeDone = true;
    }
  };

  ws.onmessage = (event: MessageEvent) => {
    const data = event.data;
    if (typeof data === "string") return;
    const bytes = data instanceof ArrayBuffer
      ? new Uint8Array(data)
      : new Uint8Array((data as Uint8Array).buffer);
    route(bytes);
  };

  ws.onclose = () => {
    for (const s of streams.values()) closeStream(s, false);
    streams.clear();
  };

  // Each WebSocket message carries a single Wisp packet (as produced by the
  // wisp-js client). DATA payloads consume the rest of the frame, so per-message
  // parsing is unambiguous.
  function route(buf: Uint8Array) {
    if (buf.length < 5) return;
    const view = new DataView(buf.buffer, buf.byteOffset, buf.length);
    const type = view.getUint8(0);
    const streamId = view.getUint32(1, true);
    const payload = buf.subarray(5);
    handlePacket(type, streamId, payload);
  }

  function handlePacket(type: number, streamId: number, payload: Uint8Array) {
    if (type === PACKET_INFO) {
      if (isV2 && !handshakeDone) {
        send(continuePacket(0, BUFFER_SIZE));
        handshakeDone = true;
      }
      return;
    }
    if (type === PACKET_CONNECT) {
      if (payload.length < 3) {
        send(closePacket(streamId, CLOSE_INVALID));
        return;
      }
      const streamType = payload[0];
      const port = new DataView(payload.buffer, payload.byteOffset).getUint16(1, true);
      const hostname = new TextDecoder().decode(payload.subarray(3));
      void connectStream(streamId, streamType, hostname, port);
    } else if (type === PACKET_DATA) {
      const s = streams.get(streamId);
      if (s) {
        s.queue.push(payload.slice());
        void pump(s);
      }
    } else if (type === PACKET_CLOSE) {
      const s = streams.get(streamId);
      if (s) closeStream(s, false);
    }
  }

  async function connectStream(
    streamId: number,
    streamType: number,
    hostname: string,
    port: number,
  ) {
    if (streamType !== STREAM_TCP) {
      send(closePacket(streamId, CLOSE_INVALID));
      return;
    }
    const s: Stream = { id: streamId, queue: [], writing: false, closed: false, sent: 0 };
    streams.set(streamId, s);
    try {
      const conn = await withTimeout(Deno.connect({ hostname, port }), CONNECT_TIMEOUT_MS);
      if (s.closed) {
        conn.close();
        return;
      }
      s.conn = conn;
      // DATA may have arrived while the TCP connect was pending; drain it now.
      void pump(s);
      void readLoop(s);
    } catch (e) {
      console.error(`[wisp] connect ${hostname}:${port} failed: ${(e as Error)?.message ?? e}`);
      streams.delete(streamId);
      send(closePacket(streamId, CLOSE_UNREACHABLE));
    }
  }

  async function readLoop(s: Stream) {
    const conn = s.conn!;
    const buf = new Uint8Array(64 * 1024);
    try {
      while (!s.closed) {
        const n = await conn.read(buf);
        if (n === null) break;
        send(makePacket(PACKET_DATA, s.id, buf.slice(0, n)));
      }
      send(closePacket(s.id, CLOSE_VOLUNTARY));
    } catch (e) {
      console.error(`[wisp] read ${s.id} failed: ${(e as Error)?.message ?? e}`);
      send(closePacket(s.id, CLOSE_NETWORK));
    } finally {
      closeStream(s, false);
    }
  }

  async function pump(s: Stream) {
    if (s.writing) return;
    s.writing = true;
    try {
      while (s.queue.length && !s.closed) {
        // Check the connection BEFORE removing the chunk: early DATA (e.g. the
        // client's TLS ClientHello) can arrive while the TCP connect is still
        // pending. If we shifted first we would drop that data forever.
        if (!s.conn) break;
        const chunk = s.queue.shift()!;
        await writeAll(s.conn, chunk);
        s.sent++;
        // Wisp flow control: the client *sets* its per-stream send budget to the
        // value we send (it does not add it), and it never sends CONTINUE back
        // for the server->client direction. So we grant budget as our queue
        // drains: this replenishes the client's allowance and applies
        // backpressure when the outbound TCP socket falls behind.
        const remaining = Math.max(0, BUFFER_SIZE - s.queue.length);
        send(continuePacket(s.id, remaining));
      }
    } catch (e) {
      console.error(`[wisp] write ${s.id} failed: ${(e as Error)?.message ?? e}`);
      send(closePacket(s.id, CLOSE_NETWORK));
      closeStream(s, false);
    } finally {
      s.writing = false;
    }
  }

  function closeStream(s: Stream, notify: boolean) {
    if (s.closed) return;
    s.closed = true;
    streams.delete(s.id);
    try {
      s.conn?.close();
    } catch {
      // already closed
    }
    if (notify) send(closePacket(s.id, CLOSE_VOLUNTARY));
  }
}
