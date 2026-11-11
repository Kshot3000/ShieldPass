#!/usr/bin/env node
/**
 * Local demo server for the ShieldPass gated-swap. Serves the UI and runs the
 * Compact contracts in compact-runtime (no network, no wallet, no secrets).
 *
 *   pnpm demo
 *   open http://127.0.0.1:8787
 */
import { createServer } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createWorld } from './world.mjs';

const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), 'public');
const HOST = process.env.GATED_SWAP_HOST ?? '127.0.0.1';
const PORT = Number(process.env.GATED_SWAP_PORT ?? 8787);
const TYPES = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json' };

let world = createWorld();

function json(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}

async function readBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  if (!chunks.length) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (req.method === 'GET' && url.pathname === '/api/state') return json(res, 200, world.snapshot());
    if (req.method === 'GET' && url.pathname === '/api/quote') {
      const amountIn = BigInt(url.searchParams.get('amountIn') ?? '0');
      const aToB = url.searchParams.get('aToB') !== '0';
      try {
        return json(res, 200, { amountIn: String(amountIn), amountOut: String(world.quote(amountIn, aToB)), aToB });
      } catch (e) {
        return json(res, 200, { amountIn: String(amountIn), amountOut: null, aToB, message: String(e.message ?? e) });
      }
    }
    if (req.method === 'POST' && url.pathname === '/api/reset') {
      world = createWorld();
      return json(res, 200, world.snapshot());
    }
    if (req.method === 'POST' && url.pathname === '/api/prove') {
      const body = await readBody(req);
      const result = await world.prove(body.profile ?? 'compliant');
      return json(res, 200, { ...result, state: world.snapshot() });
    }
    if (req.method === 'POST' && url.pathname === '/api/swap') {
      const body = await readBody(req);
      const result = world.swap({
        amountIn: body.amountIn,
        aToB: body.aToB !== false && body.aToB !== 0 && body.aToB !== '0',
        minOut: body.minOut,
        skipSessionCheck: Boolean(body.skipSessionCheck),
        profile: body.profile,
      });
      return json(res, 200, { ...result, state: world.snapshot() });
    }

    const path = url.pathname === '/' ? '/index.html' : url.pathname;
    if (path.includes('..')) {
      res.writeHead(400);
      return res.end();
    }
    const file = join(ROOT, path);
    if (!existsSync(file)) {
      res.writeHead(404);
      return res.end('Not found');
    }
    res.writeHead(200, { 'content-type': TYPES[extname(file)] ?? 'application/octet-stream' });
    res.end(readFileSync(file));
  } catch (e) {
    json(res, 500, { ok: false, message: String(e && e.message ? e.message : e) });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`ShieldPass gated-swap demo at http://${HOST}:${PORT} (compact-runtime simulation, no network)`);
});
