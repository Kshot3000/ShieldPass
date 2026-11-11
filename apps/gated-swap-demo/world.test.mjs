import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createWorld, POOL_A, POOL_B, START_A, quote } from './world.mjs';

const NOW = 1_792_000_000n;

test('compliant holder proves a ShieldPass session and the swap fills at the constant-product quote', async () => {
  const w = createWorld(NOW);
  const proved = await w.prove('compliant');
  assert.equal(proved.ok, true);
  assert.equal(w.snapshot().gate, 'open');
  assert.match(proved.session.id, /^[0-9a-f]{64}$/);
  const amountIn = 1_000n;
  const expected = quote(POOL_A, POOL_B, amountIn);
  const fill = w.swap({ amountIn, aToB: true });
  assert.equal(fill.ok, true);
  assert.equal(fill.amountOut, String(expected));
  const s = w.snapshot();
  assert.equal(s.reserves.A, String(POOL_A + amountIn));
  assert.equal(s.reserves.B, String(POOL_B - expected));
  assert.equal(s.balances.A, String(START_A - amountIn));
  assert.equal(s.balances.B, String(expected));
  assert.equal(s.swaps, '1');
  assert.equal(s.gate, 'closed', 'the session is consumed after the fill');
});

test('the off-chain gate stays closed without a proof, and failing profiles cannot prove', async () => {
  const w = createWorld(NOW);
  const blocked = w.swap({ amountIn: 100n });
  assert.equal(blocked.ok, false);
  assert.match(blocked.message, /isSessionVerified is false|Prove a ShieldPass/);
  for (const profile of ['underage', 'blocked', 'expired', 'unscreened']) {
    const r = await w.prove(profile);
    assert.equal(r.ok, false, profile);
    assert.ok(r.message, profile);
    assert.equal(w.snapshot().gate, 'closed');
  }
});

test('a failing credential is also rejected on-chain even if the off-chain session check is skipped', async () => {
  const w = createWorld(NOW);
  const r = w.swap({ amountIn: 100n, skipSessionCheck: true, profile: 'underage' });
  assert.equal(r.ok, false);
  assert.match(r.message, /below minimum age/);
});
