/**
 * Constant-product quote used by the gated-swap demo and tests.
 * Matches the on-chain check: amountOut = reserveOut * amountIn / (reserveIn + amountIn)
 * (floor division). Compact 0.31 has no `/`, so the circuit verifies this via a witness.
 */
export function quote(reserveIn, reserveOut, amountIn) {
  const rin = BigInt(reserveIn);
  const rout = BigInt(reserveOut);
  const ain = BigInt(amountIn);
  if (ain <= 0n) throw new Error('zero input');
  if (rin <= 0n || rout <= 0n) throw new Error('empty pool');
  return (rout * ain) / (rin + ain);
}

export function quoteDiv(numer, denom) {
  const n = BigInt(numer);
  const d = BigInt(denom);
  if (d <= 0n) throw new Error('division by zero');
  return [n / d, n % d];
}
