const $ = (id) => document.getElementById(id);
const logEl = $('log');

const fmt = (n) => BigInt(n).toLocaleString('en-US');

function log(message, ok) {
  const li = document.createElement('li');
  li.className = ok ? 'ok' : 'bad';
  li.textContent = message;
  logEl.prepend(li);
}

function renderPolicy(state) {
  const p = state.policy;
  $('policy').innerHTML = `
    <dt>Min KYC</dt><dd>${p.minKycLevel}</dd>
    <dt>Sanctions</dt><dd>${p.requireSanctionsClear ? 'must be clear' : 'not required'}</dd>
    <dt>Min age</dt><dd>${p.minAge}+</dd>
    <dt>Blocked</dt><dd>${p.blockedCountries.join(', ') || 'none'}</dd>
  `;
}

function renderState(state) {
  const open = state.gate === 'open';
  $('gate').className = `gate ${state.gate}`;
  $('gate').textContent = open
    ? 'Gate open — isSessionVerified is true for this session'
    : 'Gate closed — prove a credential to swap';
  $('swap').disabled = !open;
  renderPolicy(state);
  $('stats').innerHTML = `
    <div class="stat"><span>Pool reserve A</span><strong>${fmt(state.reserves.A)}</strong></div>
    <div class="stat"><span>Pool reserve B</span><strong>${fmt(state.reserves.B)}</strong></div>
    <div class="stat"><span>Your demo A</span><strong>${fmt(state.balances.A)}</strong></div>
    <div class="stat"><span>Your demo B</span><strong>${fmt(state.balances.B)}</strong></div>
    <div class="stat"><span>Fills</span><strong>${fmt(state.swaps)}</strong></div>
    <div class="stat"><span>Admitted leaves</span><strong>${fmt(state.admittedLeaves)}</strong></div>
  `;
  if (state.session) {
    $('session').hidden = false;
    $('session').textContent = `session ${state.session.id}\nnullifier ${state.session.nullifier}\nprofile ${state.session.profile}${state.session.used ? '\n(used for a fill)' : ''}`;
  } else {
    $('session').hidden = true;
    $('session').textContent = '';
  }
}

async function api(path, opts) {
  const res = await fetch(path, opts);
  const body = await res.json();
  if (!res.ok) throw new Error(body.message || `HTTP ${res.status}`);
  return body;
}

async function refresh() {
  renderState(await api('/api/state'));
  await updateQuote();
}

async function updateQuote() {
  const amountIn = $('amount').value || '0';
  const aToB = $('side').value === 'aToB';
  const q = await api(`/api/quote?amountIn=${encodeURIComponent(amountIn)}&aToB=${aToB ? '1' : '0'}`);
  $('quote').textContent = q.amountOut == null ? `Quote: ${q.message}` : `Quote: ${fmt(q.amountOut)} ${aToB ? 'B' : 'A'} for ${fmt(q.amountIn)} ${aToB ? 'A' : 'B'}`;
}

async function prove(profile) {
  const r = await api('/api/prove', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ profile }) });
  renderState(r.state);
  await updateQuote();
  if (r.ok) log(`Verified session for ${r.state.profiles[r.profile]}. The swap is open.`, true);
  else log(`Proof failed (${r.profile}): ${r.message}`, false);
}

$('prove').addEventListener('click', () => prove('compliant'));
$('reset').addEventListener('click', async () => {
  renderState(await api('/api/reset', { method: 'POST' }));
  logEl.replaceChildren();
  log('Demo reset. The gate is closed again.', true);
  await updateQuote();
});
$('amount').addEventListener('input', updateQuote);
$('side').addEventListener('change', updateQuote);

$('swap-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const r = await api('/api/swap', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ amountIn: $('amount').value, aToB: $('side').value === 'aToB' }),
  });
  renderState(r.state);
  await updateQuote();
  if (r.ok) log(`Swapped ${fmt(r.amountIn)} ${r.aToB ? 'A' : 'B'} for ${fmt(r.amountOut)} ${r.aToB ? 'B' : 'A'}. The session is now used.`, true);
  else log(`Swap blocked: ${r.message}`, false);
});

$('bypass').addEventListener('click', async () => {
  const r = await api('/api/swap', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ amountIn: $('amount').value, aToB: $('side').value === 'aToB', skipSessionCheck: true, profile: 'compliant' }),
  });
  renderState(r.state);
  await updateQuote();
  if (r.ok) log(`On-chain swap succeeded without a ShieldPass session check (demo only). Prefer the off-chain + on-chain path.`, true);
  else log(`On-chain swap without a session was still blocked: ${r.message}`, false);
});

function renderProfileButtons(state) {
  const box = $('profiles');
  box.replaceChildren();
  for (const [id, label] of Object.entries(state.profiles)) {
    if (id === 'compliant') continue;
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'tiny';
    b.textContent = label;
    b.addEventListener('click', () => prove(id));
    box.append(b);
  }
}

const boot = await api('/api/state');
renderState(boot);
renderProfileButtons(boot);
await updateQuote();
