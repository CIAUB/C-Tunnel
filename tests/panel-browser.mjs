import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_PATH || 'playwright');
const html = await readFile(new URL('../pkg/webpanel/index.html', import.meta.url), 'utf8');
const hash = tag => "'sha256-" + createHash('sha256').update(html.split(`<${tag}>`)[1].split(`</${tag}>`)[0].replace(/\r\n?/g, '\n')).digest('base64') + "'";
const fixtureCode = 'local-browser-fixture';
let state;
function reset() { state = { path: '/panel-browser-test', tunnels: [], createCalls: 0, deployCalls: 0, restartCalls: 0, updateCalls: 0, failStart: false, lastCreate: null, lastUpdate: null, listener: false, jobStarted: false }; }
reset();
const config = () => ({ base_path: state.path, domain: '', cert_file: '', key_file: '' });
const overview = () => ({ csrf_token: 'fixture-csrf', version: '0.2.5', panel: config(), methods: [
 { Name: 'gre', Title: 'Kernel GRE', Family: 'L3-Direct', IPv6Underlay: false },
 { Name: 'dtls-1.3', Title: 'Encrypted UDP', Family: 'UDP-Crypt', IPv6Underlay: false }
], system: { hostname: 'edge-01', os: 'Ubuntu 24.04 LTS', ipv4: '198.51.100.10', ipv6: '', uptime_sec: 281520, cores: 8, cpu_pct: 18, mem_total: 8589934592, mem_used: 2147483648, disk_total: 85899345920, disk_used: 12884901888, swap_total: 0, swap_used: 0, rx_rate: 7864320, tx_rate: 4194304, rx_total: 120259084288, tx_total: 75161927680, load: [0.4, 0.5, 0.3] }, tunnels: state.tunnels });
const makeTunnel = payload => ({ ...payload, name: 't' + (state.tunnels.length + 1), method: payload.method || 'gre', role: payload.role || 'iran', remote_ip: payload.remote_ip || '203.0.113.8', tun_local4: '10.77.1.1', tun_remote4: '10.77.1.2', token: 'fixture-token', setup_link: 'ctunnel://fixture', ports: payload.ports || [], state: 'up', status: { rx_bytes: 1048576, tx_bytes: 524288 }, mikrotik: '' });
const directResult = { method: 'gre', family: 'L3-Direct', mode: 'DIRECT', sent: 10, received: 10, rtt_ms: 4, jitter_ms: 1.2, down_mbps: 200, up_mbps: 180 };
const reverseResult = { method: 'rev+dtls-1.3', family: 'UDP-Crypt', mode: 'REVERSE', sent: 10, received: 10, rtt_ms: 6, jitter_ms: 2, down_mbps: 120, up_mbps: 110 };
const sessionName = host => state.legacyCookie ? 'ct_session' : 'ct_session_v2_' + createHash('sha256').update('http|' + host.toLowerCase() + '|' + state.path).digest('hex').slice(0, 24);
const server = createServer(async (req, res) => {
 try {
  const prefix = state.path;
  const send = (status, data) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(data)); };
  if (req.method === 'GET' && req.url === prefix + '/') {
   res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Security-Policy': `default-src 'none'; script-src ${hash('script')}; style-src ${hash('style')}; connect-src 'self'; img-src 'self' data:; base-uri 'none'` }); res.end(html); return;
  }
  if (!req.url.startsWith(prefix + '/api/')) { send(404, {}); return; }
  let raw = ''; for await (const b of req) raw += b;
  const body = raw ? JSON.parse(raw) : {};
  const route = req.url.slice(prefix.length);
  if (route === '/api/login') {
   if (body.code !== fixtureCode) { send(401, { error: 'Wrong login code' }); return; }
   res.setHeader('Set-Cookie', `${sessionName(req.headers.host)}=fixture; Path=${prefix}/; HttpOnly; SameSite=Strict`); send(200, { ok: true }); setTimeout(() => state.releaseOverview?.(), 100); return;
  }
  if (route === '/api/overview' && state.holdOverview) {
   state.holdOverview = false; state.onOverviewHeld();
   await new Promise(resolve => { state.releaseOverview = resolve; });
  }
  if (!req.headers.cookie?.split('; ').includes(sessionName(req.headers.host) + '=fixture')) { send(401, { error: 'unauthorized' }); return; }
  if (req.method !== 'GET' && req.headers['x-csrf-token'] !== 'fixture-csrf') { send(403, { error: 'invalid CSRF token' }); return; }
  if (route === '/api/overview') { send(200, overview()); return; }
  if (route === '/api/tunnels') {
   state.createCalls++; state.lastCreate = body;
   const tunnel = makeTunnel(body); state.tunnels.push(tunnel);
   send(200, { ...tunnel, ok: !state.failStart, error: state.failStart ? 'Saved, but starting failed' : undefined }); return;
  }
  if (route === '/api/tunnels/t1' && req.method === 'PUT') {
   state.updateCalls++; state.lastUpdate = body;
   const tunnel = state.tunnels[0]; Object.assign(tunnel, body, { name: 't1' });
   send(200, { ...tunnel, ok: true }); return;
  }
  if (route === '/api/tunnels/t1/restart') { state.restartCalls++; send(200, { ok: true }); return; }
  if (route === '/api/linktest/server/start' && req.method === 'POST') {
   state.listener = true;
   send(200, { active: true, link: 'ctunnel-test://fixture-link', host: '127.0.0.1', udp_port: 7712, tcp_port: 7711, raw_open: [4, 41, 47, 50, 97, 115], expires_at: new Date(Date.now() + 900000).toISOString(), rows: [] }); return;
  }
  if (route === '/api/linktest/server' && req.method === 'GET') {
   send(200, state.listener ? { active: true, link: 'ctunnel-test://fixture-link', host: '127.0.0.1', udp_port: 7712, tcp_port: 7711, raw_open: [4, 41, 47, 50, 97, 115], expires_at: new Date(Date.now() + 900000).toISOString(), rows: [directResult, reverseResult], report_text: 'FIXTURE VERDICT\\nDIRECT gre 200 Mbps' } : { active: false }); return;
  }
  if (route === '/api/linktest/server/stop' && req.method === 'POST') { state.listener = false; send(200, { ok: true }); return; }
  if (route === '/api/linktest/jobs' && req.method === 'POST') { state.jobStarted = true; send(202, { test_id: 'fixture-job', status: 'running' }); return; }
  if (route === '/api/linktest/jobs/fixture-job' && req.method === 'GET') {
   send(200, {
    test_id: 'fixture-job', status: 'done', rows: [directResult, reverseResult], text: 'DIRECT gre 200 Mbps\\nREVERSE rev+dtls-1.3 120 Mbps',
    best: directResult, best_settings: { method: 'gre', mode: 'DIRECT', path_mtu: 1500, tunnel_mtu: 1440, rtt_ms: 4, down_mbps: 200, up_mbps: 180 },
    deployments: { direct: { test_id: 'fixture-direct', best: directResult }, reverse: { test_id: 'fixture-reverse', best: reverseResult } }, error: ''
   }); return;
  }
  if (route === '/api/linktest') {
   send(200, { text: 'REVERSE frp+gre 8.0 ms 0% loss', deployment_available: true, test_id: 'fixture-measurement', best: { method: 'frp+gre', mode: 'REVERSE', rtt_ms: 8, down_mbps: 150, up_mbps: 120 } }); return;
  }
  if (route === '/api/deploy-best') {
   assert.ok(['fixture-direct', 'fixture-reverse'].includes(body.test_id)); state.deployCalls++;
   const tunnel = makeTunnel({ method: body.test_id === 'fixture-reverse' ? 'dtls-1.3' : 'gre', reverse: body.test_id === 'fixture-reverse' }); state.tunnels.push(tunnel); send(200, { ...tunnel, ok: true }); return;
  }
  if (route === '/api/settings' && req.method === 'GET') { send(200, config()); return; }
  if (route === '/api/settings') {
   assert.equal(body.tls_mode, 'http'); state.path = body.base_path;
   send(200, { ok: true, config: config(), url: `http://${req.headers.host}${state.path}/` }); return;
  }
  send(404, {});
 } catch (err) { res.writeHead(500); res.end(JSON.stringify({ error: err.message })); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const port = server.address().port;
await mkdir('test-results', { recursive: true });
const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || undefined, args: ['--host-resolver-rules=MAP panel.test 127.0.0.1', '--no-proxy-server'] });
async function login(page, race = false) {
 await page.goto(`http://panel.test:${port}${state.path}/`);
 await page.getByLabel('Login code', { exact: true }).fill(fixtureCode);
 if (race) {
  const held = new Promise(resolve => { state.onOverviewHeld = resolve; });
  state.holdOverview = true;
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
  await Promise.race([held, new Promise((_, reject) => setTimeout(() => reject(new Error('overview was not held')), 5000))]);
 }
 await page.getByRole('button', { name: 'Log in', exact: true }).click();
 await page.getByRole('button', { name: 'New tunnel', exact: true }).waitFor();
}
const errors = [];
try {
 const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
 page.on('pageerror', err => errors.push(err.message));
 // Reproduce the legacy Secure-cookie collision on a non-loopback hostname.
 await page.context().addCookies([{ name: 'ct_session', value: 'old-secure-session', domain: 'panel.test', path: '/', secure: true, httpOnly: true, sameSite: 'Strict' }]);
 state.legacyCookie = true;
 await page.goto(`http://panel.test:${port}${state.path}/`);
 await page.getByLabel('Login code', { exact: true }).fill(fixtureCode);
 await page.getByRole('button', { name: 'Log in', exact: true }).click();
 await page.locator('#toast').filter({ hasText: 'Session expired' }).waitFor({ state: 'visible' });
 assert.equal(await page.getByRole('button', { name: 'New tunnel', exact: true }).isVisible(), false);
 state.legacyCookie = false;
 // Login must succeed with that cookie still present and a stale overview in flight.
 await login(page, true);
 await page.getByRole('button', { name: 'Settings', exact: true }).click();
 const menu = page.locator('#menu'); await menu.waitFor({ state: 'visible' });
 assert.equal(await menu.evaluate(e => { const r = e.getBoundingClientRect(); return e.contains(document.elementFromPoint(r.left + 20, r.top + 20)); }), true);
 await page.screenshot({ path: 'test-results/panel-settings.png', fullPage: true });
 await page.keyboard.press('Escape');
 await page.getByRole('button', { name: 'New tunnel', exact: true }).click();
 await page.getByLabel('Remote server IP', { exact: true }).fill('203.0.113.8');
 await page.locator('#dlg-new summary').click();
 await page.getByLabel('MTU', { exact: true }).fill('1');
 await page.locator('#create-form [type=submit]').click();
 await page.locator('#create-error').waitFor({ state: 'visible' }); assert.equal(state.createCalls, 0);
 await page.getByLabel('MTU', { exact: true }).fill('1400');
 await page.locator('#create-form [type=submit]').click();
 await page.locator('#dlg-link').waitFor({ state: 'visible' });
 assert.equal(state.createCalls, 1); assert.equal(state.lastCreate.mtu, 1400); assert.equal(state.lastCreate.remote_ip, '203.0.113.8');
 await page.locator('#dlg-link [data-close]').click();
 await page.getByRole('button', { name: 'Edit', exact: true }).click();
 await page.getByLabel('MTU', { exact: true }).fill('1300');
 await page.locator('#create-form [type=submit]').click();
 await page.locator('#dlg-link').waitFor({ state: 'visible' });
 assert.equal(state.updateCalls, 1); assert.equal(state.lastUpdate.mtu, 1300);
 await page.locator('#dlg-link [data-close]').click();
 await page.screenshot({ path: 'test-results/panel-desktop.png', fullPage: true });
 await page.setViewportSize({ width: 375, height: 812 });
 assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
 await page.getByRole('button', { name: 'Settings', exact: true }).click();
 await page.getByRole('button', { name: 'Link test', exact: true }).click();
 await page.getByRole('button', { name: 'Start listener', exact: true }).click();
 await page.locator('#t-iran-link').waitFor({ state: 'visible' });
 assert.match(await page.locator('#t-iran-link').inputValue(), /^ctunnel-test:\/\//);
 assert.equal(state.listener, true);
 await page.getByRole('button', { name: 'Stop listener', exact: true }).click();
 await page.locator('#t-iran-status').waitFor({ state: 'hidden' });
 await page.locator('#dlg-test .test-head [data-close]').click();
 await page.getByRole('button', { name: 'Settings', exact: true }).click();
 await page.getByRole('button', { name: 'Link test', exact: true }).click();
 await page.getByRole('tab', { name: /Kharej/ }).click();
 await page.locator('#t-link').fill('ctunnel-test://fixture');
 await page.getByRole('button', { name: 'Run test', exact: true }).click();
 await page.getByRole('button', { name: 'Deploy Best Direct', exact: true }).waitFor();
 await page.locator('#t-secret').fill('fixture-secret');
 await page.getByRole('button', { name: 'Deploy Best Direct', exact: true }).click();
 await page.locator('#dlg-link').waitFor({ state: 'visible' }); assert.equal(state.deployCalls, 1); assert.equal(state.jobStarted, true);
 await page.locator('#dlg-link [data-close]').click();
 await page.screenshot({ path: 'test-results/panel-mobile.png', fullPage: true });
 await page.getByRole('button', { name: 'Settings', exact: true }).click();
 await page.getByRole('button', { name: 'Panel settings', exact: true }).click();
 await page.getByLabel('Base path', { exact: true }).fill('/panel-changed');
 await page.getByRole('button', { name: 'Save settings', exact: true }).click();
 await page.waitForURL(`http://panel.test:${port}/panel-changed/`);
 assert.equal(state.path, '/panel-changed');
 await page.close();
 reset(); state.failStart = true;
 const retryPage = await browser.newPage(); await login(retryPage);
 await retryPage.getByRole('button', { name: 'New tunnel', exact: true }).click();
 await retryPage.getByLabel('Remote server IP', { exact: true }).fill('203.0.113.8');
 await retryPage.locator('#create-form [type=submit]').click();
 await retryPage.getByRole('button', { name: 'Retry start', exact: true }).waitFor();
 await retryPage.getByRole('button', { name: 'Retry start', exact: true }).click();
 await retryPage.locator('#dlg-link').waitFor({ state: 'visible' });
 assert.equal(state.createCalls, 1); assert.equal(state.restartCalls, 1);
 assert.deepEqual(errors, []);
 console.log('PASS: legacy Secure cookie recovery, login/overview race, settings layering, validation, Create, Edit, failed-start retry, Iran listener, Kharej live job, direct deployment, routing, desktop/mobile overflow');
} finally { await browser.close(); await new Promise(resolve => server.close(resolve)); }
