// Raw webhook forwarding (services/webhook-forward.ts, routes/webhook-forward.ts).
// A verified LINE webhook is POSTed on, byte-for-byte with LINE's own
// X-Line-Signature, to the account's forward URL — so the receiver can check it
// with the same channel secret. Unsigned / wrongly signed traffic is never
// forwarded and costs no settings read. All data here is synthetic.
import { createHmac } from 'node:crypto';
import { Hono } from 'hono';
import { beforeEach, describe, expect, test, vi } from 'vitest';

const db = vi.hoisted(() => ({
  settings: new Map<string, string>(),
  getAccountSetting: vi.fn(),
  setAccountSetting: vi.fn(),
  getLineAccounts: vi.fn(),
  getLineAccountById: vi.fn(),
  recordSignatureFailure: vi.fn().mockResolvedValue(undefined),
  recordSignatureSuccess: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('@line-crm/db', () => ({
  getAccountSetting: db.getAccountSetting,
  setAccountSetting: db.setAccountSetting,
  getLineAccounts: db.getLineAccounts,
  getLineAccountById: db.getLineAccountById,
  recordSignatureFailure: db.recordSignatureFailure,
  recordSignatureSuccess: db.recordSignatureSuccess,
  UNATTRIBUTED_ACCOUNT_ID: '__unattributed__',
}));
vi.mock('../durable-objects/tenant-scheduler.js', () => ({ ensureSchedulerArmed: vi.fn().mockResolvedValue(undefined) }));
vi.mock('../services/local-line-proxy.js', () => ({ dispatchLineProxyLocally: vi.fn() }));

import { forwardUrlProblem, forwardVerifiedWebhook } from '../services/webhook-forward.js';
import { webhook } from './webhook.js';
import { webhookForward } from './webhook-forward.js';

const SECRET = 'synthetic-channel-secret';
const ACCOUNT = { id: 'acc-1', name: 'テスト', channel_id: '1', channel_secret: SECRET, channel_access_token: 'tok', is_active: 1 };
const FORWARD = 'https://receiver.example.test/in/oa-forward/made-up-token';
const sign = (body: string, secret = SECRET) => createHmac('sha256', secret).update(body).digest('base64');

const sent = vi.fn<typeof fetch>();
const D1 = {
  prepare: vi.fn(() => ({ bind: vi.fn(() => ({ run: vi.fn().mockResolvedValue({}) })) })),
} as unknown as D1Database;

beforeEach(() => {
  vi.clearAllMocks();
  db.settings.clear();
  db.getAccountSetting.mockImplementation(async (_db: unknown, id: string, key: string) => db.settings.get(`${id}|${key}`) ?? null);
  db.setAccountSetting.mockImplementation(async (_db: unknown, id: string, key: string, value: string) => { db.settings.set(`${id}|${key}`, value); });
  db.getLineAccounts.mockResolvedValue([ACCOUNT]);
  db.getLineAccountById.mockImplementation(async (_db: unknown, id: string) => (id === ACCOUNT.id ? ACCOUNT : null));
  sent.mockResolvedValue(new Response(null, { status: 200 }));
  vi.stubGlobal('fetch', sent);
});

function lineSends(body: string, signature: string) {
  const app = new Hono();
  app.route('/', webhook);
  const waits: Promise<unknown>[] = [];
  const ctx = { waitUntil: (p: Promise<unknown>) => waits.push(p), passThroughOnException: vi.fn(), props: {} } as unknown as ExecutionContext;
  const env = { DB: D1, LINE_CHANNEL_ACCESS_TOKEN: 'env-token', WORKER_URL: 'https://harness.example.test' };
  return Promise.resolve(app.request('/webhook', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Line-Signature': signature }, body }, env, ctx))
    .then(async (res: Response) => { await Promise.all(waits); return res; });
}

describe('POST /webhook → the account\'s forward URL', () => {
  // Japanese and an emoji: the forwarded bytes must still match LINE's signature.
  const body = JSON.stringify({ destination: 'U'.padEnd(33, '0'), events: [] , note: '予約を変えたいです 🙏' });

  test('a verified webhook goes on once, byte-for-byte, with LINE\'s own signature', async () => {
    db.settings.set(`acc-1|webhook_forward_url`, JSON.stringify(FORWARD));
    const res = await lineSends(body, sign(body));
    expect(res.status).toBe(200);
    expect(sent).toHaveBeenCalledTimes(1);
    const [url, init] = sent.mock.calls[0]!;
    expect(url).toBe(FORWARD);
    expect(init?.method).toBe('POST');
    expect(init?.body).toBe(body);
    const signature = new Headers(init?.headers).get('x-line-signature')!;
    expect(signature).toBe(sign(body));
    // the receiver can verify it with the same channel secret
    expect(sign(new TextDecoder().decode(new TextEncoder().encode(init?.body as string)))).toBe(signature);
  });

  test('nothing is forwarded when no URL is set', async () => {
    await lineSends(body, sign(body));
    expect(sent).not.toHaveBeenCalled();
  });

  test('a wrong or missing signature is never forwarded, nor is the setting read', async () => {
    db.settings.set(`acc-1|webhook_forward_url`, JSON.stringify(FORWARD));
    await lineSends(body, sign(body, 'another-secret'));
    await lineSends(body, '');
    expect(sent).not.toHaveBeenCalled();
    expect(db.getAccountSetting).not.toHaveBeenCalled();
  });

  test('a receiver that fails or hangs does not change LINE\'s 200', async () => {
    db.settings.set(`acc-1|webhook_forward_url`, JSON.stringify(FORWARD));
    sent.mockRejectedValueOnce(new Error('network down'));
    expect((await lineSends(body, sign(body))).status).toBe(200);
    sent.mockResolvedValueOnce(new Response(null, { status: 500 }));
    expect((await lineSends(body, sign(body))).status).toBe(200);
    expect(sent).toHaveBeenCalledTimes(2); // no retry
  });
});

describe('forwardVerifiedWebhook', () => {
  test('an unknown account reads nothing and sends nothing', async () => {
    await forwardVerifiedWebhook(D1, null, '{}', 'sig', sent);
    expect(db.getAccountSetting).not.toHaveBeenCalled();
    expect(sent).not.toHaveBeenCalled();
  });
});

describe('forwardUrlProblem', () => {
  test.each([
    ['http://receiver.example.test/x', 'https'],
    ['not a url', 'absolute'],
    ['https://user:pass@receiver.example.test/x', 'credentials'],
    ['https://harness.example.test/webhook', 'own'],
    ['https://harness.example.test/webhook/', 'own'],
  ])('%s is refused', (value, word) => {
    expect(forwardUrlProblem(value, 'https://harness.example.test')).toContain(word);
  });
  test('an https receiver elsewhere is fine, and http only on this machine (wrangler dev)', () => {
    expect(forwardUrlProblem(FORWARD, 'https://harness.example.test')).toBeNull();
    expect(forwardUrlProblem('http://127.0.0.1:8808/in/oa-forward/x', 'https://harness.example.test')).toBeNull();
    expect(forwardUrlProblem('http://localhost:8808/in/oa-forward/x', null)).toBeNull();
    expect(forwardUrlProblem('ftp://127.0.0.1/x', null)).toContain('https');
  });
});

describe('/api/line-accounts/:id/webhook-forward', () => {
  function api(role: 'owner' | 'admin' | 'staff' = 'owner') {
    const app = new Hono<{ Variables: { staff: { id: string; role: typeof role } } }>();
    app.use('*', async (c, next) => { c.set('staff', { id: 's', role }); await next(); });
    app.route('/', webhookForward as unknown as Hono);
    const env = { DB: D1, WORKER_URL: 'https://harness.example.test' };
    return {
      get: (id = 'acc-1') => app.request(`/api/line-accounts/${id}/webhook-forward`, {}, env),
      put: (url: unknown, id = 'acc-1') => app.request(`/api/line-accounts/${id}/webhook-forward`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) }, env),
    };
  }

  test('sets, reads back and clears', async () => {
    const a = api();
    expect(await (await a.get()).json()).toEqual({ success: true, data: { url: null } });
    expect((await a.put(`  ${FORWARD}  `)).status).toBe(200);
    expect(await (await a.get()).json()).toEqual({ success: true, data: { url: FORWARD } });
    expect((await a.put('')).status).toBe(200);
    expect(D1.prepare).toHaveBeenCalledWith(expect.stringContaining('DELETE FROM account_settings'));
  });

  test('refuses a bad URL, the Worker itself, a missing account and staff', async () => {
    const a = api();
    expect((await a.put('http://receiver.example.test/x')).status).toBe(400);
    expect((await a.put('https://harness.example.test/webhook')).status).toBe(400);
    expect((await a.put(42)).status).toBe(400);
    expect((await a.put(FORWARD, 'nobody')).status).toBe(404);
    expect((await api('staff').put(FORWARD)).status).toBe(403);
    expect((await api('staff').get()).status).toBe(403);
    expect(db.setAccountSetting).not.toHaveBeenCalled();
  });
});
