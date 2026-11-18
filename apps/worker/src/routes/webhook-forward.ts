import { Hono } from 'hono';
import { getLineAccountById } from '@line-crm/db';
import type { Env } from '../index.js';
import { requireRole } from '../middleware/role-guard.js';
import {
  forwardUrlProblem,
  getWebhookForwardUrl,
  setWebhookForwardUrl,
} from '../services/webhook-forward.js';

// Per-account raw webhook forwarding (services/webhook-forward.ts).
// The URL may carry a receiver's token, so reading and changing it is limited
// to owner/admin, and it is never logged.
const webhookForward = new Hono<Env>();

webhookForward.get('/api/line-accounts/:id/webhook-forward', requireRole('owner', 'admin'), async (c) => {
  const account = await getLineAccountById(c.env.DB, c.req.param('id')!);
  if (!account) return c.json({ success: false, error: 'LINE account not found' }, 404);
  const url = await getWebhookForwardUrl(c.env.DB, account.id);
  return c.json({ success: true, data: { url } });
});

webhookForward.put('/api/line-accounts/:id/webhook-forward', requireRole('owner', 'admin'), async (c) => {
  const account = await getLineAccountById(c.env.DB, c.req.param('id')!);
  if (!account) return c.json({ success: false, error: 'LINE account not found' }, 404);
  const body = await c.req.json<{ url?: unknown }>().catch((): { url?: unknown } => ({}));
  if (body.url !== null && typeof body.url !== 'string') {
    return c.json({ success: false, error: 'url must be a string (empty or null clears it)' }, 400);
  }
  const value = (body.url ?? '').trim();
  if (value !== '') {
    const problem = forwardUrlProblem(value, c.env.WORKER_URL || new URL(c.req.url).origin);
    if (problem) return c.json({ success: false, error: problem }, 400);
  }
  await setWebhookForwardUrl(c.env.DB, account.id, value);
  return c.json({ success: true, data: { url: value === '' ? null : value } });
});

export { webhookForward };
