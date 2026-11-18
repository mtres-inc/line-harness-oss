/**
 * Raw webhook forwarding (per LINE account).
 *
 * A LINE channel takes exactly one webhook URL. When this Worker holds it, an
 * operator may still want another receiver (an inbox, an AI assistant, a
 * second tool) to see the same events. With `webhook_forward_url` set for an
 * account, every webhook that passed signature verification for that account
 * is POSTed on to the URL **byte-for-byte** with LINE's own `X-Line-Signature`,
 * so the receiver can verify it with the same channel secret exactly as if
 * LINE had sent it directly.
 *
 * - Runs in waitUntil after the 200 reply: never delays LINE's ~1s deadline.
 * - One attempt, no retry, 5s timeout: a receiver outage cannot pile up work.
 *   LINE's own redelivery (when enabled) is the only retry.
 * - Cost: one indexed account_settings read per verified webhook, inside
 *   waitUntil; zero writes. Nothing is read for unsigned/invalid traffic.
 * - Never logs the URL (it may carry a token) or the body.
 */
import { getAccountSetting, setAccountSetting } from '@line-crm/db';

export const WEBHOOK_FORWARD_URL_KEY = 'webhook_forward_url';
const FORWARD_TIMEOUT_MS = 5_000;

export async function getWebhookForwardUrl(db: D1Database, accountId: string): Promise<string | null> {
  const raw = await getAccountSetting(db, accountId, WEBHOOK_FORWARD_URL_KEY);
  if (!raw) return null;
  try {
    const value = JSON.parse(raw) as unknown;
    return typeof value === 'string' && value !== '' ? value : null;
  } catch {
    return null;
  }
}

/**
 * Validate a forward URL. Returns an error message, or null when acceptable.
 * https only; never this Worker's own /webhook (that would loop forever).
 */
export function forwardUrlProblem(value: string, workerOrigin: string | null): string | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return 'url must be an absolute https:// URL';
  }
  // http only to a receiver on the same machine (wrangler dev); a deployed
  // Worker cannot reach those, so this never opens plain-text forwarding.
  const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  if (url.protocol !== 'https:' && !(local && url.protocol === 'http:')) return 'url must start with https://';
  if (url.username || url.password) return 'url must not contain credentials';
  if (workerOrigin) {
    try {
      if (url.origin === new URL(workerOrigin).origin && url.pathname.replace(/\/$/, '') === '/webhook') {
        return 'url must not be this Worker\'s own /webhook';
      }
    } catch {
      // unparsable WORKER_URL: nothing to compare against
    }
  }
  return null;
}

/** Store (or, with '', clear) the forward URL. Caller validates first. */
export async function setWebhookForwardUrl(db: D1Database, accountId: string, value: string): Promise<void> {
  if (value === '') {
    await db
      .prepare('DELETE FROM account_settings WHERE line_account_id = ? AND key = ?')
      .bind(accountId, WEBHOOK_FORWARD_URL_KEY)
      .run();
    return;
  }
  await setAccountSetting(db, accountId, WEBHOOK_FORWARD_URL_KEY, JSON.stringify(value));
}

/**
 * Forward one verified webhook as LINE sent it. Never throws.
 * `rawBody` is the exact text the signature was verified against.
 */
export async function forwardVerifiedWebhook(
  db: D1Database,
  accountId: string | null,
  rawBody: string,
  signature: string,
  send: typeof fetch = fetch,
): Promise<void> {
  if (!accountId) return;
  try {
    const url = await getWebhookForwardUrl(db, accountId);
    if (!url) return;
    const res = await send(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Line-Signature': signature },
      body: rawBody,
      redirect: 'manual',
      signal: AbortSignal.timeout(FORWARD_TIMEOUT_MS),
    });
    if (!res.ok) console.error(`[webhook-forward] receiver answered ${res.status} (account ${accountId})`);
  } catch (err) {
    const name = err instanceof Error ? err.name : 'error';
    console.error(`[webhook-forward] forward failed: ${name} (account ${accountId})`);
  }
}
