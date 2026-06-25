/**
 * @file api.ts
 * VerilockClient — all HTTP communication with the Notary.
 *
 * SECURITY CONTRACT:
 *   - agentToken is NEVER logged, never included in error messages,
 *     never thrown in any value. It lives only in the Authorization header.
 *   - Each retry generates a FRESH nonce via nonceFactory.
 *     Reusing a nonce on retry causes NONCE_REPLAY denial.
 *   - 4xx responses are NEVER retried — a denial is a final answer.
 *   - Only network-level failures trigger retries (fetch throws, ECONNREFUSED).
 */

import {
  NotaryResponseSchema,
  NotaryResponse,
  ActionRequest,
} from './types.js';
import {
  VerilockNetworkError,
  VerilockTimeoutError,
  VerilockNotaryUnreachableError,
  VerilockRequestError,
  VerilockValidationError,
  VerilockHumanApprovalTimeoutError,
} from './errors.js';

// ── BACKOFF ───────────────────────────────────────────────────────────────────

const RETRY_DELAYS_MS = [0, 1_000, 2_000, 4_000] as const;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ── CLIENT ────────────────────────────────────────────────────────────────────

export class VerilockClient {
  constructor(
    private readonly baseUrl: string,
    private readonly agentToken: string,
    private readonly timeoutMs: number = 10_000,
    private readonly maxRetries: number = 3,
  ) {}

  // ── requestApproval ──────────────────────────────────────────────────────────

  /**
   * POST /v1/action-check
   *
   * Sends the ActionRequest to the Notary and returns a validated
   * NotaryResponse. On network failure: retries up to maxRetries times
   * with exponential backoff. Each retry gets a fresh nonce via nonceFactory.
   *
   * @param request      The action request to evaluate.
   * @param nonceFactory Called before each attempt to produce a fresh nonce.
   *                     Default: crypto.randomUUID().
   */
  async requestApproval(
    request: ActionRequest,
    nonceFactory: () => string = () => crypto.randomUUID(),
  ): Promise<NotaryResponse> {
    let lastError: unknown;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      const delay = RETRY_DELAYS_MS[attempt] ?? 4_000;
      if (attempt > 0) await sleep(delay);

      // Fresh nonce and timestamp on every attempt.
      const req: ActionRequest = {
        ...request,
        nonce:     nonceFactory(),
        timestamp: new Date().toISOString(),
      };

      try {
        const response = await this._post('/v1/action-check', req);

        // ── 4xx: never retry — these are final answers ──────────────────────
        if (response.status === 401 || response.status === 403) {
          throw new VerilockNetworkError(
            null,
            `Notary rejected agent token (HTTP ${response.status}) — check agentToken config`,
          );
        }
        if (response.status === 429) {
          throw new VerilockNetworkError(null, 'Rate limited by Notary — slow down requests');
        }
        if (response.status === 400) {
          // Malformed request body — client bug, not a network or policy issue.
          let detail = 'malformed request body';
          try {
            const body = await response.json() as { error?: string };
            if (body.error) detail = body.error;
          } catch { /* ignore parse errors */ }
          throw new VerilockRequestError(400, detail);
        }
        if (response.status >= 400 && response.status < 500) {
          throw new VerilockNetworkError(null, `Notary returned HTTP ${response.status}`);
        }

        const json: unknown = await response.json();
        return this._validate(json);

      } catch (err) {
        // These errors must not be retried.
        if (err instanceof VerilockNetworkError)  throw err;
        if (err instanceof VerilockRequestError)  throw err;
        if (err instanceof VerilockValidationError) throw err;
        if (err instanceof VerilockTimeoutError)  throw err;

        // Network-level failure — eligible for retry.
        lastError = err;
        if (attempt < this.maxRetries) continue;
      }
    }

    throw new VerilockNetworkError(
      lastError,
      `Notary unreachable after ${this.maxRetries + 1} attempts`,
    );
  }

  // ── pollDecision ─────────────────────────────────────────────────────────────

  /**
   * Polls the server-provided poll_url until the decision is no longer
   * pending_human. Used after receiving a Tier 3 (pending_human) response.
   *
   * @param pollUrl      The poll_url from the pending_human response.
   *                     Use the server-provided URL — don't construct your own.
   * @param intervalMs   Milliseconds between polls (from poll_interval_seconds).
   * @param timeoutMs    Max total wait time before throwing.
   * @param onPoll       Optional callback fired before each poll attempt.
   */
  async pollDecision(
    pollUrl: string,
    intervalMs: number,
    timeoutMs: number,
    onPoll?: () => void,
  ): Promise<NotaryResponse> {
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
      onPoll?.();

      try {
        // pollUrl is a path like "/v1/decision/<id>" — prepend baseUrl.
        const fullUrl = pollUrl.startsWith('http')
          ? pollUrl
          : `${this.baseUrl}${pollUrl}`;

        const response = await this._getUrl(fullUrl);
        if (response.ok) {
          const json: unknown = await response.json();
          const parsed = this._validate(json);
          if (parsed.status !== 'pending_human') {
            return parsed;
          }
        }
      } catch {
        // Poll failures are transient — keep trying until deadline.
      }

      await sleep(intervalMs);
    }

    // Extract decisionId from the poll URL for the error message.
    const decisionId = pollUrl.split('/').pop() ?? pollUrl;
    throw new VerilockHumanApprovalTimeoutError(decisionId, timeoutMs);
  }

  // ── healthCheck ──────────────────────────────────────────────────────────────

  /**
   * GET /v1/health
   *
   * Verifies the Notary is reachable and healthy.
   * Called by VerilockSigner.create() before returning the instance.
   *
   * Distinguishes two failure modes:
   *   - Connection refused / DNS failure → Notary is not running
   *   - HTTP non-2xx → Notary is running but unhealthy (policy invalid, DB down)
   */
  async healthCheck(): Promise<boolean> {
    try {
      const response = await this._get('/v1/health');
      if (!response.ok) {
        // Notary is reachable but reports degraded status.
        throw new VerilockNotaryUnreachableError(this.baseUrl, response.status);
      }
      return true;
    } catch (err) {
      if (err instanceof VerilockNotaryUnreachableError) throw err;
      // Connection-level failure — Notary not running.
      throw new VerilockNotaryUnreachableError(this.baseUrl);
    }
  }

  // ── PRIVATE ───────────────────────────────────────────────────────────────────

  private async _post(path: string, body: unknown): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      return await fetch(`${this.baseUrl}${path}`, {
        method:  'POST',
        headers: {
          'Content-Type':  'application/json',
          // SECURITY: agentToken is never logged or included in errors.
          'Authorization': `Bearer ${this.agentToken}`,
        },
        body:   JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (err) {
      if (err instanceof Error && err.name === 'AbortError') {
        throw new VerilockTimeoutError(this.timeoutMs);
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  private async _get(path: string): Promise<Response> {
    return this._getUrl(`${this.baseUrl}${path}`);
  }

  private async _getUrl(url: string): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      return await fetch(url, {
        method:  'GET',
        headers: { 'Authorization': `Bearer ${this.agentToken}` },
        signal:  controller.signal,
      });
    } catch (err) {
      if (err instanceof Error && err.name === 'AbortError') {
        throw new VerilockTimeoutError(this.timeoutMs);
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  private _validate(json: unknown): NotaryResponse {
    const result = NotaryResponseSchema.safeParse(json);
    if (!result.success) {
      throw new VerilockValidationError(result.error);
    }
    return result.data;
  }
}