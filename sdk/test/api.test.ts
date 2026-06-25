/**
 * @file test/api.test.ts
 * Unit tests for VerilockClient using msw to mock HTTP.
 */

import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { VerilockClient } from '../src/api.js';
import {
  VerilockNetworkError,
  VerilockRequestError,
  VerilockValidationError,
  VerilockNotaryUnreachableError,
  VerilockHumanApprovalTimeoutError,
} from '../src/errors.js';
import type { ActionRequest } from '../src/types.js';

// ── FIXTURES ──────────────────────────────────────────────────────────────────

const NOTARY_URL  = 'http://localhost:8080';
const AGENT_TOKEN = 'test-token-never-logged';

// Base approval token — tier field required by updated ApprovalTokenSchema.
const validToken = {
  token_id:       '123e4567-e89b-12d3-a456-426614174000',
  agent_id:       'trading-bot-01',
  policy_version: '1.0.0',
  policy_hash:    '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
  tier:           1,
  auto_approved:  true,
  action:         'transfer',
  destination:    '0xdef4560000000000000000000000000000000000',
  amount_usd:     10.00,
  amount_raw:     '10000000',
  purpose:        'defi_yield_optimization',
  chain_id:       84532,
  nonce:          'test-nonce-001',
  issued_at:      new Date().toISOString(),
  expires_at:     new Date(Date.now() + 60_000).toISOString(),
  risk_score:     0.12,
  signature:      '0x' + 'ab'.repeat(65),
};

// Tier 2 token
const tier2Token = { ...validToken, tier: 2, auto_approved: false };

// Responses
const approvedResponse = {
  status:         'approved',
  decision_id:    '223e4567-e89b-12d3-a456-426614174001',
  tier:           1,
  approval_token: validToken,
};

const tier2Response = {
  status:              'approved_with_notification',
  decision_id:         '323e4567-e89b-12d3-a456-426614174002',
  tier:                2,
  approval_token:      tier2Token,
  veto_window_seconds: 120,
};

const pendingHumanResponse = {
  status:                'pending_human',
  decision_id:           '423e4567-e89b-12d3-a456-426614174003',
  tier:                  3,
  poll_url:              '/v1/decision/423e4567-e89b-12d3-a456-426614174003',
  poll_interval_seconds: 3,
};

const deniedResponse = {
  status:      'denied',
  decision_id: '523e4567-e89b-12d3-a456-426614174004',
  code:        'PURPOSE_MISMATCH',
  message:     'Purpose buy_nfts is not in allowed_purposes',
};

const baseRequest: ActionRequest = {
  agent_id:    'trading-bot-01',
  action:      'transfer',
  destination: '0xdef4560000000000000000000000000000000000',
  amount_usd:  10.00,
  amount_raw:  '10000000',
  purpose:     'defi_yield_optimization',
  chain_id:    84532,
  nonce:       'test-nonce-001',
  timestamp:   new Date().toISOString(),
};

// ── MSW SERVER ────────────────────────────────────────────────────────────────

const server = setupServer();

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function makeClient(overrides?: Partial<{ timeoutMs: number; maxRetries: number }>) {
  return new VerilockClient(
    NOTARY_URL,
    AGENT_TOKEN,
    overrides?.timeoutMs  ?? 5_000,
    overrides?.maxRetries ?? 0,
  );
}

// ── requestApproval — happy paths ─────────────────────────────────────────────

describe('VerilockClient.requestApproval — approved responses', () => {

  it('Tier 1: returns approved response with token', async () => {
    server.use(
      http.post(`${NOTARY_URL}/v1/action-check`, () =>
        HttpResponse.json(approvedResponse),
      ),
    );
    const result = await makeClient().requestApproval(baseRequest);
    expect(result.status).toBe('approved');
    if (result.status === 'approved') {
      expect(result.approval_token.token_id).toBe(validToken.token_id);
      expect(result.approval_token.tier).toBe(1);
      expect(result.approval_token.signature).toMatch(/^0x/);
    }
  });

  it('Tier 2: returns approved_with_notification with veto_window_seconds', async () => {
    server.use(
      http.post(`${NOTARY_URL}/v1/action-check`, () =>
        HttpResponse.json(tier2Response),
      ),
    );
    const result = await makeClient().requestApproval(baseRequest);
    expect(result.status).toBe('approved_with_notification');
    if (result.status === 'approved_with_notification') {
      expect(result.approval_token.tier).toBe(2);
      expect(result.veto_window_seconds).toBe(120);
      expect(result.approval_token).toBeDefined();
    }
  });

  it('Tier 3: returns pending_human with poll_url and poll_interval_seconds', async () => {
    server.use(
      http.post(`${NOTARY_URL}/v1/action-check`, () =>
        HttpResponse.json(pendingHumanResponse),
      ),
    );
    const result = await makeClient().requestApproval(baseRequest);
    expect(result.status).toBe('pending_human');
    if (result.status === 'pending_human') {
      expect(result.poll_url).toBe(pendingHumanResponse.poll_url);
      expect(result.poll_interval_seconds).toBe(3);
      expect(result.decision_id).toBe(pendingHumanResponse.decision_id);
    }
  });

  it('denied: returns denial code and message', async () => {
    server.use(
      http.post(`${NOTARY_URL}/v1/action-check`, () =>
        HttpResponse.json(deniedResponse),
      ),
    );
    const result = await makeClient().requestApproval(baseRequest);
    expect(result.status).toBe('denied');
    if (result.status === 'denied') {
      expect(result.code).toBe('PURPOSE_MISMATCH');
      expect(result.message).toBeTruthy();
    }
  });
});

// ── requestApproval — error handling ─────────────────────────────────────────

describe('VerilockClient.requestApproval — error handling', () => {

  it('throws VerilockValidationError on malformed response shape', async () => {
    server.use(
      http.post(`${NOTARY_URL}/v1/action-check`, () =>
        HttpResponse.json({ broken: true }),
      ),
    );
    await expect(makeClient().requestApproval(baseRequest))
      .rejects.toBeInstanceOf(VerilockValidationError);
  });

  it('throws VerilockValidationError when approval_token is missing tier', async () => {
    const tokenWithoutTier = { ...validToken };
    // @ts-expect-error intentionally testing missing field
    delete tokenWithoutTier.tier;
    server.use(
      http.post(`${NOTARY_URL}/v1/action-check`, () =>
        HttpResponse.json({ ...approvedResponse, approval_token: tokenWithoutTier }),
      ),
    );
    await expect(makeClient().requestApproval(baseRequest))
      .rejects.toBeInstanceOf(VerilockValidationError);
  });

  it('throws VerilockNetworkError on 401 — does NOT retry', async () => {
    let callCount = 0;
    server.use(
      http.post(`${NOTARY_URL}/v1/action-check`, () => {
        callCount++;
        return HttpResponse.json({ error: 'unauthorized' }, { status: 401 });
      }),
    );
    await expect(makeClient({ maxRetries: 3 }).requestApproval(baseRequest))
      .rejects.toBeInstanceOf(VerilockNetworkError);
    expect(callCount).toBe(1); // no retries on 401
  });

  it('throws VerilockNetworkError on 429 rate limit', async () => {
    server.use(
      http.post(`${NOTARY_URL}/v1/action-check`, () =>
        HttpResponse.json({ error: 'rate limited' }, { status: 429 }),
      ),
    );
    await expect(makeClient().requestApproval(baseRequest))
      .rejects.toBeInstanceOf(VerilockNetworkError);
  });

  it('throws VerilockRequestError on 400 malformed request', async () => {
    server.use(
      http.post(`${NOTARY_URL}/v1/action-check`, () =>
        HttpResponse.json({ error: 'invalid request body' }, { status: 400 }),
      ),
    );
    await expect(makeClient().requestApproval(baseRequest))
      .rejects.toBeInstanceOf(VerilockRequestError);
  });

  it('VerilockRequestError carries the HTTP status code', async () => {
    server.use(
      http.post(`${NOTARY_URL}/v1/action-check`, () =>
        HttpResponse.json({ error: 'invalid request body' }, { status: 400 }),
      ),
    );
    try {
      await makeClient().requestApproval(baseRequest);
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(VerilockRequestError);
      expect((err as VerilockRequestError).httpStatus).toBe(400);
    }
  });

  it('retries on network error and succeeds on 3rd attempt', async () => {
    let callCount = 0;
    server.use(
      http.post(`${NOTARY_URL}/v1/action-check`, () => {
        callCount++;
        return callCount < 3 ? HttpResponse.error() : HttpResponse.json(approvedResponse);
      }),
    );
    const result = await makeClient({ maxRetries: 3 }).requestApproval(baseRequest);
    expect(result.status).toBe('approved');
    expect(callCount).toBe(3);
  });

  it('each retry generates a fresh nonce', async () => {
    const nonces: string[] = [];
    server.use(
      http.post(`${NOTARY_URL}/v1/action-check`, async ({ request }) => {
        const body = await request.json() as ActionRequest;
        nonces.push(body.nonce);
        return nonces.length < 3
          ? HttpResponse.error()
          : HttpResponse.json(approvedResponse);
      }),
    );
    await makeClient({ maxRetries: 3 }).requestApproval(baseRequest);
    expect(new Set(nonces).size).toBe(nonces.length); // all unique
  });

  it('agentToken never appears in thrown error messages', async () => {
    server.use(
      http.post(`${NOTARY_URL}/v1/action-check`, () =>
        HttpResponse.json({ error: 'unauthorized' }, { status: 401 }),
      ),
    );
    try {
      await makeClient().requestApproval(baseRequest);
      expect.fail('should have thrown');
    } catch (err) {
      const errStr = JSON.stringify(err) + String(err);
      expect(errStr).not.toContain(AGENT_TOKEN);
    }
  });
});

// ── pollDecision ──────────────────────────────────────────────────────────────

describe('VerilockClient.pollDecision', () => {
  const POLL_URL  = '/v1/decision/423e4567-e89b-12d3-a456-426614174003';
  const FULL_POLL = `${NOTARY_URL}${POLL_URL}`;

  it('returns when decision transitions from pending_human to approved', async () => {
    let callCount = 0;
    server.use(
      http.get(FULL_POLL, () => {
        callCount++;
        // First two polls return pending, third returns approved.
        return callCount < 3
          ? HttpResponse.json(pendingHumanResponse)
          : HttpResponse.json(approvedResponse);
      }),
    );
    const client = makeClient();
    const result = await client.pollDecision(POLL_URL, 10, 5_000);
    expect(result.status).toBe('approved');
    expect(callCount).toBe(3);
  });

  it('returns when decision transitions to denied', async () => {
    server.use(
      http.get(FULL_POLL, () => HttpResponse.json(deniedResponse)),
    );
    const client = makeClient();
    const result = await client.pollDecision(POLL_URL, 10, 5_000);
    expect(result.status).toBe('denied');
  });

  it('throws VerilockHumanApprovalTimeoutError when always pending', async () => {
    server.use(
      http.get(FULL_POLL, () => HttpResponse.json(pendingHumanResponse)),
    );
    const client = makeClient();
    await expect(client.pollDecision(POLL_URL, 10, 50))
      .rejects.toBeInstanceOf(VerilockHumanApprovalTimeoutError);
  });

  it('handles absolute poll_url correctly', async () => {
    const absoluteUrl = FULL_POLL;
    server.use(
      http.get(absoluteUrl, () => HttpResponse.json(approvedResponse)),
    );
    const client = makeClient();
    // Should not prepend baseUrl when URL is already absolute.
    const result = await client.pollDecision(absoluteUrl, 10, 5_000);
    expect(result.status).toBe('approved');
  });

  it('calls onPoll callback before each poll', async () => {
    let pollCallbacks = 0;
    server.use(
      http.get(FULL_POLL, () => HttpResponse.json(approvedResponse)),
    );
    const client = makeClient();
    await client.pollDecision(POLL_URL, 10, 5_000, () => { pollCallbacks++; });
    expect(pollCallbacks).toBe(1);
  });
});

// ── healthCheck ───────────────────────────────────────────────────────────────

describe('VerilockClient.healthCheck', () => {

  it('returns true when Notary responds 200', async () => {
    server.use(
      http.get(`${NOTARY_URL}/v1/health`, () =>
        HttpResponse.json({ status: 'ok' }),
      ),
    );
    await expect(makeClient().healthCheck()).resolves.toBe(true);
  });

  it('throws VerilockNotaryUnreachableError when connection refused', async () => {
    server.use(
      http.get(`${NOTARY_URL}/v1/health`, () => HttpResponse.error()),
    );
    await expect(makeClient().healthCheck())
      .rejects.toBeInstanceOf(VerilockNotaryUnreachableError);
  });

  it('throws VerilockNotaryUnreachableError with httpStatus when server returns 500', async () => {
    server.use(
      http.get(`${NOTARY_URL}/v1/health`, () =>
        HttpResponse.json({ status: 'degraded' }, { status: 500 }),
      ),
    );
    try {
      await makeClient().healthCheck();
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(VerilockNotaryUnreachableError);
      expect((err as VerilockNotaryUnreachableError).httpStatus).toBe(500);
    }
  });

  it('error message distinguishes unreachable from unhealthy', async () => {
    server.use(
      http.get(`${NOTARY_URL}/v1/health`, () =>
        HttpResponse.json({ status: 'degraded' }, { status: 503 }),
      ),
    );
    try {
      await makeClient().healthCheck();
    } catch (err) {
      // Unhealthy message mentions the HTTP status.
      expect(String(err)).toContain('503');
    }
  });
});