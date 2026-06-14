/**
 * @file errors.ts
 * All Tollgate SDK error classes.
 * Every error extends TollgateError so developers can catch the whole family:
 *   catch (e) { if (e instanceof TollgateError) { ... } }
 */

// ── BASE ────────────────────────────────────────────────────────────────────

export class TollgateError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(`[Tollgate/${code}] ${message}`);
    this.name = 'TollgateError';
    // Fix instanceof checks in compiled/transpiled JS (CommonJS + down-level emit).
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ── CONFIG ──────────────────────────────────────────────────────────────────

/** Thrown when a required config field is missing or invalid. */
export class TollgateConfigError extends TollgateError {
  constructor(msg: string) {
    super('CONFIG', msg);
    this.name = 'TollgateConfigError';
  }
}

// ── NETWORK ─────────────────────────────────────────────────────────────────

/** Thrown on fetch failure (ECONNREFUSED, DNS, etc.) after all retries. */
export class TollgateNetworkError extends TollgateError {
  constructor(
    public readonly cause: unknown,
    msg: string,
  ) {
    super('NETWORK', msg);
    this.name = 'TollgateNetworkError';
  }
}

/** Thrown when a Notary request exceeds the configured timeout. */
export class TollgateTimeoutError extends TollgateError {
  constructor(ms: number) {
    super('TIMEOUT', `Notary request timed out after ${ms}ms`);
    this.name = 'TollgateTimeoutError';
  }
}

/** Thrown by healthCheck() when the Notary is not reachable. */
export class TollgateNotaryUnreachableError extends TollgateError {
  constructor(
    public readonly url: string,
    public readonly httpStatus?: number,
  ) {
    super(
      'UNREACHABLE',
      httpStatus
        ? `Notary at ${url} returned HTTP ${httpStatus} — is it healthy?`
        : `Notary not reachable at ${url} — is it running?`,
    );
    this.name = 'TollgateNotaryUnreachableError';
  }
}

// ── REQUEST ─────────────────────────────────────────────────────────────────

/**
 * Thrown when the Notary returns HTTP 400 — the request body was malformed.
 * This is a client-side bug, not a network error or a policy denial.
 */
export class TollgateRequestError extends TollgateError {
  constructor(
    public readonly httpStatus: number,
    msg: string,
  ) {
    super('REQUEST', `HTTP ${httpStatus}: ${msg}`);
    this.name = 'TollgateRequestError';
  }
}

// ── POLICY ──────────────────────────────────────────────────────────────────

/**
 * Thrown when the Notary denies the transaction.
 * denialCode and denialMessage come from the Notary — safe to surface to users.
 */
export class TollgateTransactionDeniedError extends TollgateError {
  constructor(
    public readonly denialCode: string,
    public readonly denialMessage: string,
  ) {
    super('DENIED', `[${denialCode}] ${denialMessage}`);
    this.name = 'TollgateTransactionDeniedError';
  }
}

/** Thrown when human approval times out without a decision. */
export class TollgateHumanApprovalTimeoutError extends TollgateError {
  constructor(
    public readonly decisionId: string,
    ms: number,
  ) {
    super('HUMAN_TIMEOUT', `Human approval timed out after ${ms}ms. Decision ID: ${decisionId}`);
    this.name = 'TollgateHumanApprovalTimeoutError';
  }
}

/**
 * Thrown when a Tier 2 transaction is vetoed during the veto window.
 * The transaction has already executed on-chain — this signals that a
 * human reviewer flagged it after the fact.
 */
export class TollgateVetoError extends TollgateError {
  constructor(
    public readonly decisionId: string,
    public readonly vetoWindowSeconds: number,
  ) {
    super(
      'VETOED',
      `Transaction ${decisionId} was vetoed within the ${vetoWindowSeconds}s veto window`,
    );
    this.name = 'TollgateVetoError';
  }
}

/**
 * Thrown when the token expiry is too close to safely submit.
 * The SDK rejects before hitting the chain to avoid a Guard revert.
 */
export class TollgateTokenExpiredError extends TollgateError {
  constructor(
    public readonly tokenId: string,
    public readonly expiresAt: string,
  ) {
    super('TOKEN_EXPIRED', `Token ${tokenId} expires at ${expiresAt} — too close to expiry to submit safely`);
    this.name = 'TollgateTokenExpiredError';
  }
}

// ── VALIDATION ───────────────────────────────────────────────────────────────

/**
 * Thrown when the Notary returns a response that fails Zod validation.
 * Indicates an API version mismatch or malformed response.
 */
export class TollgateValidationError extends TollgateError {
  constructor(public readonly cause: unknown) {
    super('VALIDATION', 'Notary returned an unexpected response shape. Check Notary version.');
    this.name = 'TollgateValidationError';
  }
}

// ── ON-CHAIN ─────────────────────────────────────────────────────────────────

/**
 * Thrown when the Safe transaction reverts on-chain.
 * Indicates a Guard configuration mismatch or the token was already consumed.
 */
export class TollgateOnChainError extends TollgateError {
  constructor(
    public readonly txHash: `0x${string}`,
    public readonly guardError: string,
  ) {
    super('ONCHAIN', `Transaction reverted: ${guardError}. txHash: ${txHash}`);
    this.name = 'TollgateOnChainError';
  }
}