/**
 * @file errors.ts
 * All Verilock SDK error classes.
 * Every error extends VerilockError so developers can catch the whole family:
 *   catch (e) { if (e instanceof VerilockError) { ... } }
 */

// ── BASE ────────────────────────────────────────────────────────────────────

export class VerilockError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(`[Verilock/${code}] ${message}`);
    this.name = 'VerilockError';
    // Fix instanceof checks in compiled/transpiled JS (CommonJS + down-level emit).
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ── CONFIG ──────────────────────────────────────────────────────────────────

/** Thrown when a required config field is missing or invalid. */
export class VerilockConfigError extends VerilockError {
  constructor(msg: string) {
    super('CONFIG', msg);
    this.name = 'VerilockConfigError';
  }
}

// ── NETWORK ─────────────────────────────────────────────────────────────────

/** Thrown on fetch failure (ECONNREFUSED, DNS, etc.) after all retries. */
export class VerilockNetworkError extends VerilockError {
  constructor(
    public readonly cause: unknown,
    msg: string,
  ) {
    super('NETWORK', msg);
    this.name = 'VerilockNetworkError';
  }
}

/** Thrown when a Notary request exceeds the configured timeout. */
export class VerilockTimeoutError extends VerilockError {
  constructor(ms: number) {
    super('TIMEOUT', `Notary request timed out after ${ms}ms`);
    this.name = 'VerilockTimeoutError';
  }
}

/** Thrown by healthCheck() when the Notary is not reachable. */
export class VerilockNotaryUnreachableError extends VerilockError {
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
    this.name = 'VerilockNotaryUnreachableError';
  }
}

// ── REQUEST ─────────────────────────────────────────────────────────────────

/**
 * Thrown when the Notary returns HTTP 400 — the request body was malformed.
 * This is a client-side bug, not a network error or a policy denial.
 */
export class VerilockRequestError extends VerilockError {
  constructor(
    public readonly httpStatus: number,
    msg: string,
  ) {
    super('REQUEST', `HTTP ${httpStatus}: ${msg}`);
    this.name = 'VerilockRequestError';
  }
}

// ── POLICY ──────────────────────────────────────────────────────────────────

/**
 * Thrown when the Notary denies the transaction.
 * denialCode and denialMessage come from the Notary — safe to surface to users.
 */
export class VerilockTransactionDeniedError extends VerilockError {
  constructor(
    public readonly denialCode: string,
    public readonly denialMessage: string,
  ) {
    super('DENIED', `[${denialCode}] ${denialMessage}`);
    this.name = 'VerilockTransactionDeniedError';
  }
}

/** Thrown when human approval times out without a decision. */
export class VerilockHumanApprovalTimeoutError extends VerilockError {
  constructor(
    public readonly decisionId: string,
    ms: number,
  ) {
    super('HUMAN_TIMEOUT', `Human approval timed out after ${ms}ms. Decision ID: ${decisionId}`);
    this.name = 'VerilockHumanApprovalTimeoutError';
  }
}

/**
 * Thrown when a Tier 2 transaction is vetoed during the veto window.
 * The transaction has already executed on-chain — this signals that a
 * human reviewer flagged it after the fact.
 */
export class VerilockVetoError extends VerilockError {
  constructor(
    public readonly decisionId: string,
    public readonly vetoWindowSeconds: number,
  ) {
    super(
      'VETOED',
      `Transaction ${decisionId} was vetoed within the ${vetoWindowSeconds}s veto window`,
    );
    this.name = 'VerilockVetoError';
  }
}

/**
 * Thrown when the token expiry is too close to safely submit.
 * The SDK rejects before hitting the chain to avoid a Guard revert.
 */
export class VerilockTokenExpiredError extends VerilockError {
  constructor(
    public readonly tokenId: string,
    public readonly expiresAt: string,
  ) {
    super('TOKEN_EXPIRED', `Token ${tokenId} expires at ${expiresAt} — too close to expiry to submit safely`);
    this.name = 'VerilockTokenExpiredError';
  }
}

// ── VALIDATION ───────────────────────────────────────────────────────────────

/**
 * Thrown when the Notary returns a response that fails Zod validation.
 * Indicates an API version mismatch or malformed response.
 */
export class VerilockValidationError extends VerilockError {
  constructor(public readonly cause: unknown) {
    super('VALIDATION', 'Notary returned an unexpected response shape. Check Notary version.');
    this.name = 'VerilockValidationError';
  }
}

// ── ON-CHAIN ─────────────────────────────────────────────────────────────────

/**
 * Thrown when the Safe transaction reverts on-chain.
 * Indicates a Guard configuration mismatch or the token was already consumed.
 */
export class VerilockOnChainError extends VerilockError {
  constructor(
    public readonly txHash: `0x${string}`,
    public readonly guardError: string,
  ) {
    super('ONCHAIN', `Transaction reverted: ${guardError}. txHash: ${txHash}`);
    this.name = 'VerilockOnChainError';
  }
}