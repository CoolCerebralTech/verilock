/**
 * @file index.ts
 * TollgateSigner — the only class a developer needs to import.
 *
 * Design note on viem clients:
 *   viem 2.x Base/OP Stack chains include deposit transaction types that
 *   create a type mismatch when storing PublicClient/WalletClient as class
 *   properties with generic types. The clean solution is to not store viem
 *   clients as properties — create them per-call from stored config.
 *   This is the correct pattern for an SDK library (no long-lived connections).
 *
 * Design note on Safe signatures:
 *   Gnosis Safe's checkNSignatures expects signatures over the RAW 32-byte
 *   Safe transaction hash — no EIP-191 prefix, no EIP-712 wrapper.
 *   Use account.sign({ hash }) (raw signing) NOT account.signMessage() which
 *   prepends "\x19Ethereum Signed Message:\n32" and produces a signature the
 *   Safe rejects with GS026.
 *
 *   This SDK supports threshold=1 Safes (single owner).
 *   Multi-owner Safes require the Safe SDK for signature collection.
 */

import {
  createWalletClient,
  createPublicClient,
  http,
  parseAbi,
  formatEther,
  type Hash,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { baseSepolia, base }   from 'viem/chains';

import { TollgateClient }      from './api.js';
import { injectTollgateToken } from './encoder.js';
import {
  type TollgateConfig,
  type TxRequest,
  type ActionRequest,
  type NotaryResponse,
  BASE_SEPOLIA_CHAIN_ID,
  BASE_MAINNET_CHAIN_ID,
} from './types.js';
import {
  TollgateConfigError,
  TollgateTransactionDeniedError,
  TollgateTokenExpiredError,
  TollgateOnChainError,
  TollgateNetworkError,
} from './errors.js';

// ── GNOSIS SAFE ABI (minimal) ─────────────────────────────────────────────────

const SAFE_ABI = parseAbi([
  'function execTransaction(address to, uint256 value, bytes calldata data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address payable refundReceiver, bytes memory signatures) public payable returns (bool)',
  'function nonce() public view returns (uint256)',
  'function getTransactionHash(address to, uint256 value, bytes calldata data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address payable refundReceiver, uint256 _nonce) public view returns (bytes32)',
]);

const ZERO_ADDR = '0x0000000000000000000000000000000000000000' as const;

function selectChain(useMainnet: boolean | undefined) {
  return useMainnet ? base : baseSepolia;
}

// ── TOLLGATE SIGNER ───────────────────────────────────────────────────────────

export class TollgateSigner {
  private readonly config: TollgateConfig;
  private readonly chainId: number;
  private readonly notaryClient: TollgateClient;

  private constructor(config: TollgateConfig) {
    this.config       = config;
    this.chainId      = config.useMainnet ? BASE_MAINNET_CHAIN_ID : BASE_SEPOLIA_CHAIN_ID;
    this.notaryClient = new TollgateClient(
      config.notaryUrl,
      config.agentToken,
      config.notaryTimeoutMs ?? 10_000,
      config.maxRetries      ?? 3,
    );
  }

  private _publicClient() {
    return createPublicClient({
      chain:     selectChain(this.config.useMainnet),
      transport: http(),
    });
  }

  private _walletClient() {
    return createWalletClient({
      account:   privateKeyToAccount(this.config.ownerPrivateKey),
      chain:     selectChain(this.config.useMainnet),
      transport: http(),
    });
  }

  // ── FACTORY ──────────────────────────────────────────────────────────────────

  /**
   * Creates a TollgateSigner after validating config and health-checking
   * the Notary. Always use this — the constructor is private.
   *
   * @throws TollgateConfigError             if any required field is missing
   * @throws TollgateNotaryUnreachableError  if the Notary is not reachable
   */
  static async create(config: TollgateConfig): Promise<TollgateSigner> {
    if (!config.notaryUrl)       throw new TollgateConfigError('notaryUrl is required');
    if (!config.agentToken)      throw new TollgateConfigError('agentToken is required');
    if (!config.agentId)         throw new TollgateConfigError('agentId is required');
    if (!config.safeAddress)     throw new TollgateConfigError('safeAddress is required');
    if (!config.ownerPrivateKey) throw new TollgateConfigError('ownerPrivateKey is required');
    if (!config.notaryUrl.startsWith('http')) {
      throw new TollgateConfigError('notaryUrl must start with http:// or https://');
    }
    const signer = new TollgateSigner(config);
    await signer.notaryClient.healthCheck();
    return signer;
  }

  // ── SEND TRANSACTION ─────────────────────────────────────────────────────────

  /**
   * Requests Notary approval, encodes the token into calldata, and submits
   * through the Gnosis Safe. Handles all three tiers transparently.
   *
   * Tier 1 — auto-approved:             submits immediately, no callback.
   * Tier 2 — approved_with_notification: submits immediately, fires
   *   onApprovedWithNotification with the veto window duration.
   * Tier 3 — pending_human:             polls until approved or timeout.
   *
   * @throws TollgateTransactionDeniedError    Notary denied the request
   * @throws TollgateHumanApprovalTimeoutError Tier 3 timed out
   * @throws TollgateTokenExpiredError         Token expired before submission
   * @throws TollgateOnChainError              Safe transaction reverted
   */
  async sendTransaction(params: TxRequest): Promise<Hash> {
    // ── Step 1: Validate purpose ──────────────────────────────────────────────
    const purpose = params.purpose ?? this.config.defaultPurpose ?? '';
    if (!purpose) {
      throw new TollgateConfigError(
        'purpose is required — set it on TxRequest or TollgateConfig.defaultPurpose',
      );
    }

    // ── Step 2: Build ActionRequest ───────────────────────────────────────────
    const request: ActionRequest = {
      agent_id:    this.config.agentId,
      action:      'transfer',
      destination: params.to,
      amount_usd:  params.amountUsd,
      amount_raw:  params.value.toString(),
      purpose,
      chain_id:    this.chainId,
      nonce:       crypto.randomUUID(),
      timestamp:   new Date().toISOString(),
    };

    // ── Step 3: Request Notary approval ───────────────────────────────────────
    let response: NotaryResponse = await this.notaryClient.requestApproval(request);

    // ── Step 4: Handle denial ─────────────────────────────────────────────────
    if (response.status === 'denied') {
      throw new TollgateTransactionDeniedError(response.code, response.message);
    }

    // ── Step 5: Tier 3 — poll for human approval ──────────────────────────────
    if (response.status === 'pending_human') {
      this.config.onPendingHumanApproval?.(response.decision_id);

      // Use the server-provided poll_interval_seconds first,
      // falling back to config default only if the field is absent.
      const pollIntervalMs = response.poll_interval_seconds > 0
        ? response.poll_interval_seconds * 1_000
        : (this.config.humanApprovalPollIntervalMs ?? 3_000);

      response = await this.notaryClient.pollDecision(
        response.poll_url,
        pollIntervalMs,
        this.config.humanApprovalTimeoutMs ?? 300_000,
      );

      if (response.status === 'denied') {
        throw new TollgateTransactionDeniedError(response.code, response.message);
      }
      if (response.status === 'approved' || response.status === 'approved_with_notification') {
        this.config.onHumanApprovalReceived?.(response.decision_id);
      }
    }

    // ── Step 6: Tier 2 — fire notification callback ───────────────────────────
    // Transaction executes immediately. The Notary already sent the notification.
    // Fire the callback so the developer can show the veto countdown UI.
    if (response.status === 'approved_with_notification') {
      this.config.onApprovedWithNotification?.(
        response.decision_id,
        response.veto_window_seconds,
      );
    }

    // ── Step 7: Guard — only approved statuses should reach here ─────────────
    if (response.status !== 'approved' && response.status !== 'approved_with_notification') {
      throw new TollgateTransactionDeniedError(
        'UNKNOWN',
        `Unexpected Notary status: ${response.status}`,
      );
    }

    const token = response.approval_token;

    // ── Step 8: Token expiry buffer ───────────────────────────────────────────
    const bufferSec = this.config.tokenExpiryBufferSeconds ?? 10;
    const expiresIn = new Date(token.expires_at).getTime() / 1000 - Date.now() / 1000;
    if (expiresIn < bufferSec) {
      throw new TollgateTokenExpiredError(token.token_id, token.expires_at);
    }

    // ── Step 9: Inject token into calldata ────────────────────────────────────
    const modifiedData = injectTollgateToken(params.data, token);

    // ── Step 10: Viem clients ─────────────────────────────────────────────────
    const publicClient = this._publicClient();
    const walletClient = this._walletClient();
    const account      = privateKeyToAccount(this.config.ownerPrivateKey);

    // ── Step 11: Preflight — Safe ETH balance ─────────────────────────────────
    if (params.value > 0n) {
      const safeBalance = await publicClient.getBalance({
        address: this.config.safeAddress,
      });
      if (safeBalance < params.value) {
        throw new TollgateNetworkError(
          null,
          `Safe ${this.config.safeAddress} has insufficient balance: ` +
          `has ${formatEther(safeBalance)} ETH, needs ${formatEther(params.value)} ETH`,
        );
      }
    }

    // ── Step 12: Safe nonce ───────────────────────────────────────────────────
    const safeNonce = await publicClient.readContract({
      address:      this.config.safeAddress,
      abi:          SAFE_ABI,
      functionName: 'nonce',
    });

    // ── Step 13: Safe transaction hash ────────────────────────────────────────
    const safeTxHash = await publicClient.readContract({
      address:      this.config.safeAddress,
      abi:          SAFE_ABI,
      functionName: 'getTransactionHash',
      args: [
        params.to, params.value, modifiedData,
        0, 0n, 0n, 0n,
        ZERO_ADDR, ZERO_ADDR,
        safeNonce,
      ],
    });

    // ── Step 14: Sign raw Safe transaction hash ───────────────────────────────
    // CRITICAL: account.sign({ hash }) signs the raw bytes — no EIP-191 prefix.
    // account.signMessage() would prepend "\x19Ethereum Signed Message:\n32"
    // and produce a signature Gnosis Safe rejects with GS026.
    const sig = await account.sign({
      hash: safeTxHash as `0x${string}`,
    });

    // ── Step 15: Submit execTransaction ──────────────────────────────────────
    const txHash = await walletClient.writeContract({
      address:      this.config.safeAddress,
      abi:          SAFE_ABI,
      functionName: 'execTransaction',
      args: [
        params.to, params.value, modifiedData,
        0, 0n, 0n, 0n,
        ZERO_ADDR, ZERO_ADDR,
        sig,
      ],
    });

    // ── Step 16: Wait for receipt ─────────────────────────────────────────────
    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
    if (receipt.status === 'reverted') {
      throw new TollgateOnChainError(txHash, 'Transaction reverted — check Guard configuration');
    }

    return txHash;
  }

  // ── SIMULATE ──────────────────────────────────────────────────────────────────

  /**
   * Calls the Notary and returns the decision without submitting on-chain.
   * Useful for testing policy rules and previewing which tier applies.
   */
  async simulate(params: TxRequest): Promise<NotaryResponse> {
    const purpose = params.purpose ?? this.config.defaultPurpose ?? '';
    const request: ActionRequest = {
      agent_id:    this.config.agentId,
      action:      'transfer',
      destination: params.to,
      amount_usd:  params.amountUsd,
      amount_raw:  params.value.toString(),
      purpose,
      chain_id:    this.chainId,
      nonce:       crypto.randomUUID(),
      timestamp:   new Date().toISOString(),
    };
    return this.notaryClient.requestApproval(request);
  }

  /** Returns the Safe address this signer is configured for. */
  getAddress(): `0x${string}` { return this.config.safeAddress; }

  /** Returns the chain ID (84532 = Base Sepolia, 8453 = Base Mainnet). */
  getChainId(): number { return this.chainId; }
}

// ── PUBLIC EXPORTS ────────────────────────────────────────────────────────────

export type {
  TollgateConfig,
  TxRequest,
  ApprovalToken,
  NotaryResponse,
} from './types.js';
export * from './errors.js';