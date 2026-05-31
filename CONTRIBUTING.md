# Contributing to Tollgate

Thank you for your interest in contributing. Tollgate is financial infrastructure for AI agents — correctness and security are the only priorities. We would rather have one fully verified feature than ten half-tested ones.

---

## Before You Start

Read the architecture documentation first:
- [docs/architecture.md](docs/architecture.md) — how the three components connect
- [docs/policy-reference.md](docs/policy-reference.md) — how the policy engine works

Understand the three-component model (Notary, Guard, SDK) before writing any code. Every contribution must fit cleanly into one component without leaking across boundaries.

---

## Repository Layout

```
core/        ← Go — Notary server, policy engine, ECDSA signing
contracts/   ← Solidity — Guard contract, EIP-712 verification
sdk/         ← TypeScript — developer-facing SDK
docs/        ← Documentation
examples/    ← Working examples
```

Each component has its own language, toolchain, and test suite. Changes to one component must not require changes to another unless you are explicitly bridging the phases (e.g. updating the EIP-712 type hash in both Go and Solidity simultaneously).

---

## Development Setup

### Phase 1 — Core (Go)

```bash
cd core
go version          # requires Go 1.21+
cp .env.example .env
# Fill in TOLLGATE_SIGNING_KEY_HEX and AGENT_TOKEN_SECRET
go run ./cmd/server/main.go
```

### Phase 2 — Contracts (Solidity)

```bash
cd contracts
forge --version     # requires Foundry 1.7+
forge build
forge test -vvvv    # all 22 tests must pass
```

### Phase 3 — SDK (TypeScript)

```bash
cd sdk
node --version      # requires Node 20+
npm install
npm test            # all 30 tests must pass
npx tsc --noEmit    # zero type errors
```

---

## Contribution Rules

### Security first

Any contribution that weakens a security invariant will be rejected regardless of other merits. The invariants are non-negotiable:

- The Notary never holds customer funds or keys
- The Guard always fails closed — no token means no transaction
- Every decision is written to the audit log before any response is sent
- Unknown agents are always denied — there is no default policy
- The signing key never appears in any log or error message

### One thing at a time

Pull requests should do one thing. A PR that adds a feature, refactors a module, and fixes a bug simultaneously is three PRs. Keep them small and reviewable.

### Tests are not optional

- Go: add tests to the relevant `_test.go` file. Run `go test ./...` — must pass.
- Solidity: add tests to `test/TollgateGuard.t.sol`. Run `forge test -vvvv` — must pass.
- TypeScript: add tests to `test/`. Run `npm test` — must pass.

A PR without tests for new behaviour will be returned for tests before review.

### No breaking changes to EIP-712 types

The EIP-712 type hash and domain separator are shared between Phase 1 (Go) and Phase 2 (Solidity). Changing the type string, field order, or field names breaks on-chain verification for every deployed Guard. Any change to the EIP-712 definition requires:

1. Simultaneous update to both `core/internal/signing/approval.go` and `contracts/src/TollgateTypes.sol`
2. A new Guard deployment
3. A migration guide in the PR description

---

## Pull Request Process

1. Fork the repository
2. Create a branch: `git checkout -b feat/your-feature-name`
3. Make your changes with tests
4. Run the full test suite for the affected component
5. Open a PR against `main` with a clear description of what changed and why
6. Wait for review — we review every PR carefully

---

## Reporting Security Issues

**Do not open a public GitHub issue for security vulnerabilities.**

Email security issues directly. Include:
- A description of the vulnerability
- Steps to reproduce
- The potential impact

We will respond within 48 hours and coordinate a fix before any public disclosure.

---

## Code Style

**Go:** `gofmt` — run it before committing. No custom style beyond the standard formatter.

**Solidity:** Follow the existing contract structure. Custom errors over `require` strings. No inline assembly unless absolutely necessary and thoroughly documented.

**TypeScript:** Strict mode. No `any`. No `// @ts-ignore`. If the types are hard to express, the design is probably wrong.

---

## License

By contributing to Tollgate, you agree that your contributions will be licensed under the MIT License.