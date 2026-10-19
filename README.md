# Midnight Identity Gateway (MIG)

MIG is an experimental identity- and eligibility-verification infrastructure project on the
[Midnight Network](https://midnight.network/). It centers on a Compact smart contract — the
**Verification Registry V3** — that verifies a narrow, Compact-native issuer-signed credential
profile and gates a one-shot protected action behind a consented, verified request.

> **Status: research / engineering prototype.** Verification is **local-only** against an
> ephemeral test network. This is **not** a production identity provider and has **not** been
> deployed to Preprod or Mainnet.

## Scope and honesty notes

- **Local-only.** Verification runs against an ephemeral, testcontainers-managed local Midnight
  network. No Preprod or Mainnet deployment has been performed.
- **Not production-ready.** The contract and tooling are a working prototype, not audited
  infrastructure.
- **Narrow credential profile.** The contract verifies possession of an issuer-authorized
  **Compact-native Schnorr** credential profile. It does **not** prove real-world identity.
- **No advanced privacy guarantees.** This project does **not** implement selective disclosure,
  unlinkability, or general W3C VC/VP compatibility, and makes no such claims.
- **Preprod path not executed.** The `npm run preprod-registry --prefix bboard-cli` path has not
  been run because a Blockfrost project token and a funded wallet are not configured.

## Architecture

An npm workspaces monorepo:

| Workspace | Purpose |
| --- | --- |
| `contract/` | Compact sources and generated bindings. `src/verification-registry.compact` is the V3 registry; `src/bboard.compact` is a retained bulletin-board reference example (scaffolding); `src/test/` holds the vitest suites, including the adversarial suite. |
| `api/` | Shared types, classes, and helpers used by the CLI and UI. |
| `bboard-cli/` | Command-line interface, local Stage C runner, and the (unrun) Preprod runner. |
| `bboard-ui/` | Browser UI for the bulletin-board reference DApp (Lace wallet). |

## Verification Registry V3 (implemented)

**Request state machine:** `unregistered → PENDING → CONSENTED → VERIFIED → CONSUMED`.
`DECLINED`, `CANCELLED`, `DENIED`, and `CONSUMED` are terminal states.

**Credential status:** `UNKNOWN → ACTIVE → REVOKED` (revocation is irreversible).

**Checks enforced on `decide` / `protectedAction`:**

- Issuer authorization via the upstream `@midnight-ntwrk/credential-compact`
  (`VC::assertAuthorizedIssuerProof`) with Jubjub Schnorr signatures.
- Request-context binding (registry / request / application / subject / purpose / policy digests).
- Holder binding, and binding of the proof challenge to the request id and the proof creation
  time to the credential issuance time.
- Freshness and expiry evaluated against **verifier-supplied time**.
- Credential status must be `ACTIVE`.
- A **one-shot protected action**: increments `protectedActionCount` and moves the request to
  `CONSUMED`.

## Prerequisites

- **Node.js >= 24.11.1** (`.nvmrc` pins `24.11.1`; the contract CI workflow uses Node 24).
- **Docker** — for the local Midnight node/indexer and the proof server.
- **Compact compiler 0.31.1** (`compact`) on `PATH`.
- Proof server image `midnightntwrk/proof-server:8.0.3` (pulled automatically).

## Install

```bash
npm install
```

## Build and test

Compile the Compact contracts (required before building the CLI or UI — generated `managed/`
artifacts are not committed):

```bash
npm run compact --prefix contract
npm run build   --prefix contract
```

Run the contract test suite:

```bash
npm test --prefix contract -- --run      # 58 tests
```

Full contract CI (compact + typecheck + lint + build + test):

```bash
npm run ci --prefix contract
```

CLI CI (typecheck + lint + build):

```bash
npm run ci --prefix bboard-cli
```

## Local end-to-end procedure (Stage C)

Stage C deploys the **current V3 artifacts** to an ephemeral testcontainers local network
(Midnight node + indexer) and exercises the full lifecycle plus adversarial negative cases. It
requires the compiled artifacts from the build step above and a running local proof server.

```bash
# 1. Start the local proof server (http://127.0.0.1:6300)
docker compose -f bboard-cli/proof-server-local.yml up -d

# 2. Run Stage C (spins up an ephemeral node + indexer, then tears them down)
cd bboard-cli
node --experimental-specifier-resolution=node --loader ts-node/esm src/stage-c-registry-local.ts
```

The runner injects the existing proof server on port `6300` (it does not start a second one) and
tears down only its own compose project on exit. It never targets Preprod.

**Behaviors exercised against a real local chain:**

- Valid issuer-signed credential and protected action (successful transactions).
- Altered signed claims / mismatched proof challenge / mismatched request context.
- Expired and not-yet-valid credentials.
- Revocation after approval but before the protected action.
- Unauthorized verifier decisions and unauthorized revocation.
- Repeated protected actions and terminal-state bypass attempts.

### Evidence (current)

- Contract tests: **58 passed** (`vitest`).
- Compact compilation, contract typecheck, lint, and build: **passed**.
- CLI CI (typecheck, lint, build): **passed**.
- Stage C: **deployed and executed** against an ephemeral local testkit network. Successful
  transactions carried `SucceedEntirely` status; all adversarial cases were rejected before
  submission (no failed on-chain transactions).

## Security

Do not commit secrets. The repository excludes `.env*`, `project.md`, generated `managed/`,
`dist/`, logs, local databases, and ZK proving keys. Report vulnerabilities as described in
[SECURITY.md](./SECURITY.md).

## License

See [LICENSE](./LICENSE).
