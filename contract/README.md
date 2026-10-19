# Verification Registry Contract

## V3 purpose and boundary

The Verification Registry V3 is a narrow Compact-native credential-verification profile and authorization state machine. It verifies one pinned issuer's Jubjub Schnorr signature over a canonical credential body, binds signed claims to a consented request, checks a status handle controlled by a configured authority, and consumes a successful decision once for the subject's protected action.

It is not a general W3C Verifiable Credential/Presentation implementation, a real-world identity verifier, an issuer trust network, a legal-compliance policy engine, a holder-presentation proof, or a selective-disclosure system. A valid issuer signature proves only that the configured issuer key signed this profile's message. It does not prove the issuer performed sound identity proofing or that the claim is true.

## Toolchain and upstream Compact core

The contract pins `@midnight-ntwrk/credential-compact@0.3.0`, whose published package manifest declares Compact compiler `0.31.1` and runtime `0.16.0`, matching the generated Registry artifacts. The package is labelled `supported`, maturity `core`, but is pre-1.0. Its upstream README version guidance is stale: it describes `0.2.0` as stable and `0.3.0-rc1` as the candidate, whereas the published manifest/changelog and npm `latest` report `0.3.0`. The normative core specification remains a `0.2-draft`.

The Registry composes the official `credentials/composable.compact` root and calls its `VC::assertAuthorizedIssuerProof` path. This enforces the canonical credential-body root, issuance-context Schnorr signature, issuer verification-method reference, active issuer descriptor, issuer role, and schema scope. It does not import the optional Midnight DID adapter, establish a global issuer trust root, or provide time/status/policy services. Compact's include resolver does not accept a bare npm package-name include; source includes the installed package's `dist` composition root via the workspace-relative `node_modules` path.

The target-network compatibility matrix lists Compact launcher `0.5.1`; the installed global launcher is `0.5.3`. Validation used the checksum-verified `0.5.1` launcher without modifying the global installation. Compiler/runtime versions are `0.31.1`/`0.16.0`. The workspace requires Node.js `>=24.11.1`; validation used already-installed Node.js `25.8.0`.

## Constructor and protocol

The constructor takes four arguments:

1. `verifierKey`: 32-byte `identityKey` commitment for the verifier.
2. `schema`: pinned `SchemaRef` (package ID, schema ID, major and minor versions).
3. `issuer`: active `AuthorizedSignerDescriptor` with issuer role and scope matching the schema.
4. `statusAuthorityKey`: 32-byte `identityKey` commitment for the status authority.

The three authorities are immutable for this contract instance. The deployment operator selects them; the contract does not independently prove that any authority is reputable.

The signed `RegistryClaims` contains the exact `requestId`, `applicationId`, subject key commitment, `claimDigest`, `purposeDigest`, and `policyDigest`. The VC envelope additionally binds a schema, issuance/optional expiration timestamps, holder-binding commitment, status handle, claim root, and credential version. The issuer's proof signs the canonical credential body in the package's issuance context. The synthetic signer in tests and Stage C uses only ephemeral test secrets.

Lifecycle:

```text
unregistered --registerRequest(id, app, subject, claim, purpose, policy, maxAge)--> PENDING
PENDING --consent(exact request context; subject key)--> CONSENTED
PENDING --decline(exact request context; subject key)--> DECLINED
PENDING --cancel(requestId; requester key)--> CANCELLED
UNKNOWN status --activateCredentialStatus(handle; status authority key)--> ACTIVE
ACTIVE status --revokeCredentialStatus(handle; status authority key)--> REVOKED
CONSENTED --decide(signed credential, issuer proof, verifierTime; verifier key)--> VERIFIED
CONSENTED --deny(exact context, evidence digest; verifier key)--> DENIED
VERIFIED --protectedAction(requestId; subject key, ACTIVE status)--> CONSUMED
```

`decide` verifies the credential envelope and exact claim/request context, then checks `issuedAt <= verifierTime`, `verifierTime - issuedAt <= maxCredentialAge`, and, when present, `expiresAt >= verifierTime`. The request's maximum age must be positive. Status must have been activated by the configured authority before a credential can be accepted. Revocation is irreversible and checked both at decision and protected action. `deny` is a verifier-authorized negative decision; it does not validate a credential and cannot authorize an action.

**Time limitation:** `verifierTime` is supplied by the configured verifier. Compact/runtime in this pinned toolchain does not expose a trusted wall-clock timestamp in this contract. Therefore the circuit enforces the mathematical age/expiry boundaries only relative to the verifier's assertion; a compromised verifier can backdate or lie. Expiry is not rechecked at the later protected-action call. Do not describe this as trustless freshness or continuous expiry enforcement.

**Status limitation:** the configured status authority can activate arbitrary nonzero handles and revoke active handles. It is a trust input, not a decentralized status registry or authenticated external status list. Status is read from this contract's own ledger.

## Public state and privacy boundary

Public state includes protocol version, verifier commitment, issuer descriptor and public key, schema, status-authority commitment, request ID, subject commitment, application/claim/purpose/policy digests, maximum age, request state, credential-body root, status-handle commitment, status state, and protected-action counter. These fields and transaction metadata may be linkable. Low-entropy hashes can be guessed.

The request record does not store raw credential claims, credential envelope, signature, or raw status handle. The test asserts those fields are absent and checks that only the credential-body root and hashed status handle are present. This is a ledger-state test, not a proof that transaction inputs, network metadata, or proving infrastructure cannot leak sensitive values. Do not put personal data, identity documents, biometrics, private keys, or seed material into inputs or logs.

## Source, generated artifacts, and tests

- Compact source: `src/verification-registry.compact`
- Generated bindings/proving artifacts: `src/managed/verification-registry/`
- Witness and compiled export: `src/verification-registry-witnesses.ts`, `src/verification-registry-index.ts`
- Simulator and credential test signer: `src/test/verification-registry-simulator.ts`, `src/test/verification-registry-credential-fixtures.ts`
- Registry tests: `src/test/verification-registry.test.ts`
- Proof-backed local runner: `../bboard-cli/src/stage-c-registry-local.ts`

The test-only signer uses Compact runtime Jubjub point arithmetic and the package's exported issuance challenge circuit to make synthetic Schnorr signatures. Simulator tests execute generated Compact circuits; these are not TypeScript mocks. BBoard remains separate and its original 13 tests are retained.

Validated commands from the repository root:

```sh
PATH=/usr/local/opt/node@24/bin:/path/to/compact-0.5.1:$PATH npm run ci --prefix contract
PATH=/usr/local/opt/node@24/bin:$PATH npm run ci --prefix bboard-cli
```

The contract CI compiled 2 BBoard circuits and 9 Registry circuits, then passed typecheck, lint, build, and all **30 tests** (17 Registry, 13 BBoard). CLI CI typecheck, lint, and build passed. The lockfile was updated only for the pinned credential core dependency. No generated file was manually edited.

## Proof-backed local-node execution (Stage C V3)

Run from the repository root after confirming the existing local proof server is healthy:

```sh
curl --fail http://127.0.0.1:6300/health
cd bboard-cli
node --experimental-specifier-resolution=node --loader ts-node/esm src/stage-c-registry-local.ts
```

The runner injects the existing `proof-server-local` at port 6300; it does not start another proof server. It starts a unique testkit node/indexer Compose project, waits for indexer `/ready` HTTP 200, then deploys and exercises the registry. Its `finally` block stops only the Compose project it created. The testkit local network is ephemeral and is not Preprod.

Verified infrastructure: existing proof server `GET /health` returned `{"status":"ok",...}`. The runner completed with exit code 0. Successful proof-backed operations were submitted to and finalized by the local node (`SucceedEntirely`); the indexer read the final ledger. Deployment address and transaction identifiers are ephemeral evidence for that run and have no explorer link.

| Operation | Result | Transaction ID | Block |
|---|---|---|---:|
| Deploy V3 Registry | `SucceedEntirely` | `00d4a94eae629a8460385eaad2a60d63f282f11af5674accd88491d3d79508690c` | — |
| Register main request | `SucceedEntirely` | `0027f8dbb26f3bbd9015cd31d3f42dbac9826bab951c7ea8b6654a77e6ba3f85d3` | 15 |
| Register pending request | `SucceedEntirely` | `0001f85106978cb3ce7d2f9d23a165be40659fce6497694eba52c01e024b076aae` | 20 |
| Register cancellation request | `SucceedEntirely` | `001fce3c9445a54a7516988522195eb8532db7e9ba7ca9294de26be880f4b9f2c0` | 25 |
| Register denial request | `SucceedEntirely` | `007102a05ea0020eababb2f69ecae693ebbdb6b2a5ddba5fec2d2e459fe8c9bfa2` | 30 |
| Register revocation request | `SucceedEntirely` | `000a9bf7b0c4112f619ae43dfb0bd80bbb27ecf616dfe36dac3bd020982b4ca04b` | 34 |
| Activate main credential status | `SucceedEntirely` | `000358ed3fc7dc452a9da80aca725bac5bec90f3fc0f3ba9cf5ff5310b58b417b9` | 39 |
| Activate revocation-test status | `SucceedEntirely` | `00c3cdbc52f3b48eedf09089392d5d88b79574c4b720f59c1ce2bbf0e7176f9035` | 44 |
| Subject consent | `SucceedEntirely` | `00b37fd653e8df878e85e870f6fac285e205de0ef0011dd58d8fb4eef69457879e` | 49 |
| Valid issuer-signed decision | `SucceedEntirely` | `00760e020739902450d184a11d40719420b5cdd24c68dd29ed476f1ec6de40f9d8` | 91 |
| Subject protected action | `SucceedEntirely` | `00bc98b78fcf841ea6887d22f165b30fa709bd78f0fb2f9d30f507f119fe487ab3` | 97 |
| Decline pending request | `SucceedEntirely` | `007f186d1d1139f9e7a5569ebdd5d7e9c022352a37cf2c2e0e94fbc1fa0344a26c` | 103 |
| Cancel pending request | `SucceedEntirely` | `00904b2677c0dbd53c33c7996fae1ee8c7514af53ee45d003350387cf158640b94` | 108 |
| Consent to denial request | `SucceedEntirely` | `001bc744518eb0c7db695ba09c93722febb9f44727261fc4728be54a81e3ad8ee2` | 113 |
| Verifier denial | `SucceedEntirely` | `00203255cde95d20dbe1753bfaf8307475e605fa594543b6a4441e0b9c967d7d94` | 118 |
| Consent to revoked-credential request | `SucceedEntirely` | `004f59c7f0324c7eec83c9b8125bc01153f7999b12191fbc39c72329f333213161` | 123 |
| Revoke credential status | `SucceedEntirely` | `0003ccd56d4c96bf7a52c57c2fc2b91774a88d8661765fb382e30f44c2b0ff1671` | 128 |

Final indexer-observed state: main request `CONSUMED`; decline request `DECLINED`; cancellation request `CANCELLED`; denial request `DENIED`; revoked-credential request remained `CONSENTED`; its status was `REVOKED`; `protectedActionCount` was `1`.

The following attempts failed during local proving, before submission, and therefore have no failed on-chain transaction ID:

| Attempt | Rejection | Observed state |
|---|---|---|
| Decision with unauthorized verifier key | `Not the verifier` | Main request remained `CONSENTED` |
| Tampered issuer Schnorr signature | `Signature verification failed` | Main request remained `CONSENTED` |
| Protected action while pending | `Request is not verified` | Request remained `PENDING` |
| Repeated action after consumption | `Request is not verified` | Main request remained `CONSUMED`; count remained 1 |
| Protected action after decline | `Request is not verified` | Request remained `DECLINED` |
| Protected action after denial | `Request is not verified` | Request remained `DENIED` |
| Decision with revoked credential status | `Credential is revoked` | Request remained `CONSENTED`; status remained `REVOKED` |

These results establish testkit proof generation and execution on an ephemeral local node for the defined synthetic profile. They do not establish a Preprod deployment.

## Preprod status and prerequisites

No Preprod service was contacted and no deployment was attempted in this V3 run. `BLOCKFROST_PROJECT_ID` and `MIDNIGHT_WALLET_SEED_FILE` were absent. Wallet funding was therefore not checked.

The separate command is `npm run preprod-registry --prefix bboard-cli`; the existing `npm run preprod-remote --prefix bboard-cli` continues to deploy BBoard only. Before running the Registry command, configure locally:

- `BLOCKFROST_PROJECT_ID`: a Blockfrost project token enabled for Midnight Preprod. Keep the token in a local secret manager or environment; do not paste it into chat or commit it.
- `MIDNIGHT_WALLET_SEED_FILE`: path to a file outside the repository containing exactly 64 hexadecimal characters for a test-only Preprod wallet seed; restrict permissions to owner read/write (`chmod 600`). Never put a seed in a command argument, source, committed `.env`, or chat.
- Fund that test wallet with Preprod NIGHT and DUST. The runner checks both balances before deployment. Faucet access and wallet funding are user-controlled actions; the runner does not fund the wallet or generate DUST automatically.

The official [Preprod compatibility matrix](https://docs.midnight.network/relnotes/support-matrix#preprod-support-matrix) lists launcher `0.5.1`, compiler `0.31.1`, runtime `0.16.0`, Midnight.js/testkit `4.1.1`, Wallet SDK `1.2.0`, and proof server `8.1.3`. No mainnet deployment is supported or authorized by this work.
