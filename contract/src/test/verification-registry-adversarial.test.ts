import { ecMulGenerator } from "@midnight-ntwrk/compact-runtime";
import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import { describe, expect, it } from "vitest";
import {
  CredentialStatus,
  RequestState,
  type Proof,
  type SchemaRef,
  pureCircuits,
} from "../managed/verification-registry/contract/index.js";
import { randomBytes } from "./utils.js";
import {
  JUBJUB_SUBGROUP_ORDER,
  createIssuerAuthorization,
  createSignedRegistryCredential,
  randomScalar,
  type RegistryCredential,
} from "./verification-registry-credential-fixtures.js";
import { VerificationRegistrySimulator } from "./verification-registry-simulator.js";

setNetworkId("undeployed");

const createSchema = (): SchemaRef => ({
  packageId: randomBytes(32),
  schemaId: randomBytes(32),
  majorVersion: 1n,
  minorVersion: 0n,
});

const createFixture = () => {
  const schema = createSchema();
  const issuer = createIssuerAuthorization(schema);
  const verifierSecret = randomBytes(32);
  const statusAuthoritySecret = randomBytes(32);
  const registryId = randomBytes(32);
  const simulator = new VerificationRegistrySimulator(
    verifierSecret,
    schema,
    issuer.descriptor,
    statusAuthoritySecret,
    registryId,
  );
  return {
    schema,
    registryId,
    issuer: issuer.descriptor,
    issuerSecret: issuer.secret,
    issuerMethod: issuer.verificationMethodRef,
    verifierSecret,
    statusAuthoritySecret,
    simulator,
  };
};

const createRequest = () => ({
  requestId: randomBytes(32),
  requesterSecret: randomBytes(32),
  subjectSecret: randomBytes(32),
  applicationId: randomBytes(32),
  claimDigest: randomBytes(32),
  purposeDigest: randomBytes(32),
  policyDigest: randomBytes(32),
  statusHandle: randomBytes(32),
  blockTime: 1_000n,
  issuedAt: 950n,
  expiresAt: 1_050n,
  maxCredentialAge: 100n,
});

const register = (
  fixture: ReturnType<typeof createFixture>,
  request: ReturnType<typeof createRequest>,
) => {
  fixture.simulator.useSecretKey(request.requesterSecret);
  fixture.simulator.registerRequest(
    request.requestId,
    request.applicationId,
    pureCircuits.identityKey(request.subjectSecret),
    request.claimDigest,
    request.purposeDigest,
    request.policyDigest,
    request.maxCredentialAge,
  );
};

const consent = (
  fixture: ReturnType<typeof createFixture>,
  request: ReturnType<typeof createRequest>,
) => {
  fixture.simulator.useSecretKey(request.subjectSecret);
  fixture.simulator.consent(
    request.requestId,
    request.applicationId,
    request.claimDigest,
    request.purposeDigest,
    request.policyDigest,
  );
};

const activateStatus = (
  fixture: ReturnType<typeof createFixture>,
  statusHandle: Uint8Array,
) => {
  fixture.simulator.useSecretKey(fixture.statusAuthoritySecret);
  fixture.simulator.activateCredentialStatus(statusHandle);
};

const makeCredentialAndProof = (
  fixture: ReturnType<typeof createFixture>,
  request: ReturnType<typeof createRequest>,
  overrides: {
    registryId?: Uint8Array;
    requestId?: Uint8Array;
    applicationId?: Uint8Array;
    subject?: Uint8Array;
    claimDigest?: Uint8Array;
    purposeDigest?: Uint8Array;
    policyDigest?: Uint8Array;
    schema?: SchemaRef;
    holderBinding?: Uint8Array;
    statusHandle?: Uint8Array;
    issuedAt?: bigint;
    hasExpiration?: boolean;
    expiresAt?: bigint;
    proofChallengeHash?: Uint8Array;
    proofCreatedAt?: bigint;
  } = {},
): { credential: RegistryCredential; proof: Proof } => {
  return createSignedRegistryCredential(
    overrides.schema ?? fixture.schema,
    fixture.issuerSecret,
    fixture.issuerMethod,
    {
      registryId: overrides.registryId ?? fixture.registryId,
      requestId: overrides.requestId ?? request.requestId,
      applicationId: overrides.applicationId ?? request.applicationId,
      subject:
        overrides.subject ?? pureCircuits.identityKey(request.subjectSecret),
      holderBinding: overrides.holderBinding,
      claimDigest: overrides.claimDigest ?? request.claimDigest,
      purposeDigest: overrides.purposeDigest ?? request.purposeDigest,
      policyDigest: overrides.policyDigest ?? request.policyDigest,
      statusHandle: overrides.statusHandle ?? request.statusHandle,
      issuedAt: overrides.issuedAt ?? request.issuedAt,
      hasExpiration: overrides.hasExpiration ?? true,
      expiresAt: overrides.expiresAt ?? request.expiresAt,
      proofChallengeHash: overrides.proofChallengeHash,
      proofCreatedAt: overrides.proofCreatedAt,
    },
  );
};

const decide = (
  fixture: ReturnType<typeof createFixture>,
  request: ReturnType<typeof createRequest>,
  credentialAndProof = makeCredentialAndProof(fixture, request),
  decisionBlockTime = request.blockTime,
) => {
  fixture.simulator.setBlockTime(decisionBlockTime);
  fixture.simulator.useSecretKey(fixture.verifierSecret);
  fixture.simulator.decide(
    request.requestId,
    credentialAndProof.credential,
    credentialAndProof.proof,
  );
};

const setupConsented = (
  fixture = createFixture(),
  request = createRequest(),
) => {
  register(fixture, request);
  consent(fixture, request);
  activateStatus(fixture, request.statusHandle);
  return { fixture, request };
};

const expectRejectedWithoutStateChange = (
  simulator: VerificationRegistrySimulator,
  requestId: Uint8Array,
  operation: () => void,
  error: string,
) => {
  const beforeRequest = simulator.getRequest(requestId);
  const beforeActionCount = simulator.getLedger().protectedActionCount;
  expect(operation).toThrow(`failed assert: ${error}`);
  expect(simulator.getRequest(requestId)).toEqual(beforeRequest);
  expect(simulator.getLedger().protectedActionCount).toEqual(beforeActionCount);
};

describe("Adversarial Security Review — Attack Surface A: Time and Validity", () => {
  it("rejects malformed issuance time with issuedAt = 0", () => {
    const { fixture, request } = setupConsented();
    const zeroIssued = makeCredentialAndProof(fixture, request, {
      issuedAt: 0n,
      expiresAt: 100n,
    });
    fixture.simulator.setBlockTime(50n);
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () => decide(fixture, request, zeroIssued, 50n),
      "Invalid credential issuance time",
    );
  });

  it("rejects not-yet-valid credentials when issued in the future relative to block time", () => {
    const { fixture, request } = setupConsented();
    const futureIssued = makeCredentialAndProof(fixture, request, {
      issuedAt: request.blockTime + 100n,
      expiresAt: request.blockTime + 500n,
    });
    fixture.simulator.setBlockTime(request.blockTime);
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () => decide(fixture, request, futureIssued, request.blockTime),
      "Credential issued in the future",
    );
  });

  it("rejects expired credentials when block time is after expiresAt", () => {
    const { fixture, request } = setupConsented();
    const expired = makeCredentialAndProof(fixture, request, {
      issuedAt: request.blockTime - 10n,
      expiresAt: request.blockTime - 1n,
    });
    fixture.simulator.setBlockTime(request.blockTime);
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () => decide(fixture, request, expired, request.blockTime),
      "Credential expired",
    );
  });

  it("rejects protected action if credential expires between verification and execution", () => {
    const { fixture, request } = setupConsented();
    const credentialAndProof = makeCredentialAndProof(fixture, request, {
      issuedAt: 950n,
      expiresAt: 1_000n,
    });
    // Decided when valid at blockTime = 990n
    decide(fixture, request, credentialAndProof, 990n);
    expect(fixture.simulator.getRequest(request.requestId)?.state).toEqual(
      RequestState.VERIFIED,
    );

    // Time advances past expiry
    fixture.simulator.setBlockTime(1_001n);
    fixture.simulator.useSecretKey(request.subjectSecret);
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () => fixture.simulator.protectedAction(request.requestId),
      "Credential validity period ended",
    );
  });

  it("rejects protected action if maxCredentialAge is exceeded between verification and execution", () => {
    const { fixture, request } = setupConsented();
    // No explicit expiration, valid until issuedAt + maxCredentialAge = 950 + 100 = 1050
    const credentialAndProof = makeCredentialAndProof(fixture, request, {
      issuedAt: 950n,
      hasExpiration: false,
    });
    decide(fixture, request, credentialAndProof, 960n);
    expect(fixture.simulator.getRequest(request.requestId)?.state).toEqual(
      RequestState.VERIFIED,
    );

    // Time advances past maxCredentialAge bound
    fixture.simulator.setBlockTime(1_051n);
    fixture.simulator.useSecretKey(request.subjectSecret);
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () => fixture.simulator.protectedAction(request.requestId),
      "Credential validity period ended",
    );
  });
});

describe("Adversarial Security Review — Attack Surface B: Revocation and State Transitions", () => {
  it("rejects credential revoked after consent but before verifier approval", () => {
    const { fixture, request } = setupConsented();
    // Status authority revokes the credential
    fixture.simulator.useSecretKey(fixture.statusAuthoritySecret);
    fixture.simulator.revokeCredentialStatus(request.statusHandle);

    const credentialAndProof = makeCredentialAndProof(fixture, request);
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () => decide(fixture, request, credentialAndProof),
      "Credential is revoked",
    );
    expect(fixture.simulator.getRequest(request.requestId)?.state).toEqual(
      RequestState.CONSENTED,
    );
  });

  it("rejects protected action when credential was revoked after approval", () => {
    const { fixture, request } = setupConsented();
    decide(fixture, request);
    expect(fixture.simulator.getRequest(request.requestId)?.state).toEqual(
      RequestState.VERIFIED,
    );

    // Status authority revokes the status
    fixture.simulator.useSecretKey(fixture.statusAuthoritySecret);
    fixture.simulator.revokeCredentialStatus(request.statusHandle);

    // Subject attempts protected action
    fixture.simulator.useSecretKey(request.subjectSecret);
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () => fixture.simulator.protectedAction(request.requestId),
      "Credential is revoked",
    );
    expect(fixture.simulator.getLedger().protectedActionCount).toEqual(0n);
  });

  it("rejects unauthorized revocation and unauthorized status activation", () => {
    const fixture = createFixture();
    const handle = randomBytes(32);
    fixture.simulator.useSecretKey(randomBytes(32));

    expect(() => fixture.simulator.activateCredentialStatus(handle)).toThrow(
      "failed assert: Not the status authority",
    );
    expect(() => fixture.simulator.revokeCredentialStatus(handle)).toThrow(
      "failed assert: Not the status authority",
    );
  });

  it("rejects zero status handle on activation and revocation", () => {
    const fixture = createFixture();
    const zeroHandle = new Uint8Array(32);
    fixture.simulator.useSecretKey(fixture.statusAuthoritySecret);

    expect(() =>
      fixture.simulator.activateCredentialStatus(zeroHandle),
    ).toThrow("failed assert: Invalid status handle");
    expect(() => fixture.simulator.revokeCredentialStatus(zeroHandle)).toThrow(
      "failed assert: Invalid status handle",
    );
  });

  it("rejects repeated status revocation and re-activation of revoked handle", () => {
    const fixture = createFixture();
    const handle = randomBytes(32);
    fixture.simulator.useSecretKey(fixture.statusAuthoritySecret);
    fixture.simulator.activateCredentialStatus(handle);

    // First revocation succeeds
    fixture.simulator.revokeCredentialStatus(handle);
    expect(
      fixture.simulator
        .getLedger()
        .credentialStatuses.lookup(
          pureCircuits.credentialStatusCommitment(handle),
        ),
    ).toEqual(CredentialStatus.REVOKED);

    // Repeated revocation fails
    expect(() => fixture.simulator.revokeCredentialStatus(handle)).toThrow(
      "failed assert: Credential status is not active",
    );

    // Attempting to re-activate fails
    expect(() => fixture.simulator.activateCredentialStatus(handle)).toThrow(
      "failed assert: Credential status already initialized",
    );
  });

  it("rejects attempts to bypass terminal states by re-registering request IDs", () => {
    const fixture = createFixture();

    // 1. Decline terminal state
    const reqDecline = createRequest();
    register(fixture, reqDecline);
    fixture.simulator.useSecretKey(reqDecline.subjectSecret);
    fixture.simulator.decline(
      reqDecline.requestId,
      reqDecline.applicationId,
      reqDecline.claimDigest,
      reqDecline.purposeDigest,
      reqDecline.policyDigest,
    );
    expect(fixture.simulator.getRequest(reqDecline.requestId)?.state).toEqual(
      RequestState.DECLINED,
    );
    expect(() => register(fixture, reqDecline)).toThrow(
      "failed assert: Duplicate request ID",
    );

    // 2. Cancel terminal state
    const reqCancel = createRequest();
    register(fixture, reqCancel);
    fixture.simulator.useSecretKey(reqCancel.requesterSecret);
    fixture.simulator.cancel(reqCancel.requestId);
    expect(fixture.simulator.getRequest(reqCancel.requestId)?.state).toEqual(
      RequestState.CANCELLED,
    );
    expect(() => register(fixture, reqCancel)).toThrow(
      "failed assert: Duplicate request ID",
    );

    // 3. Denied terminal state
    const reqDeny = createRequest();
    register(fixture, reqDeny);
    consent(fixture, reqDeny);
    fixture.simulator.useSecretKey(fixture.verifierSecret);
    fixture.simulator.deny(
      reqDeny.requestId,
      reqDeny.applicationId,
      reqDeny.claimDigest,
      reqDeny.purposeDigest,
      reqDeny.policyDigest,
      randomBytes(32),
    );
    expect(fixture.simulator.getRequest(reqDeny.requestId)?.state).toEqual(
      RequestState.DENIED,
    );
    expect(() => register(fixture, reqDeny)).toThrow(
      "failed assert: Duplicate request ID",
    );

    // 4. Consumed terminal state
    const reqConsume = createRequest();
    setupConsented(fixture, reqConsume);
    decide(fixture, reqConsume);
    fixture.simulator.useSecretKey(reqConsume.subjectSecret);
    fixture.simulator.protectedAction(reqConsume.requestId);
    expect(fixture.simulator.getRequest(reqConsume.requestId)?.state).toEqual(
      RequestState.CONSUMED,
    );
    expect(() => register(fixture, reqConsume)).toThrow(
      "failed assert: Duplicate request ID",
    );
  });

  it("rejects invalid state transitions from terminal states", () => {
    const fixture = createFixture();
    const req = createRequest();
    register(fixture, req);
    fixture.simulator.useSecretKey(req.subjectSecret);
    fixture.simulator.decline(
      req.requestId,
      req.applicationId,
      req.claimDigest,
      req.purposeDigest,
      req.policyDigest,
    );

    // Attempt consent on declined request
    expect(() =>
      fixture.simulator.consent(
        req.requestId,
        req.applicationId,
        req.claimDigest,
        req.purposeDigest,
        req.policyDigest,
      ),
    ).toThrow("failed assert: Request is not pending");

    // Attempt decide on declined request
    const cred = makeCredentialAndProof(fixture, req);
    fixture.simulator.useSecretKey(fixture.verifierSecret);
    expect(() =>
      fixture.simulator.decide(req.requestId, cred.credential, cred.proof),
    ).toThrow("failed assert: Request is not consented");

    // Attempt protectedAction on declined request
    fixture.simulator.useSecretKey(req.subjectSecret);
    expect(() => fixture.simulator.protectedAction(req.requestId)).toThrow(
      "failed assert: Request is not verified",
    );
  });
});

describe("Adversarial Security Review — Attack Surface C: Signature and Context Binding", () => {
  it("rejects issuer proof with mismatched challengeHash", () => {
    const { fixture, request } = setupConsented();
    const foreignChallengeHash = randomBytes(32);
    const corrupted = makeCredentialAndProof(fixture, request, {
      proofChallengeHash: foreignChallengeHash,
    });
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () => decide(fixture, request, corrupted),
      "Proof challenge hash mismatch",
    );
  });

  it("rejects issuer proof with mismatched createdAt", () => {
    const { fixture, request } = setupConsented();
    const foreignCreatedAt = request.issuedAt + 10n;
    const corrupted = makeCredentialAndProof(fixture, request, {
      proofCreatedAt: foreignCreatedAt,
    });
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () => decide(fixture, request, corrupted),
      "Proof creation time mismatch",
    );
  });

  it("rejects single-field alteration of every security-relevant field", () => {
    const { fixture, request } = setupConsented();
    const signed = makeCredentialAndProof(fixture, request);

    // 1. Schema fields
    expect(() =>
      decide(fixture, request, {
        credential: {
          ...signed.credential,
          schema: { ...signed.credential.schema, packageId: randomBytes(32) },
        },
        proof: signed.proof,
      }),
    ).toThrow();

    expect(() =>
      decide(fixture, request, {
        credential: {
          ...signed.credential,
          schema: { ...signed.credential.schema, schemaId: randomBytes(32) },
        },
        proof: signed.proof,
      }),
    ).toThrow();

    expect(() =>
      decide(fixture, request, {
        credential: {
          ...signed.credential,
          schema: {
            ...signed.credential.schema,
            majorVersion: signed.credential.schema.majorVersion + 1n,
          },
        },
        proof: signed.proof,
      }),
    ).toThrow();

    expect(() =>
      decide(fixture, request, {
        credential: {
          ...signed.credential,
          schema: {
            ...signed.credential.schema,
            minorVersion: signed.credential.schema.minorVersion + 1n,
          },
        },
        proof: signed.proof,
      }),
    ).toThrow();

    // 2. Issuer verification method ref
    expect(() =>
      decide(fixture, request, {
        credential: {
          ...signed.credential,
          issuerVerificationMethodRef: {
            ...signed.credential.issuerVerificationMethodRef,
            methodId: randomBytes(32),
          },
        },
        proof: signed.proof,
      }),
    ).toThrow();

    // 3. Holder binding
    expect(() =>
      decide(fixture, request, {
        credential: {
          ...signed.credential,
          holderBinding: randomBytes(32),
        },
        proof: signed.proof,
      }),
    ).toThrow();

    // 4. Status binding
    expect(() =>
      decide(fixture, request, {
        credential: {
          ...signed.credential,
          statusBinding: randomBytes(32),
        },
        proof: signed.proof,
      }),
    ).toThrow();

    // 5. Claim root tampering
    expect(() =>
      decide(fixture, request, {
        credential: {
          ...signed.credential,
          claimRoot: randomBytes(32),
        },
        proof: signed.proof,
      }),
    ).toThrow();

    // 6. Signature r tampering
    expect(() =>
      decide(fixture, request, {
        credential: signed.credential,
        proof: {
          ...signed.proof,
          signature: {
            ...signed.proof.signature,
            r: ecMulGenerator(randomScalar()),
          },
        },
      }),
    ).toThrow();

    // 7. Signature s tampering
    expect(() =>
      decide(fixture, request, {
        credential: signed.credential,
        proof: {
          ...signed.proof,
          signature: {
            ...signed.proof.signature,
            s: (signed.proof.signature.s + 1n) % JUBJUB_SUBGROUP_ORDER,
          },
        },
      }),
    ).toThrow();

    // 8. Signer verification method in proof
    expect(() =>
      decide(fixture, request, {
        credential: signed.credential,
        proof: {
          ...signed.proof,
          signerVerificationMethodRef: {
            ...signed.proof.signerVerificationMethodRef,
            methodId: randomBytes(32),
          },
        },
      }),
    ).toThrow();

    // State remains CONSENTED throughout
    expect(fixture.simulator.getRequest(request.requestId)?.state).toEqual(
      RequestState.CONSENTED,
    );
  });

  it("rejects signature reused across different requests", () => {
    const { fixture, request: requestA } = setupConsented();
    const signedA = makeCredentialAndProof(fixture, requestA);

    const requestB = createRequest();
    register(fixture, requestB);
    consent(fixture, requestB);
    activateStatus(fixture, requestB.statusHandle);

    // Attempting to present requestA's credential and proof for requestB
    expectRejectedWithoutStateChange(
      fixture.simulator,
      requestB.requestId,
      () => decide(fixture, requestB, signedA),
      "Credential request ID mismatch",
    );
  });
});

describe("Adversarial Security Review — Attack Surface D: Replay, Authorization, and Privacy", () => {
  it("rejects cross-contract replay of credentials", () => {
    const { fixture: fixtureA, request } = setupConsented();
    const signedForA = makeCredentialAndProof(fixtureA, request);

    // Separate registry instance B
    const fixtureB = createFixture();
    register(fixtureB, request);
    consent(fixtureB, request);
    activateStatus(fixtureB, request.statusHandle);

    expect(() => decide(fixtureB, request, signedForA)).toThrow(
      "failed assert: Credential registry mismatch",
    );
    expect(fixtureB.simulator.getRequest(request.requestId)?.state).toEqual(
      RequestState.CONSENTED,
    );
  });

  it("rejects repeated finalization (decide on already VERIFIED request)", () => {
    const { fixture, request } = setupConsented();
    const valid = makeCredentialAndProof(fixture, request);
    decide(fixture, request, valid);
    expect(fixture.simulator.getRequest(request.requestId)?.state).toEqual(
      RequestState.VERIFIED,
    );

    // Replay decide
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () => decide(fixture, request, valid),
      "Request is not consented",
    );
  });

  it("rejects repeated protected action (protectedAction on already CONSUMED request)", () => {
    const { fixture, request } = setupConsented();
    decide(fixture, request);
    fixture.simulator.useSecretKey(request.subjectSecret);
    fixture.simulator.protectedAction(request.requestId);
    expect(fixture.simulator.getRequest(request.requestId)?.state).toEqual(
      RequestState.CONSUMED,
    );

    // Repeated action attempt
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () => fixture.simulator.protectedAction(request.requestId),
      "Request is not verified",
    );
    expect(fixture.simulator.getLedger().protectedActionCount).toEqual(1n);
  });

  it("strictly enforces caller authorization for all state transitions", () => {
    const fixture = createFixture();
    const req = createRequest();
    register(fixture, req);

    const unauthorizedSecret = randomBytes(32);

    // 1. Consent requires subject key
    fixture.simulator.useSecretKey(unauthorizedSecret);
    expect(() =>
      fixture.simulator.consent(
        req.requestId,
        req.applicationId,
        req.claimDigest,
        req.purposeDigest,
        req.policyDigest,
      ),
    ).toThrow("failed assert: Not the subject");

    // 2. Decline requires subject key
    expect(() =>
      fixture.simulator.decline(
        req.requestId,
        req.applicationId,
        req.claimDigest,
        req.purposeDigest,
        req.policyDigest,
      ),
    ).toThrow("failed assert: Not the subject");

    // 3. Cancel requires requester key
    expect(() => fixture.simulator.cancel(req.requestId)).toThrow(
      "failed assert: Not the requester",
    );

    // Consent legitimately
    consent(fixture, req);
    activateStatus(fixture, req.statusHandle);

    // 4. Decide requires verifier key
    const credAndProof = makeCredentialAndProof(fixture, req);
    fixture.simulator.useSecretKey(unauthorizedSecret);
    expect(() =>
      fixture.simulator.decide(
        req.requestId,
        credAndProof.credential,
        credAndProof.proof,
      ),
    ).toThrow("failed assert: Not the verifier");

    // 5. Deny requires verifier key
    expect(() =>
      fixture.simulator.deny(
        req.requestId,
        req.applicationId,
        req.claimDigest,
        req.purposeDigest,
        req.policyDigest,
        randomBytes(32),
      ),
    ).toThrow("failed assert: Not the verifier");

    // Decide legitimately
    decide(fixture, req, credAndProof);

    // 6. ProtectedAction requires subject key
    fixture.simulator.useSecretKey(unauthorizedSecret);
    expect(() => fixture.simulator.protectedAction(req.requestId)).toThrow(
      "failed assert: Not the subject",
    );
  });

  it("verifies privacy guarantees: raw claims, signatures, and unhashed status handles are not stored in contract state", () => {
    const { fixture, request } = setupConsented();
    const { credential, proof } = makeCredentialAndProof(fixture, request);
    decide(fixture, request, { credential, proof });

    const record = fixture.simulator.getRequest(request.requestId);
    expect(record).toBeDefined();

    // Sensitive credential payloads are NOT stored in the request record
    expect(record).not.toHaveProperty("claims");
    expect(record).not.toHaveProperty("credential");
    expect(record).not.toHaveProperty("signature");
    expect(record).not.toHaveProperty("rawEvidence");

    // Only hashed status handle commitment is stored
    expect(record?.credentialStatusHandle).toEqual(
      pureCircuits.credentialStatusCommitment(request.statusHandle),
    );
    expect(record?.credentialStatusHandle).not.toEqual(request.statusHandle);

    // Only canonical credential body root is stored
    expect(record?.evidenceDigest).toEqual(
      pureCircuits.credentialBodyRoot(credential),
    );
  });
});
