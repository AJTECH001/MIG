import { ecMulGenerator } from "@midnight-ntwrk/compact-runtime";
import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import { describe, expect, it } from "vitest";
import {
  AuthorizationState,
  CredentialStatus,
  RequestState,
  SignerRole,
  VerificationProtocolVersion,
  VerificationRelationship,
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

describe("Verification Registry v3 credential protocol", () => {
  it("publishes V3 and registers a unique request with a bounded freshness policy", () => {
    const fixture = createFixture();
    const request = createRequest();
    register(fixture, request);

    expect(fixture.simulator.getLedger().protocolVersion).toEqual(
      VerificationProtocolVersion.V3,
    );
    expect(fixture.simulator.getRequest(request.requestId)).toMatchObject({
      requester: pureCircuits.identityKey(request.requesterSecret),
      subject: pureCircuits.identityKey(request.subjectSecret),
      applicationId: request.applicationId,
      claimDigest: request.claimDigest,
      purposeDigest: request.purposeDigest,
      policyDigest: request.policyDigest,
      maxCredentialAge: request.maxCredentialAge,
      state: RequestState.PENDING,
    });

    const before = fixture.simulator.getRequest(request.requestId);
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () =>
        fixture.simulator.registerRequest(
          request.requestId,
          request.applicationId,
          pureCircuits.identityKey(request.subjectSecret),
          request.claimDigest,
          request.purposeDigest,
          request.policyDigest,
          request.maxCredentialAge,
        ),
      "Duplicate request ID",
    );
    expect(fixture.simulator.getRequest(request.requestId)).toEqual(before);
  });

  it("rejects empty request context and zero maximum age", () => {
    const fixture = createFixture();
    const request = createRequest();
    fixture.simulator.useSecretKey(request.requesterSecret);
    const valid = [
      request.requestId,
      request.applicationId,
      pureCircuits.identityKey(request.subjectSecret),
      request.claimDigest,
      request.purposeDigest,
      request.policyDigest,
      request.maxCredentialAge,
    ] as const;

    for (const [index, error] of [
      "Invalid request ID",
      "Invalid application ID",
      "Invalid subject",
      "Invalid claim digest",
      "Invalid purpose digest",
      "Invalid policy digest",
    ].entries()) {
      const args: [...typeof valid] = [...valid];
      args[index] = new Uint8Array(32);
      expect(() => fixture.simulator.registerRequest(...args)).toThrow(
        `failed assert: ${error}`,
      );
      expect(fixture.simulator.getLedger().requests.size()).toEqual(0n);
    }

    const zeroAge: [...typeof valid] = [...valid];
    zeroAge[6] = 0n;
    expect(() => fixture.simulator.registerRequest(...zeroAge)).toThrow(
      "failed assert: Invalid maximum credential age",
    );
    expect(fixture.simulator.getLedger().requests.size()).toEqual(0n);
  });

  it("pins an active issuer descriptor to this credential schema", () => {
    const fixture = createFixture();
    const verifierSecret = randomBytes(32);
    expect(
      () =>
        new VerificationRegistrySimulator(
          verifierSecret,
          fixture.schema,
          {
            ...fixture.issuer,
            role: SignerRole.verifier,
            verificationRelationship: VerificationRelationship.authentication,
          },
          randomBytes(32),
          randomBytes(32),
        ),
    ).toThrow("failed assert: Authorization must be an issuer");
    expect(
      () =>
        new VerificationRegistrySimulator(
          verifierSecret,
          fixture.schema,
          { ...fixture.issuer, state: AuthorizationState.revoked },
          randomBytes(32),
          randomBytes(32),
        ),
    ).toThrow("failed assert: Issuer must be active");
    expect(
      () =>
        new VerificationRegistrySimulator(
          verifierSecret,
          fixture.schema,
          { ...fixture.issuer, scopeCommitment: randomBytes(32) },
          randomBytes(32),
          randomBytes(32),
        ),
    ).toThrow("failed assert: Issuer schema scope mismatch");
  });

  it("requires the subject key and exact context for consent and decline", () => {
    const fixture = createFixture();
    const request = createRequest();
    register(fixture, request);

    fixture.simulator.useSecretKey(randomBytes(32));
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () =>
        fixture.simulator.consent(
          request.requestId,
          request.applicationId,
          request.claimDigest,
          request.purposeDigest,
          request.policyDigest,
        ),
      "Not the subject",
    );

    fixture.simulator.useSecretKey(request.subjectSecret);
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () =>
        fixture.simulator.consent(
          request.requestId,
          randomBytes(32),
          request.claimDigest,
          request.purposeDigest,
          request.policyDigest,
        ),
      "Application mismatch",
    );
    consent(fixture, request);
    expect(fixture.simulator.getRequest(request.requestId)?.state).toEqual(
      RequestState.CONSENTED,
    );

    const declined = createRequest();
    register(fixture, declined);
    fixture.simulator.useSecretKey(declined.subjectSecret);
    fixture.simulator.decline(
      declined.requestId,
      declined.applicationId,
      declined.claimDigest,
      declined.purposeDigest,
      declined.policyDigest,
    );
    expect(fixture.simulator.getRequest(declined.requestId)?.state).toEqual(
      RequestState.DECLINED,
    );
    expectRejectedWithoutStateChange(
      fixture.simulator,
      declined.requestId,
      () =>
        fixture.simulator.consent(
          declined.requestId,
          declined.applicationId,
          declined.claimDigest,
          declined.purposeDigest,
          declined.policyDigest,
        ),
      "Request is not pending",
    );
  });

  it("allows only the requester to cancel a pending request", () => {
    const fixture = createFixture();
    const request = createRequest();
    register(fixture, request);
    fixture.simulator.useSecretKey(randomBytes(32));
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () => fixture.simulator.cancel(request.requestId),
      "Not the requester",
    );
    fixture.simulator.useSecretKey(request.requesterSecret);
    fixture.simulator.cancel(request.requestId);
    expect(fixture.simulator.getRequest(request.requestId)?.state).toEqual(
      RequestState.CANCELLED,
    );
  });

  it("allows the status authority to activate once and revoke irreversibly", () => {
    const fixture = createFixture();
    const statusHandle = randomBytes(32);
    fixture.simulator.useSecretKey(randomBytes(32));
    expect(() =>
      fixture.simulator.activateCredentialStatus(statusHandle),
    ).toThrow("failed assert: Not the status authority");
    fixture.simulator.useSecretKey(fixture.statusAuthoritySecret);
    fixture.simulator.activateCredentialStatus(statusHandle);
    expect(
      fixture.simulator
        .getLedger()
        .credentialStatuses.lookup(
          pureCircuits.credentialStatusCommitment(statusHandle),
        ),
    ).toEqual(CredentialStatus.ACTIVE);
    expect(() =>
      fixture.simulator.activateCredentialStatus(statusHandle),
    ).toThrow("failed assert: Credential status already initialized");
    fixture.simulator.revokeCredentialStatus(statusHandle);
    expect(
      fixture.simulator
        .getLedger()
        .credentialStatuses.lookup(
          pureCircuits.credentialStatusCommitment(statusHandle),
        ),
    ).toEqual(CredentialStatus.REVOKED);
    expect(() =>
      fixture.simulator.revokeCredentialStatus(statusHandle),
    ).toThrow("failed assert: Credential status is not active");
    expect(() =>
      fixture.simulator.activateCredentialStatus(randomBytes(32)),
    ).not.toThrow();
  });

  it("accepts an issuer-signed credential bound to request, policy, subject, and active status", () => {
    const { fixture, request } = setupConsented();
    const { credential, proof } = makeCredentialAndProof(fixture, request);
    decide(fixture, request, { credential, proof });

    expect(fixture.simulator.getRequest(request.requestId)).toMatchObject({
      evidenceDigest: pureCircuits.credentialBodyRoot(credential),
      credentialStatusHandle: pureCircuits.credentialStatusCommitment(
        request.statusHandle,
      ),
      state: RequestState.VERIFIED,
    });
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () => decide(fixture, request, { credential, proof }),
      "Request is not consented",
    );
  });

  it("rejects a modified issuer signature and preserves consent state", () => {
    const { fixture, request } = setupConsented();
    const signed = makeCredentialAndProof(fixture, request);
    const corrupted = {
      ...signed,
      proof: {
        ...signed.proof,
        signature: {
          ...signed.proof.signature,
          s: (signed.proof.signature.s + 1n) % JUBJUB_SUBGROUP_ORDER,
        },
      },
    };
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () => decide(fixture, request, corrupted),
      "Signature verification failed",
    );
  });

  it("rejects a credential proof from a different issuer key", () => {
    const { fixture, request } = setupConsented();
    const signed = makeCredentialAndProof(fixture, request);
    const wrongIssuer = {
      ...signed,
      proof: {
        ...signed.proof,
        publicKey: ecMulGenerator(randomScalar()),
      },
    };
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () => decide(fixture, request, wrongIssuer),
      "Jubjub points do not match",
    );
  });

  it("rejects post-signature changes to credential envelope fields", () => {
    const { fixture, request } = setupConsented();
    const signed = makeCredentialAndProof(fixture, request);
    const changedCredentials: RegistryCredential[] = [
      { ...signed.credential, version: signed.credential.version + 1n },
      {
        ...signed.credential,
        holderBinding: pureCircuits.identityKey(randomBytes(32)),
      },
      { ...signed.credential, statusBinding: randomBytes(32) },
      { ...signed.credential, issuedAt: signed.credential.issuedAt + 1n },
      { ...signed.credential, hasExpiration: false },
      { ...signed.credential, expiresAt: signed.credential.expiresAt + 1n },
    ];

    for (const credential of changedCredentials) {
      expect(() =>
        decide(fixture, request, { credential, proof: signed.proof }),
      ).toThrow();
      expect(fixture.simulator.getRequest(request.requestId)?.state).toEqual(
        RequestState.CONSENTED,
      );
    }
  });

  it("rejects credentials bound to another request context or subject", () => {
    const { fixture, request } = setupConsented();
    const wrongContexts = [
      [{ registryId: randomBytes(32) }, "Credential registry mismatch"],
      [{ requestId: randomBytes(32) }, "Credential request ID mismatch"],
      [{ applicationId: randomBytes(32) }, "Credential application mismatch"],
      [
        { subject: pureCircuits.identityKey(randomBytes(32)) },
        "Credential subject mismatch",
      ],
      [{ claimDigest: randomBytes(32) }, "Credential claim digest mismatch"],
      [
        { purposeDigest: randomBytes(32) },
        "Credential purpose digest mismatch",
      ],
      [{ policyDigest: randomBytes(32) }, "Credential policy digest mismatch"],
      [
        { holderBinding: pureCircuits.identityKey(randomBytes(32)) },
        "Credential holder binding mismatch",
      ],
    ] as const;

    for (const [overrides, error] of wrongContexts) {
      const invalid = makeCredentialAndProof(fixture, request, overrides);
      expectRejectedWithoutStateChange(
        fixture.simulator,
        request.requestId,
        () => decide(fixture, request, invalid),
        error,
      );
    }
  });

  it("rejects wrong schema, unknown status, and revoked status", () => {
    const { fixture, request } = setupConsented();
    const wrongSchema = makeCredentialAndProof(fixture, request, {
      schema: createSchema(),
    });
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () => decide(fixture, request, wrongSchema),
      "Schema reference mismatch",
    );

    const unknownStatusRequest = createRequest();
    register(fixture, unknownStatusRequest);
    consent(fixture, unknownStatusRequest);
    const unknownStatus = makeCredentialAndProof(fixture, unknownStatusRequest);
    expectRejectedWithoutStateChange(
      fixture.simulator,
      unknownStatusRequest.requestId,
      () => decide(fixture, unknownStatusRequest, unknownStatus),
      "Credential status is unknown",
    );

    const revokedRequest = createRequest();
    register(fixture, revokedRequest);
    consent(fixture, revokedRequest);
    activateStatus(fixture, revokedRequest.statusHandle);
    fixture.simulator.useSecretKey(fixture.statusAuthoritySecret);
    fixture.simulator.revokeCredentialStatus(revokedRequest.statusHandle);
    const revoked = makeCredentialAndProof(fixture, revokedRequest);
    expectRejectedWithoutStateChange(
      fixture.simulator,
      revokedRequest.requestId,
      () => decide(fixture, revokedRequest, revoked),
      "Credential is revoked",
    );
  });

  it("rejects a credential revoked before subject consent", () => {
    const fixture = createFixture();
    const request = createRequest();
    register(fixture, request);
    activateStatus(fixture, request.statusHandle);
    fixture.simulator.useSecretKey(fixture.statusAuthoritySecret);
    fixture.simulator.revokeCredentialStatus(request.statusHandle);
    consent(fixture, request);
    const revoked = makeCredentialAndProof(fixture, request);

    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () => decide(fixture, request, revoked),
      "Credential is revoked",
    );
  });

  it("enforces issuance freshness and inclusive expiration boundaries against verifier time", () => {
    const { fixture, request } = setupConsented();
    const atMaxAge = makeCredentialAndProof(fixture, request, {
      issuedAt: request.blockTime - request.maxCredentialAge,
      expiresAt: request.blockTime,
    });
    decide(fixture, request, atMaxAge);
    expect(fixture.simulator.getRequest(request.requestId)?.state).toEqual(
      RequestState.VERIFIED,
    );

    const old = createRequest();
    register(fixture, old);
    consent(fixture, old);
    activateStatus(fixture, old.statusHandle);
    const tooOld = makeCredentialAndProof(fixture, old, {
      issuedAt: old.blockTime - old.maxCredentialAge - 1n,
    });
    expectRejectedWithoutStateChange(
      fixture.simulator,
      old.requestId,
      () => decide(fixture, old, tooOld),
      "Credential is too old",
    );

    const expired = createRequest();
    register(fixture, expired);
    consent(fixture, expired);
    activateStatus(fixture, expired.statusHandle);
    const pastExpiry = makeCredentialAndProof(fixture, expired, {
      expiresAt: expired.blockTime - 1n,
    });
    expectRejectedWithoutStateChange(
      fixture.simulator,
      expired.requestId,
      () => decide(fixture, expired, pastExpiry),
      "Credential expired",
    );

    const future = createRequest();
    register(fixture, future);
    consent(fixture, future);
    activateStatus(fixture, future.statusHandle);
    const futureIssued = makeCredentialAndProof(fixture, future, {
      issuedAt: future.blockTime + 1n,
      expiresAt: future.blockTime + 10n,
    });
    expectRejectedWithoutStateChange(
      fixture.simulator,
      future.requestId,
      () => decide(fixture, future, futureIssued),
      "Credential issued in the future",
    );
  });

  it("rejects protected actions after the approved credential expires", () => {
    const { fixture, request } = setupConsented();
    const credentialAndProof = makeCredentialAndProof(fixture, request);

    fixture.simulator.setBlockTime(request.expiresAt - 1n);
    decide(fixture, request, credentialAndProof, request.expiresAt - 1n);
    fixture.simulator.setBlockTime(request.expiresAt + 1n);
    fixture.simulator.useSecretKey(request.subjectSecret);

    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () => fixture.simulator.protectedAction(request.requestId),
      "Credential validity period ended",
    );
  });

  it("rejects stale credentials using current block time, not verifier input", () => {
    const { fixture, request } = setupConsented();
    const staleCredential = makeCredentialAndProof(fixture, request, {
      issuedAt: request.blockTime - 200n,
      expiresAt: request.blockTime - 100n,
    });
    fixture.simulator.setBlockTime(request.blockTime);
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () => decide(fixture, request, staleCredential),
      "Credential is too old",
    );

    expect(fixture.simulator.getRequest(request.requestId)?.state).toEqual(
      RequestState.CONSENTED,
    );
  });

  it("rejects protected actions after the maximum credential age", () => {
    const { fixture, request } = setupConsented();
    const credentialAndProof = makeCredentialAndProof(fixture, request, {
      issuedAt: request.blockTime,
      expiresAt: request.blockTime + 1_000n,
    });
    decide(
      fixture,
      request,
      credentialAndProof,
      request.blockTime + request.maxCredentialAge,
    );
    fixture.simulator.setBlockTime(
      request.blockTime + request.maxCredentialAge + 1n,
    );
    fixture.simulator.useSecretKey(request.subjectSecret);

    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () => fixture.simulator.protectedAction(request.requestId),
      "Credential validity period ended",
    );
  });

  it("fails closed when credential freshness arithmetic exceeds Uint<64>", () => {
    const { fixture, request } = setupConsented();
    const maxUint64 = (1n << 64n) - 1n;
    const credentialAndProof = makeCredentialAndProof(fixture, request, {
      issuedAt: maxUint64 - 50n,
      expiresAt: maxUint64,
    });
    const before = fixture.simulator.getRequest(request.requestId);
    expect(() =>
      decide(fixture, request, credentialAndProof, maxUint64 - 10n),
    ).toThrow();
    expect(fixture.simulator.getRequest(request.requestId)).toEqual(before);
  });

  it("rejects issuer evidence replayed into another registry instance", () => {
    const { fixture, request } = setupConsented();
    const credentialAndProof = makeCredentialAndProof(fixture, request);
    const otherVerifierSecret = randomBytes(32);
    const otherStatusAuthoritySecret = randomBytes(32);
    const otherRegistryId = randomBytes(32);
    const otherSimulator = new VerificationRegistrySimulator(
      otherVerifierSecret,
      fixture.schema,
      fixture.issuer,
      otherStatusAuthoritySecret,
      otherRegistryId,
    );
    const otherFixture = {
      ...fixture,
      verifierSecret: otherVerifierSecret,
      statusAuthoritySecret: otherStatusAuthoritySecret,
      simulator: otherSimulator,
    };
    register(otherFixture, request);
    consent(otherFixture, request);
    activateStatus(otherFixture, request.statusHandle);

    otherSimulator.useSecretKey(otherVerifierSecret);
    otherSimulator.setBlockTime(request.blockTime);
    expect(() =>
      otherSimulator.decide(
        request.requestId,
        credentialAndProof.credential,
        credentialAndProof.proof,
      ),
    ).toThrow("failed assert: Credential registry mismatch");
    expect(otherSimulator.getRequest(request.requestId)?.state).toEqual(
      RequestState.CONSENTED,
    );
  });

  it("requires verifier key possession and rejects decisions outside CONSENTED", () => {
    const { fixture, request } = setupConsented();
    const valid = makeCredentialAndProof(fixture, request);
    fixture.simulator.useSecretKey(randomBytes(32));
    fixture.simulator.setBlockTime(request.blockTime);
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () =>
        fixture.simulator.decide(
          request.requestId,
          valid.credential,
          valid.proof,
        ),
      "Not the verifier",
    );

    const pending = createRequest();
    register(fixture, pending);
    activateStatus(fixture, pending.statusHandle);
    const pendingCredential = makeCredentialAndProof(fixture, pending);
    fixture.simulator.useSecretKey(fixture.verifierSecret);
    fixture.simulator.setBlockTime(pending.blockTime);
    expectRejectedWithoutStateChange(
      fixture.simulator,
      pending.requestId,
      () =>
        fixture.simulator.decide(
          pending.requestId,
          pendingCredential.credential,
          pendingCredential.proof,
        ),
      "Request is not consented",
    );
  });

  it("permits an authorized denial but never enables a protected action", () => {
    const { fixture, request } = setupConsented();
    fixture.simulator.useSecretKey(fixture.verifierSecret);
    fixture.simulator.deny(
      request.requestId,
      request.applicationId,
      request.claimDigest,
      request.purposeDigest,
      request.policyDigest,
      randomBytes(32),
    );
    expect(fixture.simulator.getRequest(request.requestId)?.state).toEqual(
      RequestState.DENIED,
    );
    fixture.simulator.useSecretKey(request.subjectSecret);
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () => fixture.simulator.protectedAction(request.requestId),
      "Request is not verified",
    );
  });

  it("allows only the subject to consume a verified request and rechecks revocation", () => {
    const { fixture, request } = setupConsented();
    decide(fixture, request);
    fixture.simulator.useSecretKey(randomBytes(32));
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () => fixture.simulator.protectedAction(request.requestId),
      "Not the subject",
    );

    fixture.simulator.useSecretKey(fixture.statusAuthoritySecret);
    fixture.simulator.revokeCredentialStatus(request.statusHandle);
    fixture.simulator.useSecretKey(request.subjectSecret);
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () => fixture.simulator.protectedAction(request.requestId),
      "Credential is revoked",
    );
    expect(fixture.simulator.getLedger().protectedActionCount).toEqual(0n);
  });

  it("consumes approval exactly once and rejects protected action for non-verified states", () => {
    const { fixture, request } = setupConsented();
    decide(fixture, request);
    fixture.simulator.useSecretKey(request.subjectSecret);
    fixture.simulator.protectedAction(request.requestId);
    expect(fixture.simulator.getRequest(request.requestId)?.state).toEqual(
      RequestState.CONSUMED,
    );
    expect(fixture.simulator.getLedger().protectedActionCount).toEqual(1n);
    expectRejectedWithoutStateChange(
      fixture.simulator,
      request.requestId,
      () => fixture.simulator.protectedAction(request.requestId),
      "Request is not verified",
    );
  });

  it("stores only commitments and status metadata, never raw credential claims or proofs", () => {
    const { fixture, request } = setupConsented();
    const { credential, proof } = makeCredentialAndProof(fixture, request);
    decide(fixture, request, { credential, proof });

    const record = fixture.simulator.getRequest(request.requestId);
    expect(record).toBeDefined();
    expect(record).not.toHaveProperty("claims");
    expect(record).not.toHaveProperty("credential");
    expect(record).not.toHaveProperty("signature");
    expect(record).not.toHaveProperty("rawEvidence");
    expect(record?.credentialStatusHandle).toEqual(
      pureCircuits.credentialStatusCommitment(request.statusHandle),
    );
    expect(record?.credentialStatusHandle).not.toEqual(request.statusHandle);
    expect(record?.evidenceDigest).toEqual(
      pureCircuits.credentialBodyRoot(credential),
    );
    expect(fixture.simulator.getLedger().issuerAuthorization).toEqual(
      fixture.issuer,
    );
  });
});
