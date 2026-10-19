import { randomBytes as nodeRandomBytes } from "node:crypto";
import { ecMulGenerator } from "@midnight-ntwrk/compact-runtime";
import {
  AuthorizationState,
  SignerRole,
  VerificationRelationship,
  type AuthorizedSignerDescriptor,
  type Proof,
  type SchemaRef,
  type VerificationMethodRef,
  pureCircuits,
} from "../managed/verification-registry/contract/index.js";

export const JUBJUB_SUBGROUP_ORDER =
  6554484396890773809930967563523245729705921265872317281365359162392183254199n;

export type RegistryCredential = Parameters<
  typeof pureCircuits.credentialBodyRoot
>[0];

export type CredentialInput = {
  registryId: Uint8Array;
  requestId: Uint8Array;
  applicationId: Uint8Array;
  subject: Uint8Array;
  holderBinding?: Uint8Array;
  claimDigest: Uint8Array;
  purposeDigest: Uint8Array;
  policyDigest: Uint8Array;
  statusHandle: Uint8Array;
  issuedAt: bigint;
  hasExpiration: boolean;
  expiresAt: bigint;
  proofCreatedAt?: bigint;
  proofChallengeHash?: Uint8Array;
};

const randomBytes = (size: number) => new Uint8Array(nodeRandomBytes(size));

export const randomScalar = () =>
  (BigInt(`0x${Buffer.from(randomBytes(32)).toString("hex")}`) %
    (JUBJUB_SUBGROUP_ORDER - 1n)) +
  1n;

export const createIssuerAuthorization = (schema: SchemaRef) => {
  const secret = randomScalar();
  const verificationMethodRef: VerificationMethodRef = {
    controllerAddress: { bytes: randomBytes(32) },
    methodId: randomBytes(32),
  };
  const descriptor: AuthorizedSignerDescriptor = {
    version: 1n,
    authorizationId: randomBytes(32),
    decisionSequence: 1n,
    state: AuthorizationState.active,
    role: SignerRole.issuer,
    signerVerificationMethodRef: verificationMethodRef,
    signerPublicKey: ecMulGenerator(secret),
    didStateVersion: 1n,
    verificationRelationship: VerificationRelationship.assertionMethod,
    scopeCommitment: pureCircuits.issuerScopeCommitment(schema),
    policyCommitment: randomBytes(32),
  };
  return { descriptor, secret, verificationMethodRef };
};

export const createSignedRegistryCredential = (
  schema: SchemaRef,
  issuerSecret: bigint,
  issuerMethod: VerificationMethodRef,
  input: CredentialInput,
): { credential: RegistryCredential; proof: Proof } => {
  const claims = {
    registryId: input.registryId,
    requestId: input.requestId,
    applicationId: input.applicationId,
    subject: input.subject,
    claimDigest: input.claimDigest,
    purposeDigest: input.purposeDigest,
    policyDigest: input.policyDigest,
  };
  const credential: RegistryCredential = {
    version: 1n,
    schema,
    issuerVerificationMethodRef: issuerMethod,
    holderBinding: input.holderBinding ?? input.subject,
    statusBinding: input.statusHandle,
    issuedAt: input.issuedAt,
    hasExpiration: input.hasExpiration,
    expiresAt: input.expiresAt,
    claims,
    claimCommitments: {},
    claimRoot: pureCircuits.credentialClaimRoot(claims),
  };
  const nonce = randomScalar();
  const unsignedProof: Proof = {
    signerVerificationMethodRef: issuerMethod,
    createdAt: input.proofCreatedAt ?? input.issuedAt,
    challengeHash: input.proofChallengeHash ?? input.requestId,
    publicKey: ecMulGenerator(issuerSecret),
    signature: {
      r: ecMulGenerator(nonce),
      s: 0n,
    },
  };
  const challenge = pureCircuits.issuanceProofChallenge(
    pureCircuits.credentialBodyRoot(credential),
    unsignedProof,
  );
  const proof: Proof = {
    ...unsignedProof,
    signature: {
      ...unsignedProof.signature,
      s: (nonce + challenge * issuerSecret) % JUBJUB_SUBGROUP_ORDER,
    },
  };
  return { credential, proof };
};
