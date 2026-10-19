import {
  type CircuitContext,
  CostModel,
  createConstructorContext,
  QueryContext,
} from "@midnight-ntwrk/compact-runtime";
import {
  Contract,
  type AuthorizedSignerDescriptor,
  type Ledger,
  type Proof,
  type SchemaRef,
  ledger,
  pureCircuits,
} from "../managed/verification-registry/contract/index.js";
import {
  type VerificationRegistryPrivateState,
  witnesses,
} from "../verification-registry-witnesses.js";

export class VerificationRegistrySimulator {
  readonly contract: Contract<VerificationRegistryPrivateState>;
  circuitContext: CircuitContext<VerificationRegistryPrivateState>;
  readonly schema: SchemaRef;

  constructor(
    verifierSecretKey: Uint8Array,
    schema: SchemaRef,
    issuer: AuthorizedSignerDescriptor,
    statusAuthoritySecretKey: Uint8Array,
    registryId: Uint8Array,
  ) {
    this.contract = new Contract<VerificationRegistryPrivateState>(witnesses);
    this.schema = schema;
    const verifierCommitment = pureCircuits.identityKey(verifierSecretKey);
    const {
      currentPrivateState,
      currentContractState,
      currentZswapLocalState,
    } = this.contract.initialState(
      createConstructorContext(
        { secretKey: verifierSecretKey },
        "0".repeat(64),
      ),
      verifierCommitment,
      schema,
      issuer,
      pureCircuits.identityKey(statusAuthoritySecretKey),
    );
    const contractAddress = Array.from(registryId, (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
    this.circuitContext = {
      currentPrivateState,
      currentZswapLocalState,
      costModel: CostModel.initialCostModel(),
      currentQueryContext: new QueryContext(
        currentContractState.data,
        contractAddress,
      ),
    };
  }

  static identityKey(secretKey: Uint8Array): Uint8Array {
    return pureCircuits.identityKey(secretKey);
  }

  useSecretKey(secretKey: Uint8Array): void {
    this.circuitContext.currentPrivateState = { secretKey };
  }

  setBlockTime(timestamp: bigint): void {
    const block = this.circuitContext.currentQueryContext.block;
    this.circuitContext.currentQueryContext.block = {
      ...block,
      secondsSinceEpoch: timestamp,
      lastBlockTime: timestamp,
    };
  }

  getLedger(): Ledger {
    return ledger(this.circuitContext.currentQueryContext.state);
  }

  getRequest(requestId: Uint8Array) {
    const currentLedger = this.getLedger();
    return currentLedger.requests.member(requestId)
      ? currentLedger.requests.lookup(requestId)
      : undefined;
  }

  registerRequest(
    requestId: Uint8Array,
    applicationId: Uint8Array,
    subject: Uint8Array,
    claimDigest: Uint8Array,
    purposeDigest: Uint8Array,
    policyDigest: Uint8Array,
    maxCredentialAge: bigint,
  ): void {
    this.circuitContext = this.contract.impureCircuits.registerRequest(
      this.circuitContext,
      requestId,
      applicationId,
      subject,
      claimDigest,
      purposeDigest,
      policyDigest,
      maxCredentialAge,
    ).context;
  }

  consent(
    requestId: Uint8Array,
    applicationId: Uint8Array,
    claimDigest: Uint8Array,
    purposeDigest: Uint8Array,
    policyDigest: Uint8Array,
  ): void {
    this.circuitContext = this.contract.impureCircuits.consent(
      this.circuitContext,
      requestId,
      applicationId,
      claimDigest,
      purposeDigest,
      policyDigest,
    ).context;
  }

  decline(
    requestId: Uint8Array,
    applicationId: Uint8Array,
    claimDigest: Uint8Array,
    purposeDigest: Uint8Array,
    policyDigest: Uint8Array,
  ): void {
    this.circuitContext = this.contract.impureCircuits.decline(
      this.circuitContext,
      requestId,
      applicationId,
      claimDigest,
      purposeDigest,
      policyDigest,
    ).context;
  }

  cancel(requestId: Uint8Array): void {
    this.circuitContext = this.contract.impureCircuits.cancel(
      this.circuitContext,
      requestId,
    ).context;
  }

  activateCredentialStatus(statusHandle: Uint8Array): void {
    this.circuitContext = this.contract.impureCircuits.activateCredentialStatus(
      this.circuitContext,
      statusHandle,
    ).context;
  }

  revokeCredentialStatus(statusHandle: Uint8Array): void {
    this.circuitContext = this.contract.impureCircuits.revokeCredentialStatus(
      this.circuitContext,
      statusHandle,
    ).context;
  }

  decide(
    requestId: Uint8Array,
    credential: Parameters<typeof pureCircuits.credentialBodyRoot>[0],
    proof: Proof,
  ): void {
    this.circuitContext = this.contract.impureCircuits.decide(
      this.circuitContext,
      requestId,
      credential,
      proof,
    ).context;
  }

  deny(
    requestId: Uint8Array,
    applicationId: Uint8Array,
    claimDigest: Uint8Array,
    purposeDigest: Uint8Array,
    policyDigest: Uint8Array,
    evidenceDigest: Uint8Array,
  ): void {
    this.circuitContext = this.contract.impureCircuits.deny(
      this.circuitContext,
      requestId,
      applicationId,
      claimDigest,
      purposeDigest,
      policyDigest,
      evidenceDigest,
    ).context;
  }

  protectedAction(requestId: Uint8Array): void {
    this.circuitContext = this.contract.impureCircuits.protectedAction(
      this.circuitContext,
      requestId,
    ).context;
  }
}
