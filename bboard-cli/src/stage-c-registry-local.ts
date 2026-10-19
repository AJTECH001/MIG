import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import pino from 'pino';
import {
  EnvironmentConfiguration,
  IndexerClient,
  LocalTestEnvironment,
  MidnightWalletProvider,
  NodeClient,
  ProofServerClient,
  inMemoryPrivateStateProvider,
} from '@midnight-ntwrk/testkit-js';
import { DockerComposeEnvironment, Wait, type StartedDockerComposeEnvironment } from 'testcontainers';
import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { deployContract } from '@midnight-ntwrk/midnight-js-contracts';
import { indexerPublicDataProvider } from '@midnight-ntwrk/midnight-js-indexer-public-data-provider';
import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import { NodeZkConfigProvider } from '@midnight-ntwrk/midnight-js-node-zk-config-provider';
import { SucceedEntirely } from '@midnight-ntwrk/midnight-js-types';
import {
  CompiledVerificationRegistryContractContract,
  VerificationRegistryPrivateState,
} from '../../contract/src/verification-registry-index.js';
import {
  CredentialStatus,
  RequestState,
  ledger,
  pureCircuits,
  type SchemaRef,
} from '../../contract/src/managed/verification-registry/contract/index.js';
import {
  createIssuerAuthorization,
  createSignedRegistryCredential,
} from '../../contract/src/test/verification-registry-credential-fixtures.js';

const privateStateId = 'stage-c-verification-registry';
const randomSecret = () => new Uint8Array(randomBytes(32));
const logger = pino({ level: 'silent' });
const environment = new LocalTestEnvironment(logger);
const composeUid = `stagec-${process.pid}-${Buffer.from(randomBytes(4)).toString('hex')}`;
const currentTime = () => BigInt(Math.floor(Date.now() / 1000));
const maxCredentialAge = 86_400n;
const loggerLabel = (state: RequestState) => RequestState[state];

setNetworkId('undeployed');

const assertSuccessful = async (label: string, transaction: Promise<unknown>) => {
  const finalized = (await transaction) as {
    public: { status: string; txId: string; blockHeight?: bigint };
  };
  assert.equal(finalized.public.status, SucceedEntirely, `${label} did not succeed`);
  console.log(
    JSON.stringify({
      operation: label,
      outcome: finalized.public.status,
      txId: finalized.public.txId,
      blockHeight: finalized.public.blockHeight?.toString(),
    }),
  );
};

const expectRejected = async (label: string, expectedAssertion: string, operation: () => Promise<unknown>) => {
  try {
    await operation();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    assert.ok(message.includes(expectedAssertion), `${label} failed unexpectedly: ${message}`);
    console.log(
      JSON.stringify({
        operation: label,
        outcome: 'REJECTED_BEFORE_SUBMISSION',
        expectedAssertion,
        transactionId: null,
      }),
    );
    return;
  }
  throw new Error(`${label} unexpectedly succeeded`);
};

let dockerEnv: StartedDockerComposeEnvironment | undefined;
let environmentInitialized = false;
try {
  dockerEnv = await new DockerComposeEnvironment(process.cwd(), 'compose-local-chain.yml')
    .withProjectName(`mig-stage-c-${process.pid}`)
    .withEnvironment({
      TESTCONTAINERS_UID: composeUid,
      NETWORK_ID: 'undeployed',
    })
    .withWaitStrategy(`node_${composeUid}`, Wait.forHealthCheck())
    .withWaitStrategy(
      `indexer_${composeUid}`,
      Wait.forHttp('/ready', 8088).forStatusCode(200).withStartupTimeout(180_000),
    )
    .up();
  const config = (await environment.startWithInjectedEnvironment(dockerEnv, {
    node: dockerEnv.getContainer(`node_${composeUid}`).getMappedPort(9944),
    indexer: dockerEnv.getContainer(`indexer_${composeUid}`).getMappedPort(8088),
    proofServer: 6300,
  })) as EnvironmentConfiguration;
  environmentInitialized = true;
  const healthChecks = await Promise.all([
    new NodeClient(config.node, logger).health(),
    new IndexerClient(config.indexer, logger).health(),
    new ProofServerClient(config.proofServer, logger).health(),
  ]);
  assert.ok(healthChecks.every((response) => response.status >= 200 && response.status < 300));
  const walletProviders = (await environment.startMidnightWalletProviders(2)) as MidnightWalletProvider[];
  const walletProvider = walletProviders[1];
  assert.ok(walletProvider);

  const zkConfigProvider = new NodeZkConfigProvider<
    | 'registerRequest'
    | 'consent'
    | 'decline'
    | 'cancel'
    | 'activateCredentialStatus'
    | 'revokeCredentialStatus'
    | 'decide'
    | 'deny'
    | 'protectedAction'
  >(path.resolve('../contract/src/managed/verification-registry'));
  const privateStateProvider = inMemoryPrivateStateProvider<string, VerificationRegistryPrivateState>();
  const providers = {
    privateStateProvider,
    publicDataProvider: indexerPublicDataProvider(config.indexer, config.indexerWS),
    zkConfigProvider,
    proofProvider: httpClientProofProvider(config.proofServer, zkConfigProvider),
    walletProvider,
    midnightProvider: walletProvider,
  };

  const schema: SchemaRef = {
    packageId: randomSecret(),
    schemaId: randomSecret(),
    majorVersion: 1n,
    minorVersion: 0n,
  };
  const issuer = createIssuerAuthorization(schema);
  const verifierSecret = randomSecret();
  const requesterSecret = randomSecret();
  const subjectSecret = randomSecret();
  const statusAuthoritySecret = randomSecret();
  const request = {
    requestId: randomSecret(),
    applicationId: randomSecret(),
    claimDigest: randomSecret(),
    purposeDigest: randomSecret(),
    policyDigest: randomSecret(),
    statusHandle: randomSecret(),
  };
  const pending = {
    requestId: randomSecret(),
    applicationId: randomSecret(),
    claimDigest: randomSecret(),
    purposeDigest: randomSecret(),
    policyDigest: randomSecret(),
  };
  const cancelled = {
    requestId: randomSecret(),
    applicationId: randomSecret(),
    claimDigest: randomSecret(),
    purposeDigest: randomSecret(),
    policyDigest: randomSecret(),
  };
  const denied = {
    requestId: randomSecret(),
    applicationId: randomSecret(),
    claimDigest: randomSecret(),
    purposeDigest: randomSecret(),
    policyDigest: randomSecret(),
  };
  const revoked = {
    requestId: randomSecret(),
    applicationId: randomSecret(),
    claimDigest: randomSecret(),
    purposeDigest: randomSecret(),
    policyDigest: randomSecret(),
    statusHandle: randomSecret(),
  };
  const revokedAfterApproval = {
    requestId: randomSecret(),
    applicationId: randomSecret(),
    claimDigest: randomSecret(),
    purposeDigest: randomSecret(),
    policyDigest: randomSecret(),
    statusHandle: randomSecret(),
  };
  const deployTx = await deployContract(providers, {
    compiledContract: CompiledVerificationRegistryContractContract,
    privateStateId,
    initialPrivateState: { secretKey: verifierSecret },
    args: [
      pureCircuits.identityKey(verifierSecret),
      schema,
      issuer.descriptor,
      pureCircuits.identityKey(statusAuthoritySecret),
    ],
  });
  const contractAddress = deployTx.deployTxData.public.contractAddress;
  const registryId = new Uint8Array(Buffer.from(contractAddress.replace(/^0x/, ''), 'hex'));
  assert.equal(registryId.length, 32, 'Unexpected contract address encoding');
  console.log(
    JSON.stringify({
      operation: 'deploy',
      outcome: deployTx.deployTxData.public.status,
      txId: deployTx.deployTxData.public.txId,
      blockHeight: deployTx.deployTxData.public.blockHeight?.toString(),
      contractAddress,
    }),
  );
  assert.equal(deployTx.deployTxData.public.status, SucceedEntirely);

  const readLedger = async () => {
    const contractState = await providers.publicDataProvider.queryContractState(contractAddress);
    assert.ok(contractState, 'Registry contract state was not found by the indexer');
    return ledger(contractState.data);
  };
  const readRequest = async (id: Uint8Array) => {
    const current = await readLedger();
    return current.requests.member(id) ? current.requests.lookup(id) : undefined;
  };
  const register = async (
    entry: typeof request | typeof pending | typeof revokedAfterApproval,
    maxAge = maxCredentialAge,
  ) => {
    await privateStateProvider.set(privateStateId, { secretKey: requesterSecret });
    await assertSuccessful(
      'registerRequest',
      deployTx.callTx.registerRequest(
        entry.requestId,
        entry.applicationId,
        pureCircuits.identityKey(subjectSecret),
        entry.claimDigest,
        entry.purposeDigest,
        entry.policyDigest,
        maxAge,
      ),
    );
    assert.equal((await readRequest(entry.requestId))?.state, RequestState.PENDING);
  };
  const consentRequest = async (entry: typeof request | typeof pending | typeof revokedAfterApproval) => {
    await privateStateProvider.set(privateStateId, { secretKey: subjectSecret });
    await assertSuccessful(
      'consent',
      deployTx.callTx.consent(
        entry.requestId,
        entry.applicationId,
        entry.claimDigest,
        entry.purposeDigest,
        entry.policyDigest,
      ),
    );
    assert.equal((await readRequest(entry.requestId))?.state, RequestState.CONSENTED);
  };
  const activateStatus = async (statusHandle: Uint8Array) => {
    await privateStateProvider.set(privateStateId, { secretKey: statusAuthoritySecret });
    await assertSuccessful('activateCredentialStatus', deployTx.callTx.activateCredentialStatus(statusHandle));
  };
  const signedEvidence = (entry: typeof request | typeof revoked | typeof revokedAfterApproval) =>
    createSignedRegistryCredential(schema, issuer.secret, issuer.verificationMethodRef, {
      registryId,
      requestId: entry.requestId,
      applicationId: entry.applicationId,
      subject: pureCircuits.identityKey(subjectSecret),
      claimDigest: entry.claimDigest,
      purposeDigest: entry.purposeDigest,
      policyDigest: entry.policyDigest,
      statusHandle: entry.statusHandle,
      issuedAt: currentTime() - 5n,
      hasExpiration: true,
      expiresAt: currentTime() + 86_395n,
    });

  await register(request);
  await register(pending);
  await register(cancelled);
  await register(denied);
  await register(revoked);
  await register(revokedAfterApproval);
  await activateStatus(request.statusHandle);
  await activateStatus(revoked.statusHandle);
  await activateStatus(revokedAfterApproval.statusHandle);

  await consentRequest(request);
  await privateStateProvider.set(privateStateId, { secretKey: randomSecret() });
  const validProof = signedEvidence(request);
  await expectRejected('unauthorizedDecision', 'Not the verifier', () =>
    deployTx.callTx.decide(request.requestId, validProof.credential, validProof.proof),
  );
  assert.equal((await readRequest(request.requestId))?.state, RequestState.CONSENTED);

  const expiredProof = createSignedRegistryCredential(schema, issuer.secret, issuer.verificationMethodRef, {
    registryId,
    requestId: request.requestId,
    applicationId: request.applicationId,
    subject: pureCircuits.identityKey(subjectSecret),
    claimDigest: request.claimDigest,
    purposeDigest: request.purposeDigest,
    policyDigest: request.policyDigest,
    statusHandle: request.statusHandle,
    issuedAt: currentTime() - 3_600n,
    hasExpiration: true,
    expiresAt: currentTime() - 1_800n,
  });
  await privateStateProvider.set(privateStateId, { secretKey: verifierSecret });
  await expectRejected('expiredCredential', 'Credential expired', () =>
    deployTx.callTx.decide(request.requestId, expiredProof.credential, expiredProof.proof),
  );
  assert.equal((await readRequest(request.requestId))?.state, RequestState.CONSENTED);

  const invalidSignature = {
    ...validProof,
    proof: {
      ...validProof.proof,
      signature: {
        ...validProof.proof.signature,
        s: validProof.proof.signature.s + 1n,
      },
    },
  };
  await privateStateProvider.set(privateStateId, { secretKey: verifierSecret });
  await expectRejected('invalidIssuerSignature', 'Signature verification failed', () =>
    deployTx.callTx.decide(request.requestId, invalidSignature.credential, invalidSignature.proof),
  );
  assert.equal((await readRequest(request.requestId))?.state, RequestState.CONSENTED);

  const mismatchedChallengeProof = createSignedRegistryCredential(schema, issuer.secret, issuer.verificationMethodRef, {
    registryId,
    requestId: request.requestId,
    applicationId: request.applicationId,
    subject: pureCircuits.identityKey(subjectSecret),
    claimDigest: request.claimDigest,
    purposeDigest: request.purposeDigest,
    policyDigest: request.policyDigest,
    statusHandle: request.statusHandle,
    issuedAt: currentTime() - 5n,
    hasExpiration: true,
    expiresAt: currentTime() + 86_395n,
    proofChallengeHash: randomSecret(),
  });
  await expectRejected('mismatchedProofChallenge', 'Proof challenge hash mismatch', () =>
    deployTx.callTx.decide(request.requestId, mismatchedChallengeProof.credential, mismatchedChallengeProof.proof),
  );
  assert.equal((await readRequest(request.requestId))?.state, RequestState.CONSENTED);

  const notYetValidProof = createSignedRegistryCredential(schema, issuer.secret, issuer.verificationMethodRef, {
    registryId,
    requestId: request.requestId,
    applicationId: request.applicationId,
    subject: pureCircuits.identityKey(subjectSecret),
    claimDigest: request.claimDigest,
    purposeDigest: request.purposeDigest,
    policyDigest: request.policyDigest,
    statusHandle: request.statusHandle,
    issuedAt: currentTime() + 600n,
    hasExpiration: true,
    expiresAt: currentTime() + 3_600n,
  });
  await privateStateProvider.set(privateStateId, { secretKey: verifierSecret });
  await expectRejected('notYetValidCredential', 'Credential issued in the future', () =>
    deployTx.callTx.decide(request.requestId, notYetValidProof.credential, notYetValidProof.proof),
  );
  assert.equal((await readRequest(request.requestId))?.state, RequestState.CONSENTED);

  const alteredClaimProof = createSignedRegistryCredential(schema, issuer.secret, issuer.verificationMethodRef, {
    registryId,
    requestId: request.requestId,
    applicationId: request.applicationId,
    subject: pureCircuits.identityKey(subjectSecret),
    claimDigest: randomSecret(),
    purposeDigest: request.purposeDigest,
    policyDigest: request.policyDigest,
    statusHandle: request.statusHandle,
    issuedAt: currentTime() - 5n,
    hasExpiration: true,
    expiresAt: currentTime() + 86_395n,
  });
  await privateStateProvider.set(privateStateId, { secretKey: verifierSecret });
  await expectRejected('alteredSignedClaim', 'Credential claim digest mismatch', () =>
    deployTx.callTx.decide(request.requestId, alteredClaimProof.credential, alteredClaimProof.proof),
  );
  assert.equal((await readRequest(request.requestId))?.state, RequestState.CONSENTED);

  await assertSuccessful(
    'decideWithIssuerSignedCredential',
    deployTx.callTx.decide(request.requestId, validProof.credential, validProof.proof),
  );
  const verified = await readRequest(request.requestId);
  assert.equal(verified?.state, RequestState.VERIFIED);
  assert.deepEqual(verified?.evidenceDigest, pureCircuits.credentialBodyRoot(validProof.credential));

  await expectRejected('protectedActionWhilePending', 'Request is not verified', () =>
    deployTx.callTx.protectedAction(pending.requestId),
  );
  assert.equal((await readRequest(pending.requestId))?.state, RequestState.PENDING);

  await privateStateProvider.set(privateStateId, { secretKey: subjectSecret });
  await assertSuccessful('protectedAction', deployTx.callTx.protectedAction(request.requestId));
  const consumed = await readLedger();
  assert.equal(consumed.requests.lookup(request.requestId).state, RequestState.CONSUMED);
  assert.equal(consumed.protectedActionCount, 1n);
  await expectRejected('repeatedProtectedAction', 'Request is not verified', () =>
    deployTx.callTx.protectedAction(request.requestId),
  );
  assert.equal((await readLedger()).protectedActionCount, 1n);

  await privateStateProvider.set(privateStateId, { secretKey: subjectSecret });
  await assertSuccessful(
    'decline',
    deployTx.callTx.decline(
      pending.requestId,
      pending.applicationId,
      pending.claimDigest,
      pending.purposeDigest,
      pending.policyDigest,
    ),
  );
  await expectRejected('protectedActionAfterDecline', 'Request is not verified', () =>
    deployTx.callTx.protectedAction(pending.requestId),
  );

  await privateStateProvider.set(privateStateId, { secretKey: requesterSecret });
  await assertSuccessful('cancel', deployTx.callTx.cancel(cancelled.requestId));

  await consentRequest(denied);
  await privateStateProvider.set(privateStateId, { secretKey: verifierSecret });
  await assertSuccessful(
    'deny',
    deployTx.callTx.deny(
      denied.requestId,
      denied.applicationId,
      denied.claimDigest,
      denied.purposeDigest,
      denied.policyDigest,
      randomSecret(),
    ),
  );
  await expectRejected('protectedActionAfterDenial', 'Request is not verified', () =>
    deployTx.callTx.protectedAction(denied.requestId),
  );

  await consentRequest(revoked);
  await privateStateProvider.set(privateStateId, { secretKey: randomSecret() });
  await expectRejected('unauthorizedRevocation', 'Not the status authority', () =>
    deployTx.callTx.revokeCredentialStatus(revoked.statusHandle),
  );
  await privateStateProvider.set(privateStateId, { secretKey: statusAuthoritySecret });
  await expectRejected('zeroStatusHandleRevocation', 'Invalid status handle', () =>
    deployTx.callTx.revokeCredentialStatus(new Uint8Array(32)),
  );
  await assertSuccessful('revokeCredentialStatus', deployTx.callTx.revokeCredentialStatus(revoked.statusHandle));
  await privateStateProvider.set(privateStateId, { secretKey: verifierSecret });
  const revokedProof = signedEvidence(revoked);
  await expectRejected('decisionWithRevokedCredential', 'Credential is revoked', () =>
    deployTx.callTx.decide(revoked.requestId, revokedProof.credential, revokedProof.proof),
  );
  assert.equal((await readRequest(revoked.requestId))?.state, RequestState.CONSENTED);

  await consentRequest(revokedAfterApproval);
  await privateStateProvider.set(privateStateId, { secretKey: verifierSecret });
  const approvedThenRevokedEvidence = signedEvidence(revokedAfterApproval);
  await assertSuccessful(
    'decideBeforeRevocation',
    deployTx.callTx.decide(
      revokedAfterApproval.requestId,
      approvedThenRevokedEvidence.credential,
      approvedThenRevokedEvidence.proof,
    ),
  );
  await privateStateProvider.set(privateStateId, { secretKey: statusAuthoritySecret });
  await assertSuccessful(
    'revokeAfterApproval',
    deployTx.callTx.revokeCredentialStatus(revokedAfterApproval.statusHandle),
  );
  await privateStateProvider.set(privateStateId, { secretKey: subjectSecret });
  await expectRejected('protectedActionAfterRevocation', 'Credential is revoked', () =>
    deployTx.callTx.protectedAction(revokedAfterApproval.requestId),
  );
  assert.equal((await readRequest(revokedAfterApproval.requestId))?.state, RequestState.VERIFIED);

  const finalLedger = await readLedger();
  const finalStates = {
    consumed: loggerLabel(finalLedger.requests.lookup(request.requestId).state),
    declined: loggerLabel(finalLedger.requests.lookup(pending.requestId).state),
    cancelled: loggerLabel(finalLedger.requests.lookup(cancelled.requestId).state),
    denied: loggerLabel(finalLedger.requests.lookup(denied.requestId).state),
    revokedCredentialRequest: loggerLabel(finalLedger.requests.lookup(revoked.requestId).state),
    revokedAfterApprovalRequest: loggerLabel(finalLedger.requests.lookup(revokedAfterApproval.requestId).state),
    protectedActionCount: finalLedger.protectedActionCount.toString(),
    revokedStatus:
      CredentialStatus[
        finalLedger.credentialStatuses.lookup(pureCircuits.credentialStatusCommitment(revoked.statusHandle))
      ],
  };
  assert.deepEqual(finalStates, {
    consumed: 'CONSUMED',
    declined: 'DECLINED',
    cancelled: 'CANCELLED',
    denied: 'DENIED',
    revokedCredentialRequest: 'CONSENTED',
    revokedAfterApprovalRequest: 'VERIFIED',
    protectedActionCount: '1',
    revokedStatus: 'REVOKED',
  });
  console.log(JSON.stringify({ operation: 'finalState', ...finalStates }));
} finally {
  if (environmentInitialized) {
    await environment.shutdown();
  } else if (dockerEnv) {
    await dockerEnv.down();
  }
}
