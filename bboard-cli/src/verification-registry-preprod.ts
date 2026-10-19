import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import pino from 'pino';
import { deployContract } from '@midnight-ntwrk/midnight-js-contracts';
import { indexerPublicDataProvider } from '@midnight-ntwrk/midnight-js-indexer-public-data-provider';
import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import {
  defaultContainersConfiguration,
  inMemoryPrivateStateProvider,
  setContainersConfiguration,
} from '@midnight-ntwrk/testkit-js';
import type { EnvironmentConfiguration } from '@midnight-ntwrk/testkit-js';
import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { NodeZkConfigProvider } from '@midnight-ntwrk/midnight-js-node-zk-config-provider';
import { SucceedEntirely, type FinalizedTxData } from '@midnight-ntwrk/midnight-js-types';
import {
  CredentialStatus,
  ledger,
  pureCircuits,
  RequestState,
  type SchemaRef,
} from '../../contract/src/managed/verification-registry/contract/index.js';
import {
  CompiledVerificationRegistryContractContract,
  type VerificationRegistryPrivateState,
} from '../../contract/src/verification-registry-index.js';
import {
  createIssuerAuthorization,
  createSignedRegistryCredential,
} from '../../contract/src/test/verification-registry-credential-fixtures.js';
import { MidnightWalletProvider } from './midnight-wallet-provider.js';
import { PreprodTestEnvironment } from './config.js';
import { syncWallet } from './wallet-utils.js';
import { UnshieldedAddress } from '@midnight-ntwrk/wallet-sdk-address-format';
import { unshieldedToken } from '@midnight-ntwrk/midnight-js-protocol/ledger';

const contractName = 'Verification Registry';
const privateStateId = 'verification-registry-preprod';
const logger = pino({ level: 'silent' });
setContainersConfiguration({
  ...defaultContainersConfiguration,
  proofServer: {
    ...defaultContainersConfiguration.proofServer,
    fileName: 'proof-server-preprod.yml',
  },
});
const environment = new PreprodTestEnvironment(logger);
type VerificationRegistryCircuit =
  | 'registerRequest'
  | 'consent'
  | 'decline'
  | 'cancel'
  | 'activateCredentialStatus'
  | 'revokeCredentialStatus'
  | 'decide'
  | 'deny'
  | 'protectedAction';

const readWalletSeed = async (): Promise<string> => {
  const seedFile = process.env.MIDNIGHT_WALLET_SEED_FILE?.trim();
  if (!seedFile) {
    throw new Error(
      'Set MIDNIGHT_WALLET_SEED_FILE to a private file containing the funded Preprod wallet seed. Do not pass the seed on the command line or in chat.',
    );
  }

  const fileStats = await fs.stat(seedFile);
  if (!fileStats.isFile()) {
    throw new Error('MIDNIGHT_WALLET_SEED_FILE must point to a regular file.');
  }
  if (process.platform !== 'win32' && (fileStats.mode & 0o077) !== 0) {
    throw new Error('Wallet seed file permissions are too broad; restrict it to owner read/write (chmod 600).');
  }

  const walletSeed = (await fs.readFile(seedFile, 'utf8')).trim();
  if (!/^[0-9a-fA-F]{64}$/.test(walletSeed)) {
    throw new Error('Wallet seed file must contain exactly 64 hexadecimal characters.');
  }
  return walletSeed;
};

const reportTransaction = (operation: string, result: { readonly public: FinalizedTxData }): void => {
  const transaction = result.public;
  assert.equal(transaction.status, SucceedEntirely, `${operation} did not finalize successfully`);
  console.log(
    JSON.stringify({
      network: 'preprod',
      contract: contractName,
      operation,
      status: transaction.status,
      transactionId: transaction.txId,
      blockHeight: transaction.blockHeight,
      blockHash: transaction.blockHash,
    }),
  );
};

const expectLocalRejection = async (
  operation: string,
  expectedAssertion: string,
  call: () => Promise<unknown>,
): Promise<void> => {
  try {
    await call();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!message.includes(expectedAssertion)) {
      throw new Error(`${operation} failed for an unexpected reason: ${message}`);
    }
    console.log(
      JSON.stringify({
        network: 'preprod',
        contract: contractName,
        operation,
        status: 'REJECTED_BEFORE_SUBMISSION',
        expectedAssertion,
        transactionId: null,
      }),
    );
    return;
  }
  throw new Error(`${operation} unexpectedly succeeded`);
};

const randomSecret = (): Uint8Array => new Uint8Array(randomBytes(32));

const run = async (): Promise<void> => {
  if (!process.env.BLOCKFROST_PROJECT_ID?.trim()) {
    throw new Error('Set BLOCKFROST_PROJECT_ID in the local environment for Preprod Blockfrost access.');
  }
  const walletSeed = await readWalletSeed();

  setNetworkId('preprod');
  let walletProvider: MidnightWalletProvider | undefined;
  try {
    // testkit's declarations use unresolved internal aliases for this return type.
    const environmentConfiguration = (await environment.start()) as EnvironmentConfiguration;
    await environment.healthCheck();

    walletProvider = await MidnightWalletProvider.build(logger, environmentConfiguration, walletSeed);
    await walletProvider.start();
    const walletState = await syncWallet(logger, walletProvider.wallet);
    const walletAddress = UnshieldedAddress.codec
      .encode(environmentConfiguration.networkId, walletState.unshielded.address)
      .toString();
    const nightBalance = walletState.unshielded.balances[unshieldedToken().raw] ?? 0n;
    const dustBalance = walletState.dust.balance(new Date()) ?? 0n;
    console.log(
      JSON.stringify({
        network: 'preprod',
        operation: 'walletPreflight',
        walletAddress,
        nightBalance: nightBalance.toString(),
        dustBalance: dustBalance.toString(),
      }),
    );
    if (nightBalance <= 0n || dustBalance <= 0n) {
      throw new Error(
        `The Preprod wallet needs NIGHT and DUST before deployment. Fund this address with testnet tokens and generate DUST, then rerun: ${walletAddress}`,
      );
    }

    const privateStateProvider = inMemoryPrivateStateProvider<string, VerificationRegistryPrivateState>();
    const zkConfigProvider = new NodeZkConfigProvider<VerificationRegistryCircuit>(
      path.resolve('../contract/src/managed/verification-registry'),
    );
    const providers = {
      privateStateProvider,
      publicDataProvider: indexerPublicDataProvider(
        environmentConfiguration.indexer,
        environmentConfiguration.indexerWS,
      ),
      zkConfigProvider,
      proofProvider: httpClientProofProvider(environmentConfiguration.proofServer, zkConfigProvider),
      walletProvider,
      midnightProvider: walletProvider,
    };

    const verifierSecret = randomSecret();
    const requesterSecret = randomSecret();
    const subjectSecret = randomSecret();
    const statusAuthoritySecret = randomSecret();
    const schema: SchemaRef = {
      packageId: randomSecret(),
      schemaId: randomSecret(),
      majorVersion: 1n,
      minorVersion: 0n,
    };
    const issuer = createIssuerAuthorization(schema);
    const request = {
      requestId: randomSecret(),
      applicationId: randomSecret(),
      claimDigest: randomSecret(),
      purposeDigest: randomSecret(),
      policyDigest: randomSecret(),
      statusHandle: randomSecret(),
    };
    const verifierTime = BigInt(Math.floor(Date.now() / 1000));
    const maxCredentialAge = 86_400n;
    const pendingRequestId = randomSecret();
    const pendingApplicationId = randomSecret();
    const pendingClaimDigest = randomSecret();
    const pendingPurposeDigest = randomSecret();
    const pendingPolicyDigest = randomSecret();
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
    reportTransaction('deploy', deployTx.deployTxData);
    const contractAddress = deployTx.deployTxData.public.contractAddress;
    const registryId = new Uint8Array(Buffer.from(contractAddress.replace(/^0x/, ''), 'hex'));
    assert.equal(registryId.length, 32, 'Unexpected contract address encoding');
    console.log(JSON.stringify({ network: 'preprod', operation: 'deployedContract', contractAddress }));

    const readLedger = async () => {
      const contractState = await providers.publicDataProvider.queryContractState(contractAddress);
      assert.ok(contractState, 'Deployed registry state was not found through the Preprod indexer');
      return ledger(contractState.data);
    };
    const readRequest = async (id: Uint8Array) => {
      const currentLedger = await readLedger();
      return currentLedger.requests.member(id) ? currentLedger.requests.lookup(id) : undefined;
    };

    await privateStateProvider.set(privateStateId, { secretKey: requesterSecret });
    reportTransaction(
      'registerRequest',
      await deployTx.callTx.registerRequest(
        request.requestId,
        request.applicationId,
        pureCircuits.identityKey(subjectSecret),
        request.claimDigest,
        request.purposeDigest,
        request.policyDigest,
        maxCredentialAge,
      ),
    );
    assert.equal((await readRequest(request.requestId))?.state, RequestState.PENDING);

    reportTransaction(
      'registerPendingRequest',
      await deployTx.callTx.registerRequest(
        pendingRequestId,
        pendingApplicationId,
        pureCircuits.identityKey(subjectSecret),
        pendingClaimDigest,
        pendingPurposeDigest,
        pendingPolicyDigest,
        maxCredentialAge,
      ),
    );
    assert.equal((await readRequest(pendingRequestId))?.state, RequestState.PENDING);

    await privateStateProvider.set(privateStateId, { secretKey: subjectSecret });
    reportTransaction(
      'consent',
      await deployTx.callTx.consent(
        request.requestId,
        request.applicationId,
        request.claimDigest,
        request.purposeDigest,
        request.policyDigest,
      ),
    );
    assert.equal((await readRequest(request.requestId))?.state, RequestState.CONSENTED);

    await privateStateProvider.set(privateStateId, { secretKey: randomSecret() });
    const evidence = createSignedRegistryCredential(schema, issuer.secret, issuer.verificationMethodRef, {
      ...request,
      registryId,
      subject: pureCircuits.identityKey(subjectSecret),
      statusHandle: request.statusHandle,
      issuedAt: verifierTime - 1n,
      hasExpiration: true,
      expiresAt: verifierTime + 86_400n,
    });
    await expectLocalRejection('unauthorizedDecision', 'Not the verifier', () =>
      deployTx.callTx.decide(request.requestId, evidence.credential, evidence.proof),
    );
    assert.equal((await readRequest(request.requestId))?.state, RequestState.CONSENTED);

    await expectLocalRejection('protectedActionWhilePending', 'Request is not verified', () =>
      deployTx.callTx.protectedAction(pendingRequestId),
    );
    const pendingLedger = await readLedger();
    assert.equal(pendingLedger.requests.lookup(pendingRequestId).state, RequestState.PENDING);
    assert.equal(pendingLedger.protectedActionCount, 0n);

    await privateStateProvider.set(privateStateId, { secretKey: statusAuthoritySecret });
    reportTransaction('activateCredentialStatus', await deployTx.callTx.activateCredentialStatus(request.statusHandle));
    await privateStateProvider.set(privateStateId, { secretKey: verifierSecret });
    reportTransaction(
      'decideWithIssuerSignedCredential',
      await deployTx.callTx.decide(request.requestId, evidence.credential, evidence.proof),
    );
    assert.equal((await readRequest(request.requestId))?.state, RequestState.VERIFIED);
    assert.deepEqual(
      (await readRequest(request.requestId))?.evidenceDigest,
      pureCircuits.credentialBodyRoot(evidence.credential),
    );

    await privateStateProvider.set(privateStateId, { secretKey: subjectSecret });
    reportTransaction('protectedAction', await deployTx.callTx.protectedAction(request.requestId));
    const finalLedger = await readLedger();
    assert.equal(finalLedger.requests.lookup(request.requestId).state, RequestState.CONSUMED);
    assert.equal(finalLedger.protectedActionCount, 1n);
    await expectLocalRejection('repeatedProtectedAction', 'Request is not verified', () =>
      deployTx.callTx.protectedAction(request.requestId),
    );
    const afterReplay = await readLedger();
    assert.equal(afterReplay.requests.lookup(request.requestId).state, RequestState.CONSUMED);
    assert.equal(afterReplay.protectedActionCount, 1n);
    console.log(
      JSON.stringify({
        network: 'preprod',
        operation: 'verifiedState',
        requestState: RequestState[afterReplay.requests.lookup(request.requestId).state],
        protectedActionCount: afterReplay.protectedActionCount.toString(),
        credentialStatus:
          CredentialStatus[
            afterReplay.credentialStatuses.lookup(pureCircuits.credentialStatusCommitment(request.statusHandle))
          ],
      }),
    );
  } finally {
    try {
      await walletProvider?.stop();
    } finally {
      await environment.shutdown();
    }
  }
};

run().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'Unknown Preprod registry runner error';
  console.error(message.replace(/([?&]project_id=)[^&\s]+/g, '$1[redacted]'));
  process.exitCode = 1;
});
