import { CompiledContract } from "@midnight-ntwrk/midnight-js-protocol/compact-js";

export * from "./managed/verification-registry/contract/index.js";
export * from "./verification-registry-witnesses.js";

import * as CompiledVerificationRegistryContract from "./managed/verification-registry/contract/index.js";
import * as VerificationRegistryWitnesses from "./verification-registry-witnesses.js";

export const CompiledVerificationRegistryContractContract =
  CompiledContract.make<
    CompiledVerificationRegistryContract.Contract<VerificationRegistryWitnesses.VerificationRegistryPrivateState>
  >(
    "VerificationRegistry",
    CompiledVerificationRegistryContract.Contract<VerificationRegistryWitnesses.VerificationRegistryPrivateState>,
  ).pipe(
    CompiledContract.withWitnesses(
      VerificationRegistryWitnesses.verificationRegistryWitnesses,
    ),
    CompiledContract.withCompiledFileAssets("./managed/verification-registry"),
  );
