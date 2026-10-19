import type { WitnessContext } from "@midnight-ntwrk/midnight-js-protocol/compact-runtime";
import type { Ledger } from "./managed/verification-registry/contract/index.js";

export type VerificationRegistryPrivateState = {
  readonly secretKey: Uint8Array;
};

export const verificationRegistryWitnesses = {
  localSecretKey: ({
    privateState,
  }: WitnessContext<Ledger, VerificationRegistryPrivateState>): [
    VerificationRegistryPrivateState,
    Uint8Array,
  ] => [privateState, privateState.secretKey],
};

export const witnesses = verificationRegistryWitnesses;
