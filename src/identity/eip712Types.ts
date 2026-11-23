import type { TypedDataDomain, TypedDataField } from "ethers";

/** Canonical EIP-712 domain for the BEAST 3.0 Federated Router Core. */
export const BEAST3_EIP712_DOMAIN: TypedDataDomain = {
  name: "BEAST 3.0 Federated Router Core",
  version: "1.0.0",
  chainId: 1,
  verifyingContract: "0x0000000000000000000000000000000000003333"
};

export const BEAST3_EIP712_TYPES: Record<string, Array<TypedDataField>> = {
  FederatedAuthorization: [
    { name: "citizenId", type: "string" },
    { name: "subdomain", type: "string" },
    { name: "targetRepo", type: "string" },
    { name: "action", type: "string" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" }
  ]
};

export interface FederatedAuthorizationMessage {
  citizenId: string;
  subdomain: string;
  targetRepo: string;
  action: string;
  nonce: bigint | number;
  deadline: bigint | number;
}
