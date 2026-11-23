import { ethers } from "ethers";
import {
  BEAST3_EIP712_DOMAIN,
  BEAST3_EIP712_TYPES,
  type FederatedAuthorizationMessage
} from "./eip712Types.js";
import { verifyErc1271Passkey } from "./erc1271Verifier.js";

export interface SignatureVerificationParams {
  accountAddress: string;
  message: FederatedAuthorizationMessage;
  signature: string;
  provider?: ethers.Provider;
  customDomain?: ethers.TypedDataDomain;
}

export function computeEip712Digest(
  message: FederatedAuthorizationMessage,
  customDomain?: ethers.TypedDataDomain
): string {
  return ethers.TypedDataEncoder.hash(
    customDomain || BEAST3_EIP712_DOMAIN,
    BEAST3_EIP712_TYPES,
    message
  );
}

export async function verifyFederatedEip712Signature(
  params: SignatureVerificationParams
): Promise<{ isValid: boolean; digest: string; error?: string }> {
  const { accountAddress, message, signature, provider, customDomain } = params;
  const domain = customDomain || BEAST3_EIP712_DOMAIN;
  const deadline = BigInt(message.deadline);
  const currentTimestamp = BigInt(Math.floor(Date.now() / 1000));

  if (deadline < currentTimestamp) {
    return { isValid: false, digest: "", error: "Authorization signature deadline expired." };
  }

  const digest = computeEip712Digest(message, domain);

  try {
    const recoveredAddress = ethers.verifyTypedData(
      domain,
      BEAST3_EIP712_TYPES,
      message,
      signature
    );
    if (recoveredAddress.toLowerCase() === accountAddress.toLowerCase()) {
      return { isValid: true, digest };
    }
  } catch {
    // Fall through to ERC-1271 verification.
  }

  if (provider) {
    const isErc1271Valid = await verifyErc1271Passkey(provider, {
      accountAddress,
      messageHash: digest,
      signature
    });

    if (isErc1271Valid) {
      return { isValid: true, digest };
    }
  }

  return {
    isValid: false,
    digest,
    error: "Signature verification failed for provided account address."
  };
}
