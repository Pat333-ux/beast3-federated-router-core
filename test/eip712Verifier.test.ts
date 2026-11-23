import assert from "node:assert/strict";
import test from "node:test";
import { ethers } from "ethers";
import {
  BEAST3_EIP712_DOMAIN,
  BEAST3_EIP712_TYPES,
  type FederatedAuthorizationMessage
} from "../src/identity/eip712Types.js";
import {
  computeEip712Digest,
  verifyFederatedEip712Signature
} from "../src/identity/eip712Verifier.js";

function createMessage(deadline: number): FederatedAuthorizationMessage {
  return {
    citizenId: "NWO-0001",
    subdomain: "vigo-senior",
    targetRepo: "senior-benefit-engine",
    action: "evaluate_and_prefill_only",
    nonce: 1,
    deadline
  };
}

test("computes deterministic EIP-712 digests and verifies valid EOA signatures", async () => {
  const wallet = ethers.Wallet.createRandom();
  const message = createMessage(Math.floor(Date.now() / 1000) + 3600);
  const digest = computeEip712Digest(message);

  assert.ok(digest.startsWith("0x"));

  const signature = await wallet.signTypedData(
    BEAST3_EIP712_DOMAIN,
    BEAST3_EIP712_TYPES,
    message
  );

  const verification = await verifyFederatedEip712Signature({
    accountAddress: wallet.address,
    message,
    signature
  });

  assert.equal(verification.isValid, true);
  assert.equal(verification.digest, digest);
});

test("blocks expired EIP-712 authorization deadlines", async () => {
  const wallet = ethers.Wallet.createRandom();
  const message = createMessage(Math.floor(Date.now() / 1000) - 100);
  const signature = await wallet.signTypedData(
    BEAST3_EIP712_DOMAIN,
    BEAST3_EIP712_TYPES,
    message
  );

  const verification = await verifyFederatedEip712Signature({
    accountAddress: wallet.address,
    message,
    signature
  });

  assert.equal(verification.isValid, false);
  assert.match(verification.error ?? "", /expired/i);
});

test("rejects a signature from a different account", async () => {
  const signer = ethers.Wallet.createRandom();
  const otherAccount = ethers.Wallet.createRandom();
  const message = createMessage(Math.floor(Date.now() / 1000) + 3600);
  const signature = await signer.signTypedData(
    BEAST3_EIP712_DOMAIN,
    BEAST3_EIP712_TYPES,
    message
  );

  const verification = await verifyFederatedEip712Signature({
    accountAddress: otherAccount.address,
    message,
    signature
  });

  assert.equal(verification.isValid, false);
  assert.match(verification.error ?? "", /failed/i);
});
