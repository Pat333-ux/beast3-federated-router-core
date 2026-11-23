import type { Request, Response, NextFunction } from "express";
import { verifyFederatedEip712Signature } from "../identity/eip712Verifier.js";
import type { FederatedAuthorizationMessage } from "../identity/eip712Types.js";

export interface GateChecks {
  emergencyClear: boolean;
  policyApproved: boolean;
  piiScrubbed: boolean;
  citizenConsentGiven: boolean;
}

export interface Eip712AuthHeaderPayload {
  accountAddress: string;
  signature: string;
  message: FederatedAuthorizationMessage;
  gates: GateChecks;
}

export function eip712PasskeyAuthMiddleware() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const authHeader = req.headers["x-beast3-eip712-auth"];
      const encodedPayload = Array.isArray(authHeader) ? authHeader[0] : authHeader;

      if (!encodedPayload) {
        return res.status(401).json({
          status: "blocked",
          autoSubmit: false,
          error: "Missing x-beast3-eip712-auth authorization payload header."
        });
      }

      const authPayload = JSON.parse(encodedPayload) as Eip712AuthHeaderPayload;
      const { accountAddress, signature, message, gates } = authPayload;

      if (!gates?.emergencyClear || !gates.policyApproved || !gates.piiScrubbed || !gates.citizenConsentGiven) {
        return res.status(403).json({
          status: "blocked",
          autoSubmit: false,
          error: "Blocked by BEAST 3.0 safety gates (emergency, policy, PII, or consent failed)."
        });
      }

      const verification = await verifyFederatedEip712Signature({
        accountAddress,
        message,
        signature
      });

      if (!verification.isValid) {
        return res.status(401).json({
          status: "blocked",
          autoSubmit: false,
          error: verification.error || "Invalid EIP-712 passkey signature."
        });
      }

      req.body = req.body || {};
      req.body._eip712Auth = {
        accountAddress,
        digest: verification.digest,
        citizenId: message.citizenId,
        verifiedAt: new Date().toISOString()
      };

      next();
    } catch {
      return res.status(500).json({
        status: "blocked",
        autoSubmit: false,
        error: "Internal error processing EIP-712 passkey authorization."
      });
    }
  };
}
