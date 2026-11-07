/**
 * agentSAFE x402 browser bridge.
 *
 * Thin wrapper around the OFFICIAL @x402/evm exact scheme so the landing
 * page never hand-rolls EIP-712 / EIP-3009 (nonce length, domain name,
 * typed-data serialization were all past root causes of signature
 * failures). The bridge only supplies:
 *   1. a MetaMask-backed ClientEvmSigner (address + signTypedData -> v4),
 *   2. helper mapping the backend's 402 `accept` terms into official
 *      PaymentRequirements, and
 *   3. assembly of the final v2 payload (accepted+resource+payload) the
 *      backend's x402 server verification expects.
 *
 * Built with esbuild into an IIFE exposing `window.X402Bridge`. No React,
 * no bundler inside the page: a single <script src="/static/x402-bridge.js">
 */

import { x402Version as X402_VERSION } from "@x402/core";
import { safeBase64Encode, safeBase64Decode } from "@x402/core/utils";
import { ExactEvmScheme } from "@x402/evm";

/**
 * Serialize typed data for eth_signTypedData_v4 (BigInt -> decimal string).
 */
function jsonSafe(obj) {
  return JSON.stringify(obj, (_k, v) =>
    typeof v === "bigint" ? v.toString(10) : v
  );
}

/**
 * EIP-712 domain type fields, in canonical field order.
 *
 * MetaMask's eth_signTypedData_v4 REQUIRES the `EIP712Domain` entry to be
 * present in `types` and hashes the domain separator from it. Without it,
 * MetaMask derives a DIFFERENT domain hash than viem / the x402 facilitator,
 * so the recovered signer no longer equals the authorization `from` and the
 * facilitator rejects the payment with `invalid_exact_evm_signature`.
 *
 * viem's own signTypedData injects exactly this list before signing; our
 * MetaMask bridge must do the same (it cannot rely on viem because it calls
 * the wallet RPC directly).
 */
function eip712DomainTypes(domain) {
  return [
    typeof domain?.name === "string" && { name: "name", type: "string" },
    typeof domain?.version === "string" && { name: "version", type: "string" },
    (typeof domain?.chainId === "number" || typeof domain?.chainId === "bigint") && {
      name: "chainId",
      type: "uint256",
    },
    domain?.verifyingContract && { name: "verifyingContract", type: "address" },
    domain?.salt && { name: "salt", type: "bytes32" },
  ].filter(Boolean);
}

/**
 * Wrap a MetaMask-like provider (`window.ethereum`) as a ClientEvmSigner.
 * The official scheme only needs `address` + `signTypedData`; domain/nonce
 * construction is entirely the SDK's responsibility.
 */
export function metaMaskSigner(eth, address) {
  if (!eth || typeof eth.request !== "function") {
    throw new Error("No wallet provider found. Install MetaMask and retry.");
  }
  return {
    address,
    async signTypedData({ domain, types, primaryType, message }) {
      // Inject EIP712Domain exactly like viem does; MetaMask needs it to
      // build the same domain separator the facilitator verifies against.
      const fullTypes = {
        EIP712Domain: eip712DomainTypes(domain || {}),
        ...types,
      };
      const result = await eth.request({
        method: "eth_signTypedData_v4",
        params: [address, jsonSafe({ domain, types: fullTypes, primaryType, message })],
      });
      return result;
    },
  };
}

/**
 * Map the backend's advertised accept terms to official PaymentRequirements.
 * `extra` is the AUTHORITATIVE token metadata shipped by the backend (the
 * SDK reads EIP-712 domain name/version out of it).
 */
export function toRequirements(accept) {
  if (!accept || !accept.asset || !accept.payTo) {
    throw new Error("Invalid payment terms from the server.");
  }
  const extra = accept.extra && typeof accept.extra === "object" ? accept.extra : {};
  return {
    scheme: "exact",
    network: accept.network,
    asset: accept.asset,
    payTo: accept.payTo,
    amount: String(accept.amount),
    maxTimeoutSeconds: Number(accept.maxTimeoutSeconds || 300),
    extra,
  };
}

/**
 * Build the complete v2 payment payload the backend verifies.
 * Returns { payload, requirements } — payload is ready for the payment
 * header via the SDK's own base64 codec (never hand-rolled here).
 */
export async function createPaymentPayload(eth, from, accept, resourceUrl) {
  const signer = metaMaskSigner(eth, from);
  const requirements = toRequirements(accept);
  const scheme = new ExactEvmScheme(signer);
  // x402Version 2: exact/EIP-3009 transferWithAuthorization. The version
  // constant comes from the official @x402/core package, not a literal.
  const created = await scheme.createPaymentPayload(X402_VERSION, requirements);
  const payload = {
    x402Version: X402_VERSION,
    scheme: "exact",
    network: accept.network,
    resource: { url: resourceUrl, mimeType: "application/json" },
    accepted: accept,
    payload: created.payload, // { authorization, signature } — SDK-built
  };
  return { payload, requirements };
}

/**
 * Official SDK base64 codecs for the x402 payment headers. The landing page
 * must never hand-roll base64 (alphabet/padding mistakes silently corrupt
 * payment payloads).
 */
export { safeBase64Encode, safeBase64Decode, X402_VERSION };

/** Browser global: expose for the landing page (IIFE global). */
export default { ExactEvmScheme, metaMaskSigner, eip712DomainTypes, toRequirements, createPaymentPayload, safeBase64Encode, safeBase64Decode, X402_VERSION };
