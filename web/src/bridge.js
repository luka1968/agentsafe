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

import { ExactEvmScheme } from "@x402/evm";

/** Serialize typed data for eth_signTypedData_v4 (BigInt -> decimal string). */
function jsonSafe(obj) {
  return JSON.stringify(obj, (_k, v) =>
    typeof v === "bigint" ? v.toString(10) : v
  );
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
      const result = await eth.request({
        method: "eth_signTypedData_v4",
        params: [address, jsonSafe({ domain, types, primaryType, message })],
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
 * Returns { payload, requirements } — payload is ready for b64encoding into
 * the X-PAYMENT header exactly like the previous hand-rolled version.
 */
export async function createPaymentPayload(eth, from, accept, resourceUrl) {
  const signer = metaMaskSigner(eth, from);
  const requirements = toRequirements(accept);
  const scheme = new ExactEvmScheme(signer);
  // x402Version 2: exact/EIP-3009 transferWithAuthorization.
  const created = await scheme.createPaymentPayload(2, requirements);
  const payload = {
    x402Version: 2,
    scheme: "exact",
    network: accept.network,
    resource: { url: resourceUrl, mimeType: "application/json" },
    accepted: accept,
    payload: created.payload, // { authorization, signature } — SDK-built
  };
  return { payload, requirements };
}

/** Browserideshield: expose for the landing page (IIFE global). */
export default { ExactEvmScheme, metaMaskSigner, toRequirements, createPaymentPayload };
