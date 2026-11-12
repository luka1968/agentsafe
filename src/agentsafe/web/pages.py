"""Landing page + legal pages rendered from the repository's Markdown files.

The Markdown files at the repository root are the single source of truth
(they are also what the health tool links to on GitHub). Deployments that
do not ship the repository checkout can point AGENTSAFE_LEGAL_DIR at a
directory containing copies.
"""

from __future__ import annotations

import os
from pathlib import Path

import markdown as md_lib

from agentsafe import __version__

# slug -> repository markdown file
LEGAL_FILES = {
    "terms": "TERMS_OF_SERVICE.md",
    "privacy": "PRIVACY_POLICY.md",
    "refund": "REFUND_POLICY.md",
}

LEGAL_SLUGS = tuple(LEGAL_FILES)


class LegalDocumentMissingError(RuntimeError):
    """The backing Markdown file could not be found in any known location."""


def _candidate_dirs() -> list[Path]:
    dirs: list[Path] = []
    env_dir = os.environ.get("AGENTSAFE_LEGAL_DIR", "")
    if env_dir:
        dirs.append(Path(env_dir))
    # .../src/agentsafe/web/pages.py -> repository root
    dirs.append(Path(__file__).resolve().parents[3])
    dirs.append(Path.cwd())
    return dirs


def legal_markdown(slug: str) -> str:
    """Raw Markdown text for a legal page slug ('terms' | 'privacy' | 'refund')."""
    if slug not in LEGAL_FILES:
        raise LegalDocumentMissingError(f"unknown legal page: {slug!r}")
    filename = LEGAL_FILES[slug]
    for d in _candidate_dirs():
        path = d / filename
        if path.is_file():
            # utf-8-sig: a leading BOM would break the first '# heading'
            return path.read_text(encoding="utf-8-sig")
    raise LegalDocumentMissingError(
        f"{filename} not found (set AGENTSAFE_LEGAL_DIR to the directory "
        f"containing the legal Markdown files)"
    )


_PAGE_SHELL = """<!DOCTYPE html>
<html lang="en" class="bg-black text-white">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} - agentSAFE</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-black text-white min-h-screen">
<div class="mx-auto max-w-3xl px-6 py-12">
<a href="/" class="text-cyan-400 hover:underline">&larr; agentSAFE</a>
<article class="prose prose-invert prose-sm max-w-none
 [&_table]:w-full [&_table]:text-sm [&_th]:border [&_th]:border-zinc-700
 [&_th]:px-2 [&_th]:py-1 [&_td]:border [&_td]:border-zinc-800
 [&_td]:px-2 [&_td]:py-1 [&_code]:text-cyan-300">
{body}
</article>
<footer class="mt-12 border-t border-zinc-800 pt-6 text-xs text-zinc-400">
<a href="/terms" class="hover:underline">Terms</a> &middot;
<a href="/privacy" class="hover:underline">Privacy</a> &middot;
<a href="/refund" class="hover:underline">Refund</a>
</footer>
</div>
</body>
</html>
"""


def legal_html(slug: str) -> str:
    """Rendered HTML page for a legal slug."""
    title = {"terms": "Terms of Service", "privacy": "Privacy Policy", "refund": "Refund Policy"}[
        slug
    ]
    body = md_lib.markdown(legal_markdown(slug), extensions=["tables", "fenced_code"])
    return _PAGE_SHELL.format(title=title, body=body)


CLAUDE_CONFIG_JSON = """{
  "mcpServers": {
    "agentsafe": {
      "type": "http",
      "url": "https://YOUR-DEPLOYMENT-HOST/mcp"
    }
  }
}"""

_TALLY_URL = "https://tally.so/r/laby7B"

_INDEX_ROWS = (
    ("1 &ndash; 100", "$0.50"),
    ("101 &ndash; 500", "$2.50"),
    ("501 &ndash; 1,000", "$5.00"),
    ("1,001 &ndash; 5,000", "$25.00"),
)


def _build_index_html() -> str:
    rows = "\n".join(
        f'          <tr class="border-t border-zinc-800"><td class="px-4 py-2">{label}</td>'
        f'<td class="px-4 py-2 text-right">{price}</td></tr>'
        for label, price in _INDEX_ROWS
    )
    enterprise_cell = (
        f'<a class="text-cyan-300 hover:underline" href="{_TALLY_URL}">Enterprise inquiry</a>'
    )
    pre_class = (
        "overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-900 p-4 text-xs text-cyan-300"
    )
    build_tag = "v" + __version__ + "-" + os.environ.get("VERCEL_GIT_COMMIT_SHA", "dev")[:8]
    return f"""<!DOCTYPE html>
<html lang="en" class="bg-black text-white">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>agentSAFE - AI Smart Contract Audits on Ethereum Mainnet</title>
<script src="https://cdn.tailwindcss.com"></script>
<script defer src="/static/x402-bridge.js"></script>
</head>
<body class="bg-black text-white min-h-screen">
<div class="mx-auto max-w-3xl px-6 py-16">

  <header class="mb-12">
    <h1 class="text-4xl font-bold tracking-tight">agent<span class="text-cyan-400">SAFE</span></h1>
    <p class="mt-3 text-zinc-400">AI-assisted smart-contract risk screening for
    Ethereum Mainnet. Paid per audit in USDC on Base via x402 &mdash; no account,
    no subscription.</p>
    <p class="mt-1 text-xs text-zinc-500">AI-assisted screening, not a formal
    security audit. Findings require human verification.</p>
  </header>

  <a href="{_TALLY_URL}"
     class="block mb-12 rounded-lg border border-cyan-400 bg-cyan-400/10 px-6 py-4
            text-center text-lg font-semibold text-cyan-300 hover:bg-cyan-400/20">
    Need an audit over 5,000 lines? &mdash; Contact us for enterprise pricing &rarr;
  </a>

  <section class="mb-12 rounded-xl border border-zinc-800 bg-zinc-900/50 p-6">
    <h2 class="mb-1 text-xl font-semibold">Start an audit</h2>
    <p class="mb-4 text-sm text-zinc-400">Enter a verified Ethereum Mainnet
    contract address and pay in USDC via x402 on Base, Arbitrum,
    Polygon or another supported chain. <span class="text-zinc-500">From $0.50
    &mdash; the exact price is quoted by the service before payment is
    requested.</span></p>
    <div class="flex flex-col gap-3 sm:flex-row">
      <input id="addr" type="text" spellcheck="false" autocomplete="off"
        placeholder="0x..."
        class="flex-1 rounded-lg border border-zinc-700 bg-black px-4 py-3
               font-mono text-sm text-white placeholder-zinc-600 focus:border-cyan-400 focus:outline-none">
      <button id="start"
        class="rounded-lg bg-cyan-400 px-6 py-3 font-semibold text-black
               hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-50">
        Pay USDC to audit
      </button>
    </div>
    <div class="mt-3">
      <input id="email" type="email" spellcheck="false" autocomplete="email"
        placeholder="your@email.com (optional - we email you the report when it is ready, audits take ~20 min)"
        class="w-full rounded-lg border border-zinc-700 bg-black px-4 py-3
               text-sm text-white placeholder-zinc-600 focus:border-cyan-400 focus:outline-none">
      <p class="mt-1 text-xs text-zinc-500">Optional: leave an email and we send the report link when the audit finishes, so you can close this page while you wait.</p>
    </div>
    <div id="flow" class="mt-4 hidden rounded-lg border border-zinc-800 bg-black p-4 text-sm"></div>
    <p id="wallet-hint" class="mt-2 hidden text-xs text-zinc-500">
      Your wallet will open to approve the USDC payment on the selected chain.
    </p>
  </section>

  <script>
  (function () {{
    var REST = "/api/audit";
    var addr = document.getElementById("addr");
    var email = document.getElementById("email");
    var start = document.getElementById("start");
    var flow = document.getElementById("flow");
    var hint = document.getElementById("wallet-hint");
    function show(html) {{ flow.innerHTML = html; flow.classList.remove("hidden"); }}
    function esc(s) {{ return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }}
    // x402 payment-header base64 codecs come from the OFFICIAL SDK bundle
    // (window.X402Bridge.safeBase64Encode / safeBase64Decode, @x402/core).
    // Hand-rolling base64 here has a single alphabet/padding mistake away
    // from silently corrupting a payment payload, so the manual btoa/atob
    // helpers are gone on purpose. The bridge is mandatory for payment
    // anyway (it performs the EIP-3009 signing).
    function paymentCodec() {{
      var bridge = window.X402Bridge;
      if (!(bridge && bridge.safeBase64Encode && bridge.safeBase64Decode)) return null;
      return bridge;
    }}
    // Chain metadata for the networks this service advertises (EIP-3009).
    var CHAINS = {{
      // x402.org's facilitator currently registers ONLY Base Sepolia
      // (eip155:84532) for the exact/EIP-3009 scheme. Base mainnet (8453),
      // Arbitrum (42161) and Polygon (137) return "No facilitator registered"
      // from x402.org and cannot settle, so Base Sepolia is listed first as
      // the default payable network. The others stay for when x402.org
      // enables them, but a payment on them will not complete today.
      "eip155:84532": {{ name: "Base Sepolia (testnet)", chainId: 84532, rpc: ["https://sepolia.base.org"],       symbol: "ETH",  decimals: 18, testnet: true, tokenName: "USDC" }},
      "eip155:8453":  {{ name: "Base",     chainId: 8453,  rpc: ["https://mainnet.base.org"],                      symbol: "ETH",  decimals: 18, tokenName: "USD Coin" }},
      "eip155:42161": {{ name: "Arbitrum", chainId: 42161, rpc: ["https://arb1.arbitrum.io/rpc"],                  symbol: "ETH",  decimals: 18, tokenName: "USD Coin" }},
      "eip155:137":   {{ name: "Polygon",  chainId: 137,   rpc: ["https://polygon-rpc.com"],                        symbol: "POL",  decimals: 18, tokenName: "USD Coin" }}
    }};
    // A wallet session can only host ONE pending request at a time (MetaMask
    // rejects a second wallet_requestPermissions with "already pending").
    // Keep a global lock so clicking another chain button while the wallet
    // popup is open does not fire a second connect request.
    var paying = false;
    var payingSince = 0;
    // Wallet requests can hang forever (popup ignored, extension wedged,
    // network stall). Cap every wallet call so the lock always releases.
    function withWalletTimeout(p, label) {{
      var ms = 90000;
      return new Promise(function (resolve, reject) {{
        var t = setTimeout(function () {{
          reject(new Error(label + " timed out after " + (ms / 1000) + "s. "
            + "Close any wallet popup (or unlock MetaMask) and try again."));
        }}, ms);
        p.then(function (v) {{ clearTimeout(t); resolve(v); }},
               function (e) {{ clearTimeout(t); reject(e); }});
      }});
    }}
    function friendlyErr(err) {{
      var msg = (err && err.message) || String(err);
      if (/already pending/i.test(msg)) {{
        return "Your wallet already has a pending request. Complete or close the wallet popup, then try again.";
      }}
      if (/not been authorized by the user/i.test(msg)) {{
        return "MetaMask has not granted this site permission to sign. "
          + "Click the MetaMask icon, check the Connected sites / Permissions, "
          + "and grant access to this site, then click the network again to retry.";
      }}
      if (/rejected by user|user rejected/i.test(msg)) {{
        return "The request was cancelled in your wallet. Click the network again to retry.";
      }}
      return msg;
    }}
    function isLineLimit(msg) {{
      return /line flat fee|flat fee;|exceed the .*flat fee|REST_FLAT_FEE_LINE_LIMIT/i.test(msg || "");
    }}
    // The REST flat fee only covers small contracts; larger ones are audited via
    // the MCP tool with tiered pricing. Make that explicit and reassure the user
    // that the signature alone moved no funds.
    function lineLimitNote() {{
      return "<div class='mt-2 rounded border border-amber-700/60 bg-amber-900/20 p-3 text-xs text-amber-200'>"
        + "<b>Nothing was charged.</b> A signed payment authorization is only settled "
        + "after the audit is accepted, so an over-limit contract never moves USDC "
        + "(your balance is unchanged).<br>"
        + "This contract is larger than the flat-fee REST cap, which is deliberate: "
        + "the flat fee is priced for small contracts, and larger ones are billed "
        + "per size tier on the MCP endpoint."
        + "</div>";
    }}
    // ---- PROMPT 4: explicit payment-state machine --------------------------
    // Each state maps to a distinct visual (badge + body) so the user can tell
    // "wallet approval pending" from "payment settled" from "status unknown".
    // The page NEVER claims "success" from a wallet signature alone: it only
    // reports "settled" when the backend's structured payment object says so
    // (status === "settled", which requires the facilitator's settlement op).
    var PS = {{
      REQUIRED: "payment-required",          // server asked for payment (402)
      WALLET: "wallet-approval-pending",     // wallet popup for connect/switch/sign
      SUBMITTED: "payment-submitted",        // signed; request in flight
      VERIFYING: "payment-verification-pending", // awaiting the backend's 202
      SETTLED: "payment-settled",            // backend reports settlement succeeded
      FAILED: "payment-failed",              // 402/502/413 or wallet rejection
      UNKNOWN: "payment-status-unknown"      // timeout/network after submit
    }};
    var STATE_COLOR = {{
      "payment-required": "text-yellow-300",
      "wallet-approval-pending": "text-cyan-300",
      "payment-submitted": "text-cyan-300",
      "payment-verification-pending": "text-cyan-300",
      "payment-settled": "text-emerald-400",
      "payment-failed": "text-red-400",
      "payment-status-unknown": "text-amber-300"
    }};
    function statePill(state) {{
      var labels = {{
        "payment-required": "Payment required",
        "wallet-approval-pending": "Wallet approval pending",
        "payment-submitted": "Payment submitted",
        "payment-verification-pending": "Payment verification pending",
        "payment-settled": "Payment settled",
        "payment-failed": "Payment failed",
        "payment-status-unknown": "Payment status unknown"
      }};
      var cls = STATE_COLOR[state] || "text-zinc-300";
      return "<span class='inline-flex items-center gap-1 rounded bg-zinc-800/80 px-2 py-0.5 text-[11px] " + cls + "'>"
        + "&bull; " + esc(labels[state] || state) + "</span>";
    }}
    // Map the backend's machine error_code to a human, state-appropriate line.
    // Falls through to the raw message when the code is unknown.
    function paymentErrorLine(code, msg) {{
      if (code === "invalid_exact_evm_insufficient_balance")
        return "Insufficient USDC balance on the selected network. Top up and retry.";
      if (code === "payment_replay")
        return "This payment was already used (duplicate submission). The audit is not re-dispatched.";
      if (code === "payment_authorization_expired")
        return "The signed payment authorization has expired. Refresh the terms and sign again.";
      if (code === "payment_authorization_not_yet_valid")
        return "The signed payment authorization is not valid yet (start time is in the future).";
      if (code === "payment_resource_mismatch")
        return "This payment was signed for a different resource. Refresh and sign for this audit.";
      if (code === "payment_resource_missing")
        return "The payment payload did not identify the resource. Refresh and retry.";
      if (code === "unsupported_protocol_version")
        return "The payment uses an unsupported protocol version. Refresh the page and retry.";
      if (code === "facilitator_unreachable")
        return "Payment verification is temporarily unavailable (facilitator unreachable). Try again shortly. Your funds were not moved.";
      if (code === "facilitator_malformed")
        return "Payment verification is temporarily unavailable (facilitator error). Try again shortly. Your funds were not moved.";
      if (code === "REST_FLAT_FEE_LINE_LIMIT") return msg;
      return msg;
    }}
    function extractError(data, status) {{
      return {{
        code: (data && data.error_code) || "",
        msg: (data && (data.error_description || data.error || data.error_code))
          || (data && data.detail) || ("HTTP " + status)
      }};
    }}
    // A confirmed payment summary. The user EXPLICITLY confirms paying the
    // exact amount/recipient/network shown before the wallet opens. This is
    // what makes the Mainnet<->Testnet choice deliberate: the page never picks
    // or switches a chain on its own.
    function paymentSummary(acc, meta, onConfirm) {{
      var price = (Number(acc.amount) / 1e6).toFixed(6).replace(/0+$/, "").replace(/\.$/, "");
      var payTo = acc.payTo || "";
      var netName = (meta && meta.name) || acc.network;
      var env = meta && meta.testnet
        ? "<span class='rounded bg-amber-900/60 px-1.5 py-0.5 text-[10px] text-amber-300'>TESTNET (Base Sepolia)</span>"
        : "<span class='rounded bg-emerald-900/60 px-1.5 py-0.5 text-[10px] text-emerald-300'>MAINNET (Base)</span>";
      var envNote = meta && meta.testnet
        ? "<p class='mt-1 text-[11px] text-zinc-400'>This is the <b>testnet</b> chain. No real money moves, but the wallet still signs a real EIP-3009 authorization.</p>"
        : "<p class='mt-1 text-[11px] text-zinc-400'>This is the <b>mainnet</b> chain. USDC will be transferred on Base mainnet.</p>";
      var s = "s" + Math.random().toString(36).slice(2);
      return "<div class='mt-3 rounded-lg border border-zinc-700 bg-zinc-900 p-4'>"
        + "<p class='flex items-center gap-2 text-sm'><span class='font-semibold text-cyan-300'>Confirm payment</span>" + env + "</p>"
        + "<dl class='mt-3 space-y-1 text-sm'>"
        + "<div class='flex justify-between'><dt class='text-zinc-500'>Network</dt><dd class='font-mono text-zinc-200'>" + esc(netName) + " (" + esc(acc.network) + ")</dd></div>"
        + "<div class='flex justify-between'><dt class='text-zinc-500'>Amount</dt><dd class='font-mono text-zinc-200'>" + esc(price) + " USDC</dd></div>"
        + "<div class='flex justify-between'><dt class='text-zinc-500'>Token</dt><dd class='font-mono text-zinc-200'>USDC</dd></div>"
        + "<div class='flex justify-between'><dt class='text-zinc-500'>Recipient</dt><dd class='font-mono text-zinc-200 break-all'>" + esc(payTo) + "</dd></div>"
        + "</dl>" + envNote
        + "<div class='mt-3 flex gap-2'>"
        + "<button id='" + s + "-ok' class='rounded bg-emerald-700 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-600'>Approve &amp; pay</button>"
        + "<button id='" + s + "-back' class='rounded border border-zinc-600 px-4 py-2 text-sm text-zinc-300 hover:border-zinc-400'>Back</button>"
        + "</div></div>";
    }}
    // ---- PROMPT 4: refresh / interrupted-request resume ---------------------
    // Persist the last accepted task so a page refresh never double-pays: the
    // resume affordance links to the report endpoints and the address/network
    // that were used, so the user can check the outcome instead of paying again.
    var LAST_TASK_KEY = "agentsafe_last_task";
    function persistTask(tid, address, network) {{
      try {{
        sessionStorage.setItem(LAST_TASK_KEY, JSON.stringify({{ task_id: tid, address: address, network: network, at: Date.now() }}));
      }} catch (e) {{ /* storage unavailable; ignore */ }}
    }}
    function resumeView() {{
      var raw = null;
      try {{ raw = sessionStorage.getItem(LAST_TASK_KEY); }} catch (e) {{ return ""; }}
      if (!raw) return "";
      var rec = null;
      try {{ rec = JSON.parse(raw); }} catch (e) {{ return ""; }}
      if (!rec || !rec.task_id) return "";
      var ago = Math.round((Date.now() - (rec.at || 0)) / 60000);
      return "<div class='mt-3 rounded-lg border border-zinc-700 bg-zinc-900/70 p-3 text-sm'>"
        + "<p class='text-zinc-300'>You have a recently submitted audit. <b>Do not pay again</b> unless the report is truly missing.</p>"
        + "<p class='mt-1 text-xs text-zinc-500'>Task: <code class='text-cyan-300'>" + esc(rec.task_id) + "</code>"
        + (rec.network ? " &middot; paid on " + esc(rec.network) : "")
        + (rec.address ? " &middot; " + esc(rec.address.slice(0, 10)) + "&hellip;" : "")
        + (rec.at ? " &middot; " + ago + "m ago" : "") + "</p>"
        + "<p class='mt-2 text-xs'>Reports: "
        + "<a class='text-cyan-300 hover:underline' href='/api/audit/" + esc(rec.task_id) + "/report' target='_blank'>HTML</a> &middot; "
        + "<a class='text-cyan-300 hover:underline' href='/api/audit/" + esc(rec.task_id) + "/report.json' target='_blank'>JSON</a> &middot; "
        + "<a class='text-cyan-300 hover:underline' href='/api/audit/" + esc(rec.task_id) + "/report.md' target='_blank'>Markdown</a> &middot; "
        + "<a class='text-cyan-300 hover:underline' href='/api/audit/" + esc(rec.task_id) + "/report.pdf' target='_blank'>PDF</a></p>"
        + "<button id='resume-clear' class='mt-2 text-xs text-zinc-400 hover:text-zinc-200 underline'>Dismiss</button></div>";
    }}
    // Render a payment state: statePill + optional body.
    function showState(state, html) {{
      show(statePill(state) + (html || ""));
    }}
    function fmtTask(tid) {{
      return "<p class='text-emerald-400'>Audit dispatched!</p>"
        + "<p class='mt-1 text-zinc-300'>Task ID: <code class='text-cyan-300'>" + esc(tid) + "</code></p>"
        + "<p class='mt-2 text-zinc-300'>The audit is <b>running in the background</b> and takes a few minutes.</p>"
        + "<p class='text-zinc-300'>Your report will appear here automatically when it is ready - no need to reload.</p>"
        + "<div id='report-probe-" + esc(tid) + "'></div>";
    }}
    // Poll the lightweight STATUS endpoint (one GitHub lookup, no artifact
    // download - the MythX-style async pattern) until the audit finishes.
    // Only a COMPLETED audit reveals the report download links; a FAILED run
    // shows a clear message with the credit/refund pointer.
    var REPORT_POLL_MS = 7000;
    var REPORT_POLL_MAX = 180;
    function startReportProbe(tid) {{
      var box = document.getElementById("report-probe-" + tid);
      if (!box) return;
      var attempt = 0;
      var probe = function () {{
        fetch("/api/audit/" + tid + "/status")
          .then(function (res) {{ return res.json(); }})
          .then(function (s) {{
            var state = (s && s.state) || "";
            if (state === "completed") {{
              box.innerHTML = "<p class='mt-3 text-sm text-emerald-300'>Report ready - download:</p>"
                + "<p class='mt-1 text-xs'>"
                + "<a class='text-cyan-300 hover:underline' href='/api/audit/" + esc(tid) + "/report' target='_blank'>HTML</a> &middot; "
                + "<a class='text-cyan-300 hover:underline' href='/api/audit/" + esc(tid) + "/report.json' target='_blank'>JSON</a> &middot; "
                + "<a class='text-cyan-300 hover:underline' href='/api/audit/" + esc(tid) + "/report.md' target='_blank'>Markdown</a> &middot; "
                + "<a class='text-cyan-300 hover:underline' href='/api/audit/" + esc(tid) + "/report.pdf' target='_blank'>PDF</a></p>";
              return;
            }}
            if (state === "failed") {{
              box.innerHTML = "<p class='mt-3 text-red-400'>The audit failed before producing a report. "
                + "Your payment is preserved (settled) and the credit/refund policy applies - "
                + "re-run the audit to retry.</p>";
              return;
            }}
            if (state === "running" || state === "queued") {{
              box.innerHTML = "<p class='mt-3 text-cyan-300'>Audit in progress&hellip; "
                + "<span class='text-xs text-zinc-500'>the report download links appear here automatically when it completes</span></p>";
              if (++attempt < REPORT_POLL_MAX) setTimeout(probe, REPORT_POLL_MS);
              return;
            }}
            box.innerHTML = "<p class='mt-3 text-zinc-400'>Report not available yet. "
              + "<a class='text-cyan-300 hover:underline' href='/api/audit/" + esc(tid) + "/report' target='_blank'>Check manually</a></p>";
          }})
          .catch(function () {{
            if (++attempt < REPORT_POLL_MAX) setTimeout(probe, REPORT_POLL_MS);
          }});
      }};
      setTimeout(probe, REPORT_POLL_MS);
    }}
    // Structured payment receipt from the backend 202 body (PROMPT 3): shows
    // the settlement outcome and the on-chain transaction hash ONLY when the
    // backend's settlement op confirmed it - never fabricated client-side.
    function paymentReceipt(p) {{
      if (!p) return "";
      var rows = "<p class='mt-2 rounded border border-emerald-800/60 bg-emerald-900/20 p-3 text-xs text-emerald-200'>"
        + "<b>Payment status:</b> " + esc(p.status)
        + (p.network ? " &middot; " + esc(p.network) : "");
      if (p.transaction) rows += "<br><span class='text-zinc-300'>Transaction:</span> <code class='break-all text-cyan-300'>" + esc(p.transaction) + "</code>";
      if (p.payer) rows += "<br><span class='text-zinc-300'>Payer:</span> <code class='break-all'>" + esc(p.payer) + "</code>";
      if (p.payment_ref) rows += "<br><span class='text-zinc-300'>Payment ref:</span> <code class='break-all'>" + esc(p.payment_ref) + "</code>";
      if (p.status !== "settled") rows += "<br><span class='text-amber-300'>Settlement did not confirm. The audit still runs; the report is not withheld, but no payment success is reported.</span>";
      return rows + "</p>";
    }}
    // Guidance shown when the submit request was interrupted and the payment
    // outcome is genuinely unknown (network error / timeout after signing).
    function statusUnknownNote() {{
      return "<div class='mt-3 rounded border border-amber-700/60 bg-amber-900/20 p-3 text-xs text-amber-200'>"
        + "<b>How to check</b>: if the audit was accepted you will have a Task ID and free report links. "
        + "Look above for the resume card, or re-enter the same address and check whether the report loads. "
        + "Do <b>not</b> sign a second payment for the same audit unless the report is missing."
        + "</div>";
    }}
    // Renders the network-choice buttons from the 402 terms AND binds the
    // click handler. Reusable so a user who backs out of the confirmation
    // summary can pick a different network without re-requesting terms.
    function renderChoices(accs, a, clickFn) {{
      var lines = [];
      lines.push("<p class='text-yellow-300'>Payment required to start this audit. Pick the network you want to pay on:</p>");
      lines.push("<p class='text-xs text-zinc-500'>The flat fee covers contracts up to <b>500 source lines</b>. "
        + "Larger contracts are billed per size tier on the MCP endpoint (tool "
        + "<code>audit_contract</code>); requesting one here is refused <i>before</i> "
        + "settlement, so no USDC is ever taken.</p>");
      accs.forEach(function (acc, i) {{
        var meta = CHAINS[acc.network] || {{ name: acc.network }};
        // USDC is 6 decimals. Show the true amount without padding the
        // trailing zeros so a sub-cent testnet price ($0.0001) does not
        // render as "0.00 USDC".
        var price = (Number(acc.amount) / 1e6).toFixed(6).replace(/0+$/, "").replace(/\.$/, "");
        var payTo = acc.payTo || "";
        var tag = meta.testnet
          ? " <span class='rounded bg-amber-900/60 px-1.5 py-0.5 text-[10px] text-amber-300'>TESTNET (free USDC)</span>"
          : "";
        lines.push("<button data-chain='" + i + "' class='chain-opt mt-2 w-full rounded-lg border border-zinc-700 bg-zinc-900 px-4 py-3 text-left text-sm hover:border-cyan-400'>"
          + "<span class='font-semibold text-cyan-300'>Pay with " + esc(meta.name) + "</span>" + tag
          + " <span class='text-zinc-300'>" + esc(acc.network) + "</span>"
          + " &mdash; <b>" + price + " USDC</b>"
          + "<br><span class='text-xs text-zinc-500'>pay to: <code class='break-all'>" + esc(payTo) + "</code></span>"
          + "</button>");
      }});
      lines.push("<p class='mt-3 text-xs text-zinc-500'>Your wallet will open and switch to that network, then ask you to approve the payment. "
        + "Prefer the terminal? Run the curl command below with an x402-enabled client:</p>");
      var curlCmd = "curl -X POST " + window.location.origin + REST
        + " -H 'content-type: application/json' -d '" + JSON.stringify({{"address": a}}) + "'";
      lines.push("<pre class='mt-2 overflow-x-auto rounded border border-zinc-800 bg-zinc-900 p-3 text-xs text-cyan-300'><code>"
        + esc(curlCmd) + "</code></pre>");
      showState(PS.REQUIRED, resumeView() + lines.join(""));
      flow.querySelectorAll("button.chain-opt").forEach(function (b) {{
        b.addEventListener("click", function () {{ clickFn(b, accs, a); }});
      }});
    }}
    // Click handler for one network choice: explicit payment summary first
    // (amount / token / recipient / network), then the wallet dance, then the
    // submitted -> settled / failed / unknown states.
    async function bindChainClick(btn, accs, a) {{
      if (paying) {{
        // A request may have hung (ignored popup / wedged wallet).
        // After the stale-lock window the lock self-releases so the
        // user is never stuck.
        var staleMs = 60000;
        if (Date.now() - payingSince < staleMs) {{
          show("<p class='text-yellow-300'>A wallet request is already open. "
            + "Complete or close the wallet popup (or wait " + Math.ceil((staleMs - (Date.now() - payingSince)) / 1000)
            + "s for the lock to reset), then try again.</p>");
          return;
        }}
        paying = false;
      }}
      var idx = Number(btn.getAttribute("data-chain"));
      var accept = accs[idx];
      if (!accept) return;
      var meta = CHAINS[accept.network] || {{ name: accept.network, chainId: null }};
      // Explicit payment summary FIRST: the user sees and confirms the
      // exact amount / USDC token / recipient / network before the
      // wallet opens. This is the deliberate Mainnet<->Testnet choice;
      // the page never switches a chain on its own.
      showState(PS.REQUIRED, resumeView() + paymentSummary(accept, meta));
      var confirmed = await new Promise(function (resolve) {{
        var okBtn = document.querySelector("button[id$='-ok']");
        var backBtn = document.querySelector("button[id$='-back']");
        if (okBtn) okBtn.addEventListener("click", function () {{ resolve(true); }});
        if (backBtn) backBtn.addEventListener("click", function () {{ resolve(false); }});
      }});
      if (!confirmed) {{
        // User backed out of paying on this network - do not open the
        // wallet or switch to any chain. Re-render the choices (with a
        // fresh click binding).
        paying = false;
        renderChoices(accs, a, bindChainClick);
        return;
      }}
      paying = true;
      payingSince = Date.now();
      flow.querySelectorAll("button.chain-opt").forEach(function (b) {{ b.disabled = true; }});
      showState(PS.WALLET, "<p class='text-zinc-300'>Opening your wallet to approve the payment on " + esc(meta.name) + " (USDC to " + esc(accept.payTo || "") + ")...</p>");
      if (hint) hint.classList.remove("hidden");
      try {{
        var out = await payOnChain(a, accept);
        if (out && out.__unknown) {{
          // Request never got a response: settlement outcome unknown.
          showState(PS.UNKNOWN,
            "<p class='text-zinc-300'>The request was interrupted and the payment status is <b>unknown</b>. "
            + "It may or may not have settled. <b>Check before paying again</b> - "
            + "duplicate payments are rejected and never double-settle.</p>"
            + statusUnknownNote());
          persistTask("unknown:" + String(a).slice(0, 10) + ":" + (accept.network || ""), a, accept.network);
          return;
        }}
        var tid = (out && (out.task_id || out.taskId)) || "";
        if (tid) {{
          persistTask(tid, a, (out && out.payment && out.payment.network) || accept.network);
          showState(PS.SETTLED, fmtTask(tid) + paymentReceipt(out.payment));
          // Poll the report endpoint and reveal the links only when the audit
          // actually completes (the audit runs in the background).
          if (typeof startReportProbe === "function") startReportProbe(tid);
        }} else {{
          showState(PS.SETTLED, "<pre class='mt-2 overflow-x-auto rounded border border-zinc-800 bg-zinc-900 p-3 text-xs text-cyan-300'>"
            + esc(JSON.stringify(out, null, 2)) + "</pre>");
        }}
      }} catch (err) {{
        var emsg = friendlyErr(err);
        var code = (err && err.error_code) || "";
        var shown = paymentErrorLine(code, emsg);
        if (code === "payment_replay") {{
          // Duplicate submission - the task may already exist; guide
          // toward the resume view instead of a dead error.
          shown += " " + resumeView();
        }}
        showState(PS.FAILED,
          "<p>" + esc(shown) + "</p>"
          + (err && err.diag ? "<p class='mt-1 text-[11px] text-zinc-500'>" + err.diag + "</p>" : "")
          + (isLineLimit(shown) ? lineLimitNote() : ""));
      }} finally {{
        paying = false;
        flow.querySelectorAll("button.chain-opt").forEach(function (b) {{ b.disabled = false; }});
        if (hint) hint.classList.add("hidden");
      }}
    }}
    // Sign an EIP-3009 transferWithAuthorization with the user's wallet and
    // retry the audit request with the x402 payment header (X-PAYMENT).
    async function payOnChain(a, accept) {{
      var meta = CHAINS[accept.network] || {{ name: accept.network, chainId: null }};
      if (!window.ethereum) throw new Error("No wallet found. Install MetaMask or another web3 wallet, then retry.");
      var eth = window.ethereum;
      // Wallet connection mirrors the official x402 paywall (viem's wallet
      // connect): read eth_accounts first (zero popups for an already-granted
      // site); if the site is not yet authorized, ask with
      // wallet_requestPermissions (which returns the granted accounts via its
      // caveats); fall back to eth_requestAccounts only if that yields nothing.
      // A MetaMask that returns an address from eth_accounts but rejects
      // eth_signTypedData_v4 with "not been authorized by the user" is handled
      // by the explicit permission request below plus the sign retry later.
      var accounts = [];
      try {{ accounts = await withWalletTimeout(eth.request({{ method: "eth_accounts" }}), "Wallet"); }} catch (e) {{ accounts = []; }}
      if (!accounts || !accounts.length) {{
        try {{
          var perm = await withWalletTimeout(
            eth.request({{ method: "wallet_requestPermissions", params: [{{ eth_accounts: {{}} }}] }}),
            "Authorize"
          );
          var caveat = perm && perm[0] && perm[0].caveats && perm[0].caveats[0]
            && perm[0].caveats[0].value;
          accounts = caveat && caveat.length ? caveat : [];
          if (accounts.length) {{
            try {{ accounts = await withWalletTimeout(eth.request({{ method: "eth_accounts" }}), "Wallet"); }} catch (e) {{}}
          }}
        }} catch (e) {{ /* fall through to eth_requestAccounts */ }}
        if (!accounts || !accounts.length) {{
          accounts = await withWalletTimeout(eth.request({{ method: "eth_requestAccounts" }}), "Wallet connect");
        }}
      }}
      var from = accounts && accounts[0];
      if (!from) throw new Error("Wallet connection rejected.");
      if (meta.chainId) {{
        var cur = await withWalletTimeout(eth.request({{ method: "eth_chainId" }}), "Wallet");
        var want = "0x" + meta.chainId.toString(16);
        if (String(cur).toLowerCase() !== want.toLowerCase()) {{
          try {{
            await withWalletTimeout(eth.request({{ method: "wallet_switchEthereumChain", params: [{{ chainId: want }}] }}), "Switch network");
            // MetaMask resolves the switch RPC before the wallet actually
            // re-reads its new chain; re-read eth_chainId until it matches so
            // we never sign an EIP-712 digest on the wrong chain (which would
            // recover a different signer -> invalid_exact_evm_signature).
            for (var k = 0; k < 8; k++) {{
              var after = String(await withWalletTimeout(eth.request({{ method: "eth_chainId" }}), "Wallet")).toLowerCase();
              if (after === want.toLowerCase()) break;
              await new Promise(function (r) {{ setTimeout(r, 150); }});
            }}
            var confirmed = String(await withWalletTimeout(eth.request({{ method: "eth_chainId" }}), "Wallet")).toLowerCase();
            if (confirmed !== want.toLowerCase()) {{
              throw new Error("Wallet is still on chain " + confirmed + " (expected " + want + "). Please switch to "
                + meta.name + " in MetaMask and retry.");
            }}
          }} catch (sw) {{
            if (sw && sw.code === 4902 && meta.rpc) {{
              // Chain not in wallet yet: offer to add it (MetaMask pops an
              // "Add network" confirmation).
              await withWalletTimeout(eth.request({{
                method: "wallet_addEthereumChain",
                params: [{{
                  chainId: want,
                  chainName: meta.name,
                  rpcUrls: meta.rpc,
                  nativeCurrency: {{ name: meta.symbol, symbol: meta.symbol, decimals: meta.decimals }}
                }}]
              }}), "Add network");
            }} else {{
              throw new Error("Please switch your wallet to " + meta.name + " and retry.");
            }}
          }}
        }}
      }}
      // Payment signing is delegated to the OFFICIAL @x402/evm exact scheme
      // (window.X402Bridge): it generates the 32-byte(bytes32) nonce, builds the
      // EIP-712 domain from the backend's authoritative accept.extra name/version,
      // signs via eth_signTypedData_v4, and returns the complete v2 payload the
      // backend's x402 server verification expects. Hand-rolling any of this
      // (nonce length, domain name, typed-data serialization) has caused real
      // signature failures in the past.
      var bridge = window.X402Bridge;
      if (!(bridge && bridge.createPaymentPayload)) {{
        throw new Error("Payment module not loaded. Hard-refresh the page and retry.");
      }}
      // Re-read the ACTIVE wallet account right before signing. MetaMask signs
      // eth_signTypedData_v4 with its currently-selected account; if the user
      // switched accounts after connecting, the cached `from` is stale and the
      // recovered signer != payload.from -> invalid_exact_evm_signature. Refresh
      // now so we always sign with the exact account MetaMask will use.
      var live = [];
      try {{ live = await withWalletTimeout(eth.request({{ method: "eth_accounts" }}), "Wallet"); }} catch (e) {{ live = []; }}
      if (live && live[0]) from = live[0];
      var signed;
      try {{
        signed = await withWalletTimeout(
          bridge.createPaymentPayload(eth, from, accept, window.location.origin + REST),
          "Signature"
        );
      }} catch (sigErr) {{
        var sigMsg = (sigErr && sigErr.message) || String(sigErr);
        // eth_requestAccounts above has already connected this dapp, but a
        // stale/unauthorized session can still reject the FIRST typed-data
        // signature with "not been authorized by the user". Ask for the
        // account permission once and retry. If the retry also fails, stop
        // with a clear, actionable message instead of looping silently.
        if (/not been authorized by the user/i.test(sigMsg)) {{
          try {{
            await withWalletTimeout(eth.request({{ method: "wallet_requestPermissions", params: [{{ eth_accounts: {{}} }}] }}), "Authorize");
          }} catch (e) {{ /* fall through; the retry surfaces the real problem */ }}
          try {{
            signed = await withWalletTimeout(
              bridge.createPaymentPayload(eth, from, accept, window.location.origin + REST),
              "Signature"
            );
          }} catch (retryErr) {{
            var rmsg = (retryErr && retryErr.message) || String(retryErr);
            if (/not been authorized by the user/i.test(rmsg)) {{
              throw new Error("MetaMask still does not authorize this site to sign. "
                + "Open MetaMask > Permissions, allow this site, then click the network again to retry.");
            }}
            throw retryErr;
          }}
        }} else {{
          throw sigErr;
        }}
      }}
      var payload = signed.payload;
      // Diagnostic: record what was actually signed so a rejection can be
      // debugged from the page. Surface it only on failure below.
      var signedChain = "?";
      try {{ signedChain = String(await eth.request({{ method: "eth_chainId" }})).toLowerCase(); }} catch (e) {{ signedChain = "?"; }}
      var diag = {{ network: accept.network, chainIdAtSign: signedChain, from: from,
        nonceLen: (payload && payload.payload && payload.payload.authorization
          && String(payload.payload.authorization.nonce || "").length) || -1 }};
      var codec = paymentCodec();
      if (!codec) throw new Error("Payment module not loaded. Hard-refresh the page and retry.");
      var submittedState = function () {{ showState(PS.SUBMITTED, "<p class='text-zinc-300'>Payment signed. Submitting to the service...</p>"); }};
      submittedState();
      // Retry the ORIGINAL audit request with the official x402 V2 payment
      // header (safeBase64Encode of the SDK-built payload). No hand-rolled
      // base64, no hand-assembled protocol object.
      var res;
      try {{
        res = await fetch(REST, {{
          method: "POST",
          headers: {{
            "content-type": "application/json",
            "X-PAYMENT": codec.safeBase64Encode(JSON.stringify(payload))
          }},
          body: JSON.stringify(auditBody(a))
        }});
      }} catch (netErr) {{
        // Request never got a response: the payment may or may not have been
        // settled. This is an UNKNOWN state - tell the user explicitly so they
        // do not assume success or blindly re-pay.
        return {{ __unknown: true, address: a, network: accept.network, error: netErr }};
      }}
      var text = await res.text();
      var data = null;
      try {{ data = JSON.parse(text); }} catch (e) {{ data = {{}}; }}
      if (!res.ok) {{
        // Prefer the backend's machine error_description, then its error_code,
        // then (for 500s) the diagnostic `detail` (exception class + message)
        // so a server-side failure is visible instead of a bare "internal error".
        var msg = (data && (data.error_description || data.error || data.error_code))
          || (data && data.detail) || ("HTTP " + res.status);
        if (data && data.detail && data.error) msg = data.error + " (" + data.detail + ")";
        var friendly = paymentErrorLine((data && data.error_code) || "", msg);
        if (res.status === 402) friendly = "Payment rejected: " + friendly;
        var e = new Error(friendly);
        e.status = res.status;
        e.error_code = (data && data.error_code) || "";
        e.diag = "signed on " + esc(diag.chainIdAtSign)
          + " / accepted " + esc(diag.network) + " / from " + esc((diag.from || "").slice(0, 10)) + "&hellip;"
          + " / nonce len " + diag.nonceLen;
        throw e;
      }}
      data.__submitted = true;
      return data;
    }}
    // Optional customer email: sent with both dispatch calls so the server
    // can email the report link when the audit completes. Empty -> omitted.
    function auditBody(a) {{
      var body = {{ "address": a }};
      var em = (email && email.value || "").trim();
      if (em) body.email = em;
      return body;
    }}
    start.addEventListener("click", async function () {{
      var a = (addr.value || "").trim();
      var em = (email && email.value || "").trim();
      if (em && !/^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$/.test(em)) {{
        show("<p class='text-red-400'>Enter a valid email address (or leave it empty).</p>");
        return;
      }}
      if (!/^0x[0-9a-fA-F]{{40}}$/.test(a)) {{ show("<p class='text-red-400'>Enter a valid 0x-prefixed contract address.</p>"); return; }}
      start.disabled = true; start.textContent = "Contacting service...";
      show("<p class='text-zinc-400'>Requesting payment terms from the service...</p>");
      try {{
        var res = await fetch(REST, {{
          method: "POST",
          headers: {{"content-type": "application/json"}},
          body: JSON.stringify(auditBody(a))
        }});
        if (res.status === 202) {{
          var d = await res.json().catch(function () {{ return {{}}; }});
          if (d.task_id) persistTask(d.task_id, a, (d.payment && d.payment.network) || "");
          show(fmtTask(d.task_id || "") + (d.payment ? paymentReceipt(d.payment) : ""));
          return;
        }}
        if (res.status !== 402) {{
          var e = await res.json().catch(function () {{ return {{}}; }});
          show("<p class='text-red-400'>" + esc(e.error || ("HTTP " + res.status)) + "</p>");
          return;
        }}
        var codec = paymentCodec();
        if (!codec) {{
          show("<p class='text-red-400'>Payment module not loaded. Hard-refresh the page and retry.</p>");
          return;
        }}
        var req = res.headers.get("PAYMENT-REQUIRED") || "";
        var terms = null;
        try {{ terms = req ? JSON.parse(codec.safeBase64Decode(req)) : null; }} catch (e) {{ terms = null; }}
        var accs = (terms && terms.accepts && terms.accepts.length) ? terms.accepts : [];
        if (!accs.length) {{ show("<p class='text-red-400'>Service did not return payment terms.</p>"); return; }}
        // Keep the server's accept order: the backend advertises the primary
        // payable network first (mainnet Base by default), then the extra
        // chains. Re-sorting here could surface a testnet ahead of the
        // real-money chain a mainnet deployment actually charges on.
        renderChoices(accs, a, bindChainClick);
      }} catch (err) {{
        show("<p class='text-red-400'>Request failed: " + esc((err && err.message) || String(err)) + "</p>");
      }} finally {{
        start.disabled = false; start.textContent = "Pay USDC to audit";
      }}
    }});
  }})();
  </script>

  <section class="mb-12">
    <h2 class="mb-4 text-xl font-semibold">Pricing</h2>
    <div class="overflow-x-auto rounded-lg border border-zinc-800">
      <table class="w-full text-sm">
        <thead class="bg-zinc-900 text-left text-zinc-400">
          <tr><th class="px-4 py-2">Verified source lines</th>
              <th class="px-4 py-2 text-right">Price (USDC)</th></tr>
        </thead>
        <tbody>
{rows}
          <tr class="border-t border-zinc-800"><td class="px-4 py-2">More than 5,000</td>
              <td class="px-4 py-2 text-right">{enterprise_cell}</td></tr>
        </tbody>
      </table>
    </div>
    <p class="mt-2 text-xs text-zinc-500">Line count is determined by the
    service from the verified source; blank lines excluded. Reports are
    retrieved with the issued task ID at no extra charge.</p>
  </section>

  <section class="mb-12">
    <h2 class="mb-4 text-xl font-semibold">Use with Claude</h2>
    <p class="mb-2 text-sm text-zinc-400">Add agentSAFE to your MCP client
    config (replace the host with your deployment URL):</p>
    <pre class="{pre_class}"><code>{CLAUDE_CONFIG_JSON}</code></pre>
  </section>

  <footer class="mt-16 border-t border-zinc-800 pt-6 text-xs text-zinc-400">
    <div class="mb-3">
      <a href="/terms" class="hover:underline">Terms of Service</a> &middot;
      <a href="/privacy" class="hover:underline">Privacy Policy</a> &middot;
      <a href="/refund" class="hover:underline">Refund Policy</a>
    </div>
    <p>Operated by workfern (Hong Kong). AI-assisted risk screening, not a
    formal security audit.</p>
    <p class="mt-2">landing build {build_tag}</p>
  </footer>

</div>
</body>
</html>
"""


INDEX_HTML = _build_index_html()
