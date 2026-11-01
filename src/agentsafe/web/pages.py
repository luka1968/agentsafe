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
    return f"""<!DOCTYPE html>
<html lang="en" class="bg-black text-white">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>agentSAFE - AI Smart Contract Audits on Ethereum Mainnet</title>
<script src="https://cdn.tailwindcss.com"></script>
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
    <div id="flow" class="mt-4 hidden rounded-lg border border-zinc-800 bg-black p-4 text-sm"></div>
    <p id="wallet-hint" class="mt-2 hidden text-xs text-zinc-500">
      Your wallet will open to approve the USDC payment on the selected chain.
    </p>
  </section>

  <script>
  (function () {{
    var REST = "/api/audit";
    var addr = document.getElementById("addr");
    var start = document.getElementById("start");
    var flow = document.getElementById("flow");
    var hint = document.getElementById("wallet-hint");
    function show(html) {{ flow.innerHTML = html; flow.classList.remove("hidden"); }}
    function esc(s) {{ return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }}
    function b64encode(obj) {{ return btoa(unescape(encodeURIComponent(JSON.stringify(obj)))); }}
    function b64decode(s) {{ try {{ return JSON.parse(atob(s.replace(/-/g, "+").replace(/_/g, "/"))); }} catch (e) {{ return null; }} }}
    // Chain metadata for the networks this service advertises (EIP-3009).
    var CHAINS = {{
      "eip155:8453":  {{ name: "Base",     chainId: 8453 }},
      "eip155:42161": {{ name: "Arbitrum", chainId: 42161 }},
      "eip155:137":   {{ name: "Polygon",  chainId: 137 }}
    }};
    function fmtTask(tid) {{
      return "<p class='text-emerald-400'>Audit dispatched!</p>"
        + "<p class='mt-1 text-zinc-300'>Task ID: <code class='text-cyan-300'>" + esc(tid) + "</code></p>"
        + "<p class='mt-2 text-xs text-zinc-500'>Reports (free retrieval): "
        + "<a class='text-cyan-300 hover:underline' href='/api/audit/" + esc(tid) + "/report' target='_blank'>HTML</a> &middot; "
        + "<a class='text-cyan-300 hover:underline' href='/api/audit/" + esc(tid) + "/report.json' target='_blank'>JSON</a> &middot; "
        + "<a class='text-cyan-300 hover:underline' href='/api/audit/" + esc(tid) + "/report.md' target='_blank'>Markdown</a> &middot; "
        + "<a class='text-cyan-300 hover:underline' href='/api/audit/" + esc(tid) + "/report.pdf' target='_blank'>PDF</a></p>";
    }}
    function randomHex(len) {{
      var out = "";
      for (var i = 0; i < len; i++) {{ out += "0123456789abcdef".charAt(Math.floor(Math.random() * 16)); }}
      return out;
    }}
    // Sign an EIP-3009 transferWithAuthorization with the user's wallet and
    // retry the audit request with the x402 payment header (X-PAYMENT).
    async function payOnChain(a, accept) {{
      var meta = CHAINS[accept.network] || {{ name: accept.network, chainId: null }};
      if (!window.ethereum) throw new Error("No wallet found. Install MetaMask or another web3 wallet, then retry.");
      var eth = window.ethereum;
      var accounts = await eth.request({{ method: "eth_requestAccounts" }});
      var from = accounts && accounts[0];
      if (!from) throw new Error("Wallet connection rejected.");
      if (meta.chainId) {{
        var cur = await eth.request({{ method: "eth_chainId" }});
        var want = "0x" + meta.chainId.toString(16);
        if (String(cur).toLowerCase() !== want.toLowerCase()) {{
          try {{ await eth.request({{ method: "wallet_switchEthereumChain", params: [{{ chainId: want }}] }}); }}
          catch (sw) {{ throw new Error("Please switch your wallet to " + meta.name + " and retry."); }}
        }}
      }}
      var validAfter = 0;
      var validBefore = Math.floor(Date.now() / 1000) + (accept.maxTimeoutSeconds || 300);
      var nonce = "0x" + randomHex(32);
      var domain = {{
        name: "USD Coin",
        version: "2",
        chainId: meta.chainId,
        verifyingContract: accept.asset
      }};
      var types = {{
        EIP712Domain: [
          {{ name: "name", type: "string" }},
          {{ name: "version", type: "string" }},
          {{ name: "chainId", type: "uint256" }},
          {{ name: "verifyingContract", type: "address" }}
        ],
        TransferWithAuthorization: [
          {{ name: "from", type: "address" }},
          {{ name: "to", type: "address" }},
          {{ name: "value", type: "uint256" }},
          {{ name: "validAfter", type: "uint256" }},
          {{ name: "validBefore", type: "uint256" }},
          {{ name: "nonce", type: "bytes32" }}
        ]
      }};
      var message = {{
        from: from,
        to: accept.payTo,
        value: accept.amount,
        validAfter: validAfter,
        validBefore: validBefore,
        nonce: nonce
      }};
      var typedData = {{
        primaryType: "TransferWithAuthorization",
        types: types,
        domain: domain,
        message: message
      }};
      var signature = await eth.request({{
        method: "eth_signTypedData_v4",
        params: [from, JSON.stringify(typedData)]
      }});
      var payload = {{
        x402Version: 2,
        scheme: "exact",
        network: accept.network,
        resource: {{ url: window.location.origin + REST, mimeType: "application/json" }},
        accepted: accept,
        payload: {{
          signature: signature,
          authorization: {{
            from: from,
            to: accept.payTo,
            value: String(accept.amount),
            validAfter: String(validAfter),
            validBefore: String(validBefore),
            nonce: nonce
          }}
        }}
      }};
      var res = await fetch(REST, {{
        method: "POST",
        headers: {{
          "content-type": "application/json",
          "X-PAYMENT": b64encode(payload)
        }},
        body: JSON.stringify({{ "address": a }})
      }});
      var text = await res.text();
      var data = null;
      try {{ data = JSON.parse(text); }} catch (e) {{ data = {{}}; }}
      if (!res.ok) {{
        var msg = (data && (data.error_description || data.error)) || ("HTTP " + res.status);
        if (res.status === 402) msg = "Payment rejected: " + msg;
        throw new Error(msg);
      }}
      return data;
    }}
    start.addEventListener("click", async function () {{
      var a = (addr.value || "").trim();
      if (!/^0x[0-9a-fA-F]{{40}}$/.test(a)) {{ show("<p class='text-red-400'>Enter a valid 0x-prefixed contract address.</p>"); return; }}
      start.disabled = true; start.textContent = "Contacting service...";
      show("<p class='text-zinc-400'>Requesting payment terms from the service...</p>");
      try {{
        var res = await fetch(REST, {{
          method: "POST",
          headers: {{"content-type": "application/json"}},
          body: JSON.stringify({{ "address": a }})
        }});
        if (res.status === 202) {{
          var d = await res.json().catch(function () {{ return {{}}; }});
          show(fmtTask(d.task_id || ""));
          return;
        }}
        if (res.status !== 402) {{
          var e = await res.json().catch(function () {{ return {{}}; }});
          show("<p class='text-red-400'>" + esc(e.error || ("HTTP " + res.status)) + "</p>");
          return;
        }}
        var req = res.headers.get("PAYMENT-REQUIRED") || "";
        var terms = req ? b64decode(req) : null;
        var accs = (terms && terms.accepts && terms.accepts.length) ? terms.accepts : [];
        if (!accs.length) {{ show("<p class='text-red-400'>Service did not return payment terms.</p>"); return; }}
        var lines = [];
        lines.push("<p class='text-yellow-300'>Payment required to start this audit. Choose a chain:</p>");
        accs.forEach(function (acc, i) {{
          var meta = CHAINS[acc.network] || {{ name: acc.network }};
          var price = (Number(acc.amount) / 1e6).toFixed(2);
          var payTo = acc.payTo || "";
          lines.push("<button data-chain='" + i + "' class='chain-opt mt-2 w-full rounded-lg border border-zinc-700 bg-zinc-900 px-4 py-3 text-left text-sm hover:border-cyan-400'>"
            + "<span class='font-semibold text-cyan-300'>" + esc(meta.name) + "</span>"
            + " <span class='text-zinc-300'>" + esc(acc.network) + "</span>"
            + " &mdash; <b>" + price + " USDC</b>"
            + "<br><span class='text-xs text-zinc-500'>pay to: <code class='break-all'>" + esc(payTo) + "</code></span>"
            + "</button>");
        }});
        lines.push("<p class='mt-3 text-xs text-zinc-500'>Your wallet will open to approve the payment. "
          + "Prefer the terminal? Run the curl command below with an x402-enabled client:</p>");
        var curlCmd = "curl -X POST " + window.location.origin + REST
          + " -H 'content-type: application/json' -d '" + JSON.stringify({{"address": a}}) + "'";
        lines.push("<pre class='mt-2 overflow-x-auto rounded border border-zinc-800 bg-zinc-900 p-3 text-xs text-cyan-300'><code>"
          + esc(curlCmd) + "</code></pre>");
        show(lines.join(""));
        flow.querySelectorAll("button.chain-opt").forEach(function (btn) {{
          btn.addEventListener("click", async function () {{
            var idx = Number(btn.getAttribute("data-chain"));
            var accept = accs[idx];
            if (!accept) return;
            btn.disabled = true;
            btn.textContent = "Opening wallet...";
            if (hint) hint.classList.remove("hidden");
            try {{
              var out = await payOnChain(a, accept);
              var tid = (out && (out.task_id || out.taskId)) || "";
              if (tid) show(fmtTask(tid));
              else show("<p class='text-emerald-400'>Payment accepted.</p><pre class='mt-2 overflow-x-auto rounded border border-zinc-800 bg-zinc-900 p-3 text-xs text-cyan-300'>"
                + esc(JSON.stringify(out, null, 2)) + "</pre>");
            }} catch (err) {{
              btn.disabled = false;
              btn.textContent = "Retry";
              show("<p class='text-red-400'>" + esc((err && err.message) || String(err)) + "</p>");
            }} finally {{
              if (hint) hint.classList.add("hidden");
            }}
          }});
        }});
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
  </footer>

</div>
</body>
</html>
"""


INDEX_HTML = _build_index_html()
