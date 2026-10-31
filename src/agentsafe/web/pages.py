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
    contract address and pay in USDC on Base via x402.
    <span class="text-zinc-500">From $0.50 &mdash; the exact price is quoted
    by the service before payment is requested.</span></p>
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
  </section>

  <script>
  (function () {{
    var REST = "/api/audit";
    var addr = document.getElementById("addr");
    var start = document.getElementById("start");
    var flow = document.getElementById("flow");
    function show(html) {{ flow.innerHTML = html; flow.classList.remove("hidden"); }}
    function b64decode(s) {{ try {{ return JSON.parse(atob(s.replace(/-/g, "+").replace(/_/g, "/"))); }} catch (e) {{ return null; }} }}
    start.addEventListener("click", async function () {{
      var a = (addr.value || "").trim();
      if (!/^0x[0-9a-fA-F]{{40}}$/.test(a)) {{ show("<p class='text-red-400'>Enter a valid 0x-prefixed contract address.</p>"); return; }}
      start.disabled = true; start.textContent = "Contacting service...";
      show("<p class='text-zinc-400'>Requesting payment terms from the service...</p>");
      try {{
        var res = await fetch(REST, {{
          method: "POST",
          headers: {{"content-type": "application/json"}},
          body: JSON.stringify({{"address": a}})
        }});
        if (res.status === 202) {{
          var d = await res.json().catch(function () {{ return {{}}; }});
          var tid = d.task_id || "";
          show("<p class='text-emerald-400'>Audit dispatched!</p>"
            + "<p class='mt-1 text-zinc-300'>Task ID: <code class='text-cyan-300'>" + tid + "</code></p>"
            + "<p class='mt-2 text-xs text-zinc-500'>Reports (free retrieval): "
            + "<a class='text-cyan-300 hover:underline' href='/api/audit/" + tid + "/report' target='_blank'>HTML</a> &middot; "
            + "<a class='text-cyan-300 hover:underline' href='/api/audit/" + tid + "/report.json' target='_blank'>JSON</a> &middot; "
            + "<a class='text-cyan-300 hover:underline' href='/api/audit/" + tid + "/report.md' target='_blank'>Markdown</a> &middot; "
            + "<a class='text-cyan-300 hover:underline' href='/api/audit/" + tid + "/report.pdf' target='_blank'>PDF</a></p>");
          return;
        }}
        if (res.status === 402) {{
          var req = res.headers.get("PAYMENT-REQUIRED") || "";
          var terms = req ? b64decode(req) : null;
          var acc = (terms && terms.accepts && terms.accepts[0]) ? terms.accepts[0] : null;
          var price = acc ? (acc.amount / 1e6) : null;
          var payTo = acc ? (acc.payTo || "") : "";
          var net = acc ? (acc.network || "") : "";
          var lines = [];
          lines.push("<p class='text-yellow-300'>Payment required to start this audit:</p>");
          if (price !== null) lines.push("<p class='mt-1 text-zinc-200'>Amount: <b>" + price.toFixed(2) + " USDC</b></p>");
          if (payTo) lines.push("<p class='text-zinc-200'>Pay to: <code class='text-cyan-300 break-all'>" + payTo + "</code></p>");
          if (net) lines.push("<p class='text-zinc-200'>Network: <code>" + net + "</code></p>");
          lines.push("<p class='mt-3 text-xs text-zinc-500'>Pay with a wallet that supports x402 (e.g. PayAI). "
            + "Or copy the curl command below and run it locally with your x402-enabled client:</p>");
          lines.push("<pre class='mt-2 overflow-x-auto rounded border border-zinc-800 bg-zinc-900 p-3 text-xs text-cyan-300'><code>curl -X POST " + window.location.origin + REST + " \\"
            + "  -H 'content-type: application/json' \\"
            + "  -d '{{\"address\":\"" + a + "\"}}'</code></pre>");
          lines.push("<p class='mt-2 text-xs text-zinc-500'>On HTTP 402 the server returns the machine-readable "
            + "<code>PAYMENT-REQUIRED</code> header; sign the quoted USDC transfer with your wallet "
            + "and resend with the <code>PAYMENT-SIGNATURE</code> header.</p>");
          show(lines.join(""));
          return;
        }}
        var e = await res.json().catch(function () {{ return {{}}; }});
        show("<p class='text-red-400'>" + (e.error || ("HTTP " + res.status)) + "</p>");
      }} catch (err) {{
        show("<p class='text-red-400'>Request failed: " + err.message + "</p>");
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
