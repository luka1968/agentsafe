# agentSAFE — Terms of Service

Version: 1.0-draft (pending owner review) · Status: **draft for legal review**

These Terms of Service ("ToS") govern use of the agentSAFE MCP service
("Service"), an AI-assisted smart-contract risk-screening tool. By calling
any Service tool, you ("you", "the user") accept these terms. If you do not
accept them, do not use the Service.

> **Publication note:** this file is the source of truth for the ToS text.
> It becomes publicly accessible once published at a stable URL (e.g. the
> repository's rendered page, or a page on the operator's site) — see
> `DEPLOYMENT.md`. A file in a repository is not, by itself, a published
> legal page. `TODO — OWNER INPUT REQUIRED: final publication URL.`

## 1. Service description and scope

agentSAFE performs AI-assisted screening of Ethereum Mainnet smart
contracts. For a contract address you provide, the Service retrieves the
verified source code, runs third-party static and symbolic analysis tools,
and uses large language model ("LLM") agents to summarize potential risks.
The output is a machine-readable report of findings for human review.

The Service screens contracts. It does not certify, approve, or endorse any
contract, and it is not a substitute for a professional security audit.

## 2. AI-assisted analysis limitations

Findings are generated with the assistance of LLM agents and automated
tools. LLMs can produce incorrect, incomplete, or misleading output
("hallucination"), and automated tools have known blind spots. Analysis
quality depends on the availability of verified source code and on-chain
data at the time of the request. Results represent a point-in-time
assessment only.

## 3. No guarantee of vulnerability detection

The Service does not guarantee that all vulnerabilities will be detected.
Absence of findings is not evidence of safety.

## 4. No guarantee of contract safety

A report with few or no findings does not mean the contract is safe, and
must not be represented as such to any third party.

## 5. User responsibility

You are solely responsible for verifying all findings, for any action you
take based on a report, and for any decision to deploy, use, or interact
with the audited contract. `TODO — OWNER INPUT REQUIRED: confirm this
allocation of responsibility with counsel.`

## 6. Pricing, payment authorization, and service fees

Prices are denominated in USDC and settled via the x402 payment protocol on
Base (or the network advertised by the Service at request time). Calling a
paid tool without payment returns a payment request; your payment
application authorizes the exact advertised amount before the Service
executes your request. Third-party payment infrastructure (facilitators,
blockchain networks) may charge its own settlement and network fees, which
are separate from the Service price.

Current pricing is advertised by the Service at request time. For contracts
exceeding the largest advertised size tier, contact us for custom pricing:
<https://tally.so/r/xVXx0k>.

## 7. Audit execution failures, partial results, and report availability

The Service runs each audit on ephemeral infrastructure with a bounded
execution time. If one or more analysis tools fail, the report is marked as
a **partial audit** and lists the tools that failed; results from tools
that completed are preserved. A partial audit is never presented as a fully
completed one, and a failed tool is never presented as a successful scan
with zero findings. Reports are retained for a limited period
(currently 2 days, per the report retention setting); retrieve your report
promptly after completion.

## 8. Refund and failed-service handling

Payment is settled only after the requested work has executed
successfully. If execution fails before settlement, no payment is collected.
If a payment settles but the Service fails to deliver a usable report, the
operator will, at its discretion, re-run the audit or otherwise remedy the
failed delivery. `TODO — OWNER INPUT REQUIRED: the operator must decide and
state an explicit refund/remedy policy, and confirm it is compatible with
the chosen payment facilitator's rules.`

## 9. Report access tokens and confidentiality

Audit reports are associated with an unguessable task identifier issued at
request time. Keep your task identifiers confidential: possession of a
valid identifier is the authorization used to retrieve the corresponding
report. The Service does not publish your reports. The Service is not a
secret store, however — treat report contents as non-confidential data.

## 10. Data handling, source-code processing, and retention

The Service processes only: (a) the contract address you submit, (b) public
verified source code and on-chain data it retrieves for that address, and
(c) payment metadata required by the x402 protocol. Reports and task
records are retained for the period stated in Section 7 and then expire.
The Service does not knowingly process personal data. `TODO — OWNER INPUT
REQUIRED: privacy practices (e.g. GDPR/CCPA statements, data processor
terms) must be reviewed and added if required for your jurisdiction.`

## 11. Acceptable use and prohibited activity

You agree not to: attempt to bypass payment or replay payment payloads;
reverse-engineer the Service to resell its output as your own security
certification; submit malicious automated workloads or attempt to disrupt
the Service; use the Service in violation of applicable law or sanctions;
or misrepresent Service output to third parties.

## 12. Service availability and maintenance

The Service is offered "as available". It may be paused for maintenance,
or degraded by third-party outages (RPC providers, explorers, GitHub
Actions, LLM providers, payment facilitators). There is no uptime
guarantee. `TODO — OWNER INPUT REQUIRED: state any intended SLA, or
explicitly state that none is offered.`

## 13. Limitation of liability

To the maximum extent permitted by law, the Service is provided "as is"
and "as available" without warranties of any kind, express or implied,
including merchantability, fitness for a particular purpose, and
non-infringement. The operator is not liable for any damages, losses, or
costs arising from use of, or reliance on, the Service or its reports.
This section is drafted for legal review and is not presented as
guaranteed enforceable. `TODO — OWNER INPUT REQUIRED: governing law,
jurisdiction, and any liability cap must be set by the operator with
counsel.`

## 14. Contact

Commercial inquiries and custom pricing:
<https://tally.so/r/xVXx0k>

`TODO — OWNER INPUT REQUIRED: official contact e-mail, legal entity name,
registered address, and governing jurisdiction. Do not publish placeholder
contact information.`
