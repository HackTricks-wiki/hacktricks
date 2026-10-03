# AI Agent Security Methodology

{{#include ../banners/hacktricks-training.md}}

An agent assessment should follow **attacker-controlled input to an externally observable effect**. Jailbreaking, character changes, and system-prompt disclosure prove that a reasoning channel is influenceable, but the high-impact finding is the chain into data access, an unauthorized tool action, a downstream injection sink, persistence, or another agent.<sup>[[2]](#references)</sup>

The [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) is useful for labeling coverage (goal hijacking, tool misuse, privilege abuse, supply chain, code execution, memory poisoning, inter-agent trust, cascading failures, human trust, and rogue agents). Use those labels after constructing an end-to-end attack path rather than treating a model's unexpected text as the end of the test.<sup>[[1]](#references)[[2]](#references)</sup>

## Build the target map

Record these five dimensions for every agent workflow before writing payloads:<sup>[[2]](#references)</sup>

| Dimension | What to enumerate | Security question |
|---|---|---|
| **Untrusted input** | Chat/API parameters, URLs, documents, email, tickets, calendar entries, retrieved chunks, memory, tool results, and peer-agent messages | Where can an attacker place content that later enters model context? |
| **Tools** | Tool names and schemas, side effects, auto-execution, confirmation behavior, and dynamically loaded tools | Which calls read secrets, write state, send messages, delete data, execute code, or transfer value? |
| **Authority** | User delegation, service accounts, API tokens, credential lifetime, tenant/resource scope, and network reach | As which identity does each call run, and is authorization repeated at the tool boundary? |
| **Processing** | Query builders, shells, URL fetchers, template engines, interpreters, parsers, file operations, and deserializers | Where does model-generated data become syntax for another interpreter? |
| **Output** | Responses, rendered Markdown/HTML, links, image fetches, webhooks, email, files, logs, reports, metrics, and peer-agent traffic | Which observable channel can carry a secret or trigger a secondary request? |

Do not collapse this into a list of advertised integrations. A useful artifact maps each source to the exact context position it reaches, the tools available at that point, the credential used by each tool, the downstream interpreter, and every egress route. The same tool can be low impact with a per-user read token and critical with a shared administrator credential.<sup>[[2]](#references)</sup>

## Reconnaissance

### Map every delivery and ingestion path

Start with the delivery surface (web, mobile, API, email, chat platform, browser extension) and proxy the client-to-backend traffic. Inspect fields hidden by the UI, search/autocomplete/filter parameters, conversation-state objects, upload and indexing jobs, tool responses, and sub-agent traffic. Mobile-only clients may require an emulator and instrumentation to bypass certificate pinning before the real request schema becomes visible.<sup>[[2]](#references)</sup>

Then map the stack beneath the model: orchestration framework, prompt assembly, retrieval and memory stores, runtime (for example Python, container, or WASM), mounted volumes, host services, internal APIs, cloud metadata reachability, and neighboring networks. Framework defaults matter because some “tool calls” are implemented by generating or evaluating code; the runtime/sandbox boundary determines whether that result stays contained.<sup>[[2]](#references)</sup>

### Fingerprint routing with non-destructive probes

Compare an in-scope request with several unrelated requests while preserving the complete response, status code, latency, and streaming behavior. A stable rejection before any task-specific reasoning may indicate a separate gateway/classifier; a contextual refusal suggests that the request reached the model; an empty or purely extractive answer may indicate keyword search or narrow retrieval. Treat these as hypotheses and confirm them by replaying the same probe through alternate API fields and ingestion paths.<sup>[[2]](#references)</sup>

Recon is complete when the assessment can name the earliest attacker-controlled source that changes agent behavior **and** the tools, identities, interpreters, and outputs reachable from that source.<sup>[[2]](#references)</sup>

## Exploitation: cross a trust boundary

Test channels, not only prompt wording. Start with direct injection to establish what the visible front door blocks, then repeat equivalent intent through the less-visible paths below:<sup>[[2]](#references)</sup>

- **Indirect content:** pages, files, email, tickets, metadata, alt text, HTML comments, off-screen text, or zero-width characters. See [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) for payload-delivery techniques.
- **Retrieval and memory:** poison content that will be retrieved later or state that will be reloaded in later sessions. Record whether deletion of the original source removes the behavior.
- **Tool output and peer agents:** place the marker in a tool response or agent-to-agent message to test whether internal traffic bypasses filters applied only to user input and final output.
- **Supply chain:** review tool descriptors, plugins, connected servers, skills, models, and dependencies as trusted instruction sources. For MCP-specific tests, see [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Human approval:** compare the actual structured tool call with the model-generated approval text. Test whether attacker influence can omit the destination, scope, affected objects, or irreversible side effects.

Use a benign, unique marker first. Preserve the source artifact, assembled context if observable, selected tool call, approval data, backend request/response, and final state. This separates influence from a hallucinated claim that an action occurred.<sup>[[2]](#references)</sup>

## Execution: prove real impact

There are two distinct routes from influence to impact:<sup>[[2]](#references)</sup>

1. **Capability abuse:** the authorized tool already performs the objective. Examples include reading one tenant's record and writing it to an attacker-visible report, sending email, changing records, deleting a file, or initiating a payment. No secondary software bug is required.
2. **Downstream sink exploitation:** attacker-steered model output becomes syntax for another component. Review database queries for [SQL injection](../pentesting-web/sql-injection/README.md) or [NoSQL injection](../pentesting-web/nosql-injection.md), shell wrappers for [command injection](../pentesting-web/command-injection.md), chosen URLs for [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), file operations for traversal, template/code evaluators for RCE, and object parsers for [unsafe deserialization](../pentesting-web/deserialization/README.md).

For every candidate, prove this chain:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

A read-only integration is still exploitable when any later component can publish what it read. Test ordinary responses plus less-obvious egress such as attacker-controlled links, automatic image retrieval, webhooks, logs, reports, counters, notifications, and messages to other agents.<sup>[[2]](#references)</sup>

## Actions on objectives

After confirming one action, evaluate the complete blast radius rather than stopping at the first visible effect:<sup>[[2]](#references)</sup>

- **Exfiltration:** secrets, user records, internal files, conversation data, or prompt/context content leave through an observable channel.
- **Unauthorized action:** the agent uses legitimate write capabilities for the attacker's objective.
- **Denial of service:** destructive tools or repeated expensive operations affect integrity or availability.
- **Persistence:** poisoned memory, indexed content, trusted state, or runtime changes survive the originating session or source removal.
- **Propagation:** a trusted peer consumes the compromised agent's message or shared state and repeats the action with its own tools and credentials.

Severity should follow reachable data, effective privilege, sink exploitability, egress, persistence, and propagation—not how surprising the model's text appears.<sup>[[2]](#references)</sup>

## Controls to validate during the assessment

Prompt filters and a better system prompt can raise attacker cost, but they should not be treated as authorization boundaries. Validate the controls below by re-running the same chain through direct input, indirect content, memory, tools, and peer agents:<sup>[[2]](#references)</sup>

- A deterministic policy layer checks the authenticated user, tenant, object, action, and destination on **every tool invocation**; the model cannot supply or override the caller identity.
- Read and write capabilities use separate, least-privilege, short-lived credentials; high-impact tools are exposed just in time and never auto-execute from ingested content.
- Network egress and internal destinations are allowlisted independently of model-selected URLs; runtime access to metadata endpoints, mounted secrets, and neighboring services is blocked unless required.
- Approval UI is generated from the canonical structured request and shows exact arguments, identity, destination, affected objects, and side effects—not a free-form model summary.
- Success is verified from the destination system or system of record. Agent narration, a tool-call request, or an HTTP redirect is not proof of the claimed state change.
- Memory and retrieval entries retain provenance and trust labels, can be invalidated, and are re-authorized when used for a later action.
- Inter-agent messages are authenticated and authorized as untrusted requests; a peer's reputation or agent card does not implicitly delegate the receiver's tools.

## References

- [1] [OWASP Top 10 for Agentic Applications for 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [The Hacker's Guide to Attacking AI Agents](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)

{{#include ../banners/hacktricks-training.md}}
