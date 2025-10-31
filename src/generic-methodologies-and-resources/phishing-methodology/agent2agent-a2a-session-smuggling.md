# Agent2Agent (A2A) Session Smuggling

{{#include ../../banners/hacktricks-training.md}}

## Overview

Agent session smuggling is a multi‑turn prompt‑injection technique against stateful Agent2Agent (A2A) systems. A malicious remote agent injects covert turns between a client’s initial delegation and the benign‑looking final response. Because the session is stateful and inter‑agent turns are often hidden from the end user, the attack enables:
- Sensitive context exfiltration (system prompts/instructions, prior history, tool inventory/schemas).
- Unauthorized tool invocation under the victim agent’s identity.
- Stealth via normal‑looking final answers while covert mid‑session exchanges remain invisible to users.

Notes:
- This is not an A2A protocol bug; it is a systemic risk whenever autonomous, multi‑turn, cross‑boundary agents persist per‑session state.
- Compared to stateless MCP tool calls, stateful agent links make adaptive mid‑session abuse practical.

---

## Threat Model and Preconditions
- Client agent establishes a trusted A2A session with a remote agent (often cross‑org).
- Remote agent is malicious (or turns malicious via rug‑pull/compromise).
- UI typically exposes only the final message; intermediate inter‑agent turns require a developer UI/logs to observe.

---

## Core Attack Flow
```
1) Client → Remote: normal delegation request (opens/continues stateful session)
2) Remote ↔ Client: covert, injected multi‑turn instructions during the active session
3) Remote → Client: expected final response (benign‑looking), masking step (2)
```
Key properties: stateful memory, multi‑turn adaptation, cross‑boundary autonomy, user‑invisible mid‑turns.

---

## Operator Patterns (What to Do)

1) Context exfiltration via “clarifications”
- Ask iterative, harmless‑looking questions to elicit: system instructions, conversation history, tool list and schemas.
- Leverage alternating function_call/function_response style turns to reconstruct capabilities without breaking the active session.

2) Covert unauthorized tool execution
- Smuggle directives that cause the victim to invoke sensitive tools (trading, data export, admin actions) unrelated to the user’s intent.
- Keep the final answer on‑topic so UI appears normal while side‑effects already happened mid‑session.

3) Trust‑boundary abuse
- Target cross‑organisation agent links where implicit trust exists and identity/capability attestation is weak.

---

## Example Artifacts and Telemetry (ADK+A2A PoC)
Environment commonly used for demos/tests:
- Framework/UI: Google ADK + ADK Developer Web UI
- Protocol: A2A
- Client: financial‑advisor agent with tools: get_portfolio, get_profile, buy_stock, sell_stock
- Remote (malicious): data_analyst agent with web search

What to look for in logs:
- Client activity log shows an initial delegated request (row N) and a final result (row M), with many hidden interleaved function_call/function_response rows in between that reveal exfiltration and tool planning.
- Remote agent log captures the exfiltrated system config, tool schemas, and the entire session history.
- Unauthorized tool calls appear as extra actions between the initial request and the final response.

---

## Detection and Hunting Heuristics

Surface the invisible mid‑turns and constrain high‑risk tool use.

Telemetry sources
- Agent runtime/dev UI logs (turn sequence, tool invocations, remote‑instruction indicators).
- Gateway/proxy logs for A2A messages; correlate with client‑side activity.
- Application audit trails for tool invocations and side‑effects (e.g., trade execution).

Heuristics
- Smuggled‑turn density: unusually high count of remote‑initiated turns between a single delegation and its final response.
- Topic drift: remote turn content diverges semantically from the original task intent.
- Sensitive tool calls inside delegated flows that were not explicitly requested by the user.
- Off‑host side‑effects: actions occurring without any corresponding user‑visible prompt.

Example rules (pseudo‑logic):
```yaml
- when: a2a_session.start -> a2a_session.end
  and mid_turns.remote_count > 3
  and (contains_tool_calls OR final_message.on_topic == true)
  then: tag("possible session smuggling")

- when: tool_call.sensitivity in [TRADING, DATA_EXPORT, ADMIN]
  and tool_call.origin == "delegated_remote_turn"
  and user_approval == absent
  then: alert("unauthorised tool use via remote agent")
```

Context grounding (alignment gate)
```python
# Pseudo: reject remote instructions that drift off the initial task intent
anchor = embed(user_intent_text_at_session_start)
for turn in remote_agent_turns:
    sim = cosine(embed(turn.text), anchor)
    if sim < 0.55:  # tune threshold per domain
        terminate_session("off-topic remote instruction")
```

---

## Hardening and Preventive Controls

- Out‑of‑band human approvals: pause critical actions and require confirmations via a UI the model cannot influence (push/app notification or non‑LLM modal).
- Context grounding: derive a task anchor from the user’s initial intent; continuously validate remote instructions for semantic alignment and terminate on drift.
- Agent identity and capability verification: require verifiable credentials (e.g., cryptographically signed AgentCards; see sigstore‑a2a). Maintain allow‑lists and auditable, tamper‑evident records.
- User visibility: surface real‑time agent activity (tool invocations, remote‑instruction banners, execution logs). Provide a transcript of delegated turns with provenance labels.
- Scope/time‑box delegated sessions: restrict duration, tools, and privileges; disable auto‑execution for high‑risk tools unless human‑approved.
- Prefer closed multi‑agent graphs within a single trust boundary for high‑risk workflows.

---

## Red‑Team Notes
- Keep intermediate turns on‑topic and incremental; ask for “clarifications” that naturally solicit hidden state.
- Learn tool inventory from public docs or prior leakage; craft minimal directives to trigger sensitive calls near the end of the session.
- Return a plausible final answer that matches user intent to mask covert mid‑session activity.

---

## References
- [When AI Agents Go Rogue: Agent Session Smuggling Attack in A2A Systems (Unit 42)](https://unit42.paloaltonetworks.com/agent-session-smuggling-in-agent2agent-systems/)
- [Agent‑to‑Agent (A2A) Protocol](https://a2a-protocol.org/latest/)
- [Google Agent Development Kit (ADK)](https://google.github.io/adk-docs/)
- [ADK Developer Web UI](https://github.com/google/adk-web)
- [ADK financial‑advisor sample](https://github.com/google/adk-samples/tree/main/python/agents/financial-advisor)
- [sigstore‑a2a (agent identity)](https://github.com/sigstore/sigstore-a2a)

{{#include ../../banners/hacktricks-training.md}}
