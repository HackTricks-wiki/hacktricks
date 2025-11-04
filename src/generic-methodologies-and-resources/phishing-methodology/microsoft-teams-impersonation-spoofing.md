# Microsoft Teams Impersonation & Notification Spoofing (CVE-2024-38197)

{{#include ../../banners/hacktricks-training.md}}

Abusing client-controlled fields in Microsoft Teams messages and call setup allowed convincing identity spoofing and stealth message history manipulation across clients (now patched by Microsoft). These primitives are highly relevant for social engineering, BEC, and real-time voice/video impersonation scenarios.

Note: Microsoft fixed all issues disclosed by Check Point Research by Oct 2025. The notification sender spoofing was tracked as CVE-2024-38197.

## Scope, IDs and Relevant Fields
- User identifiers (examples): `8:orgid:<UUID>` discovered when enumerating conversations/messages.
- Message send body commonly includes:
  - `content` (HTML-wrapped message body)
  - `messagetype` (e.g., `"RichText/Html"`)
  - `clientmessageid` (client-generated unique ID)
  - `imdisplayname` (sender display name rendered by some clients/notifications)
- Server response provides `OriginalArrivalTime` (Unix ms), used by clients for edit/delete/quote alignment.

## 1) Edit Without “Edited” Label via clientmessageid Reuse
Some clients correlate the rendered message to the `clientmessageid`. Re-sending a message reusing the original `clientmessageid` would display the new content as if it were the original, omitting the “Edited” marker.

Example sequence (conceptual):
```json
// Initial send
{
  "content": "<div>Quarter numbers draft</div>",
  "messagetype": "RichText/Html",
  "clientmessageid": "2711247313308716623",
  "imdisplayname": "Alice"
}
// Response includes
// OriginalArrivalTime = 1709414616944

// Replacement send (reusing clientmessageid)
{
  "content": "<div>Final numbers approved</div>",
  "messagetype": "RichText/Html",
  "clientmessageid": "2711247313308716623",
  "imdisplayname": "Alice"
}
```
Effect: Recipients see the updated text without any “Edited” badge, enabling stealthy history manipulation.

Detection ideas:
- Two distinct sends sharing the same `clientmessageid`.
- Discrepancy between `OriginalArrivalTime` ordering and rendered content sequence.

## 2) Notification Sender Spoofing (CVE-2024-38197)
Earlier Teams clients rendered notification sender strings from a client-supplied field (e.g., `imdisplayname`) without sufficient canonicalization/validation. Bots/webhooks could forge the sender shown in toast/lock‑screen notifications.

Concept payload:
```json
{
  "content": "<div>Urgent: approve the transfer now</div>",
  "messagetype": "RichText/Html",
  "clientmessageid": "<new-guid>",
  "imdisplayname": "CEO - John Smith"
}
```
Impact: Highly convincing spoof of trusted identities in notifications, driving immediate user action. Fixed by Microsoft; tracked as CVE-2024-38197.

Detection ideas:
- Notification events where the displayed sender differs from the canonical directory identity (UPN/objectID).
- Inbound messages from external/bot contexts carrying unexpected `imdisplayname` patterns (role/exec names).

## 3) 1:1 Chat Display-Name Tampering via Topic API
Teams exposes a "topic" property setter for group chats. Mis-scoping allowed altering the visible name of a 1:1 chat using the same endpoint, misleading participants about the conversation context/peer.

Endpoint abused:
```
PUT /api/chatsvc/emea/v1/threads/`<ConversationID>`/properties?name=topic
```
Effect: Private chat appears relabelled (e.g., "Finance - Approvals"), eroding identity/context assurances.

Detection ideas:
- Property changes to 1:1 threads using the group-topic endpoint.
- Sudden 1:1 thread rename events not initiated by the tenant’s client versions expected to enforce scope.

## 4) Caller Identity Spoofing in Audio/Video Calls
During call setup, the client posts to an endpoint where the incoming-call UI renders `participants[].displayName`. Setting an arbitrary displayName forged the identity shown in ringing/in-call views.

Call setup (conceptual):
```
POST /api/v2/epconv
```
Payload excerpt:
```json
{
  "participants": [
    { "id": "8:orgid:37f85325...", "displayName": "CEO John Smith" }
  ],
  "modalities": ["audio", "video"]
}
```
Effect: Targets see an incoming call labelled as a chosen identity, enabling real-time voice/video impersonation.

Detection ideas:
- Compare displayed caller name vs. authoritative directory attributes associated with the participant `id`.
- Alert on call invites from external/guest contexts that inject privileged-looking display names.

## Operator Notes (Prereqs & TTPs)
- Actor must be able to message/call within the target tenant (guest access or insider).
- Useful data points: `clientmessageid`, `imdisplayname`, `OriginalArrivalTime`, user IDs like `8:orgid:...`.
- Even though fixes are deployed, similar trust‑signal weaknesses are common across collaboration platforms; always test whether display strings are treated as authoritative identities.

## Defensive Guidance (High Level)
- Treat notification and call UI display fields as untrusted; ensure clients map to and render canonical identities (UPN/objectID) rather than payload-provided strings.
- Detect reuse of `clientmessageid` across multiple sends and reconcile UI vs. timeline metadata.
- Flag thread-topic changes on 1:1 chats.
- Educate users to verify sensitive/urgent requests via out-of-band channels and to inspect profile cards/UPNs, not just the display name.

## References

- [Exploiting Microsoft Teams: Impersonation and Spoofing Vulnerabilities Exposed (Check Point Research)](https://research.checkpoint.com/2025/microsoft-teams-impersonation-and-spoofing-vulnerabilities-exposed/)

{{#include ../../banners/hacktricks-training.md}}
