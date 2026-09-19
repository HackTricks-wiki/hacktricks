# Operational Privacy Playbooks

{{#include ../banners/hacktricks-training.md}}

These playbooks combine the controls from the rest of this section. They are starting points, not guarantees: update the threat model whenever a new observer, account, device, location, payment, file or counterparty enters the workflow.

## Universal preflight

1. Write the legitimate objective and what must remain private **from whom**.
2. Record the identities, devices, networks, accounts, payment rails, counterparties, physical locations and data that the activity will touch.
3. Identify the strongest likely observer and consequence of failure.
4. Confirm authorization, applicable law, provider terms and organizational policy.
5. Decide what must remain attributable internally for safety, incident response, accounting and audit.
6. Pick the smallest workable compartment; establish its recovery and shutdown paths before use.
7. Test the compartment against a controlled service, including IP/DNS/IPv6, browser identity, document metadata, payment statement and notification leakage.

Use the detailed model in [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md).

## Everyday privacy baseline

Goal: reduce commercial tracking, account takeover and unnecessary exposure without trying to become anonymous.

- Use a maintained OS with full-disk encryption, automatic updates, screen lock and secure boot where available.
- Put password manager, recovery email and phishing-resistant MFA/security keys in order first.
- Review app permissions, location history, advertising identifiers, cloud sync and third-party account connections.
- Use a mainstream browser with few extensions, tracking protection, HTTPS, and separate profiles for work/personal/high-risk browsing.
- Use private relay aliases or distinct email addresses by relationship; do not use a personal phone number when it is merely optional.
- Prefer end-to-end encrypted messaging for content, while remembering that participants, timing, groups and endpoints remain metadata.
- Remove metadata from files deliberately and inspect the exported copy—not the original—before publishing.
- Use virtual-card or wallet tokens for payment-credential compartmentalization; do not call them anonymous.
- Back up encrypted recovery material and test restoration.

## Pseudonymous publication

Goal: prevent casual readers and platforms from trivially linking a publication to a civil identity. This does not defeat a capable targeted investigation.

1. Define whether the platform, hosting provider, readers, contacts, local network, payment provider or legal process is in the threat model.
2. Create a dedicated endpoint/account context from a clean baseline. Disable personal browser sync, cloud documents, contact upload and notification previews.
3. Create the pseudonymous account through the chosen network compartment. Do not reuse usernames, avatars, recovery channels, writing boilerplate or personal identity-provider login.
4. Use Tor Browser when destination unlinkability is more important than speed; do not add extensions, resize/customize it heavily, or open downloaded documents while online in an ordinary desktop session.
5. Draft with a process that does not embed personal template names, revision authors, printer paths, GPS/EXIF, thumbnails or hidden layers. Export a copy and inspect it with appropriate metadata tools.
6. Check content for self-identifying facts: unique dates, workplace details, local weather/time zone, reflections, background audio, linguistic habits and prior-publication text reuse.
7. Use a separate reply channel. Treat every direct contact, attachment and link as a potential correlation or phishing attempt.
8. If money is involved, use the lawful method that exposes only the necessary data. Assume the platform and regulated intermediary may know the payee even if readers do not.
9. Publish, then inspect the public result from a different clean context. Record what the platform added or transformed.
10. Maintain a planned cadence only if it does not create a stable behavioral fingerprint; retire the compartment instead of silently repurposing it.

For serious journalism, activism, domestic abuse or state-level risk, obtain tailored help from an experienced digital-security organization; a static checklist cannot model local law or a live adversary.

## Authorized red-team engagement

Goal: keep operators' personal identities and home networks out of target telemetry while preserving authorization, control and incident response.

### Before the start window

- Finalize the ROE infrastructure annex, targets/exclusions, source ranges, dates, emergency stop and third-party/provider permissions.
- Allocate a dedicated operator profile or VM, engagement secrets, evidence store, cloud project, domains and budget.
- Prefer client-provided egress or an organization-controlled fixed bastion. Test full-tunnel IPv4/IPv6/DNS behavior and fail-closed policy.
- Store the mapping from operator to public infrastructure with the exercise controller or agreed escrow contact.
- Establish rate limits, destination allowlists and separate approval for destructive, wireless, physical, phishing or credential-collection actions.
- Use an organization-controlled payment rail and record approvals internally.

### During the engagement

- Start from the approved endpoint and tunnel; verify observed egress before assessment traffic.
- Keep personal accounts, devices, phone numbers, repositories, SSH/GPG keys and cloud sync out of the compartment.
- Log operator/job, start/stop, source, scoped destination and configuration change without collecting unnecessary client content.
- Stop on scope ambiguity, unexpected third-party systems, provider abuse notification, safety impact, lost equipment or loss of controller contact.
- Never improvise with a neighbor's Wi-Fi, stolen credentials, an unapproved SIM/account, or hardware hidden at a venue.

### End of engagement

- Stop jobs and C2; recover approved drop devices; revoke tokens, credentials and certificates.
- Reconcile infrastructure, domains, source addresses, expenses, data and provider cases against the inventory.
- Return/delete/retain client data according to contract, preserve the minimum required audit evidence, and have a second operator verify shutdown.

See [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) for the full build and teardown guide.

## Lawful private purchase or donation

Goal: minimize disclosure to the merchant or public while meeting issuer, accounting, tax and sanctions obligations.

1. List who must not learn what: public audience, merchant, payment intermediary, employer/family account delegate, delivery service, or blockchain observer.
2. Check local rules, the recipient/counterparty, provider terms, cash limits and recordkeeping needs.
3. Choose the rail:
   - cash for accepted lawful local payments with no payment-network record;
   - a regulated virtual/merchant-specific card for online credential separation;
   - cryptocurrency only after analyzing acquisition, ledger, wallet backend, network, counterparty and later-spend links.
4. Use truthful required details and omit only optional loyalty/marketing information. Do not use another person's identity/address or split a transaction around a threshold.
5. Separate the merchant browser/account context and avoid unrelated social login, loyalty or personal recovery channels.
6. Confirm what appears on statements, receipts, notifications, shipping and public donor lists.
7. Store required receipt/tax/authorization evidence encrypted; revoke disposable payment credentials after the refund window.

See [Private Digital Payments](private-digital-payments.md) and [Cryptocurrency Privacy](cryptocurrency-privacy.md).

## Travel and untrusted networks

Goal: protect data and accounts on networks not administered by the user—not to conceal unauthorized activity.

- Update devices and download needed credentials/maps before travel.
- Minimize stored data; use full-disk encryption, strong unlock, remote-recovery planning and powered-off border/physical-risk procedures appropriate to legal advice.
- Verify the venue SSID/captive portal. Prefer a personal hotspot when appropriate, but remember cellular subscriber and location records.
- Use a full/forced approved VPN for organizational data; verify tethered devices share it and test IPv6/DNS behavior.
- Use a travel router for client isolation and repeatable policy, not as an anonymity guarantee.
- Treat public USB charging, borrowed computers, public printers and shared meeting-room systems as separate threats.
- Assume physical presence, radio identifiers, portal login, cameras and payment/location records can correlate the visit.

The comparison and setup details are in [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md).

## Failure and exposure response

When a compartment leaks or may be linked:

1. Stop the activity if continuation increases harm; use the engagement emergency stop where applicable.
2. Preserve necessary evidence without spreading sensitive data. Record exact time, observed indicator and affected assets.
3. Notify the appropriate owner/controller/security contact. Do not conceal an incident to preserve a privacy narrative.
4. Revoke sessions, tokens, payment credentials and infrastructure access; rotate secrets from a known-clean endpoint.
5. Determine which edges linked: endpoint, account recovery, network, payment, metadata, content, behavior, counterparty or physical presence.
6. Treat the whole affected compartment as burned. Do not merely change its username or exit IP.
7. Meet breach, provider, client, financial and legal notification duties.
8. Rebuild only after changing the process that caused the link; document the control and test it.

## Periodic audit

- [ ] Threat model and legal/provider assumptions reviewed on a dated schedule.
- [ ] Devices, accounts, aliases, domains, network paths and payment credentials inventoried.
- [ ] Recovery paths do not cross compartments unexpectedly.
- [ ] Full-tunnel, DNS, IPv6 and fail-closed behavior tested.
- [ ] Public files and profiles checked for metadata/content reuse.
- [ ] Wallet nodes/backends and crypto protocol assumptions remain current.
- [ ] Logs and receipts are minimal, encrypted, access-controlled and within retention.
- [ ] Old compartments and engagement infrastructure were fully retired.
{{#include ../banners/hacktricks-training.md}}
