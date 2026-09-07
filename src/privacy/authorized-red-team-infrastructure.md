# Authorized Red-Team Infrastructure

For a professional red team, the goal is **controlled attribution**, not immunity from accountability. The target should not trivially see an operator's home IP or personal accounts, while the engagement owner must be able to identify the source, stop the operation, handle abuse reports, preserve evidence, and prove authorization.

NIST defines rules of engagement (ROE) as pre-established constraints that grant authority for defined testing activities.<sup>[[1]](#references)</sup> Privacy architecture cannot expand that authority.

## Choose an egress pattern

| Pattern | Best use | Target sees | Provider/local observer sees | Accountability |
|---|---|---|---|---|
| Client-provided VPN/jump host | Most assessments | Client address range | Client identity and operator access | Strongest |
| Red-team organization bastion | Repeatable controlled egress | Organization range | Hosting provider and organization | Strong |
| Engagement-specific VPS | Isolate clients/campaigns | VPS address | Host account, billing, control-plane and access logs | Strong if documented |
| Approved commercial VPN | Research/scanning permitted by provider and ROE | Shared/dedicated VPN egress | VPN account and source connection | Medium |
| Tor Browser | Web research needing destination unlinkability | Tor exit | Local network sees Tor/bridge; destination sees Tor | Poor fit for allowlisted source attribution |
| Client-approved on-site drop | Internal simulation | On-site device/address | Site network and remote tunnel provider | Strong if inventoried |
| Lawful guest Wi-Fi | Low-risk administrative/research use | Venue public IP or tunnel egress | Venue, ISP, VPN/Tor | Weak and physically observable |

For most work, a client-provided or organization-controlled fixed egress is safer and faster than consumer anonymity services. It also lets defenders allowlist, monitor, or deliberately **not** allowlist known source ranges according to the exercise design.

## ROE infrastructure annex

Record before deployment:

- legal entities granting and receiving authorization;
- exact targets and explicit exclusions;
- start/end times, time zone, and permitted techniques;
- source IPs, autonomous-system/provider names, domains, redirectors, mail infrastructure, and on-site device identifiers;
- whether phishing, C2, credential capture, wireless testing, physical access, denial-of-service, persistence, or third-party services are permitted;
- client and provider approvals, including any pre-notification reference;
- emergency stop phrase, 24/7 client and provider abuse contacts, and maximum response time;
- data classes that may be collected, encryption, access, retention, and deletion;
- evidence and logging requirements, including who holds the mapping from public infrastructure to operator;
- teardown, domain expiration, certificate revocation, credential rotation, device recovery, and final attestation.

Verify that public IPs and domains are actually controlled by the authorizing party or explicitly included in scope. NIST SP 800-115 recommends confirming public target addresses are under the organization's purview before testing.<sup>[[2]](#references)</sup>

## Engagement-specific fast egress

### Build workflow

1. **Create an engagement account/project** under the red-team organization using accurate billing and ownership details. Separate roles, API keys, budgets, and audit logs from other clients.
2. **Check every provider policy.** Cloud, VPS, CDN, domain, email, and VPN providers have different rules. AWS, for example, permits specified assessments but requires prior approval for hosted C2/covert simulations and prohibits listed activities.<sup>[[3]](#references)</sup>
3. **Allocate fixed egress addresses** and put them in the ROE annex. Avoid rapid IP/resource cycling; it complicates incident response and may violate provider policy.
4. **Harden management:** key-only SSH or an identity-aware management plane, phishing-resistant MFA, separate admin network, least privilege, patched images, no public admin ports, and encrypted secret storage.
5. **Create a full-tunnel path** from the operator endpoint to the bastion. Route DNS and IPv6 deliberately and enforce a firewall deny when the tunnel is down.
6. **Restrict outbound destinations and ports** to the authorized scope when feasible. Rate-limit scanners and put irreversible/destructive techniques behind a separate approval gate.
7. **Log for accountability, not surveillance:** operator authentication, configuration changes, start/stop, source address, scoped destination, and tool/job identifiers. Avoid payload/credential capture unless required by the exercise and protected by the data plan.
8. **Validate through a controlled endpoint** owned by the organization: observed IPv4/IPv6, DNS path, reverse DNS, clock, source-port behavior, failure/reconnect, and provider abuse contact.
9. **Share the attribution map securely** with the exercise controller or an agreed escrow contact. Do not publish it to the target team if blind detection is part of the test.

### Architecture

```text
dedicated operator context
        |
   fail-closed tunnel
        |
engagement bastion / fixed egress ---- management + audit plane
        |
 scope allowlist / rate limits
        |
   authorized targets
```

A VPS is pseudonymous only to the destination. The host can have contact, billing, identity, source-IP, API, device, location, and usage records; customer-visible AWS CloudTrail history alone can expose management activity.<sup>[[4]](#references)</sup> Paying for hosting with cryptocurrency does not erase those records.

## Domains and certificates

- Use an engagement-specific registrar account owned by the organization.
- Enable registrar lock, DNSSEC where supported, MFA/security keys, and auto-renew only for the approved period.
- Use registration privacy to reduce public exposure, not to misrepresent registrant information. ICANN policy requires registrars to collect registration data even when public display is redacted or proxied.<sup>[[5]](#references)</sup>
- Avoid names that unlawfully impersonate unrelated parties. Typosquatting/lookalike domains require explicit client and provider approval.
- Inventory DNS, certificates, CDN/redirector configuration, and third-party analytics that could leak operators or clients.
- At teardown, remove records, revoke certificates/tokens, preserve agreed evidence, and decide whether the domain should be defensively retained.

## Authorized on-site drop nodes

A Raspberry Pi or similar appliance is acceptable only when the property/network owner and client explicitly authorize its exact placement and behavior. A safe plan:

1. Record device serial, MAC/private-MAC policy, photo, owner, exact approved location, power source, retrieval deadline, and tamper contact.
2. Use a minimal signed image, encrypted secrets, read-only or recoverable storage, host firewall, automatic security updates where practical, and no default credentials.
3. Configure outbound-only communication to a named engagement endpoint. Do not expose an unauthenticated listener.
4. Allowlist destinations and capabilities. Packet capture, credential collection, wireless impersonation, and lateral movement must each be explicitly authorized.
5. Use mutual authentication, short-lived keys, remote kill, health reporting, and bandwidth limits.
6. Ensure loss/theft does not reveal reusable credentials or client data.
7. Put retrieval and secure wipe/decommission in the calendar; obtain a signed recovery record.

Do not hide hardware at a café, hotel, shared office, neighbor's property, or public venue without the owner/operator's written permission.

## Guest networks and travel routers

If an authorized scenario requires guest access:

- verify the SSID and acceptable-use policy with the venue/client;
- use an organization-owned travel router or low-trust bridge device to isolate the privileged workstation;
- complete captive portals outside the privileged workstation;
- start the approved tunnel before assessment traffic;
- confirm tethered devices actually use that tunnel;
- assume the venue can correlate radio association, portal, physical presence, and camera/payment records;
- never bypass access control, clone another device, attack Wi-Fi, or leave equipment behind.

## Operational separation

- One client/engagement per endpoint compartment, cloud project, secrets set, domain group, redirector set, and evidence store.
- No personal email, browser sync, phone number, cloud drive, SSH/GPG key, code-signing identity, or payment reimbursement outside approved organization systems.
- Do not reuse distinctive payload configuration, callback paths, certificates, or public repositories across clients unless the exercise design accepts fingerprinting.
- Give infrastructure a kill date and budget alert. Orphaned systems become risk to both client and Internet.
- Preserve enough internal attribution to investigate accidents. “No logs” is usually incompatible with professional evidence and safety obligations.

## Teardown checklist

- [ ] Exercise controller confirms stop.
- [ ] C2, tunnels, redirectors, mail, VPN, and scheduled jobs are disabled.
- [ ] On-site devices are physically recovered and reconciled.
- [ ] Tokens, API keys, SSH keys, certificates, and captured credentials are revoked/rotated.
- [ ] DNS and cloud resources are removed or transferred for defensive retention.
- [ ] Client data is returned, retained, or destroyed according to the contract.
- [ ] Required financial, audit, and authorization records remain encrypted and access-controlled.
- [ ] Provider abuse cases are closed and the client receives final source indicators.
- [ ] A second operator verifies that no infrastructure remains active.

## References

- [1] [NIST CSRC — Rules of Engagement](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Customer Support Policy for Penetration Testing](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Privacy Notice](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Registration Data Policy](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
