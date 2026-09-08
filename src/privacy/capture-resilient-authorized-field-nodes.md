# Capture-Resilient Authorized Field Nodes

An on-site Raspberry Pi, mini-PC, travel router or cellular appliance can give an authorized red team a durable vantage point. It is also a likely point of discovery, theft and attribution. The right design objective is therefore **stable, controlled access with little authority on the field node**, not an untraceable implant.

This guide applies only to equipment placed with the site owner's written authorization. A coffee shop, neighbor, hotel or shared building is not in scope merely because its network is reachable. Do not hide hardware in an unconsenting venue, bypass a captive portal, use another person's credentials, interfere with monitoring, or attempt to erase evidence after discovery.

{% hint style="warning" %}
There is no dependable “leave no traces” setting. Radio association, DHCP/NAT, carrier, camera, purchase, device, provider, controller and destination records can survive the device. An accountable red team instead removes **personal and unrelated secrets** from the node, retains protected controller-side attribution, and makes capture cheap to contain.
{% endhint %}

## Pros and cons

**Pros:** realistic internal or target-adjacent source; stable high-speed testing; validates NAC, egress, physical inventory and SOC coverage; can continue through operator address changes; bounded access can be revoked centrally.

**Cons:** physical placement creates strong evidence; loss can expose device credentials, network profiles and collected data; repeated control traffic is detectable; power, portals and radio changes impair reliability; a broad tunnel can become an uncontrolled pivot.

## Threat model and design invariants

Assume that a finder can remove storage, inspect firmware, copy every software-held secret, observe later network behavior and provide the device to the client or law enforcement. Full-disk encryption protects a powered-off device only under its stated threat model; a running unlocked node and keys released to memory are different cases.

| Invariant | Practical consequence |
|---|---|
| No direct operator-to-node identity | Operator signs in to the organization gateway; the node has a different device identity |
| No personal workstation material | No personal SSH key, browser profile, email, password manager, phone pairing or cloud CLI cache |
| No controller master secret | One node cannot enroll another, change policy or decrypt other engagements |
| Outbound-only and narrow | The field network accepts no management listener; the node reaches only named rendezvous/update/time services |
| Short-lived, scoped authority | Each credential has one device, audience, service, expiry and immediate revocation path |
| Minimal local data | Results stream to the controller; caches are encrypted, size/TTL bounded and non-authoritative |
| Controller accountability survives capture | Asset-to-engagement mapping, approvals, operator access and commands are stored centrally and access-controlled |
| Loss stops work | Discovery or unexplained state change triggers stop, revoke, notify and evidence preservation—not remote destruction |

NIST's IoT baseline groups device identification, configuration, data protection, logical access, secure software update and cybersecurity-state awareness as core capabilities. It specifically treats state awareness and off-device event records as support for compromise investigation.<sup>[[1]](#references)</sup>

## Reference architecture

```text
operator workstation
  |  phishing-resistant MFA; named user; no field-device key
  v
organization access gateway ----> immutable audit / alerting
  |  per-engagement authorization          ^
  v                                        |
rendezvous/broker <==== outbound mTLS or WireGuard ==== field node
  |                                                     |-- approved site Wi-Fi/Ethernet
  +---- allowlisted owned test services                 +-- organization cellular fallback
```

The gateway must know which named operator reached which named device. The field node needs only a device credential for the rendezvous. It never learns the operator's source address or authentication secret, and the operator never copies a private management key to it. This reduces the personal link recoverable **from the field storage** without destroying exercise accountability.

For a larger fleet, a workload-identity system can issue short-lived X.509 identities and rotate keys automatically. SPIFFE recommends X.509 SVIDs where possible and describes short lifetimes and frequent rotation as limiting key-compromise exposure.<sup>[[2]](#references)</sup> A small team can apply the same properties with a private CA and automated per-device certificates; installing SPIRE is not required simply to satisfy the pattern.

## Step 1: authorize and register the placement

1. Record owner, site, exact allowed placement zone, allowed networks, assessment window, allowed destinations/actions and emergency contacts.
2. Record model, serial, storage serial, wired/wireless MACs, modem IMEI/eSIM or SIM ICCID, power supply and a current photograph.
3. Give the device a non-personal engagement identifier, for example `E2026-014-DROP03`. Do not encode a client name in broadcast hostnames or SSIDs.
4. Tell the exercise controller and the smallest necessary physical-security/SOC deconfliction group what “lost,” “moved,” and “discovered” mean for this test.
5. Pre-agree who may retrieve it and how a finder can report it. A safety label can omit sensitive client detail while providing a controlled callback.
6. Set an automatic authorization expiry. Connectivity continuing after scope end must not extend permission.

## Step 2: build a minimal recoverable image

Use a supported OS image, verify its signature/checksum through the vendor's documented channel, install security updates and keep a reproducible build manifest. Prefer a read-only or immutable base with a small writable data partition where the software permits it.

1. Remove default accounts, demo services, compilers and packages not needed for the authorized workload.
2. Disable local GUI, Bluetooth, discovery protocols, file sharing, Wi-Fi P2P and inbound administration unless the exercise explicitly requires one.
3. Enable secure boot and measured boot/TPM-backed key release if the hardware genuinely supports them; do not claim that a Raspberry Pi configuration has PC-class measured boot without validating the exact model.
4. Encrypt local writable state and configure a strict maximum size and retention time. Encryption is a delay/containment control, not proof that a running node reveals nothing.
5. Send important logs off-device. Bound local journals to prevent storage exhaustion, but do not configure log wiping or anti-forensic deletion.
6. Store the image manifest, package versions, configuration hash and recovery instructions at the controller.
7. Reimage a spare from the manifest and run the same health test. A design that only its builder can recover is not field-ready.

## Step 3: issue identities with one-way trust

Create three different identities:

- a **device identity**, accepted only by the rendezvous for this device;
- an **operator identity**, accepted by the organization gateway and protected with phishing-resistant MFA; and
- a **controller/deployment identity**, used to sign approved jobs or configuration, held outside both operator and field node.

The node should have the public key needed to verify signed jobs, never the signing key. A captured device credential must not authenticate to cloud consoles, source repositories, payment accounts, other nodes or client production.

Use short certificate lifetimes where automatic renewal is dependable. When a long-lived WireGuard key is operationally necessary, treat its public key as the revocation handle and constrain it with peer-specific tunnel address, firewall policy and broker authorization. Keep a tested controller action that removes that peer immediately.

## Step 4: stable outbound rendezvous

The following owned-lab pattern provides stable management through NAT without exposing an inbound service. It is ordinary WireGuard networking, not a covert reverse shell. Use documentation addresses and replace them only with organization-owned endpoints.

At the organization rendezvous, assign `10.77.0.1/32`; assign the field node `10.77.0.20/32`. The gateway peer entry should accept only the node's single address:

```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```

The node points outbound to the rendezvous and keeps the NAT mapping only when required:

```ini
# field node: /etc/wireguard/wg-field.conf
[Interface]
Address = 10.77.0.20/32
PrivateKey = <DROP03_PRIVATE_KEY>

[Peer]
PublicKey = <RENDEZVOUS_PUBLIC_KEY>
Endpoint = vpn.redteam.example:51820
AllowedIPs = 10.77.0.1/32
PersistentKeepalive = 25
```

WireGuard documents 25 seconds as a sensible keepalive interval across many NAT/firewall implementations when persistence is needed; leaving it disabled is preferable when it is not needed.<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` deliberately makes this a management path, not a default-route pivot.

Then apply controls outside WireGuard:

1. Resolve `vpn.redteam.example` through the approved bootstrap DNS path and pin the expected organization endpoint in deployment records.
2. On the node, allow outbound DHCP/RA, required DNS/NTP, the rendezvous endpoint and the minimum approved update path. Deny unsolicited inbound traffic on every uplink.
3. On the rendezvous, allow `10.77.0.20` to reach only the broker/health service required for the exercise. Do not forward it generally into a client network.
4. Put interactive operator access behind the organization gateway. Avoid exposing SSH from the node across the tunnel if a signed pull-job interface satisfies the assessment.
5. Configure the service manager to start the tunnel after networking, restart it after failure with bounded backoff and alert after repeated failure. A restart loop must not overwhelm the venue or hide the underlying fault.
6. Verify the peer's latest handshake, but do not use “handshake exists” as proof that the device is uncompromised.

TURN can provide relay-only reachability for a purpose-built WebRTC control plane, and a message queue can tolerate intermittent service. TURN explicitly gives a client a public relay address behind NAT; its server remains an observer.<sup>[[4]](#references)</sup> Choose one control architecture rather than stacking tunnels without a stated observer or reliability benefit.

## Step 5: uplink stability without personal links

For an authorized venue node, prefer this order:

1. client-provided wired or dedicated test VLAN;
2. owner-approved enterprise/guest Wi-Fi profile;
3. organization-contracted cellular/private APN fallback.

Never seed it with a personal phone hotspot, home SSID, personal eSIM, personal Apple/Google account or a Wi-Fi profile exported from a daily laptop. Those are exactly the artifacts a capture will join.

For each approved uplink:

- record SSID/BSSID or switch/VLAN and expected captive-portal behavior;
- set deterministic priority and a health check to an owned endpoint;
- make failover change only the underlay; the device and operator identities remain at the broker;
- ensure DNS, IPv6 and application traffic do not bypass the rendezvous during transition;
- alert on an unknown SSID/BSSID, SIM change, new default gateway, public-IP/ASN change or simultaneous uplinks;
- test power loss, DHCP renewal, AP restart, public-IP change, 24-hour idle, tunnel loss and primary-to-secondary-to-primary recovery before deployment.

Private MAC addressing can reduce casual cross-network tracking, but a stable per-network MAC is often needed for authorized NAC. Record what the chosen OS actually does and do not rotate around an owner's access control.

## Step 6: constrain work and data

A safe field node should not accept arbitrary shell text from a mailbox. Define signed job types such as `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` or another action explicitly named in the rules of engagement. Validate destination, duration, rate, output size and scope again on the node.

1. Give every job a unique ID, device audience, issue time, expiry, scope reference and maximum output.
2. Sign it with the controller/deployment identity.
3. Reject unknown fields, expired/replayed jobs and jobs for another device.
4. Stream results to an owned collector; encrypt and TTL any unavoidable local spool.
5. Log accepted/rejected job ID and result hash at the controller. Do not place sensitive command parameters in a public monitoring channel.
6. Stop processing when authorization expires, identity rotation fails or the controller marks the device quarantined.

## Monitoring for discovery, loss or compromise

Monitoring can tell the controller that observed state changed. It cannot reliably prove “investigators found the device,” and trying to surveil responders or probe their systems would exceed an authorized assessment.

### Collect off-device state

Send a signed, low-volume health record to the controller at a randomized but bounded operational interval. Include only what the controller needs:

- device ID, boot ID/counter and monotonic uptime;
- configuration/image hash and software version;
- device-certificate serial and renewal state;
- uplink class, interface, BSSID or switch context as authorized, default-gateway hash and public IP/ASN as observed by an owned service;
- tunnel handshake age, packet counters and queue depth;
- enclosure switch or hardware-tamper state if the owner approved the sensor;
- disk pressure, temperature, clock-offset estimate and last successful job ID;
- a sequence number and signature to expose replay or gaps.

Store gateway authentication, policy decisions, operator access, job submission, result hashes, provider audit events and alerts centrally. CISA recommends centralizing logs, protecting them from deletion, baselining normal activity and designating incident-response contacts.<sup>[[5]](#references)</sup>

### Discovery/compromise indicators

| Signal | Possible explanations | Controller action |
|---|---|---|
| Heartbeat absent | power/network failure, portal change, damage, deliberate blocking or removal | corroborate provider/site state; do not reconnect from an unapproved path |
| Boot counter changed unexpectedly | power cut, crash, removal or maintenance | quarantine jobs; compare time and site events |
| Config/image hash changed | update error, storage fault or tampering | stop work; revoke if not a controller-approved release |
| New uplink/BSSID/gateway/ASN | AP replacement, roaming, moved device or interception | compare approved inventory; quarantine an unexplained transition |
| Repeated rejected job/signature | corruption, replay or unauthorized controller | stop processing and investigate gateway/controller logs |
| Device credential used twice or from incompatible paths | cloned key, snapshot reuse or network transition | revoke immediately; retain both session records |
| Unexpected local login, interface, process or privilege event | maintenance or compromise | isolate through broker policy; preserve evidence |
| Enclosure switch/state transition | service, movement or discovery | notify the named site contact; do not trigger destructive action |
| Provider abuse notice/account query or SOC alert | detection, misconfiguration or out-of-scope traffic | stop activity and invoke deconfliction/incident process |
| Sentinel credential touched | someone read a no-privilege decoy secret unique to this node | revoke real device identity and preserve the alert trail |

A sentinel credential must grant **no access**, call only an organization-owned alert service and be disclosed in the rules of engagement. It is a tripwire for unauthorized reading, not a beacon for tracking whoever found the equipment.

### Alert thresholds

Use stateful rules, not one dramatic “caught” alarm:

- **warning:** one missed interval, normal address change or queue growth;
- **degraded:** three consecutive misses, renewal delay, primary-uplink loss or repeated restart;
- **quarantine:** unapproved hash/boot/uplink change, duplicate credential, sentinel use or unexpected privileged event;
- **confirmed discovery/loss:** site/controller report, physical inventory mismatch, device recovery by an unplanned party or validated provider/SOC escalation.

Test alert delivery through a channel independent of the field node. Avoid sending sensitive client/device detail to personal messaging or consumer push accounts.

## Suspected discovery or capture runbook

1. **Stop:** suspend new jobs and operator sessions. Do not send a “check if watched” probe.
2. **Quarantine:** make the broker deny the device identity and its routes while retaining existing logs.
3. **Revoke:** revoke the device certificate/key, queue token, update credential and any single-purpose service token. Suspend the organization SIM when physical loss is plausible.
4. **Preserve:** snapshot controller, gateway, provider and alert records; record trusted time, who acted and the last known configuration. Do not clear or remotely wipe the node.
5. **Notify:** contact the exercise controller, client incident contact and legal/privacy contacts defined in the authorization. If a third party found it, use the pre-agreed recovery process.
6. **Assess:** assume every secret and cached result on the node is exposed. Enumerate exactly what each secret could access and whether it was used after the suspicious event.
7. **Contain downstream:** rotate affected service credentials, invalidate pending jobs and inspect owned target/provider logs for unexpected behavior.
8. **Recover safely:** retrieve only through an authorized person; photograph/package it, record custody and acquire forensic evidence as the client directs.
9. **Resume with a new identity:** never silently re-enable the captured credential. Rebuild from the known manifest, fix the control failure and obtain explicit approval.

NIST's current incident-response guidance integrates preparation, detection, response and recovery into organization-wide cybersecurity risk management; preserve first so the client can determine what happened and choose the appropriate response.<sup>[[6]](#references)</sup>

## Capture drill before deployment

Hand an unlocked test unit or copy of its storage to a separate reviewer and ask them to enumerate:

1. device/site/engagement identifiers;
2. operator names, personal accounts, home/workstation networks and recovery contacts;
3. controller/broker destinations and credentials;
4. client network profiles and cached results;
5. other devices/projects reachable with each secret;
6. value or payment credentials;
7. what the controller can revoke and how quickly;
8. which activity remains attributable from central logs.

Pass criteria: zero personal accounts/workstation keys; zero cross-engagement or enrollment authority; no payment credential; bounded encrypted cache; one documented device-revocation action; complete controller-side accountability. Treat any unexpected personal link or lateral capability as a release blocker.

## Closeout

1. Stop jobs and disable the broker route at scope end.
2. Retrieve and reconcile the exact inventory; report anything missing.
3. Preserve logs/results and, if required, a forensic image according to the engagement retention plan.
4. Revoke device, SIM, queue, update and service identities even when the hardware was recovered.
5. Only after preservation/acceptance, sanitize or destroy media with the owner's approved data-disposal process and record completion. This is lifecycle management, not concealment.
6. Remove venue NAC/DHCP reservations, broker routes, DNS, cloud roles, alert rules and temporary contacts.
7. Document observed detection, missed telemetry, time to quarantine and every artifact that capture exposed.

## References

- [1] [NIST — IoT Device Cybersecurity Capability Catalog](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Concepts and short-lived workload identities](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Use Logging on Business Systems](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
