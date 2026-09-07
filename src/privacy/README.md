# Privacy

Digital privacy is not a product and **anonymity is not the same as hiding an IP address**. A workable plan combines a threat model, identity separation, endpoint security, an appropriate network path, payment choices, and disciplined behavior. EFF's security-planning method starts with the assets to protect, the adversaries, the consequences of failure, likelihood, acceptable effort, and available allies.<sup>[[1]](#references)</sup>

This section is written for privacy-conscious users and **authorized** red-team operators. It covers realistic techniques and their limits; it does not promise perfect anonymity.

**Research cutoff:** 7 September 2026. Provider availability, product behavior, sanctions, cash/prepaid thresholds, SIM-registration rules, and crypto regulation change frequently; verify them again before relying on them.

{% hint style="danger" %}
Privacy tools do not authorize access. Do not join or compromise a neighbor's network, bypass a captive portal, use credentials that are not yours, plant a device in a café or other premises without permission, evade KYC or sanctions, conceal criminal proceeds, or test third-party systems outside written scope. Unauthorized access is criminalized in many jurisdictions, including under the US CFAA, the UK Computer Misuse Act, and EU member-state laws implementing Directive 2013/40/EU.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
{% endhint %}

## Privacy, pseudonymity, anonymity and security

| Goal | Meaning | Typical failure |
|---|---|---|
| **Confidentiality** | Outsiders cannot read content | Metadata still identifies the parties |
| **Privacy** | Information disclosure is limited to what is necessary | A provider retains more data than expected |
| **Pseudonymity** | Activity uses a stable identity not publicly tied to a legal identity | Recovery email, payment, IP, photo, or writing style links it |
| **Anonymity** | An observer cannot distinguish the actor from a meaningful set of others | Login, fingerprint, timing, location, or transaction correlation shrinks the set |
| **Unlinkability** | Two actions cannot reliably be attributed to the same actor | Reused identifiers, simultaneous activity, or shared infrastructure joins them |
| **Security** | Systems resist compromise | A secure but identified account remains non-anonymous |

These properties are observer-specific. A merchant might not see a card number while the issuer still knows the customer and transaction. A website might see a Tor exit rather than a home IP while an account login identifies the user immediately.

## Start with the observer

Before choosing tools, write down:

1. **Assets:** identity, location, browsing destinations, message contents, social graph, payment details, client name, red-team source infrastructure, or stored evidence.
2. **Observers:** local Wi-Fi operator, ISP/mobile carrier, VPN, Tor entry/exit, DNS resolver, website, ad network, cloud host, payment issuer, merchant, exchange, counterparties, employer, or government.
3. **Correlation handles:** IP address, account/recovery fields, phone number, device identifiers, cookies, browser fingerprint, time zone, payment instrument, shipping address, writing style, transaction graph, physical presence, and cameras.
4. **Capability and time:** passive commercial tracking is different from a targeted observer able to subpoena providers, seize endpoints, or watch both ends of a connection.
5. **Failure cost:** embarrassment, account suspension, client harm, financial loss, physical danger, or legal exposure.

Then select the smallest sustainable controls. A complicated plan that is routinely bypassed is weaker than a simpler plan used consistently.

## Quick decision table

| Need | Sensible starting point | What it does **not** solve |
|---|---|---|
| Hide browsing metadata from an ISP/local network | Reputable VPN or Tor Browser | Accounts, cookies, device fingerprint, endpoint compromise |
| Stronger web anonymity | Tor Browser; Tails for an amnesic session | Global traffic correlation, personal disclosures, physical observation |
| Persistent compartmentalized work | Whonix or Qubes-Whonix; separate qubes/profiles | Hypervisor/host compromise, behavior linking identities |
| Fast authorized red-team egress | Client-provided jump host or engagement-specific VPS/VPN | Provider/customer attribution; scope and cloud policy obligations |
| Reduce merchant exposure of a card number | Issuer virtual card or tokenized wallet | Issuer/network knowledge, shipping, account and device data |
| Minimize point-of-sale payment data | Lawfully obtained cash where accepted | CCTV, receipts, withdrawal trail, cash limits |
| Improve public-chain crypto privacy | Own wallet/node, new addresses, coin control, Tor, supported PayJoin | Exchange/KYC, counterparty records, permanent-chain analysis |
| Default on-chain amount/receiver/sender confidentiality | Monero with separate wallet contexts and network privacy | Acquisition/off-ramp records, endpoint compromise, merchant/shipping data |

## Core rules

- **Separate contexts before activity starts.** Retrofitting separation after accounts, devices, and payments have already been linked rarely undoes the history.
- **Do not customize yourself into uniqueness.** Browser fingerprinting can correlate activity even after cookies are cleared or an IP changes; standard configurations with larger anonymity sets are usually preferable.<sup>[[5]](#references)</sup>
- **Protect the endpoint.** Network anonymity cannot save an unlocked, infected, or seized device.
- **Encrypt content and minimize metadata.** End-to-end encryption protects message content, not necessarily who communicated, when, from where, or with which device.
- **Treat providers as observers.** VPNs, email services, cloud hosts, exchanges, payment issuers, and alias forwarders see different parts of the activity.
- **Prefer verifiable claims.** Look for protocol documentation, reproducible software, public audits, retention details, and transparency reports instead of “military-grade” marketing.
- **Reassess periodically.** Services, laws, threat actors, and defaults change.

## Section map

- [Threat Modeling & Identity Separation](threat-modeling-and-identity-separation.md)
- [Network Privacy & Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md)
- [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md)
- [Privacy Operating Systems](privacy-operating-systems.md)
- [Privacy-Preserving Communications and Sharing](privacy-preserving-communications-and-sharing.md)
- [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md)
- [Private Digital Payments](private-digital-payments.md)
- [Cryptocurrency Privacy](cryptocurrency-privacy.md)
- [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md)
- [Reproducible Privacy Testing](reproducible-privacy-testing.md)
- [Operational Privacy Playbooks](operational-privacy-playbooks.md)

## Guide and verification index

| Technique | Deployment guide | Verification/failure test |
|---|---|---|
| Identity/browser compartment | [Threat Modeling & Identity Separation](threat-modeling-and-identity-separation.md) | [Browser and OS tests](reproducible-privacy-testing.md#browser-compartment-test) |
| VPN, Tor, guest Wi-Fi, travel router, cellular | [Network Privacy & Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md) | [Network-path test](reproducible-privacy-testing.md#network-path-test) |
| Split relays, OHTTP, namespaces, bridges, onions, I2P | [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md) | [Tor/onion and route tests](reproducible-privacy-testing.md#tor-and-onion-service-test) |
| Tails, Whonix and Qubes | [Privacy Operating Systems](privacy-operating-systems.md) | [OS isolation test](reproducible-privacy-testing.md#operating-system-isolation-test) |
| Signal, SimpleX, Briar, OnionShare and encrypted files | [Privacy-Preserving Communications and Sharing](privacy-preserving-communications-and-sharing.md) | [Communications/file tests](reproducible-privacy-testing.md#communications-metadata-test) |
| Authorized red-team egress/drop nodes | [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) | [Accountability drill](reproducible-privacy-testing.md#authorized-red-team-accountability-drill) |
| Cash, prepaid and virtual cards | [Private Digital Payments](private-digital-payments.md) | [Payment privacy test](reproducible-privacy-testing.md#payment-privacy-test) |
| Bitcoin, PayJoin/CoinJoin, Lightning and Monero | [Cryptocurrency Privacy](cryptocurrency-privacy.md) | [Payment privacy test](reproducible-privacy-testing.md#payment-privacy-test) |
| Silent Payments, Zcash, Taler and federated e-cash | [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md) | [Payment privacy test](reproducible-privacy-testing.md#payment-privacy-test) |

## References

- [1] [EFF Surveillance Self-Defense — Your Security Plan](https://ssd.eff.org/module/your-security-plan)
- [2] [US Code, 18 USC §1030 — Fraud and related activity in connection with computers](https://uscode.house.gov/view.xhtml?req=title:18%20section:1030%20edition:prelim)
- [3] [UK Computer Misuse Act 1990, section 1](https://www.legislation.gov.uk/ukpga/1990/18/section/1)
- [4] [EUR-Lex — Directive 2013/40/EU on attacks against information systems](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32013L0040)
- [5] [W3C — Mitigating Browser Fingerprinting in Web Specifications](https://www.w3.org/TR/fingerprinting-guidance/)
