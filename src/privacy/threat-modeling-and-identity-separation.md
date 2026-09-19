# Threat Modeling & Identity Separation

{{#include ../banners/hacktricks-training.md}}

The most common anonymity failure is not broken cryptography. It is **linkage**: one identifier, timing pattern, device, account, payment, file, or human habit connects two contexts that were supposed to remain separate.

## Build a privacy threat model

EFF's six-question security plan is a strong base: what must be protected, from whom, the impact and likelihood of failure, the effort available, and allies who can help.<sup>[[1]](#references)</sup> Make it operational with a small table:

| Asset/action | Observer | Observable data | Correlation route | Control | Residual risk |
|---|---|---|---|---|---|
| Researching a client | ISP | Destination/timing metadata | Home subscriber record | Tor Browser | Tor use visible; end-to-end correlation |
| Pseudonymous account | Platform | IP, browser, recovery data | Reused phone/email/photo | Dedicated context and alias | Writing/social graph correlation |
| Online purchase | Merchant | Account, delivery, tokenized card | Address and account history | Guest checkout, minimal fields, virtual card | Issuer and carrier retain records |
| Red-team traffic | Target/client | Source IP and behavior | Provider/engagement records | Dedicated authorized egress | Deliberately attributable under escalation |

Review the table whenever the location, provider, device, counterpart, or consequences change.

## Draw the linkability graph

Treat each identity as a separate node. Add an edge for every shared attribute:

- email or recovery address;
- phone number or contact-book upload;
- username, avatar, photo, bio, or writing/code style;
- password, passkey-sync account, or recovery question;
- device, advertising ID, browser profile, cookies, fonts, or extensions;
- IP address, time zone, language, schedule, or simultaneous online status;
- bank card, exchange account, wallet cluster, shipping address, or loyalty program;
- document author fields, EXIF location, printer marks, or cloud-share owner;
- colleague, group membership, and social graph.

An edge is not automatically fatal, but it tells you which observer can make the connection. EFF specifically warns that phone numbers, email addresses, and reused photographs can link profiles.<sup>[[2]](#references)</sup>

## Create a compartment step by step

1. **Name the context and prohibited links.** Example: `client-red-2026`, prohibited from personal email, home browser profiles, personal payment methods, and unrelated clients.
2. **Choose the isolation boundary.** In increasing strength: separate browser profile → separate OS account → separate VM/qube → dedicated device. A separate tab or private window is not a security boundary.
3. **Create fresh identifiers inside that boundary.** Use a context-specific email/alias, username, password-manager vault or collection, and authentication keys. Do not add a personal recovery channel if unlinkability from the provider matters.
4. **Choose one network policy.** Decide whether the context always uses a client VPN, engagement VPS, trusted VPN, or Tor. Enforce fail-closed routing where possible.
5. **Choose a payment policy.** The payment method must match the observer model; a virtual card may hide the PAN from a merchant but still identifies the customer to the issuer.
6. **Set data-transfer rules.** Prefer narrowly scoped, deliberate transfers. Treat clipboard, shared folders, USB devices, cloud sync, printers, and screenshots as possible bridges.
7. **Record creation and teardown dates.** Define which evidence must be retained for contracts/tax/compliance and which transient data should expire.
8. **Test for links before use.** Inspect account settings, recovery fields, public profile, IP/DNS, browser state, file metadata, and provider dashboards.

{% hint style="warning" %}
Do not invent identity information where a service or law requires accurate identification. A privacy compartment is about data minimization and separation, not identity fraud or bypassing customer due diligence.
{% endhint %}

## Endpoint and account baseline

- Use supported hardware and promptly install OS, browser, wallet, and firmware updates.
- Enable device encryption and use a strong device passcode. Encryption at rest helps when a powered-off device is lost or seized, but not while malware or an unlocked session can read data.<sup>[[3]](#references)</sup>
- Use unique, randomly generated passwords in a password manager.
- Prefer phishing-resistant authentication such as WebAuthn/passkeys or hardware security keys where the threat model permits their recovery/sync model. NIST notes that manually entered OTPs are not phishing-resistant because an impostor can relay them.<sup>[[4]](#references)</sup>
- Keep recovery codes offline and separated from the endpoint. Review whether a synced passkey account joins identities that should remain separate.
- Disable unnecessary location, contacts, microphone, camera, Bluetooth, advertising-ID, and background permissions.
- Do not mix personal cloud sync, browser sync, password-manager accounts, or app stores into a high-separation context.

## Browser privacy

Browser fingerprinting uses observable configuration, device, environment, and behavior to identify or correlate a user. Clearing cookies or changing IP addresses does not reliably defeat it, and the W3C considers complete technical elimination by widely deployed means implausible.<sup>[[5]](#references)</sup>

For ordinary privacy:

1. Use a maintained browser with HTTPS-only mode and strong tracking protection.
2. Block third-party tracking and partition state where supported.
3. Use separate browser profiles for genuinely separate contexts.
4. Disable unneeded permissions and clear site data on a defined schedule.
5. Avoid logging into identity-rich accounts while doing unrelated sensitive research.

For web anonymity, use **Tor Browser in its standard configuration**. Do not proxy a normal browser through Tor: Tor Project warns that ordinary browsers can leak through DNS/WebRTC, persistent state, fonts, plugins, and fingerprint differences.<sup>[[6]](#references)</sup> Avoid extra extensions, unusual window sizes, custom fonts, and preferences that make the browser stand out.<sup>[[7]](#references)</sup>

## Communications and metadata

Metadata includes sender, recipient, time, location, and other context even when message content is encrypted.<sup>[[8]](#references)</sup>

- Prefer end-to-end-encrypted tools with minimized server-side metadata and open protocols/clients where practical.
- Verify sensitive contacts using an independent channel or in person. Signal safety numbers are designed for this check.<sup>[[9]](#references)</sup>
- Signal usernames can initiate contact without sharing a phone number, but a phone number is still required to register; configure phone-number visibility/discoverability deliberately.<sup>[[9]](#references)</sup>
- Disappearing messages reduce retained copies; recipients can still photograph, copy, forward, or archive content.
- Email normally exposes routing metadata. Even privacy-focused providers cannot make a message end-to-end encrypted when the other side uses ordinary email unless both parties use a compatible E2EE method. Proton, for example, documents that ordinary mail to other providers uses TLS and remains readable by the receiving provider.<sup>[[10]](#references)</sup>
- Separate address books and do not upload personal contacts to a pseudonymous account.

## Files, photos and authorship

Tails warns that photographs can contain camera and location data and office documents can contain author and creation-time fields.<sup>[[11]](#references)</sup>

Before sharing:

```bash
# Inspect recursively; do not assume the extension tells the whole story
exiftool -a -u -g1 path/to/file

# Create a cleaned copy. Verify the copy before publishing.
exiftool -all= -o cleaned-file path/to/file
```

Then reopen the cleaned copy in an isolated viewer and check:

- document properties, comments, tracked changes, hidden sheets/slides, thumbnails and attachments;
- EXIF/XMP/IPTC, GPS, timestamps, device/software names and unique IDs;
- visible reflections, landmarks, screen contents, voices, faces and background sounds;
- filename, archive paths, cloud-share owner, signing certificate and revision history.

Sanitization can damage evidence or authenticity. Preserve an encrypted original when chain of custody or later verification matters. Stylometry and coding style may also link authorship; metadata removal does not change human style.

## Common failure patterns

- Logging into a personal account through an “anonymous” connection.
- Reusing a recovery phone, avatar, username, public key, wallet, or donation address.
- Operating two identities at the same time from correlated contexts.
- Copying text/files through a personal cloud clipboard or shared folder.
- Installing distinctive Tor Browser extensions or changing many defaults.
- Trusting a “no logs” claim without understanding what is logged, for how long, and by which subcontractors.
- Assuming a secondary phone is anonymous while it travels alongside a personal phone. EFF notes that cellular location and co-travel can correlate the devices.<sup>[[3]](#references)</sup>
- Treating encryption as deletion; endpoints and recipients may retain plaintext.

## Verification checklist

- [ ] The context has no personal recovery address, phone, sync account, or reused media unless intentionally accepted.
- [ ] The intended network path is active and fails closed.
- [ ] Browser/device time zone, locale, extensions, and permissions match the plan.
- [ ] No personal accounts are open in the compartment.
- [ ] Files have been inspected and sanitized; originals are handled separately.
- [ ] Contacts are authenticated through a second channel.
- [ ] The provider-visible metadata and retention period are understood.
- [ ] Teardown, evidence retention, and account-recovery procedures are documented.

## References

- [1] [EFF Surveillance Self-Defense — Your Security Plan](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — Protecting Yourself on Social Networks](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — Attending a Protest](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Authentication and Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — Mitigating Browser Fingerprinting in Web Specifications](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — Using Tor with other browsers](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Plugins and add-ons in Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — Why Communication Metadata Matters](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Phone Number Privacy and Usernames: Deeper Dive](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — What is encrypted within Proton Mail?](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Warnings: Tails is safe but not magic](https://tails.net/doc/about/warnings/index.en.html)
{{#include ../banners/hacktricks-training.md}}
