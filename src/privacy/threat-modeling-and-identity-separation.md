# Threat Modeling और Identity Separation

{{#include ../banners/hacktricks-training.md}}

Anonymity failure का सबसे सामान्य कारण टूटी हुई cryptography नहीं है। यह **linkage** है: एक identifier, timing pattern, device, account, payment, file या human habit दो ऐसे contexts को जोड़ देता है जिन्हें अलग रहना था।

## Privacy threat model बनाएं

EFF की six-question security plan एक मजबूत आधार है: क्या सुरक्षित रखना है, किससे सुरक्षित रखना है, failure का impact और likelihood क्या है, उपलब्ध effort कितना है, और कौन से allies सहायता कर सकते हैं।<sup>[[1]](#references)</sup> इसे एक छोटी table के साथ operational बनाएं:

| Asset/action | Observer | Observable data | Correlation route | Control | Residual risk |
|---|---|---|---|---|---|
| किसी client पर research करना | ISP | Destination/timing metadata | Home subscriber record | Tor Browser | Tor use दिखाई दे सकता है; end-to-end correlation |
| Pseudonymous account | Platform | IP, browser, recovery data | Reused phone/email/photo | Dedicated context और alias | Writing/social graph correlation |
| Online purchase | Merchant | Account, delivery, tokenized card | Address और account history | Guest checkout, minimal fields, virtual card | Issuer और carrier records बनाए रखते हैं |
| Red-team traffic | Target/client | Source IP और behavior | Provider/engagement records | Dedicated authorized egress | Escalation के दौरान जानबूझकर attributable |

Location, provider, device, counterpart या consequences बदलने पर table की समीक्षा करें।

## Linkability graph बनाएं

हर identity को एक अलग node मानें। हर shared attribute के लिए एक edge जोड़ें:

- email या recovery address;
- phone number या contact-book upload;
- username, avatar, photo, bio या writing/code style;
- password, passkey-sync account या recovery question;
- device, advertising ID, browser profile, cookies, fonts या extensions;
- IP address, time zone, language, schedule या simultaneous online status;
- bank card, exchange account, wallet cluster, shipping address या loyalty program;
- document author fields, EXIF location, printer marks या cloud-share owner;
- colleague, group membership और social graph।

कोई edge अपने-आप fatal नहीं होता, लेकिन यह बताता है कि कौन-सा observer connection बना सकता है। EFF विशेष रूप से चेतावनी देता है कि phone numbers, email addresses और reused photographs profiles को link कर सकते हैं।<sup>[[2]](#references)</sup>

## Compartment को step by step बनाएं

1. **Context और prohibited links का नाम तय करें।** उदाहरण: `client-red-2026`, जिसे personal email, home browser profiles, personal payment methods और unrelated clients से अलग रखना है।
2. **Isolation boundary चुनें।** बढ़ती strength के क्रम में: separate browser profile → separate OS account → separate VM/qube → dedicated device। Separate tab या private window security boundary नहीं है।
3. **उस boundary के भीतर fresh identifiers बनाएं।** Context-specific email/alias, username, password-manager vault या collection और authentication keys का उपयोग करें। यदि provider से unlinkability महत्वपूर्ण है, तो personal recovery channel न जोड़ें।
4. **एक network policy चुनें।** तय करें कि context हमेशा client VPN, engagement VPS, trusted VPN या Tor का उपयोग करेगा। जहां संभव हो, fail-closed routing लागू करें।
5. **Payment policy चुनें।** Payment method observer model के अनुरूप होना चाहिए; virtual card merchant से PAN छिपा सकता है, लेकिन issuer के लिए customer की पहचान फिर भी बनी रहती है।
6. **Data-transfer rules तय करें।** केवल narrowly scoped और deliberate transfers को प्राथमिकता दें। Clipboard, shared folders, USB devices, cloud sync, printers और screenshots को संभावित bridges मानें।
7. **Creation और teardown dates रिकॉर्ड करें।** तय करें कि contracts/tax/compliance के लिए कौन-सा evidence बनाए रखना है और कौन-सा transient data expire होना चाहिए।
8. **उपयोग से पहले links की जांच करें।** Account settings, recovery fields, public profile, IP/DNS, browser state, file metadata और provider dashboards inspect करें।

{% hint style="warning" %}
जहां कोई service या law accurate identification मांगता है, वहां identity information गढ़ें नहीं। Privacy compartment का उद्देश्य data minimization और separation है, identity fraud या customer due diligence को bypass करना नहीं।
{% endhint %}

## Endpoint और account baseline

- Supported hardware का उपयोग करें और OS, browser, wallet तथा firmware updates तुरंत install करें।
- Device encryption enable करें और strong device passcode का उपयोग करें। Encryption at rest powered-off device के खोने या seize होने पर सहायता करता है, लेकिन malware या unlocked session data पढ़ सकता हो तो नहीं।<sup>[[3]](#references)</sup>
- Password manager में unique, randomly generated passwords का उपयोग करें।
- जहां threat model उनके recovery/sync model की अनुमति देता हो, वहां WebAuthn/passkeys या hardware security keys जैसी phishing-resistant authentication को प्राथमिकता दें। NIST के अनुसार manually entered OTPs phishing-resistant नहीं होते, क्योंकि impostor उन्हें relay कर सकता है।<sup>[[4]](#references)</sup>
- Recovery codes को offline रखें और endpoint से अलग रखें। जांचें कि synced passkey account उन identities को जोड़ तो नहीं रहा जिन्हें अलग रहना चाहिए।
- अनावश्यक location, contacts, microphone, camera, Bluetooth, advertising-ID और background permissions disable करें।
- High-separation context में personal cloud sync, browser sync, password-manager accounts या app stores को mix न करें।

## Browser privacy

Browser fingerprinting observable configuration, device, environment और behavior का उपयोग करके user की पहचान या correlation करता है। Cookies clear करने या IP addresses बदलने से यह भरोसेमंद तरीके से समाप्त नहीं होता, और W3C widely deployed means द्वारा complete technical elimination को implausible मानता है।<sup>[[5]](#references)</sup>

सामान्य privacy के लिए:

1. HTTPS-only mode और strong tracking protection वाला maintained browser उपयोग करें।
2. Third-party tracking block करें और जहां supported हो, state partition करें।
3. वास्तव में अलग contexts के लिए अलग browser profiles उपयोग करें।
4. अनावश्यक permissions disable करें और defined schedule पर site data clear करें।
5. Unrelated sensitive research करते समय identity-rich accounts में login करने से बचें।

Web anonymity के लिए **Tor Browser in its standard configuration** का उपयोग करें। Normal browser को Tor के माध्यम से proxy न करें: Tor Project चेतावनी देता है कि ordinary browsers DNS/WebRTC, persistent state, fonts, plugins और fingerprint differences के माध्यम से leak कर सकते हैं।<sup>[[6]](#references)</sup> Extra extensions, unusual window sizes, custom fonts और ऐसी preferences से बचें जो browser को अलग दिखाएं।<sup>[[7]](#references)</sup>

## Communications और metadata

Metadata में sender, recipient, time, location और अन्य context शामिल होते हैं, भले ही message content encrypted हो।<sup>[[8]](#references)</sup>

- जहां practical हो, minimized server-side metadata और open protocols/clients वाले end-to-end-encrypted tools को प्राथमिकता दें।
- Sensitive contacts को independent channel या personally verify करें। Signal safety numbers इसी check के लिए design किए गए हैं।<sup>[[9]](#references)</sup>
- Signal usernames phone number share किए बिना contact शुरू कर सकते हैं, लेकिन register करने के लिए phone number अभी भी आवश्यक है; phone-number visibility/discoverability को सोच-समझकर configure करें।<sup>[[9]](#references)</sup>
- Disappearing messages retained copies को कम करते हैं; recipients फिर भी content की photograph ले सकते हैं, उसे copy, forward या archive कर सकते हैं।
- Email सामान्यतः routing metadata expose करता है। Privacy-focused providers भी message को end-to-end encrypted नहीं बना सकते जब दूसरी ओर ordinary email का उपयोग हो, जब तक दोनों parties compatible E2EE method का उपयोग न करें। उदाहरण के लिए, Proton document करता है कि अन्य providers को भेजे गए ordinary mail में TLS का उपयोग होता है और वह receiving provider द्वारा readable रहता है।<sup>[[10]](#references)</sup>
- Address books अलग रखें और personal contacts को pseudonymous account पर upload न करें।

## Files, photos और authorship

Tails चेतावनी देता है कि photographs में camera और location data हो सकता है तथा office documents में author और creation-time fields हो सकते हैं।<sup>[[11]](#references)</sup>

Share करने से पहले:
```bash
# Inspect recursively; do not assume the extension tells the whole story
exiftool -a -u -g1 path/to/file

# Create a cleaned copy. Verify the copy before publishing.
exiftool -all= -o cleaned-file path/to/file
```
फिर cleaned copy को एक isolated viewer में दोबारा खोलें और जांचें:

- document properties, comments, tracked changes, hidden sheets/slides, thumbnails और attachments;
- EXIF/XMP/IPTC, GPS, timestamps, device/software names और unique IDs;
- दिखाई देने वाले reflections, landmarks, screen contents, voices, faces और background sounds;
- filename, archive paths, cloud-share owner, signing certificate और revision history।

Sanitization से evidence या authenticity को नुकसान पहुंच सकता है। जब chain of custody या बाद में verification महत्वपूर्ण हो, तो encrypted original सुरक्षित रखें। Stylometry और coding style भी authorship से link कर सकते हैं; metadata removal से human style नहीं बदलती।

## सामान्य failure patterns

- किसी “anonymous” connection के माध्यम से personal account में login करना।
- recovery phone, avatar, username, public key, wallet या donation address को reuse करना।
- correlated contexts से एक ही समय पर दो identities operate करना।
- personal cloud clipboard या shared folder के माध्यम से text/files copy करना।
- विशिष्ट Tor Browser extensions install करना या कई defaults बदलना।
- यह समझे बिना “no logs” claim पर भरोसा करना कि क्या log किया जाता है, कितने समय तक रखा जाता है और किन subcontractors द्वारा रखा जाता है।
- यह मान लेना कि secondary phone anonymous है, जबकि वह personal phone के साथ-साथ travel करता है। EFF के अनुसार cellular location और co-travel devices को correlate कर सकते हैं।<sup>[[3]](#references)</sup>
- encryption को deletion समझना; endpoints और recipients plaintext retain कर सकते हैं।

## Verification checklist

- [ ] Context में कोई personal recovery address, phone, sync account या reused media नहीं है, जब तक इसे जानबूझकर स्वीकार न किया गया हो।
- [ ] Intended network path active है और fails closed।
- [ ] Browser/device time zone, locale, extensions और permissions plan से match करते हैं।
- [ ] Compartment में कोई personal account open नहीं है।
- [ ] Files inspect और sanitize कर लिए गए हैं; originals को अलग से handle किया जाता है।
- [ ] Contacts को second channel के माध्यम से authenticate किया गया है।
- [ ] Provider-visible metadata और retention period समझे गए हैं।
- [ ] Teardown, evidence retention और account-recovery procedures documented हैं।

## References

- [1] [EFF Surveillance Self-Defense — आपकी Security Plan](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — Social Networks पर अपनी सुरक्षा करना](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — Protest में भाग लेना](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Authentication और Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — Web Specifications में Browser Fingerprinting को Mitigate करना](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — अन्य browsers के साथ Tor का उपयोग करना](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Tor Browser में Plugins और add-ons](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — Communication Metadata क्यों महत्वपूर्ण है](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Phone Number Privacy और Usernames: Deeper Dive](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — Proton Mail में क्या encrypted है?](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Warnings: Tails सुरक्षित है, लेकिन magic नहीं है](https://tails.net/doc/about/warnings/index.en.html)
{{#include ../banners/hacktricks-training.md}}
