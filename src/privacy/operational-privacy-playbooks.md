# Operational Privacy Playbooks

ये playbooks इस section के बाकी हिस्सों के controls को एक साथ जोड़ते हैं। ये शुरुआती बिंदु हैं, गारंटी नहीं: जब भी कोई नया observer, account, device, location, payment, file या counterparty workflow में शामिल हो, threat model को अपडेट करें।

## Universal preflight

1. वैध उद्देश्य और यह लिखें कि क्या **किससे** private रहना चाहिए।
2. उन identities, devices, networks, accounts, payment rails, counterparties, physical locations और data को दर्ज करें जिन्हें activity छुएगी।
3. सबसे मजबूत संभावित observer और failure के consequence की पहचान करें।
4. Authorization, लागू कानून, provider terms और organizational policy की पुष्टि करें।
5. तय करें कि safety, incident response, accounting और audit के लिए internally क्या attributable रहना चाहिए।
6. सबसे छोटा workable compartment चुनें; उपयोग से पहले उसके recovery और shutdown paths स्थापित करें।
7. Compartment को एक controlled service के विरुद्ध test करें, जिसमें IP/DNS/IPv6, browser identity, document metadata, payment statement और notification leakage शामिल हों।

[Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md) में दिए गए detailed model का उपयोग करें।

## Everyday privacy baseline

Goal: commercial tracking, account takeover और अनावश्यक exposure को कम करना, anonymous बनने की कोशिश किए बिना।

- Maintained OS का उपयोग करें जिसमें full-disk encryption, automatic updates, screen lock और उपलब्ध होने पर secure boot हो।
- पहले password manager, recovery email और phishing-resistant MFA/security keys को व्यवस्थित करें।
- App permissions, location history, advertising identifiers, cloud sync और third-party account connections की समीक्षा करें।
- कुछ extensions, tracking protection और HTTPS वाले mainstream browser का उपयोग करें, तथा work/personal/high-risk browsing के लिए अलग profiles रखें।
- Relationship के अनुसार private relay aliases या अलग email addresses का उपयोग करें; जब personal phone number केवल optional हो, तो उसका उपयोग न करें।
- Content के लिए end-to-end encrypted messaging को प्राथमिकता दें, लेकिन याद रखें कि participants, timing, groups और endpoints metadata बने रहते हैं।
- Files से metadata जानबूझकर हटाएं और publish करने से पहले original नहीं, exported copy को inspect करें।
- Payment-credential compartmentalization के लिए virtual-card या wallet tokens को प्राथमिकता दें; इन्हें anonymous न कहें।
- Encrypted recovery material का backup लें और restoration को test करें।

## Pseudonymous publication

Goal: casual readers और platforms को किसी publication को civil identity से आसानी से link करने से रोकना। यह capable targeted investigation को नहीं रोकता।

1. तय करें कि platform, hosting provider, readers, contacts, local network, payment provider या legal process threat model में शामिल हैं या नहीं।
2. Clean baseline से dedicated endpoint/account context बनाएं। Personal browser sync, cloud documents, contact upload और notification previews को disable करें।
3. चुने गए network compartment के माध्यम से pseudonymous account बनाएं। Usernames, avatars, recovery channels, writing boilerplate या personal identity-provider login को reuse न करें।
4. जब destination unlinkability speed से अधिक महत्वपूर्ण हो, तो Tor Browser का उपयोग करें; इसमें extensions न जोड़ें, इसे बहुत अधिक resize/customize न करें, और ordinary desktop session में online रहते हुए downloaded documents न खोलें।
5. ऐसे process से draft तैयार करें जो personal template names, revision authors, printer paths, GPS/EXIF, thumbnails या hidden layers embed न करे। एक copy export करें और appropriate metadata tools से उसे inspect करें।
6. Content में self-identifying facts की जांच करें: unique dates, workplace details, local weather/time zone, reflections, background audio, linguistic habits और prior-publication text reuse।
7. अलग reply channel का उपयोग करें। हर direct contact, attachment और link को संभावित correlation या phishing attempt मानें।
8. यदि money शामिल है, तो उस lawful method का उपयोग करें जो केवल आवश्यक data expose करे। मानकर चलें कि readers को पता न होने पर भी platform और regulated intermediary payee को जान सकते हैं।
9. Publish करने के बाद अलग clean context से public result को inspect करें। Platform ने क्या जोड़ा या transform किया, उसे record करें।
10. Planned cadence तभी बनाए रखें जब उससे stable behavioral fingerprint न बने; compartment को चुपचाप repurpose करने के बजाय retire करें।

Serious journalism, activism, domestic abuse या state-level risk के लिए किसी experienced digital-security organization से tailored help लें; static checklist local law या live adversary को model नहीं कर सकती।

## Authorized red-team engagement

Goal: authorization, control और incident response बनाए रखते हुए operators की personal identities और home networks को target telemetry से बाहर रखना।

### Before the start window

- ROE infrastructure annex, targets/exclusions, source ranges, dates, emergency stop और third-party/provider permissions को finalize करें।
- Dedicated operator profile या VM, engagement secrets, evidence store, cloud project, domains और budget allocate करें।
- Client-provided egress या organization-controlled fixed bastion को प्राथमिकता दें। Full-tunnel IPv4/IPv6/DNS behavior और fail-closed policy को test करें।
- Operator से public infrastructure तक की mapping को exercise controller या agreed escrow contact के पास store करें।
- Rate limits, destination allowlists और destructive, wireless, physical, phishing या credential-collection actions के लिए separate approval स्थापित करें।
- Organization-controlled payment rail का उपयोग करें और approvals को internally record करें।

### During the engagement

- Approved endpoint और tunnel से शुरू करें; assessment traffic से पहले observed egress verify करें।
- Personal accounts, devices, phone numbers, repositories, SSH/GPG keys और cloud sync को compartment से बाहर रखें।
- Operator/job, start/stop, source, scoped destination और configuration change को log करें, लेकिन अनावश्यक client content collect न करें।
- Scope ambiguity, unexpected third-party systems, provider abuse notification, safety impact, lost equipment या controller contact खोने पर रुकें।
- Neighbor के Wi-Fi, stolen credentials, unapproved SIM/account या किसी venue में छिपाए गए hardware के साथ कभी improvise न करें।

### End of engagement

- Jobs और C2 रोकें; approved drop devices recover करें; tokens, credentials और certificates revoke करें।
- Inventory के विरुद्ध infrastructure, domains, source addresses, expenses, data और provider cases का reconciliation करें।
- Contract के अनुसार client data return/delete/retain करें, minimum required audit evidence preserve करें, और दूसरे operator से shutdown verify करवाएं।

पूर्ण build और teardown guide के लिए [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) देखें।

## Lawful private purchase or donation

Goal: issuer, accounting, tax और sanctions obligations पूरी करते हुए merchant या public के सामने disclosure को कम करना।

1. सूची बनाएं कि किसे क्या नहीं जानना चाहिए: public audience, merchant, payment intermediary, employer/family account delegate, delivery service या blockchain observer।
2. Local rules, recipient/counterparty, provider terms, cash limits और recordkeeping needs की जांच करें।
3. Rail चुनें:
- accepted lawful local payments के लिए cash, जिसमें payment-network record न हो;
- online credential separation के लिए regulated virtual/merchant-specific card;
- cryptocurrency केवल acquisition, ledger, wallet backend, network, counterparty और later-spend links का analysis करने के बाद।
4. Required details truthful रूप से दें और केवल optional loyalty/marketing information को छोड़ें। किसी अन्य व्यक्ति की identity/address का उपयोग न करें या threshold के आसपास transaction split न करें।
5. Merchant browser/account context को अलग रखें और unrelated social login, loyalty या personal recovery channels से बचें।
6. पुष्टि करें कि statements, receipts, notifications, shipping और public donor lists पर क्या दिखाई देता है।
7. Required receipt/tax/authorization evidence को encrypted रूप से store करें; refund window के बाद disposable payment credentials revoke करें।

[Private Digital Payments](private-digital-payments.md) और [Cryptocurrency Privacy](cryptocurrency-privacy.md) देखें।

## Travel and untrusted networks

Goal: user द्वारा administer न किए जाने वाले networks पर data और accounts की सुरक्षा करना—not to conceal unauthorized activity।

- Devices update करें और travel से पहले आवश्यक credentials/maps download करें।
- Stored data को कम से कम रखें; full-disk encryption, strong unlock, remote-recovery planning और legal advice के अनुसार powered-off border/physical-risk procedures का उपयोग करें।
- Venue SSID/captive portal verify करें। Appropriate होने पर personal hotspot को प्राथमिकता दें, लेकिन याद रखें कि cellular subscriber और location records मौजूद रहते हैं।
- Organizational data के लिए full/forced approved VPN का उपयोग करें; verify करें कि tethered devices भी इसे share करें और IPv6/DNS behavior को test करें।
- Client isolation और repeatable policy के लिए travel router का उपयोग करें, anonymity guarantee के रूप में नहीं।
- Public USB charging, borrowed computers, public printers और shared meeting-room systems को अलग threats मानें।
- मानकर चलें कि physical presence, radio identifiers, portal login, cameras और payment/location records visit को correlate कर सकते हैं।

Comparison और setup details [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md) में हैं।

## Failure and exposure response

जब कोई compartment leak हो जाए या link होने की संभावना हो:

1. यदि continuation से harm बढ़ता है तो activity रोक दें; जहां लागू हो, engagement emergency stop का उपयोग करें।
2. Sensitive data फैलाए बिना आवश्यक evidence preserve करें। Exact time, observed indicator और affected assets record करें।
3. Appropriate owner/controller/security contact को notify करें। Privacy narrative बचाने के लिए incident को conceal न करें।
4. Sessions, tokens, payment credentials और infrastructure access revoke करें; secrets को known-clean endpoint से rotate करें।
5. निर्धारित करें कि कौन-से edges link हुए: endpoint, account recovery, network, payment, metadata, content, behavior, counterparty या physical presence।
6. पूरे affected compartment को burned मानें। केवल उसका username या exit IP बदलना पर्याप्त नहीं है।
7. Breach, provider, client, financial और legal notification duties पूरी करें।
8. Link पैदा करने वाले process को बदलने के बाद ही rebuild करें; control को document और test करें।

## Periodic audit

- [ ] Threat model और legal/provider assumptions की dated schedule पर समीक्षा की गई।
- [ ] Devices, accounts, aliases, domains, network paths और payment credentials का inventory बनाया गया।
- [ ] Recovery paths अनपेक्षित रूप से compartments को cross नहीं करते।
- [ ] Full-tunnel, DNS, IPv6 और fail-closed behavior test किए गए।
- [ ] Public files और profiles में metadata/content reuse की जांच की गई।
- [ ] Wallet nodes/backends और crypto protocol assumptions अभी भी current हैं।
- [ ] Logs और receipts minimal, encrypted, access-controlled और retention limits के भीतर हैं।
- [ ] पुराने compartments और engagement infrastructure को पूरी तरह retire किया गया।
