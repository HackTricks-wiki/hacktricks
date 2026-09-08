# Authorized Red-Team Infrastructure

दीर्घकालिक on-site devices के लिए [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) design और suspected-discovery runbook का उपयोग करें।

एक professional red team के लिए लक्ष्य accountability से बचना नहीं, बल्कि **controlled attribution** है। Target को operator का home IP या personal accounts आसानी से दिखाई नहीं देने चाहिए, जबकि engagement owner को source की पहचान करने, operation रोकने, abuse reports संभालने, evidence सुरक्षित रखने और authorization सिद्ध करने में सक्षम होना चाहिए।

यह पृष्ठ lawful engagement के लिए deployment baseline है। जिस adversary tradecraft का यह अनुकरण करता है—जिसमें compromised ORBs, residential relays, fronting, dead drops और nearby wireless pivots शामिल हैं—उसके लिए [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) और [Government and APT Case Studies](government-and-apt-case-studies.md) से शुरू करें, फिर आवश्यक telemetry को [authorized labs](authorized-adversary-emulation-labs.md) में दोहराएं।

NIST rules of engagement (ROE) को पहले से निर्धारित उन constraints के रूप में परिभाषित करता है जो परिभाषित testing activities के लिए authority प्रदान करते हैं।<sup>[[1]](#references)</sup> Privacy architecture उस authority का विस्तार नहीं कर सकता।

## Egress pattern चुनें

| Pattern | सबसे अच्छा उपयोग | Target को दिखाई देता है | Provider/local observer को दिखाई देता है | Accountability |
|---|---|---|---|---|
| Client-provided VPN/jump host | अधिकांश assessments | Client address range | Client identity और operator access | सबसे मजबूत |
| Red-team organization bastion | दोहराए जा सकने वाले controlled egress | Organization range | Hosting provider और organization | मजबूत |
| Engagement-specific VPS | Clients/campaigns को अलग करना | VPS address | Host account, billing, control-plane और access logs | Documentation होने पर मजबूत |
| Approved commercial VPN | Provider और ROE द्वारा अनुमत research/scanning | Shared/dedicated VPN egress | VPN account और source connection | मध्यम |
| Tor Browser | Destination unlinkability की आवश्यकता वाली web research | Tor exit | Local network को Tor/bridge; destination को Tor दिखाई देता है | Allowlisted source attribution के लिए अनुपयुक्त |
| Client-approved on-site drop | Internal simulation | On-site device/address | Site network और remote tunnel provider | Inventory होने पर मजबूत |
| Lawful guest Wi-Fi | कम-जोखिम वाला administrative/research उपयोग | Venue public IP या tunnel egress | Venue, ISP, VPN/Tor | कमजोर और physically observable |

अधिकांश कार्यों के लिए consumer anonymity services की तुलना में client-provided या organization-controlled fixed egress अधिक सुरक्षित और तेज़ होता है। इससे defenders को exercise design के अनुसार ज्ञात source ranges को allowlist करने, monitor करने या जानबूझकर **allowlist न करने** की सुविधा भी मिलती है।

## ROE infrastructure annex

Deployment से पहले दर्ज करें:

- authorization देने और प्राप्त करने वाली legal entities;
- exact targets और explicit exclusions;
- start/end times, time zone और अनुमत techniques;
- source IPs, autonomous-system/provider names, domains, redirectors, mail infrastructure और on-site device identifiers;
- phishing, C2, credential capture, wireless testing, physical access, denial-of-service, persistence या third-party services की अनुमति है या नहीं;
- client और provider approvals, जिसमें कोई pre-notification reference भी शामिल है;
- emergency stop phrase, 24/7 client और provider abuse contacts तथा maximum response time;
- collect किए जा सकने वाले data classes, encryption, access, retention और deletion;
- evidence और logging requirements, जिसमें public infrastructure से operator तक mapping किसके पास है;
- teardown, domain expiration, certificate revocation, credential rotation, device recovery और final attestation।

सत्यापित करें कि public IPs और domains वास्तव में authorizing party द्वारा नियंत्रित हैं या स्पष्ट रूप से scope में शामिल हैं। NIST SP 800-115 testing से पहले यह पुष्टि करने की सलाह देता है कि public target addresses organization के purview में हैं।<sup>[[2]](#references)</sup>

## Engagement-specific fast egress

### Build workflow

1. **Engagement account/project बनाएं** और accurate billing तथा ownership details का उपयोग करते हुए इसे red-team organization के अंतर्गत रखें। Roles, API keys, budgets और audit logs को अन्य clients से अलग रखें।
2. **हर provider policy जांचें।** Cloud, VPS, CDN, domain, email और VPN providers के अलग-अलग rules होते हैं। उदाहरण के लिए, AWS specified assessments की अनुमति देता है, लेकिन hosted C2/covert simulations के लिए prior approval आवश्यक है और सूचीबद्ध activities प्रतिबंधित हैं।<sup>[[3]](#references)</sup>
3. **Fixed egress addresses allocate करें** और उन्हें ROE annex में डालें। Rapid IP/resource cycling से बचें; इससे incident response जटिल होता है और provider policy का उल्लंघन हो सकता है।
4. **Management को harden करें:** key-only SSH या identity-aware management plane, phishing-resistant MFA, separate admin network, least privilege, patched images, no public admin ports और encrypted secret storage का उपयोग करें।
5. **Operator endpoint से bastion तक full-tunnel path बनाएं।** DNS और IPv6 को जानबूझकर route करें और tunnel down होने पर firewall deny लागू करें।
6. **जब संभव हो, outbound destinations और ports को authorized scope तक सीमित करें।** Scanners पर rate-limit लगाएं और irreversible/destructive techniques को अलग approval gate के पीछे रखें।
7. **Surveillance के लिए नहीं, accountability के लिए log करें:** operator authentication, configuration changes, start/stop, source address, scoped destination और tool/job identifiers। Payload/credential capture से बचें, जब तक exercise के लिए इसकी आवश्यकता न हो और data plan द्वारा इसकी सुरक्षा न की गई हो।
8. **Organization के स्वामित्व वाले controlled endpoint के माध्यम से validation करें:** observed IPv4/IPv6, DNS path, reverse DNS, clock, source-port behavior, failure/reconnect और provider abuse contact की जांच करें।
9. **Attribution map को exercise controller या सहमत escrow contact के साथ securely share करें।** यदि blind detection test का हिस्सा है, तो इसे target team के लिए publish न करें।

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
VPS destination के लिए केवल pseudonymous होता है। Host के पास contact, billing, identity, source-IP, API, device, location और usage records हो सकते हैं; केवल customer-visible AWS CloudTrail history ही management activity उजागर कर सकती है।<sup>[[4]](#references)</sup> Hosting के लिए cryptocurrency से भुगतान करने पर भी ये records मिटते नहीं हैं।

## Domains और certificates

- Organization के स्वामित्व वाला engagement-specific registrar account उपयोग करें।
- Registrar lock, जहाँ समर्थित हो वहाँ DNSSEC, MFA/security keys और auto-renew को केवल approved अवधि के लिए enable करें।
- Public exposure कम करने के लिए registration privacy उपयोग करें, registrant information को गलत दिखाने के लिए नहीं। ICANN policy के अनुसार registrars को registration data एकत्र करना आवश्यक है, भले ही public display redacted या proxied हो।<sup>[[5]](#references)</sup>
- ऐसे names से बचें जो गैर-संबंधित parties का unlawful impersonation करें। Typosquatting/lookalike domains के लिए client और provider की explicit approval आवश्यक है।
- DNS, certificates, CDN/redirector configuration और third-party analytics की inventory रखें, जो operators या clients को leak कर सकते हैं।
- Teardown के समय records हटाएँ, certificates/tokens revoke करें, agreed evidence सुरक्षित रखें और तय करें कि domain को defensively retain करना चाहिए या नहीं।

## Authorized on-site drop nodes

Raspberry Pi या इसी प्रकार का appliance केवल तब स्वीकार्य है जब property/network owner और client उसके exact placement और behavior को स्पष्ट रूप से authorize करें। एक सुरक्षित plan:

1. Device serial, MAC/private-MAC policy, photo, owner, exact approved location, power source, retrieval deadline और tamper contact दर्ज करें।
2. Minimal signed image, encrypted secrets, read-only या recoverable storage, host firewall, जहाँ व्यावहारिक हो वहाँ automatic security updates और कोई default credentials न रखें।
3. Named engagement endpoint से केवल outbound communication configure करें। Unauthenticated listener expose न करें।
4. Destinations और capabilities को allowlist करें। Packet capture, credential collection, wireless impersonation और lateral movement में से प्रत्येक के लिए explicit authorization आवश्यक है।
5. Mutual authentication, short-lived keys, remote kill, health reporting और bandwidth limits का उपयोग करें।
6. Loss/theft की स्थिति में reusable credentials या client data उजागर न हो, यह सुनिश्चित करें।
7. Retrieval और secure wipe/decommission को calendar में दर्ज करें; signed recovery record प्राप्त करें।

Café, hotel, shared office, neighbor's property या public venue में owner/operator की written permission के बिना hardware न छिपाएँ।

## Guest networks और travel routers

यदि authorized scenario में guest access आवश्यक हो:

- Venue/client के साथ SSID और acceptable-use policy verify करें;
- Privileged workstation को isolate करने के लिए organization-owned travel router या low-trust bridge device उपयोग करें;
- Captive portals को privileged workstation के बाहर complete करें;
- Assessment traffic से पहले approved tunnel शुरू करें;
- Confirm करें कि tethered devices वास्तव में उसी tunnel का उपयोग कर रहे हैं;
- मानकर चलें कि venue radio association, portal, physical presence और camera/payment records को correlate कर सकता है;
- Access control को कभी bypass न करें, किसी अन्य device को clone न करें, Wi-Fi पर attack न करें और equipment पीछे न छोड़ें।

## Operational separation

- प्रत्येक client/engagement के लिए अलग endpoint compartment, cloud project, secrets set, domain group, redirector set और evidence store रखें।
- Approved organization systems के बाहर personal email, browser sync, phone number, cloud drive, SSH/GPG key, code-signing identity या payment reimbursement का उपयोग न करें।
- Clients के बीच distinctive payload configuration, callback paths, certificates या public repositories reuse न करें, जब तक exercise design fingerprinting को स्वीकार न करता हो।
- Infrastructure के लिए kill date और budget alert निर्धारित करें। Orphaned systems client और Internet दोनों के लिए risk बन जाते हैं।
- Accidents की investigation के लिए पर्याप्त internal attribution सुरक्षित रखें। “No logs” आमतौर पर professional evidence और safety obligations के साथ compatible नहीं है।

## Defenders से blind, controller के लिए attributable

जब exercise objective allowlist को test करने के बजाय detection को measure करना हो, तब operation को unaccountable बनाए बिना target SOC को blind रखा जा सकता है:

1. Exercise controller प्रत्येक public source, domain, certificate और on-site device को approve करता है, लेकिन उनकी list SOC से छिपाकर रखता है।
2. Controller source-to-engagement/operator map को separate encrypted vault में two-person emergency access के साथ store करता है।
3. प्रत्येक operator job को scope, time window, source compartment और irreversible job identifier वाला signed manifest मिलता है। Normal operation के दौरान target को manifest देखने की आवश्यकता नहीं होती।
4. Bastion audit events को chained या append-only रूप में controller storage पर भेजा जाता है, ताकि कोई operator incident के बाद attribution को चुपचाप rewrite न कर सके।
5. 24/7 provider-abuse contact एक verification phrase/reference रखता है, जो client को publicly disclose किए बिना authorization की पुष्टि करता है।
6. प्रत्येक path एक out-of-band stop channel implement करता है, जो assessment C2, target network या किसी एक operator के account पर निर्भर नहीं होता।
7. Live testing से पहले प्रत्येक source से benign canaries भेजें। Confirm करें कि controller उन्हें ROE response time के भीतर resolve और stop कर सकता है।
8. Exercise के बाद SOC telemetry की controller ledger से तुलना करें, source list disclose करें और missed/incorrect detections समझाएँ।

Anti-forensics, log destruction, compromised relays या false subscriber identities न जोड़ें। ये accountable testing को बेहतर बनाने के बजाय उसे विफल करते हैं।

## Teardown checklist

- [ ] Exercise controller stop की पुष्टि करता है।
- [ ] C2, tunnels, redirectors, mail, VPN और scheduled jobs disable किए गए हैं।
- [ ] On-site devices physically recover करके reconcile किए गए हैं।
- [ ] Tokens, API keys, SSH keys, certificates और captured credentials revoke/rotate किए गए हैं।
- [ ] DNS और cloud resources हटा दिए गए हैं या defensive retention के लिए transfer किए गए हैं।
- [ ] Contract के अनुसार client data return, retain या destroy किया गया है।
- [ ] Required financial, audit और authorization records encrypted तथा access-controlled बने हुए हैं।
- [ ] Provider abuse cases close किए गए हैं और client को final source indicators प्राप्त हो गए हैं।
- [ ] दूसरा operator verify करता है कि कोई infrastructure active नहीं बचा है।

## References

- [1] [NIST CSRC — Engagement के नियम](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Information Security Testing और Assessment के लिए Technical Guide](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Penetration Testing के लिए Customer Support Policy](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Privacy Notice](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Registration Data Policy](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
