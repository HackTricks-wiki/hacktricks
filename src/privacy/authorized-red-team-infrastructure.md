# अधिकृत Red-Team Infrastructure

{{#include ../banners/hacktricks-training.md}}

टिकाऊ on-site devices के लिए [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) design और suspected-discovery runbook का उपयोग करें।

एक professional red team के लिए लक्ष्य **controlled attribution** है, accountability से मुक्ति नहीं। Target को operator का home IP या personal accounts आसानी से नहीं दिखने चाहिए, जबकि engagement owner source की पहचान करने, operation रोकने, abuse reports संभालने, evidence सुरक्षित रखने और authorization सिद्ध करने में सक्षम होना चाहिए।

यह पेज एक lawful engagement के लिए deployment baseline है। जिस adversary tradecraft का यह अनुकरण करने के लिए है—जिसमें compromised ORBs, residential relays, fronting, dead drops और nearby wireless pivots शामिल हैं—उसके लिए [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) और [Government and APT Case Studies](government-and-apt-case-studies.md) से शुरू करें, फिर आवश्यक telemetry को [authorized labs](authorized-adversary-emulation-labs.md) में पुनरुत्पादित करें।

NIST rules of engagement (ROE) को pre-established constraints के रूप में परिभाषित करता है, जो defined testing activities के लिए authority प्रदान करते हैं।<sup>[[1]](#references)</sup> Privacy architecture उस authority का विस्तार नहीं कर सकता।

## egress pattern चुनें

| Pattern | Best use | Target sees | Provider/local observer sees | Accountability |
|---|---|---|---|---|
| Client-provided VPN/jump host | अधिकांश assessments | Client address range | Client identity और operator access | सबसे मजबूत |
| Red-team organization bastion | दोहराने योग्य controlled egress | Organization range | Hosting provider और organization | मजबूत |
| Engagement-specific VPS | Clients/campaigns को अलग करना | VPS address | Host account, billing, control-plane और access logs | Documentation होने पर मजबूत |
| Approved commercial VPN | Provider और ROE द्वारा अनुमत research/scanning | Shared/dedicated VPN egress | VPN account और source connection | मध्यम |
| Tor Browser | Destination unlinkability की आवश्यकता वाले web research | Tor exit | Local network को Tor/bridge दिखता है; destination को Tor दिखता है | Allowlisted source attribution के लिए अनुपयुक्त |
| Client-approved on-site drop | Internal simulation | On-site device/address | Site network और remote tunnel provider | Inventory होने पर मजबूत |
| Lawful guest Wi-Fi | Low-risk administrative/research use | Venue public IP या tunnel egress | Venue, ISP, VPN/Tor | कमजोर और physical रूप से observable |

अधिकांश कार्यों के लिए consumer anonymity services की तुलना में client-provided या organization-controlled fixed egress अधिक सुरक्षित और तेज़ होता है। इससे defenders exercise design के अनुसार known source ranges को allowlist, monitor या जानबूझकर **allowlist न करने** में भी सक्षम होते हैं।

## ROE infrastructure annex

Deployment से पहले दर्ज करें:

- authorization देने और प्राप्त करने वाली legal entities;
- exact targets और explicit exclusions;
- start/end times, time zone और permitted techniques;
- source IPs, autonomous-system/provider names, domains, redirectors, mail infrastructure और on-site device identifiers;
- क्या phishing, C2, credential capture, wireless testing, physical access, denial-of-service, persistence या third-party services की अनुमति है;
- client और provider approvals, जिसमें कोई भी pre-notification reference शामिल है;
- emergency stop phrase, 24/7 client और provider abuse contacts, तथा maximum response time;
- एकत्र की जा सकने वाली data classes, encryption, access, retention और deletion;
- evidence और logging requirements, जिसमें यह भी शामिल है कि public infrastructure और operator के बीच mapping किसके पास होगी;
- teardown, domain expiration, certificate revocation, credential rotation, device recovery और final attestation।

सत्यापित करें कि public IPs और domains वास्तव में authorizing party के नियंत्रण में हैं या scope में स्पष्ट रूप से शामिल हैं। NIST SP 800-115 testing से पहले यह पुष्टि करने की सलाह देता है कि public target addresses organization के purview में हैं।<sup>[[2]](#references)</sup>

## Engagement-specific fast egress

### Build workflow

1. **Engagement account/project बनाएँ** और accurate billing तथा ownership details के साथ इसे red-team organization के अंतर्गत रखें। Roles, API keys, budgets और audit logs को अन्य clients से अलग रखें।
2. **हर provider policy जाँचें।** Cloud, VPS, CDN, domain, email और VPN providers के अलग-अलग rules होते हैं। उदाहरण के लिए, AWS निर्दिष्ट assessments की अनुमति देता है, लेकिन hosted C2/covert simulations के लिए prior approval आवश्यक है और सूचीबद्ध activities निषिद्ध हैं।<sup>[[3]](#references)</sup>
3. **Fixed egress addresses allocate करें** और उन्हें ROE annex में रखें। Rapid IP/resource cycling से बचें; इससे incident response जटिल होता है और provider policy का उल्लंघन हो सकता है।
4. **Management को harden करें:** key-only SSH या identity-aware management plane, phishing-resistant MFA, separate admin network, least privilege, patched images, कोई public admin ports नहीं और encrypted secret storage।
5. **Operator endpoint से bastion तक full-tunnel path बनाएँ।** DNS और IPv6 को जानबूझकर route करें और tunnel down होने पर firewall deny लागू करें।
6. **जब संभव हो, outbound destinations और ports को authorized scope तक सीमित करें।** Scanners पर rate-limit लागू करें और irreversible/destructive techniques को अलग approval gate के पीछे रखें।
7. **Accountability के लिए log करें, surveillance के लिए नहीं:** operator authentication, configuration changes, start/stop, source address, scoped destination और tool/job identifiers। जब तक exercise के लिए आवश्यक न हो और data plan द्वारा protected न हो, payload/credential capture से बचें।
8. **Organization के स्वामित्व वाले controlled endpoint के माध्यम से validate करें:** observed IPv4/IPv6, DNS path, reverse DNS, clock, source-port behavior, failure/reconnect और provider abuse contact।
9. **Attribution map को exercise controller या सहमत escrow contact के साथ securely share करें।** यदि blind detection test का हिस्सा है, तो इसे target team के साथ publish न करें।

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
एक VPS केवल destination के लिए pseudonymous होता है। Host के पास contact, billing, identity, source-IP, API, device, location और usage records हो सकते हैं; केवल customer-visible AWS CloudTrail history ही management activity उजागर कर सकती है।<sup>[[4]](#references)</sup> Hosting के लिए cryptocurrency से भुगतान करने पर भी ये records समाप्त नहीं होते।

## Domains और certificates

- Organization के स्वामित्व वाला engagement-specific registrar account उपयोग करें।
- Registrar lock, समर्थित होने पर DNSSEC, MFA/security keys, और केवल approved period के लिए auto-renew सक्षम करें।
- Public exposure कम करने के लिए registration privacy उपयोग करें, registrant information को गलत दर्शाने के लिए नहीं। ICANN policy के अनुसार registrars को registration data एकत्र करना आवश्यक है, भले ही public display redacted या proxied हो।<sup>[[5]](#references)</sup>
- ऐसे names से बचें जो गैर-संबंधित parties का unlawful impersonation करते हों। Typosquatting/lookalike domains के लिए client और provider की explicit approval आवश्यक है।
- DNS, certificates, CDN/redirector configuration और third-party analytics की inventory रखें, जो operators या clients को leak कर सकते हों।
- Teardown के समय records हटाएं, certificates/tokens revoke करें, agreed evidence सुरक्षित रखें, और तय करें कि domain को defensively retain करना है या नहीं।

## Authorized on-site drop nodes

Raspberry Pi या इसी प्रकार का appliance तभी स्वीकार्य है जब property/network owner और client उसके exact placement और behavior को explicitly authorize करें। एक safe plan:

1. Device serial, MAC/private-MAC policy, photo, owner, exact approved location, power source, retrieval deadline और tamper contact दर्ज करें।
2. Minimal signed image, encrypted secrets, read-only या recoverable storage, host firewall, जहां practical हो automatic security updates, और कोई default credentials न रखें।
3. किसी named engagement endpoint के लिए केवल outbound-only communication configure करें। Unauthenticated listener expose न करें।
4. Destinations और capabilities को allowlist करें। Packet capture, credential collection, wireless impersonation और lateral movement प्रत्येक के लिए explicit authorization आवश्यक है।
5. Mutual authentication, short-lived keys, remote kill, health reporting और bandwidth limits उपयोग करें।
6. सुनिश्चित करें कि loss/theft से reusable credentials या client data उजागर न हो।
7. Retrieval और secure wipe/decommission को calendar में निर्धारित करें; signed recovery record प्राप्त करें।

Owner/operator की written permission के बिना café, hotel, shared office, neighbor's property या public venue में hardware न छिपाएं।

## Guest networks और travel routers

यदि authorized scenario में guest access आवश्यक हो:

- Venue/client के साथ SSID और acceptable-use policy verify करें;
- Privileged workstation को isolate करने के लिए organization-owned travel router या low-trust bridge device उपयोग करें;
- Captive portals को privileged workstation के बाहर पूरा करें;
- Assessment traffic से पहले approved tunnel शुरू करें;
- Confirm करें कि tethered devices वास्तव में उसी tunnel का उपयोग कर रहे हैं;
- मानकर चलें कि venue radio association, portal, physical presence और camera/payment records को correlate कर सकता है;
- कभी भी access control bypass न करें, किसी अन्य device को clone न करें, Wi-Fi पर attack न करें, और equipment पीछे न छोड़ें।

## Operational separation

- प्रत्येक client/engagement के लिए अलग endpoint compartment, cloud project, secrets set, domain group, redirector set और evidence store रखें।
- Approved organization systems के बाहर personal email, browser sync, phone number, cloud drive, SSH/GPG key, code-signing identity या payment reimbursement का उपयोग न करें।
- Clients के बीच distinctive payload configuration, callback paths, certificates या public repositories reuse न करें, जब तक exercise design fingerprinting स्वीकार न करता हो।
- Infrastructure के लिए kill date और budget alert निर्धारित करें। Orphaned systems client और Internet दोनों के लिए risk बन जाते हैं।
- Accidents की जांच के लिए पर्याप्त internal attribution सुरक्षित रखें। “No logs” आमतौर पर professional evidence और safety obligations के साथ compatible नहीं होता।

## Defenders से blind, controller के लिए attributable

जब exercise objective detection को measure करना हो, न कि allowlist का test करना, तब operation को unaccountable बनाए बिना target SOC को blind रखा जा सकता है:

1. Exercise controller प्रत्येक public source, domain, certificate और on-site device को approve करता है, लेकिन उनकी list SOC से withheld रखता है।
2. Controller source-to-engagement/operator map को separate encrypted vault में two-person emergency access के साथ store करता है।
3. प्रत्येक operator job को scope, time window, source compartment और irreversible job identifier वाला signed manifest दिया जाता है। Normal operation के दौरान target को manifest देखने की आवश्यकता नहीं होती।
4. Bastion audit events को chained या append-only रूप में controller storage पर भेजा जाता है, ताकि incident के बाद operator attribution को चुपचाप rewrite न कर सके।
5. 24/7 provider-abuse contact के पास एक verification phrase/reference होती है, जो client को publicly disclose किए बिना authorization की पुष्टि करती है।
6. प्रत्येक path में एक out-of-band stop channel लागू करें, जो assessment C2, target network या किसी एक operator account पर निर्भर न हो।
7. Live testing से पहले प्रत्येक source से benign canaries भेजें। Confirm करें कि controller ROE response time के भीतर उन्हें resolve और stop कर सकता है।
8. Exercise के बाद SOC telemetry की controller ledger से तुलना करें, source list disclose करें, और missed/incorrect detections समझाएं।

Anti-forensics, log destruction, compromised relays या false subscriber identities न जोड़ें। ये accountable testing को बेहतर बनाने के बजाय उसे विफल करते हैं।

## Teardown checklist

- [ ] Exercise controller stop की पुष्टि करता है।
- [ ] C2, tunnels, redirectors, mail, VPN और scheduled jobs disable किए गए हैं।
- [ ] On-site devices physically recover और reconcile किए गए हैं।
- [ ] Tokens, API keys, SSH keys, certificates और captured credentials revoke/rotate किए गए हैं।
- [ ] DNS और cloud resources remove किए गए हैं या defensive retention के लिए transfer किए गए हैं।
- [ ] Contract के अनुसार client data return, retain या destroy किया गया है।
- [ ] Required financial, audit और authorization records encrypted और access-controlled बने हुए हैं।
- [ ] Provider abuse cases close किए गए हैं और client को final source indicators प्राप्त हो गए हैं।
- [ ] दूसरा operator verify करता है कि कोई infrastructure active नहीं बचा है।

## References

- [1] [NIST CSRC — Rules of Engagement](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Information Security Testing और Assessment के लिए Technical Guide](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Penetration Testing के लिए Customer Support Policy](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Privacy Notice](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Registration Data Policy](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
{{#include ../banners/hacktricks-training.md}}
