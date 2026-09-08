# Capture-Resilient Authorized Field Nodes

{{#include ../banners/hacktricks-training.md}}

एक on-site Raspberry Pi, mini-PC, travel router या cellular appliance authorized red team को एक टिकाऊ vantage point दे सकता है। यह discovery, theft और attribution का संभावित बिंदु भी है। इसलिए सही design objective **field node पर कम authority के साथ स्थिर, नियंत्रित access** है, न कि untraceable implant।

यह guide केवल उस equipment पर लागू होती है जिसे site owner की written authorization के साथ रखा गया हो। केवल इसलिए कि किसी coffee shop, neighbor, hotel या shared building का network reachable है, वह scope में नहीं आता। किसी असहमत venue में hardware न छिपाएं, captive portal को bypass न करें, किसी अन्य व्यक्ति के credentials का उपयोग न करें, monitoring में हस्तक्षेप न करें, या discovery के बाद evidence मिटाने का प्रयास न करें।

{% hint style="warning" %}
कोई भरोसेमंद “leave no traces” setting नहीं होती। Radio association, DHCP/NAT, carrier, camera, purchase, device, provider, controller और destination records device के बाद भी मौजूद रह सकते हैं। एक accountable red team इसके बजाय node से **personal और unrelated secrets** हटाती है, protected controller-side attribution बनाए रखती है, और capture को contain करना आसान बनाती है।
{% endhint %}

## फायदे और नुकसान

**फायदे:** realistic internal या target-adjacent source; स्थिर high-speed testing; NAC, egress, physical inventory और SOC coverage का validation; operator address changes के दौरान भी जारी रह सकता है; bounded access को centrally revoke किया जा सकता है।

**नुकसान:** physical placement मजबूत evidence बनाता है; loss से device credentials, network profiles और collected data उजागर हो सकते हैं; repeated control traffic detect किया जा सकता है; power, portals और radio changes reliability को प्रभावित करते हैं; broad tunnel uncontrolled pivot बन सकता है।

## Threat model और design invariants

मान लें कि finder storage हटा सकता है, firmware inspect कर सकता है, software-held हर secret की copy कर सकता है, बाद के network behavior को observe कर सकता है और device को client या law enforcement को सौंप सकता है। Full-disk encryption केवल powered-off device को उसके stated threat model के अंतर्गत सुरक्षित करती है; running unlocked node और memory में release की गई keys अलग मामले हैं।

| Invariant | Practical consequence |
|---|---|
| Operator-to-node की direct identity नहीं | Operator organization gateway में sign in करता है; node की अलग device identity होती है |
| Personal workstation material नहीं | Personal SSH key, browser profile, email, password manager, phone pairing या cloud CLI cache नहीं |
| Controller master secret नहीं | एक node किसी अन्य को enroll नहीं कर सकता, policy बदल नहीं सकता या अन्य engagements को decrypt नहीं कर सकता |
| Outbound-only और narrow | Field network कोई management listener स्वीकार नहीं करता; node केवल named rendezvous/update/time services तक पहुंचता है |
| Short-lived, scoped authority | प्रत्येक credential में एक device, audience, service, expiry और immediate revocation path होता है |
| Minimal local data | Results controller को stream किए जाते हैं; caches encrypted, size/TTL bounded और non-authoritative होते हैं |
| Controller accountability capture के बाद भी बनी रहती है | Asset-to-engagement mapping, approvals, operator access और commands centrally तथा access-controlled रूप में store किए जाते हैं |
| Loss से काम रुक जाता है | Discovery या unexplained state change से stop, revoke, notify और evidence preservation trigger होते हैं—remote destruction नहीं |

NIST का IoT baseline device identification, configuration, data protection, logical access, secure software update और cybersecurity-state awareness को core capabilities के रूप में समूहित करता है। यह विशेष रूप से state awareness और off-device event records को compromise investigation के समर्थन के रूप में देखता है।<sup>[[1]](#references)</sup>

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
gateway को यह जानना आवश्यक है कि किस named operator ने किस named device तक पहुंच बनाई। rendezvous के लिए field node को केवल device credential चाहिए। इसे operator का source address या authentication secret कभी पता नहीं चलता, और operator इसमें private management key कभी कॉपी नहीं करता। इससे exercise accountability को नष्ट किए बिना **field storage से** recover की जा सकने वाली व्यक्तिगत link कम होती है।

बड़े fleet के लिए, workload-identity system short-lived X.509 identities जारी कर सकता है और keys को अपने-आप rotate कर सकता है। SPIFFE जहां संभव हो वहां X.509 SVIDs की अनुशंसा करता है और बताता है कि short lifetimes तथा frequent rotation key-compromise exposure को सीमित करते हैं।<sup>[[2]](#references)</sup> छोटी team private CA और automated per-device certificates के साथ यही properties लागू कर सकती है; केवल इस pattern को पूरा करने के लिए SPIRE install करना आवश्यक नहीं है।

## Step 1: placement को authorize और register करें

1. Owner, site, exact allowed placement zone, allowed networks, assessment window, allowed destinations/actions और emergency contacts रिकॉर्ड करें।
2. Model, serial, storage serial, wired/wireless MACs, modem IMEI/eSIM या SIM ICCID, power supply और एक current photograph रिकॉर्ड करें।
3. Device को एक non-personal engagement identifier दें, उदाहरण के लिए `E2026-014-DROP03`। Broadcast hostnames या SSIDs में client name encode न करें।
4. Exercise controller और आवश्यकतानुसार सबसे छोटे physical-security/SOC deconfliction group को बताएं कि इस test के लिए “lost,” “moved” और “discovered” का क्या अर्थ है।
5. पहले से तय करें कि इसे कौन retrieve कर सकता है और finder इसकी report कैसे कर सकता है। Safety label में sensitive client detail छोड़ी जा सकती है, लेकिन controlled callback उपलब्ध होना चाहिए।
6. Automatic authorization expiry सेट करें। Scope समाप्त होने के बाद connectivity जारी रहना permission को extend नहीं करना चाहिए।

## Step 2: एक minimal recoverable image बनाएं

Supported OS image का उपयोग करें, vendor के documented channel के माध्यम से उसके signature/checksum को verify करें, security updates install करें और reproducible build manifest रखें। जहां software इसकी अनुमति देता हो, small writable data partition के साथ read-only या immutable base को प्राथमिकता दें।

1. Default accounts, demo services, compilers और authorized workload के लिए आवश्यक न होने वाले packages हटाएं।
2. Local GUI, Bluetooth, discovery protocols, file sharing, Wi-Fi P2P और inbound administration को disable करें, जब तक exercise में इनमें से किसी की स्पष्ट आवश्यकता न हो।
3. यदि hardware वास्तव में support करता हो तो secure boot और measured boot/TPM-backed key release enable करें; exact model को validate किए बिना यह दावा न करें कि Raspberry Pi configuration में PC-class measured boot है।
4. Local writable state को encrypt करें और strict maximum size तथा retention time configure करें। Encryption delay/containment control है, यह इस बात का proof नहीं है कि running node कुछ भी reveal नहीं करता।
5. Important logs को off-device भेजें। Storage exhaustion रोकने के लिए local journals की सीमा तय करें, लेकिन log wiping या anti-forensic deletion configure न करें।
6. Image manifest, package versions, configuration hash और recovery instructions controller पर store करें।
7. Manifest से एक spare को reimage करें और वही health test चलाएं। ऐसा design जिसे केवल उसका builder recover कर सके, field-ready नहीं है।

## Step 3: one-way trust के साथ identities जारी करें

तीन अलग identities बनाएं:

- एक **device identity**, जिसे केवल इस device के rendezvous द्वारा स्वीकार किया जाए;
- एक **operator identity**, जिसे organization gateway स्वीकार करे और जो phishing-resistant MFA से protected हो; और
- एक **controller/deployment identity**, जिसका उपयोग approved jobs या configuration sign करने के लिए हो और जिसे operator तथा field node दोनों से बाहर रखा जाए।

Node के पास signed jobs verify करने के लिए आवश्यक public key होनी चाहिए, signing key कभी नहीं। Captured device credential cloud consoles, source repositories, payment accounts, अन्य nodes या client production में authenticate नहीं कर सकना चाहिए।

जहां automatic renewal dependable हो, वहां short certificate lifetimes का उपयोग करें। जब long-lived WireGuard key operationally आवश्यक हो, तो उसकी public key को revocation handle मानें और उसे peer-specific tunnel address, firewall policy तथा broker authorization से constrain करें। ऐसा tested controller action रखें जो उस peer को तुरंत remove कर सके।

## Step 4: stable outbound rendezvous

निम्न owned-lab pattern inbound service expose किए बिना NAT के माध्यम से stable management प्रदान करता है। यह ordinary WireGuard networking है, covert reverse shell नहीं। Documentation addresses का उपयोग करें और उन्हें केवल organization-owned endpoints से replace करें।

Organization rendezvous पर `10.77.0.1/32` assign करें; field node को `10.77.0.20/32` assign करें। Gateway peer entry को केवल node के single address को accept करना चाहिए:
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
Node rendezvous की ओर outbound कनेक्शन बनाता है और NAT mapping को केवल आवश्यकता होने पर बनाए रखता है:
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
WireGuard कई NAT/firewall implementations में, जब persistence आवश्यक हो, 25 seconds को एक उचित keepalive interval के रूप में document करता है; जब इसकी आवश्यकता न हो, तो इसे disabled रखना बेहतर है।<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` जानबूझकर इसे management path बनाता है, default-route pivot नहीं।

फिर WireGuard के बाहर controls लागू करें:

1. Approved bootstrap DNS path के माध्यम से `vpn.redteam.example` को resolve करें और deployment records में अपेक्षित organization endpoint को pin करें।
2. Node पर outbound DHCP/RA, आवश्यक DNS/NTP, rendezvous endpoint और न्यूनतम approved update path की अनुमति दें। प्रत्येक uplink पर unsolicited inbound traffic को deny करें।
3. Rendezvous पर `10.77.0.20` को केवल exercise के लिए आवश्यक broker/health service तक पहुंचने दें। इसे सामान्य रूप से client network में forward न करें।
4. Interactive operator access को organization gateway के पीछे रखें। यदि signed pull-job interface assessment के लिए पर्याप्त है, तो tunnel के माध्यम से node से SSH expose करने से बचें।
5. Service manager को networking के बाद tunnel start करने, failure के बाद bounded backoff के साथ restart करने और repeated failure के बाद alert करने के लिए configure करें। Restart loop को venue पर अत्यधिक भार नहीं डालना चाहिए या underlying fault को छिपाना नहीं चाहिए।
6. Peer का latest handshake verify करें, लेकिन “handshake exists” को device के uncompromised होने का प्रमाण न मानें।

TURN purpose-built WebRTC control plane के लिए relay-only reachability प्रदान कर सकता है, और message queue intermittent service को सहन कर सकता है। TURN NAT के पीछे मौजूद client को स्पष्ट रूप से public relay address देता है; उसका server observer बना रहता है।<sup>[[4]](#references)</sup> बिना किसी स्पष्ट observer या reliability benefit के tunnels को stack करने के बजाय एक control architecture चुनें।

## Step 5: personal links के बिना uplink stability

Authorized venue node के लिए यह क्रम प्राथमिकता दें:

1. client-provided wired या dedicated test VLAN;
2. owner-approved enterprise/guest Wi-Fi profile;
3. organization-contracted cellular/private APN fallback।

इसे कभी भी personal phone hotspot, home SSID, personal eSIM, personal Apple/Google account या daily laptop से exported Wi-Fi profile से seed न करें। यही वे artifacts हैं जिनसे capture connect होगा।

प्रत्येक approved uplink के लिए:

- SSID/BSSID या switch/VLAN और अपेक्षित captive-portal behavior record करें;
- deterministic priority और owned endpoint के लिए health check निर्धारित करें;
- failover केवल underlay बदले; device और operator identities broker पर बनी रहें;
- सुनिश्चित करें कि transition के दौरान DNS, IPv6 और application traffic rendezvous को bypass न करें;
- unknown SSID/BSSID, SIM change, new default gateway, public-IP/ASN change या simultaneous uplinks पर alert करें;
- deployment से पहले power loss, DHCP renewal, AP restart, public-IP change, 24-hour idle, tunnel loss और primary-to-secondary-to-primary recovery का परीक्षण करें।

Private MAC addressing casual cross-network tracking को कम कर सकती है, लेकिन authorized NAC के लिए अक्सर per-network स्थिर MAC आवश्यक होता है। चुना गया OS वास्तव में क्या करता है, इसे record करें और owner के access control के आसपास rotate न करें।

## Step 6: work और data को सीमित करें

एक safe field node को mailbox से arbitrary shell text स्वीकार नहीं करना चाहिए। Signed job types जैसे `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` या rules of engagement में स्पष्ट रूप से नामित किसी अन्य action को define करें। Destination, duration, rate, output size और scope को node पर फिर से validate करें।

1. प्रत्येक job को unique ID, device audience, issue time, expiry, scope reference और maximum output दें।
2. इसे controller/deployment identity से sign करें।
3. Unknown fields, expired/replayed jobs और किसी अन्य device के लिए बने jobs को reject करें।
4. Results को owned collector पर stream करें; अपरिहार्य local spool को encrypt और TTL करें।
5. Controller पर accepted/rejected job ID और result hash log करें। Sensitive command parameters को public monitoring channel में न रखें।
6. Authorization expire होने, identity rotation fail होने या controller द्वारा device को quarantined mark करने पर processing रोक दें।

## Discovery, loss या compromise के लिए Monitoring

Monitoring controller को यह बता सकती है कि observed state बदल गई है। यह विश्वसनीय रूप से “investigators ने device खोज लिया” सिद्ध नहीं कर सकती, और responders की निगरानी करने या उनके systems को probe करने का प्रयास authorized assessment की सीमा से बाहर होगा।

### Off-device state collect करें

Controller को randomized लेकिन bounded operational interval पर signed, low-volume health record भेजें। केवल वही शामिल करें जिसकी controller को आवश्यकता है:

- device ID, boot ID/counter और monotonic uptime;
- configuration/image hash और software version;
- device-certificate serial और renewal state;
- uplink class, interface, BSSID या authorized switch context, default-gateway hash और owned service द्वारा observed public IP/ASN;
- tunnel handshake age, packet counters और queue depth;
- यदि owner ने sensor को approve किया हो तो enclosure switch या hardware-tamper state;
- disk pressure, temperature, clock-offset estimate और last successful job ID;
- replay या gaps उजागर करने के लिए sequence number और signature।

Gateway authentication, policy decisions, operator access, job submission, result hashes, provider audit events और alerts को centrally store करें। CISA logs को centralize करने, उन्हें deletion से सुरक्षित रखने, normal activity का baseline बनाने और incident-response contacts नामित करने की recommendation देता है।<sup>[[5]](#references)</sup>

### Discovery/compromise indicators

| Signal | Possible explanations | Controller action |
|---|---|---|
| Heartbeat absent | power/network failure, portal change, damage, deliberate blocking या removal | provider/site state से corroborate करें; unapproved path से reconnect न करें |
| Boot counter changed unexpectedly | power cut, crash, removal या maintenance | jobs quarantine करें; time और site events की तुलना करें |
| Config/image hash changed | update error, storage fault या tampering | work रोकें; यदि यह controller-approved release नहीं है तो revoke करें |
| New uplink/BSSID/gateway/ASN | AP replacement, roaming, moved device या interception | approved inventory से तुलना करें; unexplained transition को quarantine करें |
| Repeated rejected job/signature | corruption, replay या unauthorized controller | processing रोकें और gateway/controller logs की जांच करें |
| Device credential used twice or from incompatible paths | cloned key, snapshot reuse या network transition | तुरंत revoke करें; दोनों session records सुरक्षित रखें |
| Unexpected local login, interface, process or privilege event | maintenance या compromise | broker policy के माध्यम से isolate करें; evidence सुरक्षित रखें |
| Enclosure switch/state transition | service, movement या discovery | named site contact को notify करें; destructive action trigger न करें |
| Provider abuse notice/account query or SOC alert | detection, misconfiguration या out-of-scope traffic | activity रोकें और deconfliction/incident process लागू करें |
| Sentinel credential touched | किसी ने केवल इसी node के लिए unique no-privilege decoy secret पढ़ा | वास्तविक device identity revoke करें और alert trail सुरक्षित रखें |

Sentinel credential को **कोई access नहीं** देना चाहिए, केवल organization-owned alert service को call करना चाहिए और rules of engagement में disclose किया जाना चाहिए। यह unauthorized reading के लिए tripwire है, equipment खोजने वाले व्यक्ति को track करने के लिए beacon नहीं।

### Alert thresholds

एक नाटकीय “caught” alarm के बजाय stateful rules का उपयोग करें:

- **warning:** एक missed interval, normal address change या queue growth;
- **degraded:** तीन consecutive misses, renewal delay, primary-uplink loss या repeated restart;
- **quarantine:** unapproved hash/boot/uplink change, duplicate credential, sentinel use या unexpected privileged event;
- **confirmed discovery/loss:** site/controller report, physical inventory mismatch, unplanned party द्वारा device recovery या validated provider/SOC escalation।

Alert delivery का परीक्षण field node से independent channel के माध्यम से करें। Sensitive client/device detail को personal messaging या consumer push accounts पर भेजने से बचें।

## Suspected discovery or capture runbook

1. **Stop:** नए jobs और operator sessions suspend करें। “check if watched” probe न भेजें।
2. **Quarantine:** broker को device identity और उसके routes deny करने दें, जबकि existing logs सुरक्षित रहें।
3. **Revoke:** device certificate/key, queue token, update credential और प्रत्येक single-purpose service token revoke करें। यदि physical loss संभव हो तो organization SIM suspend करें।
4. **Preserve:** controller, gateway, provider और alert records का snapshot लें; trusted time, कार्रवाई करने वाले व्यक्ति और last known configuration record करें। Node को clear या remotely wipe न करें।
5. **Notify:** exercise controller, client incident contact और authorization में परिभाषित legal/privacy contacts से संपर्क करें। यदि किसी third party ने इसे पाया है, तो pre-agreed recovery process का उपयोग करें।
6. **Assess:** मानें कि node पर मौजूद प्रत्येक secret और cached result exposed है। ठीक-ठीक निर्धारित करें कि प्रत्येक secret किस access की अनुमति दे सकता था और suspicious event के बाद उसका उपयोग हुआ या नहीं।
7. **Contain downstream:** प्रभावित service credentials rotate करें, pending jobs invalidate करें और unexpected behavior के लिए owned target/provider logs inspect करें।
8. **Recover safely:** केवल authorized व्यक्ति के माध्यम से retrieve करें; इसकी photograph/package बनाएं, custody record करें और client के निर्देशानुसार forensic evidence acquire करें।
9. **Resume with a new identity:** captured credential को कभी silently re-enable न करें। Known manifest से rebuild करें, control failure ठीक करें और explicit approval प्राप्त करें।

NIST का current incident-response guidance preparation, detection, response और recovery को organization-wide cybersecurity risk management में integrate करता है; पहले preserve करें ताकि client यह निर्धारित कर सके कि क्या हुआ और उचित response चुन सके।<sup>[[6]](#references)</sup>

## Capture drill before deployment

एक unlocked test unit या उसके storage की copy किसी अलग reviewer को दें और उनसे यह enumerate करने को कहें:

1. device/site/engagement identifiers;
2. operator names, personal accounts, home/workstation networks और recovery contacts;
3. controller/broker destinations और credentials;
4. client network profiles और cached results;
5. प्रत्येक secret से reachable अन्य devices/projects;
6. value या payment credentials;
7. controller क्या revoke कर सकता है और कितनी जल्दी;
8. central logs से कौन-सी activity attributable बनी रहती है।

Pass criteria: zero personal accounts/workstation keys; zero cross-engagement या enrollment authority; no payment credential; bounded encrypted cache; one documented device-revocation action; complete controller-side accountability। किसी भी unexpected personal link या lateral capability को release blocker मानें।

## Closeout

1. Jobs रोकें और scope end पर broker route disable करें।
2. Exact inventory retrieve और reconcile करें; जो कुछ missing हो उसकी report करें।
3. Engagement retention plan के अनुसार logs/results और, यदि आवश्यक हो, forensic image सुरक्षित रखें।
4. Hardware recover हो जाने पर भी device, SIM, queue, update और service identities revoke करें।
5. Preservation/acceptance के बाद ही owner की approved data-disposal process से media sanitize या destroy करें और completion record करें। यह lifecycle management है, concealment नहीं।
6. Venue NAC/DHCP reservations, broker routes, DNS, cloud roles, alert rules और temporary contacts हटाएं।
7. Observed detection, missed telemetry, quarantine तक का समय और capture द्वारा exposed प्रत्येक artifact को document करें।

## References

- [1] [NIST — IoT Device Cybersecurity Capability Catalog](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Concepts and short-lived workload identities](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Use Logging on Business Systems](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
{{#include ../banners/hacktricks-training.md}}
