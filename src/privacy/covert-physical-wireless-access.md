# गुप्त भौतिक और Wireless Access

{{#include ../banners/hacktricks-training.md}}

Outbound rendezvous, power/uplink recovery, device पर रखे जाने वाले न्यूनतम secrets, capture testing और संभावित discovery की monitoring को शामिल करने वाले, owner-approved विस्तृत implementation के लिए [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) देखें।

Network path बदलने से दिखाई देने वाला भौतिक origin भी बदल सकता है। कोई sophisticated actor nearby compromised system, hidden device, public access, cellular backhaul या satellite receiver का उपयोग कर सकता है, जिससे target logs operator से दूर किसी स्थान की ओर संकेत करें। इनमें से कोई भी physical, radio या provider evidence को समाप्त नहीं करता; ये attribution को अलग-अलग datasets में स्थानांतरित कर देते हैं।

## Technique matrix

| Technique | दिखाई देने वाला origin | आवश्यक शर्त | उच्च-मूल्य evidence |
|---|---|---|---|
| Nearby wireless pivot | target के पास का business/home | compromised dual-homed host और target Wi-Fi access | neighbor-host endpoint logs, RF association और target RADIUS/DHCP |
| Public/guest network | venue NAT या tunnel exit | lawful access या access-control bypass | captive portal, DHCP, AP association, CCTV और payment/location records |
| Covert drop device | target/nearby wired, Wi-Fi या cellular address | physical placement या delivery | switchport/USB, RF, inventory, power और outbound tunnel telemetry |
| Cellular router/eSIM | carrier NAT या dedicated APN | modem/SIM/subscription | IMEI/IMSI/eSIM, cell-sector, carrier account और traffic timing |
| Satellite-link abuse | beam footprint में subscriber address | protocol- और service-specific weakness | RF location, uplink flow, impossible RTT/routing और provider records |

## Nearest-neighbor attack

Volexity ने 2022 के एक APT28/GRU operation का documentation किया, जिसमें actor अपने ultimate target से दूर था। उसने valid credentials प्राप्त करने के लिए target की public service पर password-spraying किया, लेकिन MFA ने direct Internet login को रोक दिया। Target का enterprise Wi-Fi उन credentials को MFA के बिना स्वीकार करता था। Actor ने target के भौतिक रूप से निकट organizations को compromise किया, wireless reach वाले dual-homed system को खोजा और उस system का उपयोग target Wi-Fi पर authenticate करने के लिए किया। Volexity ने इसे **Nearest Neighbor Attack** नाम दिया।<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
नवीनता इसका composition है। कोई operator target तक नहीं जाता और Internet-facing service का MFA अभी भी काम करता है। compromised neighbor physical proximity उपलब्ध कराता है; चुराया गया target credential logical access उपलब्ध कराता है; target Wi-Fi boundary-crossing path बन जाता है।

### Preconditions and visibility

- एक nearby system को remotely controllable होना चाहिए और उसमें compatible radio या किसी अन्य nearby pivot तक access होना चाहिए।
- target SSID उस system तक पहुंचना चाहिए, और Wi-Fi admission को reusable credential/certificate/device state स्वीकार करना चाहिए।
- pivot को अक्सर दो simultaneous paths की आवश्यकता होती है: एक operator तक वापस जाने के लिए और दूसरा target WLAN में जाने के लिए।
- target को नया station MAC और legitimate username दिखाई दे सकता है, लेकिन उससे संबंधित managed-device certificate, posture, history या expected building entry नहीं दिखाई देगी।
- Neighbor endpoint logs में wireless scans, new profiles, interface changes, tunneling और remote-control activity दिखाई दे सकती है।

### Detection and prevention

1. Enterprise Wi-Fi के लिए certificate-backed EAP-TLS और managed-device posture अनिवार्य करें; केवल इसलिए कि कोई password radio के माध्यम से पहुंचा है, Internet पर MFA में विफल हुआ password पर्याप्त न मानें।
2. RADIUS authentication को MDM/NAC identity, historical station/device binding, AP location, physical-access events और concurrent sessions के साथ correlate करें।
3. जब कोई account पहली बार associate करे, unusual AP edge से आए, managed certificate के बिना हो, या वही identity कहीं और active हो, तो alert करें।
4. Interfaces को bridge करने में सक्षम endpoints को monitor करें। Windows, Linux और network appliances पर unexpected WLAN profiles, forwarding/NAT configuration, virtual adapters और persistent tunnels की जांच करें।
5. उचित AP placement और power planning से अनावश्यक signal spill कम करें। यह supporting control है, authentication नहीं।
6. Incident response को neighboring tenants के साथ coordinate करें: अंतिम radio source स्वयं victim हो सकता है।

[owned two-organization lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) इन observables को किसी neighbor पर attack किए बिना reproduce करता है।

## Public venues and third-party Wi-Fi

Café, hotel, airport या municipal Wi-Fi का उपयोग करने से destination को दिखाई देने वाला IP बदल जाता है। इससे anonymity नहीं बनती। Venue या उसका provider AP association, device MAC, DHCP lease, captive-portal account, SMS/email validation और flow logs retain कर सकता है। Physical entry, CCTV, purchase, mobile-location और travel records digital event को किसी व्यक्ति से जोड़ सकते हैं।

कोई actor randomized MAC addresses, separate device, cash या tunnel का उपयोग करके एक handle को कम करने का प्रयास कर सकता है। Arrival time, repeated venue pattern, radio fingerprints, portal behavior, traffic timing, camera footage और tunnel provider के माध्यम से cross-layer correlation अभी भी संभव है। VPN destination को venue logs से VPN logs में स्थानांतरित करता है; यह venue की इस जानकारी को समाप्त नहीं करता कि device वहां मौजूद था।

Public access के defenders को clients को isolate करना चाहिए, lateral traffic block करना चाहिए, जहां संभव हो WPA2/3-Enterprise या per-device keys का उपयोग करना चाहिए, proportionate DHCP/RADIUS/security logs retain करने चाहिए, captive portals को सुरक्षित रखना चाहिए और abuse process प्रकाशित करना चाहिए। Red teams को ऐसे venue का उपयोग केवल तब करना चाहिए जब उसके terms और engagement इसकी अनुमति दें; portal को bypass करना, access चुराना या अन्य guests को target करना authorized testing shortcut नहीं है।

## Covert drop devices and warshipping

एक drop एक छोटा system होता है जिसे site में रखा या वहां deliver किया जाता है, फिर outbound Ethernet, Wi-Fi या cellular के माध्यम से control किया जाता है। “Warshipping” device को इस तरह package करता है कि सामान्य delivery उसे radio perimeter के अंदर पहुंचा दे। Possible hardware एक single-board computer से लेकर modified charger, USB peripheral, network appliance या battery-powered modem तक हो सकता है।

Operational architecture:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
डिवाइस remote foothold प्रदान कर सकता है, wireless measurements कर सकता है, किसी authorized exercise peripheral का emulation कर सकता है या traffic relay कर सकता है। इसका दिखाई देने वाला source local होता है, लेकिन यह physical artifacts बनाता है: serial numbers, packaging, fingerprints, cameras, access logs, power draw, USB descriptors, switchport negotiation, DHCP fingerprints, MAC OUI/randomization behavior, RF emissions और recurring rendezvous connections।

### Defensive controls

- receiving-room और asset-inventory procedures बनाए रखें; unexpected electronics और nonexistent staff को address किए गए packages की जांच करें।
- wired और wireless access पर 802.1X/NAC का उपयोग करें, unused ports को disable करें और unknown devices को restricted remediation VLAN में रखें।
- नए DHCP fingerprints, लगातार बने रहने वाले locally administered MACs, नए USB network/HID devices, unauthorized Wi-Fi Direct/Bluetooth और लंबे समय तक चलने वाले outbound tunnels पर alert करें।
- switchport, power-over-Ethernet, DNS और TLS behavior का baseline बनाएं। बिना inventory record वाला कोई छोटा host, जो समय-समय पर encrypted connections बना रहा हो, केवल “Raspberry Pi OUI” की तुलना में अधिक उच्च-सिग्नल संकेत है।
- किसी exercise के दौरान inventory बनाएं, label लगाएं, scope निर्धारित करें, encrypt करें, remote kill उपलब्ध कराएं, retrieval deadline तय करें और सुनिश्चित करें कि device खोने पर reusable credentials उजागर न हो सकें।

## Cellular और eSIM backhaul

Cellular modem target के Internet gateway से बचता है और outbound rendezvous के माध्यम से carrier NAT के पीछे मौजूद drop को reachable बनाए रख सकता है। Mobile addresses rotate या share हो सकते हैं; फिर भी cellular operator के पास मजबूत subscriber और network evidence होता है: SIM/eSIM identity, IMSI, device IMEI, assigned addresses/ports, cell/sector timing, account/payment और roaming records।

Enterprise के दृष्टिकोण से, wireless/RF surveys, endpoint USB/PCI inventory, MDM restrictions, rogue-SSID monitoring और physical inspection के माध्यम से unexpected modems और personal hotspots का पता लगाएं। Cellular का उपयोग control के लिए करने वाला drop भी अपने local Ethernet/Wi-Fi behavior और radio emissions के कारण पकड़ा जा सकता है।

Authorized exercises के लिए, organization को subscription और modem का स्वामी होना चाहिए, identifiers को controller के साथ record करना चाहिए और सत्यापित करना चाहिए कि carrier/provider terms उस traffic की अनुमति देते हैं। Prepaid label या cryptocurrency purchase tower, device या retail records को समाप्त नहीं करती।

## MAC randomization और device fingerprinting

Modern systems प्रत्येक network के लिए locally administered random MAC का उपयोग कर सकते हैं। इससे stable factory MAC द्वारा होने वाली passive long-term tracking कम होती है; लेकिन यह निम्नलिखित को नहीं छिपाता:

- probe/association timing और requested network capabilities का set;
- 802.11 information elements, supported rates और vendor-specific behavior;
- DHCP options/hostname, IPv6 identifiers और captive-portal/browser fingerprint;
- authenticated 802.1X identity या certificate;
- higher-layer account, tunnel और traffic pattern; या
- physical observation।

Defenders को MAC allowlists का उपयोग authentication के रूप में नहीं करना चाहिए। Radio identity को certificate/device posture से जोड़ें और changing MACs को सामान्य मानें, जब तक अन्य context anomalous न हो।

## Satellite-link hijacking

Kaspersky ने पुराने one-way DVB-S satellite Internet में weaknesses का उपयोग करते हुए Turla को document किया। Reported model में, legitimate remote subscriber ने terrestrial link के माध्यम से outbound requests भेजीं, लेकिन downstream data एक unencrypted wide-area satellite broadcast के जरिए प्राप्त किया। Satellite footprint के अंदर मौजूद actor downlink को observe कर सकता था, किसी active subscriber IP को चुन सकता था और C2 replies को उस IP पर address किए जाने की व्यवस्था कर सकता था। Legitimate subscriber और actor दोनों को broadcast प्राप्त होता था; actor ने selected port के लिए traffic extract किया, जबकि legitimate subscriber ने unsolicited packets को discard कर दिया। इसके बाद C2 operator ऐसा दिखाई देता था मानो वह किसी अन्य geography में मौजूद satellite-provider address का उपयोग कर रहा हो।<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
यह protocol/service-specific, bandwidth-constrained था और modern bidirectional encrypted satellite terminal को compromise करने के बराबर नहीं था। इसने पर्याप्त सक्षम observer से actor के outbound request path को भी छिपाया नहीं। Detection opportunities में asymmetric/impossible routing, ऐसे subscriber को traffic भेजना जिसने flow शुरू नहीं किया था, unusual destination ports, provider telemetry, receiver location/RF investigation और malware configuration शामिल हैं। इस case का उपयोग इस assumption को चुनौती देने के लिए करें कि किसी C2 IP को geolocate करने से उसके controller की geolocation हो जाती है—इसे build recipe के रूप में उपयोग न करें।

## Physical-to-digital correlation worksheet

जब कोई apparently local source संदिग्ध हो, तो एक timeline बनाएं:

1. AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switch और physical-access clocks को normalize करें;
2. केवल first alert नहीं, बल्कि first radio association या link-up की पहचान करें;
3. station को certificate, device posture, DHCP fingerprint और switch/AP location से map करें;
4. nearby systems पर simultaneous remote-control/tunnel activity देखें;
5. applicable policy/law के तहत deliveries, visitors, inventory exceptions, cameras और RF findings की समीक्षा करें;
6. suspected device और volatile network state को preserve करें; बिना सोचे power-cycle न करें;
7. निर्धारित करें कि apparent source actor-controlled infrastructure है या कोई अन्य victim।

## References

- [1] [Volexity — The Nearest Neighbor Attack: How a Russian APT ने nearby Wi-Fi networks को covert access के लिए weaponize किया](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: sky में APT command and control](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Hardware Additions (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Wireless Local Area Networks को secure करने के guidelines](https://csrc.nist.gov/pubs/sp/800/153/final)
{{#include ../banners/hacktricks-training.md}}
