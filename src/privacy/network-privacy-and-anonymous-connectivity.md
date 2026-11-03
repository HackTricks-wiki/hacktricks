# Network Privacy & Anonymous Connectivity

{{#include ../banners/hacktricks-training.md}}

नेटवर्क गोपनीयता routing का निर्णय है, पूर्ण पहचान-छिपाव नहीं। रास्ता चुनते समय पूछें कि किससे **source**, **destination**, **content**, और **timing** छिपे होने चाहिए।

हर access-path family के लिए मानकीकृत सूची—`Pros`, `Cons`, चरण-दर-चरण `Procedure`, और `Detection`—के लिए [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) से शुरू करें। यह पेज आम तौर पर इस्तेमाल किए जा सकने वाले विकल्पों का विस्तार करता है।

## हर observer आम तौर पर क्या देख सकता है

| Path | Local network / ISP | Intermediary | Destination | मुख्य सीमा | सापेक्ष गति |
|---|---|---|---|---|---|
| Direct HTTPS | Source, destination metadata, timing/volume | Hosting/CDN को connection दिखता है | Source IP, browser/app data | Source-IP गोपनीयता नहीं | सबसे तेज़ |
| Commercial VPN | Source VPN से जुड़ा हुआ; आम तौर पर destination metadata नहीं | VPN को source और destination metadata दिखता है | VPN egress IP | एक provider correlation point बन जाता है | आम तौर पर तेज़ |
| Self-hosted VPN/VPS | Source VPS से जुड़ा हुआ | Host/account/payment/control-plane logs | VPS egress IP | किराए के server/account से जोड़ना आसान | आम तौर पर तेज़ |
| Tor Browser | Source Tor/bridge से जुड़ा हुआ; timing/volume | हर relay को सीमित हिस्सा दिखता है | Tor exit, browser data | धीमा; account/endpoint/correlation जोखिम | मध्यम/धीमा |
| Tails/Whonix | मिलता-जुलता Tor path, अधिक मज़बूत routing boundaries के साथ | Tor की वही सीमाएँ | Tor exit/application data | परिचालन संबंधी गलतियाँ और host/hardware फिर भी जोखिम बने रहते हैं | मध्यम/धीमा |
| Public guest Wi-Fi + HTTPS | Venue को local device/timing और destinations दिखते हैं | Venue ISP को metadata दिखता है | Guest public IP | भौतिक मौजूदगी/captive-portal/device correlation | तेज़/बदलती हुई |
| Cellular hotspot | Carrier को subscriber/device/location और destinations दिखते हैं | इस्तेमाल होने पर VPN/Tor | Carrier, VPN, या Tor egress IP | Mobile subscription और location स्थायी पहचानकर्ता हैं | तेज़/बदलती हुई |
| Mixnet | Access को mixnet का उपयोग और timing/volume दिखते हैं | कई mixing nodes | Gateway/egress | उभरता हुआ ecosystem; latency और bandwidth की लागत | सबसे धीमा |

HTTPS transit में content की रक्षा करता है, लेकिन सभी metadata की नहीं। EFF के अनुसार, page paths, credentials, और messages एन्क्रिप्टेड होने पर भी domain, time, और traffic size intermediaries को दिख सकते हैं।<sup>[[1]](#references)</sup>

Encrypted overlay अपने-आप anonymity network नहीं होता: Yggdrasil के direct peers एक-दूसरे के IP addresses देख सकते हैं।<sup>[[20]](#references)</sup> इसका [userspace forwarding और SOCKS transport](../generic-hacking/tunneling-and-port-forwarding.md#yggdrasil-userspace-overlay-with-yggstack) tunneling का विकल्प है, source-anonymity layer नहीं।<sup>[[20]](#references)[[21]](#references)</sup>

## VPNs: केंद्रित भरोसे के साथ तेज़ privacy

VPN, access ISP से destination metadata छिपाने, अविश्वसनीय network पर पहले hop की सुरक्षा करने, engagement के लिए स्थिर egress address देने, या private network तक पहुँचने में उपयोगी है। यह उपयोगकर्ता को anonymous **नहीं** बनाता। VPN source connection देखता है और destination metadata देख सकता है; accounts, cookies, GPS, fingerprints, और payment information फिर भी मौजूद रहते हैं।<sup>[[1]](#references)</sup>

### Provider की जाँच-सूची

1. **Ownership और jurisdiction:** कानूनी entity, parent company, संचालन वाले देश, infrastructure subcontractors, और लागू कानूनी प्रक्रिया की पहचान करें।
2. **एकत्र किया गया data:** account/billing, source IP, connection timestamps, bandwidth, crash telemetry, DNS queries, और destination logs में अंतर करें। “No browsing logs” का मतलब “कोई data नहीं” नहीं है।
3. **Retention और deletion:** सटीक अवधि पता करें और जाँचें कि backups, fraud systems, और processors भी उसी अवधि का पालन करते हैं या नहीं।
4. **Evidence:** ऐसे सार्वजनिक audits को प्राथमिकता दें जिनका scope, date, findings, और remediation उपलब्ध हों; साथ ही reproducible/open clients, transparency reports, और दर्ज incidents देखें।
5. **Protocol और client:** maintained WireGuard, OpenVPN, या कोई अन्य reviewed protocol; automatic updates; DNS और IPv6 handling; kill switch; और हर platform पर leak tests।
6. **Business model:** समझें कि free या subsidized service को पैसा कहाँ से मिलता है। App-store में मौजूद होना भरोसेमंद संचालन का प्रमाण नहीं है।
7. **Payment की उपयुक्तता:** वैकल्पिक payment से VPN को billing जानकारी कम मिल सकती है, लेकिन हर connection पर देखा जाने वाला source IP मिटता नहीं है।

### VPN को configure और verify करें

1. Provider/organization का signed client उसके आधिकारिक स्रोत से install करें।
2. **Full tunnel** चुनें, जब तक किसी documented route को tunnel से बाहर रखना ज़रूरी न हो। Split tunneling से correlation और leak के रास्ते बनते हैं।
3. Fail-closed/always-on व्यवहार चालू करें और reconnect के दौरान traffic block करें।
4. DNS को tunnel से भेजें और IPv4 तथा IPv6 दोनों जाँचें। किसी protocol को तभी disable करें जब उसे सुरक्षित रूप से tunnel न किया जा सके और उसकी functionality खोना स्वीकार्य हो।
5. Sleep/wake, network switching, captive-portal login, tunnel crash, और hotspot tethering जाँचें। NCSC चेतावनी देता है कि कुछ platforms पर tethered clients, phone के VPN को bypass कर सकते हैं।<sup>[[2]](#references)</sup>
6. देखे गए IPv4, IPv6, DNS resolver, और connection timing दर्ज करने के लिए organization-controlled test endpoint इस्तेमाल करें। किसी संवेदनशील engagement को अनजान “leak test” sites के सामने उजागर न करें।
7. Client, OS, network, या policy में बदलाव के बाद फिर से जाँचें।

### Hostile-LAN routing bypasses

VPN “connected” दिखता रह सकता है, जबकि चुने हुए packets उसे bypass कर सकते हैं, क्योंकि operating system packet को VPN द्वारा encrypt किए जाने **से पहले** route चुनता है। TunnelCrack ने आम routing exceptions के दुरुपयोग के दो तरीके दिखाए: **LocalNet** Internet destination को सीधे जुड़े subnet का हिस्सा दिखाता है, जबकि **ServerIP** VPN-gateway resolution को spoof करता है, ताकि target address को VPN transport के लिए ज़रूरी clear-network exception मिल जाए। ये client/routing की विफलताएँ हैं, WireGuard, OpenVPN, IPsec, या TLS को तोड़ना नहीं; HTTPS payload end-to-end encrypted रहते हैं, लेकिन local observer destination/timing metadata और cleartext protocol data हासिल कर सकता है।<sup>[[18]](#references)</sup>

TunnelVision, DHCP option 121 के ज़रिए इसी pre-encryption primitive का इस्तेमाल करता है। Malicious या compromised DHCP server ऐसा classless route install कर सकता है जो VPN के catch-all route से अधिक specific हो और किसी भी host या range के लिए physical interface चुन सके। VPN control channel चालू रह सकता है, इसलिए केवल tunnel disconnect होने पर सक्रिय होने वाला kill switch शायद चालू न हो; साथ ही, एक अकेली सार्वजनिक “IP leak” जाँच चुनिंदा bypasses को पकड़ने में विफल हो सकती है।<sup>[[19]](#references)</sup>

ऐसा packet-filter kill switch जो physical interface पर केवल DHCP और authenticated VPN transport की अनुमति देता है, इसे fail-closed व्यवहार में बदलना चाहिए। फिर भी, लक्षित route injection से selective-denial side channel बन सकता है। अधिक गंभीर परिणामों वाले Linux workloads के लिए, अधिक मज़बूत [route-enforced network-namespace pattern](advanced-network-privacy-architectures.md#enforce-the-route-per-workload) को प्राथमिकता दें, जहाँ application namespace में न तो physical interface हो और न ही clear-network default route।<sup>[[19]](#references)</sup>

#### Owned-lab verification

ठीक उसी client/OS/version को अपने AP, DHCP server, VPN endpoint, और destination पर जाँचें; product-wide दावे जल्दी पुराने हो जाते हैं, क्योंकि routing और packet-filter implementations platform के अनुसार अलग होते हैं। Endpoint पर और test server पर, दोनों जगह capture करें—केवल egress-IP website से यह साबित नहीं होता कि हर destination tunnel से होकर जाता है।<sup>[[18]](#references)[[19]](#references)</sup>

1. VPN से connect करें, VPN-server address दर्ज करें, और IPv4/IPv6 की हर routing table तथा policy-routing rule सहेजें। Windows पर `route print`, macOS पर `netstat -rn`, और Linux पर नीचे दिए गए commands इस्तेमाल करें।
2. अपने कई destination IPs के लिए चुना गया route जाँचें। Documented VPN transport endpoint को छोड़कर, next hop/interface tunnel होना चाहिए।
3. TunnelVision जाँचने के लिए, controlled DHCP network पर lease renew करें और option 121 route **केवल अपने test destination के लिए** install करें। Pass का मतलब है कि traffic tunnel से जाता रहे या block हो—वह physical interface पर destination traffic के रूप में कभी न निकले।
4. LocalNet जाँचने के लिए, client को lab-only public documentation subnet जैसे `203.0.113.0/24` का address दें और अपने test destination को उसी में रखें। Verify करें कि LAN access चालू करने से Internet-class destinations tunnel bypass न करें।
5. ServerIP जाँचने के लिए, VPN connection से पहले controlled DNS से अपने VPN hostname को अपने test destination पर resolve कराएँ, जबकि lab gateway VPN transport को असली owned VPN endpoint तक forward करे। Client को spoofed address पर unrelated application traffic की छूट नहीं देनी चाहिए।
6. “local network access” को चालू और बंद—दोनों स्थितियों में, reconnect, sleep/wake, network switching, और VPN-process crash के बाद फिर से जाँचें। IPv4, IPv6, और DNS को अलग-अलग test करें।
7. Physical-interface capture की जाँच करें। उसमें DHCP और VPN server को भेजे गए encrypted packets होने चाहिए, न कि सीधे अपने test destination को भेजे गए packets। यह भी पुष्टि करें कि अस्वीकृत bypass, user prompts या connectivity repair के बाद चुपचाप fallback न कर सके।

```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```

## Tor Browser: अधिक मजबूत web unlinkability

Tor कई relays के ज़रिए एक circuit बनाता है, ताकि सामान्यतः किसी एक relay को source और destination दोनों का पता न हो। Destination को user के IP के बजाय Tor exit दिखाई देता है; स्थानीय नेटवर्क को सामान्यतः Tor connection दिखाई देता है।<sup>[[3]](#references)</sup> Tor को low-latency TCP applications के लिए डिज़ाइन किया गया है, इसलिए यह धीमा है और ऐसे adversary के विरुद्ध सुरक्षा की गारंटी नहीं दे सकता जो दोनों सिरों पर traffic correlate कर सके।<sup>[[4]](#references)</sup>

### Tor Browser का सुरक्षित workflow

1. Tor Browser केवल Tor Project या किसी आधिकारिक mirror से डाउनलोड करें और संभव हो तो signature verify करें।
2. Tor SOCKS port की ओर निर्देशित सामान्य browser के बजाय **Tor Browser** इस्तेमाल करें। सामान्य browsers से DNS/WebRTC और पहचान बताने वाली state leak हो सकती है।<sup>[[5]](#references)</sup>
3. डिफ़ॉल्ट size, fonts, extensions और privacy settings बनाए रखें। अतिरिक्त add-ons browser को अधिक विशिष्ट बना सकते हैं।<sup>[[6]](#references)</sup>
4. जब बढ़ी हुई breakage स्वीकार्य हो, तो **Safer** या **Safest** security level चुनें।
5. जब direct Tor blocked हो या सामान्य relay IPs से स्थानीय स्तर पर अस्वीकार्य visibility बनती हो, तो bridge इस्तेमाल करें। Bridges से आसानी से पहचानना मुश्किल होता है; वे traffic analysis को खत्म नहीं करते।<sup>[[7]](#references)</sup>
6. पहचान बताने वाले account में log in न करें, पहचान बताने वाली जानकारी न दें, और डाउनलोड किए गए active documents को किसी बाहरी networked application में न खोलें।
7. हर identity के लिए अलग session/context इस्तेमाल करें। “New circuit” का अर्थ browser/application identity मिटाना नहीं है; ज़रूरत के अनुसार **New Identity** इस्तेमाल करें या isolated environment restart करें।
8. Authenticated HTTPS या authenticated onion service को प्राथमिकता दें। Tor exit unencrypted HTTP traffic देख सकता है।

### Tor और VPN साथ में

इन्हें साथ इस्तेमाल करना अपने आप अधिक सुरक्षित नहीं बनाता। Tor से पहले VPN लगाने पर ISP से direct Tor relay connections छिप सकती हैं, जबकि VPN को source दिखता है; VPN से पहले Tor लगाने पर VPN को Tor के बाद की activity का स्थिर दृश्य मिलता है और anonymity set छोटा हो सकता है। गलत configuration से leaks हो सकते हैं। Tor Project ऐसे संयोजनों की सिफारिश केवल उन्नत, स्पष्ट threat models के लिए करता है।<sup>[[8]](#references)</sup>

## सार्वजनिक और guest Wi-Fi

आधुनिक HTTPS का अर्थ है कि निष्क्रिय पड़ोसी आमतौर पर ठीक से encrypted web content नहीं पढ़ सकते, लेकिन guest Wi-Fi anonymity नहीं है। स्थल association times, device identifiers, captive-portal data, destinations और DHCP details रिकॉर्ड कर सकता है; कैमरे, खरीदारी, परिवहन और प्रत्यक्ष निगरानी user की पहचान कर सकते हैं। इसी तरह के नाम वाला नकली hotspot portal credentials भी हासिल कर सकता है या unencrypted traffic में हेरफेर कर सकता है।<sup>[[9]](#references)</sup>

### Guest network का वैध workflow

1. केवल वही network इस्तेमाल करें जो guests के लिए उपलब्ध कराया गया हो या जिसके लिए owner ने स्पष्ट अनुमति दी हो। कर्मचारियों से सटीक SSID और portal प्रक्रिया पूछें।
2. पहुँचने से पहले endpoint और travel router update करें। File/printer sharing, inbound discovery, auto-join और याद रखे गए network की probing बंद करें।
3. OS का private/randomized Wi-Fi address चालू करें। मौजूदा Apple systems खुले/कमज़ोर networks पर rotating addresses इस्तेमाल कर सकते हैं; आधुनिक Android में randomization आमतौर पर प्रति SSID स्थायी होती है। इससे केवल एक स्थानीय identifier कम होता है।<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Privileged workstation और guest network के बीच organization-controlled travel router या low-trust bridge device को प्राथमिकता दें। इससे firewall/VPN policy एक जगह लागू होती है, लेकिन स्थल से router नहीं छिपता।<sup>[[12]](#references)</sup>
5. Captive portal केवल निर्धारित low-trust device/browser से पूरा करें। कथित anonymous context के लिए personal या दोबारा इस्तेमाल किए गए credentials कभी न डालें। Connection स्थापित होने के बाद portal browser बंद कर दें।
6. संवेदनशील activity से पहले full-tunnel VPN या Tor शुरू करें और fail-closed behavior की पुष्टि करें।
7. इस्तेमाल के बाद network को भूल जाएँ और portal की account/data-retention policy देखें।

{% hint style="danger" %}
पड़ोसी का Wi-Fi crack करना, portal bypass करना, leaked guest credentials इस्तेमाल करना, किसी अन्य guest का access clone करना या कैफ़े में Raspberry Pi छिपाना अनधिकृत गतिविधि है—privacy technique नहीं। सुरक्षित विकल्प हैं: वैध guest network, client-अनुमोदित site, या property owner की लिखित सहमति से लगाई और वापस ली गई documented drop node।
{% endhint %}

## Travel routers

Travel router workstation को शत्रुतापूर्ण स्थानीय broadcasts से अलग कर सकता है, firewall लागू कर सकता है, एक स्थिर आंतरिक SSID दे सकता है और VPN से अपने आप दोबारा connect हो सकता है। यह **anonymous** नहीं है: upstream को इसकी radio identity और traffic timing दिखते हैं, और इसके VPN provider को tunnel source दिखता है।

- समर्थित OpenWrt/vendor firmware इस्तेमाल करें और अनुपयोगी services हटाएँ।
- Ethernet या अलग management SSID पर अद्वितीय password के साथ administration करें।
- WAN-side administration, UPnP, WPS, file sharing और अनचाहे inbound traffic को बंद करें।
- Randomized/private WAN MAC का इस्तेमाल केवल वहीं करें जहाँ यह समर्थित और अनुमत हो।
- Router पर DNS और IPv6 समेत VPN policy लागू करें, और tunnel विफल होने पर egress block करें।
- यह न मानें कि phone hotspot, tethered devices को phone के VPN से tunnel करता है; इसकी जाँच करें।

## Cellular, SIMs और eSIMs

Cellular सुविधाजनक है, लेकिन anonymous नहीं। Operators subscriber/device identifiers और network से जुड़ने के आधार पर स्थान की जानकारी रखते हैं; eSIM भी mobile subscription ही है। Prepaid का अर्थ हमेशा unregistered नहीं होता—आवश्यकताएँ देश के अनुसार अलग होती हैं और बदलती रहती हैं।<sup>[[13]](#references)</sup>

व्यावहारिक तौर पर:

- Personal data का exposure कम करने के लिए अलग, समर्थित device इस्तेमाल करें; काल्पनिक subscriber बनाने के लिए नहीं।
- अगर threat model में साथ-साथ मौजूद होना शामिल है, तो “अलग” device को personal phone के साथ लगातार न रखें।
- अनुपयोगी cellular, Wi-Fi, Bluetooth और location access बंद करें; radio boundary बनाने के लिए power off करना UI toggles से अधिक प्रभावी है।
- संवेदनशील traffic को स्वीकृत VPN/Tor path के भीतर रखें, लेकिन यह ध्यान रखें कि carrier को subscription/device का स्थान और tunnel endpoint फिर भी पता रहता है।
- मौजूदा registration और retention नियम national regulator या स्थानीय वकील से जाँचें; “anonymous SIM countries” की online सूचियों पर भरोसा न करें।

## DNS और TLS metadata

- **DoH/DoT/DoQ** client और resolver के बीच DNS को encrypt करते हैं, जिससे स्थानीय स्तर पर उसे आसानी से पढ़ना या बदलना संभव नहीं रहता; लेकिन resolver को queries और transport identifiers दिखते हैं। इससे trust का स्थान बदलता है; anonymity नहीं मिलती।<sup>[[14]](#references)</sup>
- **ODoH** एक proxy जोड़ता है, ताकि resolver को client IP जानने की ज़रूरत न पड़े—यह मानते हुए कि proxy और target मिलीभगत न करें। Traffic analysis स्पष्ट रूप से इसके दायरे से बाहर है।<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** TLS handshake में भीतरी server name की सुरक्षा कर सकता है, बशर्ते client, DNS और server इसका समर्थन करें। Destination IP, timing, volume और endpoint फिर भी दिखाई देते हैं।<sup>[[16]](#references)</sup>
- ठीक से configure किए गए VPN या Tor environment में DNS को उसी environment के समर्थित route से जाना चाहिए। अलग resolver जोड़ने से नया observer या fingerprint बन सकता है।

### Encrypted-DNS/ECH सत्यापन workflow

1. तय करें कि DNS को VPN/Tor environment, OS या application में से कौन नियंत्रित करेगा। असंबंधित resolvers की परतें लगाने के बजाय इसे **एक** इच्छित layer में configure करें।
2. प्रकाशित privacy/retention policy के आधार पर resolver चुनें और platform द्वारा समर्थित होने पर strict encrypted mode चालू करें। Opportunistic fallback चुपचाप plaintext पर लौट सकता है।
3. अपने नियंत्रण वाले authoritative test zone के अंतर्गत एक unique subdomain query करें; पुष्टि करें कि authoritative log में इच्छित recursive resolver दिखाई दे रहा है।
4. अनुमति के साथ केवल test device का traffic capture करें। पुष्टि करें कि access network plaintext DNS नहीं पढ़ सकता, लेकिन यह ध्यान रखें कि उसे encrypted resolver/tunnel endpoint दिखाई देता है।
5. किसी blocked/unreachable encrypted resolver की जाँच करें। सफल परिणाम चुना हुआ fail-closed या documented fallback behavior है—अनजाने में clear query होना नहीं।
6. ECH के लिए नियंत्रित ECH-enabled host इस्तेमाल करें और client/server diagnostics देखें, ताकि पुष्टि हो कि **inner** ClientHello स्वीकार किया गया। केवल HTTPS record उपलब्ध होने से यह साबित नहीं होता कि ECH सफल हुआ।
7. Network में बदलाव, captive portals, browser updates और VPN reconnects के बाद दोबारा जाँचें। दर्ज करें कि DNS/ECH का नियंत्रण किस component के पास है, ताकि बाद के administrators कोई bypass न बना दें।

## Mixnets

Nym या Katzenpost जैसे mixnets timing correlation से बचाव के लिए fixed-size packets, delay, reordering और cover traffic जोड़ते हैं। इन विशेषताओं की कीमत latency और bandwidth है, और deployment के बड़े पैमाने पर स्वतंत्र प्रमाण सीमित हैं। मौजूदा consumer mixnets को Tor/VPNs के तेज़ या सुनिश्चित विकल्प नहीं, बल्कि **उभरते/उच्च-latency वाले विकल्प** मानें।<sup>[[17]](#references)</sup>

### मूल्यांकन workflow

1. Maintained client और उसके द्वारा समर्थित सटीक application की पहचान करें; arbitrary browser/system traffic को undocumented proxy से जबरन न भेजें।
2. Entry, mix nodes, gateway, destination और collusion से जुड़ी धारणाओं के लिए मौजूदा threat model पढ़ें।
3. अलग test compartment में आधिकारिक signed source से install करें और केवल अपने नियंत्रण वाले benign endpoint का इस्तेमाल करें।
4. Delivery latency, message-size limits, reliability, retransmission और gateway अनुपलब्ध होने पर होने वाले व्यवहार को मापें।
5. इच्छित path और source की पुष्टि के लिए स्थानीय traffic और अपने नियंत्रण वाले endpoint की जाँच करें। यह भी देखें कि replies में वही privacy design इस्तेमाल होता है या नहीं।
6. Shutdown/failure की जाँच करें: application को चुपचाप direct Internet access पर वापस नहीं जाना चाहिए।
7. केवल गति के लिए cover traffic बंद न करें, delays कम न करें या असामान्य fixed routes न चुनें; इन बदलावों से घोषित anonymity model अमान्य हो सकता है।
8. जब तक विशेष deployment, स्वतंत्र विश्लेषण और operational reliability परिणामों के स्तर के अनुरूप न हों, इसे प्रयोगात्मक ही रखें।

## Network preflight checklist

- [ ] अनुमति में access network, target, dates और source infrastructure शामिल हैं।
- [ ] Endpoint में असंबंधित identities या सक्रिय sync sessions नहीं हैं।
- [ ] IPv4, IPv6, DNS और reconnect behavior योजना के अनुरूप हैं।
- [ ] नियंत्रित DHCP/local-subnet route injection test traffic को physical interface पर नहीं भेज सकता।
- [ ] Destination को केवल अपेक्षित egress दिखाई देता है।
- [ ] Captive portal और hotspot behavior को संवेदनशील traffic के बिना जाँचा गया है।
- [ ] स्थानीय sharing/discovery और automatic network joining बंद हैं।
- [ ] Observer table और शेष traffic-correlation risk स्वीकार किए गए हैं।
- [ ] Provider policy, retention और emergency contact की जानकारी मौजूदा है।

Split-knowledge relays, route-enforced workloads, pluggable transports, onion services, I2P और disposable remote browsers के लिए, [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md) पर जाएँ।



## References

- [1] [EFF — आपके लिए सही VPN चुनना](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Device security guidance: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Tor द्वारा दी जाने वाली privacy और anonymity सुरक्षा](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Tor का संक्षिप्त परिचय](https://spec.torproject.org/intro/)
- [5] [Tor Project — अन्य browsers के साथ Tor का इस्तेमाल](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Tor Browser में plugins और add-ons](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Tor की रुकावट हटाना](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — VPN के साथ Tor Browser का इस्तेमाल](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — क्या सार्वजनिक Wi-Fi नेटवर्क सुरक्षित हैं?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Apple devices के साथ Wi-Fi privacy](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — MAC randomization लागू करना](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — सुरक्षित Privileged Access Workstations के सिद्धांत](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — अनिवार्य SIM registration: नीतिगत और नियामक दृष्टिकोण](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — DNS Privacy Service Operators के लिए सुझाव](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — Tunnels को bypass करना: Routing Tables का दुरुपयोग करके VPN Client Traffic leak करना](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: Routing-Based VPNs को पूरी तरह VPN leak करने के लिए Attackers कैसे Decloak कर सकते हैं](https://www.leviathansecurity.com/blog/tunnelvision)
- [20] [Yggdrasil FAQ: क्या Yggdrasil anonymous है?](https://yggdrasil-network.github.io/faq.html#is-yggdrasil-anonymous)
- [21] [Yggstack README](https://github.com/yggdrasil-network/yggstack)
{{#include ../banners/hacktricks-training.md}}
