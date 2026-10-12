# गुप्त भौतिक और वायरलेस एक्सेस

{{#include ../banners/hacktricks-training.md}}

outbound rendezvous, power/uplink recovery, डिवाइस पर रखे जाने वाले न्यूनतम secrets, capture testing और संभावित खोज की निगरानी को कवर करने वाले विस्तृत, मालिक-अनुमोदित कार्यान्वयन के लिए, [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) देखें।

नेटवर्क पथ बदलने से दिखाई देने वाला भौतिक मूल स्थान भी बदल सकता है। कोई परिष्कृत हमलावर target के logs को operator से दूर दिखाने के लिए पास के compromised system, छिपे हुए device, public access, cellular backhaul या satellite receiver का उपयोग कर सकता है। इनमें से कोई भी तरीका भौतिक, radio या provider से जुड़े साक्ष्य मिटाता नहीं है; यह attribution को अलग-अलग datasets में ले जाता है।

## Technique matrix

| Technique | दिखाई देने वाला मूल स्थान | आवश्यक शर्त | उच्च-मूल्य वाले साक्ष्य |
|---|---|---|---|
| Nearby wireless pivot | target के पास का business/home | compromised dual-homed host और target Wi-Fi access | पड़ोसी host के endpoint logs, RF association और target RADIUS/DHCP |
| Public/guest network | venue NAT या tunnel exit | वैध access या access-control bypass | captive portal, DHCP, AP association, CCTV और भुगतान/स्थान रिकॉर्ड |
| Covert drop device | target/पास का wired, Wi-Fi या cellular address | भौतिक रूप से रखना या पहुँचाना | switchport/USB, RF, inventory, power और outbound tunnel telemetry |
| Cellular router/eSIM | carrier NAT या dedicated APN | modem/SIM/subscription | IMEI/IMSI/eSIM, cell-sector, carrier account और traffic timing |
| Satellite-link abuse | beam footprint में subscriber address | protocol- और service-specific कमजोरी | RF location, uplink flow, असंभव RTT/routing और provider records |

## Nearest-neighbor attack

Volexity ने 2022 के एक APT28/GRU ऑपरेशन का दस्तावेज़ीकरण किया, जिसमें हमलावर अपने अंतिम target से दूर था। उसने वैध credentials हासिल करने के लिए target की public service पर password spraying किया, लेकिन MFA ने सीधे Internet login को रोक दिया। Target का enterprise Wi-Fi उन्हीं credentials को MFA के बिना स्वीकार करता था। हमलावर ने target के भौतिक रूप से पास की organizations को compromise किया, wireless reach वाले dual-homed system का पता लगाया और उस system का उपयोग करके target के Wi-Fi पर authenticate किया। Volexity ने इसे **Nearest Neighbor Attack** नाम दिया।<sup>[[1]](#references)</sup>

```text
remote operator
      |
compromised organization C
      |
compromised organization B -- Wi-Fi radio --> target organization A
                                               |
                                        internal service
```

इसकी नवीनता इसके संयोजन में है। कोई ऑपरेटर लक्ष्य तक नहीं जाता और इंटरनेट-सामना करने वाली सेवा का MFA अब भी काम करता है। समझौता किया गया पड़ोसी भौतिक निकटता देता है; चुराया गया लक्ष्य क्रेडेंशियल लॉजिकल एक्सेस देता है; लक्ष्य का Wi-Fi सीमा-पार जाने का रास्ता बन जाता है।

### पूर्वापेक्षाएँ और दृश्यता

- पास के सिस्टम को दूर से नियंत्रित किया जा सकना चाहिए और उसमें संगत रेडियो या किसी दूसरे पास के pivot तक पहुँच होनी चाहिए।
- लक्ष्य SSID उस सिस्टम तक पहुँचना चाहिए, और Wi-Fi प्रवेश में पुनः उपयोग किए जा सकने वाले क्रेडेंशियल/सर्टिफ़िकेट/डिवाइस स्थिति को स्वीकार किया जाना चाहिए।
- pivot को अक्सर एक साथ दो रास्तों की ज़रूरत होती है: एक ऑपरेटर तक वापस जाने के लिए और दूसरा लक्ष्य WLAN में जाने के लिए।
- लक्ष्य को नया station MAC और वैध username दिख सकता है, लेकिन उससे जुड़ा कोई managed-device सर्टिफ़िकेट, posture, इतिहास या अपेक्षित भवन-प्रवेश रिकॉर्ड नहीं।
- पड़ोसी endpoint लॉग में wireless scans, नए profiles, interface में बदलाव, tunneling और remote-control गतिविधि दिख सकती है।

### पहचान और रोकथाम

1. एंटरप्राइज़ Wi-Fi के लिए certificate-backed EAP-TLS और managed-device posture अनिवार्य करें; केवल इसलिए कि पासवर्ड रेडियो के ज़रिए आया है, उसे पर्याप्त न मानें—खासकर तब, जब वह इंटरनेट पर MFA में विफल रहा हो।
2. RADIUS authentication का MDM/NAC identity, ऐतिहासिक station/device binding, AP location, physical-access events और concurrent sessions से मिलान करें।
3. जब कोई account पहली बार associate करे, किसी असामान्य AP edge से आए, managed सर्टिफ़िकेट के बिना हो, या वही identity कहीं और सक्रिय हो, तो alert दें।
4. interfaces को bridge करने में सक्षम endpoints की निगरानी करें। Windows, Linux और network appliances पर अनपेक्षित WLAN profiles, forwarding/NAT configuration, virtual adapters और persistent tunnels की जाँच करें।
5. AP की जगह और power planning सोच-समझकर करके अनावश्यक signal spill कम करें। यह सहायक नियंत्रण है, authentication का विकल्प नहीं।
6. पड़ोसी tenants के साथ incident response का समन्वय करें: अंतिम radio source स्वयं भी पीड़ित हो सकता है।

[दो संगठनों वाली अधिकृत lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) किसी पड़ोसी पर हमला किए बिना इन observable संकेतों को दोहराती है।

### Windows pivot path को मान्य करें

दो नेटवर्क से जुड़ा Windows host अपने interfaces को अपने-आप bridge नहीं करता। पहले उसके adapters, routes और WLAN स्थिति की सूची बनाएँ, फिर केवल स्वीकृत profile के ज़रिए associate करें। `netsh wlan connect` का `name` argument किसी installed profile की पहचान करता है, किसी मनमाने SSID और password की नहीं। Association से पहले और बाद की route table की तुलना करें, ताकि नया default route control path को न तोड़े या परिणाम को अमान्य न करे। [Association के बाद की जाँचों](../generic-methodologies-and-resources/pentesting-wifi/wifi-post-association-and-client-isolation-attacks.md) पर तभी आगे बढ़ें, जब इच्छित interface और route की पुष्टि हो जाए।<sup>[[1]](#references)[[6]](#references)</sup>

```powershell
Get-NetAdapter -Physical | Sort-Object Status -Descending
Get-NetIPConfiguration
Get-NetRoute -AddressFamily IPv4 | Sort-Object InterfaceIndex,RouteMetric

netsh wlan show interfaces
netsh wlan show networks mode=bssid
netsh wlan show profiles

# Connect only with an approved profile already installed on the endpoint.
netsh wlan connect name="<approved-profile>" interface="Wi-Fi"
Get-NetConnectionProfile
```

Volexity द्वारा जारी incident artifact एक और उपयोगी अंतर दिखाता है। इसमें एम्बेड किया गया C# WLAN API खोलता है, interfaces की गणना करता है, डिस्क से EAP XML पढ़ता है और पहले wireless interface पर नामित profile के लिए `WlanSetProfileEapXmlUserData` कॉल करता है। यह API किसी मौजूदा 802.1X profile पर EAP user credentials सेट करता है, लेकिन जारी किए गए component में न तो `WlanConnect` है और न ही report में वर्णित discovery logic। इसे पूर्ण connector के बजाय profile provisioning मानें, और [client and supplicant assessment](../generic-methodologies-and-resources/pentesting-wifi/wifi-client-and-supplicant-assessment.md) के हिस्से के रूप में परिणामी profile की जांच करें।<sup>[[5]](#references)[[7]](#references)</sup>

## Public venues and third-party Wi-Fi

कैफ़े, होटल, हवाई अड्डे या नगरपालिका के Wi-Fi का इस्तेमाल करने से destination को दिखने वाला IP बदल जाता है। इससे anonymity नहीं मिलती। स्थल या उसका provider AP association, device MAC, DHCP lease, captive-portal account, SMS/email validation और flow logs रख सकता है। स्थल पर भौतिक प्रवेश, CCTV, खरीदारी, mobile-location और यात्रा के रिकॉर्ड डिजिटल घटना को किसी व्यक्ति से जोड़ सकते हैं।

कोई actor randomized MAC addresses, अलग device, नकद या tunnel का इस्तेमाल करके एक पहचान-सूत्र कम करने की कोशिश कर सकता है। फिर भी, arrival time, स्थल पर बार-बार जाने के pattern, radio fingerprints, portal behavior, traffic timing, camera footage और tunnel provider के ज़रिए अलग-अलग layers का correlation संभव रहता है। VPN destination को स्थल के logs से VPN logs पर स्थानांतरित भी कर देता है; इससे यह तथ्य नहीं मिटता कि device स्थल पर मौजूद था।

Public access के defenders को clients को अलग रखना चाहिए, lateral traffic रोकना चाहिए, जहां संभव हो WPA2/3-Enterprise या प्रति-device keys का उपयोग करना चाहिए, अनुपातिक DHCP/RADIUS/security logs बनाए रखने चाहिए, captive portals को सुरक्षित रखना चाहिए और abuse process प्रकाशित करनी चाहिए। Red teams को ऐसे स्थल का उपयोग तभी करना चाहिए जब उसकी शर्तें और engagement इसकी अनुमति दें; portal को bypass करना, access चुराना या अन्य मेहमानों को target करना, authorized testing का शॉर्टकट नहीं है।

## Covert drop devices and warshipping

Drop एक छोटा system होता है जिसे किसी स्थल पर रखा जाता है या वहां पहुंचाया जाता है, और फिर outbound Ethernet, Wi-Fi या cellular के ज़रिए नियंत्रित किया जाता है। “Warshipping” device को इस तरह पैक करता है कि सामान्य delivery उसे radio perimeter के भीतर पहुंचा दे। संभावित hardware में single-board computer से लेकर modified charger, USB peripheral, network appliance या battery-powered modem तक शामिल हैं।

Operational architecture:

```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
                                                        |
                                             scoped local interface
```

डिवाइस remote foothold दे सकता है, wireless measurements कर सकता है, किसी authorized exercise peripheral का अनुकरण कर सकता है या traffic relay कर सकता है। इसका स्रोत स्थानीय दिखाई देता है, लेकिन इससे भौतिक निशान बनते हैं: serial numbers, packaging, fingerprints, cameras, access logs, power draw, USB descriptors, switchport negotiation, DHCP fingerprints, MAC OUI/randomization behavior, RF emissions और बार-बार होने वाले rendezvous connections।

### रक्षात्मक नियंत्रण

- Receiving-room और asset-inventory प्रक्रियाएँ बनाए रखें; अनपेक्षित electronics और ऐसे packages की जाँच करें जो अस्तित्व में न होने वाले कर्मचारियों के नाम पर आए हों।
- Wired और wireless access पर 802.1X/NAC का उपयोग करें, अप्रयुक्त ports को बंद करें और अज्ञात devices को restricted remediation VLAN में रखें।
- नए DHCP fingerprints, लंबे समय तक बने रहने वाले locally administered MACs, नए USB network/HID devices, unauthorized Wi-Fi Direct/Bluetooth और लंबे समय तक चलने वाले outbound tunnels पर alert करें।
- Switchport, power-over-Ethernet, DNS और TLS behavior का baseline बनाएँ। Inventory record के बिना किसी छोटे host का समय-समय पर encrypted connections बनाना, केवल “Raspberry Pi OUI” से कहीं अधिक महत्वपूर्ण संकेत है।
- Exercise के दौरान inventory और label बनाएँ, scope तय करें, encryption लागू करें, remote kill उपलब्ध कराएँ, वापसी की समय-सीमा निर्धारित करें और सुनिश्चित करें कि डिवाइस खोने पर reusable credentials उजागर न हों।

## Cellular और eSIM backhaul

Cellular modem, target के Internet gateway से बच निकलता है और outbound rendezvous के ज़रिए carrier NAT के पीछे भी drop तक पहुँच बनाए रख सकता है। Mobile addresses बदल सकते हैं या साझा हो सकते हैं; फिर भी cellular operator के पास subscriber और network से जुड़े पुख्ता साक्ष्य होते हैं: SIM/eSIM identity, IMSI, device IMEI, assigned addresses/ports, cell/sector timing, account/payment और roaming records।

Enterprise के दृष्टिकोण से, wireless/RF surveys, endpoint USB/PCI inventory, MDM restrictions, rogue-SSID monitoring और भौतिक निरीक्षण के ज़रिए अनपेक्षित modems और personal hotspots का पता लगाएँ। Control के लिए cellular का उपयोग करने वाले drop को उसके स्थानीय Ethernet/Wi-Fi behavior और radio emissions से अब भी पकड़ा जा सकता है।

Authorized exercises के लिए, organization को subscription और modem का स्वामित्व रखना चाहिए, controller के साथ identifiers दर्ज करने चाहिए और पुष्टि करनी चाहिए कि carrier/provider की शर्तें उस traffic की अनुमति देती हैं। Prepaid label या cryptocurrency से खरीदारी करने पर tower, device या retail records मिटते नहीं हैं।

## MAC randomization और device fingerprinting

आधुनिक systems हर network के लिए locally administered random MAC का उपयोग कर सकते हैं। इससे स्थिर factory MAC के ज़रिए passive long-term tracking कम होती है; लेकिन ये चीज़ें छिपती नहीं हैं:

- probe/association का समय और अनुरोधित network capabilities का समूह;
- 802.11 information elements, supported rates और vendor-specific behavior;
- DHCP options/hostname, IPv6 identifiers और captive-portal/browser fingerprint;
- authenticated 802.1X identity या certificate;
- higher-layer account, tunnel और traffic pattern; या
- भौतिक निगरानी।

Defenders को authentication के लिए MAC allowlists का उपयोग नहीं करना चाहिए। Radio identity को certificate/device posture से जोड़ें और बदलते MACs को तब तक सामान्य मानें, जब तक अन्य संदर्भ में कुछ असामान्य न हो।

## Satellite-link hijacking

Kaspersky ने Turla द्वारा पुराने one-way DVB-S satellite Internet की कमज़ोरियों का उपयोग करने का दस्तावेज़ीकरण किया। रिपोर्ट किए गए मॉडल में, एक वैध remote subscriber terrestrial link के ज़रिए outbound requests भेजता था, लेकिन downstream data उसे unencrypted wide-area satellite broadcast से मिलता था। Satellite footprint के भीतर कोई actor downlink देख सकता था, किसी सक्रिय subscriber IP को चुन सकता था और C2 replies को उस IP पर भेजने की व्यवस्था कर सकता था। वैध subscriber और actor—दोनों को broadcast मिलता था; actor चुने गए port के लिए traffic निकालता था, जबकि वैध subscriber unsolicited packets को छोड़ देता था। इसके बाद C2 operator किसी अन्य भौगोलिक क्षेत्र में satellite-provider address का उपयोग करता हुआ दिखाई देता था।<sup>[[2]](#references)</sup>

```text
actor uplink request -> C2 server -> Internet -> satellite gateway
                                           satellite broadcast
                                  +--------------+-------------+
                                  |                            |
                         legitimate subscriber          actor receiver
```

यह protocol/service-विशिष्ट था, bandwidth-सीमित था और किसी आधुनिक bidirectional encrypted satellite terminal को compromise करने के बराबर नहीं था। इससे किसी पर्याप्त रूप से सक्षम observer से actor का outbound request path भी छिपा नहीं। Detection के अवसरों में asymmetric/impossible routing, ऐसे subscriber को traffic भेजना जिसने flow शुरू नहीं किया, unusual destination ports, provider telemetry, receiver location/RF investigation और malware configuration शामिल हैं। इस मामले का उपयोग इस धारणा को चुनौती देने के लिए करें कि C2 IP को geolocate करने से उसके controller की location मिल जाती है—इसे बनाने की विधि न समझें।

## Physical-to-digital correlation worksheet

जब कोई स्पष्ट रूप से स्थानीय source संदिग्ध लगे, तो एक timeline बनाएं:

1. AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switch और physical-access की clocks को normalize करें;
2. केवल पहला alert नहीं, बल्कि पहला radio association या link-up पहचानें;
3. station को certificate, device posture, DHCP fingerprint और switch/AP location से map करें;
4. आस-पास के systems पर एक ही समय में remote-control/tunnel activity देखें;
5. लागू policy/law के तहत deliveries, visitors, inventory exceptions, cameras और RF findings की समीक्षा करें;
6. संदिग्ध device और volatile network state को सुरक्षित रखें; बिना सोचे-समझे power-cycle न करें;
7. तय करें कि apparent source actor-controlled infrastructure है या कोई अन्य victim।

## References

- [1] [Volexity — निकटतम पड़ोसी हमला: एक रूसी APT ने गुप्त access के लिए पास के Wi-Fi networks को हथियार बनाया](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: आसमान में APT command and control](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Hardware Additions (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Wireless Local Area Networks को सुरक्षित करने के दिशानिर्देश](https://csrc.nist.gov/pubs/sp/800/153/final)
- [5] [Volexity — संपादित PowerShell/C# WLAN profile code](https://github.com/volexity/threat-intel/blob/main/2024/2024-11-22%20GruesomeLarch/wifi_ps1_redacted.cs)
- [6] [Microsoft — netsh wlan](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wlan)
- [7] [Microsoft — WlanSetProfileEapXmlUserData function](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlansetprofileeapxmluserdata)
{{#include ../banners/hacktricks-training.md}}
