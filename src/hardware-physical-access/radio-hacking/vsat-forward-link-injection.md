# VSAT Forward-Link Signal Injection

{{#include ../../banners/hacktricks-training.md}}

VSAT terminal आम तौर पर अपने satellite downlink को operator के hub से आने वाले traffic के रूप में मानता है। DVB-RCS system में forward link पर user IP packets और modem control messages, दोनों हो सकते हैं। यदि receiver किसी message को process करने से पहले authenticate नहीं करता, तो locally injected signal radio-to-control-plane trust boundary पार कर सकता है। यह **terminal पर downlink injection** है, satellite पर uplink नहीं और न ही passive downlink interception। इसका प्रदर्शित परिणाम modem के protocol implementation और message authentication पर निर्भर करता है, केवल DVB-RCS पर नहीं।<sup>[[1]](#references)[[2]](#references)</sup>

## RF-सीमित lab में परीक्षण करें

अपना terminal, उसका firmware और modem के receive input से उचित attenuation के ज़रिए जुड़ा SDR, या shielded RF setup इस्तेमाल करें। किसी live satellite channel पर signal transmit न करें। सबसे पहले terminal का configured start-up carrier, symbol rate और population ID दर्ज करें; ये forward-link acquisition में मदद करते हैं।<sup>[[1]](#references)[[3]](#references)</sup> DVB-RCS acquisition chain में Network Information Table (NIT) का उपयोग RCS Map Table (RMT) ढूँढ़ने के लिए होता है, फिर Program Association Table (PAT) और Program Map Table (PMT) का उपयोग forward-link signalling streams ढूँढ़ने के लिए होता है। Data stream तक पहुँचने से पहले terminal कई transport-stream carriers पर retune कर सकता है।<sup>[[3]](#references)</sup>

1. Target के start-up transport stream को decode या reconstruct करें और उसका NIT, RMT, service IDs, packet IDs (PIDs) तथा clock-reference handling जाँचें। Standard की तुलना target के parser और logs से करें; vendor-specific ordering या descriptors के कारण कोई अन्यथा valid stream स्वीकार नहीं हो सकती।
2. Lab transmitter में एक harmless UDP probe को `UDP/IP → MPE → MPEG-TS → DVB-S2 I/Q` के रूप में encapsulate करें और SDR sink के ज़रिए isolated receive path में भेजें। Transport stream का Program Clock Reference (PCR), byte rate के अनुरूप रखें; अन्यथा probe process होने से पहले modem synchronization खो सकता है।
3. किसी अपने internal endpoint पर **demodulator lock** और probe का पहुँचना, दोनों की पुष्टि करें। केवल lock से यह साबित होता है कि physical layer ने waveform स्वीकार किया। इसके बाद जाँचें कि unauthenticated management या update *signalling* उजागर है या नहीं; कोई image install न करें और service configuration न बदलें।

प्रकाशित MDM2200 case में DVB-RCS/MPE/MPEG-TS के लिए GNU Radio source module और DVB-S2 modulation के लिए `gr-dtv` का उपयोग किया गया था। उस modem को target-विशिष्ट initialization details की ज़रूरत थी: PAT/PMT से पहले SDT, table ID `0x3E` वाला RCS content descriptor, और उसके GSE/4CPM mode के लिए `0x01` वाला RMT private byte। यह न मानें कि ये values किसी अन्य terminal पर भी काम करेंगी।<sup>[[1]](#references)</sup> Researchers ने यह भी देखा कि उनके setup में multicast MPE packets receiving modems तक पहुँचे; इसलिए targeting केवल ज्ञात unicast MAC address तक सीमित नहीं थी।<sup>[[1]](#references)</sup> एक अलग analysis में अध्ययन किए गए system पर unprotected control और software-update signalling मिली, लेकिन इस finding को हर implementation पर अलग से verify करना चाहिए।<sup>[[2]](#references)</sup>

User traffic के लिए IPsec या VPN tunnel, पहले से मौजूद DVB-RCS signalling या modem के अपने update parser को authenticate नहीं करता। अधिकृत assessment में **user IP**, **forward-link control** और **maintenance/recovery** traffic की cryptographic protection को अलग-अलग जाँचें; secure user tunnel को इस बात का प्रमाण न मानें कि radio injection रोका गया है।<sup>[[1]](#references)[[2]](#references)</sup>

शुरुआती I/Q निरीक्षण के लिए [radio signal analysis](../hardware-hacking/radio.md) देखें। Board-side firmware और parser की जाँच के लिए [firmware analysis](../firmware-analysis/) देखें। अन्य interfaces के लिए [Radio Hacking overview](./) पर लौटें।

## References

- [1] [Bisping et al. - VSAT Satellite Modems पर Wireless Signal Injection Attacks (USENIX Security 2024)](https://www.usenix.org/system/files/usenixsecurity24-bisping.pdf)
- [2] [Willbold et al. - मौजूदा VSAT System Practices में अंतर्निहित सुरक्षा समस्याओं का पता लगाना: VSAsTer (WiSec 2024)](https://www.lenders.ch/publications/conferences/wisec24.pdf)
- [3] [ETSI EN 301 790 - Satellite distribution systems के लिए DVB interaction channel](https://www.etsi.org/deliver/etsi_en/301700_301799/301790/01.04.01_40/en_301790v010401o.pdf)
{{#include ../../banners/hacktricks-training.md}}
