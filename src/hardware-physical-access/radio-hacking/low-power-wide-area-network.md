# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Introduction

**Low-Power Wide Area Network** (LPWAN) कम-बिटरेट पर **लंबी दूरी के संचार** के लिए बनाई गई वायरलेस, कम-ऊर्जा वाली wide-area network तकनीकों का समूह है।
रेडियो पैरामीटर, एंटीना, नियामक क्षेत्र, भूभाग और duty cycle के आधार पर, LPWAN deployment कई किलोमीटर की coverage और कई साल की battery life के बदले throughput कम कर सकते हैं। विक्रेता द्वारा बताए गए range और battery संबंधी आंकड़ों को गारंटी के बजाय design targets मानें।<sup>[[3]](#references)</sup>

Long Range (**LoRa**) फ़िलहाल सबसे अधिक deployed LPWAN physical layer है और इसकी open MAC-layer specification **LoRaWAN** है।

---

## LPWAN, LoRa, और LoRaWAN

* LoRa – Semtech द्वारा विकसित Chirp Spread Spectrum (CSS) physical layer (proprietary, लेकिन documented)।
* LoRaWAN – LoRa-Alliance द्वारा अनुरक्षित open MAC/Network layer। Versions 1.0.x और 1.1 field में आम हैं।
* सामान्य architecture: *end-device → gateway (packet-forwarder) → network-server → application-server*।<sup>[[3]](#references)</sup>

> LoRaWAN 1.1 में, **security model** OTAA के दौरान role-specific session keys बनाने के लिए अलग-अलग AES-128 application और network root keys का उपयोग करता है। पुराने 1.0.x deployment में आम तौर पर network और application session keys बनाने के लिए एक AppKey का उपयोग होता है, जबकि ABP में session keys सीधे provision की जाती हैं। इसलिए leaked key से मिलने वाली क्षमता LoRaWAN version और उजागर हुई key पर निर्भर करती है।<sup>[[3]](#references)</sup>

---

## Attack surface का सारांश

| Layer | कमजोरी | व्यावहारिक प्रभाव |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | स्थानीय स्तर पर packet loss; प्रभावशीलता link budget, timing, bandwidth और नियामक सीमाओं पर निर्भर करती है |
| MAC | Nonce/counter state के दोबारा उपयोग पर join और data-frame replay | Device desynchronization, spoofing या injection—यदि server/device replay protections का उल्लंघन करे |
| Network-Server | असुरक्षित packet-forwarder, कमज़ोर MQTT/UDP filters, outdated gateway firmware | Gateways पर RCE → OT/IT network में pivot |
| Application | Hard-coded या अनुमानित AppKeys | Traffic को brute-force/decrypt करना, sensors का रूप धारण करना |

---

## उदाहरण के तौर पर implementation की कमजोरियाँ

* **CVE-2024-29862** – 4.0.11 से पुराने ChirpStack Gateway Bridge versions और 4.2.1 से पुराने MQTT Forwarder versions, TLS server-certificate validation बंद होने के कारण, attacker-controlled MQTT broker से connect हो सकते थे। इससे credentials और gateway traffic उजागर हो सकते थे; fixed releases पर upgrade करें।<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227 में unauthenticated `/lib/` directory listing का वर्णन है, जिसमें downloadable backup file शामिल है; CVE-2022-45228 logout page में low-severity CSRF है। ये records कथित LG308 impact, configuration overwrite, प्रभावित उपकरणों की संख्या या 2025 की patch स्थिति की पुष्टि नहीं करते।<sup>[[6]](#references)[[7]](#references)</sup>
* इस page के पुराने version में Semtech UDP packet-forwarder की एक कथित समस्या का वर्णन था: **255 bytes से बड़ा crafted uplink, जिससे SX130x reference gateways पर stack smash और RCE होता है**। इसे Black Hat Europe 2023 की “LoRa Exploitation Reloaded” presentation और अक्टूबर 2023 के private patch से जोड़ा गया था। इन सटीक विवरणों को यहाँ research lead के रूप में रखा गया है, लेकिन इनकी पुष्टि करने वाला कोई मेल खाता public advisory, presentation या patch नहीं मिला। प्रभावित product/version और सत्यापन योग्य primary source प्राप्त किए बिना इसे ज्ञात vulnerability न मानें।

---

## व्यावहारिक attack techniques

### 1. Sniff & Decrypt ट्रैफ़िक

```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
    --freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```

ये commands मूल workflow को **illustrative syntax** के रूप में बनाए रखते हैं; repository layout और flags अलग-अलग projects/releases में भिन्न होते हैं। Passive capture से strong AppKey का पता नहीं चलता। Offline guessing तभी उपयोगी है, जब root key इतना weak हो कि उसे ढूँढा जा सके और captured join exchange में ऐसा value हो जिससे candidates को validate किया जा सके।<sup>[[2]](#references)[[3]](#references)</sup>

### 2. OTAA replay protection और nonce state की जाँच करें

1. अधिकृत test network में एक वैध **JoinRequest** capture करें।
2. उसी request को replay करें और पुष्टि करें कि network server दोबारा इस्तेमाल किए गए `DevNonce` को अस्वीकार करता है।
3. test device को reboot या reset करें और nonce state खो जाने का पता लगाने के लिए जाँच दोहराएँ। नियमों के अनुरूप server को इस्तेमाल किए गए nonces track करने चाहिए; केवल JoinRequest replay करने से नए derived session keys का पता नहीं चलता और न ही replayer को किसी session पर नियंत्रण मिलता है।<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Adaptive Data-Rate (ADR) को downgrade करना

जो attacker network-layer MAC commands को authenticate कर सकता है—उदाहरण के लिए, लागू network session key या network server को compromise करने के बाद—वह inefficient data-rate parameters लागू करने और airtime बढ़ाने की कोशिश कर सकता है। पास का unauthenticated transmitter केवल device address जानकर वैध रूप से ADR commands जारी नहीं कर सकता।<sup>[[3]](#references)</sup>

### 4. Reactive jamming

Reactive jammer, LoRa preamble का पता लगाने के बाद transmit कर सकता है और चुने हुए frames को बाधित कर सकता है। पहले वाले page में दावा किया गया था कि HackRF/GNU Radio setup ने **2 km पर 200 mW से अधिक नहीं** में पूरा outage किया, लेकिन कोई supporting measurement source नहीं दिया गया था; इन संख्याओं को केवल reproduction target मानें, अपेक्षित परिणाम नहीं। आवश्यक transmit power, timing, bandwidth, प्रभावित spreading factors और range, environment पर निर्भर करते हैं। केवल अधिकृत, RF-contained setup में test करें और स्थानीय spectrum नियमों का पालन करें।

---

## Offensive tooling (2025)

| Tool | उद्देश्य | टिप्पणियाँ |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | LoRaWAN frames बनाना/parse करना/उन पर attack करना, DB-backed analyzers, brute-forcer | Docker image; Semtech UDP input को support करता है<sup>[[1]](#references)</sup> |
| **LoRaPWN** | OTAA पर brute force करने, downlinks बनाने और payloads decrypt करने वाली Trend Micro Python utility | सार्वजनिक research utility; supported hardware और protocol versions verify करें<sup>[[2]](#references)</sup> |
| **LoRAttack** | Multi-channel LoRaWAN capture, session analysis, key derivation और replay testing के लिए research framework | 2024 की master's thesis में वर्णित; example flags पर निर्भर होने से पहले exact implementation प्राप्त करें और verify करें<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | LoRa baseband reception या transceiver research के लिए GNU Radio out-of-tree blocks | Projects की GNU Radio compatibility और feature set अलग-अलग हैं<sup>[[9]](#references)</sup> |

---

## Defensive recommendations (pentester checklist)

1. **OTAA** को प्राथमिकता दें और verify करें कि devices तथा servers आवश्यक nonce state को persist करते हैं; अस्वीकृत duplicate joins को monitor करें।
2. जहाँ supported हो, **LoRaWAN 1.1** को प्राथमिकता दें, ताकि network functions अलग-अलग session keys और updated nonce handling का उपयोग करें।<sup>[[3]](#references)</sup>
3. Frame-counter को non-volatile memory में store करें (**ABP**) या OTAA पर migrate करें।
4. सामान्य firmware storage में root keys के exposure को कम करने के लिए उपयुक्त **secure element** (उदाहरण के लिए, supported design में ATECC608A) deploy करें।
5. Configured packet-forwarder UDP listeners (आमतौर पर 1700) को untrusted networks के सामने expose न करें; gateway backhaul को authenticate/encrypt करें या VPN से restrict करें।
6. Gateways को vendor-supported firmware पर रखें और लागू advisories के अनुसार exact model/version की पुष्टि करें।
7. **Traffic anomaly detection** लागू करें (उदाहरण के लिए, LAF analyzer) – counter resets, duplicate joins और अचानक ADR changes को flag करें।<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN का अवलोकन](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - LoRaWAN L2 1.1 विनिर्देश](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - LoRaWAN 1.1 regional parameters और join synchronization](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [CTU thesis catalogue - SDR Technology का उपयोग करके LPWAN Protocol Security Analysis](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [EPFL `gr-lora_sdr` GNU Radio transceiver](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
