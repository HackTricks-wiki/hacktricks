# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## परिचय

**Low-Power Wide Area Network** (LPWAN) wireless, low-power, wide-area network technologies का एक समूह है, जिसे कम bit rate पर **long-range communications** के लिए डिज़ाइन किया गया है।
Radio parameters, antenna, regulatory region, terrain और duty cycle के आधार पर, LPWAN deployments multi-kilometre coverage और multi-year battery life के लिए throughput का trade-off कर सकते हैं। Vendor द्वारा दिए गए range और battery आंकड़ों को गारंटी के बजाय design targets मानें।<sup>[[3]](#references)</sup>

Long Range (**LoRa**) वर्तमान में सबसे अधिक deployed LPWAN physical layer है और इसका open MAC-layer specification **LoRaWAN** है।

---

## LPWAN, LoRa, और LoRaWAN

* LoRa – Semtech द्वारा विकसित Chirp Spread Spectrum (CSS) physical layer (proprietary लेकिन documented)।
* LoRaWAN – LoRa-Alliance द्वारा maintained Open MAC/Network layer। Versions 1.0.x और 1.1 field में common हैं।
* Typical architecture: *end-device → gateway (packet-forwarder) → network-server → application-server*।<sup>[[3]](#references)</sup>

> LoRaWAN 1.1 में, **security model** OTAA के दौरान role-specific session keys derive करने के लिए अलग-अलग AES-128 application और network root keys का उपयोग करता है। Earlier 1.0.x deployments में सामान्यतः network और application session keys derive करने के लिए एक AppKey का उपयोग होता है, जबकि ABP session keys को directly provision करता है। इसलिए leaked key से प्राप्त capability LoRaWAN version और expose हुई key पर निर्भर करती है।<sup>[[3]](#references)</sup>

---

## Attack surface का सारांश

| Layer | Weakness | Practical impact |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | Localized packet loss; effectiveness link budget, timing, bandwidth और regulatory constraints पर निर्भर करती है |
| MAC | Join और data-frame replay, जब nonce/counter state reuse किया जाता है | Device desynchronization, spoofing या injection, यदि server/device replay protections का उल्लंघन करता है |
| Network-Server | Insecure packet-forwarder, weak MQTT/UDP filters, outdated gateway firmware | Gateways पर RCE → OT/IT network में pivot |
| Application | Hard-coded या predictable AppKeys | Brute-force/decrypt traffic, sensors का impersonation |

---

## Representative implementation vulnerabilities

* **CVE-2024-29862** – 4.0.11 से पहले के ChirpStack Gateway Bridge versions और 4.2.1 से पहले के MQTT Forwarder versions attacker-controlled MQTT broker से connect हो सकते थे, क्योंकि TLS server-certificate validation disabled था। इससे credentials और gateway traffic expose हो सकता था; fixed releases पर upgrade करें।<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227 में unauthenticated `/lib/` directory listing का वर्णन है, जिसमें downloadable backup file मौजूद थी; CVE-2022-45228 logout page में low-severity CSRF है। ये records claimed LG308 impact, configuration overwrite, population size या 2025 patch state को establish नहीं करते।<sup>[[6]](#references)[[7]](#references)</sup>
* इस page के earlier version में एक alleged Semtech UDP packet-forwarder issue का वर्णन था, जिसमें **greater-than-255-byte crafted uplink causing a stack smash and RCE on SX130x reference gateways** का दावा किया गया था। इसे “LoRa Exploitation Reloaded” Black Hat Europe 2023 presentation और October 2023 private patch से attributed किया गया था। वे precise details research lead के रूप में यहां retained हैं, लेकिन किसी matching public advisory, presentation या patch की पुष्टि नहीं हो सकी। Affected product/version और verifiable primary source प्राप्त किए बिना इस issue को known vulnerability न मानें।

---

## Practical attack techniques

### 1. Sniff & Decrypt traffic
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
ये commands मूल workflow को **illustrative syntax** के रूप में बनाए रखते हैं; repository layout और flags projects/releases के बीच अलग हो सकते हैं। Passive capture से strong AppKey का पता नहीं चलता। Offline guessing तभी उपयोगी है जब root key इतनी weak हो कि उसे खोजा जा सके और captured join exchange ऐसा value प्रदान करे जिससे candidates को validate किया जा सके।<sup>[[2]](#references)[[3]](#references)</sup>

### 2. OTAA replay protection और nonce state का परीक्षण

1. किसी authorized test network में एक legitimate **JoinRequest** capture करें।
2. उसी request को replay करें और पुष्टि करें कि network server reused `DevNonce` को reject करता है।
3. test device को reboot या reset करें और lost nonce state का पता लगाने के लिए जांच दोहराएं। एक compliant server को used nonces track करने चाहिए; केवल JoinRequest को replay करने से newly derived session keys का खुलासा नहीं होता और न ही replayer को किसी session का control मिलता है।<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Adaptive Data-Rate (ADR) downgrading

ऐसा attacker जो network-layer MAC commands को authenticate कर सकता है—for example, applicable network session key या network server compromise करने के बाद—inefficient data-rate parameters force करने और airtime बढ़ाने का प्रयास कर सकता है। किसी device address की जानकारी मात्र होने से कोई nearby unauthenticated transmitter वैध रूप से ADR commands जारी नहीं कर सकता।<sup>[[3]](#references)</sup>

### 4. Reactive jamming

एक reactive jammer LoRa preamble का पता लगाने के बाद transmit कर सकता है और frames को selectively disrupt कर सकता है। पिछले page में दावा किया गया था कि HackRF/GNU Radio setup ने **2 km पर 200 mW से अधिक नहीं** power के साथ full outage उत्पन्न किया, लेकिन supporting measurement source प्रदान नहीं किया गया था; उन numbers को expected result के बजाय केवल reproduction target के रूप में रखें। Required transmit power, timing, bandwidth, affected spreading factors और range environment-specific होते हैं। केवल authorized, RF-contained setup के अंदर test करें और local spectrum rules का पालन करें।

---

## Offensive tooling (2025)

| Tool | Purpose | Notes |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | LoRaWAN frames को craft/parse/attack करना, DB-backed analyzers, brute-forcer | Docker image; Semtech UDP input को support करता है<sup>[[1]](#references)</sup> |
| **LoRaPWN** | OTAA को brute करना, downlinks generate करना, payloads decrypt करना वाला Trend Micro Python utility | Public research utility; supported hardware और protocol versions verify करें<sup>[[2]](#references)</sup> |
| **LoRAttack** | Multi-channel LoRaWAN capture, session analysis, key derivation और replay testing के लिए research framework | 2024 master's thesis में वर्णित; example flags पर निर्भर करने से पहले exact implementation प्राप्त करके verify करें<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | LoRa baseband reception या transceiver research के लिए GNU Radio out-of-tree blocks | Projects GNU Radio compatibility और feature set में अलग-अलग होते हैं<sup>[[9]](#references)</sup> |

---

## Defensive recommendations (pentester checklist)

1. **OTAA** को प्राथमिकता दें और verify करें कि devices और servers आवश्यक nonce state persist करते हैं; rejected duplicate joins को monitor करें।
2. जहां supported हो वहां **LoRaWAN 1.1** को प्राथमिकता दें, ताकि network functions distinct session keys और updated nonce handling का उपयोग करें।<sup>[[3]](#references)</sup>
3. Frame-counter को non-volatile memory (**ABP**) में store करें या OTAA पर migrate करें।
4. Ordinary firmware storage में root keys का exposure कम करने के लिए suitable **secure element** deploy करें (for example, supported design में ATECC608A)।
5. Configured packet-forwarder UDP listeners (commonly 1700) को untrusted networks के सामने expose न करें; gateway backhaul को authenticate/encrypt करें या VPN से restrict करें।
6. Gateways को vendor-supported firmware पर रखें और applicable advisories के अनुसार exact model/version confirm करें।
7. **Traffic anomaly detection** implement करें (e.g., LAF analyzer) – counter resets, duplicate joins और sudden ADR changes को flag करें।<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN overview](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - LoRaWAN L2 1.1 specification](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - LoRaWAN 1.1 regional parameters and join synchronization](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [CTU thesis catalogue - LPWAN Protocol Security Analysis Leveraging SDR Technology](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [EPFL `gr-lora_sdr` GNU Radio transceiver](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
