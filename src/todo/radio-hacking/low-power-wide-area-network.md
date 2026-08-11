# Mtandao wa Wide Area wenye Matumizi Madogo ya Nishati

{{#include ../../banners/hacktricks-training.md}}

## Utangulizi

**Low-Power Wide Area Network** (LPWAN) ni kundi la teknolojia za mtandao zisizotumia waya, zenye matumizi madogo ya nishati na zinazofunika eneo pana, zilizoundwa kwa ajili ya **mawasiliano ya masafa marefu** kwa kiwango kidogo cha bit.
Kulingana na vigezo vya radio, antenna, eneo la udhibiti, mandhari na duty cycle, deployments za LPWAN zinaweza kubadilishana throughput kwa coverage ya kilomita nyingi na maisha ya betri ya miaka kadhaa. Chukulia takwimu za vendor kuhusu masafa na betri kama malengo ya usanifu badala ya hakikisho.<sup>[[3]](#references)</sup>

Long Range (**LoRa**) ndiyo physical layer ya LPWAN inayotumika zaidi kwa sasa, na specification yake ya wazi ya MAC-layer ni **LoRaWAN**.

---

## LPWAN, LoRa, na LoRaWAN

* LoRa – Chirp Spread Spectrum (CSS) physical layer iliyotengenezwa na Semtech (proprietary lakini documented).
* LoRaWAN – Open MAC/Network layer inayodumishwa na LoRa-Alliance. Versions 1.0.x na 1.1 hutumika kwa kawaida kwenye field.
* Muundo wa kawaida: *end-device → gateway (packet-forwarder) → network-server → application-server*.<sup>[[3]](#references)</sup>

> Katika LoRaWAN 1.1, **security model** hutumia application na network root keys tofauti za AES-128 ili kuunda role-specific session keys wakati wa OTAA. Deployments za awali za 1.0.x kwa kawaida hutumia AppKey moja kuunda network na application session keys, huku ABP ikiweka session keys moja kwa moja. Uwezo unaopatikana kutokana na key iliyovuja hutegemea version ya LoRaWAN na ni key gani iliyofichuliwa.<sup>[[3]](#references)</sup>

---

## Muhtasari wa attack surface

| Layer | Weakness | Practical impact |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | Kupotea kwa packets katika eneo maalum; ufanisi hutegemea link budget, timing, bandwidth na vikwazo vya regulatory |
| MAC | Join na data-frame replay pale ambapo hali ya nonce/counter inatumiwa tena | Device desynchronization, spoofing au injection ikiwa server/device itakiuka replay protections |
| Network-Server | Packet-forwarder isiyo salama, MQTT/UDP filters dhaifu, gateway firmware iliyopitwa na wakati | RCE kwenye gateways → pivot kuingia kwenye mtandao wa OT/IT |
| Application | AppKeys zilizowekwa moja kwa moja kwenye code au zinazotabirika | Brute-force/decrypt traffic, kuiga sensors |

---

## Vulnerabilities za utekelezaji zinazowakilisha

* **CVE-2024-29862** – Versions za ChirpStack Gateway Bridge kabla ya 4.0.11 na MQTT Forwarder kabla ya 4.2.1 ziliweza kuunganishwa na MQTT broker inayodhibitiwa na attacker kwa sababu TLS server-certificate validation ilikuwa imezimwa. Hili lingeweza kufichua credentials na gateway traffic; upgrade kwenda kwenye releases zilizorekebishwa.<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227 inaeleza `/lib/` directory listing isiyohitaji authentication, iliyokuwa na backup file inayoweza kupakuliwa; CVE-2022-45228 ni CSRF yenye severity ndogo kwenye logout page. Records hizi hazithibitishi LG308 impact, configuration overwrite, ukubwa wa population, au hali ya patch ya 2025 iliyodaiwa.<sup>[[6]](#references)[[7]](#references)</sup>
* Toleo la awali la ukurasa huu lilieleza issue inayodaiwa ya Semtech UDP packet-forwarder kama **greater-than-255-byte crafted uplink causing a stack smash and RCE on SX130x reference gateways**, ikihusishwa na presentation ya “LoRa Exploitation Reloaded” ya Black Hat Europe 2023 na private patch ya Oktoba 2023. Maelezo hayo mahususi yamehifadhiwa hapa kama research lead, lakini hakuna public advisory, presentation au patch inayolingana iliyoweza kuthibitishwa. Usichukulie issue hii kama vulnerability inayojulikana bila kupata product/version iliyoathiriwa na primary source inayoweza kuthibitishwa.

---

## Mbinu za Practical attack

### 1. Sniff & Decrypt traffic
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
Amri hizi huhifadhi workflow ya awali kama **illustrative syntax**; mpangilio wa repository na flags hutofautiana kati ya miradi/releases. Passive capture haifichui AppKey yenye nguvu. Offline guessing ni muhimu tu wakati root key ni dhaifu vya kutosha kupatikana na captured join exchange inatoa thamani inayoweza kuthibitisha candidates.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. Kupima ulinzi wa OTAA dhidi ya replay na hali ya nonce

1. Katika mtandao wa majaribio ulioidhinishwa, capture **JoinRequest** halali.
2. Replay ombi hilo hilo na uthibitishe kwamba network server inakataa `DevNonce` iliyotumiwa tena.
3. Reboot au reset kifaa cha majaribio kisha rudia ukaguzi ili kugundua nonce state iliyopotea. Server inayotii viwango lazima ifuatilie nonces zilizotumiwa; kureplay JoinRequest pekee hakufichui session keys mpya zilizotengenezwa wala kumpa mchezaji anayerudia udhibiti wa session.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Kupunguza Adaptive Data-Rate (ADR)

Mshambuliaji anayeweza authenticate network-layer MAC commands—for example, baada ya kucompromise applicable network session key au network server—anaweza kujaribu kulazimisha data-rate parameters zisizofaa na kuongeza airtime. Transmitter iliyo karibu na ambayo haija-authenticate haiwezi kutoa ADR commands kihalali kwa kujua tu device address.<sup>[[3]](#references)</sup>

### 4. Reactive jamming

Reactive jammer inaweza kutuma baada ya kugundua LoRa preamble na kuvuruga frames kwa kuchagua. Ukurasa wa awali ulidai kwamba setup ya HackRF/GNU Radio ilisababisha outage kamili katika **2 km with no more than 200 mW**, lakini hakuna chanzo cha vipimo kilichotolewa; hifadhi nambari hizo kama lengo la reproduction tu, si matokeo yanayotarajiwa. Transmit power, timing, bandwidth, spreading factors zinazoathiriwa, na range vinategemea mazingira. Fanya majaribio ndani ya setup iliyoidhinishwa na iliyotengwa kwa RF pekee, na ufuate sheria za spectrum za eneo lako.

---

## Zana za offensive (2025)

| Tool | Purpose | Notes |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Kutengeneza/ku-parse/ku-attack LoRaWAN frames, analyzers zinazotumia DB, brute-forcer | Docker image; inasaidia Semtech UDP input<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Python utility ya Trend Micro ya kubrute OTAA, kutengeneza downlinks, na ku-decrypt payloads | Public research utility; thibitisha hardware na protocol versions zinazoungwa mkono<sup>[[2]](#references)</sup> |
| **LoRAttack** | Research framework ya multi-channel LoRaWAN capture, session analysis, key derivation, na replay testing | Imeelezwa katika master's thesis ya 2024; pata na uthibitishe implementation halisi kabla ya kutegemea example flags<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | GNU Radio out-of-tree blocks za LoRa baseband reception au transceiver research | Miradi hutofautiana katika GNU Radio compatibility na feature set<sup>[[9]](#references)</sup> |

---

## Mapendekezo ya ulinzi (checklist ya pentester)

1. Pendelea **OTAA** na uthibitishe kwamba devices na servers zinahifadhi nonce state inayohitajika; monitor rejected duplicate joins.
2. Pendelea **LoRaWAN 1.1** inapoungwa mkono ili network functions zitumie session keys tofauti na nonce handling iliyosasishwa.<sup>[[3]](#references)</sup>
3. Hifadhi frame-counter katika non-volatile memory (**ABP**) au hamia OTAA.
4. Deploy **secure element** inayofaa (kwa mfano, ATECC608A katika design inayoungwa mkono) ili kupunguza exposure ya root keys katika firmware storage ya kawaida.
5. Usifichue packet-forwarder UDP listeners zilizosanidiwa (kwa kawaida 1700) kwa networks zisizoaminika; authenticate/encrypt gateway backhaul au izuie kwa VPN.
6. Weka gateways kwenye firmware inayoungwa mkono na vendor na uthibitishe model/version halisi dhidi ya advisories zinazotumika.
7. Implement **traffic anomaly detection** (kwa mfano, LAF analyzer) – flag counter resets, duplicate joins, na mabadiliko ya ghafla ya ADR.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Muhtasari wa Trend Micro LoRaPWN](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - Maelezo ya LoRaWAN L2 1.1](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - Vigezo vya kikanda vya LoRaWAN 1.1 na ulandanishaji wa join](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [Katalogi ya thesis za CTU - Uchambuzi wa Usalama wa Itifaki ya LPWAN kwa Kutumia Teknolojia ya SDR](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [EPFL `gr-lora_sdr` GNU Radio transceiver](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
