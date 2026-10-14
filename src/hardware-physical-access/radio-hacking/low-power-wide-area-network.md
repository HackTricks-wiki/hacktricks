# Mtandao wa Eneo Pana wenye Matumizi Madogo ya Nishati

{{#include ../../banners/hacktricks-training.md}}

## Utangulizi

**Low-Power Wide Area Network** (LPWAN) ni kundi la teknolojia za mtandao zisizotumia waya, zenye matumizi madogo ya nishati na eneo pana, zilizoundwa kwa ajili ya **mawasiliano ya masafa marefu** kwa kasi ndogo ya biti.
Kulingana na vigezo vya redio, antena, eneo la udhibiti, mandhari na duty cycle, mifumo ya LPWAN inaweza kubadilishana kasi ya data kwa huduma ya kilomita nyingi na maisha ya betri ya miaka mingi. Chukulia takwimu za watengenezaji kuhusu masafa na betri kama malengo ya usanifu badala ya hakikisho.<sup>[[3]](#references)</sup>

Long Range (**LoRa**) ndiyo physical layer ya LPWAN iliyosambazwa zaidi kwa sasa, na vipimo vyake vya MAC-layer vilivyo wazi ni **LoRaWAN**.

---

## LPWAN, LoRa, na LoRaWAN

* LoRa – Physical layer ya Chirp Spread Spectrum (CSS) iliyotengenezwa na Semtech (ni ya wamiliki lakini imeandikwa).
* LoRaWAN – MAC/Network layer iliyo wazi inayodumishwa na LoRa-Alliance. Matoleo 1.0.x na 1.1 yanatumika sana.
* Usanifu wa kawaida: *end-device → gateway (packet-forwarder) → network-server → application-server*.<sup>[[3]](#references)</sup>

> Katika LoRaWAN 1.1, **muundo wa usalama** hutumia root key tofauti za AES-128 za application na network ili kupata session key za kila jukumu wakati wa OTAA. Mifumo ya awali ya 1.0.x kwa kawaida hutumia AppKey moja kupata session key za network na application, ilhali ABP huweka session key moja kwa moja. Uwezo unaopatikana kutokana na key iliyovuja hutegemea toleo la LoRaWAN na key iliyofichuliwa.<sup>[[3]](#references)</sup>

---

## Muhtasari wa sehemu za mashambulizi

| Tabaka | Udhaifu | Athari ya kiutendaji |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | Upotevu wa pakiti katika eneo fulani; ufanisi hutegemea link budget, muda, bandwidth na vikwazo vya udhibiti |
| MAC | Kucheza tena join na data-frame pale hali ya nonce/counter inapotumika tena | Kukosa usawazishaji kwa kifaa, spoofing au injection ikiwa server/kifaa kitakiuka ulinzi dhidi ya replay |
| Network-Server | packet-forwarder isiyo salama, vichujio dhaifu vya MQTT/UDP, firmware ya gateway iliyopitwa na wakati | RCE kwenye gateway → kupenya zaidi kwenye mtandao wa OT/IT |
| Application | AppKey zilizowekwa ndani ya programu au zinazotabirika | Brute-force/decrypt ya trafiki, kujifanya sensa |

---

## Udhaifu wa utekelezaji unaojulikana

* **CVE-2024-29862** – Matoleo ya ChirpStack Gateway Bridge kabla ya 4.0.11 na MQTT Forwarder kabla ya 4.2.1 yaliweza kuunganishwa na MQTT broker inayodhibitiwa na mshambuliaji kwa sababu uthibitishaji wa cheti cha seva cha TLS ulikuwa umezimwa. Hili lingeweza kufichua credentials na trafiki ya gateway; sasisha hadi matoleo yaliyorekebishwa.<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227 inahusu uorodheshaji wa saraka ya `/lib/` bila uthibitishaji, iliyokuwa na faili ya backup inayoweza kupakuliwa; CVE-2022-45228 ni CSRF yenye ukali mdogo kwenye ukurasa wa logout. Rekodi hizi hazithibitishi athari inayodaiwa kwa LG308, kufutwa kwa usanidi, ukubwa wa idadi ya vifaa vilivyoathirika, au hali ya viraka vya 2025.<sup>[[6]](#references)[[7]](#references)</sup>
* Toleo la awali la ukurasa huu lilieleza suala linalodaiwa la Semtech UDP packet-forwarder kama **uplink iliyoundwa kwa makusudi yenye zaidi ya baiti 255 inayosababisha stack smash na RCE kwenye SX130x reference gateway**, likihusishwa na wasilisho la “LoRa Exploitation Reloaded” la Black Hat Europe 2023 na kiraka cha faragha cha Oktoba 2023. Maelezo hayo mahususi yamehifadhiwa hapa kama kidokezo cha utafiti, lakini hakuna ushauri wa umma, wasilisho au kiraka kinacholingana kilichoweza kuthibitishwa. Usichukulie suala hili kuwa udhaifu unaojulikana bila kupata bidhaa/toleo lililoathirika na chanzo cha msingi kinachoweza kuthibitishwa.

---

## Mbinu za mashambulizi za kiutendaji

### 1. Sniff & Decrypt trafiki

```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
    --freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```

Amri hizi huhifadhi mtiririko wa awali kama **sintaksia ya kuonyesha mfano**; mpangilio wa hazina na flags hutofautiana kati ya miradi/toleo. Kunasa bila kutuma hakufichui AppKey imara. Kukisia offline kuna manufaa tu ikiwa root key ni dhaifu kiasi cha kupatikana, na mawasiliano ya join yaliyonaswa yana thamani inayoweza kutumika kuthibitisha wagombea.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. Jaribu ulinzi dhidi ya OTAA replay na hali ya nonce

1. Katika mtandao wa majaribio ulioidhinishwa, nasa **JoinRequest** halali.
2. Rudia ombi lilelile na uthibitishe kuwa network server inakataa `DevNonce` iliyotumika tena.
3. Washa upya au reset kifaa cha majaribio, kisha rudia ukaguzi ili kugundua hali ya nonce iliyopotea. Server inayotii viwango lazima ifuatilie nonce zilizotumika; kurudia JoinRequest pekee hakufichui session keys zilizotokana upya wala kumpa anayerudia udhibiti wa session.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Kushusha kiwango cha Adaptive Data-Rate (ADR)

Mshambulizi anayeweza kuthibitisha network-layer MAC commands—kwa mfano, baada ya kuhatarisha network session key husika au network server—anaweza kujaribu kulazimisha vigezo vya data-rate visivyofaa na kuongeza muda wa hewani. Transmitter iliyo karibu na isiyothibitishwa haiwezi kutoa ADR commands kihalali kwa kujua tu anwani ya kifaa.<sup>[[3]](#references)</sup>

### 4. Kuzuia mawasiliano kwa mawimbi tendaji (reactive jamming)

Reactive jammer inaweza kutuma mawimbi baada ya kutambua preamble ya LoRa na kuvuruga frames maalum. Ukurasa wa awali ulidai kuwa usanidi wa HackRF/GNU Radio ulisababisha kukatika kabisa kwa huduma kwa umbali wa **2 km kwa nguvu isiyozidi 200 mW**, lakini hakuna chanzo cha vipimo kilichotolewa; hifadhi namba hizo kama lengo la kujaribu kuzalisha matokeo, si matokeo yanayotarajiwa. Nguvu ya kutuma inayohitajika, muda, bandwidth, spreading factors zinazoathiriwa na masafa hutegemea mazingira. Jaribu tu ndani ya usanidi ulioidhinishwa unaozuia RF, na uzingatie sheria za masafa za eneo husika.

---

## Zana za offensive (2025)

| Zana | Madhumuni | Maelezo |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Kutengeneza/kuchanganua/kushambulia LoRaWAN frames, analyzers zinazotumia DB, brute-forcer | Docker image; inasaidia ingizo la Semtech UDP<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Zana ya Python ya Trend Micro ya kufanya brute force ya OTAA, kutengeneza downlinks na kusimbua payloads | Zana ya utafiti inayopatikana hadharani; thibitisha maunzi na matoleo ya itifaki inayotumia<sup>[[2]](#references)</sup> |
| **LoRAttack** | Mfumo wa utafiti wa kunasa LoRaWAN ya multi-channel, kuchanganua sessions, kupata keys na kujaribu replay | Imeelezwa katika thesis ya uzamili ya 2024; pata na uthibitishe utekelezaji halisi kabla ya kutegemea flags za mfano<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | Blocks za GNU Radio out-of-tree za kupokea LoRa baseband au kufanya utafiti wa transceiver | Miradi hutofautiana katika uoanifu na GNU Radio na seti ya vipengele<sup>[[9]](#references)</sup> |

---

## Mapendekezo ya kujilinda (orodha ya ukaguzi ya pentester)

1. Pendelea **OTAA** na uthibitishe kuwa vifaa na servers huhifadhi hali ya nonce inayohitajika; fuatilia join zilizokataliwa kwa sababu ya kurudiwa.
2. Pendelea **LoRaWAN 1.1** inapoungwa mkono ili network functions zitumie session keys tofauti na ushughulikiaji wa nonce ulioboreshwa.<sup>[[3]](#references)</sup>
3. Hifadhi frame-counter kwenye memory isiyopoteza data (**ABP**) au hamia OTAA.
4. Tumia **secure element** inayofaa (kwa mfano, ATECC608A katika usanifu unaoiunga mkono) ili kupunguza hatari ya root keys kufichuliwa kwenye hifadhi ya kawaida ya firmware.
5. Usifichue packet-forwarder UDP listeners zilizosanidiwa (mara nyingi 1700) kwa mitandao isiyoaminika; thibitisha/simba kwa njia fiche mawasiliano ya gateway backhaul au uyazuie kwa VPN.
6. Sasisha gateways kwa firmware inayoungwa mkono na vendor, na uthibitishe model/version halisi dhidi ya advisories zinazohusika.
7. Tekeleza **traffic anomaly detection** (kwa mfano, LAF analyzer) – weka alama kwa counter resets, join zinazojirudia na mabadiliko ya ghafla ya ADR.<sup>[[1]](#references)</sup>



## References

- [1] [Mfumo wa Ukaguzi wa LoRaWAN (LAF)](https://github.com/IOActive/laf)
- [2] [Muhtasari wa Trend Micro LoRaPWN](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - Maelezo ya LoRaWAN L2 1.1](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - Vigezo vya kikanda vya LoRaWAN 1.1 na usawazishaji wa join](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [Orodha ya thesis za CTU - Uchambuzi wa Usalama wa Itifaki za LPWAN kwa Kutumia Teknolojia ya SDR](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [Transceiver ya GNU Radio ya EPFL `gr-lora_sdr`](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
