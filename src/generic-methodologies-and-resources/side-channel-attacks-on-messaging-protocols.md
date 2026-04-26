# Mashambulizi ya Side-Channel ya Delivery Receipt katika E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Delivery receipts ni lazima katika messengers za kisasa za end-to-end encrypted (E2EE) kwa sababu clients zinahitaji kujua wakati ciphertext ime-decryptiwa ili ziweze kutupa ratcheting state na ephemeral keys. Server husafirisha opaque blobs, kwa hiyo device acknowledgements (double checkmarks) hutolewa na mpokeaji baada ya decryption kufanikiwa. Kupima round-trip time (RTT) kati ya kitendo kilichochochewa na attacker na delivery receipt inayolingana hufichua high-resolution timing channel inayovuja device state, online presence, na inaweza kutumiwa kwa covert DoS. Multi-device "client-fanout" deployments huongeza uvujaji kwa sababu kila device iliyosajiliwa hu-decrypt probe na kurudisha receipt yake mwenyewe.

## Delivery receipt sources vs. user-visible signals

Chagua message types ambazo kila mara hutoa delivery receipt lakini hazioneshi UI artifacts kwa victim. Jedwali hapa chini linatoa muhtasari wa tabia iliyothibitishwa kimajaribio:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Kila mara ni noisy → inafaa tu kuanzisha state. |
| | Reaction | ● | ◐ (only if reacting to victim message) | Self-reactions na removals hubaki kimya. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; bado ack’d baada ya muda kuisha. |
| | Delete for everyone | ● | ○ | UI huruhusu ~60 h, lakini packets za baadaye bado ack’d. |
| **Signal** | Text message | ● | ● | Vizuizi sawa na WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions hazionekani kwa victim. |
| | Edit/Delete | ● | ○ | Server hutekeleza ~48 h window, huruhusu hadi 10 edits, lakini late packets bado ack’d. |
| **Threema** | Text message | ● | ● | Multi-device receipts huunganishwa, hivyo RTT moja tu kwa kila probe huonekana. |

Legend: ● = always, ◐ = conditional, ○ = never. Tabia ya UI inayotegemea platform imeandikwa ndani ya mstari husika. Zima read receipts ikihitajika, lakini delivery receipts haziwezi kuzimwa katika WhatsApp au Signal.

## Lengo na modeli za attacker

* **G1 – Device fingerprinting:** Hesabu ni receipts ngapi zinafika kwa kila probe, panga RTTs katika clusters ili kudhani OS/client (Android dhidi ya iOS dhidi ya desktop), na ufuatilie mabadiliko ya online/offline.
* **G2 – Behavioural monitoring:** Chukulia mfululizo wa RTT wa juu-frequency (≈1 Hz ni stable) kama time-series na uinfer screen on/off, app foreground/background, commuting vs working hours, n.k.
* **G3 – Resource exhaustion:** Weka radios/CPUs za kila victim device zikiwa macho kwa kutuma silent probes zisizoisha, ukimaliza battery/data na kudhoofisha ubora wa VoIP/RTC.

Threat actors wawili wanatosha kuelezea abuse surface:

1. **Creepy companion:** tayari anashiriki chat na victim na anatumia self-reactions, reaction removals, au repeated edits/deletes zinazohusishwa na existing message IDs.
2. **Spooky stranger:** anasajili burner account na kutuma reactions zikirejelea message IDs ambazo hazikuwahi kuwepo katika local conversation; WhatsApp na Signal bado huzidecrypt na kuzikubali hata kama UI hutupa state change, hivyo hakuna conversation ya awali inayohitajika.

## Tooling ya raw protocol access

Tegemea clients zinazoonyesha underlying E2EE protocol ili uweze kuunda packets nje ya UI constraints, kubainisha `message_id`s za kiholela, na kurekodi timestamps sahihi:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) au [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) hukuruhusu kutoa raw `ReactionMessage`, `ProtocolMessage` (edit/delete), na `Receipt` frames huku ukisynchronise double-ratchet state.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) pamoja na [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) huonyesha kila message type kupitia CLI/API. Mfano wa self-reaction toggle:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** Source ya Android client inaonyesha jinsi delivery receipts huunganishwa kabla ya kutoka kwenye device, ikieleza kwa nini side channel ina bandwidth ndogo sana hapo.
* **Turnkey PoCs:** public projects kama `device-activity-tracker` na `careless-whisper-python` tayari zinaotomatisha silent delete/reaction probes na RTT classification. Zichukulie kama tayari zipo kwa ajili ya reconnaissance badala ya protocol references; sehemu muhimu ni kwamba zinathibitisha attack ni rahisi kiutendaji pindi raw client access inapopatikana.

Wakati custom tooling haipatikani, bado unaweza kuchochea silent actions kutoka WhatsApp Web au Signal Desktop na kunusa encrypted websocket/WebRTC channel, lakini raw APIs huondoa UI delays na kuruhusu invalid operations.

## Creepy companion: silent sampling loop

1. Chagua historical message yoyote uliyoandika mwenyewe katika chat ili victim asione kamwe "reaction" balloons zikibadilika.
2. Badilisha kati ya emoji inayoonekana na empty reaction payload (iliyofungwa kama `""` katika WhatsApp protobufs au `--remove` katika signal-cli). Kila transmission hutoa device ack licha ya kutokuwa na UI delta kwa victim.
3. Weka timestamp ya wakati wa kutuma na kila delivery receipt inavyofika. Loop ya 1 Hz kama ifuatayo hutoa per-device RTT traces bila kikomo:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Kwa sababu WhatsApp/Signal hukubali unlimited reaction updates, attacker hahitaji kamwe kuchapisha content mpya ya chat au kuhangaika na edit windows.

## Spooky stranger: probing arbitrary phone numbers

1. Sajili akaunti mpya ya WhatsApp/Signal na chukua public identity keys kwa namba ya target (hufanyika kiotomatiki wakati wa session setup).
2. Tunga reaction/edit/delete packet inayorejelea random `message_id` ambayo haijawahi kuonekana na upande wowote (WhatsApp hukubali arbitrary `key.id` GUIDs; Signal hutumia millisecond timestamps).
3. Tuma packet hata kama hakuna thread. Victim devices huidecrypt, hushindwa kuoanisha base message, hutupa state change, lakini bado huacknowledge ciphertext inayoingia, na kutuma device receipts kurudi kwa attacker.
4. Rudia mfululizo ili kujenga RTT series bila kuonekana hata kidogo katika chat list ya victim.

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** Baada ya message kufutwa-for-everyone mara moja, delete packets zaidi zinazorejelea hiyo hiyo `message_id` hazina athari ya UI lakini kila device bado hui-decrypt na kui-acknowledge.
* **Out-of-window operations:** WhatsApp hutekeleza ~60 h delete / ~20 min edit windows katika UI; Signal hutekeleza ~48 h. Crafted protocol messages nje ya windows hizi hupuuzwa kimya kwenye victim device lakini receipts hutumwa, hivyo attackers wanaweza kuprobe kwa muda mrefu hata baada ya conversation kuisha.
* **Invalid payloads:** Malformed edit bodies au deletes zinazorejelea messages zilizokwisha purged huleta tabia ile ile—decryption pamoja na receipt, zero user-visible artefacts.

## Multi-device amplification & fingerprinting

* Kila device iliyounganishwa (phone, desktop app, browser companion) hu-decrypt probe kwa kujitegemea na kurudisha ack yake. Kuhesabu receipts kwa kila probe hufichua idadi halisi ya devices.
* Ikiwa device iko offline, receipt yake huwekwa kwenye queue na kutumwa inapounganishwa tena. Kwa hiyo gaps huvuja online/offline cycles na hata commuting schedules (kwa mfano, desktop receipts husimama wakati wa travel).
* RTT distributions hutofautiana kulingana na platform kwa sababu ya OS power management na push wakeups. Panga RTTs katika clusters (kwa mfano, k-means kwenye median/variance features) ili ku-label “Android handset", “iOS handset", “Electron desktop", n.k.
* Kwa sababu sender lazima apate key inventory ya recipient kabla ya ku-encrypt, attacker pia anaweza kuona wakati new devices zina-pair; ongezeko la ghafla la idadi ya devices au new RTT cluster ni kiashirio kikubwa.

## Behaviour inference kutoka RTT traces

1. Sampulia kwa ≥1 Hz ili kunasa OS scheduling effects. Kwa WhatsApp kwenye iOS, RTTs <1 s huonyesha uwiano mkubwa na screen-on/foreground, >1 s na screen-off/background throttling.
2. Jenga classifiers rahisi (thresholding au two-cluster k-means) zinazo- label kila RTT kama "active" au "idle". Unganisha labels kuwa streaks ili kupata bedtimes, commutes, work hours, au wakati desktop companion iko active.
3. Linganisha simultaneous probes kuelekea kila device ili kuona wakati users wanabadilika kutoka mobile kwenda desktop, wakati companions wanaenda offline, na kama app imewekewa rate limit na push dhidi ya persistent socket.

## Location inference from delivery RTT

Teknolojia hiyo hiyo ya timing inaweza kutumiwa upya ili kudhani recipient yuko wapi, si tu kama wanafanya kazi. Kazi ya `Hope of Delivery` ilionyesha kwamba mafunzo juu ya RTT distributions kwa receiver locations vinavyojulikana huruhusu attacker baadaye ku-classify location ya victim kutoka delivery confirmations pekee:

* Jenga baseline kwa target yuleyule wakiwa katika maeneo kadhaa yanayojulikana (home, office, campus, country A dhidi ya country B, n.k.).
* Kwa kila location, kusanya normal message RTTs nyingi na toa features rahisi kama median, variance, au percentile buckets.
* Wakati wa attack halisi, linganisha series mpya ya probe dhidi ya clusters zilizofunzwa. Karatasi inaripoti kwamba hata locations ndani ya mji mmoja mara nyingi zinaweza kutenganishwa, kwa usahihi wa `>80%` katika setting ya locations 3.
* Hii hufanya kazi vizuri zaidi wakati attacker anadhibiti sender environment na anaprobe chini ya similar network conditions, kwa sababu njia iliyopimwa inajumuisha recipient access network, wake-up latency, na messenger infrastructure.

Tofauti na silent reaction/edit/delete attacks hapo juu, location inference haihitaji invalid message IDs au stealthy state-changing packets. Plain messages zenye normal delivery confirmations zinatosha, kwa hiyo tradeoff ni stealth ndogo lakini applicability pana zaidi katika messengers.

## Stealthy resource exhaustion

Kwa sababu kila silent probe lazima i-decryptiwe na ku-acknowledgeiwa, kutuma mfululizo reaction toggles, invalid edits, au delete-for-everyone packets huleta application-layer DoS:

* Hulazimisha radio/modem kutuma/kupokea kila sekunde → battery drain inayoonekana, hasa kwenye handsets zisizotumika.
* Huzalisha upstream/downstream traffic isiyo-metered inayotumia mobile data plans huku ikichanganyika na TLS/WebSocket noise.
* Hushikilia crypto threads na kuanzisha jitter katika latency-sensitive features (VoIP, video calls) hata ingawa user haoni notifications kamwe.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)

{{#include ../banners/hacktricks-training.md}}
