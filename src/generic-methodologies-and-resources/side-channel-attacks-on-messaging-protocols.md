# Mashambulizi ya Side-Channel ya Delivery Receipt katika E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Delivery receipts ni lazima katika messengers za kisasa za end-to-end encrypted (E2EE) kwa sababu clients zinahitaji kujua wakati ciphertext ilipodecrypted ili ziweze kutupa ratcheting state na ephemeral keys. Server husafirisha opaque blobs, hivyo device acknowledgements (double checkmarks) hutolewa na mpokeaji baada ya decryption kufanikiwa. Kupima round-trip time (RTT) kati ya hatua iliyochochewa na attacker na delivery receipt inayolingana hufichua high-resolution timing channel ambayo leak device state, online presence, na inaweza kutumiwa kwa covert DoS. Multi-device "client-fanout" deployments huongeza leak kwa sababu kila device iliyosajiliwa hufanya decrypt ya probe na kurudisha receipt yake yenyewe.

## Delivery receipt sources vs. user-visible signals

Chagua message types ambazo kila mara hutuma delivery receipt lakini hazionyeshi UI artifacts kwa victim. Jedwali hapa chini linafupisha tabia iliyothibitishwa kimajaribio:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Kila mara ni noisy → hufaa tu kwa kuanzisha state. |
| | Reaction | ● | ◐ (only if reacting to victim message) | Self-reactions na removals hubaki kimya. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; bado ack’d baada ya kuisha muda. |
| | Delete for everyone | ● | ○ | UI huruhusu ~60 h, lakini packets za baadaye bado ack’d. |
| **Signal** | Text message | ● | ● | Vizuizi sawa na WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions hazionekani kwa victim. |
| | Edit/Delete | ● | ○ | Server hutekeleza ~48 h window, huruhusu hadi 10 edits, lakini late packets bado ack’d. |
| **Threema** | Text message | ● | ● | Multi-device receipts huunganishwa, hivyo RTT moja tu kwa kila probe huonekana. |

Legend: ● = always, ◐ = conditional, ○ = never. Platform-dependent tabia ya UI imeandikwa ndani ya mstari husika. Zima read receipts ikiwa inahitajika, lakini delivery receipts haziwezi kuzimwa katika WhatsApp au Signal.

## Malengo ya attacker na models

* **G1 – Device fingerprinting:** Hesabu ni receipts ngapi zinawasili kwa kila probe, cluster RTTs ili kubaini OS/client (Android vs iOS vs desktop), na kufuatilia online/offline transitions.
* **G2 – Behavioural monitoring:** Chukulia high-frequency RTT series (≈1 Hz ni stable) kama time-series na utabiri screen on/off, app foreground/background, commuting vs working hours, n.k.
* **G3 – Resource exhaustion:** Weka radios/CPUs za kila victim device zikiendelea kuwa awake kwa kutuma silent probes zisizoisha, ukimaliza battery/data na kushusha ubora wa VoIP/RTC.

Threat actors wawili wanatosha kueleza abuse surface:

1. **Creepy companion:** tayari anashiriki chat na victim na anatumia self-reactions, reaction removals, au repeated edits/deletes zinazohusishwa na existing message IDs.
2. **Spooky stranger:** anasajili burner account na kutuma reactions zinazorejelea message IDs ambazo hazikuwepo kamwe kwenye local conversation; WhatsApp na Signal bado huzidecrypt na kuzacknowledge ingawa UI hutupa state change, hivyo hakuna haja ya kuwa na mazungumzo ya awali.

## Tooling ya raw protocol access

Tegemea clients zinazoonyesha underlying E2EE protocol ili uweze kutengeneza packets nje ya UI constraints, kubainisha `message_id`s za kiholela, na kurekodi timestamps kwa usahihi:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) au [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) hukuruhusu kutuma raw `ReactionMessage`, `ProtocolMessage` (edit/delete), na `Receipt` frames huku ukidumisha double-ratchet state kwenye sync.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) ikichanganywa na [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) hufichua kila message type kupitia CLI/API. Syntax ya sasa ya `signal-cli` hutumia `sendReaction RECIPIENT --target-author --target-timestamp`; endelea kuendesha `receive` au `daemon` ili delivery receipts zikikusanywe kweli. Mfano wa self-reaction toggle:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Source ya Android client inaeleza jinsi delivery receipts huunganishwa kabla hazijatoka kwenye device, ikieleza kwa nini side channel ina bandwidth ndogo sana hapo.
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) inakuja na WhatsApp/Signal backends, kwa chaguo-msingi hutumia silent delete probes, na huweka lebo `active` vs `standby` kwa rolling-median threshold (`RTT < 0.9 * median`). [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) ni CLI nyepesi ya WhatsApp-first yenye `--delay`, `--concurrent`, CSV/Prometheus exporters, na output inayofaa Grafana. Chukulia zote mbili kama reconnaissance helpers badala ya protocol references; takeaway muhimu ni jinsi code kidogo inavyotosha mara tu raw client access inapopatikana.

Wakati custom tooling haipatikani, bado unaweza kuchochea silent actions kutoka WhatsApp Web au Signal Desktop na kunusa encrypted websocket/WebRTC channel, lakini raw APIs huondoa UI delays na huruhusu invalid operations.

## Creepy companion: silent sampling loop

1. Chagua historical message yoyote uliyoituma mwenyewe kwenye chat ili victim asione kamwe "reaction" balloons zikibadilika.
2. Badilisha kati ya emoji inayoonekana na empty reaction payload (iliyosimbwa kama `""` katika WhatsApp protobufs au `--remove` katika signal-cli). Kila transmission hutoa device ack licha ya kuwa hakuna UI delta kwa victim.
3. Weka timestamp ya send time na kila delivery receipt arrival. Loop ya 1 Hz kama ifuatayo hutoa per-device RTT traces bila kikomo:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Kwa sababu WhatsApp/Signal hukubali unlimited reaction updates, attacker hahitaji kamwe kutuma chat content mpya au kuogopa edit windows.

## Spooky stranger: probing arbitrary phone numbers

1. Sajili WhatsApp/Signal account mpya na upate public identity keys kwa target number (hufanyika kiotomatiki wakati wa session setup).
2. Tunga reaction/edit/delete packet inayorejelea `message_id` ya kubahatisha ambayo haijawahi kuonekana na pande zote mbili (WhatsApp hukubali arbitrary `key.id` GUIDs; Signal hutumia millisecond timestamps).
3. Tuma packet hata kama hakuna thread. Victim devices hui decrypt, hushindwa kulinganisha base message, hutupa state change, lakini bado huacknowledge incoming ciphertext, na kutuma device receipts kurudi kwa attacker.
4. Rudia mfululizo ili kujenga RTT series bila kamwe kuonekana kwenye chat list ya victim.

Ikiwa kwanza unahitaji kujua ni nambari zipi zimesajiliwa au unataka kuandaa device inventories kwa kiwango kikubwa, unganisha hili na [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) badala ya kukisia E.164 ranges kwa mkono.

Utafiti uliochapishwa wa contact-discovery ulionyesha kwa nini hii ni muhimu kiutendaji: kwa phone-prefix tables sahihi na resources za wastani, watafiti waliweza kuuliza takriban `10%` ya US mobile numbers kwenye WhatsApp na `100%` kwenye Signal kabla ya kuendelea na targeted probing. Kivitendo, kuchuja kwanza live accounts huweka silent-probe budget yako ikilenga nambari ambazo kwa kweli zitadecrypt packets.

Recent WhatsApp builds pia hufichua `Settings -> Privacy -> Advanced -> Block unknown account messages`. Chukulia kama throughput limiter, si fix: hasa huumiza sustained stranger-only flooding na haina umuhimu mara tu unapokuwa tayari ni known contact.

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** Baada ya message kufutwa-for-everyone mara moja, delete packets zaidi zinazorejelea same `message_id` hazina UI effect lakini kila device bado huzidecrypt na kuziacknowledge.
* **Out-of-window operations:** WhatsApp hutekeleza ~60 h delete / ~20 min edit windows kwenye UI; Signal hutekeleza ~48 h. Crafted protocol messages nje ya windows hizi hupuuzwa kimya kimya kwenye victim device lakini receipts hutumwa, hivyo attackers wanaweza kuprobe muda mrefu hata baada ya conversation kumalizika.
* **Invalid payloads:** Malformed edit bodies au deletes zinazorejelea messages ambazo tayari zimepurged huleta tabia ile ile—decryption pamoja na receipt, zero user-visible artefacts.

## Multi-device amplification & fingerprinting

* Kila associated device (phone, desktop app, browser companion) huidecrypt probe kivyake na kurudisha ack yake yenyewe. Kuhesabu receipts kwa kila probe hufichua exact device count.
* Ikiwa device iko offline, receipt yake huwekwa kwenye queue na kutumwa baada ya reconnect. Hivyo gaps hufichua online/offline cycles na hata commuting schedules (kwa mfano, desktop receipts husimama wakati wa safari).
* RTT distributions hutofautiana kwa platform kutokana na OS power management na push wakeups. Cluster RTTs (kwa mfano, k-means kwenye median/variance features) ili kuweka lebo “Android handset", “iOS handset", “Electron desktop", n.k.
* Kwa sababu sender lazima apate recipient key inventory kabla ya encryption, attacker pia anaweza kuona wakati devices mpya zinaunganishwa; ongezeko la ghafla la device count au new RTT cluster ni indicator yenye nguvu.

## Sampling cadence, queueing, and stacked receipts

* **WhatsApp burst tolerance:** Vipimo vilivyochapishwa viliripoti kuwa WhatsApp ilikubali silent-reaction bursts kwa kasi ya probe moja kila `50 ms` bila queueing ya wazi upande wa server. Hiyo ni muhimu kwa short calibration bursts, fast device counting, au kuongeza kasi ya drain attack.
* **Signal long-run queueing:** Signal ilistahimili short bursts lakini ikaanza kuqueue sustained multi-probe-per-second traffic. Kwa monitoring ya muda mrefu, weka cadence karibu `1 Hz` (au chini) ili kila receipt bado ionyeshe current device state badala ya backlog drain.
* **Reconnect artefacts:** Wakati device inarudi online, baadhi ya clients hu-batch au kwa haraka flush delayed receipts nyingi. Chukulia bursts hizo za receipts kama state-transition marker badala ya samples huru za RTT, au clustering / `active` vs `idle` classifier yako ita-overfit reconnect noise.

## Behaviour inference from RTT traces

1. Sampuli kwa ≥1 Hz ili kunasa OS scheduling effects. Kwa WhatsApp kwenye iOS, RTTs za <1 s zina uhusiano mkubwa na screen-on/foreground, >1 s na screen-off/background throttling.
2. Tengeneza simple classifiers (thresholding au two-cluster k-means) zinazoita kila RTT "active" au "idle". Unganisha labels kuwa streaks ili kubaini bedtimes, commutes, work hours, au wakati desktop companion iko active.
3. Linganisha probes za wakati mmoja kuelekea kila device ili kuona wakati users wanabadilika kutoka mobile kwenda desktop, wakati companions zinaenda offline, na kama app inapunguzwa kasi na push dhidi ya persistent socket.
4. Katika mitandao halisi, epuka hardcoded `1 s` threshold moja. Bootstrap kila device kwa short warm-up window na weka rolling baseline (kwa mfano, `threshold = 0.9 * median RTT`) ili Wi-Fi/cellular drift isiharibu classifier yako.

## Location inference from delivery RTT

Primitives ile ile ya timing inaweza kutumiwa upya kubaini mpokeaji yuko wapi, si tu kama yuko active. Utafiti wa `Hope of Delivery` ulionyesha kwamba mafunzo juu ya RTT distributions kwa known receiver locations huruhusu attacker baadaye kuclassify location ya victim kutoka delivery confirmations pekee:

* Tengeneza baseline kwa target yule yule akiwa sehemu kadhaa zinazojulikana (home, office, campus, country A vs country B, n.k.).
* Kwa kila location, kusanya normal message RTTs nyingi na utoe features rahisi kama median, variance, au percentile buckets.
* Wakati wa attack halisi, linganisha mfululizo mpya wa probes dhidi ya trained clusters. Karatasi inaripoti kwamba hata locations ndani ya city moja mara nyingi zinaweza kutofautishwa, kwa usahihi wa `>80%` katika setting ya maeneo 3.
* Hii hufanya kazi vizuri zaidi wakati attacker anadhibiti sender environment na anaprobes chini ya network conditions zinazofanana, kwa sababu path iliyopimwa inajumuisha recipient access network, wake-up latency, na messenger infrastructure.

Tofauti na silent reaction/edit/delete attacks hapo juu, location inference haihitaji invalid message IDs au stealthy state-changing packets. Plain messages zenye normal delivery confirmations zinatosha, hivyo tradeoff ni stealth ndogo lakini matumizi mapana zaidi kwa messengers.

## Stealthy resource exhaustion

Kwa sababu kila silent probe lazima idecrypted na kuacknowledged, kutuma reaction toggles, invalid edits, au delete-for-everyone packets mfululizo huunda application-layer DoS:

* Hulazimisha radio/modem kutuma/kupokea kila sekunde → battery drain inayoonekana, hasa kwenye idle handsets.
* Hutengeneza unmetered upstream/downstream traffic inayotumia mobile data plans huku ikichanganyika na TLS/WebSocket noise.
* Huchukua crypto threads na kuleta jitter kwenye features zinazotegemea latency (VoIP, video calls) hata kama user haoni notifications.
* Kwenye WhatsApp, invalid reactions hukubali data nyingi zaidi kuliko emoji ya kawaida inavyodokeza: vipimo vilivyochapishwa vilipata server-side acceptance hadi takriban `1 MB` kwa kila reaction.
* Oversized reactions huacha kutoa delivery receipts za kuaminika mara body inapokua zaidi ya takriban `30 bytes`, lakini bado husafirishwa na kushughulikiwa kabla ya kutupwa. Weka reaction bodies ndogo unapohitaji ACKs; ziweke kubwa tu wakati lengo ni pure drain au covert one-way transport.
* Vipimo vya umma vilifikia takriban `3.7 MB/s` (`~13.3 GB/h`) ya victim traffic katika mode hii.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [All the Numbers are US: Large-scale Abuse of Contact Discovery in Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
