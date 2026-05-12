# Mashambulizi ya Side-Channel ya Delivery Receipt katika E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Delivery receipts ni lazima katika messengers za kisasa za end-to-end encrypted (E2EE) kwa sababu clients zinahitaji kujua lini ciphertext ilidecryptiwa ili ziweze kutupa ratcheting state na ephemeral keys. Server husambaza opaque blobs, kwa hiyo device acknowledgements (double checkmarks) hutolewa na mpokeaji baada ya decryption kufanikiwa. Kupima round-trip time (RTT) kati ya kitendo kilichoanzishwa na attacker na delivery receipt inayolingana kunaweka wazi high-resolution timing channel inayoleak device state, online presence, na inaweza kutumiwa kwa covert DoS. Multi-device "client-fanout" deployments huongeza leak sababu kila device iliyosajiliwa hudecrypt probe na kurudisha receipt yake.

## Delivery receipt sources vs. user-visible signals

Chagua aina za message ambazo daima hutoa delivery receipt lakini hazionyeshi UI artifacts kwa victim. Jedwali hapa chini linafupisha tabia iliyothibitishwa kwa majaribio:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Daima noisy → ni muhimu tu kubootstrap state. |
| | Reaction | ● | ◐ (only if reacting to victim message) | Self-reactions na removals hubaki kimya. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20min; bado ack’d baada ya kuisha. |
| | Delete for everyone | ● | ○ | UI huruhusu ~60 h, lakini packets za baadaye bado ack’d. |
| **Signal** | Text message | ● | ● | Mapungufu sawa na WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions hazionekani kwa victim. |
| | Edit/Delete | ● | ○ | Server hutekeleza ~48 h window, huruhusu hadi edits 10, lakini late packets bado ack’d. |
| **Threema** | Text message | ● | ● | Multi-device receipts huunganishwa, kwa hiyo RTT moja tu kwa kila probe huonekana. |

Legend: ● = always, ◐ = conditional, ○ = never. Tabia ya UI inayotegemea platform imeandikwa ndani ya mstari husika. Zima read receipts ikihitajika, lakini delivery receipts haziwezi kuzimwa katika WhatsApp au Signal.

## Malengo ya attacker na models

* **G1 – Device fingerprinting:** Hesabu receipts wangapi wanakuja kwa kila probe, cluster RTTs ili infer OS/client (Android vs iOS vs desktop), na fuatilia mabadiliko ya online/offline.
* **G2 – Behavioural monitoring:** Tumia high-frequency RTT series (≈1 Hz ni stable) kama time-series na infer screen on/off, app foreground/background, commuting vs working hours, n.k.
* **G3 – Resource exhaustion:** Weka radios/CPUs za kila victim device zikiwa awake kwa kutuma silent probes zisizoisha, ukimaliza battery/data na kudhoofisha ubora wa VoIP/RTC.

Wahusika wawili wa threat wanatosha kuelezea surface ya matumizi mabaya:

1. **Creepy companion:** tayari anashiriki chat na victim na hutumia self-reactions, reaction removals, au repeated edits/deletes zilizounganishwa na existing message IDs.
2. **Spooky stranger:** anasajili burner account na kutuma reactions zinazonukuu message IDs ambazo hazijawahi kuwepo kwenye local conversation; WhatsApp na Signal bado huzidecrypt na kuzikubali hata kama UI hutupa state change, kwa hiyo conversation ya awali haihitajiki.

## Tooling kwa raw protocol access

Tegemea clients zinazoonyesha underlying E2EE protocol ili uweze kuunda packets nje ya UI constraints, kubainisha `message_id`s za kiholela, na kuhifadhi precise timestamps:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) au [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) hukuruhusu kutoa raw `ReactionMessage`, `ProtocolMessage` (edit/delete), na `Receipt` frames huku ukidumisha double-ratchet state in sync.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) pamoja na [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) huonyesha kila message type kupitia CLI/API. Syntax ya sasa ya `signal-cli` hutumia `sendReaction RECIPIENT --target-author --target-timestamp`; weka `receive` au `daemon` ikiendelea ili delivery receipts zikamatwe kweli. Mfano wa self-reaction toggle:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Source ya Android client inaonyesha jinsi delivery receipts huunganishwa kabla ya kuondoka kwenye device, ikieleza kwa nini side channel ina bandwidth ndogo sana hapo.
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) huja na WhatsApp/Signal backends, huweka silent delete probes kwa chaguo la msingi, na huweka alama `active` vs `standby` kwa rolling-median threshold (`RTT < 0.9 * median`). [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) ni CLI nyepesi ya WhatsApp-first yenye `--delay`, `--concurrent`, CSV/Prometheus exporters, na output inayofaa Grafana. Chukulia zote mbili kama reconnaissance helpers badala ya protocol references; jambo muhimu ni jinsi code ndogo inavyotosha mara tu raw client access inapatikana.

Kama custom tooling haipatikani, bado unaweza kuchochea silent actions kutoka WhatsApp Web au Signal Desktop na kunusa encrypted websocket/WebRTC channel, lakini raw APIs huondoa UI delays na huruhusu invalid operations.

## Creepy companion: silent sampling loop

1. Chagua message yoyote ya kihistoria ambayo uliiandika wewe mwenyewe katika chat ili victim asione balloon za "reaction" zikibadilika.
2. Badilisha kati ya emoji inayoonekana na empty reaction payload (iliyowekwa kama `""` katika WhatsApp protobufs au `--remove` katika signal-cli). Kila transmission hutoa device ack licha ya hakuna UI delta kwa victim.
3. Weka timestamp ya muda wa kutuma na arrival ya kila delivery receipt. 1 Hz loop kama ifuatayo inatoa per-device RTT traces bila kikomo:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Kwa kuwa WhatsApp/Signal hukubali reaction updates zisizo na kikomo, attacker hahitaji kamwe kuchapisha content mpya ya chat wala kuogopa edit windows.

## Spooky stranger: probing arbitrary phone numbers

1. Sajili WhatsApp/Signal account mpya na fetch public identity keys kwa nambari lengwa (hufanyika kiotomatiki wakati wa session setup).
2. Tengeneza reaction/edit/delete packet inayoreference random `message_id` ambayo haijawahi kuonekana na upande wowote (WhatsApp hukubali arbitrary `key.id` GUIDs; Signal hutumia millisecond timestamps).
3. Tuma packet hata kama hakuna thread. Victim devices hui decrypt, hushindwa kulinganisha base message, hutupa state change, lakini bado huack incoming ciphertext, zikirejesha device receipts kwa attacker.
4. Rudia mfululizo ili kuunda RTT series bila kuonekana kamwe katika chat list ya victim.

Ukiwa kwanza unahitaji kugundua ni nambari zipi zimesajiliwa au unataka pre-seed device inventories kwa kiwango kikubwa, unganisha hili na [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) badala ya kubahatisha random E.164 ranges kwa mkono.

Recent WhatsApp builds pia hufichua `Settings -> Privacy -> Advanced -> Block unknown account messages`. Ichukulie kama throughput limiter, si fix: hasa huathiri sustained stranger-only flooding na haina umuhimu tena mara tu unapokuwa tayari ni known contact.

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** Baada ya message kufutwa-for-everyone mara moja, delete packets zaidi zinazoreference same `message_id` hazina athari ya UI lakini kila device bado hudecrypt na kuack.
* **Out-of-window operations:** WhatsApp hutekeleza ~60 h delete / ~20 min edit windows kwenye UI; Signal hutekeleza ~48 h. Crafted protocol messages nje ya windows hizi hupuuzwa kimya kwenye victim device lakini receipts hutumwa, kwa hiyo attackers wanaweza kuprobe kwa muda mrefu baada ya conversation kuisha.
* **Invalid payloads:** Malformed edit bodies au deletes zinazoreference messages ambazo tayari zimepurged huleta tabia ile ile—decryption plus receipt, hakuna artefacts zinazoonekana kwa user.

## Multi-device amplification & fingerprinting

* Kila device iliyounganishwa (phone, desktop app, browser companion) hudecrypt probe kwa kujitegemea na kurudisha ack yake yenyewe. Kuhesabu receipts kwa kila probe hufichua exact device count.
* Ikiwa device iko offline, receipt yake huwekwa kwenye queue na hutumwa pindi inaporeconnect. Kwa hiyo gaps hu leak online/offline cycles na hata commuting schedules (mfano, desktop receipts huacha wakati wa kusafiri).
* RTT distributions hutofautiana kulingana na platform kutokana na OS power management na push wakeups. Cluster RTTs (mfano, k-means kwenye median/variance features) ili kuweka lebo “Android handset", “iOS handset", “Electron desktop", n.k.
* Kwa kuwa sender lazima apate key inventory ya recipient kabla ya encrypting, attacker anaweza pia kuona lini devices mpya zinaunganishwa; ongezeko la ghafla la device count au new RTT cluster ni kiashiria chenye nguvu.

## Behaviour inference from RTT traces

1. Sampuli kwa ≥1 Hz ili kunasa OS scheduling effects. Kwa WhatsApp kwenye iOS, RTTs za <1 s zina correlation kali na screen-on/foreground, >1 s na screen-off/background throttling.
2. Jenga classifiers rahisi (thresholding au two-cluster k-means) zinazoita kila RTT "active" au "idle". Kusanya labels kuwa streaks ili kutoa bedtimes, commutes, work hours, au wakati desktop companion iko active.
3. Correlate probes za wakati mmoja kwenda kila device ili kuona wakati users wanabadilika kutoka mobile kwenda desktop, wakati companions wanaenda offline, na kama app imewekewa rate limit na push vs persistent socket.
4. Kwenye networks za kweli, epuka `1 s` threshold moja iliyo hardcoded. Bootstrapa kila device kwa short warm-up window na endelea na rolling baseline (kwa mfano, `threshold = 0.9 * median RTT`) ili Wi-Fi/cellular drift isivunje classifier yako.

## Location inference from delivery RTT

The same timing primitive inaweza kutumiwa upya ili infer victim yuko wapi, si tu kama wako active. Kazi ya `Hope of Delivery` ilionyesha kuwa kufundisha juu ya RTT distributions kwa known receiver locations huruhusu attacker baadaye kuclassify location ya victim kutoka delivery confirmations pekee:

* Tengeneza baseline kwa target yuleyule wakiwa katika maeneo kadhaa yanayojulikana (home, office, campus, nchi A vs nchi B, n.k.).
* Kwa kila location, kusanya normal message RTTs nyingi na toa features rahisi kama median, variance, au percentile buckets.
* Wakati wa attack halisi, linganisha new probe series dhidi ya trained clusters. Karatasi inaripoti kuwa hata locations ndani ya mji mmoja mara nyingi zinaweza kutenganishwa, kwa usahihi wa `>80%` katika setting ya locations 3.
* Hii hufanya kazi vizuri zaidi wakati attacker anadhibiti sender environment na huprobe chini ya network conditions zinazofanana, kwa sababu path inayopimwa inajumuisha recipient access network, wake-up latency, na messenger infrastructure.

Tofauti na silent reaction/edit/delete attacks hapo juu, location inference haihitaji invalid message IDs au stealthy state-changing packets. Plain messages zenye normal delivery confirmations zinatosha, kwa hiyo tradeoff ni stealth ndogo lakini applicability pana zaidi katika messengers.

## Stealthy resource exhaustion

Kwa kuwa kila silent probe lazima idecryptiwa na kuacknowledged, kutuma reaction toggles, invalid edits, au delete-for-everyone packets mfululizo kunaunda application-layer DoS:

* Hulazimisha radio/modem kutuma/kupokea kila sekunde → battery drain inayoonekana, hasa kwenye idle handsets.
* Huzalisha upstream/downstream traffic isiyopimwa ambayo hutumia mobile data plans huku ikichanganyika na TLS/WebSocket noise.
* Huchukua crypto threads na kuingiza jitter kwenye latency-sensitive features (VoIP, video calls) ingawa user haoni notifications.
* Kwenye WhatsApp, invalid reactions hukubali data nyingi zaidi kuliko emoji ya kawaida inavyodokeza: measurements zilizochapishwa zilipata acceptance ya server-side hadi takriban `1 MB` kwa kila reaction.
* Oversized reactions huacha kutoa delivery receipts za kuaminika mara tu body inapozidi takriban `30 bytes`, lakini bado husambazwa na kuchakatwa kabla ya kutupwa. Weka reaction bodies ndogo unapohitaji ACKs; zikuze tu wakati lengo ni pure drain au covert one-way transport.
* Measurements za umma zilifikia takriban `3.7 MB/s` (`~13.3 GB/h`) ya victim traffic katika mode hii.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)

{{#include ../banners/hacktricks-training.md}}
