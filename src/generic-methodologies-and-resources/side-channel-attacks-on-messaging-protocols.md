# Mashambulizi ya Side-Channel ya Delivery Receipt katika E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Delivery receipts ni lazima katika E2EE messengers za kisasa kwa sababu clients zinahitaji kujua wakati ciphertext ilipodecryptiwa ili ziweze kutupa ratcheting state na ephemeral keys. Server inasambaza opaque blobs, kwa hiyo device acknowledgements (double checkmarks) hutumwa na recipient baada ya decryption kufanikiwa. Kupima round-trip time (RTT) kati ya action iliyoanzishwa na attacker na delivery receipt inayolingana hufichua timing channel yenye resolution ya juu inayoleak hali ya device, uwepo online, na inaweza kutumiwa kwa covert DoS. Deployments za multi-device za aina ya "client-fanout" huongeza leakage kwa sababu kila device iliyosajiliwa inadecrypt probe na kutuma receipt yake.<sup>[[1]](#references)</sup>

## Vyanzo vya delivery receipt dhidi ya signals zinazoonekana kwa mtumiaji

Chagua aina za messages ambazo hutuma delivery receipt kila mara lakini hazionyeshi UI artifacts kwa victim. Jedwali lililo hapa chini linatoa muhtasari wa tabia iliyothibitishwa kwa majaribio:<sup>[[1]](#references)</sup>

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Huleta kelele kila mara → ni muhimu tu kwa kuanzisha state. |
| | Reaction | ● | ◐ (ikiwa tu reacting to victim message) | Self-reactions na removals hubaki kimya. |
| | Edit | ● | Silent push inayotegemea platform | Edit window ≈20 min; bado ina-ack baada ya expiry. |
| | Delete for everyone | ● | ○ | UI inaruhusu ~60 h, lakini packets za baadaye bado zina-ack. |
| **Signal** | Text message | ● | ● | Ina limitations sawa na WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions hazionekani kwa victim. |
| | Edit/Delete | ● | ○ | Server inalazimisha window ya ~48 h, inaruhusu edits hadi 10, lakini packets zilizochelewa bado zina-ack. |
| **Threema** | Text message | ● | ● | Multi-device receipts zina-aggregated, kwa hiyo RTT moja tu kwa kila probe huonekana. |

Legend: ● = kila mara, ◐ = kwa masharti, ○ = kamwe. Tabia ya UI inayotegemea platform imeonyeshwa ndani ya jedwali. Zima read receipts ikihitajika, lakini delivery receipts haziwezi kuzimwa katika WhatsApp au Signal.<sup>[[1]](#references)</sup>

## Malengo na models za attacker

* **G1 – Device fingerprinting:** Hesabu receipts ngapi zinawasili kwa kila probe, cluster RTTs ili kubaini OS/client (Android dhidi ya iOS au desktop), na fuatilia mabadiliko ya online/offline.
* **G2 – Behavioural monitoring:** Chukulia mfululizo wa RTT wa frequency ya juu (≈1 Hz ni stable) kama time-series na infer screen on/off, app foreground/background, muda wa kusafiri dhidi ya muda wa kazi, n.k.
* **G3 – Resource exhaustion:** Weka radios/CPUs za kila victim device zikiwa active kwa kutuma silent probes zisizoisha, ukimaliza battery/data na kushusha ubora wa VoIP/RTC.<sup>[[1]](#references)</sup>

Threat actors wawili wanatosha kueleza abuse surface:<sup>[[1]](#references)</sup>

1. **Creepy companion:** Tayari anashiriki chat na victim na anatumia vibaya self-reactions, reaction removals, au edits/deletes zinazorudiwa zinazohusishwa na message IDs zilizopo.
2. **Spooky stranger:** Anasajili burner account na kutuma reactions zinazorejelea message IDs ambazo hazijawahi kuwepo katika local conversation; WhatsApp na Signal bado huzidecrypt na kuzikubali hata UI inapotupa state change, kwa hiyo conversation ya awali haihitajiki.

## Tooling ya raw protocol access

Tegemea clients zinazofichua E2EE protocol ya msingi ili uweze kutengeneza packets nje ya UI constraints, kubainisha `message_id`s za kiholela, na kurekodi timestamps sahihi:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) au [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) hukuruhusu kutuma raw `ReactionMessage`, `ProtocolMessage` (edit/delete), na `Receipt` frames huku ukiweka double-ratchet state katika sync.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) pamoja na [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) hufichua kila message type kupitia CLI/API.<sup>[[5]](#references)[[7]](#references)</sup> Syntax ya sasa ya `signal-cli` hutumia `sendReaction RECIPIENT --target-author --target-timestamp`; endelea kuendesha `receive` au `daemon` ili delivery receipts zikusanywe kwa kweli.<sup>[[6]](#references)</sup> Mfano wa self-reaction toggle:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Source ya Android client inaeleza jinsi delivery receipts zinavyounganishwa kabla hazijaondoka kwenye device, ikifafanua kwa nini side channel ina bandwidth ndogo sana hapo.<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) inakuja na WhatsApp/Signal backends, kwa default hutumia silent delete probes, na huweka labels za `active` dhidi ya `standby` kwa rolling-median threshold (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) ni CLI nyepesi inayolenga WhatsApp, yenye `--delay`, `--concurrent`, CSV/Prometheus exporters, na output inayofaa Grafana.<sup>[[9]](#references)</sup> Zichukulie zote mbili kama reconnaissance helpers badala ya protocol references; jambo muhimu ni jinsi code kidogo inavyohitajika mara raw client access inapopatikana.

Custom tooling isipopatikana, bado unaweza kuanzisha silent actions kutoka WhatsApp Web au Signal Desktop na kusniff encrypted websocket/WebRTC channel, lakini raw APIs huondoa UI delays na kuruhusu operations zisizo valid.

## Creepy companion: silent sampling loop

1. Chagua message yoyote ya zamani uliyoandika kwenye chat ili victim asione "reaction" balloons zikibadilika.
2. Badilisha kati ya emoji inayoonekana na empty reaction payload (iliyoencode kama `""` katika WhatsApp protobufs au `--remove` katika signal-cli). Kila transmission hutoa device ack licha ya kutokuwepo kwa UI delta kwa victim.
3. Weka timestamp ya muda wa kutuma na kila delivery receipt inayowasili. Loop ya 1 Hz kama iliyo hapa chini hutoa per-device RTT traces bila kikomo:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Kwa sababu WhatsApp/Signal zinakubali reaction updates zisizo na kikomo, attacker hahitaji kutuma chat content mpya wala kuwa na wasiwasi kuhusu edit windows.<sup>[[1]](#references)</sup>

## Spooky stranger: kuprobe phone numbers za kiholela

1. Sajili WhatsApp/Signal account mpya na upate public identity keys za target number (hufanyika automatically wakati wa session setup).
2. Tengeneza reaction/edit/delete packet inayorejelea random `message_id` ambayo haijawahi kuonekana na upande wowote (WhatsApp inakubali GUID za kiholela za `key.id`; Signal hutumia millisecond timestamps).
3. Tuma packet hata kama hakuna thread. Victim devices huidecrypt, hushindwa kupata base message, hutupa state change, lakini bado hu-ack incoming ciphertext na kutuma device receipts kwa attacker.
4. Rudia continuously ili kujenga RTT series bila kamwe kuonekana kwenye chat list ya victim.<sup>[[1]](#references)</sup>

Ikiwa kwanza unahitaji kugundua ni numbers zipi zimesajiliwa au unataka kuandaa device inventories kwa kiwango kikubwa, unganisha hii na [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) badala ya kukisia random E.164 ranges kwa mkono.

Kazi iliyochapishwa kuhusu contact-discovery ilionyesha kwa nini hili ni muhimu operationally: kwa kutumia accurate phone-prefix tables na resources za wastani, researchers waliweza kuquery takriban `10%` ya US mobile numbers kwenye WhatsApp na `100%` kwenye Signal kabla ya kuendelea na targeted probing.<sup>[[11]](#references)</sup> Kwa matumizi halisi, pre-filtering ya live accounts kwanza huweka silent-probe budget kwenye numbers ambazo zita-decrypt packets kwa kweli.

WhatsApp builds za hivi karibuni pia zinaonyesha `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Ichukulie kama throughput limiter, si fix: huathiri zaidi sustained stranger-only flooding na haina umuhimu pale ambapo tayari wewe ni known contact.

## Kutumia tena edits na deletes kama covert triggers

* **Repeated deletes:** Baada ya message kufutwa kwa kila mtu mara moja, delete packets zaidi zinazorejelea `message_id` hiyo hazina UI effect, lakini kila device bado hu-decrypt na kuzi-ack.
* **Out-of-window operations:** WhatsApp inalazimisha takriban windows za delete za ~60 h na edit za ~20 min katika UI; Signal inalazimisha ~48 h. Crafted protocol messages zilizo nje ya windows hizi hupuzwa kimya kwenye victim device, lakini receipts hutumwa, hivyo attackers wanaweza kuprobe kwa muda usio na kikomo muda mrefu baada ya conversation kuisha.
* **Invalid payloads:** Malformed edit bodies au deletes zinazorejelea messages ambazo tayari zimepurge hutoa tabia hiyo hiyo—decryption pamoja na receipt, bila artefacts zinazoonekana kwa mtumiaji.<sup>[[1]](#references)</sup>

## Multi-device amplification & fingerprinting

* Kila associated device (phone, desktop app, browser companion) hu-decrypt probe independently na kutuma ack yake. Kuhesabu receipts kwa kila probe hufichua idadi kamili ya devices.
* Device ikiwa offline, receipt yake huwekwa kwenye queue na kutumwa inapounganishwa tena. Kwa hiyo mapengo hu-leak mizunguko ya online/offline na hata ratiba za kusafiri (kwa mfano, desktop receipts huacha wakati wa safari).
* RTT distributions hutofautiana kulingana na platform kwa sababu ya OS power management na push wakeups. Cluster RTTs (kwa mfano, k-means kwenye median/variance features) ili kuweka labels kama “Android handset", “iOS handset", “Electron desktop", n.k.
* Kwa sababu sender lazima apate key inventory ya recipient kabla ya kuencrypt, attacker anaweza pia kufuatilia wakati devices mpya zinaunganishwa; ongezeko la ghafla la device count au RTT cluster mpya ni kiashiria madhubuti.<sup>[[1]](#references)</sup>

## Sampling cadence, queueing, na stacked receipts

* **WhatsApp burst tolerance:** Vipimo vilivyochapishwa viliripoti kuwa WhatsApp ilikubali silent-reaction bursts kwa kasi ya probe moja kila `50 ms` bila queueing inayoonekana upande wa server. Hii ni muhimu kwa short calibration bursts, device counting ya haraka, au kuanzisha drain attack kwa kasi.
* **Signal long-run queueing:** Signal ilivumilia bursts fupi lakini ilianza kuqueue sustained traffic yenye probes nyingi kwa sekunde. Kwa monitoring ya muda mrefu, weka cadence karibu na `1 Hz` (au chini) ili kila receipt bado iakisi current device state badala ya backlog drain.
* **Reconnect artefacts:** Device inaporudi online, baadhi ya clients hu-batch au huflush kwa haraka delayed receipts nyingi. Zichukulie receipt bursts hizo kama state-transition marker badala ya RTT samples zinazojitegemea, la sivyo clustering / `active` dhidi ya `idle` classifier yako ita-overfit reconnect noise.<sup>[[1]](#references)</sup>

## Behaviour inference kutoka RTT traces

1. Sample kwa ≥1 Hz ili kunasa OS scheduling effects. Kwa WhatsApp kwenye iOS, RTT za <1 s zinahusiana kwa nguvu na screen-on/foreground, huku >1 s zikihusiana na screen-off/background throttling.
2. Tengeneza classifiers rahisi (thresholding au two-cluster k-means) zinazoweka kila RTT kama "active" au "idle". Kusanya labels katika streaks ili kupata muda wa kulala, safari, saa za kazi, au wakati desktop companion iko active.
3. Linganisha probes zinazotumwa kwa wakati mmoja kuelekea kila device ili kuona wakati users wanapobadilika kutoka mobile kwenda desktop, companions zinapokuwa offline, na kama app ina-rate limitiwa na push dhidi ya persistent socket.
4. Katika networks halisi, epuka threshold moja ya `1 s` iliyowekwa hardcoded. Bootstrap kila device kwa short warm-up window na tumia rolling baseline (kwa mfano, `threshold = 0.9 * median RTT`) ili Wi-Fi/cellular drift isivunje classifier yako.<sup>[[1]](#references)</sup>

## Location inference kutoka delivery RTT

Timing primitive hiyo hiyo inaweza kutumiwa tena ku-infer mahali recipient alipo, si tu kama yuko active. Kazi ya `Hope of Delivery` ilionyesha kuwa training kwenye RTT distributions za receiver locations zinazojulikana humruhusu attacker baadaye ku-classify location ya victim kutokana na delivery confirmations pekee:<sup>[[2]](#references)</sup>

* Tengeneza baseline ya target huyo huyo akiwa katika maeneo kadhaa yanayojulikana (nyumbani, ofisini, campus, country A dhidi ya country B, n.k.).
* Kwa kila location, kusanya normal message RTTs nyingi na utoe features rahisi kama median, variance, au percentile buckets.
* Wakati wa attack halisi, linganisha probe series mpya na trained clusters. Paper inaripoti kuwa hata locations zilizo ndani ya jiji moja mara nyingi zinaweza kutenganishwa, kwa accuracy ya `>80%` katika mazingira yenye locations 3.
* Hii hufanya kazi vizuri zaidi attacker anapodhibiti sender environment na kuprobe chini ya network conditions zinazofanana, kwa sababu measured path inajumuisha recipient access network, wake-up latency, na messenger infrastructure.<sup>[[2]](#references)</sup>

Tofauti na silent reaction/edit/delete attacks zilizo hapo juu, location inference haihitaji invalid message IDs au stealthy state-changing packets. Plain messages zenye normal delivery confirmations zinatosha, kwa hiyo tradeoff ni stealth ndogo lakini applicability pana zaidi katika messengers mbalimbali.

## Stealthy resource exhaustion

Kwa sababu kila silent probe lazima idecryptiwe na iacknowledgeiwe, kutuma reaction toggles, invalid edits, au delete-for-everyone packets continuously huunda application-layer DoS:<sup>[[1]](#references)</sup>

* Hulazimisha radio/modem kutransmit/receive kila sekunde → battery drain inayoonekana, hasa kwenye idle handsets.
* Hutengeneza upstream/downstream traffic isiyopimwa inayotumia mobile data plans huku ikichanganyika na TLS/WebSocket noise.
* Hushughulisha crypto threads na kuleta jitter katika features zinazohitaji latency ndogo (VoIP, video calls) ingawa user haoni notifications.
* Kwenye WhatsApp, invalid reactions hukubali data nyingi zaidi kuliko emoji ya kawaida inavyodokeza: vipimo vilivyochapishwa vilipata server-side acceptance ya hadi takriban `1 MB` kwa reaction.
* Oversized reactions huacha kutoa delivery receipts zinazoaminika body inapozidi takriban `30 bytes`, lakini bado husambazwa na kuchakatwa kabla ya kutupwa. Weka reaction bodies ndogo unapohitaji ACKs; zikuze tu lengo linapokuwa pure drain au covert one-way transport.
* Vipimo vya umma vilifikia takriban `3.7 MB/s` (`~13.3 GB/h`) ya victim traffic katika mode hii.

## References

- [1] [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [11] [All the Numbers are US: Large-scale Abuse of Contact Discovery in Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
