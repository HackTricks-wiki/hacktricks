# Mashambulizi ya Side-Channel ya Delivery Receipt katika E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Delivery receipts ni lazima katika E2EE messengers za kisasa kwa sababu clients wanahitaji kujua ciphertext ilipo-decryptiwa ili waweze kutupa hali ya ratcheting na ephemeral keys. Server hu-forward opaque blobs, hivyo acknowledgements za device (double checkmarks) hutumwa na recipient baada ya decryption kufanikiwa. Kupima round-trip time (RTT) kati ya kitendo kilichoanzishwa na attacker na delivery receipt inayolingana hufichua timing channel yenye resolution kubwa inayovuja hali ya device, uwepo online, na inaweza kutumiwa vibaya kwa covert DoS. Deployments za multi-device zenye "client-fanout" huongeza leakage kwa sababu kila device iliyosajiliwa hu-decrypt probe na kurudisha receipt yake.<sup>[[1]](#references)</sup>

## Vyanzo vya delivery receipt dhidi ya signals zinazoonekana na user

Chagua aina za messages ambazo hutuma delivery receipt kila mara lakini hazionyeshi artifacts za UI kwa victim. Jedwali hapa chini linatoa muhtasari wa tabia iliyothibitishwa kwa majaribio:<sup>[[1]](#references)</sup>

| Messenger | Kitendo | Delivery receipt | Notification ya victim | Maelezo |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Huleta kelele kila mara → muhimu tu kwa kuanzisha state. |
| | Reaction | ● | ◐ (ikiwa tu inareact kwa message ya victim) | Self-reactions na removals hubaki kimya. |
| | Edit | ● | Silent push inayotegemea platform | Edit window ≈20 min; bado hu-ack baada ya expiry. |
| | Delete for everyone | ● | ○ | UI inaruhusu takriban saa 60, lakini packets za baadaye bado hu-ack. |
| **Signal** | Text message | ● | ● | Vikwazo sawa na WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions hazionekani kwa victim. |
| | Edit/Delete | ● | ○ | Server hutekeleza window ya takriban saa 48, huruhusu hadi edits 10, lakini packets za kuchelewa bado hu-ack. |
| **Threema** | Text message | ● | ● | Multi-device receipts hu-aggregated, kwa hiyo RTT moja tu kwa kila probe huonekana. |

Legend: ● = kila mara, ◐ = kwa masharti, ○ = kamwe. Tabia ya UI inayotegemea platform imeonyeshwa ndani ya mistari. Zima read receipts ikihitajika, lakini delivery receipts haziwezi kuzimwa katika WhatsApp au Signal.<sup>[[1]](#references)</sup>

## Malengo na models za attacker

* **G1 – Device fingerprinting:** Hesabu idadi ya receipts zinazowasili kwa kila probe, cluster RTTs ili kubaini OS/client (Android dhidi ya iOS dhidi ya desktop), na fuatilia mabadiliko ya online/offline.
* **G2 – Behavioural monitoring:** Chukulia mfululizo wa RTT wa frequency ya juu (≈1 Hz ni thabiti) kama time-series na bainisha screen on/off, app foreground/background, muda wa kusafiri dhidi ya saa za kazi, n.k.
* **G3 – Resource exhaustion:** Weka radios/CPUs za kila device ya victim zikiwa active kwa kutuma silent probes zisizoisha, ukimaliza battery/data na kupunguza ubora wa video-call.<sup>[[1]](#references)</sup>

Threat actors wawili wanatosha kueleza abuse surface:<sup>[[1]](#references)</sup>

1. **Creepy companion:** Tayari anashiriki chat na victim na hutumia vibaya self-reactions, reaction removals, au edits/deletes zinazorudiwa zinazohusishwa na message IDs zilizopo.
2. **Spooky stranger:** Husajili burner account na kutuma reactions zinazorejelea message IDs ambazo hazijawahi kuwepo katika conversation ya ndani; WhatsApp na Signal bado hu-decrypt na ku-acknowledge hizo reactions ingawa UI hutupa state change, kwa hiyo conversation ya awali haihitajiki.

## Tooling ya kufikia raw protocol

Tegemea clients zinazoonyesha sehemu ya kutosha ya E2EE protocol ya msingi ili kuunda packets zinazoungwa mkono nje ya vikwazo vya UI na kurekodi timestamps sahihi; message IDs za kiholela zinahitaji kukaguliwa katika kila implementation:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web multidevice API) inaandika kuhusu kutuma na kupokea delivery receipts; [Cobalt](https://github.com/Auties00/Cobalt) (unofficial Java/Kotlin Web and mobile API) inaandika kuhusu message operations kama reacting, editing, na deleting. Tumia APIs zao zilizoandikwa badala ya kudhani kuwa kila internal frame imewekwa wazi.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) inaonyesha CLI, JSON-RPC, na D-Bus interfaces, huku [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) ikiwa Java library ya kuwasiliana na Signal.<sup>[[5]](#references)[[7]](#references)</sup> Syntax ya sasa ya `signal-cli` hutumia `sendReaction RECIPIENT --target-author --target-timestamp`; endelea kuendesha `receive` au `daemon` ili protocol updates ziendelee kuchakatwa.<sup>[[6]](#references)</sup> Mfano wa self-reaction toggle:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Vipimo katika paper ya Careless Whisper viligundua kuwa delivery receipts husawazishwa katika devices, kwa hiyo receipt moja tu kwa kila message huonekana hata katika setup ya multi-device.<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) husambaza WhatsApp/Signal backends, kwa default hutumia silent delete probes, na huweka labels za `active` dhidi ya `standby` kwa threshold ya rolling-median (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) ni CLI nyepesi inayolenga WhatsApp kwanza, yenye `--delay`, `--concurrent`, CSV/Prometheus exporters, na output inayofaa Grafana.<sup>[[9]](#references)</sup> Zichukulie zote mbili kama reconnaissance helpers badala ya protocol references; jambo muhimu ni jinsi code ndogo inavyohitajika pindi raw client access inapopatikana.

Custom tooling isipopatikana, official clients au browser developer tools bado zinaweza kuanzisha silent actions na kuonyesha timing ya encrypted traffic; raw APIs huondoa ucheleweshaji wa UI na huruhusu invalid operations.<sup>[[1]](#references)</sup>

## Creepy companion: silent sampling loop

1. Chagua message yoyote ya zamani uliyoandika katika chat ili victim asione mabadiliko ya "reaction" balloons.
2. Badilisha kati ya emoji inayoonekana na empty reaction payload (iliyowekwa kama `""` katika WhatsApp protobufs au `--remove` katika signal-cli). Kila transmission hutoa device ack licha ya kutokuwepo kwa UI delta kwa victim.
3. Weka timestamp ya muda wa kutuma na kila delivery receipt inayowasili. Loop ya 1 Hz kama ifuatayo hutoa RTT traces za kila device bila kikomo:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Kwa sababu WhatsApp/Signal hukubali reaction updates zisizo na kikomo, attacker hahitaji kamwe kuchapisha chat content mpya au kuwa na wasiwasi kuhusu edit windows.<sup>[[1]](#references)</sup>

## Spooky stranger: kuchunguza namba za simu kiholela

1. Sajili WhatsApp/Signal account mpya na upate public identity keys za namba inayolengwa (hufanyika kiotomatiki wakati wa session setup).
2. Tengeneza reaction packet inayorejelea `message_id` ya nasibu ambayo haijawahi kuonekana na upande wowote; paper inaripoti kuwa WhatsApp na Signal hukubali reactions kama hizo na bado hutengeneza delivery receipts.<sup>[[1]](#references)</sup>
3. Tuma packet hata kama hakuna thread. Devices za victim hu-decrypt, hushindwa kupata base message, hutupa state change, lakini bado hu-acknowledge incoming ciphertext, na kutuma device receipts kurudi kwa attacker.
4. Rudia mfululizo ili kujenga RTT series bila conversation ya awali au notification inayoonekana.<sup>[[1]](#references)</sup>

Ikiwa kwanza unahitaji kugundua namba zilizosajiliwa au kutayarisha device inventories kwa kiwango kikubwa, unganisha hii na [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) badala ya kubahatisha ranges za E.164 kwa mkono.

Kazi iliyochapishwa kuhusu contact-discovery ilionyesha kwa nini hili ni muhimu kiutendaji: kwa kutumia phone-prefix tables sahihi na resources za wastani, watafiti waliweza ku-query takriban `10%` ya namba za mobile za Marekani kwenye WhatsApp na `100%` kwenye Signal kabla ya kuendelea na targeted probing.<sup>[[11]](#references)</sup> Kwa matumizi ya kawaida, kuchuja live accounts kwanza huweka silent-probe budget yako ikilenga namba ambazo kwa hakika zita-decrypt packets.

WhatsApp builds za hivi karibuni pia zinaonyesha `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Ichukulie kama throughput limiter: tracker documentation inasema WhatsApp huzuia high-volume messages kutoka kwa unknown accounts lakini haifichui threshold, kwa hiyo haizuii kikamilifu probe reactions.<sup>[[8]](#references)</sup>

## Kutumia tena edits na deletes kama covert triggers

* **Repeated deletes:** Baada ya message kufutwa kwa kila mtu mara moja, delete packets zaidi zinazorejelea `message_id` hiyo hiyo hazina athari ya UI lakini kila device bado hu-decrypt na ku-acknowledge.
* **Out-of-window operations:** WhatsApp hutekeleza delete windows za takriban saa 60 / edit windows za takriban dakika 20 katika UI; Signal hutekeleza takriban saa 48. Crafted protocol messages zilizo nje ya windows hizi hupuuziwa kimya kwenye device ya victim lakini receipts hutumwa, hivyo attackers wanaweza ku-probe kwa muda usio na kikomo muda mrefu baada ya conversation kumalizika.
* **Invalid payloads:** Paper inaripoti kuwa invalid messages bado zinaweza ku-acknowledge; tabia kamili ya malformed bodies au purged IDs inategemea implementation, kwa hiyo fanya majaribio kabla ya kuitegemea.<sup>[[1]](#references)</sup>

## Multi-device amplification & fingerprinting

* Katika WhatsApp na Signal, kila associated device (phone, desktop app, browser companion) hu-decrypt probe kivyake na kurudisha ack yake. Kuhesabu receipts kwa kila probe hufichua idadi kamili ya devices.<sup>[[1]](#references)</sup>
* Device ikiwa offline, receipt yake huwekwa kwenye queue na kutumwa inapounganishwa tena. Kwa hiyo mapengo huvuja mizunguko ya online/offline na hata ratiba za kusafiri (kwa mfano, desktop receipts hukoma wakati wa safari).
* Distributions za RTT hutofautiana kulingana na platform na mazingira kwa sababu OS, model, client, na hali za network huathiri timing. Cluster RTTs (kwa mfano, k-means kwenye median/variance features) ili kuweka labels kama “Android handset", “iOS handset", “Electron desktop", n.k.
* Kwa sababu sender lazima apate recipient’s key inventory kabla ya ku-encrypt, attacker anaweza pia kufuatilia devices mpya zinapounganishwa; ongezeko la ghafla la idadi ya devices au RTT cluster mpya ni kiashiria thabiti.<sup>[[1]](#references)</sup>

## Sampling cadence, queueing, na stacked receipts

* **WhatsApp burst tolerance:** Vipimo vilivyochapishwa viliripoti kuwa WhatsApp ilikubali silent-reaction bursts zenye kasi ya probe moja kila `50 ms` bila queueing inayoonekana upande wa server. Hii ni muhimu kwa calibration bursts fupi, kuhesabu devices haraka, au kuongeza kasi ya drain attack.
* **Signal long-run queueing:** Signal ilivumilia bursts fupi lakini ilianza kuweka kwenye queue traffic endelevu ya probes nyingi kwa sekunde. Kwa monitoring ya muda mrefu, weka cadence karibu na `1 Hz` (au chini) ili kila receipt bado iakisi hali ya sasa ya device badala ya kumaliza backlog.
* **Reconnect artefacts:** Device inaporudi online, baadhi ya clients hu-batch au hu-flush kwa kasi receipts nyingi zilizochelewa. Chukulia receipt bursts hizo kama state-transition marker badala ya RTT samples huru, la sivyo classifier yako ya clustering / `active` dhidi ya `idle` ita-overfit reconnect noise.<sup>[[1]](#references)</sup>

## Behaviour inference kutoka RTT traces

1. Sample kwa ≥1 Hz ili kunasa athari za OS scheduling. Kwa WhatsApp kwenye iOS, RTT za <1 s huhusiana kwa nguvu na screen-on/foreground, huku >1 s zikihusiana na screen-off/background throttling.
2. Tengeneza classifiers rahisi (thresholding au two-cluster k-means) zinazoweka kila RTT label ya "active" au "idle". Aggregati labels katika streaks ili kupata muda wa kulala, safari za kwenda/kutoka, saa za kazi, au wakati desktop companion iko active.
3. Correlate probes za wakati mmoja kuelekea kila device ili kuona wakati users wanabadilika kutoka mobile kwenda desktop, companions zinapoenda offline, na kama app inawekewa rate limit na push dhidi ya persistent socket.
4. Katika networks halisi, epuka threshold moja ngumu ya `1 s`. Anzisha kila device kwa short warm-up window na weka rolling baseline (kwa mfano, device-activity-tracker PoC hutumia `threshold = 0.9 * median RTT`) ili Wi-Fi/cellular drift isivunje classifier yako.<sup>[[1]](#references)[[8]](#references)</sup>

## Location inference kutoka delivery RTT

Timing primitive hiyo hiyo inaweza kutumiwa tena kubaini recipient yuko wapi, si tu kama yuko active. Kazi ya `Hope of Delivery` ilionyesha kuwa training kwenye RTT distributions za receiver locations zinazojulikana humwezesha attacker baadaye ku-classify location ya victim kutokana na delivery confirmations pekee:<sup>[[2]](#references)</sup>

* Tengeneza baseline kwa target huyo huyo akiwa katika maeneo kadhaa yanayojulikana (nyumbani, ofisini, campus, country A dhidi ya country B, n.k.).
* Kwa kila location, kusanya normal message RTTs nyingi na utoe features rahisi kama median, variance, au percentile buckets.
* Wakati wa attack halisi, linganisha probe series mpya na trained clusters. Paper inaripoti kuwa hata locations zilizo ndani ya mji huo huo mara nyingi zinaweza kutenganishwa, kwa accuracy ya `>80%` katika setting yenye locations 3.
* Hii hufanya kazi vizuri zaidi attacker anapodhibiti sender environment na ku-probe chini ya hali zinazofanana za network, kwa sababu njia inayopimwa inajumuisha recipient access network, wake-up latency, na messenger infrastructure.<sup>[[2]](#references)</sup>

Tofauti na silent reaction/edit/delete attacks zilizo hapo juu, location inference haihitaji invalid message IDs au stealthy state-changing packets. Plain messages zenye normal delivery confirmations zinatosha, kwa hiyo tradeoff ni stealth ndogo lakini applicability pana katika messengers mbalimbali.

## Stealthy resource exhaustion

Kwa sababu kila silent probe lazima i-decryptiwe na i-acknowledge, kutuma reaction toggles, invalid edits, au delete-for-everyone packets kila mara hutengeneza application-layer DoS:<sup>[[1]](#references)</sup>

* Hulazimisha radio/modem kutuma/kupokea kila sekunde → battery drain inayoonekana, hasa kwenye idle handsets.
* Hutengeneza upstream/downstream traffic inayotumia mobile data plans na inaweza kushindana na features zinazohitaji latency ndogo kama video calls.<sup>[[1]](#references)</sup>
* Invalid payloads kubwa huongeza processing work, lakini paper inaripoti kuwa cryptography yenyewe ni sehemu ndogo sana ya battery cost.<sup>[[1]](#references)</sup>
* Kwenye WhatsApp, invalid reactions hukubali data nyingi zaidi kuliko emoji ya kawaida inavyodokeza: vipimo vilivyochapishwa vilipata server-side acceptance ya hadi takriban `1 MB` kwa reaction.
* Oversized reactions huacha kutoa delivery receipts zinazoaminika body inapozidi takriban `30 bytes`, lakini bado hu-forwardiwa na kuchakatwa kabla ya kutupwa. Weka reaction bodies ndogo unapohitaji ACKs; zikuze tu unapolenga pure drain au covert one-way transport.
* Vipimo vya umma vilifikia takriban `3.7 MB/s` (`~13.3 GB/h`) ya victim traffic katika hali hii.

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
