# E2EE Messengers में Delivery Receipt Side-Channel Attacks

{{#include ../banners/hacktricks-training.md}}

Delivery receipts आधुनिक end-to-end encrypted (E2EE) messengers में अनिवार्य हैं क्योंकि clients को यह जानना होता है कि ciphertext कब decrypt हुआ, ताकि वे ratcheting state और ephemeral keys discard कर सकें। Server opaque blobs forward करता है, इसलिए device acknowledgements (double checkmarks) recipient द्वारा successful decryption के बाद emit होते हैं। Attacker-triggered action और संबंधित delivery receipt के बीच round-trip time (RTT) मापने से एक high-resolution timing channel खुलता है, जो device state, online presence leak करता है, और covert DoS के लिए abuse किया जा सकता है। Multi-device "client-fanout" deployments leakage को बढ़ाते हैं क्योंकि हर registered device probe decrypt करता है और अपना receipt लौटाता है।

## Delivery receipt sources vs. user-visible signals

ऐसे message types चुनें जो हमेशा delivery receipt emit करें लेकिन victim पर UI artifacts न दिखाएँ। नीचे की table empirically confirmed behaviour का सार देती है:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | हमेशा noisy → केवल state bootstrap करने के लिए उपयोगी। |
| | Reaction | ● | ◐ (केवल if reacting to victim message) | Self-reactions और removals silent रहते हैं। |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; expiry के बाद भी ack'd रहता है। |
| | Delete for everyone | ● | ○ | UI में ~60 h तक allowed, लेकिन बाद के packets भी ack'd रहते हैं। |
| **Signal** | Text message | ● | ● | WhatsApp जैसी ही limitations। |
| | Reaction | ● | ◐ | Self-reactions victim को दिखाई नहीं देते। |
| | Edit/Delete | ● | ○ | Server ~48 h window enforce करता है, up to 10 edits allow करता है, लेकिन late packets भी ack'd रहते हैं। |
| **Threema** | Text message | ● | ● | Multi-device receipts aggregate होते हैं, इसलिए प्रति probe केवल एक RTT visible होता है। |

Legend: ● = always, ◐ = conditional, ○ = never. Platform-dependent UI behaviour inline noted है। जरूरत हो तो read receipts disable करें, लेकिन WhatsApp या Signal में delivery receipts turn off नहीं किए जा सकते।

## Attacker goals and models

* **G1 – Device fingerprinting:** प्रति probe कितने receipts आते हैं, यह count करें; RTTs cluster करके OS/client (Android vs iOS vs desktop) infer करें, और online/offline transitions observe करें।
* **G2 – Behavioural monitoring:** high-frequency RTT series (≈1 Hz stable है) को time-series की तरह treat करें और screen on/off, app foreground/background, commuting vs working hours, आदि infer करें।
* **G3 – Resource exhaustion:** never-ending silent probes भेजकर हर victim device के radios/CPUs को awake रखें, battery/data drain करें, और VoIP/RTC quality degrade करें।

Abuse surface describe करने के लिए दो threat actors काफी हैं:

1. **Creepy companion:** पहले से victim के साथ chat share करता है और self-reactions, reaction removals, या existing message IDs से जुड़े repeated edits/deletes abuse करता है।
2. **Spooky stranger:** एक burner account register करता है और ऐसे message IDs को refer करने वाली reactions भेजता है जो local conversation में कभी मौजूद नहीं थे; WhatsApp और Signal फिर भी उन्हें decrypt और acknowledge करते हैं, भले ही UI state change discard कर दे, इसलिए prior conversation की जरूरत नहीं होती।

## Tooling for raw protocol access

ऐसे clients पर निर्भर रहें जो underlying E2EE protocol expose करते हैं, ताकि आप UI constraints के बाहर packets craft कर सकें, arbitrary `message_id`s specify कर सकें, और precise timestamps log कर सकें:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) या [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) आपको raw `ReactionMessage`, `ProtocolMessage` (edit/delete), और `Receipt` frames emit करने देते हैं, जबकि double-ratchet state sync में रहती है।
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) को [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) के साथ मिलाकर हर message type CLI/API के जरिए expose होती है। Current `signal-cli` syntax `sendReaction RECIPIENT --target-author --target-timestamp` उपयोग करती है; delivery receipts वास्तव में collect हों, इसके लिए `receive` या `daemon` चलाते रहें। Self-reaction toggle का example:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Android client का source document करता है कि delivery receipts device से बाहर जाने से पहले consolidate होते हैं, जिससे स्पष्ट होता है कि वहाँ side channel की bandwidth नगण्य है।
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) WhatsApp/Signal backends ship करता है, default रूप से silent delete probes use करता है, और rolling-median threshold (`RTT < 0.9 * median`) के साथ `active` vs `standby` label करता है। [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) एक हल्का WhatsApp-first CLI है जिसमें `--delay`, `--concurrent`, CSV/Prometheus exporters, और Grafana-friendly output हैं। दोनों को protocol references की बजाय reconnaissance helpers की तरह देखें; महत्वपूर्ण takeaway यह है कि raw client access मिलने पर कितना कम code चाहिए।

जब custom tooling उपलब्ध न हो, तब भी आप WhatsApp Web या Signal Desktop से silent actions trigger कर सकते हैं और encrypted websocket/WebRTC channel sniff कर सकते हैं, लेकिन raw APIs UI delays हटाती हैं और invalid operations allow करती हैं।

## Creepy companion: silent sampling loop

1. chat में अपनी कोई historical message चुनें ताकि victim को कभी "reaction" balloons बदलते हुए न दिखें।
2. visible emoji और empty reaction payload के बीच alternate करें (WhatsApp protobufs में `""` के रूप में या signal-cli में `--remove`)। हर transmission victim के लिए कोई UI delta न होने के बावजूद device ack देता है।
3. send time और हर delivery receipt arrival को timestamp करें। निम्न जैसा 1 Hz loop प्रति-device RTT traces indefinitely देता है:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. क्योंकि WhatsApp/Signal unlimited reaction updates accept करते हैं, attacker को कभी नया chat content post करने या edit windows की चिंता करने की जरूरत नहीं होती।

## Spooky stranger: probing arbitrary phone numbers

1. एक fresh WhatsApp/Signal account register करें और target number के public identity keys fetch करें (session setup के दौरान automatically होता है)।
2. एक reaction/edit/delete packet craft करें जो ऐसे random `message_id` को reference करता हो जो दोनों पक्षों में से किसी ने कभी नहीं देखा (WhatsApp arbitrary `key.id` GUIDs accept करता है; Signal millisecond timestamps उपयोग करता है)।
3. packet भेजें, भले ही कोई thread मौजूद न हो। Victim devices इसे decrypt करते हैं, base message से match नहीं पाते, state change discard करते हैं, लेकिन फिर भी incoming ciphertext acknowledge करते हैं, और device receipts attacker को वापस भेजते हैं।
4. victim की chat list में कभी दिखाई दिए बिना RTT series बनाने के लिए इसे लगातार repeat करें।

अगर पहले आपको यह पता लगाना हो कि कौन-से numbers registered हैं, या scale पर device inventories pre-seed करनी हों, तो random E.164 ranges हाथ से guess करने की बजाय इसे [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) के साथ chain करें।

Published contact-discovery work ने operational तौर पर दिखाया कि यह क्यों मायने रखता है: accurate phone-prefix tables और modest resources के साथ, researchers WhatsApp पर लगभग US mobile numbers के `10%` और Signal पर `100%` query करने में सक्षम थे, targeted probing पर जाने से पहले। व्यवहार में, पहले live accounts pre-filter करने से silent-probe budget उन्हीं numbers पर केंद्रित रहता है जो वास्तव में packets decrypt करेंगे।

Recent WhatsApp builds में `Settings -> Privacy -> Advanced -> Block unknown account messages` भी उपलब्ध है। इसे fix नहीं, throughput limiter समझें: यह मुख्यतः sustained stranger-only flooding को नुकसान पहुँचाता है और एक बार आप already known contact हों तो irrelevant हो जाता है।

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** एक message को delete-for-everyone once करने के बाद, उसी `message_id` को reference करने वाले further delete packets का कोई UI effect नहीं होता, लेकिन हर device फिर भी उन्हें decrypt और acknowledge करता है।
* **Out-of-window operations:** WhatsApp UI में ~60 h delete / ~20 min edit windows enforce करता है; Signal ~48 h enforce करता है। इन windows के बाहर crafted protocol messages victim device पर silently ignore हो जाते हैं, लेकिन receipts transmitted होते हैं, इसलिए attackers conversation खत्म होने के काफी बाद भी indefinitely probe कर सकते हैं।
* **Invalid payloads:** Malformed edit bodies या पहले ही purged messages को reference करने वाले deletes वही behaviour दिखाते हैं—decryption plus receipt, zero user-visible artefacts।

## Multi-device amplification & fingerprinting

* हर associated device (phone, desktop app, browser companion) probe को independently decrypt करता है और अपना own ack लौटाता है। प्रति probe receipts गिनने से exact device count पता चलता है।
* अगर कोई device offline है, तो उसका receipt queue होता है और reconnection पर emit होता है। इसलिए gaps online/offline cycles और commuting schedules तक leak करते हैं (जैसे travel के दौरान desktop receipts रुक जाते हैं)।
* RTT distributions platform के अनुसार अलग होते हैं क्योंकि OS power management और push wakeups अलग हैं। RTTs cluster करें (जैसे median/variance features पर k-means) ताकि “Android handset", “iOS handset", “Electron desktop", आदि label किए जा सकें।
* क्योंकि sender को encrypt करने से पहले recipient का key inventory retrieve करना होता है, attacker यह भी देख सकता है कि नए devices कब paired हुए; device count में अचानक वृद्धि या नया RTT cluster एक मजबूत indicator है।

## Sampling cadence, queueing, and stacked receipts

* **WhatsApp burst tolerance:** Published measurements में बताया गया कि WhatsApp लगभग हर `50 ms` में एक probe जितनी तेज silent-reaction bursts accept करता था, बिना obvious server-side queueing के। यह short calibration bursts, fast device counting, या drain attack को जल्दी ramp करने के लिए उपयोगी है।
* **Signal long-run queueing:** Signal short bursts tolerate करता था, लेकिन sustained multi-probe-per-second traffic को queue करना शुरू कर देता था। Long-lived monitoring के लिए cadence लगभग `1 Hz` (या उससे कम) रखें, ताकि हर receipt current device state को reflect करे, backlog drain को नहीं।
* **Reconnect artefacts:** जब कोई device वापस online आता है, कुछ clients कई delayed receipts को batch करते हैं या तेजी से flush करते हैं। उन receipt bursts को independent RTT samples की बजाय state-transition marker मानें, वरना आपका clustering / `active` vs `idle` classifier reconnect noise पर overfit हो जाएगा।

## Behaviour inference from RTT traces

1. OS scheduling effects capture करने के लिए ≥1 Hz पर sample करें। WhatsApp on iOS में, <1 s RTTs screen-on/foreground से strongly correlate करते हैं, >1 s screen-off/background throttling से।
2. सरल classifiers बनाएं (thresholding या two-cluster k-means) जो हर RTT को "active" या "idle" label करें। उन labels को streaks में aggregate करें ताकि bedtimes, commutes, work hours, या desktop companion active होने का समय निकाला जा सके।
3. simultaneous probes को हर device की ओर correlate करें ताकि देखा जा सके कि users mobile से desktop पर कब switch करते हैं, companions कब offline होते हैं, और app push बनाम persistent socket द्वारा rate limited है या नहीं।
4. वास्तविक networks में single hardcoded `1 s` threshold से बचें। हर device को short warm-up window से bootstrap करें और rolling baseline रखें (उदाहरण के लिए, `threshold = 0.9 * median RTT`) ताकि Wi-Fi/cellular drift आपका classifier collapse न करे।

## Location inference from delivery RTT

उसी timing primitive को recipient के active होने के अलावा यह infer करने के लिए भी repurpose किया जा सकता है कि वे कहाँ हैं। `Hope of Delivery` work ने दिखाया कि known receiver locations के RTT distributions पर training करके attacker बाद में केवल delivery confirmations से victim की location classify कर सकता है:

* उसी target के लिए baseline बनाएं जब वे कई known places पर हों (home, office, campus, country A vs country B, आदि)।
* हर location के लिए, कई normal message RTTs collect करें और median, variance, या percentile buckets जैसे सरल features extract करें।
* असली attack के दौरान, नए probe series को trained clusters से compare करें। Paper रिपोर्ट करता है कि एक ही city के भीतर की locations भी अक्सर अलग की जा सकती हैं, `>80%` accuracy के साथ 3-location setting में।
* यह सबसे अच्छा तब काम करता है जब attacker sender environment को control करता हो और समान network conditions के तहत probe करे, क्योंकि measured path में recipient access network, wake-up latency, और messenger infrastructure शामिल होते हैं।

ऊपर दिए गए silent reaction/edit/delete attacks के विपरीत, location inference के लिए invalid message IDs या stealthy state-changing packets की जरूरत नहीं होती। सामान्य delivery confirmations वाले plain messages काफी हैं, इसलिए tradeoff कम stealth लेकिन messengers across wider applicability है।

## Stealthy resource exhaustion

क्योंकि हर silent probe को decrypt और acknowledge करना पड़ता है, लगातार reaction toggles, invalid edits, या delete-for-everyone packets भेजना application-layer DoS बनाता है:

* हर second radio/modem को transmit/receive करने पर मजबूर करता है → noticeable battery drain, खासकर idle handsets पर।
* Unmetered upstream/downstream traffic generate करता है जो TLS/WebSocket noise में blend होते हुए mobile data plans consume करता है।
* Crypto threads occupy करता है और latency-sensitive features (VoIP, video calls) में jitter introduce करता है, भले ही user को notifications कभी दिखें ही नहीं।
* WhatsApp पर invalid reactions normal emoji से कहीं ज्यादा data accept कर सकते हैं: published measurements में server-side acceptance roughly `1 MB` प्रति reaction तक पाया गया।
* Oversized reactions लगभग `30 bytes` से बड़ा body होने पर reliable delivery receipts देना बंद कर देते हैं, लेकिन discard से पहले फिर भी forward और process होते हैं। जब आपको ACKs चाहिए हों तो reaction bodies छोटी रखें; उन्हें सिर्फ pure drain या covert one-way transport के लिए बड़ा करें।
* Public measurements में इस mode में victim traffic लगभग `3.7 MB/s` (`~13.3 GB/h`) तक पहुँचा।

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
