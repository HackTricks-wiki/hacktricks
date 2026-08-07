# E2EE Messengers में Delivery Receipt Side-Channel Attacks

{{#include ../banners/hacktricks-training.md}}

आधुनिक end-to-end encrypted (E2EE) messengers में delivery receipts अनिवार्य होते हैं, क्योंकि clients को यह जानना होता है कि ciphertext कब decrypt हुआ, ताकि वे ratcheting state और ephemeral keys को discard कर सकें। Server opaque blobs को forward करता है, इसलिए device acknowledgements (double checkmarks) recipient द्वारा सफल decryption के बाद भेजे जाते हैं। Attacker-triggered action और संबंधित delivery receipt के बीच round-trip time (RTT) मापने से high-resolution timing channel सामने आता है, जो device state और online presence को leak करता है तथा covert DoS के लिए दुरुपयोग किया जा सकता है। Multi-device "client-fanout" deployments इस leakage को बढ़ाते हैं, क्योंकि हर registered device probe को decrypt करके अपना receipt लौटाता है।<sup>[[1]](#references)</sup>

## Delivery receipt sources बनाम user-visible signals

ऐसे message types चुनें जो हमेशा delivery receipt भेजते हों, लेकिन victim को कोई UI artifact न दिखाएँ। नीचे दी गई table empirically confirmed behaviour का सारांश है:<sup>[[1]](#references)</sup>

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | हमेशा noisy → केवल state bootstrap करने के लिए उपयोगी। |
| | Reaction | ● | ◐ (केवल victim के message पर reaction करने पर) | Self-reactions और removals silent रहते हैं। |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; expiry के बाद भी ack’d। |
| | Delete for everyone | ● | ○ | UI लगभग 60 h की अनुमति देता है, लेकिन बाद के packets अभी भी ack’d होते हैं। |
| **Signal** | Text message | ● | ● | WhatsApp जैसी ही limitations। |
| | Reaction | ● | ◐ | Self-reactions victim को दिखाई नहीं देते। |
| | Edit/Delete | ● | ○ | Server लगभग 48 h window लागू करता है और 10 edits तक की अनुमति देता है, लेकिन late packets अभी भी ack’d होते हैं। |
| **Threema** | Text message | ● | ● | Multi-device receipts aggregated होते हैं, इसलिए प्रत्येक probe के लिए केवल एक RTT दिखाई देता है। |

Legend: ● = हमेशा, ◐ = conditional, ○ = कभी नहीं। Platform-dependent UI behaviour को inline दर्शाया गया है। आवश्यकता होने पर read receipts disable करें, लेकिन WhatsApp या Signal में delivery receipts बंद नहीं किए जा सकते।<sup>[[1]](#references)</sup>

## Attacker goals और models

* **G1 – Device fingerprinting:** प्रत्येक probe पर आने वाले receipts की संख्या गिनें, OS/client (Android बनाम iOS बनाम desktop) का अनुमान लगाने के लिए RTTs को cluster करें और online/offline transitions पर नज़र रखें।
* **G2 – Behavioural monitoring:** high-frequency RTT series (≈1 Hz स्थिर है) को time-series की तरह लें और screen on/off, app foreground/background, commuting बनाम working hours आदि का अनुमान लगाएँ।
* **G3 – Resource exhaustion:** प्रत्येक victim device के radios/CPUs को never-ending silent probes भेजकर awake रखें, battery/data drain करें और VoIP/RTC quality को degrade करें।<sup>[[1]](#references)</sup>

Abuse surface का वर्णन करने के लिए दो threat actors पर्याप्त हैं:<sup>[[1]](#references)</sup>

1. **Creepy companion:** पहले से victim के साथ chat साझा करता है और self-reactions, reaction removals या existing message IDs से जुड़े repeated edits/deletes का दुरुपयोग करता है।
2. **Spooky stranger:** burner account register करता है और ऐसे message IDs को reference करने वाले reactions भेजता है जो local conversation में कभी मौजूद नहीं थे; WhatsApp और Signal तब भी उन्हें decrypt और acknowledge करते हैं, भले ही UI state change को discard कर दे। इसलिए prior conversation आवश्यक नहीं है।

## Raw protocol access के लिए Tooling

ऐसे clients पर निर्भर रहें जो underlying E2EE protocol expose करते हों, ताकि आप UI constraints के बाहर packets craft कर सकें, arbitrary `message_id`s specify कर सकें और precise timestamps log कर सकें:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) या [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) आपको raw `ReactionMessage`, `ProtocolMessage` (edit/delete) और `Receipt` frames emit करने देते हैं, जबकि double-ratchet state sync में रहती है।<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) को [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) के साथ उपयोग करने पर CLI/API के माध्यम से प्रत्येक message type expose होता है।<sup>[[5]](#references)[[7]](#references)</sup> वर्तमान `signal-cli` syntax `sendReaction RECIPIENT --target-author --target-timestamp` का उपयोग करता है; delivery receipts वास्तव में collect करने के लिए `receive` या `daemon` को running रखें।<sup>[[6]](#references)</sup> Example self-reaction toggle:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Android client का Source दस्तावेज़ करता है कि delivery receipts device से बाहर जाने से पहले कैसे consolidate किए जाते हैं, जिससे स्पष्ट होता है कि वहाँ side channel की bandwidth नगण्य क्यों है।<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) WhatsApp/Signal backends के साथ आता है, silent delete probes को default बनाता है और rolling-median threshold (`RTT < 0.9 * median`) के आधार पर `active` बनाम `standby` label करता है।<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) एक हल्का WhatsApp-first CLI है, जिसमें `--delay`, `--concurrent`, CSV/Prometheus exporters और Grafana-friendly output हैं।<sup>[[9]](#references)</sup> दोनों को protocol references के बजाय reconnaissance helpers समझें; मुख्य बात यह है कि raw client access मिलने के बाद कितने कम code की आवश्यकता होती है।

जब custom tooling उपलब्ध न हो, तब भी WhatsApp Web या Signal Desktop से silent actions trigger करके encrypted websocket/WebRTC channel sniff किया जा सकता है, लेकिन raw APIs UI delays हटाते हैं और invalid operations की अनुमति देते हैं।

## Creepy companion: silent sampling loop

1. Chat में आपके द्वारा authored कोई भी historical message चुनें, ताकि victim को "reaction" balloons बदलते हुए न दिखें।
2. Visible emoji और empty reaction payload के बीच alternate करें (WhatsApp protobufs में `""` के रूप में encoded या signal-cli में `--remove`)। Victim के लिए कोई UI delta न होने के बावजूद प्रत्येक transmission device ack उत्पन्न करता है।
3. Send time और प्रत्येक delivery receipt arrival का timestamp लें। निम्न जैसा 1 Hz loop अनिश्चित समय तक per-device RTT traces देता है:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. क्योंकि WhatsApp/Signal unlimited reaction updates स्वीकार करते हैं, attacker को नया chat content post करने या edit windows की चिंता करने की आवश्यकता नहीं होती।<sup>[[1]](#references)</sup>

## Spooky stranger: arbitrary phone numbers को probe करना

1. नया WhatsApp/Signal account register करें और target number के public identity keys प्राप्त करें (यह session setup के दौरान automatically होता है)।
2. ऐसा reaction/edit/delete packet craft करें जो किसी random `message_id` को reference करे, जिसे किसी भी party ने कभी नहीं देखा हो (WhatsApp arbitrary `key.id` GUIDs स्वीकार करता है; Signal millisecond timestamps का उपयोग करता है)।
3. Thread मौजूद न होने पर भी packet भेजें। Victim devices इसे decrypt करते हैं, base message से match न होने पर state change discard करते हैं, लेकिन incoming ciphertext को फिर भी acknowledge करते हैं और device receipts attacker को वापस भेजते हैं।
4. Victim की chat list में कभी दिखाई दिए बिना RTT series बनाने के लिए इसे लगातार दोहराएँ।<sup>[[1]](#references)</sup>

यदि पहले यह पता लगाना आवश्यक हो कि कौन-से numbers registered हैं या बड़े scale पर device inventories pre-seed करनी हैं, तो random E.164 ranges को manually guess करने के बजाय इसे [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) के साथ chain करें।

Published contact-discovery work ने दिखाया कि यह operationally क्यों महत्वपूर्ण है: accurate phone-prefix tables और modest resources के साथ researchers WhatsApp पर लगभग `10%` और Signal पर `100%` US mobile numbers query करने में सक्षम थे, जिसके बाद targeted probing किया गया।<sup>[[11]](#references)</sup> व्यवहार में, पहले live accounts को pre-filter करने से silent-probe budget उन numbers पर केंद्रित रहता है जो वास्तव में packets decrypt करेंगे।

हाल के WhatsApp builds `Settings -> Privacy -> Advanced -> Block unknown account messages` भी expose करते हैं।<sup>[[10]](#references)</sup> इसे fix नहीं, बल्कि throughput limiter समझें: यह मुख्यतः sustained stranger-only flooding को प्रभावित करता है और जब आप पहले से known contact हों, तब अप्रासंगिक है।

## Covert triggers के रूप में edits और deletes को recycle करना

* **Repeated deletes:** किसी message को एक बार delete-for-everyone करने के बाद, उसी `message_id` को reference करने वाले आगे के delete packets का कोई UI effect नहीं होता, लेकिन प्रत्येक device उन्हें decrypt और acknowledge करता रहता है।
* **Out-of-window operations:** WhatsApp UI में लगभग 60 h delete / लगभग 20 min edit windows लागू करता है; Signal लगभग 48 h लागू करता है। इन windows के बाहर crafted protocol messages victim device पर silently ignore किए जाते हैं, फिर भी receipts transmit होते हैं। इसलिए conversation समाप्त होने के लंबे समय बाद भी attackers indefinitely probe कर सकते हैं।
* **Invalid payloads:** Malformed edit bodies या पहले से purged messages को reference करने वाले deletes भी यही behaviour उत्पन्न करते हैं—decryption और receipt, लेकिन zero user-visible artefacts।<sup>[[1]](#references)</sup>

## Multi-device amplification और fingerprinting

* प्रत्येक associated device (phone, desktop app, browser companion) probe को independently decrypt करता है और अपना ack लौटाता है। प्रति probe receipts की संख्या गिनने से exact device count पता चलता है।
* यदि कोई device offline है, तो उसका receipt queued रहता है और reconnection पर emit होता है। इसलिए gaps online/offline cycles और commuting schedules तक leak करते हैं (जैसे travel के दौरान desktop receipts बंद हो जाते हैं)।
* OS power management और push wakeups के कारण platforms के RTT distributions अलग होते हैं। RTTs को cluster करें (जैसे median/variance features पर k-means) और उन्हें “Android handset", “iOS handset", “Electron desktop" आदि label करें।
* Encryption से पहले sender को recipient का key inventory retrieve करना पड़ता है, इसलिए attacker यह भी देख सकता है कि नए devices कब pair किए गए; device count में अचानक वृद्धि या नया RTT cluster एक strong indicator है।<sup>[[1]](#references)</sup>

## Sampling cadence, queueing और stacked receipts

* **WhatsApp burst tolerance:** Published measurements के अनुसार WhatsApp ने silent-reaction bursts को लगभग `50 ms` में एक probe की गति तक बिना स्पष्ट server-side queueing के स्वीकार किया। यह short calibration bursts, fast device counting या drain attack को जल्दी ramp करने के लिए उपयोगी है।
* **Signal long-run queueing:** Signal ने short bursts tolerate किए, लेकिन sustained multi-probe-per-second traffic को queue करना शुरू कर दिया। Long-lived monitoring के लिए cadence लगभग `1 Hz` (या कम) रखें, ताकि प्रत्येक receipt backlog drain के बजाय current device state को दर्शाए।
* **Reconnect artefacts:** जब कोई device online वापस आता है, तो कुछ clients कई delayed receipts को batch या तेजी से flush करते हैं। इन receipt bursts को independent RTT samples के बजाय state-transition marker समझें, अन्यथा आपका clustering / `active` बनाम `idle` classifier reconnect noise पर overfit करेगा।<sup>[[1]](#references)</sup>

## RTT traces से Behaviour inference

1. OS scheduling effects capture करने के लिए ≥1 Hz पर sample करें। WhatsApp on iOS में <1 s RTTs screen-on/foreground और >1 s RTTs screen-off/background throttling से strongly correlate करते हैं।
2. Simple classifiers (thresholding या two-cluster k-means) बनाएँ, जो प्रत्येक RTT को "active" या "idle" label करें। Bedtimes, commutes, work hours या desktop companion के active होने का अनुमान लगाने के लिए labels को streaks में aggregate करें।
3. प्रत्येक device की ओर simultaneous probes correlate करें, ताकि पता चल सके कि users mobile से desktop पर कब switch करते हैं, companions कब offline जाते हैं और app push बनाम persistent socket द्वारा rate limited है या नहीं।
4. Real networks में एक single hardcoded `1 s` threshold से बचें। प्रत्येक device को short warm-up window से bootstrap करें और rolling baseline रखें (उदाहरण के लिए, `threshold = 0.9 * median RTT`), ताकि Wi-Fi/cellular drift आपके classifier को collapse न करे।<sup>[[1]](#references)</sup>

## Delivery RTT से Location inference

इसी timing primitive का उपयोग recipient के active होने के बजाय उसके स्थान का अनुमान लगाने के लिए भी किया जा सकता है। `Hope of Delivery` work ने दिखाया कि known receiver locations के RTT distributions पर training करने के बाद attacker केवल delivery confirmations से victim की location classify कर सकता है:<sup>[[2]](#references)</sup>

* Target के लिए कई known places (home, office, campus, country A बनाम country B आदि) पर baseline बनाएँ।
* प्रत्येक location के लिए कई normal message RTTs collect करें और median, variance या percentile buckets जैसी simple features extract करें।
* वास्तविक attack के दौरान नई probe series की तुलना trained clusters से करें। Paper के अनुसार, एक ही city के भीतर की locations को भी अक्सर अलग किया जा सकता है; 3-location setting में accuracy `>80%` तक रही।
* यह तब सबसे अच्छा काम करता है जब attacker sender environment को control करता हो और similar network conditions में probes करता हो, क्योंकि measured path में recipient access network, wake-up latency और messenger infrastructure शामिल होते हैं।<sup>[[2]](#references)</sup>

ऊपर दिए गए silent reaction/edit/delete attacks के विपरीत, location inference के लिए invalid message IDs या stealthy state-changing packets आवश्यक नहीं हैं। Normal delivery confirmations वाले plain messages पर्याप्त हैं, इसलिए tradeoff कम stealth लेकिन messengers के बीच व्यापक applicability है।

## Stealthy resource exhaustion

क्योंकि प्रत्येक silent probe को decrypt और acknowledge करना आवश्यक है, reaction toggles, invalid edits या delete-for-everyone packets लगातार भेजने से application-layer DoS उत्पन्न होता है:<sup>[[1]](#references)</sup>

* Radio/modem को हर second transmit/receive करने के लिए बाध्य करता है → विशेषकर idle handsets पर noticeable battery drain।
* Unmetered upstream/downstream traffic उत्पन्न करता है, जो TLS/WebSocket noise में blend होते हुए mobile data plans consume करता है।
* Crypto threads को व्यस्त करता है और latency-sensitive features (VoIP, video calls) में jitter लाता है, भले ही user को कोई notification दिखाई न दे।
* WhatsApp पर invalid reactions normal emoji से संकेतित data की तुलना में कहीं अधिक data स्वीकार करते हैं: published measurements में प्रति reaction server-side acceptance लगभग `1 MB` तक पाया गया।
* Body लगभग `30 bytes` से बड़ा होने पर oversized reactions reliable delivery receipts देना बंद कर देते हैं, लेकिन discard से पहले भी forward और process किए जाते हैं। ACKs की आवश्यकता हो तो reaction bodies छोटे रखें; pure drain या covert one-way transport का लक्ष्य होने पर ही उन्हें inflate करें।
* Public measurements में इस mode में लगभग `3.7 MB/s` (`~13.3 GB/h`) victim traffic तक पहुँचा।

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
