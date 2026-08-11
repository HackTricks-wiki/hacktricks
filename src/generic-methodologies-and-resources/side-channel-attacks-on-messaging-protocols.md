# E2EE Messengers में Delivery Receipt Side-Channel Attacks

{{#include ../banners/hacktricks-training.md}}

आधुनिक end-to-end encrypted (E2EE) messengers में delivery receipts अनिवार्य होते हैं, क्योंकि clients को यह जानना आवश्यक होता है कि ciphertext कब decrypt हुआ, ताकि वे ratcheting state और ephemeral keys को discard कर सकें। Server opaque blobs को forward करता है, इसलिए device acknowledgements (double checkmarks) recipient द्वारा successful decryption के बाद भेजे जाते हैं। Attacker द्वारा trigger किए गए action और संबंधित delivery receipt के बीच round-trip time (RTT) को मापने से एक high-resolution timing channel उजागर होता है, जो device state और online presence को leak करता है और covert DoS के लिए दुरुपयोग किया जा सकता है। Multi-device "client-fanout" deployments इस leakage को बढ़ा देते हैं, क्योंकि प्रत्येक registered device probe को decrypt करके अपनी receipt लौटाता है।<sup>[[1]](#references)</sup>

## Delivery receipt sources vs. user-visible signals

ऐसे message types चुनें जो हमेशा delivery receipt भेजें, लेकिन victim के UI में कोई artifact दिखाई न दे। नीचे दी गई table empirically confirmed behaviour का सारांश देती है:<sup>[[1]](#references)</sup>

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | हमेशा noisy → केवल state को bootstrap करने के लिए उपयोगी। |
| | Reaction | ● | ◐ (केवल victim message पर react करने पर) | Self-reactions और removals silent रहते हैं। |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; expiry के बाद भी ack’d होता है। |
| | Delete for everyone | ● | ○ | UI ~60 h की अनुमति देता है, लेकिन बाद के packets अभी भी ack’d होते हैं। |
| **Signal** | Text message | ● | ● | WhatsApp जैसी ही limitations। |
| | Reaction | ● | ◐ | Self-reactions victim को दिखाई नहीं देते। |
| | Edit/Delete | ● | ○ | Server ~48 h window लागू करता है और अधिकतम 10 edits की अनुमति देता है, लेकिन late packets अभी भी ack’d होते हैं। |
| **Threema** | Text message | ● | ● | Multi-device receipts aggregate की जाती हैं, इसलिए प्रत्येक probe के लिए केवल एक RTT दिखाई देता है। |

Legend: ● = हमेशा, ◐ = conditional, ○ = कभी नहीं। Platform-dependent UI behaviour को inline बताया गया है। आवश्यकता होने पर read receipts disable करें, लेकिन WhatsApp या Signal में delivery receipts को बंद नहीं किया जा सकता।<sup>[[1]](#references)</sup>

## Attacker goals and models

* **G1 – Device fingerprinting:** प्रत्येक probe पर आने वाली receipts की संख्या गिनें, OS/client (Android बनाम iOS बनाम desktop) का अनुमान लगाने के लिए RTTs को cluster करें और online/offline transitions पर नज़र रखें।
* **G2 – Behavioural monitoring:** high-frequency RTT series (≈1 Hz स्थिर है) को time-series की तरह देखें और screen on/off, app foreground/background, commuting बनाम working hours आदि का अनुमान लगाएँ।
* **G3 – Resource exhaustion:** प्रत्येक victim device के radios/CPUs को लगातार silent probes भेजकर awake रखें, battery/data समाप्त करें और video-call quality को degrade करें।<sup>[[1]](#references)</sup>

Abuse surface का वर्णन करने के लिए दो threat actors पर्याप्त हैं:<sup>[[1]](#references)</sup>

1. **Creepy companion:** पहले से victim के साथ chat share करता है और existing message IDs से जुड़े self-reactions, reaction removals या repeated edits/deletes का दुरुपयोग करता है।
2. **Spooky stranger:** एक burner account register करता है और ऐसे message IDs को reference करने वाले reactions भेजता है जो local conversation में कभी मौजूद नहीं थे; WhatsApp और Signal state change को UI द्वारा discard किए जाने के बावजूद उन्हें decrypt और acknowledge करते हैं, इसलिए किसी prior conversation की आवश्यकता नहीं होती।

## Tooling for raw protocol access

ऐसे clients पर निर्भर रहें जो underlying E2EE protocol का पर्याप्त भाग expose करते हों, ताकि UI constraints के बाहर supported packets बनाए जा सकें और precise timestamps log किए जा सकें; arbitrary message IDs के लिए प्रत्येक implementation की जाँच आवश्यक है:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web multidevice API) delivery receipts भेजने और प्राप्त करने का documentation देता है; [Cobalt](https://github.com/Auties00/Cobalt) (unofficial Java/Kotlin Web और mobile API) reacting, editing और deleting जैसे message operations का documentation देता है। हर internal frame exposed है ऐसा मानने के बजाय इनके documented APIs का उपयोग करें।<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) CLI, JSON-RPC और D-Bus interfaces expose करता है, जबकि [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) Signal के साथ communicate करने के लिए एक Java library है।<sup>[[5]](#references)[[7]](#references)</sup> वर्तमान `signal-cli` syntax `sendReaction RECIPIENT --target-author --target-timestamp` का उपयोग करता है; protocol updates को process करते रहने के लिए `receive` या `daemon` को running रखें।<sup>[[6]](#references)</sup> Example self-reaction toggle:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Careless Whisper paper में किए गए measurements से पता चला कि delivery receipts devices के बीच synchronized होती हैं, इसलिए multi-device setup में भी प्रत्येक message के लिए केवल एक receipt expose होती है।<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) WhatsApp/Signal backends के साथ आता है, default रूप से silent delete probes का उपयोग करता है और rolling-median threshold (`RTT < 0.9 * median`) के आधार पर `active` बनाम `standby` label करता है।<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) एक हल्का WhatsApp-first CLI है जिसमें `--delay`, `--concurrent`, CSV/Prometheus exporters और Grafana-friendly output हैं।<sup>[[9]](#references)</sup> दोनों को protocol references के बजाय reconnaissance helpers मानें; मुख्य बात यह है कि raw client access उपलब्ध होने के बाद कितने कम code की आवश्यकता होती है।

जब custom tooling उपलब्ध न हो, तब official clients या browser developer tools भी silent actions trigger कर सकते हैं और encrypted traffic timing expose कर सकते हैं; raw APIs UI delays हटाते हैं और invalid operations की अनुमति देते हैं।<sup>[[1]](#references)</sup>

## Creepy companion: silent sampling loop

1. Chat में अपने द्वारा authored कोई भी historical message चुनें, ताकि victim को "reaction" balloons में बदलाव दिखाई न दे।
2. Visible emoji और empty reaction payload के बीच alternate करें (WhatsApp protobufs में `""` या signal-cli में `--remove` के रूप में encoded)। प्रत्येक transmission victim के लिए किसी UI delta के न होने के बावजूद device ack उत्पन्न करता है।
3. Send time और प्रत्येक delivery receipt arrival का timestamp दर्ज करें। निम्न जैसा 1 Hz loop अनिश्चित समय तक प्रत्येक device के RTT traces देता है:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. चूँकि WhatsApp/Signal unlimited reaction updates स्वीकार करते हैं, attacker को कभी नया chat content post करने या edit windows की चिंता करने की आवश्यकता नहीं होती।<sup>[[1]](#references)</sup>

## Spooky stranger: probing arbitrary phone numbers

1. नया WhatsApp/Signal account register करें और target number के लिए public identity keys fetch करें (यह session setup के दौरान automatically होता है)।
2. ऐसा reaction packet बनाएँ जो random `message_id` को reference करे, जिसे किसी भी party ने कभी नहीं देखा हो; paper के अनुसार WhatsApp और Signal दोनों ऐसे reactions स्वीकार करते हैं और फिर भी delivery receipts generate करते हैं।<sup>[[1]](#references)</sup>
3. Thread मौजूद न होने के बावजूद packet भेजें। Victim devices इसे decrypt करते हैं, base message से match करने में fail होते हैं, state change को discard करते हैं, लेकिन incoming ciphertext को acknowledge करते हैं और device receipts attacker को वापस भेजते हैं।
4. किसी prior conversation या visible notification के बिना RTT series बनाने के लिए लगातार repeat करें।<sup>[[1]](#references)</sup>

यदि पहले यह discover करना आवश्यक हो कि कौन-से numbers registered हैं, या scale पर device inventories pre-seed करनी हों, तो random E.164 ranges को manually guess करने के बजाय इसे [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) के साथ chain करें।

Published contact-discovery work ने दिखाया कि यह operational रूप से क्यों महत्वपूर्ण है: accurate phone-prefix tables और modest resources के साथ researchers WhatsApp पर लगभग `10%` और Signal पर `100%` US mobile numbers को query करने में सक्षम थे, जिसके बाद targeted probing किया गया।<sup>[[11]](#references)</sup> व्यवहार में, पहले live accounts को pre-filter करने से आपका silent-probe budget उन्हीं numbers पर केंद्रित रहता है जो वास्तव में packets decrypt करेंगे।

हाल के WhatsApp builds में `Settings -> Privacy -> Advanced -> Block unknown account messages` भी उपलब्ध है।<sup>[[10]](#references)</sup> इसे throughput limiter मानें: tracker documentation के अनुसार WhatsApp unknown accounts से आने वाले high-volume messages को block करता है, लेकिन threshold disclose नहीं करता, इसलिए यह probe reactions को पूरी तरह नहीं रोकता।<sup>[[8]](#references)</sup>

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** किसी message को एक बार delete-for-everyone करने के बाद, उसी `message_id` को reference करने वाले आगे के delete packets का कोई UI effect नहीं होता, लेकिन प्रत्येक device उन्हें decrypt और acknowledge करता रहता है।
* **Out-of-window operations:** WhatsApp UI में ~60 h delete / ~20 min edit windows लागू करता है; Signal ~48 h लागू करता है। इन windows के बाहर crafted protocol messages victim device पर silently ignore किए जाते हैं, फिर भी receipts transmit होती हैं, इसलिए attackers conversation समाप्त होने के लंबे समय बाद भी probe कर सकते हैं।
* **Invalid payloads:** Paper के अनुसार invalid messages को भी acknowledge किया जा सकता है; malformed bodies या purged IDs के लिए exact behaviour implementation-dependent है, इसलिए इस पर निर्भर करने से पहले test करें।<sup>[[1]](#references)</sup>

## Multi-device amplification & fingerprinting

* WhatsApp और Signal पर प्रत्येक associated device (phone, desktop app, browser companion) probe को independently decrypt करता है और अपना ack लौटाता है। प्रत्येक probe पर receipts गिनने से exact device count पता चलता है।<sup>[[1]](#references)</sup>
* यदि कोई device offline है, तो उसकी receipt queue में रखी जाती है और reconnection पर emit होती है। इसलिए gaps online/offline cycles और commuting schedules तक leak करते हैं (जैसे, travel के दौरान desktop receipts रुक जाती हैं)।
* OS, model, client और network conditions timing को प्रभावित करने के कारण platform और environment के अनुसार RTT distributions अलग होती हैं। RTTs को cluster करें (जैसे median/variance features पर k-means) और उन्हें “Android handset", “iOS handset", “Electron desktop" आदि label करें।
* Encrypt करने से पहले sender को recipient की key inventory retrieve करनी होती है, इसलिए attacker यह भी देख सकता है कि नए devices कब pair किए गए; device count में अचानक वृद्धि या नया RTT cluster एक मजबूत indicator है।<sup>[[1]](#references)</sup>

## Sampling cadence, queueing, and stacked receipts

* **WhatsApp burst tolerance:** Published measurements के अनुसार WhatsApp ने स्पष्ट server-side queueing के बिना silent-reaction bursts को प्रत्येक `50 ms` में एक probe तक की गति से स्वीकार किया। यह short calibration bursts, fast device counting या drain attack को तेजी से ramp करने के लिए उपयोगी है।
* **Signal long-run queueing:** Signal ने short bursts tolerate किए, लेकिन sustained multi-probe-per-second traffic को queue करना शुरू कर दिया। Long-lived monitoring के लिए cadence लगभग `1 Hz` (या कम) रखें, ताकि प्रत्येक receipt backlog drain के बजाय current device state को reflect करे।
* **Reconnect artefacts:** Device के online होने पर कुछ clients multiple delayed receipts को batch या rapidly flush करते हैं। इन receipt bursts को independent RTT samples के बजाय state-transition marker मानें, अन्यथा आपका clustering / `active` बनाम `idle` classifier reconnect noise पर overfit करेगा।<sup>[[1]](#references)</sup>

## Behaviour inference from RTT traces

1. OS scheduling effects capture करने के लिए ≥1 Hz पर sample करें। WhatsApp on iOS में <1 s RTTs screen-on/foreground के साथ strongly correlate करते हैं, जबकि >1 s screen-off/background throttling के साथ correlate करते हैं।
2. Simple classifiers (thresholding या two-cluster k-means) बनाएँ जो प्रत्येक RTT को "active" या "idle" label करें। Bedtimes, commutes, work hours या desktop companion के active होने का पता लगाने के लिए labels को streaks में aggregate करें।
3. प्रत्येक device की ओर simultaneous probes को correlate करें, ताकि पता चल सके कि users mobile से desktop पर कब switch करते हैं, companions कब offline जाते हैं और app push बनाम persistent socket द्वारा rate limited है या नहीं।
4. Real networks में एक single hardcoded `1 s` threshold से बचें। प्रत्येक device को short warm-up window से bootstrap करें और rolling baseline रखें (उदाहरण के लिए, device-activity-tracker PoC `threshold = 0.9 * median RTT` का उपयोग करता है), ताकि Wi-Fi/cellular drift आपके classifier को collapse न करे।<sup>[[1]](#references)[[8]](#references)</sup>

## Location inference from delivery RTT

इसी timing primitive को केवल active होने का पता लगाने के बजाय recipient के स्थान का अनुमान लगाने के लिए भी repurpose किया जा सकता है। `Hope of Delivery` work ने दिखाया कि known receiver locations के लिए RTT distributions पर training करने से attacker बाद में केवल delivery confirmations से victim का location classify कर सकता है:<sup>[[2]](#references)</sup>

* जब target कई known places (home, office, campus, country A बनाम country B आदि) में हो, तब उसी target के लिए baseline बनाएँ।
* प्रत्येक location के लिए कई normal message RTTs collect करें और median, variance या percentile buckets जैसे simple features extract करें।
* वास्तविक attack के दौरान नई probe series की तुलना trained clusters से करें। Paper के अनुसार, एक ही city के भीतर के locations को भी अक्सर अलग किया जा सकता है; 3-location setting में accuracy `>80%` तक रही।
* यह सबसे अच्छा तब काम करता है जब attacker sender environment को control करता हो और similar network conditions में probes करता हो, क्योंकि measured path में recipient access network, wake-up latency और messenger infrastructure शामिल होते हैं।<sup>[[2]](#references)</sup>

ऊपर बताए गए silent reaction/edit/delete attacks के विपरीत, location inference के लिए invalid message IDs या stealthy state-changing packets की आवश्यकता नहीं होती। Normal delivery confirmations वाले plain messages पर्याप्त हैं, इसलिए tradeoff कम stealth लेकिन messengers के बीच व्यापक applicability है।

## Stealthy resource exhaustion

क्योंकि प्रत्येक silent probe को decrypt और acknowledge करना आवश्यक है, reaction toggles, invalid edits या delete-for-everyone packets को लगातार भेजने से application-layer DoS उत्पन्न होता है:<sup>[[1]](#references)</sup>

* Radio/modem को हर second transmit/receive करने के लिए मजबूर करता है → विशेष रूप से idle handsets पर noticeable battery drain।
* Upstream/downstream traffic generate करता है, जो mobile data plans consume करता है और video calls जैसी latency-sensitive features के साथ contention पैदा कर सकता है।<sup>[[1]](#references)</sup>
* Large invalid payloads processing work बढ़ाते हैं, लेकिन paper के अनुसार cryptography स्वयं battery cost का negligible भाग है।<sup>[[1]](#references)</sup>
* WhatsApp पर invalid reactions सामान्य emoji के संकेत से कहीं अधिक data स्वीकार करते हैं: published measurements में प्रत्येक reaction के लिए server-side acceptance लगभग `1 MB` तक पाई गई।
* Body लगभग `30 bytes` से अधिक बढ़ने पर oversized reactions reliable delivery receipts उत्पन्न करना बंद कर देते हैं, लेकिन discard से पहले वे अभी भी forward और process किए जाते हैं। ACKs की आवश्यकता होने पर reaction bodies छोटे रखें; केवल drain या covert one-way transport लक्ष्य होने पर उन्हें inflate करें।
* Public measurements में इस mode में लगभग `3.7 MB/s` (`~13.3 GB/h`) victim traffic पहुँचा।

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
