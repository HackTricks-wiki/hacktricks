# E2EE Messengers में Delivery Receipt Side-Channel Attacks

{{#include ../banners/hacktricks-training.md}}

Delivery receipts आधुनिक end-to-end encrypted (E2EE) messengers में अनिवार्य हैं क्योंकि clients को यह जानना होता है कि ciphertext कब decrypt हुआ ताकि वे ratcheting state और ephemeral keys discard कर सकें। server opaque blobs forward करता है, इसलिए device acknowledgements (double checkmarks) recipient द्वारा successful decryption के बाद emit किए जाते हैं। attacker-triggered action और corresponding delivery receipt के बीच round-trip time (RTT) मापने से एक high-resolution timing channel मिलता है जो device state, online presence leak करता है, और covert DoS के लिए abuse किया जा सकता है। Multi-device "client-fanout" deployments leakage को amplify करते हैं क्योंकि हर registered device probe decrypt करता है और अपना खुद का receipt लौटाता है।

## Delivery receipt sources vs. user-visible signals

ऐसे message types चुनें जो हमेशा delivery receipt emit करें लेकिन victim पर UI artifacts न दिखाएँ। नीचे दिया गया table empirically confirmed behaviour का सारांश है:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | हमेशा noisy → केवल state bootstrap करने के लिए उपयोगी। |
| | Reaction | ● | ◐ (केवल अगर victim message पर reacting हो) | Self-reactions और removals silent रहते हैं। |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20min; expiry के बाद भी ack’d रहता है। |
| | Delete for everyone | ● | ○ | UI लगभग 60h तक allow करता है, लेकिन बाद के packets भी ack’d रहते हैं। |
| **Signal** | Text message | ● | ● | वही limitations जो WhatsApp में हैं। |
| | Reaction | ● | ◐ | Self-reactions victim को invisible रहते हैं। |
| | Edit/Delete | ● | ○ | Server लगभग 48h window enforce करता है, 10 edits तक allow करता है, लेकिन late packets भी ack’d रहते हैं। |
| **Threema** | Text message | ● | ● | Multi-device receipts aggregated होते हैं, इसलिए प्रति probe केवल एक RTT visible होता है। |

Legend: ● = हमेशा, ◐ = conditional, ○ = कभी नहीं। Platform-dependent UI behaviour inline noted है। जरूरत हो तो read receipts disable करें, लेकिन delivery receipts WhatsApp या Signal में turn off नहीं किए जा सकते।

## Attacker goals and models

* **G1 – Device fingerprinting:** प्रति probe कितने receipts आते हैं गिनें, RTTs को cluster करें ताकि OS/client (Android vs iOS vs desktop) infer हो सके, और online/offline transitions देखें।
* **G2 – Behavioural monitoring:** high-frequency RTT series (≈1 Hz स्थिर है) को time-series की तरह treat करें और screen on/off, app foreground/background, commuting vs working hours, आदि infer करें।
* **G3 – Resource exhaustion:** कभी न खत्म होने वाले silent probes भेजकर हर victim device के radios/CPUs को awake रखें, battery/data drain करें और VoIP/RTC quality degrade करें।

Abuse surface को describe करने के लिए दो threat actors पर्याप्त हैं:

1. **Creepy companion:** पहले से victim के साथ chat share करता है और self-reactions, reaction removals, या existing message IDs से जुड़े repeated edits/deletes का abuse करता है।
2. **Spooky stranger:** एक burner account register करता है और ऐसे message IDs को reference करने वाली reactions भेजता है जो local conversation में कभी मौजूद ही नहीं थे; WhatsApp और Signal फिर भी उन्हें decrypt और acknowledge करते हैं, भले ही UI state change discard कर दे, इसलिए पहले से conversation होना आवश्यक नहीं है।

## Tooling for raw protocol access

ऐसे clients पर भरोसा करें जो underlying E2EE protocol expose करते हों ताकि आप UI constraints के बाहर packets craft कर सकें, arbitrary `message_id`s specify कर सकें, और precise timestamps log कर सकें:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) या [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) आपको raw `ReactionMessage`, `ProtocolMessage` (edit/delete), और `Receipt` frames emit करने देते हैं, जबकि double-ratchet state sync में रहती है।
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) को [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) के साथ मिलाकर हर message type CLI/API के जरिए expose होता है। Current `signal-cli` syntax `sendReaction RECIPIENT --target-author --target-timestamp` उपयोग करता है; delivery receipts वास्तव में collect हों इसलिए `receive` या `daemon` चलाते रहें। Example self-reaction toggle:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Android client का source document करता है कि delivery receipts device से बाहर जाने से पहले consolidated हो जाते हैं, इसलिए वहाँ side channel की bandwidth नगण्य होती है।
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) WhatsApp/Signal backends ship करता है, default रूप से silent delete probes use करता है, और rolling-median threshold (`RTT < 0.9 * median`) के साथ `active` vs `standby` label करता है। [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) एक हल्का WhatsApp-first CLI है जिसमें `--delay`, `--concurrent`, CSV/Prometheus exporters, और Grafana-friendly output हैं। दोनों को protocol references की बजाय reconnaissance helpers की तरह देखें; मुख्य takeaway यह है कि raw client access होने पर code कितना कम चाहिए।

जब custom tooling उपलब्ध न हो, तब भी आप WhatsApp Web या Signal Desktop से silent actions trigger कर सकते हैं और encrypted websocket/WebRTC channel sniff कर सकते हैं, लेकिन raw APIs UI delays हटा देती हैं और invalid operations की अनुमति देती हैं।

## Creepy companion: silent sampling loop

1. चैट में अपनी authored कोई भी historical message चुनें ताकि victim को कभी "reaction" balloons बदलते हुए न दिखें।
2. एक visible emoji और एक empty reaction payload (WhatsApp protobufs में `""` या signal-cli में `--remove`) के बीच alternate करें। हर transmission victim के लिए कोई UI delta न होने पर भी device ack देता है।
3. send time और हर delivery receipt arrival timestamp करें। निम्न जैसा 1 Hz loop प्रति-device RTT traces indefinitely देता है:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. क्योंकि WhatsApp/Signal unlimited reaction updates accept करते हैं, attacker को नया chat content post करने या edit windows की चिंता करने की जरूरत नहीं होती।

## Spooky stranger: probing arbitrary phone numbers

1. एक fresh WhatsApp/Signal account register करें और target number के लिए public identity keys fetch करें (session setup के दौरान automatic होता है)।
2. ऐसा reaction/edit/delete packet craft करें जो किसी random `message_id` को reference करता हो जो दोनों पक्षों ने कभी नहीं देखा (WhatsApp arbitrary `key.id` GUIDs accept करता है; Signal millisecond timestamps use करता है)।
3. Packet भेजें, भले ही कोई thread मौजूद न हो। victim devices इसे decrypt करते हैं, base message से match करने में fail होते हैं, state change discard करते हैं, लेकिन फिर भी incoming ciphertext acknowledge करते हैं, और device receipts attacker को वापस भेजते हैं।
4. इसे लगातार repeat करें ताकि victim की chat list में कभी दिखाई दिए बिना RTT series बन सके।

अगर पहले आपको यह पता करना हो कि कौन-से numbers registered हैं या scale पर device inventories pre-seed करनी हों, तो random E.164 ranges को हाथ से guess करने के बजाय इसे [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) के साथ chain करें।

Recent WhatsApp builds में `Settings -> Privacy -> Advanced -> Block unknown account messages` भी expose होता है। इसे fix नहीं, throughput limiter समझें: यह मुख्यतः sustained stranger-only flooding को नुकसान पहुँचाता है और एक बार आप known contact बन चुके हों तो irrelevant हो जाता है।

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** एक message को delete-for-everyone once delete करने के बाद, same `message_id` को reference करने वाले आगे के delete packets का कोई UI effect नहीं होता, लेकिन हर device फिर भी उन्हें decrypt और acknowledge करता है।
* **Out-of-window operations:** WhatsApp UI में लगभग 60h delete / लगभग 20min edit windows enforce करता है; Signal लगभग 48h enforce करता है। इन windows के बाहर crafted protocol messages victim device पर silently ignored हो जाते हैं, लेकिन receipts transmit होते रहते हैं, इसलिए attacker conversation खत्म होने के बहुत बाद तक probe कर सकता है।
* **Invalid payloads:** Malformed edit bodies या पहले से purged messages को reference करने वाले deletes वही behaviour दिखाते हैं—decryption plus receipt, zero user-visible artefacts।

## Multi-device amplification & fingerprinting

* हर associated device (phone, desktop app, browser companion) probe को independently decrypt करता है और अपना own ack लौटाता है। प्रति probe receipts गिनने से exact device count पता चलता है।
* अगर कोई device offline है, तो उसका receipt queued रहता है और reconnection पर emit होता है। इसलिए gaps online/offline cycles और commuting schedules तक leak करते हैं (जैसे travel के दौरान desktop receipts रुक जाते हैं)।
* RTT distributions platform के अनुसार अलग होती हैं क्योंकि OS power management और push wakeups अलग होते हैं। RTTs cluster करें (जैसे median/variance features पर k-means) ताकि “Android handset", “iOS handset", “Electron desktop", आदि label किए जा सकें।
* क्योंकि sender को encrypt करने से पहले recipient के key inventory को retrieve करना होता है, attacker यह भी देख सकता है कि नए devices कब paired हुए; device count में अचानक वृद्धि या नया RTT cluster एक मजबूत indicator है।

## Behaviour inference from RTT traces

1. OS scheduling effects capture करने के लिए ≥1 Hz पर sample करें। WhatsApp on iOS में, <1 s RTTs screen-on/foreground से strongly correlate करती हैं, >1 s RTTs screen-off/background throttling से।
2. सरल classifiers बनाएं (thresholding या two-cluster k-means) जो हर RTT को "active" या "idle" label करें। इन labels को streaks में aggregate करके bedtime, commute, work hours, या desktop companion active होने का समय derive करें।
3. सभी devices की simultaneous probes correlate करें ताकि पता चले user mobile से desktop पर कब switch करता है, companions कब offline होते हैं, और app push vs persistent socket से rate limited है या नहीं।
4. वास्तविक networks में, एक hardcoded `1 s` threshold से बचें। हर device को short warm-up window से bootstrap करें और rolling baseline रखें (उदाहरण के लिए, `threshold = 0.9 * median RTT`) ताकि Wi-Fi/cellular drift आपका classifier collapse न कर दे।

## Location inference from delivery RTT

वही timing primitive recipient कहाँ है यह infer करने के लिए reuse किया जा सकता है, सिर्फ यह नहीं कि वे active हैं या नहीं। `Hope of Delivery` work ने दिखाया कि ज्ञात receiver locations की RTT distributions पर training करने से attacker बाद में केवल delivery confirmations से victim की location classify कर सकता है:

* उसी target के लिए baseline बनाएं जब वे कई ज्ञात स्थानों पर हों (home, office, campus, country A vs country B, आदि)।
* हर location के लिए कई normal message RTTs collect करें और median, variance, या percentile buckets जैसे simple features extract करें।
* वास्तविक attack के दौरान, नए probe series को trained clusters के against compare करें। paper रिपोर्ट करता है कि एक ही city के भीतर locations भी अक्सर अलग किए जा सकते हैं, 3-location setting में `>80%` accuracy के साथ।
* यह तब सबसे अच्छा काम करता है जब attacker sender environment control करता हो और similar network conditions में probe करता हो, क्योंकि measured path में recipient access network, wake-up latency, और messenger infrastructure शामिल होती है।

ऊपर दिए गए silent reaction/edit/delete attacks के विपरीत, location inference के लिए invalid message IDs या stealthy state-changing packets की जरूरत नहीं होती। Normal delivery confirmations वाले plain messages पर्याप्त हैं, इसलिए tradeoff कम stealth लेकिन messengers में wider applicability है।

## Stealthy resource exhaustion

क्योंकि हर silent probe को decrypt और acknowledge करना पड़ता है, लगातार reaction toggles, invalid edits, या delete-for-everyone packets भेजना application-layer DoS बनाता है:

* हर second radio/modem को transmit/receive करने के लिए मजबूर करता है → noticeable battery drain, खासकर idle handsets पर।
* Unmetered upstream/downstream traffic generate करता है जो mobile data plans consume करता है, जबकि TLS/WebSocket noise में blend हो जाता है।
* Crypto threads occupy करता है और latency-sensitive features (VoIP, video calls) में jitter introduce करता है, भले ही user को कोई notification कभी न दिखे।
* WhatsApp पर, invalid reactions normal emoji से कहीं अधिक data accept करते हैं: published measurements ने server-side acceptance लगभग `1 MB` प्रति reaction तक पाया।
* Oversized reactions लगभग `30 bytes` से body बड़ी होने पर reliable delivery receipts देना बंद कर देते हैं, लेकिन discard से पहले फिर भी forward और process किए जाते हैं। जब ACKs चाहिए हों तो reaction bodies छोटी रखें; उन्हें केवल तब inflate करें जब goal pure drain या covert one-way transport हो।
* Public measurements ने इस mode में victim traffic लगभग `3.7 MB/s` (`~13.3 GB/h`) तक पहुँचाया।

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
