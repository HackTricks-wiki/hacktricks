# E2EE Messengers में Delivery Receipt Side-Channel Attacks

{{#include ../banners/hacktricks-training.md}}

Delivery receipts आधुनिक end-to-end encrypted (E2EE) messengers में अनिवार्य हैं क्योंकि clients को यह जानना होता है कि ciphertext कब decrypted हुआ, ताकि वे ratcheting state और ephemeral keys को discard कर सकें। Server opaque blobs forward करता है, इसलिए device acknowledgements (double checkmarks) recipient द्वारा successful decryption के बाद emit होते हैं। Attacker-triggered action और corresponding delivery receipt के बीच round-trip time (RTT) मापने से एक high-resolution timing channel exposed होता है जो device state, online presence, और covert DoS के लिए abuse किया जा सकता है। Multi-device "client-fanout" deployments leakage को amplify करते हैं क्योंकि हर registered device probe को decrypt करता है और अपना receipt वापस भेजता है।

## Delivery receipt sources vs. user-visible signals

ऐसे message types चुनें जो हमेशा delivery receipt emit करें लेकिन victim पर UI artifacts न दिखाएँ। नीचे दी गई table empirically confirmed behaviour का सार देती है:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | हमेशा noisy → केवल state bootstrap करने के लिए उपयोगी। |
| | Reaction | ● | ◐ (only if reacting to victim message) | Self-reactions और removals silent रहते हैं। |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; expiry के बाद भी ack’d रहता है। |
| | Delete for everyone | ● | ○ | UI ~60 h तक allow करता है, लेकिन बाद के packets भी ack’d रहते हैं। |
| **Signal** | Text message | ● | ● | वही सीमाएँ जो WhatsApp में हैं। |
| | Reaction | ● | ◐ | Self-reactions victim को invisible रहते हैं। |
| | Edit/Delete | ● | ○ | Server ~48 h window enforce करता है, 10 edits तक allow करता है, लेकिन late packets फिर भी ack’d रहते हैं। |
| **Threema** | Text message | ● | ● | Multi-device receipts aggregated होते हैं, इसलिए प्रति probe केवल एक RTT visible होता है। |

Legend: ● = always, ◐ = conditional, ○ = never. Platform-dependent UI behaviour inline noted है। जरूरत हो तो read receipts disable करें, लेकिन WhatsApp या Signal में delivery receipts बंद नहीं किए जा सकते।

## Attacker goals and models

* **G1 – Device fingerprinting:** प्रति probe कितने receipts आते हैं यह count करें, RTTs को cluster करके OS/client (Android vs iOS vs desktop) infer करें, और online/offline transitions observe करें।
* **G2 – Behavioural monitoring:** high-frequency RTT series (≈1 Hz stable है) को time-series की तरह treat करें और screen on/off, app foreground/background, commuting vs working hours, आदि infer करें।
* **G3 – Resource exhaustion:** कभी खत्म न होने वाले silent probes भेजकर हर victim device के radios/CPUs को awake रखें, battery/data drain करें और VoIP/RTC quality degrade करें।

Abuse surface को describe करने के लिए दो threat actors पर्याप्त हैं:

1. **Creepy companion:** पहले से victim के साथ chat share करता है और self-reactions, reaction removals, या existing message IDs से जुड़े repeated edits/deletes का abuse करता है।
2. **Spooky stranger:** burner account register करता है और ऐसे message IDs को reference करने वाले reactions भेजता है जो local conversation में कभी थे ही नहीं; WhatsApp और Signal फिर भी उन्हें decrypt और acknowledge करते हैं भले ही UI state change discard कर दे, इसलिए पहले से conversation होना जरूरी नहीं है।

## Tooling for raw protocol access

ऐसे clients पर rely करें जो underlying E2EE protocol expose करते हैं ताकि आप UI constraints के बाहर packets craft कर सकें, arbitrary `message_id`s specify कर सकें, और precise timestamps log कर सकें:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) या [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) आपको raw `ReactionMessage`, `ProtocolMessage` (edit/delete), और `Receipt` frames emit करने देते हैं, जबकि double-ratchet state sync बनी रहती है।
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) को [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) के साथ मिलाकर हर message type को CLI/API के जरिए expose किया जा सकता है। Example self-reaction toggle:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** Android client का source बताता है कि delivery receipts device से बाहर जाने से पहले कैसे consolidated होते हैं, जिससे स्पष्ट होता है कि वहाँ side channel की bandwidth नगण्य है।
* **Turnkey PoCs:** public projects जैसे `device-activity-tracker` और `careless-whisper-python` पहले से silent delete/reaction probes और RTT classification automate करते हैं। इन्हें protocol references की बजाय ready-made reconnaissance helpers समझें; interesting बात यह है कि ये confirm करते हैं कि raw client access होने पर attack operationally simple है।

जब custom tooling उपलब्ध न हो, तब भी आप WhatsApp Web या Signal Desktop से silent actions trigger कर सकते हैं और encrypted websocket/WebRTC channel sniff कर सकते हैं, लेकिन raw APIs UI delays हटाती हैं और invalid operations allow करती हैं।

## Creepy companion: silent sampling loop

1. chat में अपनी कोई historical message चुनें ताकि victim को कभी "reaction" balloons बदलते हुए न दिखें।
2. visible emoji और empty reaction payload (WhatsApp protobufs में `""` के रूप में encoded, या signal-cli में `--remove`) के बीच alternate करें। हर transmission victim के लिए कोई UI delta न होने के बावजूद device ack देता है।
3. send time और हर delivery receipt arrival timestamp करें। नीचे जैसा 1 Hz loop प्रति-device RTT traces अनिश्चितकाल तक देता है:
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

1. एक fresh WhatsApp/Signal account register करें और target number के लिए public identity keys fetch करें (session setup के दौरान automatically किया जाता है)।
2. ऐसा reaction/edit/delete packet craft करें जो किसी random `message_id` को reference करे जो किसी भी party ने कभी नहीं देखा (WhatsApp arbitrary `key.id` GUIDs accept करता है; Signal millisecond timestamps इस्तेमाल करता है)।
3. Packet भेजें, भले ही कोई thread मौजूद न हो। Victim devices उसे decrypt करते हैं, base message match करने में fail करते हैं, state change discard करते हैं, लेकिन फिर भी incoming ciphertext acknowledge करते हैं और device receipts attacker को वापस भेजते हैं।
4. इसे लगातार repeat करें ताकि victim के chat list में कभी दिखाई दिए बिना RTT series बन सके।

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** एक message को once delete-for-everyone करने के बाद, उसी `message_id` को reference करने वाले आगे के delete packets का UI पर कोई effect नहीं होता, लेकिन हर device फिर भी उन्हें decrypt और acknowledge करता है।
* **Out-of-window operations:** WhatsApp UI में ~60 h delete / ~20 min edit windows enforce करता है; Signal ~48 h enforce करता है। इन windows के बाहर crafted protocol messages victim device पर silently ignored हो जाते हैं, फिर भी receipts transmit होते हैं, इसलिए attackers बातचीत खत्म होने के बहुत बाद तक भी probe कर सकते हैं।
* **Invalid payloads:** Malformed edit bodies या पहले से purged messages को reference करने वाले deletes वही व्यवहार दिखाते हैं—decryption plus receipt, zero user-visible artefacts।

## Multi-device amplification & fingerprinting

* हर associated device (phone, desktop app, browser companion) probe को independently decrypt करता है और अपना own ack लौटाता है। प्रति probe receipts count करने से exact device count पता चलता है।
* अगर कोई device offline है, तो उसका receipt queue में रहता है और reconnection पर emit होता है। इसलिए gaps online/offline cycles और यहाँ तक कि commuting schedules भी leak करते हैं (जैसे travel के दौरान desktop receipts रुक जाते हैं)।
* RTT distributions platform के अनुसार अलग होती हैं, OS power management और push wakeups की वजह से। RTTs को cluster करें (जैसे median/variance features पर k-means) ताकि “Android handset", “iOS handset", “Electron desktop", आदि label किए जा सकें।
* क्योंकि sender को encrypt करने से पहले recipient का key inventory retrieve करना होता है, attacker यह भी देख सकता है कि नए devices कब paired हुए; device count में अचानक बढ़ोतरी या नया RTT cluster एक मजबूत indicator है।

## Behaviour inference from RTT traces

1. OS scheduling effects capture करने के लिए ≥1 Hz पर sample करें। WhatsApp on iOS में, <1 s RTTs screen-on/foreground से strongly correlate करते हैं, जबकि >1 s screen-off/background throttling से।
2. Simple classifiers (thresholding या two-cluster k-means) बनाएं जो हर RTT को "active" या "idle" label करें। इन labels को streaks में aggregate करके bedtime, commutes, work hours, या desktop companion active होने का समय निकाला जा सकता है।
3. सभी devices की तरफ simultaneous probes correlate करें ताकि पता चले user कब mobile से desktop पर switch करता है, कब companions offline जाते हैं, और क्या app push या persistent socket द्वारा rate limited है।

## Location inference from delivery RTT

वही timing primitive इस काम के लिए repurpose किया जा सकता है कि recipient कहाँ है, सिर्फ यह नहीं कि वे active हैं या नहीं। `Hope of Delivery` work ने दिखाया कि known receiver locations के RTT distributions पर training करके attacker बाद में केवल delivery confirmations से victim की location classify कर सकता है:

* उसी target के लिए baseline बनाएं जब वे कई known places में हों (home, office, campus, country A vs country B, आदि)।
* हर location के लिए कई normal message RTTs collect करें और median, variance, या percentile buckets जैसे simple features extract करें।
* वास्तविक attack के दौरान, नए probe series को trained clusters से compare करें। Paper reports करता है कि एक ही शहर के भीतर की locations भी अक्सर अलग की जा सकती हैं, 3-location setting में `>80%` accuracy के साथ।
* यह सबसे अच्छा तब काम करता है जब attacker sender environment control करता हो और similar network conditions में probes चलाए, क्योंकि measured path में recipient access network, wake-up latency, और messenger infrastructure शामिल होती है।

ऊपर दिए गए silent reaction/edit/delete attacks के विपरीत, location inference के लिए invalid message IDs या stealthy state-changing packets की जरूरत नहीं होती। Normal delivery confirmations वाले plain messages पर्याप्त हैं, इसलिए tradeoff कम stealth लेकिन messengers में wider applicability है।

## Stealthy resource exhaustion

क्योंकि हर silent probe को decrypt और acknowledge करना पड़ता है, लगातार reaction toggles, invalid edits, या delete-for-everyone packets भेजना application-layer DoS बनाता है:

* हर second radio/modem को transmit/receive करने के लिए मजबूर करता है → noticeable battery drain, खासकर idle handsets पर।
* Unmetered upstream/downstream traffic generate करता है जो mobile data plans consume करता है, जबकि TLS/WebSocket noise में blend हो जाता है।
* Crypto threads occupy करता है और latency-sensitive features (VoIP, video calls) में jitter introduce करता है, भले ही user को notifications कभी दिखें नहीं।

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)

{{#include ../banners/hacktricks-training.md}}
