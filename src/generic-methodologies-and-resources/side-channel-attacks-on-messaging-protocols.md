# Delivery Receipt Side-Channel Attacks in E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Delivery receipts आधुनिक end-to-end encrypted (E2EE) messengers में अनिवार्य हैं क्योंकि क्लाइंट्स को पता होना चाहिए कि कोई ciphertext कब decrypted हुआ ताकि वे ratcheting state और ephemeral keys को discard कर सकें। Server opaque blobs आगे भेजता है, इसलिए device acknowledgements (double checkmarks) सफल decryption के बाद recipient द्वारा जारी किए जाते हैं। attacker-triggered action और संबंधित delivery receipt के बीच round-trip time (RTT) को मापना एक high-resolution timing channel उजागर करता है जो device state, online presence को leaks करता है और covert DoS के लिए दुरुपयोग किया जा सकता है। Multi-device "client-fanout" deployments इस leakage को amplify करते हैं क्योंकि हर registered device probe को decrypt करके अपना खुद का receipt लौटाता है।

## Delivery receipt sources vs. user-visible signals

ऐसे message types चुनें जो हमेशा delivery receipt जारी करते हैं लेकिन victim पर UI artifacts नहीं दिखाते। नीचे का तालिका empirically confirmed behaviour को सारांशित करता है:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | हमेशा noisy → केवल state bootstrap करने के लिए उपयोगी। |
| | Reaction | ● | ◐ (only if reacting to victim message) | Self-reactions और removals silent रहते हैं। |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; expiry के बाद भी ack किया जाता है। |
| | Delete for everyone | ● | ○ | UI ~60 h की अनुमति देता है, पर बाद के packets भी ack किए जाते हैं। |
| **Signal** | Text message | ● | ● | WhatsApp के समान सीमाएँ। |
| | Reaction | ● | ◐ | Self-reactions victim के लिए invisible रहते हैं। |
| | Edit/Delete | ● | ○ | Server ~48 h window लागू करता है, अधिकतम 10 edits की अनुमति, पर late packets फिर भी ack किए जाते हैं। |
| **Threema** | Text message | ● | ● | Multi-device receipts aggregate होते हैं, इसलिए प्रति probe केवल एक RTT दिखाई देता है। |

Legend: ● = always, ◐ = conditional, ○ = never. Platform-dependent UI behaviour inline नोट की गई है। आवश्यक होने पर read receipts disable करें, लेकिन WhatsApp या Signal में delivery receipts को बंद नहीं किया जा सकता।

## Attacker goals and models

* **G1 – Device fingerprinting:** प्रति probe कितने receipts आते हैं गिनें, RTTs को क्लस्टर करें ताकि OS/client (Android vs iOS vs desktop) का अनुमान लगाया जा सके, और online/offline transitions देखें।
* **G2 – Behavioural monitoring:** उच्च-फ़्रीक्वेंसी RTT series (≈1 Hz स्थिर) को time-series की तरह treat करके screen on/off, app foreground/background, commuting vs working hours आदि का inference करें।
* **G3 – Resource exhaustion:** लगातार silent probes भेजकर हर victim device के radios/CPUs को जागृत रखें, battery/data drain करें और VoIP/RTC गुणवत्ता को degrade करें।

दो threat actors पर्याप्त हैं abuse surface को describe करने के लिए:

1. **Creepy companion:** पहले से victim के साथ chat share करता है और self-reactions, reaction removals, या existing message IDs से जुड़ी repeated edits/deletes का दुरुपयोग करता है।
2. **Spooky stranger:** burner account register करता है और ऐसे reactions भेजता है जो उन message IDs का reference देते हैं जो local conversation में कभी मौजूद नहीं थे; WhatsApp और Signal इन्हें decrypt करके acknowledge करते हैं भले ही UI state change discard कर दे, इसलिए किसी prior conversation की ज़रूरत नहीं होती।

## Tooling for raw protocol access

ऐसे clients पर भरोसा करें जो underlying E2EE protocol expose करते हैं ताकि आप UI constraints के बाहर packets craft कर सकें, arbitrary `message_id`s specify कर सकें, और precise timestamps log कर सकें:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) या [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) आपको raw `ReactionMessage`, `ProtocolMessage` (edit/delete), और `Receipt` frames भेजने देते हैं जबकि double-ratchet state sync में रहता है।
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) को [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) के साथ मिलाकर CLI/API के माध्यम से हर message type एक्सपोज़ होता है। उदाहरण self-reaction toggle:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** Android client का source बताता है कि delivery receipts कैसे consolidated होते हुए device से बाहर जाते हैं, जो समझाता है कि वहां side channel का bandwidth नगण्य क्यों है।

जब custom tooling उपलब्ध नहीं हो, तब भी आप WhatsApp Web या Signal Desktop से silent actions trigger कर सकते हैं और encrypted websocket/WebRTC channel sniff कर सकते हैं, पर raw APIs UI delays हटाते हैं और invalid operations की अनुमति देते हैं।

## Creepy companion: silent sampling loop

1. किसी भी historical message को चुनें जो आपने chat में authored किया था ताकि victim को "reaction" balloons बदलते न दिखें।
2. एक visible emoji और एक empty reaction payload (WhatsApp protobufs में `""` के रूप में encoded या signal-cli में `--remove`) के बीच alternate करें। हर transmission के बाद device ack आता है भले ही victim के लिए कोई UI delta न हो।
3. send time और हर delivery receipt arrival को timestamp करें। नीचे जैसा 1 Hz loop per-device RTT traces अनिश्चित काल के लिए देता है:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. क्योंकि WhatsApp/Signal unlimited reaction updates स्वीकार करते हैं, attacker को नए chat content पोस्ट करने या edit windows की चिंता करने की ज़रूरत नहीं पड़ती।

## Spooky stranger: probing arbitrary phone numbers

1. एक नया WhatsApp/Signal account register करें और target number के public identity keys fetch करें (session setup के दौरान यह स्वतः होता है)।
2. ऐसा reaction/edit/delete packet craft करें जो किसी random `message_id` को संदर्भित करता है जिसे दोनों पक्षों ने कभी नहीं देखा (WhatsApp arbitrary `key.id` GUIDs स्वीकार करता है; Signal millisecond timestamps का उपयोग करता है)।
3. उस packet को भेजें भले ही कोई thread मौजूद न हो। victim devices उसे decrypt करके base message से मैच न कर पाने पर state change discard कर देती हैं, पर फिर भी incoming ciphertext acknowledge करती हैं और device receipts attacker को वापस भेजती हैं।
4. सतत रूप से repeat करके RTT series बनाएं बिना कभी victim के chat list में दिखाई दिए।

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** एक बार message delete-for-everyone होने के बाद, उसी `message_id` को संदर्भित करने वाले आगे के delete packets का कोई UI प्रभाव नहीं होता पर हर device उन्हें decrypt और acknowledge करता है।
* **Out-of-window operations:** WhatsApp UI में ~60 h delete / ~20 min edit windows लागू करता है; Signal ~48 h लागू करता है। इन windows के बाहर crafted protocol messages victim device पर silent ignore किए जाते हैं फिर भी receipts transmit होते हैं, इसलिए attackers conversation खत्म होने के बाद भी अनिश्चित काल तक probe कर सकते हैं।
* **Invalid payloads:** malformed edit bodies या पहले से purge किए गए messages को संदर्भित करने वाले deletes भी वही व्यवहार उत्पन्न करते हैं—decryption प्लस receipt, शून्य user-visible artifacts।

## Multi-device amplification & fingerprinting

* हर associated device (phone, desktop app, browser companion) probe को स्वतंत्र रूप से decrypt करके अपना ack लौटाता है। प्रति probe receipts गिनने से exact device count पता चलता है।
* अगर कोई device offline है, तो उसका receipt queued रहता है और reconnection पर जारी किया जाता है। इसलिए gaps online/offline cycles और commuting schedules (जैसे, desktop receipts यात्रा के दौरान रुकते हैं) को उजागर करते हैं।
* RTT distributions प्लेटफ़ॉर्म के अनुसार अलग होते हैं क्योंकि OS power management और push wakeups भिन्न होते हैं। RTTs को क्लस्टर करें (उदा., median/variance features पर k-means) ताकि “Android handset", “iOS handset", “Electron desktop" जैसा लेबल लगाया जा सके।
* क्योंकि sender को encrypt करने से पहले recipient’s key inventory retrieve करनी होती है, attacker यह भी देख सकता है जब नए devices paired होते हैं; device count में अचानक वृद्धि या नया RTT cluster एक मजबूत संकेत है।

## Behaviour inference from RTT traces

1. OS scheduling effects capture करने के लिए ≥1 Hz पर sample करें। WhatsApp on iOS के साथ, <1 s RTTs screen-on/foreground से मजबूत correlation दिखाते हैं, और >1 s screen-off/background throttling के साथ।
2. simple classifiers (thresholding या two-cluster k-means) बनाकर हर RTT को "active" या "idle" लेबल करें। लेबल्स को streaks में aggregate करके bedtimes, commutes, work hours, या कब desktop companion active है निकालें।
3. हर device की समानांतर probes को correlate करें ताकि देखा जा सके कि user कब mobile से desktop पर switch करता है, companions कब offline जाते हैं, और app कब push vs persistent socket द्वारा rate limited है।

## Stealthy resource exhaustion

हर silent probe को decrypt और acknowledge करना पड़ता है, इसलिए लगातार reaction toggles, invalid edits, या delete-for-everyone packets भेजने से application-layer DoS बनता है:

* Radio/modem को हर सेकंड transmit/receive करने के लिए मजबूर करता है → idle handsets पर battery drain noticeable होता है।
* Unmetered upstream/downstream traffic जनरेट करता है जो mobile data plans consume करता है जबकि TLS/WebSocket noise में blend हो जाता है।
* Crypto threads occupy करता है और latency-sensitive features (VoIP, video calls) में jitter बढ़ाता है भले ही user कभी notifications न देखे।

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)

{{#include ../banners/hacktricks-training.md}}
