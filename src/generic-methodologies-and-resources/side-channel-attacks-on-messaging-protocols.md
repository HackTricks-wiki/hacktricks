# E2EE मैसेंजर्स में डिलीवरी रसीदों पर साइड-चैनल हमले

{{#include ../banners/hacktricks-training.md}}

आधुनिक end-to-end encrypted (E2EE) मैसेंजर्स में डिलीवरी रसीदें अनिवार्य हैं, क्योंकि क्लाइंट्स को यह जानना होता है कि ciphertext कब decrypt हुआ, ताकि वे ratcheting state और ephemeral keys को हटा सकें। सर्वर opaque blobs को आगे भेजता है, इसलिए सफल decryption के बाद प्राप्तकर्ता डिवाइस acknowledgements (डबल चेकमार्क) भेजते हैं। हमलावर द्वारा शुरू की गई कार्रवाई और उससे जुड़ी डिलीवरी रसीद के बीच round-trip time (RTT) मापने से एक उच्च-रिज़ॉल्यूशन timing channel सामने आता है, जो डिवाइस की स्थिति और ऑनलाइन मौजूदगी leak करता है, और covert DoS के लिए इसका दुरुपयोग किया जा सकता है। Multi-device "client-fanout" deployments में यह leakage बढ़ जाता है, क्योंकि हर registered device probe को decrypt करके अपनी रसीद भेजता है।<sup>[[1]](#references)</sup>

## डिलीवरी रसीद के स्रोत बनाम उपयोगकर्ता को दिखने वाले संकेत

ऐसे message types चुनें जो हमेशा डिलीवरी रसीद भेजें, लेकिन पीड़ित को UI में कुछ न दिखाएँ। नीचे दी गई तालिका में अनुभवजन्य रूप से पुष्टि किया गया व्यवहार संक्षेप में दिया गया है:<sup>[[1]](#references)</sup>

| मैसेंजर | कार्रवाई | डिलीवरी रसीद | पीड़ित को सूचना | टिप्पणियाँ |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | टेक्स्ट संदेश | ● | ● | हमेशा ध्यान खींचता है → केवल शुरुआती state स्थापित करने के लिए उपयोगी। |
| | Reaction | ● | ◐ (केवल पीड़ित के संदेश पर reaction देने पर) | Self-reactions और removals चुपचाप रहते हैं। |
| | Edit | ● | Platform के अनुसार silent push | Edit window ≈20 मिनट; इसके बाद भी ack’d होता है। |
| | सभी के लिए Delete | ● | ○ | UI लगभग 60 घंटे तक अनुमति देता है, लेकिन बाद के packets भी ack’d होते हैं। |
| **Signal** | टेक्स्ट संदेश | ● | ● | WhatsApp जैसी ही सीमाएँ। |
| | Reaction | ● | ◐ | Self-reactions पीड़ित को दिखाई नहीं देते। |
| | Edit/Delete | ● | ○ | सर्वर लगभग 48 घंटे की window लागू करता है और अधिकतम 10 edits की अनुमति देता है, लेकिन देर से भेजे गए packets भी ack’d होते हैं। |
| **Threema** | टेक्स्ट संदेश | ● | ● | Multi-device receipts को aggregate किया जाता है, इसलिए हर probe के लिए केवल एक RTT दिखाई देता है। |

संकेत: ● = हमेशा, ◐ = शर्तों के साथ, ○ = कभी नहीं। Platform पर निर्भर UI व्यवहार का उल्लेख साथ में किया गया है। ज़रूरत पड़ने पर read receipts बंद करें, लेकिन WhatsApp या Signal में delivery receipts बंद नहीं की जा सकतीं।<sup>[[1]](#references)</sup>

## हमलावर के लक्ष्य और मॉडल

* **G1 – डिवाइस fingerprinting:** हर probe से आने वाली रसीदों की संख्या गिनें, OS/client (Android बनाम iOS बनाम desktop) का अनुमान लगाने के लिए RTTs को समूहों में बाँटें, और online/offline बदलावों पर नज़र रखें।
* **G2 – व्यवहार की निगरानी:** उच्च-आवृत्ति वाली RTT श्रृंखला (≈1 Hz स्थिर है) को time-series मानें और स्क्रीन के चालू/बंद होने, app के foreground/background में होने, आने-जाने और काम के घंटों आदि का अनुमान लगाएँ।
* **G3 – संसाधन समाप्त करना:** लगातार silent probes भेजकर पीड़ित के हर डिवाइस के radios/CPUs को सक्रिय रखें, जिससे बैटरी/डेटा खर्च हो और video-call की गुणवत्ता घटे।<sup>[[1]](#references)</sup>

दुरुपयोग की संभावनाओं का वर्णन करने के लिए दो threat actors पर्याप्त हैं:<sup>[[1]](#references)</sup>

1. **Creepy companion:** पहले से ही पीड़ित के साथ chat साझा करता है और मौजूदा message IDs से जुड़े self-reactions, reaction removals या बार-बार किए गए edits/deletes का दुरुपयोग करता है।
2. **Spooky stranger:** burner account register करता है और ऐसे message IDs का संदर्भ देने वाले reactions भेजता है जो local conversation में कभी मौजूद ही नहीं थे; WhatsApp और Signal फिर भी उन्हें decrypt करके acknowledge करते हैं, भले ही UI state change को discard कर दे, इसलिए पहले से कोई conversation होना ज़रूरी नहीं है।

## Raw protocol access के लिए टूलिंग

ऐसे clients का उपयोग करें जो underlying E2EE protocol का पर्याप्त हिस्सा उपलब्ध कराते हों, ताकि UI की सीमाओं के बाहर समर्थित packets बनाए जा सकें और सटीक timestamps log किए जा सकें; arbitrary message IDs के लिए हर implementation की जाँच ज़रूरी है:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web multidevice API) delivery receipts भेजने और प्राप्त करने का documentation देता है; [Cobalt](https://github.com/Auties00/Cobalt) (अनौपचारिक Java/Kotlin Web और mobile API) reaction देने, edit करने और delete करने जैसे message operations का documentation देता है। हर internal frame उपलब्ध है, ऐसा मानने के बजाय उनके documented APIs का उपयोग करें।<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) CLI, JSON-RPC और D-Bus interfaces उपलब्ध कराता है, जबकि [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) Signal से संवाद करने वाली Java library है।<sup>[[5]](#references)[[7]](#references)</sup> मौजूदा `signal-cli` syntax में `sendReaction RECIPIENT --target-author --target-timestamp` का उपयोग होता है; protocol updates को process करते रहने के लिए `receive` या `daemon` चालू रखें।<sup>[[6]](#references)</sup> Self-reaction toggle का उदाहरण:
  ```bash
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --emoji "👍"
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --remove
  ```
* **Threema:** Careless Whisper पेपर में किए गए मापों से पता चला कि delivery receipts डिवाइसों के बीच सिंक्रनाइज़ होते हैं, इसलिए multi-device सेटअप में भी प्रति संदेश केवल एक receipt उजागर होता है।<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) में WhatsApp/Signal backends शामिल हैं, यह डिफ़ॉल्ट रूप से silent delete probes का उपयोग करता है, और rolling-median threshold (`RTT < 0.9 * median`) के आधार पर `active` और `standby` को लेबल करता है।<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) एक हल्का, WhatsApp-केंद्रित CLI है, जिसमें `--delay`, `--concurrent`, CSV/Prometheus exporters और Grafana-अनुकूल आउटपुट हैं।<sup>[[9]](#references)</sup> दोनों को protocol references के बजाय reconnaissance helpers मानें; अहम बात यह है कि raw client access उपलब्ध होने पर कितना कम कोड चाहिए।

जब custom tooling उपलब्ध न हो, तब भी official clients या browser developer tools silent actions ट्रिगर कर सकते हैं और encrypted traffic की timing उजागर कर सकते हैं; raw APIs UI की देरी हटाते हैं और invalid operations की अनुमति देते हैं।<sup>[[1]](#references)</sup>

## डरावना साथी: silent sampling loop

1. चैट में अपना लिखा हुआ कोई भी पुराना संदेश चुनें, ताकि पीड़ित को "reaction" balloons बदलते हुए न दिखें।
2. एक दिखाई देने वाले emoji और खाली reaction payload (`""` के रूप में WhatsApp protobufs में encoded या signal-cli में `--remove`) के बीच बारी-बारी से स्विच करें। हर transmission से device ack मिलता है, भले ही पीड़ित के लिए UI में कोई बदलाव न हो।
3. भेजने का समय और हर delivery receipt के आने का समय दर्ज करें। नीचे दिए गए जैसा 1 Hz loop अनिश्चितकाल तक per-device RTT traces देता है:
   ```python
   while True:
       send_reaction(msg_id, "👍")
       log_receipts()
       send_reaction(msg_id, "")  # removal
       log_receipts()
       time.sleep(0.5)
   ```
4. क्योंकि WhatsApp/Signal असीमित reaction updates स्वीकार करते हैं, इसलिए हमलावर को कभी भी नया chat content पोस्ट करने या edit windows की चिंता करने की ज़रूरत नहीं होती।<sup>[[1]](#references)</sup>

## अनजान व्यक्ति: किसी भी फ़ोन नंबर की जाँच

1. एक नया WhatsApp/Signal account रजिस्टर करें और target number के public identity keys प्राप्त करें (session setup के दौरान यह अपने आप हो जाता है)।
2. ऐसा reaction packet तैयार करें जो किसी ऐसे random `message_id` को संदर्भित करता हो जिसे किसी भी पक्ष ने कभी नहीं देखा है; शोधपत्र के अनुसार, WhatsApp और Signal दोनों ऐसी reactions स्वीकार करते हैं और फिर भी delivery receipts जनरेट करते हैं।<sup>[[1]](#references)</sup>
3. कोई thread मौजूद न होने पर भी packet भेजें। Victim devices इसे decrypt करते हैं, base message से match नहीं कर पाते और state change को discard कर देते हैं, लेकिन फिर भी incoming ciphertext की पुष्टि करते हुए attacker को device receipts भेजते हैं।
4. बिना किसी पिछली बातचीत या दिखाई देने वाली notification के RTT series बनाने के लिए इसे लगातार दोहराएँ।<sup>[[1]](#references)</sup>

अगर आपको पहले यह पता लगाना है कि कौन-से नंबर रजिस्टर हैं या बड़े पैमाने पर device inventories पहले से तैयार करनी हैं, तो E.164 ranges का हाथ से अंदाज़ा लगाने के बजाय इसे [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) के साथ जोड़ें।

प्रकाशित contact-discovery शोध से पता चला कि व्यावहारिक रूप से यह क्यों मायने रखता है: सटीक phone-prefix tables और सीमित संसाधनों के साथ, शोधकर्ता लक्षित probing शुरू करने से पहले WhatsApp पर लगभग `10%` और Signal पर `100%` US mobile numbers को query कर पाए।<sup>[[11]](#references)</sup> व्यवहार में, पहले live accounts को filter करने से आपका silent-probe budget उन नंबरों पर केंद्रित रहता है जो वास्तव में packets decrypt करेंगे।

WhatsApp के हालिया builds में `Settings -> Privacy -> Advanced -> Block unknown account messages` भी उपलब्ध है।<sup>[[10]](#references)</sup> इसे throughput limiter मानें: tracker documentation के अनुसार WhatsApp अज्ञात accounts से आने वाले high-volume messages को block करता है, लेकिन threshold नहीं बताता। इसलिए यह probe reactions को पूरी तरह नहीं रोकता।<sup>[[8]](#references)</sup>

## छिपे हुए triggers के रूप में edits और deletes का दोबारा उपयोग

* **बार-बार deletes:** किसी message को एक बार everyone के लिए delete कर दिए जाने के बाद, उसी `message_id` को संदर्भित करने वाले आगे के delete packets का UI पर कोई असर नहीं होता, लेकिन हर device फिर भी उन्हें decrypt करके acknowledge करता है।
* **समय-सीमा के बाद की कार्रवाइयाँ:** WhatsApp UI में ~60 h delete / ~20 min edit windows लागू करता है; Signal ~48 h लागू करता है। इन windows के बाहर भेजे गए crafted protocol messages को victim device चुपचाप अनदेखा करता है, लेकिन receipts फिर भी भेजे जाते हैं। इसलिए बातचीत खत्म होने के काफी समय बाद तक हमलावर probe कर सकते हैं।
* **अमान्य payloads:** शोधपत्र के अनुसार, अमान्य messages को भी acknowledge किया जा सकता है; malformed bodies या purged IDs के लिए सटीक व्यवहार implementation पर निर्भर करता है, इसलिए इस पर भरोसा करने से पहले परीक्षण करें।<sup>[[1]](#references)</sup>

## Multi-device amplification और fingerprinting

* WhatsApp और Signal पर, हर associated device (फ़ोन, desktop app, browser companion) probe को स्वतंत्र रूप से decrypt करता है और अपना ack लौटाता है। हर probe के लिए receipts गिनने से devices की सटीक संख्या पता चलती है।<sup>[[1]](#references)</sup>
* अगर कोई device offline है, तो उसकी receipt queue में रखी जाती है और reconnect होने पर भेजी जाती है। इसलिए gaps से online/offline cycles और यहाँ तक कि आने-जाने के शेड्यूल का भी पता leak हो सकता है (जैसे, यात्रा के दौरान desktop receipts आना बंद हो जाना)।
* OS, model, client और network conditions के कारण platform और environment के अनुसार RTT distributions अलग होते हैं। “Android handset”, “iOS handset”, “Electron desktop” आदि की पहचान के लिए RTTs को cluster करें (जैसे, median/variance features पर k-means)।
* चूँकि sender को encrypt करने से पहले recipient की key inventory प्राप्त करनी पड़ती है, इसलिए attacker यह भी देख सकता है कि नए devices कब pair किए जाते हैं; devices की संख्या में अचानक वृद्धि या नया RTT cluster इसका मज़बूत संकेत है।<sup>[[1]](#references)</sup>

**Queued receipts से fingerprint करें:** Target device के offline होने पर अलग-अलग message IDs वाले कई probes भेजें। उसके reconnect होने पर, लौटाई गई delivery receipts में IDs का मिलान करें और देखें कि वे अलग-अलग receipts में हैं या एक receipt में stacked हैं, और stacked IDs भेजने का क्रम बनाए रखते हैं या उलट देते हैं। परीक्षण किए गए clients में WhatsApp Android/iOS ने अलग-अलग delivery receipts लौटाईं, जबकि Web, Windows और macOS ने उन्हें stack किया; macOS ने stacked क्रम उलट दिया। Signal Desktop ने receipts stack कीं, जबकि उसके mobile clients ने ऐसा नहीं किया। इससे reconnect होने वाले client की पहचान की जा सकती है, भले ही RTT distributions एक-दूसरे से overlap करें। Delivery receipts को read receipts न समझें, क्योंकि उन्हें stack करने के नियम अलग हैं।<sup>[[1]](#references)</sup>

बिना messages deliver किए **server-side prekey refills** पढ़ने वाले एक अलग WhatsApp probe के लिए, [Prekey Bundle Depletion and Refill Side Channel](whatsapp-prekey-bundle-side-channel.md) देखें।

## Sampling cadence, queueing और stacked receipts

* **WhatsApp burst tolerance:** प्रकाशित मापों के अनुसार, WhatsApp ने बिना किसी स्पष्ट server-side queueing के हर `50 ms` में एक probe तक की दर से silent-reaction bursts स्वीकार किए। यह छोटे calibration bursts, तेज़ device counting या drain attack को जल्दी तेज़ करने के लिए उपयोगी है।
* **Signal में लंबे समय तक queueing:** Signal ने छोटे bursts सहन किए, लेकिन लगातार कई probes प्रति सेकंड वाले traffic को queue करना शुरू कर दिया। लंबे समय तक monitoring के लिए cadence लगभग `1 Hz` (या उससे कम) रखें, ताकि हर receipt backlog drain के बजाय device की मौजूदा स्थिति दर्शाए।
* **Reconnect artefacts:** Device के वापस online होने पर, कुछ clients कई delayed receipts को batch करते हैं या तेज़ी से भेजते हैं। ऐसे receipt bursts को स्वतंत्र RTT samples के बजाय state-transition marker मानें, वरना आपकी clustering / `active` बनाम `idle` classifier reconnect के noise पर overfit हो जाएगी।<sup>[[1]](#references)</sup>

## RTT traces से व्यवहार का अनुमान

1. OS scheduling effects पकड़ने के लिए ≥1 Hz पर sample लें। iOS पर WhatsApp के साथ, <1 s RTTs का screen-on/foreground से और >1 s RTTs का screen-off/background throttling से मज़बूत संबंध होता है।
2. ऐसे सरल classifiers बनाएँ (thresholding या two-cluster k-means) जो हर RTT को "active" या "idle" का label दें। सोने का समय, आने-जाने का समय, काम के घंटे या desktop companion कब active है, इसका अनुमान लगाने के लिए labels को लगातार अवधियों में एकत्र करें।
3. हर device को एक साथ probes भेजकर पता लगाएँ कि users mobile से desktop पर कब switch करते हैं, companions कब offline होते हैं और app को push या persistent socket के ज़रिए rate limit किया जा रहा है या नहीं।
4. वास्तविक networks में एक ही hardcoded `1 s` threshold का उपयोग न करें। हर device को एक छोटी warm-up अवधि के साथ bootstrap करें और rolling baseline बनाए रखें (उदाहरण के लिए, device-activity-tracker PoC में `threshold = 0.9 * median RTT` का उपयोग किया जाता है), ताकि Wi-Fi/cellular drift से आपका classifier बेकार न हो जाए।<sup>[[1]](#references)[[8]](#references)</sup>

## Delivery RTT से location का अनुमान

इसी timing primitive का उपयोग यह अनुमान लगाने के लिए किया जा सकता है कि recipient कहाँ है, न कि सिर्फ़ यह कि वह active है या नहीं। `Hope of Delivery` शोध ने दिखाया कि ज्ञात receiver locations के RTT distributions पर training देने से attacker बाद में केवल delivery confirmations के आधार पर victim की location classify कर सकता है:<sup>[[2]](#references)</sup>

* उसी target के कई ज्ञात स्थानों (घर, दफ़्तर, campus, देश A बनाम देश B आदि) में होने पर baseline बनाएँ।
* हर location के लिए, सामान्य messages के कई RTTs इकट्ठा करें और median, variance या percentile buckets जैसी सरल features निकालें।
* वास्तविक attack के दौरान, नई probe series की तुलना trained clusters से करें। शोधपत्र के अनुसार, एक ही शहर के अंदर की locations को भी अक्सर अलग पहचाना जा सकता है; 3-location setting में accuracy `>80%` तक होती है।
* यह तब सबसे अच्छा काम करता है जब attacker sender environment को नियंत्रित करता हो और समान network conditions में probes भेजता हो, क्योंकि मापा गया path recipient access network, wake-up latency और messenger infrastructure—तीनों को शामिल करता है।<sup>[[2]](#references)</sup>

ऊपर बताए गए silent reaction/edit/delete attacks के विपरीत, location inference के लिए invalid message IDs या stealthy state-changing packets की ज़रूरत नहीं होती। सामान्य delivery confirmations वाले plain messages ही काफ़ी हैं, इसलिए इसमें stealth कम है लेकिन messengers पर लागू होने की क्षमता अधिक है।

## Stealthy resource exhaustion

चूँकि हर silent probe को decrypt और acknowledge करना पड़ता है, इसलिए reaction toggles, invalid edits या delete-for-everyone packets लगातार भेजने से application-layer DoS होता है:<sup>[[1]](#references)</sup>

* हर सेकंड radio/modem को transmit/receive करने के लिए मजबूर करता है → battery का ध्यान देने योग्य drain, ख़ासकर idle handsets पर।
* Upstream/downstream traffic जनरेट करता है, जो mobile data plans का उपयोग करता है और video calls जैसी latency-sensitive सुविधाओं में रुकावट डाल सकता है।<sup>[[1]](#references)</sup>
* बड़े invalid payloads से processing का काम बढ़ता है, लेकिन शोधपत्र के अनुसार cryptography का battery cost में योगदान नगण्य है।<sup>[[1]](#references)</sup>
* WhatsApp पर, invalid reactions सामान्य emoji से कहीं अधिक data स्वीकार करती हैं: प्रकाशित मापों में server-side acceptance प्रति reaction लगभग `1 MB` तक पाया गया।
* Body का आकार लगभग `30 bytes` से अधिक होने पर oversized reactions भरोसेमंद delivery receipts देना बंद कर देती हैं, लेकिन discard होने से पहले उन्हें फिर भी forward और process किया जाता है। ACKs की ज़रूरत होने पर reaction bodies छोटी रखें; उन्हें केवल तब बड़ा करें जब लक्ष्य सिर्फ़ drain करना या covert one-way transport हो।
* सार्वजनिक मापों में इस mode में victim traffic लगभग `3.7 MB/s` (`~13.3 GB/h`) तक पहुँचा।



## References

- [1] [लापरवाह फुसफुसाहट: Mobile Instant Messengers पर Users की निगरानी के लिए Silent Delivery Receipts का दुरुपयोग](https://arxiv.org/html/2411.11194v4)
- [2] [Delivery की आशा: Mobile Instant Messengers से Users की Locations निकालना](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [अज्ञात messages की अधिक मात्रा को कैसे block करें | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [11] [सभी नंबर US के हैं: Mobile Messengers में Contact Discovery का बड़े पैमाने पर दुरुपयोग](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
