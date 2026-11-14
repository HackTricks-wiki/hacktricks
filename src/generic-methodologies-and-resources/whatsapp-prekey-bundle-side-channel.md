# WhatsApp Prekey Bundle का depletion और refill side channel

{{#include ../banners/hacktricks-training.md}}

WhatsApp हर डिवाइस के लिए एक identity key, एक signed prekey और one-time prekeys का reserve स्टोर करता है। किसी डिवाइस का bundle fetch करने पर सर्वर पर रखा एक one-time prekey इस्तेमाल हो जाता है, भले ही अनुरोधकर्ता कोई message न भेजे। इससे WhatsApp account और target के phone number वाले attacker को एक **server-side** probe मिलता है, जो [client delivery-receipt timing](side-channel-attacks-on-messaging-protocols.md) से अलग है। One-time prekey न होने से नए स्थापित session के *शुरुआती* messages की forward secrecy भी कमज़ोर होती है; लेकिन इससे अपने-आप plaintext उजागर नहीं होता।<sup>[[1]](#references)[[2]](#references)</sup>

## Target के device bundles की जाँच करें

[Prekey Pogo artifact](https://github.com/sbaresearch/prekey-pogo) को WhatsApp companion session के रूप में pair किया जा सकता है और यह **manual** device तथा prekey queries की सुविधा देता है। इसे test account के साथ pair करें, फिर इसके interactive `target`, `devices`, `prekey` (primary device) और `combine` (सभी devices) commands इस्तेमाल करें। जारी किए गए artifact में जानबूझकर automated depletion और server-clogging functions शामिल नहीं हैं।<sup>[[1]](#references)[[3]](#references)</sup>

```bash
git clone https://github.com/sbaresearch/prekey-pogo
cd prekey-pogo
./setup.sh
go run .
```

हर response के लिए, device JID, bundle timestamp `t`, signed-prekey ID `skey.id`, और यह दर्ज करें कि one-time `key.id` मौजूद है या नहीं। Device ID `0` फोन होता है; nonzero IDs companion devices के होते हैं। पेपर में जाँचे गए implementations में, initial signed-prekey ID कुछ clients की पहचान भी बताता है: Android `0` से शुरू होता है, iOS और macOS random value इस्तेमाल करते हैं, और WhatsApp Web तथा Windows Desktop `1` से शुरू होते हैं। इसे implementation fingerprint मानें, immutable protocol rule नहीं।<sup>[[1]](#references)</sup>

## Refill को online-status oracle में बदलें

पहले अपने नियंत्रण वाले device पर calibration करें: उसके bundle को बार-बार request करें, जब तक server one-time `key` देना बंद न कर दे। आखिरी timestamp और key IDs नोट करें। Target device के लिए, depletion दोहराएँ और तय अंतराल के बाद फिर से query करें: नया one-time key और आगे बढ़ा हुआ bundle timestamp यह संकेत देते हैं कि device ने नई batch upload की है। रिपोर्ट किए गए WhatsApp tests में, 11 से कम keys बचने पर server ने refill के लिए prompt किया और clients ने 812 नई keys upload कीं। फोन और companions में अंतर करने के लिए यह प्रक्रिया हर device JID पर लागू करें। देर से होने वाला refill केवल यह **संकेत देता है** कि device offline है: background scheduling, network loss और client-specific refill latency से भी यही observation हो सकता है। Receipt RTT के विपरीत, इस probe के लिए delivered ciphertext या victim-side acknowledgment की आवश्यकता नहीं होती।<sup>[[1]](#references)[[2]](#references)</sup>

हर query एक one-time key इस्तेमाल करती है, इसलिए लगातार oracle चलाने के लिए ऐसा custom client चाहिए जो बार-बार prekey retrieval कर सके; public artifact में केवल manual queries दिखाई गई हैं। Reserve को खाली रखने से दूसरे users one-time prekey के बिना नई sessions स्थापित कर सकते हैं। इससे initial messages के लिए forward secrecy कम हो जाती है, जब तक कि fresh ratchet step न हो जाए; लेकिन recorded ciphertext का शोषण करने के लिए E2EE ciphertext तक पहुँच और बाद में संबंधित long- और medium-term private keys का compromise भी आवश्यक है। पहले से स्थापित sessions अपने-आप downgrade नहीं होतीं।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Prekey Pogo: WhatsApp के Handshake Mechanism में Security और Privacy Issues की जाँच](https://www.usenix.org/system/files/woot25-gegenhuber.pdf)
- [2] [The X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
- [3] [Prekey Pogo artifacts](https://github.com/sbaresearch/prekey-pogo)
{{#include ../banners/hacktricks-training.md}}
