# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## परिचय <a href="#id-9wrzi" id="id-9wrzi"></a>

RFID और NFC की जानकारी के लिए यह पेज देखें:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## समर्थित NFC कार्ड <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> NFC कार्ड के अलावा, Flipper Zero **अन्य प्रकार के High-frequency कार्ड** भी सपोर्ट करता है, जैसे कई **Mifare** Classic और Ultralight तथा **NTAG** कार्ड।

नीचे दी गई क्षमता-सूची मूल लेख में बताए गए firmware का वर्णन करती है। इसे मौजूदा सपोर्ट की संपूर्ण सूची न मानें। समय के साथ Flipper firmware में प्रोटोकॉल जुड़ते और NFC का व्यवहार बदलता रहा है; इंस्टॉल किए गए firmware के लिए मौजूदा आधिकारिक दस्तावेज़ देखें।<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Bank cards (EMV)** — UID, SAK और ATQA केवल पढ़ता है, सेव नहीं करता।
- **Unknown cards** — UID, SAK और ATQA पढ़ता है और UID को emulate करता है।

**NFC कार्ड प्रकार B, F और V** के लिए, बताए गए firmware में UID को सेव किए बिना पढ़ा जा सकता था।

### NFC कार्ड प्रकार A <a href="#uvusf" id="uvusf"></a>

#### Bank card (EMV) <a href="#kzmrp" id="kzmrp"></a>

बताए गए firmware में bank card से UID, SAK, ATQA और उपलब्ध application data **सेव किए बिना** पढ़ा जा सकता था।

इन bank cards के लिए firmware डेटा दिखाता था, लेकिन कार्ड को सेव या emulate नहीं करता था।

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Unknown cards <a href="#id-37eo8" id="id-37eo8"></a>

जब Flipper Zero **NFC कार्ड का प्रकार निर्धारित नहीं कर पाता**, तो केवल **UID, SAK और ATQA** को **पढ़कर सेव** किया जा सकता है।

Unknown NFC कार्ड के लिए यह mode केवल उसका UID emulate कर सकता है।

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC कार्ड प्रकार B, F और V <a href="#wyg51" id="wyg51"></a>

मूल लेख में बताए गए firmware में NFC कार्ड प्रकार B, F और V का identifier केवल पढ़कर दिखाया जा सकता था; इसे सेव नहीं किया जा सकता था।<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## क्रियाएँ

NFC के परिचय के लिए [**यह पेज पढ़ें**](../pentesting-rfid.md#high-frequency-rfid-tags-1356-mhz-1)।

### पढ़ना

Flipper Zero NFC कार्ड पढ़ सकता है, लेकिन ISO 14443 पर आधारित हर higher-level protocol लागू नहीं करता। इसलिए यह low-level UID, SAK और ATQA प्राप्त कर सकता है, जबकि application protocol की पहचान नहीं हो पाती। केवल UID के आधार पर अनुमति देने वाले साधारण access systems के लिए यह tool उस identifier को पढ़, मैन्युअल रूप से दर्ज और emulate कर सकता है; cryptographic authentication वाले systems के लिए कॉपी किए गए UID से अधिक की आवश्यकता होती है।<sup>[[1]](#references)</sup>

#### UID पढ़ना VS अंदर का डेटा पढ़ना <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Flipper में 13.56 MHz tags को पढ़ने के दो हिस्से हैं:<sup>[[1]](#references)</sup>

- **Low-level read** — केवल UID, SAK और ATQA पढ़ता है। कार्ड से पढ़े गए इस डेटा के आधार पर Flipper high-level protocol का अनुमान लगाने की कोशिश करता है। इससे पूरी निश्चितता नहीं मिलती, क्योंकि यह कुछ कारकों पर आधारित सिर्फ़ एक अनुमान है।
- **High-level read** — किसी खास high-level protocol का उपयोग करके कार्ड की memory से डेटा पढ़ता है। उदाहरण के लिए, Mifare Ultralight से डेटा पढ़ना, Mifare Classic के sectors पढ़ना, या PayPass/Apple Pay से कार्ड के attributes पढ़ना।

### विशिष्ट कार्ड पढ़ें

अगर Flipper Zero low-level डेटा से कार्ड का प्रकार नहीं पहचान पाता, तो `Extra Actions` में `Read Specific Card Type` चुनकर **मैन्युअल रूप से** **पढ़े जाने वाले कार्ड का प्रकार चुन सकते हैं**।

#### EMV Bank Cards (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

पुराने Flipper firmware और उनसे संगत EMV cards में UID के अलावा अधिक डेटा उपलब्ध हो सकता था—संभवतः PAN, expiration date, cardholder name या transaction log—अगर कार्ड ने ये records उपलब्ध कराए हों। यह डेटा कार्ड, application और firmware के अनुसार अलग-अलग होता है। कार्ड पर छपा magnetic-stripe CVV इस तरीके से उपलब्ध नहीं होता, और इन records को पढ़ने से contactless payment करने के लिए ज़रूरी cryptographic transaction क्षमता clone नहीं होती।<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero के साथ RFID प्रोटोकॉल की गहराई से पड़ताल](https://blog.flipperzero.one/rfid/)
- [2] [Flipper Zero दस्तावेज़ - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
