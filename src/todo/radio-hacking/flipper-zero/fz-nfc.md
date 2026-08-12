# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## परिचय <a href="#id-9wrzi" id="id-9wrzi"></a>

RFID और NFC की जानकारी के लिए निम्नलिखित पेज देखें:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## समर्थित NFC cards <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> NFC cards के अलावा Flipper Zero **अन्य प्रकार के High-frequency cards** को भी support करता है, जैसे कई **Mifare** Classic और Ultralight तथा **NTAG**।

नीचे दी गई capability list मूल article में documented firmware का वर्णन करती है और इसे वर्तमान exhaustive support matrix नहीं माना जाना चाहिए। Flipper firmware ने समय के साथ protocols जोड़े हैं और NFC behavior बदला है; installed firmware के लिए वर्तमान official documentation देखें।<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Bank cards (EMV)** — केवल UID, SAK और ATQA को बिना save किए read करें।
- **Unknown cards** — UID, SAK और ATQA read करें और UID को emulate करें।

**NFC card types B, F, और V** के लिए, documented firmware UID को बिना save किए read कर सकता था।

### NFC cards type A <a href="#uvusf" id="uvusf"></a>

#### Bank card (EMV) <a href="#kzmrp" id="kzmrp"></a>

Documented firmware किसी bank card से UID, SAK, ATQA और उपलब्ध application data को **बिना save किए** read कर सकता था।

इन bank cards के लिए firmware ने card को save या emulate किए बिना data display किया।

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Unknown cards <a href="#id-37eo8" id="id-37eo8"></a>

जब Flipper Zero **NFC card का type निर्धारित करने में असमर्थ होता है**, तब केवल **UID, SAK और ATQA** को **read और save** किया जा सकता है।

Unknown NFC card के लिए यह mode केवल उसके UID को emulate कर सकता है।

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC cards types B, F, और V <a href="#wyg51" id="wyg51"></a>

मूल article में documented firmware में NFC card types B, F और V के लिए केवल identifier को read और display किया जा सकता था, उसे save नहीं किया जा सकता था।<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Actions

NFC के परिचय के लिए [**इस पेज को पढ़ें**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Read

Flipper Zero NFC cards को read कर सकता है, लेकिन ISO 14443 पर आधारित हर higher-level protocol को implement नहीं करता। इसलिए यह low-level UID, SAK और ATQA recover कर सकता है, जबकि application protocol unknown रह सकता है। केवल UID के आधार पर authorize करने वाले primitive access systems के लिए tool उस identifier को read, manually enter और emulate कर सकता है; cryptographically authenticated systems के लिए copied UID से अधिक की आवश्यकता होती है।<sup>[[1]](#references)</sup>

#### Reading the UID VS Reading the Data Inside <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Flipper में 13.56 MHz tags को read करना दो parts में विभाजित किया जा सकता है:<sup>[[1]](#references)</sup>

- **Low-level read** — केवल UID, SAK और ATQA read करता है। Flipper card से read किए गए इस data के आधार पर high-level protocol का अनुमान लगाने का प्रयास करता है। इससे आप 100% निश्चित नहीं हो सकते, क्योंकि यह केवल कुछ factors पर आधारित assumption है।
- **High-level read** — किसी specific high-level protocol का उपयोग करके card की memory से data read करता है। इसमें Mifare Ultralight का data read करना, Mifare Classic के sectors read करना या PayPass/Apple Pay से card के attributes read करना शामिल है।

### Specific Read

यदि Flipper Zero low-level data से card का type पता करने में सक्षम नहीं है, तो `Extra Actions` में आप `Read Specific Card Type` select करके उस card type को **manually** **indicate कर सकते हैं जिसे आप read करना चाहते हैं**।

#### EMV Bank Cards (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

पुराने Flipper firmware और compatible EMV cards UID से अधिक data expose कर सकते थे, जिसमें संभवतः PAN, expiration date, cardholder name या transaction log शामिल हो सकते थे, जब card द्वारा वे records उपलब्ध कराए गए हों। Availability card, application और firmware के अनुसार अलग-अलग होती है। Card पर printed magnetic-stripe CVV इस तरीके से expose नहीं होता, और इन records को read करने से contactless payment करने के लिए आवश्यक cryptographic transaction capability clone नहीं होती।<sup>[[1]](#references)</sup>

## References

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)
- [2] [Flipper Zero documentation - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
