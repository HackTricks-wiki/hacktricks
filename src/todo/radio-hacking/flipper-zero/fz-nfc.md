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

समर्थित cards की list में नए प्रकार के NFC cards जोड़े जाएंगे। Flipper Zero निम्नलिखित **NFC cards type A** (ISO 14443A) को support करता है:

- **Bank cards (EMV)** — केवल UID, SAK और ATQA को बिना save किए read करता है।
- **Unknown cards** — UID, SAK और ATQA read करता है और एक UID को emulate करता है।

**NFC cards type B, type F और type V** के लिए Flipper Zero UID को बिना save किए read करने में सक्षम है।

### NFC cards type A <a href="#uvusf" id="uvusf"></a>

#### Bank card (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero bank cards पर केवल UID, SAK, ATQA और stored data को **बिना save किए** read कर सकता है।

Bank card reading screenBank cards के लिए Flipper Zero data को केवल **बिना save और emulate किए** read कर सकता है।

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Unknown cards <a href="#id-37eo8" id="id-37eo8"></a>

जब Flipper Zero **NFC card का type निर्धारित करने में असमर्थ होता है**, तब केवल **UID, SAK और ATQA** को **read और save** किया जा सकता है।

Unknown card reading screenUnknown NFC cards के लिए Flipper Zero केवल UID को emulate कर सकता है।

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC cards types B, F और V <a href="#wyg51" id="wyg51"></a>

**NFC cards types B, F और V** के लिए Flipper Zero केवल UID को **बिना save किए read और display** कर सकता है।

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Actions

NFC के परिचय के लिए [**यह पेज पढ़ें**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Read

Flipper Zero **NFC cards read** कर सकता है, हालांकि यह ISO 14443 पर आधारित **सभी protocols को नहीं समझता**। फिर भी, क्योंकि **UID एक low-level attribute है**, ऐसी स्थिति हो सकती है जब **UID पहले ही read हो चुका हो, लेकिन high-level data transfer protocol अभी भी unknown हो**। आप उन primitive readers के लिए Flipper का उपयोग करके UID को read, emulate और manually input कर सकते हैं जो authorization के लिए UID का उपयोग करते हैं।<sup>[[1]](#references)</sup>

#### UID को Read करना VS अंदर के Data को Read करना <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Flipper में 13.56 MHz tags को read करना दो भागों में विभाजित किया जा सकता है:<sup>[[1]](#references)</sup>

- **Low-level read** — केवल UID, SAK और ATQA read करता है। Flipper card से read किए गए इस data के आधार पर high-level protocol का अनुमान लगाने का प्रयास करता है। इसके बारे में 100% निश्चित नहीं हुआ जा सकता, क्योंकि यह कुछ factors पर आधारित केवल एक assumption है।
- **High-level read** — किसी specific high-level protocol का उपयोग करके card की memory से data read करता है। इसका अर्थ Mifare Ultralight पर data read करना, Mifare Classic से sectors read करना या PayPass/Apple Pay से card के attributes read करना होगा।

### Specific Read

यदि Flipper Zero low-level data से card का type खोजने में सक्षम नहीं है, तो `Extra Actions` में आप `Read Specific Card Type` select करके **manually** उस **card type को indicate कर सकते हैं जिसे आप read करना चाहते हैं**।

#### EMV Bank Cards (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

केवल UID read करने के अलावा, आप bank card से और भी बहुत-सा data extract कर सकते हैं। **पूरा card number** (card के front पर मौजूद 16 digits), **validity date**, और कुछ मामलों में **owner का name** तथा **सबसे हाल के transactions** की list भी **प्राप्त की जा सकती है**।\
हालांकि, आप इस तरीके से **CVV read नहीं कर सकते** (card के back पर मौजूद 3 digits)। साथ ही **bank cards replay attacks से protected होते हैं**, इसलिए Flipper से इसे copy करके किसी payment के लिए emulate करने का प्रयास काम नहीं करेगा।<sup>[[1]](#references)</sup>

## References

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
