# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#id-9wrzi" id="id-9wrzi"></a>

RFID और NFC के बारे में जानकारी के लिए निम्नलिखित पृष्ठ देखें:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Supported NFC cards <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> NFC कार्डों के अलावा Flipper Zero **अन्य प्रकार के उच्च-आवृत्ति कार्डों** का समर्थन करता है जैसे कि कई **Mifare** Classic और Ultralight और **NTAG**।

NFC कार्डों के नए प्रकारों को समर्थित कार्डों की सूची में जोड़ा जाएगा। Flipper Zero निम्नलिखित **NFC कार्ड प्रकार A** (ISO 14443A) का समर्थन करता है:

- **बैंक कार्ड (EMV)** — केवल UID, SAK, और ATQA पढ़ें, बिना सहेजे।
- **अज्ञात कार्ड** — (UID, SAK, ATQA) पढ़ें और एक UID का अनुकरण करें।

**NFC कार्ड प्रकार B, प्रकार F, और प्रकार V** के लिए, Flipper Zero UID को बिना सहेजे पढ़ने में सक्षम है।

### NFC cards type A <a href="#uvusf" id="uvusf"></a>

#### Bank card (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero केवल UID, SAK, ATQA, और बैंक कार्डों पर संग्रहीत डेटा को **बिना सहेजे** पढ़ सकता है।

बैंक कार्ड पढ़ने का स्क्रीनबैंक कार्डों के लिए, Flipper Zero केवल डेटा को **बिना सहेजे और अनुकरण किए** पढ़ सकता है।

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Unknown cards <a href="#id-37eo8" id="id-37eo8"></a>

जब Flipper Zero **NFC कार्ड के प्रकार का निर्धारण करने में असमर्थ होता है**, तब केवल **UID, SAK, और ATQA** को **पढ़ा और सहेजा** जा सकता है।

अज्ञात कार्ड पढ़ने का स्क्रीनअज्ञात NFC कार्डों के लिए, Flipper Zero केवल एक UID का अनुकरण कर सकता है।

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC cards types B, F, and V <a href="#wyg51" id="wyg51"></a>

**NFC कार्ड प्रकार B, F, और V** के लिए, Flipper Zero केवल **UID को पढ़ और प्रदर्शित** कर सकता है बिना इसे सहेजे।

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Actions

NFC के बारे में एक परिचय के लिए [**इस पृष्ठ को पढ़ें**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Read

Flipper Zero **NFC कार्डों को पढ़ सकता है**, हालाँकि, यह **ISO 14443 पर आधारित सभी प्रोटोकॉल को नहीं समझता**। हालाँकि, चूंकि **UID एक निम्न-स्तरीय विशेषता है**, आप एक ऐसी स्थिति में हो सकते हैं जब **UID पहले से पढ़ा गया हो, लेकिन उच्च-स्तरीय डेटा ट्रांसफर प्रोटोकॉल अभी भी अज्ञात हो**। आप Flipper का उपयोग करके UID को पढ़, अनुकरण और मैन्युअल रूप से इनपुट कर सकते हैं जो UID का उपयोग करने वाले प्राथमिक रीडर्स के लिए अधिकृत है।

#### Reading the UID VS Reading the Data Inside <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Flipper में, 13.56 MHz टैग को पढ़ने को दो भागों में विभाजित किया जा सकता है:

- **निम्न-स्तरीय पढ़ाई** — केवल UID, SAK, और ATQA पढ़ता है। Flipper इस डेटा के आधार पर उच्च-स्तरीय प्रोटोकॉल का अनुमान लगाने की कोशिश करता है जो कार्ड से पढ़ा गया है। आप इसके साथ 100% निश्चित नहीं हो सकते, क्योंकि यह कुछ कारकों के आधार पर केवल एक अनुमान है।
- **उच्च-स्तरीय पढ़ाई** — एक विशिष्ट उच्च-स्तरीय प्रोटोकॉल का उपयोग करके कार्ड की मेमोरी से डेटा पढ़ता है। यह Mifare Ultralight पर डेटा पढ़ना, Mifare Classic से सेक्टर पढ़ना, या PayPass/Apple Pay से कार्ड के गुण पढ़ना होगा।

### Read Specific

यदि Flipper Zero निम्न स्तर के डेटा से कार्ड के प्रकार को खोजने में असमर्थ है, तो `Extra Actions` में आप `Read Specific Card Type` का चयन कर सकते हैं और **मैन्युअल रूप से** **उस कार्ड के प्रकार को इंगित कर सकते हैं जिसे आप पढ़ना चाहते हैं**।

#### EMV Bank Cards (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

UID को केवल पढ़ने के अलावा, आप बैंक कार्ड से और भी बहुत सा डेटा निकाल सकते हैं। यह **पूर्ण कार्ड संख्या** (कार्ड के सामने के 16 अंक), **वैधता तिथि**, और कुछ मामलों में यहां तक कि **स्वामी का नाम** और **हाल के लेनदेन** की सूची प्राप्त करना संभव है।\
हालांकि, आप **इस तरह से CVV नहीं पढ़ सकते** (कार्ड के पीछे के 3 अंक)। इसके अलावा **बैंक कार्डों को पुनःप्रयोजन हमलों से सुरक्षित किया गया है**, इसलिए Flipper के साथ इसे कॉपी करना और फिर इसे किसी चीज़ के लिए भुगतान करने के लिए अनुकरण करने की कोशिश करना काम नहीं करेगा।

## References

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
