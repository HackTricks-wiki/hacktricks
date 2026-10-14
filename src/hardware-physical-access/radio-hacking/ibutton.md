# iButton

{{#include ../../banners/hacktricks-training.md}}

## परिचय

iButton इलेक्ट्रॉनिक पहचान-कुंजी का एक सामान्य नाम है, जिसे **सिक्के के आकार के धातु के खोल** में रखा जाता है। इसे **Dallas Touch** Memory या contact memory भी कहा जाता है। अक्सर इसे गलत रूप से “magnetic” key कहा जाता है, लेकिन इसमें **कुछ भी magnetic नहीं** होता। दरअसल, इसके अंदर digital protocol पर काम करने वाली एक पूर्ण **microchip** छिपी होती है।<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### iButton क्या है? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

iButton नाम इसके टिकाऊ, सिक्के के आकार के पैकेज और contact व्यवस्था को दर्शाता है। इसे रखने के लिए plastic fobs, rings और pendants उपलब्ध हैं।

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

जब दोनों contacts reader से जुड़ते हैं, तो device को power मिलती है और data का आदान-प्रदान होता है। अगर धँसी हुई contact संरचना के कारण बाहरी ground contacts आपस में नहीं मिलते, तो कुंजी को reader की दीवार से तिरछा टिकाने पर संपर्क फिर से स्थापित हो सकता है।<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protocol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas/Maxim keys, 1-Wire protocol का उपयोग करती हैं: एक data contact द्विदिशीय traffic ले जाता है और parasitic power भी दे सकता है, जबकि धातु का खोल return contact होता है। Controller transactions शुरू करता है और device जवाब देता है।<sup>[[2]](#references)</sup>

जब key (Slave), intercom (Master) से संपर्क करती है, तो intercom से power मिलने पर key के अंदर की chip चालू होती है और key initialize हो जाती है। इसके बाद intercom, key से उसका ID माँगता है। आगे, हम इस प्रक्रिया को विस्तार से देखेंगे।

Flipper, key को पढ़ते समय controller की तरह और reader को stored identifier दिखाते समय emulated device की तरह काम कर सकता है।<sup>[[1]](#references)</sup>

### Dallas, Cyfral और Metakom keys

इन keys के काम करने के तरीके की जानकारी के लिए यह पेज देखें: [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Attacks

iButtons पर Flipper Zero से हमला किया जा सकता है:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Flipper Zero से iButton को समझना](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — Software के ज़रिए 1-Wire communication](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
