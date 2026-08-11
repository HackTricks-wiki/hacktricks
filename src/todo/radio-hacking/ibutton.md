# iButton

{{#include ../../banners/hacktricks-training.md}}

## परिचय

iButton एक coin-shaped metal container में पैक की गई electronic identification key का generic name है। इसे **Dallas Touch** Memory या contact memory भी कहा जाता है। हालांकि इसे अक्सर गलत तरीके से “magnetic” key कहा जाता है, इसमें **कुछ भी magnetic नहीं** होता। वास्तव में, इसके अंदर digital protocol पर काम करने वाली एक पूर्ण **microchip** छिपी होती है।<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### iButton क्या है? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

iButton नाम इसके टिकाऊ coin-shaped package और contact arrangement को दर्शाता है। इसके holders में plastic fobs, rings और pendants शामिल हैं।

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

जब दोनों contacts reader से जुड़ते हैं, तो device को power मिलती है और data का आदान-प्रदान होता है। यदि recessed contact geometry के कारण बाहरी ground contacts आपस में नहीं जुड़ पाते, तो key को reader की wall के विरुद्ध झुकाने से contact फिर से स्थापित किया जा सकता है।<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protocol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas/Maxim keys 1-Wire protocol का उपयोग करती हैं: एक data contact bidirectional traffic को वहन करता है और parasitic power भी प्रदान कर सकता है, जबकि metal can return contact का काम करता है। Controller transactions शुरू करता है और device response देता है।<sup>[[2]](#references)</sup>

जब key (Slave), intercom (Master) से contact करती है, तो key के अंदर की chip intercom से power प्राप्त करके चालू हो जाती है और key initialize हो जाती है। इसके बाद intercom key ID का अनुरोध करता है। आगे, हम इस process को अधिक विस्तार से देखेंगे।

Flipper key को पढ़ते समय controller के रूप में और reader के सामने stored identifier प्रस्तुत करते समय emulated device के रूप में काम कर सकता है।<sup>[[1]](#references)</sup>

### Dallas, Cyfral और Metakom keys

इन keys के काम करने के तरीके की जानकारी के लिए यह page देखें: [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Attacks

iButtons पर Flipper Zero से attack किया जा सकता है:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Flipper Zero के साथ iButton को नियंत्रित करना](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — software के माध्यम से 1-Wire communication](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
