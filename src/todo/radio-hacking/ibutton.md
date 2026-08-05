# iButton

{{#include ../../banners/hacktricks-training.md}}

## परिचय

iButton electronic identification key के लिए इस्तेमाल किया जाने वाला एक generic name है, जिसे **coin-shaped metal container** में पैक किया जाता है। इसे **Dallas Touch** Memory या contact memory भी कहा जाता है। हालांकि इसे अक्सर गलती से “magnetic” key कहा जाता है, इसमें **कुछ भी magnetic नहीं** होता। वास्तव में, इसके अंदर digital protocol पर काम करने वाला एक पूर्ण **microchip** छिपा होता है।<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### iButton क्या है? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

आमतौर पर, iButton से key और reader का physical form समझा जाता है - दो contacts वाला एक गोल coin। इसे घेरने वाले frame में सबसे सामान्य hole वाले plastic holder से लेकर rings, pendants आदि तक कई variations होते हैं।

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

जब key reader तक पहुंचती है, तो **contacts आपस में touch होते हैं** और key को अपना ID **transmit** करने के लिए power मिलती है। कभी-कभी key को तुरंत **read नहीं किया जाता**, क्योंकि intercom का **contact PSD अपेक्षा से बड़ा** होता है। इसलिए key और reader के बाहरी contours आपस में touch नहीं कर पाते। ऐसी स्थिति में आपको key को reader की किसी एक wall पर दबाना होगा।

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protocol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas keys data exchange करने के लिए 1-wire protocol का इस्तेमाल करती हैं। दोनों दिशाओं में data transfer के लिए केवल एक contact (!!) होता है, यानी master से slave और इसके विपरीत। 1-wire protocol Master-Slave model के अनुसार काम करता है। इस topology में Master हमेशा communication शुरू करता है और Slave उसके instructions का पालन करता है।

जब key (Slave), intercom (Master) से contact करती है, तो key के अंदर का chip intercom से power लेकर on हो जाता है और key initialize हो जाती है। इसके बाद intercom key से उसका ID request करता है। आगे, हम इस process को अधिक detail में देखेंगे।

Flipper Master और Slave दोनों modes में काम कर सकता है। Key reading mode में Flipper एक reader की तरह काम करता है, यानी यह Master के रूप में काम करता है। और key emulation mode में Flipper एक key होने का दिखावा करता है, यानी यह Slave mode में होता है।

### Dallas, Cyfral & Metakom keys

इन keys के काम करने के तरीके की जानकारी के लिए यह page देखें [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Attacks

iButtons पर Flipper Zero से attack किया जा सकता है:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Taming iButton](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
