# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

## Intro

125 kHz tags कैसे काम करते हैं, इसकी पृष्ठभूमि के लिए देखें:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

[low-frequency RFID introduction](../pentesting-rfid.md#low-frequency-rfid-tags-125khz) में सामान्य tag families और उनके data formats समझाए गए हैं।

## Actions

### Read

Tag data capture करने के लिए **Read** का उपयोग करें। सफलतापूर्वक read करने के बाद, Flipper Zero saved tag को emulate कर सकता है।<sup>[[1]](#references)</sup>

> [!WARNING]
> कुछ intercom readers read करने से पहले write command भेजकर writable duplicate tags का पता लगाने का प्रयास करते हैं। Flipper Zero emulation writable tag memory को उसी तरह expose नहीं करती।<sup>[[1]](#references)</sup>

### Add manually

आप Flipper Zero में tag data manually enter कर सकते हैं, उसे save कर सकते हैं और फिर उसे emulate कर सकते हैं।<sup>[[1]](#references)</sup>

#### IDs on cards

कभी-कभी किसी card की ID का पूरा या कुछ हिस्सा उसके बाहरी भाग पर printed होता है।

- **EM Marin**

उदाहरण के लिए, चित्र में दिखाया गया EM-Marin card अपने पाँच ID bytes में से अंतिम तीन को दिखाता है। यदि tag read नहीं किया जा सकता, तो missing दो bytes को brute-force किया जा सकता है।

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

इसी तरह, चित्र में दिखाया गया HID card तीन ID bytes में से केवल दो को print करता है।

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

किसी tag को read करने या उसकी ID manually enter करने के बाद, Flipper Zero saved credential को emulate कर सकता है। Supported writable tags के लिए, यह saved data को compatible card में write भी कर सकता है।<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: Diving into RFID Protocols](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
