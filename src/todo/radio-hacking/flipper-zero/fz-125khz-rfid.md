# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}


## परिचय

125kHz tags कैसे काम करते हैं, इसकी अधिक जानकारी के लिए देखें:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## क्रियाएँ

इस प्रकार के tags के बारे में अधिक जानकारी के लिए [**यह परिचय पढ़ें**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz)।

### Read

Card की जानकारी **read** करने का प्रयास करता है। इसके बाद यह उन्हें **emulate** कर सकता है।<sup>[[1]](#references)</sup>

> [!WARNING]
> ध्यान दें कि कुछ intercoms, reading से पहले write command भेजकर खुद को key duplication से सुरक्षित रखने का प्रयास करते हैं। यदि write सफल हो जाता है, तो उस tag को fake माना जाता है। जब Flipper RFID को emulate करता है, तो reader के पास उसे original से अलग पहचानने का कोई तरीका नहीं होता, इसलिए ऐसी कोई समस्या नहीं होती।

### Manually Add करें

आप Flipper Zero में अपने द्वारा manually दिए गए data को दर्शाने वाले **fake cards** बना सकते हैं और फिर उन्हें emulate कर सकते हैं।

#### Cards पर IDs

कभी-कभी, जब आपको कोई card मिलता है, तो आप उसका ID (या उसका कुछ भाग) card पर स्पष्ट रूप से लिखा हुआ देख सकते हैं।

- **EM Marin**

उदाहरण के लिए, इस EM-Marin card में physical card पर **5 bytes में से अंतिम 3 bytes को clear में read करना** संभव है।\
यदि आप card से अन्य 2 bytes को read नहीं कर सकते, तो उन्हें brute-force किया जा सकता है।<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

इस HID card में भी ऐसा ही होता है, जहाँ 3 bytes में से केवल 2 bytes card पर printed मिलते हैं।

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

किसी card को **copy करने** या उसका ID **manually दर्ज करने** के बाद, Flipper Zero से उसे **emulate** करना या किसी real card में **write** करना संभव है।<sup>[[1]](#references)</sup>

## References

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)


{{#include ../../../banners/hacktricks-training.md}}
