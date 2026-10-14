# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

## परिचय

125 kHz tags कैसे काम करते हैं, इसकी पृष्ठभूमि के लिए देखें:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

[लो-फ़्रीक्वेंसी RFID का परिचय](../pentesting-rfid.md#low-frequency-rfid-tags-125khz) में आम tag families और उनके data formats की जानकारी दी गई है।

## कार्रवाइयाँ

### पढ़ें

Tag data कैप्चर करने के लिए **Read** का उपयोग करें। सफलतापूर्वक पढ़ने के बाद, Flipper Zero सेव किए गए tag को emulate कर सकता है।<sup>[[1]](#references)</sup>

> [!WARNING]
> कुछ intercom readers, पढ़ने से पहले write command जारी करके writable duplicate tags का पता लगाने की कोशिश करते हैं। Flipper Zero emulation में writable tag memory उसी तरह उपलब्ध नहीं होती।<sup>[[1]](#references)</sup>

### मैन्युअली जोड़ें

आप Flipper Zero में tag data मैन्युअली दर्ज करके उसे सेव कर सकते हैं और फिर emulate कर सकते हैं।<sup>[[1]](#references)</sup>

#### Cards पर IDs

कभी-कभी किसी card की पूरी या कुछ ID उसके बाहरी हिस्से पर छपी होती है।

- **EM Marin**

उदाहरण के लिए, चित्र में दिखाए गए EM-Marin card पर उसकी पाँच ID bytes में से आख़िरी तीन दिखाई देती हैं। अगर tag पढ़ा नहीं जा सकता, तो गायब दो bytes को brute-force किया जा सकता है।

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

इसी तरह, चित्र में दिखाए गए HID card पर उसकी तीन ID bytes में से केवल दो छपी हैं।

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

Tag पढ़ने या उसकी ID मैन्युअली दर्ज करने के बाद, Flipper Zero सेव किए गए credential को emulate कर सकता है। समर्थित writable tags के लिए, यह सेव किए गए data को compatible card पर लिख भी सकता है।<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: RFID Protocols की गहराई में](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
