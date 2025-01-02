# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Intro

125kHz टैग कैसे काम करते हैं, इसके बारे में अधिक जानकारी के लिए देखें:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Actions

इन प्रकार के टैग के बारे में अधिक जानकारी के लिए [**यह परिचय पढ़ें**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Read

कार्ड की जानकारी को **पढ़ने** की कोशिश करता है। फिर इसे **अनुकरण** कर सकता है।

> [!WARNING]
> ध्यान दें कि कुछ इंटरकॉम अपने आप को कुंजी डुप्लिकेशन से बचाने के लिए पढ़ने से पहले एक लिखने का आदेश भेजने की कोशिश करते हैं। यदि लिखना सफल होता है, तो उस टैग को नकली माना जाता है। जब Flipper RFID का अनुकरण करता है, तो रीडर के लिए इसे मूल से अलग करना संभव नहीं होता, इसलिए ऐसी समस्याएँ नहीं होती हैं।

### Add Manually

आप Flipper Zero में **नकली कार्ड बना सकते हैं** जो आप मैन्युअल रूप से डेटा दिखाते हैं और फिर इसे अनुकरण कर सकते हैं।

#### IDs on cards

कभी-कभी, जब आप एक कार्ड प्राप्त करते हैं, तो आप कार्ड पर दिखाई देने वाले ID (या भाग) को पाएंगे।

- **EM Marin**

उदाहरण के लिए, इस EM-Marin कार्ड में भौतिक कार्ड में **स्पष्ट रूप से 5 बाइट में से अंतिम 3 को पढ़ना संभव है**।\
यदि आप उन्हें कार्ड से नहीं पढ़ सकते हैं, तो अन्य 2 को ब्रूट-फोर्स किया जा सकता है।

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

इस HID कार्ड में भी यही होता है जहाँ केवल 3 बाइट में से 2 को कार्ड पर मुद्रित पाया जा सकता है।

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

एक कार्ड को **कॉपी करने** या **मैन्युअल रूप से** ID **दाखिल करने** के बाद इसे Flipper Zero के साथ **अनुकरण** करना या इसे एक असली कार्ड में **लिखना** संभव है।

## References

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../../banners/hacktricks-training.md}}
