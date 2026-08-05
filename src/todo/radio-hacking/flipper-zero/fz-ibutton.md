# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## परिचय

iButton क्या है, इसकी अधिक जानकारी के लिए देखें:


{{#ref}}
../ibutton.md
{{#endref}}

## डिज़ाइन

निम्नलिखित image का **नीला** भाग दिखाता है कि Flipper को उसे **read** करने के लिए आपको **वास्तविक iButton** को किस प्रकार रखना होगा। **हरा** भाग दिखाता है कि **iButton को सही ढंग से emulate** करने के लिए आपको Flipper Zero से reader को किस प्रकार touch करना होगा।<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## क्रियाएँ

### Read

Read Mode में Flipper iButton key के touch होने की प्रतीक्षा करता है और तीन प्रकार की keys को process कर सकता है: **Dallas, Cyfral, और Metakom**। Flipper **key के type का स्वयं पता लगा लेता है**। Key protocol का नाम ID number के ऊपर screen पर प्रदर्शित होगा।<sup>[[1]](#references)</sup>

### manually जोड़ें

**Dallas, Cyfral, और Metakom** type का iButton **manually जोड़ना** संभव है।

### **Emulate**

saved iButtons (read किए गए या manually जोड़े गए) को **emulate** करना संभव है।

> [!TIP]
> यदि आप Flipper Zero के contacts को reader से touch कराकर अपेक्षित contact नहीं बना पा रहे हैं, तो आप **external GPIO का उपयोग कर सकते हैं:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## संदर्भ

- [1] [Taming iButton Keys with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
