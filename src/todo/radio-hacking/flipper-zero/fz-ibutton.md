# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Intro

iButton क्या है इसके बारे में अधिक जानकारी के लिए देखें:

{{#ref}}
../ibutton.md
{{#endref}}

## Design

निम्नलिखित छवि का **नीला** भाग वह है जहाँ आपको **वास्तविक iButton** को **रखना** होगा ताकि Flipper इसे **पढ़ सके।** **हरा** भाग वह है जहाँ आपको **Flipper zero के साथ रीडर को छूना** है ताकि **iButton को सही तरीके से अनुकरण** किया जा सके।

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Actions

### Read

Read Mode में Flipper iButton कुंजी के छूने का इंतजार कर रहा है और तीन प्रकार की कुंजियों: **Dallas, Cyfral, और Metakom** में से किसी को भी समझने में सक्षम है। Flipper **कुंजी के प्रकार का पता खुद लगाएगा।** कुंजी प्रोटोकॉल का नाम ID संख्या के ऊपर स्क्रीन पर प्रदर्शित होगा।

### Add manually

यह **हाथ से जोड़ना** संभव है एक iButton प्रकार: **Dallas, Cyfral, और Metakom**

### **Emulate**

यह **अनुकरण** करना संभव है सहेजे गए iButtons (पढ़े गए या हाथ से जोड़े गए)।

> [!NOTE]
> यदि आप Flipper Zero के अपेक्षित संपर्कों को रीडर को छूने में असमर्थ हैं तो आप **बाहरी GPIO का उपयोग कर सकते हैं:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
