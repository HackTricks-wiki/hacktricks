# Linux Environment Variables

{{#include ../banners/hacktricks-training.md}}

## Global variables

वैश्विक चर **बच्चे प्रक्रियाओं** द्वारा विरासत में लिए जाएंगे।

आप अपने वर्तमान सत्र के लिए एक वैश्विक चर बनाने के लिए कर सकते हैं:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
यह वेरिएबल आपकी वर्तमान सत्रों और इसके चाइल्ड प्रोसेस द्वारा एक्सेस किया जाएगा।

आप एक वेरिएबल को **हटाने** के लिए कर सकते हैं:
```bash
unset MYGLOBAL
```
## स्थानीय चर

**स्थानीय चर** केवल **वर्तमान शेल/स्क्रिप्ट** द्वारा **पहुँच** किए जा सकते हैं।
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## वर्तमान वेरिएबल्स की सूची
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## सामान्य वेरिएबल

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – **X** द्वारा उपयोग किया जाने वाला डिस्प्ले। यह वेरिएबल आमतौर पर **:0.0** पर सेट होता है, जिसका अर्थ है वर्तमान कंप्यूटर पर पहला डिस्प्ले।
- **EDITOR** – उपयोगकर्ता का पसंदीदा टेक्स्ट संपादक।
- **HISTFILESIZE** – इतिहास फ़ाइल में शामिल अधिकतम पंक्तियों की संख्या।
- **HISTSIZE** – जब उपयोगकर्ता अपनी सत्र समाप्त करता है तो इतिहास फ़ाइल में जोड़ी गई पंक्तियों की संख्या।
- **HOME** – आपका होम डायरेक्टरी।
- **HOSTNAME** – कंप्यूटर का होस्टनेम।
- **LANG** – आपकी वर्तमान भाषा।
- **MAIL** – उपयोगकर्ता के मेल स्पूल का स्थान। आमतौर पर **/var/spool/mail/USER**।
- **MANPATH** – मैनुअल पृष्ठों के लिए खोजने के लिए निर्देशिकाओं की सूची।
- **OSTYPE** – ऑपरेटिंग सिस्टम का प्रकार।
- **PS1** – बैश में डिफ़ॉल्ट प्रॉम्प्ट।
- **PATH** – सभी निर्देशिकाओं का पथ संग्रहीत करता है जो बाइनरी फ़ाइलें रखती हैं, जिन्हें आप केवल फ़ाइल के नाम को निर्दिष्ट करके निष्पादित करना चाहते हैं, न कि सापेक्ष या पूर्ण पथ द्वारा।
- **PWD** – वर्तमान कार्यशील निर्देशिका।
- **SHELL** – वर्तमान कमांड शेल का पथ (उदाहरण के लिए, **/bin/bash**).
- **TERM** – वर्तमान टर्मिनल प्रकार (उदाहरण के लिए, **xterm**).
- **TZ** – आपका समय क्षेत्र।
- **USER** – आपका वर्तमान उपयोगकर्ता नाम।

## हैकिंग के लिए दिलचस्प वेरिएबल

### **HISTFILESIZE**

इस वेरिएबल का **मान 0** में बदलें, ताकि जब आप **अपना सत्र समाप्त करें** तो **इतिहास फ़ाइल** (\~/.bash_history) **हटा दी जाएगी**।
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

इस **चर का मान 0** में बदलें, ताकि जब आप **अपनी सत्र समाप्त करें** तो कोई भी आदेश **इतिहास फ़ाइल** (\~/.bash_history) में जोड़ा न जाए।
```bash
export HISTSIZE=0
```
### http_proxy & https_proxy

प्रक्रियाएँ यहाँ घोषित **proxy** का उपयोग करके **http या https** के माध्यम से इंटरनेट से कनेक्ट होंगी।
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL_CERT_FILE & SSL_CERT_DIR

प्रक्रियाएँ **इन env variables** में निर्दिष्ट प्रमाणपत्रों पर भरोसा करेंगी।
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

अपने प्रॉम्प्ट को कैसे दिखता है, बदलें।

[**यह एक उदाहरण है**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

रूट:

![](<../images/image (897).png>)

सामान्य उपयोगकर्ता:

![](<../images/image (740).png>)

एक, दो और तीन बैकग्राउंड जॉब्स:

![](<../images/image (145).png>)

एक बैकग्राउंड जॉब, एक रुकी हुई और अंतिम कमांड सही ढंग से समाप्त नहीं हुई:

![](<../images/image (715).png>)

{{#include ../banners/hacktricks-training.md}}
