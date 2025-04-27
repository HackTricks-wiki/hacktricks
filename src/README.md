# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks लोगो और मोशन डिज़ाइन_ [_@ppiernacho_](https://www.instagram.com/ppieranacho/)_ द्वारा।_

### HackTricks को स्थानीय रूप से चलाएँ
```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks

# Select the language you want to use
export LANG="master" # Leave master for english
# "af" for Afrikaans
# "de" for German
# "el" for Greek
# "es" for Spanish
# "fr" for French
# "hi" for Hindi
# "it" for Italian
# "ja" for Japanese
# "ko" for Korean
# "pl" for Polish
# "pt" for Portuguese
# "sr" for Serbian
# "sw" for Swahili
# "tr" for Turkish
# "uk" for Ukrainian
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "cd /app && git config --global --add safe.directory /app && git checkout $LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
आपकी स्थानीय कॉपी HackTricks **[http://localhost:3337](http://localhost:3337)** पर <5 मिनट के बाद उपलब्ध होगी (इसमें पुस्तक बनाने की आवश्यकता है, धैर्य रखें)।

## कॉर्पोरेट प्रायोजक

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) एक बेहतरीन साइबर सुरक्षा कंपनी है जिसका नारा है **HACK THE UNHACKABLE**। वे अपने स्वयं के शोध करते हैं और **कई मूल्यवान साइबर सुरक्षा सेवाएं** जैसे कि pentesting, Red teams और प्रशिक्षण के लिए अपने स्वयं के हैकिंग उपकरण विकसित करते हैं।

आप उनके **ब्लॉग** को [**https://blog.stmcyber.com**](https://blog.stmcyber.com) पर देख सकते हैं।

**STM Cyber** भी HackTricks जैसे साइबर सुरक्षा ओपन-सोर्स प्रोजेक्ट्स का समर्थन करता है :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) **स्पेन** में सबसे प्रासंगिक साइबर सुरक्षा कार्यक्रम है और **यूरोप** में सबसे महत्वपूर्ण में से एक है। **तकनीकी ज्ञान को बढ़ावा देने** के मिशन के साथ, यह कांग्रेस हर अनुशासन में प्रौद्योगिकी और साइबर सुरक्षा पेशेवरों के लिए एक उष्णकटिबंधीय बैठक स्थल है।

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** **यूरोप का #1** नैतिक हैकिंग और **बग बाउंटी प्लेटफॉर्म** है।

**बग बाउंटी टिप**: **Intigriti** के लिए **साइन अप करें**, एक प्रीमियम **बग बाउंटी प्लेटफॉर्म जो हैकर्स द्वारा, हैकर्स के लिए बनाया गया है**! आज ही [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) पर हमारे साथ जुड़ें, और **$100,000** तक के बाउंटी कमाना शुरू करें!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) का उपयोग करें ताकि आप दुनिया के **सबसे उन्नत** सामुदायिक उपकरणों द्वारा संचालित **वर्कफ़्लो** को आसानी से बना और स्वचालित कर सकें।

आज ही एक्सेस प्राप्त करें:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) सर्वर में शामिल हों ताकि आप अनुभवी हैकर्स और बग बाउंटी शिकारियों के साथ संवाद कर सकें!

- **हैकिंग अंतर्दृष्टि:** उस सामग्री के साथ संलग्न हों जो हैकिंग के रोमांच और चुनौतियों में गहराई से जाती है
- **वास्तविक समय हैक समाचार:** वास्तविक समय की समाचार और अंतर्दृष्टि के माध्यम से तेज़-तर्रार हैकिंग दुनिया के साथ अद्यतित रहें
- **नवीनतम घोषणाएँ:** नए बग बाउंटी लॉन्च और महत्वपूर्ण प्लेटफॉर्म अपडेट के साथ सूचित रहें

**हमारे साथ जुड़ें** [**Discord**](https://discord.com/invite/N3FrSbmwdy) पर और आज ही शीर्ष हैकर्स के साथ सहयोग करना शुरू करें!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - आवश्यक पेनिट्रेशन टेस्टिंग टूलकिट

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**अपने वेब ऐप्स, नेटवर्क और क्लाउड पर हैकर का दृष्टिकोण प्राप्त करें**

**महत्वपूर्ण, शोषण योग्य कमजोरियों को खोजें और रिपोर्ट करें जिनका वास्तविक व्यापार पर प्रभाव है।** हमारे 20+ कस्टम टूल का उपयोग करें ताकि हमले की सतह का मानचित्रण करें, सुरक्षा मुद्दों को खोजें जो आपको विशेषाधिकार बढ़ाने की अनुमति देते हैं, और आवश्यक सबूत इकट्ठा करने के लिए स्वचालित शोषण का उपयोग करें, जिससे आपका कठिन काम प्रभावशाली रिपोर्टों में बदल जाए।

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** तेज और आसान वास्तविक समय APIs प्रदान करता है ताकि आप **सर्च इंजन परिणामों** तक पहुँच सकें। वे सर्च इंजनों को स्क्रैप करते हैं, प्रॉक्सी को संभालते हैं, कैप्चा हल करते हैं, और आपके लिए सभी समृद्ध संरचित डेटा को पार्स करते हैं।

SerpApi की योजनाओं में से एक की सदस्यता में विभिन्न सर्च इंजनों के लिए 50 से अधिक विभिन्न APIs तक पहुँच शामिल है, जिसमें Google, Bing, Baidu, Yahoo, Yandex, और अधिक शामिल हैं।\
अन्य प्रदाताओं के विपरीत, **SerpApi केवल जैविक परिणामों को स्क्रैप नहीं करता है**। SerpApi प्रतिक्रियाएँ लगातार सभी विज्ञापनों, इनलाइन छवियों और वीडियो, ज्ञान ग्राफ़, और खोज परिणामों में मौजूद अन्य तत्वों और सुविधाओं को शामिल करती हैं।

वर्तमान SerpApi ग्राहक **Apple, Shopify, और GrubHub** हैं।\
अधिक जानकारी के लिए उनके [**ब्लॉग**](https://serpapi.com/blog/) पर जाएं, या उनके [**प्लेग्राउंड**](https://serpapi.com/playground) में एक उदाहरण आजमाएं।\
आप **यहां** [**एक मुफ्त खाता**](https://serpapi.com/users/sign_up) **बना सकते हैं।**

---

### [8kSec Academy – गहन मोबाइल सुरक्षा पाठ्यक्रम](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

कमजोरियों के शोध, पेनिट्रेशन टेस्टिंग, और रिवर्स इंजीनियरिंग को करने के लिए आवश्यक तकनीकों और कौशलों को सीखें ताकि मोबाइल ऐप्लिकेशनों और उपकरणों की सुरक्षा की जा सके। **iOS और Android सुरक्षा में महारत हासिल करें** हमारे ऑन-डिमांड पाठ्यक्रमों के माध्यम से और **प्रमाणित** हों:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) एक पेशेवर साइबर सुरक्षा कंपनी है जो **एम्स्टर्डम** में स्थित है जो **दुनिया भर में** व्यवसायों की **सुरक्षा** में मदद करती है नवीनतम साइबर सुरक्षा खतरों के खिलाफ **आक्रामक-सुरक्षा सेवाएं** प्रदान करके एक **आधुनिक** दृष्टिकोण के साथ।

WebSec एक अंतरराष्ट्रीय सुरक्षा कंपनी है जिसके कार्यालय एम्स्टर्डम और वायोमिंग में हैं। वे **ऑल-इन-वन सुरक्षा सेवाएं** प्रदान करते हैं जिसका अर्थ है कि वे सब कुछ करते हैं; Pentesting, **सुरक्षा** ऑडिट, जागरूकता प्रशिक्षण, फ़िशिंग अभियान, कोड समीक्षा, शोषण विकास, सुरक्षा विशेषज्ञों का आउटसोर्सिंग और बहुत कुछ।

WebSec के बारे में एक और अच्छी बात यह है कि उद्योग के औसत के विपरीत WebSec **अपनी क्षमताओं में बहुत आत्मविश्वास** है, इस हद तक कि वे **सर्वश्रेष्ठ गुणवत्ता परिणामों की गारंटी** देते हैं, यह उनकी वेबसाइट पर लिखा है "**अगर हम इसे हैक नहीं कर सकते, तो आप इसे नहीं चुकाएंगे!**" अधिक जानकारी के लिए उनकी [**वेबसाइट**](https://websec.net/en/) और [**ब्लॉग**](https://websec.net/blog/) पर जाएं!

उपरोक्त के अलावा WebSec भी HackTricks का **प्रतिबद्ध समर्थक** है।

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) एक डेटा ब्रीच (leak) सर्च इंजन है। \
हम सभी प्रकार के डेटा लीक पर यादृच्छिक स्ट्रिंग खोज (जैसे गूगल) प्रदान करते हैं - केवल बड़े नहीं - कई स्रोतों से डेटा पर। \
लोगों की खोज, AI खोज, संगठन की खोज, API (OpenAPI) एक्सेस, theHarvester एकीकरण, सभी सुविधाएँ जो एक pentester को चाहिए।\
**HackTricks हमारे लिए एक बेहतरीन शिक्षण प्लेटफॉर्म बना हुआ है और हम इसे प्रायोजित करने पर गर्व महसूस करते हैं!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

## लाइसेंस और अस्वीकरण

उन्हें देखें:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## गिटहब आँकड़े

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
