# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks के लोगो और मोशन डिज़ाइन द्वारा_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
# "hi" for HindiP
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
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
Your local copy of HackTricks will be **available at [http://localhost:3337](http://localhost:3337)** after <5 minutes (it needs to build the book, be patient).

## कॉर्पोरेट प्रायोजक

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) एक उत्कृष्ट साइबर सुरक्षा कंपनी है जिसका नारा **HACK THE UNHACKABLE** है। वे अपना शोध करते हैं और अपने खुद के hacking tools विकसित करते हैं ताकि वे कई मूल्यवान साइबर सुरक्षा सेवाएं प्रदान कर सकें, जैसे pentesting, Red teams और प्रशिक्षण।

आप उनका **ब्लॉग** [**https://blog.stmcyber.com**](https://blog.stmcyber.com) पर देख सकते हैं

**STM Cyber** HackTricks जैसे साइबर सुरक्षा open source projects का भी समर्थन करता है :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) **Spain** में सबसे प्रासंगिक साइबर सुरक्षा इवेंट है और **Europe** में सबसे महत्वपूर्ण आयोजनों में से एक है। तकनीकी ज्ञान को बढ़ावा देने के मिशन के साथ, यह कांग्रेस प्रौद्योगिकी और साइबर सुरक्षा पेशेवरों के लिए सभी विधाओं में एक जोशीला मिलन स्थल है।

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** Europe की #1 ethical hacking और **bug bounty platform** है।

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) का उपयोग करके आप आसानी से workflows बनाकर और automate कर सकते हैं, जो दुनिया के सबसे advanced community tools से संचालित होते हैं।

आज ही Access प्राप्त करें:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

- **Hacking Insights:** ऐसे कंटेंट के साथ जुड़ें जो hacking के रोमांच और चुनौतियों पर गहराई से चर्चा करता है
- **Real-Time Hack News:** रियल-टाइम समाचार और insights के माध्यम से तेज़ी से बदलती hacking दुनिया के साथ अपडेट रहें
- **Latest Announcements:** नए लॉन्च हो रहे bug bounties और महत्वपूर्ण प्लेटफ़ॉर्म अपडेट्स के बारे में जानकारी पाएं

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security व्यावहारिक **AI Security training** प्रदान करता है जिसमें एक engineering-first, hands-on lab approach शामिल है। हमारे कोर्स सुरक्षा इंजीनियरों, AppSec पेशेवरों, और डेवलपर्स के लिए बने हैं जो वास्तविक AI/LLM-powered applications को बनाना, तोड़ना, और सुरक्षित करना चाहते हैं।

**AI Security Certification** वास्तविक दुनिया के कौशलों पर केंद्रित है, जिसमें शामिल हैं:
- Securing LLM and AI-powered applications
- Threat modeling for AI systems
- Embeddings, vector databases, and RAG security
- LLM attacks, abuse scenarios, and practical defenses
- Secure design patterns and deployment considerations

सारे कोर्स **on-demand**, **lab-driven**, और केवल सिद्धांत नहीं बल्कि वास्तविक-दुनिया के security tradeoffs के अनुसार डिज़ाइन किए गए हैं।

👉 AI Security course के बारे में और जानकारी:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** तेज़ और आसान real-time APIs प्रदान करता है ताकि आप **search engine results** तक पहुँच सकें। वे search engines को scrape करते हैं, proxies संभालते हैं, captchas सुलझाते हैं, और सभी rich structured data को आपके लिए parse करते हैं।

SerpApi की किसी योजना की subscription के साथ आप 50+ अलग APIs तक पहुँच प्राप्त कर सकते हैं जो विभिन्न search engines को scrape करते हैं, जिनमें Google, Bing, Baidu, Yahoo, Yandex और और भी शामिल हैं.\
अन्य प्रदाताओं के विपरीत, **SerpApi सिर्फ organic results को ही scrape नहीं करता**। SerpApi responses में लगातार सभी ads, inline images और videos, knowledge graphs, और search results में मौजूद अन्य elements और features शामिल रहते हैं।

वर्तमान SerpApi ग्राहकों में **Apple, Shopify, and GrubHub** शामिल हैं।\
अधिक जानकारी के लिए उनके [**blog**](https://serpapi.com/blog/)**,** देखें, या उनके [**playground**](https://serpapi.com/playground)** में एक उदाहरण आज़माएँ।**\
आप **free account** [**यहाँ**](https://serpapi.com/users/sign_up)** बना सकते हैं।**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

मोबाइल एप्लिकेशन और डिवाइस की सुरक्षा के लिए vulnerability research, penetration testing, और reverse engineering करने के लिए आवश्यक तकनीकों और कौशलों को सीखें। हमारे on-demand कोर्सेस के माध्यम से **iOS और Android security** में महारत हासिल करें और **get certified**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) एक पेशेवर साइबर सुरक्षा कंपनी है जो **Amsterdam** में स्थित है और जो दुनिया भर के व्यवसायों को नवीनतम साइबर सुरक्षा खतरों के विरुद्ध सुरक्षित करने में मदद करती है, आधुनिक दृष्टिकोण के साथ offensive-security services प्रदान करके।

WebSec एक international security कंपनी है जिसके कार्यालय Amsterdam और Wyoming में हैं। वे **all-in-one security services** प्रदान करते हैं जिसका मतलब है कि वे सब कुछ करते हैं; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing और बहुत कुछ।

WebSec का एक और दिलचस्प पहलू यह है कि industry average की तुलना में WebSec अपनी क्षमताओं पर बहुत आत्मविश्वासी है, इस कदर कि वे अपने परिणामों की सर्वोत्तम गुणवत्ता की गारंटी देते हैं, उनकी वेबसाइट पर लिखा है "**If we can't hack it, You don't pay it!**". अधिक जानकारी के लिए उनकी [**website**](https://websec.net/en/) और [**blog**](https://websec.net/blog/) देखें!

ऊपर के अलावा WebSec HackTricks का भी एक समर्थक रहा है।

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) प्रभावी साइबर सुरक्षा प्रशिक्षण विकसित और प्रदान करता है जिसे उद्योग विशेषज्ञों द्वारा बनाया और संचालित किया जाता है। उनके प्रोग्राम केवल सिद्धांत से आगे जाकर टीमों को गहरी समझ और actionable कौशल प्रदान करते हैं, कस्टम environments का उपयोग करते हुए जो वास्तविक दुनिया के खतरों को प्रतिबिंबित करते हैं। कस्टम प्रशिक्षण पूछताछ के लिए, हमसे [**यहाँ**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) संपर्क करें।

**क्या चीज़ें उनके प्रशिक्षण को अलग बनाती हैं:**
* कस्टम-निर्मित सामग्री और labs
* शीर्ष-स्तरीय tools और platforms द्वारा समर्थित
* practitioners द्वारा डिज़ाइन और सिखाया गया

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions शिक्षा और FinTech संस्थानों के लिए विशेषीकृत साइबर सुरक्षा सेवाएं प्रदान करता है, जिसमें विशेष ध्यान penetration testing, cloud security assessments, और compliance readiness (SOC 2, PCI-DSS, NIST) पर है। हमारी टीम में OSCP और CISSP certified professionals शामिल हैं, जो हर engagement में गहरी तकनीकी विशेषज्ञता और industry-standard insight लाते हैं।

हम automated scans से आगे जाकर manual, intelligence-driven testing करते हैं जो high-stakes environments के लिए अनुकूलित होता है। student records की सुरक्षा से लेकर financial transactions की रक्षा तक, हम संगठनों को वह चीज़ें सुरक्षित करने में मदद करते हैं जो सबसे महत्वपूर्ण हैं।

_“A quality defense requires knowing the offense, we provide security through understanding.”_

नवीनतम साइबर सुरक्षा समाचार और जानकारी के लिए उनके [**blog**](https://www.lasttowersolutions.com/blog) पर जाएँ।

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE DevOps, DevSecOps, और डेवलपर्स को Kubernetes clusters को कुशलतापूर्वक manage, monitor, और secure करने में सक्षम बनाता है। हमारे AI-driven insights, advanced security framework, और intuitive CloudMaps GUI का उपयोग करके अपने clusters का visualization करें, उनकी स्थिति समझें, और आत्मविश्वास के साथ कार्रवाई करें।

इसके अलावा, K8Studio सभी प्रमुख kubernetes distributions के साथ compatible है (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## License & Disclaimer

Check them in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
