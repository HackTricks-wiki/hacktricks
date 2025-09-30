# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks के लोगो और मोशन डिज़ाइन द्वारा_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### HackTricks स्थानीय रूप से चलाएँ
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

[**STM Cyber**](https://www.stmcyber.com) एक बेहतरीन साइबरसिक्योरिटी कंपनी है जिसका नारा **HACK THE UNHACKABLE** है। वे अपना खुद का अनुसंधान करते हैं और अपने hacking tools विकसित करते हैं ताकि कई मूल्यवान साइबरसिक्योरिटी सेवाएं प्रदान कर सकें, जैसे pentesting, Red teams और training।

आप उनका **blog** [**https://blog.stmcyber.com**](https://blog.stmcyber.com) देख सकते हैं

**STM Cyber** HackTricks जैसे साइबरसिक्योरिटी open source प्रोजेक्ट्स का भी समर्थन करते हैं :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) Spain में सबसे प्रासंगिक साइबरसिक्योरिटी इवेंट है और Europe में सबसे महत्वपूर्ण आयोजनों में से एक है। तकनीकी ज्ञान को बढ़ावा देने के मिशन के साथ, यह सम्मेलन प्रौद्योगिकी और साइबरसिक्योरिटी पेशेवरों के लिए हर अनुशासन में एक प्रमुख मिलन स्थल है।

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** Europe की #1 ethical hacking और bug bounty platform है।

**Bug bounty tip**: **sign up** for **Intigriti**, एक प्रीमियम **bug bounty platform created by hackers, for hackers**! आज ही [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) पर जुड़ें, और $100,000 तक की bounties कमाना शुरू करें!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) का उपयोग करके आप आसानी से workflows बनाएं और automate करें, जो दुनिया के सबसे advanced community tools द्वारा संचालित हैं।

Get Access Today:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

- **Hacking Insights:** उन विषयों से जुड़ें जो hacking के रोमांच और चुनौतियों में डूबते हैं
- **Real-Time Hack News:** तेज़-तर्रार hacking दुनिया की real-time news और insights के साथ अपडेट रहें
- **Latest Announcements:** नए लॉन्च हो रहे bug bounties और महत्वपूर्ण प्लेटफ़ॉर्म अपडेट्स से सूचित रहें

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Get a hacker's perspective on your web apps, network, and cloud**

**Find and report critical, exploitable vulnerabilities with real business impact.** हमारे 20+ custom tools का उपयोग करके attack surface को map करें, उन security issues को ढूंढें जो आपको privileges escalate करने देते हैं, और automated exploits का उपयोग करके आवश्यक सबूत एकत्र करें, जिससे आपका मेहनतपूर्ण काम प्रभावी रिपोर्ट्स में बदल सके।

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** तेज़ और आसान real-time APIs प्रदान करता है ताकि आप search engine results तक पहुंच सकें। वे search engines scrape करते हैं, proxies संभालते हैं, captchas हल करते हैं, और आपके लिए सभी समृद्ध संरचित डेटा को parse करते हैं।

SerpApi की किसी भी योजना की सदस्यता में विभिन्न search engines को scrape करने के लिए 50+ अलग APIs तक पहुंच शामिल है, जिनमें Google, Bing, Baidu, Yahoo, Yandex और अन्य शामिल हैं.\
अन्य प्रदाताओं के विपरीत, **SerpApi सिर्फ organic results को scrape नहीं करता**। SerpApi responses लगातार सभी ads, inline images और videos, knowledge graphs, और search results में मौजूद अन्य तत्वों और फीचर्स को शामिल करते हैं।

Current SerpApi customers में **Apple, Shopify, and GrubHub** शामिल हैं।\
अधिक जानकारी के लिए उनका [**blog**](https://serpapi.com/blog/) देखें, या उनके [**playground**](https://serpapi.com/playground) में एक उदाहरण आज़माएँ।\
आप यहाँ एक मुफ्त खाता बना सकते हैं: [**https://serpapi.com/users/sign_up**](https://serpapi.com/users/sign_up)

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

मोबाइल एप्लिकेशन और डिवाइस की रक्षा करने के लिए vulnerability research, penetration testing, और reverse engineering करने के लिए आवश्यक तकनीकें और कौशल सीखें। हमारी ऑन-डिमांड कोर्सेज के माध्यम से **iOS and Android security** में महारथ हासिल करें और **get certified**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) एक पेशेवर साइबरसिक्योरिटी कंपनी है जो **Amsterdam** में आधारित है और दुनिया भर के व्यवसायों को नवीनतम साइबर खतरों से बचाने में मदद करती है, आधुनिक दृष्टिकोण के साथ **offensive-security services** प्रदान करके।

WebSec एक अंतरराष्ट्रीय security कंपनी है जिसकी ऑफिस Amsterdam और Wyoming में हैं। वे **all-in-one security services** प्रदान करते हैं, जिसका अर्थ है कि वे सब कुछ करते हैं; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing और बहुत कुछ।

WebSec के बारे में एक और अच्छी बात यह है कि उद्योग के औसत की तुलना में WebSec अपनी क्षमताओं के प्रति **बहुत आत्मविश्वासी** है, इस हद तक कि वे **best quality results** की गारंटी भी देते हैं, उनकी वेबसाइट पर लिखा है "**If we can't hack it, You don't pay it!**". अधिक जानकारी के लिए उनकी [**website**](https://websec.net/en/) और [**blog**](https://websec.net/blog/) देखें!

इसके अलावा WebSec HackTricks का भी **समर्पित समर्थक** है।

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) एक data breach (leak) search engine है. \
हम random string search (जैसे google) प्रदान करते हैं 모든 प्रकार के data leaks पर—बड़े और छोटे दोनों पर—कई स्रोतों के डेटा पर। \
People search, AI search, organization search, API (OpenAPI) access, theHarvester integration, सभी फ़ीचर्स जो एक pentester को चाहिए।\
**HackTricks हमारे लिए सीखने का एक शानदार प्लेटफ़ॉर्म बना रहता है और हमें इसे स्पॉन्सर करते हुए गर्व है!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) industry experts द्वारा निर्मित और नेतृत्व में विकसित प्रभावी साइबरसिक्योरिटी training विकसित करता और प्रदान करता है। उनके प्रोग्राम सिर्फ सिद्धांत से परे जाते हैं ताकि टीमों को गहरी समझ और actionable कौशल मिले, उन custom environments का उपयोग करके जो real-world threats को प्रतिबिंबित करते हैं। custom training के लिए inquiries हेतु हमसे यहाँ संपर्क करें [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks)।

**What sets their training apart:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions शिक्षा और FinTech संस्थानों के लिए विशेष साइबरसिक्योरिटी सेवाएं प्रदान करता है, विशेष रूप से penetration testing, cloud security assessments, और compliance readiness (SOC 2, PCI-DSS, NIST) पर ध्यान केंद्रित करता है। हमारी टीम में **OSCP and CISSP certified professionals** शामिल हैं, जो हर engagement में गहरी तकनीकी विशेषज्ञता और industry-standard insight लाते हैं।

हम automated scans से आगे जाते हैं और high-stakes environments के लिए tailored manual, intelligence-driven testing प्रदान करते हैं। छात्र रिकॉर्ड सुरक्षित करने से लेकर वित्तीय लेनदेन की रक्षा करने तक, हम संगठनों को वह सुरक्षा देने में मदद करते हैं जो सबसे अधिक मायने रखती है।

_“A quality defense requires knowing the offense, we provide security through understanding.”_

नवीनतम साइबरसिक्योरिटी अपडेट्स के लिए उनके [**blog**](https://www.lasttowersolutions.com/blog) पर जाएँ।

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE DevOps, DevSecOps, और developers को Kubernetes clusters को कुशलतापूर्वक manage, monitor, और secure करने में सक्षम बनाता है। हमारे AI-driven insights, advanced security framework, और intuitive CloudMaps GUI का लाभ उठाकर अपने clusters को visualize करें, उनकी स्थिति समझें, और आत्मविश्वास के साथ कार्रवाई करें।

इसके अलावा, K8Studio सभी प्रमुख kubernetes distributions के साथ **compatible** है (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## लाइसेंस & अस्वीकरण

इन्हें देखें:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
