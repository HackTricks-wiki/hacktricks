# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logos & motion design by_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### HackTricks को लोकली चलाएँ
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
Your local copy of HackTricks will be **[http://localhost:3337](http://localhost:3337)** पर **<5 मिनट** के बाद उपलब्ध होगा (इसे book build करनी है, धैर्य रखें)।

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) एक शानदार cybersecurity कंपनी है जिसका slogan **HACK THE UNHACKABLE** है। वे अपना research करते हैं और अपने खुद के hacking tools develop करते हैं ताकि **pentesting, Red teams और training** जैसी कई valuable cybersecurity services दे सकें।

आप उनका **blog** [**https://blog.stmcyber.com**](https://blog.stmcyber.com) पर देख सकते हैं

**STM Cyber** HackTricks जैसे cybersecurity open source projects को भी support करता है :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** **Europe's #1** ethical hacking और **bug bounty platform** है।

**Bug bounty tip**: **Intigriti** पर **sign up** करें, जो hackers द्वारा, hackers के लिए बनाया गया premium **bug bounty platform** है! आज ही [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) पर हमसे जुड़ें, और **$100,000** तक के bounties कमाना शुरू करें!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

अनुभवी hackers और bug bounty hunters के साथ communicate करने के लिए [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server से जुड़ें!

- **Hacking Insights:** hacking की thrill और challenges पर गहराई से जाने वाले content के साथ engage करें
- **Real-Time Hack News:** real-time news और insights के जरिए तेज़-रफ़्तार hacking world से up-to-date रहें
- **Latest Announcements:** लॉन्च हो रहे newest bug bounties और important platform updates की जानकारी रखें

आज ही [**Discord**](https://discord.com/invite/N3FrSbmwdy) पर हमसे जुड़ें और top hackers के साथ collaboration शुरू करें!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security **practical AI Security training** देती है, जिसमें **engineering-first, hands-on lab approach** है। हमारे courses security engineers, AppSec professionals, और developers के लिए बनाए गए हैं जो **real AI/LLM-powered applications build, break, और secure** करना चाहते हैं।

**AI Security Certification** real-world skills पर focus करती है, जिनमें शामिल हैं:
- LLM और AI-powered applications को secure करना
- AI systems के लिए Threat modeling
- Embeddings, vector databases, और RAG security
- LLM attacks, abuse scenarios, और practical defenses
- Secure design patterns और deployment considerations

सभी courses **on-demand**, **lab-driven** हैं, और केवल theory नहीं बल्कि **real-world security tradeoffs** के आसपास design किए गए हैं।

👉 AI Security course के बारे में अधिक जानकारी:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** search engine results तक **access** के लिए तेज़ और आसान real-time APIs देता है। वे search engines scrape करते हैं, proxies handle करते हैं, captchas solve करते हैं, और आपके लिए सभी rich structured data parse करते हैं।

SerpApi की किसी plan की subscription में Google, Bing, Baidu, Yahoo, Yandex, और अन्य सहित अलग-अलग search engines को scrape करने के लिए 50 से अधिक अलग-अलग APIs का access शामिल है।\
दूसरे providers के विपरीत, **SerpApi सिर्फ organic results scrape नहीं करता**। SerpApi responses में लगातार सभी ads, inline images और videos, knowledge graphs, और search results में मौजूद अन्य elements और features शामिल होते हैं।

SerpApi के current customers में **Apple, Shopify, और GrubHub** शामिल हैं।\
अधिक जानकारी के लिए उनका [**blog**](https://serpapi.com/blog/)**,** देखें, या उनके [**playground**](https://serpapi.com/playground)**.** में एक example आज़माएँ।\
आप [**यहाँ**](https://serpapi.com/users/sign_up) **free account** बना सकते हैं।

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

vulnerability research, penetration testing, और reverse engineering करने के लिए आवश्यक technologies और skills सीखें ताकि mobile applications और devices को protect किया जा सके। हमारे on-demand courses के माध्यम से **iOS और Android security master** करें और **certified** प्राप्त करें:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** एक AI-powered security platform है जो attackers से पहले exploitable vulnerabilities ढूँढने के लिए बनाया गया है।

**Code security tip**: NaxusAI पर **sign up** करें, एक smart vulnerability monitoring platform जो developers और security teams के लिए बनाया गया है! आज ही हमसे जुड़ें और production तक पहुँचने से पहले **real security risks को detect, validate, और fix** करने के लिए AI का उपयोग करना शुरू करें!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) **Amsterdam** में स्थित एक professional cybersecurity company है जो **modern** approach के साथ **offensive-security services** प्रदान करके businesses को **all over the world** latest cybersecurity threats से **protect** करने में मदद करती है।

WebSec एक international security company है जिसके offices Amsterdam और Wyoming में हैं। वे **all-in-one security services** देते हैं, यानी वे सब कुछ करते हैं; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing और बहुत कुछ।

WebSec की एक और अच्छी बात यह है कि industry average के विपरीत WebSec अपनी skills को लेकर **बहुत confident** है, इतना कि वे **best quality results की गारंटी** देते हैं; उनकी website पर लिखा है "**If we can't hack it, You don't pay it!**". अधिक जानकारी के लिए उनकी [**website**](https://websec.net/en/) और [**blog**](https://websec.net/blog/) देखें!

उपरोक्त के अलावा WebSec HackTricks का एक **committed supporter** भी है।

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**मैदान के लिए बनाया गया। आपके लिए बनाया गया।**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) industry experts द्वारा बनाया और संचालित effective cybersecurity training develop और deliver करता है। उनके programs theory से आगे जाकर teams को deep understanding और actionable skills देते हैं, custom environments का उपयोग करके जो real-world threats को reflect करते हैं। Custom training inquiries के लिए, हमसे [**यहाँ**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) संपर्क करें।

**उनकी training को अलग बनाता है:**
* Custom-built content और labs
* Top-tier tools और platforms द्वारा backed
* Practitioners द्वारा designed और taught

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions **Education** और **FinTech** institutions के लिए specialized cybersecurity services देती है, जिनका focus **penetration testing, cloud security assessments**, और **compliance readiness** (SOC 2, PCI-DSS, NIST) पर है। हमारी team में **OSCP और CISSP certified professionals** शामिल हैं, जो हर engagement में deep technical expertise और industry-standard insight लाते हैं।

हम high-stakes environments के लिए tailored **manual, intelligence-driven testing** के साथ automated scans से आगे जाते हैं। student records को secure करने से लेकर financial transactions को protect करने तक, हम organizations को सबसे महत्वपूर्ण चीज़ों की रक्षा करने में मदद करते हैं।

_“एक quality defense के लिए offense को जानना ज़रूरी है, हम understanding के माध्यम से security प्रदान करते हैं।”_

हमारे [**blog**](https://www.lasttowersolutions.com/blog) पर जाकर cybersecurity की latest जानकारी से up to date रहें।

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE DevOps, DevSecOps, और developers को Kubernetes clusters को efficiently manage, monitor, और secure करने में सक्षम बनाता है। अपने clusters को visualize करने, उनकी state समझने, और confidence के साथ action लेने के लिए हमारे AI-driven insights, advanced security framework, और intuitive CloudMaps GUI का लाभ उठाएँ।

इसके अलावा, K8Studio **all major kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more) के साथ **compatible** है।

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## License & Disclaimer

इन्हें यहाँ देखें:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
