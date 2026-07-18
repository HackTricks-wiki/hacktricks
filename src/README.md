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
HackTricks की आपकी local copy **[http://localhost:3337](http://localhost:3337) पर** <5 मिनट के बाद उपलब्ध होगी (इसे book build करने की आवश्यकता है, धैर्य रखें)।

वैकल्पिक रूप से, यदि आपके पास Docker Compose है, तो आप repo root से बस निम्नलिखित चला सकते हैं:
```bash
docker compose up
```
यह bundled `docker-compose.yml` का उपयोग करके आपके local checkout को [http://localhost:3337](http://localhost:3337) पर live reload के साथ serve करता है।

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) एक बेहतरीन cybersecurity company है, जिसका slogan है **HACK THE UNHACKABLE**। वे अपना research करते हैं और अपने hacking tools develop करते हैं, ताकि pentesting, Red teams और training जैसी **कई मूल्यवान cybersecurity services प्रदान कर सकें**।

आप उनका **blog** [**https://blog.stmcyber.com**](https://blog.stmcyber.com) पर देख सकते हैं।

**STM Cyber** HackTricks जैसे cybersecurity open source projects को भी support करता है :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti**, **Europe's #1** ethical hacking और **bug bounty platform** है।

**Bug bounty tip**: **Intigriti** के लिए **sign up** करें, यह **hackers द्वारा hackers के लिए बनाया गया premium bug bounty platform** है! आज ही [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) पर हमारे साथ जुड़ें और **$100,000** तक की bounties कमाना शुरू करें!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security **engineering-first, hands-on lab approach** के साथ **practical AI Security training** प्रदान करता है। हमारे courses security engineers, AppSec professionals और उन developers के लिए बनाए गए हैं जो **वास्तविक AI/LLM-powered applications को build, break और secure करना चाहते हैं**।

**AI Security Certification** real-world skills पर केंद्रित है, जिनमें शामिल हैं:
- LLM और AI-powered applications को secure करना
- AI systems के लिए threat modeling
- Embeddings, vector databases और RAG security
- LLM attacks, abuse scenarios और practical defenses
- Secure design patterns और deployment considerations

सभी courses **on-demand**, **lab-driven** हैं और केवल theory के बजाय **real-world security tradeoffs** के आधार पर design किए गए हैं।

👉 AI Security course के बारे में अधिक जानकारी:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** **search engine results तक पहुंचने** के लिए fast और आसान real-time APIs प्रदान करता है। वे search engines को scrape करते हैं, proxies संभालते हैं, captchas solve करते हैं और आपके लिए सभी rich structured data parse करते हैं।

SerpApi के किसी plan की subscription में अलग-अलग search engines को scrape करने के लिए 50 से अधिक APIs का access शामिल है, जिनमें Google, Bing, Baidu, Yahoo, Yandex और अन्य शामिल हैं।\
अन्य providers के विपरीत, **SerpApi केवल organic results scrape नहीं करता**। SerpApi responses में लगातार सभी ads, inline images और videos, knowledge graphs तथा search results में मौजूद अन्य elements और features शामिल होते हैं।

**Apple, Shopify और GrubHub** SerpApi के वर्तमान customers में शामिल हैं।\
अधिक जानकारी के लिए उनका [**blog**](https://serpapi.com/blog/)** देखें,** या उनके [**playground**](https://serpapi.com/playground) में कोई example आज़माएं।**\
आप [**यहां**](https://serpapi.com/users/sign_up) **free account create** कर सकते हैं।**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** आपको offensive mobile और AI security की training active researchers द्वारा देता है – यही team CVE writeups और Black Hat, HITB तथा Zer0con में talks के पीछे है। Courses self-paced हैं, real targets पर labs के आसपास बनाए गए हैं और hands-on certification द्वारा समर्थित हैं।

Catalog में दो tracks हैं:

**Mobile Security** – app layer से लेकर नीचे तक iOS और Android: Ghidra और LLDB के साथ reverse engineering, ARM64 exploitation, kernel internals और modern mitigations (PAC, MTE, SELinux), jailbreak और rooting mechanics।

**AI Security** – इस field को कवर करने वाले दो complete courses। Practical AI Security में बताया जाता है कि LLMs, RAG pipelines, AI agents और MCP कैसे काम करते हैं तथा उन्हें attack और defend कैसे किया जाए। Advanced AI Security frontier पर build-heavy है: Garak और PyRIT के साथ बड़े scale पर AI systems की red teaming, MCP servers का exploitation, model backdoors को plant और detect करना तथा Apple Silicon पर fine-tuning attacks और defenses।

Courses और certifications:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** एक AI-powered security platform है, जो attackers से पहले exploitable vulnerabilities ढूंढता है।

**Code security tip**: NaxusAI के लिए sign up करें, यह developers और security teams के लिए बनाया गया smart vulnerability monitoring platform है! आज ही हमारे साथ जुड़ें और **real security risks के production तक पहुंचने से पहले उन्हें detect, validate और fix करने के लिए AI का उपयोग शुरू करें**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) **Amsterdam** में स्थित एक professional cybersecurity company है, जो **modern** approach के साथ **offensive-security services** प्रदान करके **दुनियाभर** के businesses को नवीनतम cybersecurity threats से **protect करने में मदद करती है**।

WebSec Amsterdam और Wyoming में offices वाली एक international security company है। वे **all-in-one security services** प्रदान करते हैं, जिसका अर्थ है कि वे सब कुछ करते हैं; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing और बहुत कुछ।

WebSec की एक और अच्छी बात यह है कि industry average के विपरीत WebSec को **अपनी skills पर बहुत confidence है**, इतना कि वे **best quality results की guarantee देते हैं**। उनकी website पर लिखा है: "**If we can't hack it, You don't pay it!**"। अधिक जानकारी के लिए उनकी [**website**](https://websec.net/en/) और [**blog**](https://websec.net/blog/) देखें!

उपरोक्त के अलावा WebSec **HackTricks का committed supporter** भी है।

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) industry experts द्वारा बनाए और संचालित effective cybersecurity training को develop और deliver करता है। उनके programs theory से आगे जाकर teams को गहरी understanding और actionable skills से equip करते हैं तथा ऐसे custom environments का उपयोग करते हैं जो real-world threats को reflect करते हैं। Custom training inquiries के लिए हमसे [**यहां**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) संपर्क करें।

**उनकी training को अलग बनाने वाली बातें:**
* Custom-built content और labs
* Top-tier tools और platforms द्वारा समर्थित
* Practitioners द्वारा design और teach किया गया

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions **Education** और **FinTech** institutions के लिए specialized cybersecurity services प्रदान करता है, जिसमें **penetration testing, cloud security assessments** और **compliance readiness** (SOC 2, PCI-DSS, NIST) पर focus किया जाता है। हमारी team में **OSCP और CISSP
certified professionals** शामिल हैं, जो हर engagement में गहरी technical expertise और industry-standard insight लाते हैं।

हम **manual, intelligence-driven testing** के साथ automated scans से आगे जाकर high-stakes environments के लिए tailored solutions प्रदान करते हैं। Student records को secure करने से लेकर financial transactions को protect करने तक, हम organizations को सबसे महत्वपूर्ण चीज़ों की रक्षा करने में सहायता करते हैं।

_“A quality defense requires knowing the offense, we provide security through understanding.”_

हमारे [**blog**](https://www.lasttowersolutions.com/blog) पर जाकर cybersecurity में नवीनतम जानकारी से अवगत और up to date रहें।

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE DevOps, DevSecOps और developers को Kubernetes clusters को efficiently manage, monitor और secure करने में सक्षम बनाता है। हमारे AI-driven insights, advanced security framework और intuitive CloudMaps GUI का लाभ उठाकर अपने clusters को visualize करें, उनकी स्थिति समझें और confidence के साथ action लें।

इसके अलावा, K8Studio **सभी major kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift और अन्य) के साथ **compatible** है।

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## License & Disclaimer

इन्हें यहां देखें:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
