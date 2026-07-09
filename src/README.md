# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks लोगो और motion design_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_द्वारा।_

### Run HackTricks Locally
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
आपकी local copy of HackTricks **5 मिनट से कम समय में [http://localhost:3337](http://localhost:3337)** पर उपलब्ध होगी (इसे book build करनी होती है, धैर्य रखें)।

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) एक बेहतरीन cybersecurity कंपनी है जिसका slogan है **HACK THE UNHACKABLE**। वे अपना research करते हैं और अपने hacking tools विकसित करते हैं ताकि **pentesting, Red teams और training** जैसी कई valuable cybersecurity services **offer** कर सकें।

आप उनका **blog** [**https://blog.stmcyber.com**](https://blog.stmcyber.com) पर देख सकते हैं।

**STM Cyber** HackTricks जैसे cybersecurity open source projects को भी support करता है :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** **Europe का #1** ethical hacking और **bug bounty platform** है।

**Bug bounty tip**: **Intigriti** के लिए **sign up** करें, यह hackers द्वारा hackers के लिए बनाया गया premium **bug bounty platform** है! आज ही [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) पर जुड़ें, और **$100,000** तक के bounties कमाना शुरू करें!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

अनुभवी hackers और bug bounty hunters से संवाद करने के लिए [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server से जुड़ें!

- **Hacking Insights:** hacking के रोमांच और चुनौतियों में गहराई से जाने वाली content के साथ engage करें
- **Real-Time Hack News:** real-time news और insights के जरिए तेज़-तर्रार hacking world से अपडेट रहें
- **Latest Announcements:** नए bug bounties लॉन्च होने और महत्वपूर्ण platform updates की जानकारी रखें

**[**Discord**](https://discord.com/invite/N3FrSbmwdy) पर हमारे साथ जुड़ें और आज ही top hackers के साथ collaboration शुरू करें!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security **practical AI Security training** देता है, जो **engineering-first, hands-on lab approach** पर आधारित है। हमारे courses security engineers, AppSec professionals, और developers के लिए बनाए गए हैं जो **real AI/LLM-powered applications को build, break, और secure** करना चाहते हैं।

**AI Security Certification** इन वास्तविक-world skills पर केंद्रित है, जिनमें शामिल हैं:
- LLM और AI-powered applications को secure करना
- AI systems के लिए threat modeling
- Embeddings, vector databases, और RAG security
- LLM attacks, abuse scenarios, और practical defenses
- Secure design patterns और deployment considerations

सभी courses **on-demand**, **lab-driven** हैं, और केवल theory नहीं बल्कि **real-world security tradeoffs** के आधार पर डिज़ाइन किए गए हैं।

👉 AI Security course पर अधिक जानकारी:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** search engine results को **access** करने के लिए तेज़ और आसान real-time APIs प्रदान करता है। वे search engines scrape करते हैं, proxies handle करते हैं, captchas solve करते हैं, और आपके लिए सभी rich structured data parse करते हैं।

SerpApi की किसी plan की subscription में Google, Bing, Baidu, Yahoo, Yandex, और अन्य सहित अलग-अलग search engines को scrape करने के लिए 50 से अधिक APIs का access शामिल है।\
दूसरे providers के विपरीत, **SerpApi सिर्फ organic results scrape नहीं करता**। SerpApi responses में लगातार सभी ads, inline images और videos, knowledge graphs, और search results में मौजूद अन्य elements और features शामिल होते हैं।

SerpApi के current customers में **Apple, Shopify, और GrubHub** शामिल हैं।\
अधिक जानकारी के लिए उनका [**blog**](https://serpapi.com/blog/)**,** देखें, या उनके [**playground**](https://serpapi.com/playground)**.** में एक example आज़माएँ।\
आप [**here**](https://serpapi.com/users/sign_up)**.** पर **free account** बना सकते हैं।

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** आपको offensive mobile और AI security में प्रशिक्षित करता है, जिसे active researchers पढ़ाते हैं – वही team जो CVE writeups और Black Hat, HITB, और Zer0con की talks के पीछे है। Courses self-paced हैं, real targets पर labs के साथ बनाए गए हैं, और hands-on certification द्वारा समर्थित हैं।

Catalog दो tracks में चलता है:

**Mobile Security** – iOS और Android को app layer से लेकर नीचे तक: Ghidra और LLDB के साथ reverse engineering, ARM64 exploitation, kernel internals और modern mitigations (PAC, MTE, SELinux), jailbreak और rooting mechanics.

**AI Security** – इस field को कवर करने वाले दो full courses। Practical AI Security बताता है कि LLMs, RAG pipelines, AI agents और MCP कैसे काम करते हैं, और उन्हें कैसे attack और defend किया जाए। Advanced AI Security frontier पर build-heavy है: Garak और PyRIT के साथ scale पर AI systems का red teaming, MCP servers exploit करना, model backdoors लगाना और detect करना, और Apple Silicon पर fine-tuning attacks और defenses.

Courses और certifications:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** एक AI-powered security platform है जो attackers से पहले exploitable vulnerabilities ढूँढता है।

**Code security tip**: NaxusAI के लिए sign up करें, यह developers और security teams के लिए बना smart vulnerability monitoring platform है! आज ही जुड़ें और production तक पहुँचने से पहले **real security risks का detecting, validating, and fixing** करने के लिए AI का उपयोग शुरू करें!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) **Amsterdam** आधारित एक professional cybersecurity company है, जो **modern** approach के साथ **offensive-security services** प्रदान करके **दुनिया भर** के businesses को latest cybersecurity threats से **protecting** में मदद करती है।

WebSec Amsterdam और Wyoming में offices वाली एक intenational security company है। वे **all-in-one security services** देते हैं, यानी वे सब कुछ करते हैं; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing और बहुत कुछ।

WebSec की एक और अच्छी बात यह है कि industry average के विपरीत WebSec अपनी skills में **बहुत confident** है, और इतनी हद तक कि वे **best quality results की guarantee** देते हैं, उनकी website पर लिखा है "**If we can't hack it, You don't pay it!**". अधिक जानकारी के लिए उनकी [**website**](https://websec.net/en/) और [**blog**](https://websec.net/blog/) देखें!

ऊपर के अलावा WebSec HackTricks का **committed supporter** भी है।

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) industry experts द्वारा निर्मित और संचालित effective cybersecurity training विकसित और deliver करता है। उनके programs theory से आगे जाकर teams को deep understanding और actionable skills देते हैं, custom environments का उपयोग करके जो real-world threats को reflect करते हैं। Custom training inquiries के लिए, हमसे [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) संपर्क करें।

**What sets their training apart:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions **Education** और **FinTech**
institutions के लिए specialized cybersecurity services प्रदान करता है, जिनका focus **penetration testing, cloud security assessments**, और
**compliance readiness** (SOC 2, PCI-DSS, NIST) पर है। हमारी team में **OSCP और CISSP
certified professionals** शामिल हैं, जो हर engagement में गहरी technical expertise और industry-standard insight लाते हैं।

हम **manual, intelligence-driven testing** के साथ automated scans से आगे जाते हैं, जो
high-stakes environments के लिए tailored है। Student records को secure करने से लेकर financial transactions को protect करने तक,
हम organizations को महत्वपूर्ण चीज़ों की रक्षा करने में मदद करते हैं।

_“A quality defense requires knowing the offense, we provide security through understanding.”_

हमारी [**blog**](https://www.lasttowersolutions.com/blog) पर जाकर cybersecurity की latest जानकारी से अपडेट रहें।

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE DevOps, DevSecOps, और developers को Kubernetes clusters को efficiently manage, monitor, और secure करने में सक्षम बनाता है। हमारी AI-driven insights, advanced security framework, और intuitive CloudMaps GUI का लाभ उठाकर आप अपने clusters को visualize कर सकते हैं, उनकी state समझ सकते हैं, और confidence के साथ action ले सकते हैं।

इसके अलावा, K8Studio **सभी प्रमुख kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift और more) के साथ compatible है।

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
