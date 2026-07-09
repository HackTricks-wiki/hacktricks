# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logo za Hacktricks na muundo wa mwendo na_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Endesha HackTricks Kwenye Kompyuta ya Ndani
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
Nakili yako ya eneo la HackTricks itapatikana kwenye [http://localhost:3337](http://localhost:3337) baada ya <5 minutes (inahitaji kujenga kitabu, kuwa mvumilivu).

## Washirika wa HackTricks

---

## Marafiki wa HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ni kampuni bora ya cybersecurity ambayo kaulimbiu yake ni **HACK THE UNHACKABLE**. Wanafanya utafiti wao wenyewe na kuendeleza zana zao wenyewe za hacking ili **kutoa huduma kadhaa muhimu za cybersecurity** kama pentesting, Red teams na training.

Unaweza kuangalia **blog** yao katika [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** pia wanaunga mkono miradi ya open source ya cybersecurity kama HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** ni **Europe's #1** ethical hacking na **bug bounty platform.**

**Bug bounty tip**: **jiandikishe** kwa **Intigriti**, **bug bounty platform** ya kiwango cha juu iliyoundwa na hackers, kwa hackers! Jiunge nasi kwenye [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na anza kupata bounties hadi **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security inatoa **mafunzo ya vitendo ya AI Security** yenye mbinu ya **engineering-first, hands-on lab approach**. Kozi zetu zimejengwa kwa ajili ya security engineers, AppSec professionals, na developers wanaotaka **kujenga, kuvunja, na kulinda real AI/LLM-powered applications**.

**AI Security Certification** inalenga ujuzi wa dunia halisi, ikijumuisha:
- Kulinda LLM na AI-powered applications
- Threat modeling kwa AI systems
- Embeddings, vector databases, na RAG security
- LLM attacks, abuse scenarios, na practical defenses
- Secure design patterns na deployment considerations

Kozi zote ni **on-demand**, **lab-driven**, na zimeundwa kuzunguka **real-world security tradeoffs**, si nadharia tu.

👉 Maelezo zaidi kuhusu kozi ya AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** hutoa APIs za haraka na rahisi za real-time ili **kupata results za search engine**. Wanacrawl search engines, kushughulikia proxies, kutatua captchas, na kuchambua rich structured data yote kwa ajili yako.

Subscription ya mojawapo ya plans za SerpApi inajumuisha access kwa zaidi ya APIs 50 tofauti za scraping search engines tofauti, ikiwemo Google, Bing, Baidu, Yahoo, Yandex, na zaidi.\
Tofauti na providers wengine, **SerpApi haichapishi tu organic results**. Majibu ya SerpApi hujumuisha mara kwa mara ads zote, inline images na videos, knowledge graphs, na vipengele vingine vilivyopo kwenye search results.

Wateja wa sasa wa SerpApi ni pamoja na **Apple, Shopify, na GrubHub**.\
Kwa maelezo zaidi angalia [**blog**](https://serpapi.com/blog/)**,** au jaribu mfano katika [**playground**](https://serpapi.com/playground)**.**\
Unaweza **kuunda account ya bure** [**hapa**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** hukufundisha offensive mobile na AI security, ikifundishwa na active researchers – timu ile ile nyuma ya CVE writeups na mazungumzo katika Black Hat, HITB, na Zer0con. Kozi ni za kujifunza kwa kasi yako mwenyewe, zimejengwa kuzunguka labs kwenye real targets, na zinaungwa mkono na hands-on certification.

Katalogi ina njia mbili:

**Mobile Security** – iOS na Android kutoka app layer hadi chini: reverse engineering kwa Ghidra na LLDB, ARM64 exploitation, kernel internals na modern mitigations (PAC, MTE, SELinux), mechanics za jailbreak na rooting.

**AI Security** – kozi mbili kamili zinazoshughulikia field nzima. Practical AI Security inaeleza jinsi LLMs, RAG pipelines, AI agents na MCP zinavyofanya kazi, na jinsi ya kuzipiga na kuzitunza. Advanced AI Security inaingia zaidi kwenye build-heavy frontier: red teaming AI systems kwa kiwango kikubwa na Garak na PyRIT, exploiting MCP servers, kuweka na kugundua model backdoors, na fine-tuning attacks na defenses kwenye Apple Silicon.

Kozi na certifications:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** ni jukwaa la AI-powered security la kutafuta vulnerabilities zinazoweza kutumiwa kabla ya attackers kufanya hivyo.

**Code security tip**: jiandikishe kwa NaxusAI, smart vulnerability monitoring platform iliyojengwa kwa ajili ya developers na security teams! Jiunge nasi leo na anza kutumia AI kwa **kugundua, kuthibitisha, na kurekebisha real security risks kabla hazijafika production**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) ni kampuni ya kitaalamu ya cybersecurity iliyo katika **Amsterdam** ambayo husaidia **kulinda** biashara **duniani kote** dhidi ya vitisho vya hivi karibuni vya cybersecurity kwa kutoa **offensive-security services** kwa mbinu ya **modern**.

WebSec ni kampuni ya usalama ya kimataifa yenye ofisi Amsterdam na Wyoming. Wanatoa **all-in-one security services** ambayo ina maana wanafanya yote; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing na mengi zaidi.

Jambo jingine zuri kuhusu WebSec ni kwamba tofauti na wastani wa tasnia, WebSec ina **imani kubwa sana katika ujuzi wao**, hadi kufikia kiwango cha kwamba **wanahakikisha matokeo bora zaidi**, imeandikwa kwenye website yao "**If we can't hack it, You don't pay it!**". Kwa maelezo zaidi angalia [**website**](https://websec.net/en/) yao na [**blog**](https://websec.net/blog/)!

Mbali na hayo, WebSec pia ni **mchango wa dhati wa HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Imejengwa kwa ajili ya field. Imejengwa kukuzunguka wewe.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) hutengeneza na kutoa mafunzo bora ya cybersecurity yaliyoundwa na kuongozwa na
wataalamu wa industry. Programu zao huenda zaidi ya nadharia ili kuandaa teams kwa ufahamu wa kina
na skills zinazoweza kutumika, kwa kutumia custom environments zinazoakisi real-world
threats. Kwa maswali ya custom training, wasiliana nasi [**hapa**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Kinachotofautisha mafunzo yao:**
* Custom-built content and labs
* Zinaungwa mkono na tools na platforms za kiwango cha juu
* Zimeundwa na kufundishwa na practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions hutoa specialized cybersecurity services kwa taasisi za **Education** na **FinTech**
, kwa kuzingatia **penetration testing, cloud security assessments**, na
**compliance readiness** (SOC 2, PCI-DSS, NIST). Timu yetu inajumuisha wataalamu waliothibitishwa wa **OSCP and CISSP**
, wakileta utaalamu wa kina wa kiufundi na maarifa ya industry-standard kwa
kila engagement.

Tunaenda zaidi ya automated scans kwa **manual, intelligence-driven testing** iliyobinafsishwa kwa
mazingira yenye viwango vya juu. Kuanzia kulinda student records hadi kulinda financial transactions,
tunasaidia organizations kutetea kile kilicho muhimu zaidi.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Endelea kupata taarifa na kuwa updated na latest katika cybersecurity kwa kutembelea [**blog**](https://www.lasttowersolutions.com/blog) yetu.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE huwezesha DevOps, DevSecOps, na developers kusimamia, kufuatilia, na kulinda Kubernetes clusters kwa ufanisi. Tumia AI-driven insights zetu, advanced security framework, na intuitive CloudMaps GUI ili kuonyesha clusters zako, kuelewa hali yake, na kuchukua hatua kwa ujasiri.

Zaidi ya hayo, K8Studio ni **compatible with all major kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## Leseni & Kanusho

Angalia hapa:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Takwimu za Github

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
