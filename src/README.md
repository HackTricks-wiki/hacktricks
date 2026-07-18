# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logo za HackTricks na motion design na_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Endesha HackTricks Kwenye Kompyuta Yako Locally
```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks

# Select the language you want to use
export HT_LANG="master" # Leave master for English
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
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
Nakala yako ya ndani ya HackTricks itapatikana **kwenye [http://localhost:3337](http://localhost:3337)** baada ya <5 minutes (inahitaji kujenga kitabu, kuwa mvumilivu).

Vinginevyo, ikiwa una Docker Compose, unaweza kuendesha yafuatayo kutoka kwenye mzizi wa repo:
```bash
docker compose up
```
Hii hutumia `docker-compose.yml` iliyojumuishwa kuhudumia branch iliyochaguliwa kwa sasa kwenye host kupitia [http://localhost:3337](http://localhost:3337), ikiwa na live reload. Ili kubadilisha lugha unapotumia Compose, chagua branch ya lugha unayotaka kabla ya kuanzisha service.

## Washirika wa HackTricks

---

## Marafiki wa HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ni kampuni bora ya cybersecurity yenye kauli mbiu **HACK THE UNHACKABLE**. Hufanya utafiti wao wenyewe na hutengeneza hacking tools zao wenyewe ili **kutoa huduma kadhaa muhimu za cybersecurity** kama vile pentesting, Red teams na training.

Unaweza kuangalia **blog** yao kwenye [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** pia huunga mkono miradi ya open source ya cybersecurity kama HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** ni **nambari 1 barani Ulaya** katika ethical hacking na **bug bounty platform.**

**Bug bounty tip**: **jisajili** kwenye **Intigriti**, **bug bounty platform ya kiwango cha juu iliyoundwa na hackers, kwa ajili ya hackers**! Jiunge nasi kupitia [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na uanze kupata zawadi za hadi **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security hutoa **practical AI Security training** kwa kutumia **engineering-first, hands-on lab approach**. Kozi zetu zimeundwa kwa ajili ya security engineers, wataalamu wa AppSec, na developers wanaotaka **kujenga, kuvunja, na kulinda real AI/LLM-powered applications**.

**AI Security Certification** inalenga ujuzi wa ulimwengu halisi, ikijumuisha:
- Kulinda LLM na AI-powered applications
- Threat modeling kwa AI systems
- Embeddings, vector databases, na RAG security
- LLM attacks, abuse scenarios, na practical defenses
- Secure design patterns na deployment considerations

Kozi zote ni **on-demand**, **lab-driven**, na zimeundwa kuzingatia **real-world security tradeoffs**, si theory pekee.

👉 Maelezo zaidi kuhusu AI Security course:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** hutoa APIs za haraka na rahisi za wakati halisi ili **kufikia search engine results**. Hufanya scraping ya search engines, hushughulikia proxies, hutatua captchas, na kuchanganua structured data yote kwa niaba yako.

Usajili wa mojawapo ya mipango ya SerpApi unajumuisha ufikiaji wa APIs zaidi ya 50 tofauti za kufanya scraping ya search engines mbalimbali, zikiwemo Google, Bing, Baidu, Yahoo, Yandex, na nyinginezo.\
Tofauti na providers wengine, **SerpApi haifanyi scraping ya organic results pekee**. Majibu ya SerpApi hujumuisha kwa uthabiti ads zote, inline images na videos, knowledge graphs, pamoja na vipengele vingine vilivyopo kwenye search results.

Wateja wa sasa wa SerpApi wanajumuisha **Apple, Shopify, na GrubHub**.\
Kwa maelezo zaidi, tembelea [**blog**](https://serpapi.com/blog/)**,** au jaribu mfano kwenye [**playground**](https://serpapi.com/playground)**.**\
Unaweza **kuunda akaunti ya bure** [**hapa**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** hukufundisha offensive mobile na AI security, ikifundishwa na active researchers – timu hiyo hiyo iliyo nyuma ya CVE writeups na talks katika Black Hat, HITB, na Zer0con. Kozi zinafuatwa kwa kasi yako mwenyewe, zimejengwa kuzunguka labs kwenye real targets, na zinaungwa mkono na hands-on certification.

Catalog ina tracks mbili:

**Mobile Security** – iOS na Android kuanzia app layer hadi chini: reverse engineering kwa kutumia Ghidra na LLDB, ARM64 exploitation, kernel internals na modern mitigations (PAC, MTE, SELinux), jailbreak na rooting mechanics.

**AI Security** – kozi mbili kamili zinazohusu eneo hili. Practical AI Security inaeleza jinsi LLMs, RAG pipelines, AI agents na MCP zinavyofanya kazi, na jinsi ya kuzishambulia na kuzilinda. Advanced AI Security inaenda kwa undani zaidi katika frontier: red teaming AI systems kwa kiwango kikubwa kwa kutumia Garak na PyRIT, exploiting MCP servers, kupanda na kugundua model backdoors, pamoja na fine-tuning attacks na defenses kwenye Apple Silicon.

Kozi na certifications:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** ni AI-powered security platform ya kutafuta exploitable vulnerabilities kabla attackers hawajazipata.

**Code security tip**: jisajili kwenye NaxusAI, smart vulnerability monitoring platform iliyoundwa kwa developers na security teams! Jiunge nasi leo na uanze kutumia AI kwa **kugundua, kuthibitisha, na kurekebisha security risks halisi kabla hazijafika production**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) ni kampuni ya kitaalamu ya cybersecurity yenye makao yake **Amsterdam**, inayosaidia **kulinda** biashara **duniani kote** dhidi ya cybersecurity threats za hivi karibuni kwa kutoa **offensive-security services** kwa kutumia mbinu **ya kisasa**.

WebSec ni kampuni ya kimataifa ya security yenye offices huko Amsterdam na Wyoming. Hutoa **all-in-one security services**, ikimaanisha kuwa hufanya kila kitu; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing na mengine mengi.

Jambo lingine zuri kuhusu WebSec ni kwamba, tofauti na wastani wa industry, WebSec **ina imani kubwa na ujuzi wake**, kiasi kwamba **inahakikisha matokeo yenye ubora bora zaidi**. Tovuti yao inasema "**If we can't hack it, You don't pay it!**". Kwa maelezo zaidi, tembelea [**website**](https://websec.net/en/) na [**blog**](https://websec.net/blog/) yao!

Mbali na hayo, WebSec pia ni **mfuasi thabiti wa HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) hutengeneza na kutoa cybersecurity training yenye ufanisi, iliyoundwa na kuongozwa na
industry experts. Programs zao huenda zaidi ya theory ili kuzipa teams
uelewa wa kina na skills zinazoweza kutumika, kwa kutumia custom environments zinazoakisi
real-world threats. Kwa maombi ya custom training, wasiliana nasi [**hapa**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**What sets their training apart:**
* Custom-built content and labs
* Inaungwa mkono na tools na platforms za kiwango cha juu
* Imeundwa na kufundishwa na practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions hutoa specialized cybersecurity services kwa taasisi za **Education** na **FinTech**, ikilenga **penetration testing, cloud security assessments**, na **compliance readiness** (SOC 2, PCI-DSS, NIST). Timu yetu inajumuisha **OSCP na CISSP
certified professionals**, wanaoleta technical expertise ya kina na maarifa yanayokubalika kwenye industry katika kila engagement.

Tunazidi automated scans kwa kutumia **manual, intelligence-driven testing** iliyolengwa kwa mazingira yenye hatari kubwa. Kuanzia kulinda student records hadi kulinda financial transactions, tunasaidia organizations kutetea mambo muhimu zaidi.

_“Ulinzi bora unahitaji kujua offense, tunatoa security kupitia uelewa.”_

Endelea kupata taarifa na kusasishwa kuhusu cybersecurity ya hivi karibuni kwa kutembelea [**blog**](https://www.lasttowersolutions.com/blog) yetu.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE huwawezesha DevOps, DevSecOps, na developers kusimamia, kufuatilia, na kulinda Kubernetes clusters kwa ufanisi. Tumia AI-driven insights zetu, advanced security framework, na intuitive CloudMaps GUI ili kuonyesha clusters zako, kuelewa hali yake, na kuchukua hatua kwa kujiamini.

Zaidi ya hayo, K8Studio **inaoana na kubernetes distributions zote kuu** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift na nyinginezo).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## License & Disclaimer

Zikague hapa:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
