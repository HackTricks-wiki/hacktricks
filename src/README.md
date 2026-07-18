# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Alama za Hacktricks na muundo wa mwendo wa_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Endesha HackTricks Kwenye Kompyuta Yako
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
Nakala yako ya ndani ya HackTricks **itapatikana kwenye [http://localhost:3337](http://localhost:3337)** baada ya <dakika 5 (inahitajika kuunda kitabu, kuwa mvumilivu).

Vinginevyo, ikiwa una Docker Compose unaweza tu kuendesha yafuatayo kutoka kwenye mzizi wa repo:
```bash
docker compose up
```
Hii hutumia `docker-compose.yml` iliyojumuishwa kuhudumia checkout yako ya ndani kwenye [http://localhost:3337](http://localhost:3337) ikiwa na live reload.

## Washirika wa HackTricks

---

## Marafiki wa HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ni kampuni bora ya cybersecurity yenye kauli mbiu **HACK THE UNHACKABLE**. Wanafanya utafiti wao wenyewe na kutengeneza hacking tools zao wenyewe ili **kutoa huduma kadhaa muhimu za cybersecurity** kama vile pentesting, Red teams na training.

Unaweza kusoma **blog** yao kwenye [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** pia inaunga mkono miradi ya open source ya cybersecurity kama HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** ni **ethical hacking na bug bounty platform nambari 1 barani Ulaya.**

**Ushauri wa bug bounty**: **jisajili** kwenye **Intigriti**, premium **bug bounty platform iliyoundwa na hackers, kwa ajili ya hackers**! Jiunge nasi kwenye [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na uanze kupata bounties za hadi **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security hutoa **AI Security training ya vitendo** kwa kutumia **engineering-first, hands-on lab approach**. Kozi zetu zimeundwa kwa ajili ya security engineers, wataalamu wa AppSec, na developers wanaotaka **kujenga, kuvunja, na kulinda applications halisi zinazotumia AI/LLM**.

**AI Security Certification** inalenga skills za ulimwengu halisi, zikiwemo:
- Kulinda applications zinazotumia LLM na AI
- Threat modeling kwa AI systems
- Embeddings, vector databases, na RAG security
- LLM attacks, abuse scenarios, na practical defenses
- Secure design patterns na deployment considerations

Kozi zote ni **on-demand**, **lab-driven**, na zimeundwa kulingana na **real-world security tradeoffs**, si theory pekee.

👉 Maelezo zaidi kuhusu AI Security course:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** hutoa APIs za haraka na rahisi za wakati halisi ili **kufikia matokeo ya search engine**. Wanascrape search engines, hushughulikia proxies, hutatua captchas, na kukupangia data yote tajiri yenye muundo.

Usajili wa mojawapo ya mipango ya SerpApi unajumuisha ufikiaji wa APIs zaidi ya 50 tofauti za kuscrape search engines mbalimbali, zikiwemo Google, Bing, Baidu, Yahoo, Yandex, na nyinginezo.\
Tofauti na providers wengine, **SerpApi haiscrape tu organic results**. Majibu ya SerpApi mara kwa mara hujumuisha ads zote, inline images na videos, knowledge graphs, pamoja na vipengele vingine vinavyopatikana kwenye search results.

Wateja wa sasa wa SerpApi wanajumuisha **Apple, Shopify, na GrubHub**.\
Kwa maelezo zaidi tembelea [**blog**](https://serpapi.com/blog/)**,** au jaribu mfano kwenye [**playground**](https://serpapi.com/playground)**.**\
Unaweza **kutengeneza akaunti ya bure** [**hapa**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** inakufundisha offensive mobile na AI security, ikifundishwa na researchers wanaofanya kazi – timu ileile iliyo nyuma ya CVE writeups na talks katika Black Hat, HITB, na Zer0con. Kozi ni za kujifunza kwa kasi yako mwenyewe, zimejengwa kuzunguka labs kwenye targets halisi, na zinaungwa mkono na hands-on certification.

Catalog ina tracks mbili:

**Mobile Security** – iOS na Android kuanzia app layer hadi chini zaidi: reverse engineering kwa kutumia Ghidra na LLDB, ARM64 exploitation, kernel internals na modern mitigations (PAC, MTE, SELinux), jailbreak na rooting mechanics.

**AI Security** – kozi mbili kamili zinazohusu eneo hili. Practical AI Security inaeleza jinsi LLMs, RAG pipelines, AI agents na MCP zinavyofanya kazi, na jinsi ya kuzishambulia na kuzilinda. Advanced AI Security inalenga sana ujenzi katika frontier: red teaming AI systems kwa kiwango kikubwa kwa kutumia Garak na PyRIT, kutumia vibaya MCP servers, kupanda na kugundua model backdoors, pamoja na fine-tuning attacks na defenses kwenye Apple Silicon.

Kozi na certifications:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** ni security platform inayoendeshwa na AI ya kutafuta vulnerabilities zinazoweza kutumiwa kabla attackers hawajazigundua.

**Ushauri wa Code security**: jisajili kwenye NaxusAI, smart vulnerability monitoring platform iliyoundwa kwa developers na security teams! Jiunge nasi leo na uanze kutumia AI kwa **kugundua, kuthibitisha, na kurekebisha security risks halisi kabla hazijafika production**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) ni kampuni ya kitaalamu ya cybersecurity yenye makao yake **Amsterdam**, inayosaidia **kulinda** biashara **duniani kote** dhidi ya cybersecurity threats za hivi karibuni kwa kutoa **offensive-security services** kwa mtazamo **wa kisasa**.

WebSec ni kampuni ya kimataifa ya security yenye ofisi Amsterdam na Wyoming. Wanatoa **all-in-one security services**, kumaanisha kwamba wanafanya kila kitu; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing na mengi zaidi.

Jambo jingine zuri kuhusu WebSec ni kwamba, tofauti na wastani wa sekta, WebSec **inajiamini sana katika skills zao**, kiasi kwamba **wanahakikisha matokeo yenye ubora bora**. Kwenye website yao wanasema "**If we can't hack it, You don't pay it!**". Kwa maelezo zaidi angalia [**website**](https://websec.net/en/) na [**blog**](https://websec.net/blog/) yao!

Mbali na hayo, WebSec pia ni **mfuasi aliyejitolea wa HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Imeundwa kwa ajili ya field. Imejengwa kukuzingatia wewe.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) hutengeneza na kutoa cybersecurity training yenye ufanisi, iliyoundwa na kuongozwa na
industry experts. Programs zao zinaenda zaidi ya theory ili kuzipa teams
uelewa wa kina na skills zinazoweza kutumika, kwa kutumia custom environments zinazoakisi
threats za ulimwengu halisi. Kwa maombi ya custom training, wasiliana nasi [**hapa**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Kinachotofautisha training yao:**
* Content na labs zilizotengenezwa maalum
* Inaungwa mkono na tools na platforms za kiwango cha juu
* Imeundwa na kufundishwa na practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions hutoa huduma maalum za cybersecurity kwa taasisi za **Education** na **FinTech**, kwa kuzingatia **penetration testing, cloud security assessments**, na
**compliance readiness** (SOC 2, PCI-DSS, NIST). Timu yetu inajumuisha wataalamu **waliothibitishwa na OSCP na CISSP**, wakileta utaalamu wa kina wa kiufundi na uelewa unaoendana na viwango vya sekta katika kila engagement.

Tunapita zaidi ya automated scans kwa kutumia **manual, intelligence-driven testing** iliyolengwa kwa mazingira yenye hatari kubwa. Kuanzia kulinda student records hadi kulinda financial transactions,
tunasaidia mashirika kutetea vitu muhimu zaidi.

_“Ulinzi bora unahitaji kujua offense, tunatoa security kupitia uelewa.”_

Endelea kupata taarifa na kusasishwa kuhusu cybersecurity ya hivi karibuni kwa kutembelea [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE huwawezesha DevOps, DevSecOps, na developers kusimamia, kufuatilia, na kulinda Kubernetes clusters kwa ufanisi. Tumia AI-driven insights zetu, advanced security framework, na intuitive CloudMaps GUI ili kuvisualize clusters zako, kuelewa hali yake, na kuchukua hatua kwa ujasiri.

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
