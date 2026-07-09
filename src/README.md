# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logo za Hacktricks na muundo wa mwendo na_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Endesha HackTricks Kwenye Kifaa cha Mtaa
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

## Washirika wa HackTricks

---

## Marafiki wa HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ni kampuni bora ya usalama wa mtandao ambayo kaulimbiu yake ni **HACK THE UNHACKABLE**. Wanafanya utafiti wao wenyewe na kutengeneza zana zao wenyewe za hacking ili **kutoa huduma kadhaa muhimu za usalama wa mtandao** kama pentesting, Red teams na mafunzo.

Unaweza kuangalia **blog** yao katika [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** pia inasaidia miradi ya open source ya usalama wa mtandao kama HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** ni **jukwaa la #1 la Ulaya** la ethical hacking na **bug bounty platform.**

**Kidokezo cha bug bounty**: **jisajili** kwa **Intigriti**, **bug bounty platform ya hali ya juu iliyoundwa na hackers, kwa hackers**! Jiunge nasi katika [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na anza kupata bounties hadi **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Jiunge na server ya [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) ili kuwasiliana na hackers wenye uzoefu na bug bounty hunters!

- **Hacking Insights:** Shiriki katika maudhui yanayochunguza msisimko na changamoto za hacking
- **Real-Time Hack News:** Endelea kupata habari za wakati halisi kuhusu dunia ya hacking kupitia habari na maarifa ya papo hapo
- **Latest Announcements:** Pata taarifa kuhusu bug bounties mpya zinazoanza na masasisho muhimu ya jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na hackers bora leo!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security hutoa **mafunzo ya vitendo ya AI Security** kwa **mbinu ya uhandisi kwanza, maabara ya vitendo**. Kozi zetu zimejengwa kwa ajili ya wahandisi wa usalama, wataalamu wa AppSec, na watengenezaji wanaotaka **kujenga, kuvunja, na kulinda programu halisi zinazoendeshwa na AI/LLM**.

**AI Security Certification** inalenga ujuzi wa ulimwengu halisi, ikijumuisha:
- Kulinda programu za LLM na AI-powered
- Threat modeling kwa mifumo ya AI
- Embeddings, vector databases, na usalama wa RAG
- LLM attacks, abuse scenarios, na ulinzi wa vitendo
- Miundo salama ya usanifu na masuala ya deployment

Kozi zote ni **kwa mahitaji**, **zinazoendeshwa na maabara**, na zimeundwa kuzunguka **tradeoffs za usalama za ulimwengu halisi**, si nadharia tu.

👉 Maelezo zaidi kuhusu kozi ya AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** hutoa APIs za haraka na rahisi za wakati halisi ili **kupata matokeo ya injini za utafutaji**. Wanascrape injini za utafutaji, hushughulikia proxies, husuluhisha captchas, na kuchanganua rich structured data yote kwa ajili yako.

Usajili wa mojawapo ya mipango ya SerpApi unajumuisha ufikiaji wa zaidi ya APIs 50 tofauti za scraping za injini mbalimbali za utafutaji, ikijumuisha Google, Bing, Baidu, Yahoo, Yandex, na zaidi.\
Tofauti na watoa huduma wengine, **SerpApi hai-scrape tu matokeo ya kikaboni**. Majibu ya SerpApi mara kwa mara hujumuisha matangazo yote, inline images na videos, knowledge graphs, na vipengele vingine vilivyopo katika matokeo ya utafutaji.

Wateja wa sasa wa SerpApi ni pamoja na **Apple, Shopify, na GrubHub**.\
Kwa maelezo zaidi angalia [**blog**](https://serpapi.com/blog/)**,** au jaribu mfano katika [**playground**](https://serpapi.com/playground)**.**\
Unaweza **kuunda akaunti ya bure** [**hapa**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** hukufundisha offensive mobile na AI security, ikifundishwa na watafiti hai – timu ile ile iliyo nyuma ya CVE writeups na mazungumzo kwenye Black Hat, HITB, na Zer0con. Kozi ni za kujiongoza mwenyewe, zimejengwa kuzunguka maabara kwenye targets halisi, na zinaungwa mkono na certification ya vitendo.

Katalogi ina tracks mbili:

**Mobile Security** – iOS na Android kutoka layer ya app hadi chini: reverse engineering kwa Ghidra na LLDB, ARM64 exploitation, kernel internals na modern mitigations (PAC, MTE, SELinux), jailbreak na rooting mechanics.

**AI Security** – kozi mbili kamili zinazogusa uwanja mzima. Practical AI Security inashughulikia jinsi LLMs, RAG pipelines, AI agents na MCP zinavyofanya kazi, na jinsi ya kuzishambulia na kuzilinda. Advanced AI Security inaenda zaidi upande wa ujenzi kwenye frontier: red teaming AI systems kwa kiwango kikubwa kwa kutumia Garak na PyRIT, exploiting MCP servers, kupanda na kugundua model backdoors, na fine-tuning attacks na defenses kwenye Apple Silicon.

Kozi na certifications:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** ni jukwaa la usalama linaloendeshwa na AI ili kupata vulnerabilities zinazoweza kutumika kabla ya washambuliaji kufanya hivyo.

**Kidokezo cha code security**: jisajili kwa NaxusAI, jukwaa janja la ufuatiliaji wa vulnerabilities lililojengwa kwa ajili ya developers na security teams! Jiunge nasi leo na anza kutumia AI kwa **kutambua, kuthibitisha, na kurekebisha hatari halisi za usalama kabla hazijafika production**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) ni kampuni ya kitaalamu ya usalama wa mtandao iliyoko **Amsterdam** ambayo husaidia **kulinda** biashara **duniani kote** dhidi ya vitisho vipya zaidi vya usalama wa mtandao kwa kutoa **huduma za offensive-security** kwa mbinu ya **kisasa**.

WebSec ni kampuni ya usalama ya kimataifa yenye ofisi Amsterdam na Wyoming. Wanatoa **huduma za usalama za yote kwa pamoja** ambayo inamaanisha wanafanya kila kitu; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing na mengi zaidi.

Jambo jingine zuri kuhusu WebSec ni kwamba tofauti na wastani wa sekta WebSec ina **uhakika mkubwa sana katika ujuzi wao**, hadi kufikia kiwango kwamba **wanahakikisha matokeo bora zaidi**, tovuti yao inasema "**If we can't hack it, You don't pay it!**". Kwa taarifa zaidi angalia [**website**](https://websec.net/en/) na [**blog**](https://websec.net/blog/) zao!

Mbali na hayo hapo juu WebSec pia ni **mshirika mwenye kujitolea wa HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Imejengwa kwa ajili ya uwanja. Imejengwa kuzunguka wewe.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) hutengeneza na kutoa mafunzo yenye ufanisi ya usalama wa mtandao yaliyojengwa na kuongozwa na
wataalamu wa sekta. Programu zao huenda zaidi ya nadharia ili kuandaa timu kwa
uelewa wa kina na ujuzi unaoweza kutekelezwa, kwa kutumia mazingira maalum yanayoakisi vitisho vya
ulimwengu halisi. Kwa maulizo ya mafunzo maalum, wasiliana nasi [**hapa**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Kinachotofautisha mafunzo yao:**
* Maudhui na maabara zilizojengwa maalum
* Zinaungwa mkono na zana na majukwaa ya kiwango cha juu
* Zimeundwa na kufundishwa na wataalamu wanaofanya kazi moja kwa moja

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions hutoa huduma maalum za usalama wa mtandao kwa taasisi za **Elimu** na **FinTech**,
kwa lengo la **penetration testing, cloud security assessments**, na
**compliance readiness** (SOC 2, PCI-DSS, NIST). Timu yetu inajumuisha wataalamu waliothibitishwa wa **OSCP na CISSP**,
ikileta utaalamu wa kina wa kiufundi na ufahamu wa kiwango cha sekta kwa
kila ushirikiano.

Tunaenda zaidi ya scans za kiotomatiki kwa **manual, intelligence-driven testing** iliyolengwa kwa
mazingira yenye hatari kubwa. Kuanzia kulinda rekodi za wanafunzi hadi kulinda miamala ya kifedha,
tunasaidia mashirika kutetea kilicho muhimu zaidi.

_“Ulinzi wa ubora unahitaji kujua mashambulizi, tunatoa usalama kupitia uelewa.”_

Endelea kupata habari na masasisho ya hivi karibuni kuhusu usalama wa mtandao kwa kutembelea [**blog**](https://www.lasttowersolutions.com/blog) yetu.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE huwawezesha DevOps, DevSecOps, na developers kusimamia, kufuatilia, na kulinda Kubernetes clusters kwa ufanisi. Tumia maarifa yetu yanayoendeshwa na AI, advanced security framework, na CloudMaps GUI angavu ili kuona clusters zako, kuelewa hali yake, na kuchukua hatua kwa ujasiri.

Zaidi ya hayo, K8Studio ina **utangamano na usambazaji wote wakuu wa kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift na zaidi).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## Leseni & Kanusho

Angalia katika:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Takwimu za Github

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
