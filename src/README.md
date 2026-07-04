# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logo za HackTricks na muundo wa mwendo na_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Endesha HackTricks Kwenye Kompyuta ya Mitaa
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
Your local copy of HackTricks itakuwa **inapatikana katika [http://localhost:3337](http://localhost:3337)** baada ya <5 minutes (inahitaji kujenga kitabu, kuwa na subira).

## Washirika wa HackTricks

---

## Marafiki wa HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ni kampuni nzuri ya cybersecurity ambayo kaulimbiu yake ni **HACK THE UNHACKABLE**. Wanafanya utafiti wao wenyewe na kuunda zana zao wenyewe za hacking ili **kutoa huduma kadhaa muhimu za cybersecurity** kama pentesting, Red teams na mafunzo.

Unaweza kuangalia **blog** yao katika [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** pia wanaunga mkono miradi ya open source ya cybersecurity kama HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** ni **#1 ya Ulaya** kwa ethical hacking na **bug bounty platform.**

**Kidokezo cha bug bounty**: **jisajili** kwa **Intigriti**, **bug bounty platform ya premium iliyoundwa na hackers, kwa hackers**! Jiunge nasi katika [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na anza kupata bounties hadi **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Jiunge na server ya [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) ili kuwasiliana na hackers wenye uzoefu na bug bounty hunters!

- **Hacking Insights:** Shirikiana na maudhui yanayochunguza msisimko na changamoto za hacking
- **Real-Time Hack News:** Endelea kusasishwa na ulimwengu wa hacking unaokwenda kwa kasi kupitia habari na maarifa ya wakati halisi
- **Latest Announcements:** Pata taarifa kuhusu bug bounties mpya zinazozinduliwa na masasisho muhimu ya platform

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na top hackers leo!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security hutoa **mafunzo ya vitendo ya AI Security** kwa mtazamo wa **engineering-first, hands-on lab approach**. Kozi zetu zimejengwa kwa security engineers, AppSec professionals, na developers wanaotaka **kujenga, kuvunja, na kulinda real AI/LLM-powered applications**.

**AI Security Certification** inalenga ujuzi wa dunia halisi, ikijumuisha:
- Kulinda LLM na AI-powered applications
- Threat modeling kwa AI systems
- Embeddings, vector databases, na usalama wa RAG
- LLM attacks, abuse scenarios, na ulinzi wa vitendo
- Secure design patterns na masuala ya deployment

Kozi zote ni **on-demand**, **lab-driven**, na zimeundwa kuzunguka **real-world security tradeoffs**, si nadharia tu.

👉 Maelezo zaidi kuhusu kozi ya AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** hutoa APIs za haraka na rahisi za wakati halisi ili **kufikia matokeo ya search engine**. Wanascrape search engines, hushughulikia proxies, hutatua captchas, na kuchanganua data zote tajiri zilizopangwa kwa ajili yako.

Usajili wa mojawapo ya plans za SerpApi unajumuisha ufikiaji wa zaidi ya 50 tofauti APIs za kuscrape search engines mbalimbali, ikiwemo Google, Bing, Baidu, Yahoo, Yandex, na zaidi.\
Tofauti na providers wengine, **SerpApi hai-scrape tu organic results**. Responses za SerpApi mara kwa mara hujumuisha ads zote, inline images na videos, knowledge graphs, na vipengele vingine vilivyopo kwenye matokeo ya utafutaji.

Wateja wa sasa wa SerpApi ni pamoja na **Apple, Shopify, na GrubHub**.\
Kwa taarifa zaidi angalia [**blog**](https://serpapi.com/blog/)**,** au jaribu mfano katika [**playground**](https://serpapi.com/playground)**.**\
Unaweza **kuunda akaunti ya bure** [**hapa**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Jifunze technologies na skills zinazohitajika kufanya vulnerability research, penetration testing, na reverse engineering ili kulinda mobile applications na devices. **Miliki usalama wa iOS na Android** kupitia kozi zetu za on-demand na **pata certification**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** ni security platform inayoendeshwa na AI ya kutafuta vulnerabilities vinavyoweza kutumiwa kabla ya attackers kufanya hivyo.

**Kidokezo cha code security**: jisajili kwa NaxusAI, smart vulnerability monitoring platform iliyojengwa kwa developers na security teams! Jiunge nasi leo na anza kutumia AI kwa **kutambua, kuthibitisha, na kurekebisha real security risks kabla hazijafika production**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) ni kampuni ya kitaalamu ya cybersecurity iliyoko **Amsterdam** ambayo husaidia **kulinda** biashara **duniani kote** dhidi ya threats za hivi karibuni za cybersecurity kwa kutoa **offensive-security services** kwa mtazamo wa **modern**.

WebSec ni kampuni ya usalama ya intenational yenye ofisi Amsterdam na Wyoming. Wanatoa **all-in-one security services** ambayo inamaanisha wanafanya yote; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing na mengi zaidi.

Jambo jingine zuri kuhusu WebSec ni kwamba tofauti na wastani wa industry WebSec ina **imani kubwa sana katika skills zao**, kiasi kwamba **wanahakikisha matokeo bora zaidi ya ubora**, kwenye website yao inasema "**If we can't hack it, You don't pay it!**". Kwa taarifa zaidi angalia [**website**](https://websec.net/en/) yao na [**blog**](https://websec.net/blog/)!

Mbali na hayo, WebSec pia ni **mfuasi thabiti wa HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Imejengwa kwa ajili ya field. Imejengwa kuzunguka wewe.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) hutengeneza na kutoa mafunzo bora ya cybersecurity yaliyojengwa na kuongozwa na
wataalamu wa industry. Programu zao huenda zaidi ya nadharia ili kuandaa teams kwa uelewa wa kina
na skills zinazoweza kutumika, kwa kutumia mazingira maalum yanayoakisi threats za dunia halisi. Kwa maombi ya mafunzo maalum, wasiliana nasi [**hapa**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Kinachotofautisha mafunzo yao:**
* Content na labs zilizojengwa maalum
* Zimeungwa mkono na tools na platforms za kiwango cha juu
* Zimeundwa na kufundishwa na practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions hutoa huduma maalum za cybersecurity kwa taasisi za **Education** na **FinTech**
, kwa kuzingatia **penetration testing, cloud security assessments**, na
**compliance readiness** (SOC 2, PCI-DSS, NIST). Timu yetu inajumuisha wataalamu **walioidhinishwa na OSCP na CISSP**, wakileta utaalamu wa kina wa kiufundi na maarifa ya kiwango cha industry katika
kila engagement.

Tunaenda zaidi ya automated scans kwa **manual, intelligence-driven testing** iliyobinafsishwa kwa
mazingira yenye hatari kubwa. Kuanzia kulinda student records hadi kulinda financial transactions,
tunasaidia organizations kulinda kilicho muhimu zaidi.

_“Ulinzi wa ubora unahitaji kujua mashambulizi, tunatoa usalama kupitia uelewa.”_

Endelea kufahamishwa na kusasishwa kuhusu latest katika cybersecurity kwa kutembelea [**blog**](https://www.lasttowersolutions.com/blog) yetu.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE huwawezesha DevOps, DevSecOps, na developers kusimamia, kufuatilia, na kulinda Kubernetes clusters kwa ufanisi. Tumia AI-driven insights zetu, advanced security framework, na intuitive CloudMaps GUI kuonyesha clusters zako, kuelewa hali yake, na kuchukua hatua kwa ujasiri.

Zaidi ya hayo, K8Studio ina **compatibility na all major kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift na zaidi).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## Leseni & Kanusho

Zikague katika:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Takwimu za Github

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
