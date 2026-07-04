# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logos za Hacktricks na muundo wa mwendo na_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Endesha HackTricks Kwenye Mashine Yako Mwenyewe
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

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ni kampuni bora ya cybersecurity ambayo kauli mbiu yake ni **HACK THE UNHACKABLE**. Hufanya utafiti wao wenyewe na hutengeneza zana zao wenyewe za hacking ili **kutoa huduma kadhaa muhimu za cybersecurity** kama vile pentesting, Red teams na mafunzo.

Unaweza kuangalia **blog** yao katika [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** pia inasaidia miradi ya open source ya cybersecurity kama HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** ni **#1 barani Ulaya** kwa ethical hacking na **bug bounty platform.**

**Bug bounty tip**: **jiandikishe** kwa **Intigriti**, **bug bounty platform** ya premium iliyoundwa na hackers, kwa hackers! Jiunge nasi katika [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na anza kupata bounties hadi **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Jiunge na server ya [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) ili kuwasiliana na hackers wenye uzoefu na bug bounty hunters!

- **Hacking Insights:** Shirikiana na maudhui yanayoingia ndani ya msisimko na changamoto za hacking
- **Real-Time Hack News:** Endelea kusasishwa na ulimwengu wa hacking unaokwenda kwa kasi kupitia habari na insights za wakati halisi
- **Latest Announcements:** Pata taarifa kuhusu bug bounties mpya zaidi zinazozinduliwa na masasisho muhimu ya platform

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na hackers bora leo!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security hutoa **mafunzo ya AI Security ya vitendo** kwa **mbinu ya engineering-first, hands-on lab**. Kozi zetu zimeundwa kwa ajili ya security engineers, AppSec professionals, na developers wanaotaka **kujenga, kuvunja, na kulinda applications halisi zinazoendeshwa na AI/LLM**.

**AI Security Certification** inalenga ujuzi wa ulimwengu halisi, ikijumuisha:
- Kulinda applications za LLM na zinazotumia AI
- Threat modeling kwa mifumo ya AI
- Embeddings, vector databases, na RAG security
- Mashambulizi ya LLM, matumizi mabaya, na defenses za vitendo
- Mifumo salama ya design na masuala ya deployment

Kozi zote ni **on-demand**, **lab-driven**, na zimeundwa kuzunguka **tradeoffs za usalama za ulimwengu halisi**, si theory tu.

👉 Maelezo zaidi kuhusu kozi ya AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** inatoa APIs za haraka na rahisi za wakati halisi za **kupata matokeo ya search engine**. Wanadukua search engines, hushughulikia proxies, hutatua captchas, na kuchanganua rich structured data yote kwa ajili yako.

Usajili wa mojawapo ya mipango ya SerpApi unajumuisha access kwa zaidi ya APIs 50 tofauti za kudukua search engines tofauti, ikijumuisha Google, Bing, Baidu, Yahoo, Yandex, na zaidi.\
Tofauti na providers wengine, **SerpApi haiduki tu organic results**. Responses za SerpApi mara kwa mara hujumuisha ads zote, inline images na videos, knowledge graphs, na elements na features nyingine zilizopo katika search results.

Wateja wa sasa wa SerpApi ni pamoja na **Apple, Shopify, na GrubHub**.\
Kwa maelezo zaidi angalia [**blog**](https://serpapi.com/blog/)**,** au jaribu mfano katika [**playground**](https://serpapi.com/playground)**.**\
Unaweza **kuunda akaunti ya bure** [**hapa**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Jifunze teknolojia na ujuzi unaohitajika ili kufanya vulnerability research, penetration testing, na reverse engineering ili kulinda mobile applications na devices. **Bobea katika usalama wa iOS na Android** kupitia kozi zetu za on-demand na **pata certification**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** ni platform ya usalama inayoendeshwa na AI ili kupata vulnerabilities vinavyoweza kutumiwa kabla ya attackers kufanya hivyo.

**Code security tip**: jiandikishe kwa NaxusAI, platform ya smart vulnerability monitoring iliyoundwa kwa ajili ya developers na security teams! Jiunge nasi leo na anza kutumia AI kwa ajili ya **kugundua, kuthibitisha, na kurekebisha security risks halisi kabla hazijafika production**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) ni kampuni ya kitaalamu ya cybersecurity iliyoko **Amsterdam** ambayo husaidia **kulinda** biashara **duniani kote** dhidi ya vitisho vya hivi karibuni vya cybersecurity kwa kutoa **offensive-security services** kwa mbinu ya **kisasa**.

WebSec ni kampuni ya usalama ya kimataifa yenye ofisi Amsterdam na Wyoming. Wanatoa **all-in-one security services** ambayo inamaanisha wanafanya yote; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing na mengi zaidi.

Jambo jingine zuri kuhusu WebSec ni kwamba tofauti na wastani wa industry WebSec ina uhakika mkubwa sana na uwezo wao, kiasi kwamba **wanahakikisha matokeo ya ubora bora**, katika website yao wanasema "**If we can't hack it, You don't pay it!**". Kwa maelezo zaidi angalia [**website**](https://websec.net/en/) yao na [**blog**](https://websec.net/blog/)!

Mbali na hayo, WebSec pia ni **mfuasi makini wa HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) hutengeneza na kutoa mafunzo madhubuti ya cybersecurity yaliyojengwa na kuongozwa na
wataalamu wa industry. Programu zao huenda zaidi ya theory ili kuipa timu uelewa wa kina na ujuzi wa kuchukua hatua, kwa kutumia mazingira maalum yanayoakisi
vitisho vya ulimwengu halisi. Kwa maswali ya mafunzo maalum, wasiliana nasi [**hapa**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Kinachotofautisha mafunzo yao:**
* Maudhui na labs zilizojengwa maalum
* Yanaungwa mkono na tools na platforms za kiwango cha juu
* Zimeundwa na kufundishwa na practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions hutoa huduma maalum za cybersecurity kwa taasisi za **Education** na **FinTech**,
kwa kuzingatia **penetration testing, cloud security assessments**, na
**compliance readiness** (SOC 2, PCI-DSS, NIST). Timu yetu inajumuisha wataalamu waliothibitishwa na **OSCP na CISSP**,
wakiwa na utaalamu wa kina wa kiufundi na maarifa ya kiwango cha industry kwa
kila engagement.

Tunaenda zaidi ya automated scans kwa **manual, intelligence-driven testing** iliyobinafsishwa kwa
mazingira ya hatari kubwa. Kuanzia kulinda rekodi za wanafunzi hadi kulinda miamala ya kifedha,
tunasaidia mashirika kulinda jambo linaloleta maana zaidi.

_“Ulinzi wa ubora unahitaji kujua ushambuliaji, tunatoa usalama kupitia uelewa.”_

Endelea kupata taarifa na masasisho ya hivi karibuni katika cybersecurity kwa kutembelea [**blog**](https://www.lasttowersolutions.com/blog) yetu.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE huwawezesha DevOps, DevSecOps, na developers kusimamia, kufuatilia, na kulinda Kubernetes clusters kwa ufanisi. Tumia AI-driven insights zetu, advanced security framework, na CloudMaps GUI angavu kuonyesha clusters zako, kuelewa hali yake, na kuchukua hatua kwa uhakika.

Zaidi ya hayo, K8Studio ina **uendana na major kubernetes distributions zote** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift na zaidi).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

<!-- hacktricks-friends:friend:friend-carlospolop:start -->
### [HackTricks Books](https://book.hacktricks.wiki/)

<figure class="sponsor-logo"><img src="https://friends.hacktricks.wiki/assets/17181413/5e15e93e6b8523dac2ad.png" alt="HackTricks Books logo"><figcaption></figcaption></figure>

Huu ni maandishi ya kuwasilisha cybersecurity free wiki: <b>Hacktricks Book </b>. Jifunze aina zote za hacking tricks bila malipo sasa!

{{#ref}}
https://book.hacktricks.wiki/
{{#endref}}

---
<!-- hacktricks-friends:friend:friend-carlospolop:end -->

## License & Disclaimer

Iangalie katika:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
