# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logo za Hacktricks na muundo wa mwendo na_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Endesha HackTricks Kwenye Kompyuta Ya Ndani
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
Your local copy of HackTricks itakuwa **inapatikana katika [http://localhost:3337](http://localhost:3337)** baada ya <5 dakika (inahitaji ku-build kitabu, kuwa na subira).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ni kampuni bora ya cybersecurity ambayo kaulimbiu yake ni **HACK THE UNHACKABLE**. Wanafanya utafiti wao wenyewe na kuendeleza own hacking tools zao ili **kutoa huduma kadhaa muhimu za cybersecurity** kama pentesting, Red teams na training.

Unaweza kuangalia **blog** yao katika [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** pia huunga mkono miradi ya open source ya cybersecurity kama HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** ni **Europe's #1** ethical hacking na **bug bounty platform.**

**Bug bounty tip**: **jiandikishe** kwa **Intigriti**, premium **bug bounty platform iliyoundwa na hackers, kwa hackers**! Jiunge nasi katika [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na anza kupata bounties hadi **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Jiunge na server ya [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) ili kuwasiliana na hackers wenye uzoefu na bug bounty hunters!

- **Hacking Insights:** Shirikiana na maudhui yanayoingia ndani ya msisimko na changamoto za hacking
- **Real-Time Hack News:** Endelea kupata taarifa za kisasa kuhusu ulimwengu wa hacking kupitia habari na insights za wakati halisi
- **Latest Announcements:** Endelea kufahamu bug bounties mpya zinazozinduliwa na masasisho muhimu ya platform

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na hackers wakuu leo!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security inatoa **mafunzo ya vitendo ya AI Security** kwa mbinu ya **engineering-first, hands-on lab approach**. Kozi zetu zimejengwa kwa ajili ya security engineers, AppSec professionals, na developers wanaotaka **kujenga, kuvunja, na kulinda real AI/LLM-powered applications**.

**AI Security Certification** inalenga ujuzi wa ulimwengu halisi, ikijumuisha:
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

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** inatoa APIs za haraka na rahisi za real-time ili **kupata search engine results**. Wanacrawl search engines, kushughulikia proxies, kutatua captchas, na kuchambua rich structured data yote kwa ajili yako.

Usajili wa mojawapo ya plans za SerpApi unajumuisha access kwa zaidi ya APIs 50 tofauti za kuchambua tofauti search engines, zikiwemo Google, Bing, Baidu, Yahoo, Yandex, na nyinginezo.\
Tofauti na providers wengine, **SerpApi haichambui tu organic results**. Majibu ya SerpApi kwa uthabiti hujumuisha ads zote, inline images na videos, knowledge graphs, na vipengele vingine vilivyopo katika search results.

Wateja wa sasa wa SerpApi ni pamoja na **Apple, Shopify, na GrubHub**.\
Kwa maelezo zaidi angalia [**blog**](https://serpapi.com/blog/)** yao,** au jaribu mfano katika [**playground**](https://serpapi.com/playground)** yao.**\
Unaweza **kuunda akaunti ya bure** [**hapa**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Jifunze teknolojia na ujuzi unaohitajika ili kufanya vulnerability research, penetration testing, na reverse engineering kulinda mobile applications na devices. **Bobea katika iOS na Android security** kupitia kozi zetu za on-demand na **pata certification**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) ni kampuni ya kitaalamu ya cybersecurity iliyoko **Amsterdam** ambayo husaidia **kulinda** biashara **duniani kote** dhidi ya vitisho vipya vya cybersecurity kwa kutoa **offensive-security services** kwa mbinu ya **kisasa**.

WebSec ni kampuni ya usalama ya kimataifa yenye ofisi Amsterdam na Wyoming. Wanatoa **all-in-one security services** ambayo ina maana wanafanya yote; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing na mengi zaidi.

Jambo lingine zuri kuhusu WebSec ni kwamba tofauti na wastani wa industry WebSec ina **imani kubwa sana katika skills zao**, hadi kiasi kwamba **wanahakikisha matokeo bora zaidi**, kwenye website yao inasema "**If we can't hack it, You don't pay it!**". Kwa taarifa zaidi angalia [**website**](https://websec.net/en/) yao na [**blog**](https://websec.net/blog/)!

Mbali na hayo, WebSec pia ni **mfuasi aliyejitolea wa HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) inatengeneza na kutoa mafunzo madhubuti ya cybersecurity yaliyojengwa na kuendeshwa na
industry experts. Programu zao huenda zaidi ya nadharia ili kuandaa teams kwa
ufahamu wa kina na skills zinazoweza kutekelezwa, kwa kutumia custom environments zinazoakisi real-world
threats. Kwa maswali ya custom training, wasiliana nasi [**hapa**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Kinachotofautisha mafunzo yao:**
* Custom-built content na labs
* Yakiungwa mkono na top-tier tools na platforms
* Yameundwa na kufundishwa na practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions inatoa specialized cybersecurity services kwa taasisi za **Education** na **FinTech**
, kwa kuzingatia **penetration testing, cloud security assessments**, na
**compliance readiness** (SOC 2, PCI-DSS, NIST). Timu yetu ina **OSCP na CISSP
certified professionals**, ikileta utaalamu wa kina wa kiufundi na uelewa wa viwango vya industry kwenye
kila ushirikiano.

Tunaenda zaidi ya automated scans kwa **manual, intelligence-driven testing** iliyoandaliwa mahususi kwa
mazingira yenye umuhimu mkubwa. Kuanzia kulinda student records hadi kulinda financial transactions,
tunasaidia organizations kutetea kilicho muhimu zaidi.

_“Ulinzi wa ubora unahitaji kujua shambulio, tunatoa security kupitia uelewa.”_

Endelea kufahamu na kupata updates za hivi karibuni katika cybersecurity kwa kutembelea [**blog**](https://www.lasttowersolutions.com/blog) yetu.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE huwawezesha DevOps, DevSecOps, na developers kusimamia, kufuatilia, na kulinda Kubernetes clusters kwa ufanisi. Tumia AI-driven insights zetu, advanced security framework, na intuitive CloudMaps GUI ili kuona clusters zako, kuelewa hali yake, na kuchukua hatua kwa kujiamini.

Zaidi ya hayo, K8Studio **inaendana na major kubernetes distributions zote** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift na zaidi).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## License & Disclaimer

Zikague katika:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
