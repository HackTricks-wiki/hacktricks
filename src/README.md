# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Nembo za Hacktricks & muundo wa mwendo na_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Endesha HackTricks kwa Kompyuta Yako
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

## Wadhamini wa Kampuni

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ni kampuni nzuri ya usalama wa mtandao ambayo kauli mbiu yake ni **HACK THE UNHACKABLE**. Wanafanya utafiti wao wenyewe na kuendeleza zana zao za hacking ili **kutoa huduma kadhaa muhimu za usalama wa mtandao** kama pentesting, Red teams na mafunzo.

Unaweza kuangalia **blog** yao kwenye [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** pia inasaidia miradi ya chanzo huria ya usalama wa mtandao kama HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) ni tukio muhimu kwa usalama wa mtandao nchini Spain na mojawapo ya muhimu zaidi barani Europe. Kwa lengo la kukuza ujuzi wa kiufundi, kongamano hili ni kitovu cha kukutana cha shughuli nyingi kwa wataalamu wa teknolojia na usalama wa mtandao katika nyanja zote.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** ni the **Europe's #1** ethical hacking na **bug bounty platform.**

Kidokezo cha bug bounty: **jisajili** kwa **Intigriti**, jukwaa la kiwango cha juu la **bug bounty created by hackers, for hackers**! Jiunge nasi kwenye [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na anza kupata bounties hadi **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kujenga kwa urahisi na **kuotomatisha workflows** zinazoendeshwa na zana za jamii zenye maendeleo zaidi duniani.

Pata Ufikiaji Leo:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Jiunge na [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server ili kuwasiliana na hackers wenye uzoefu na wadudu bounty hunters!

- **Hacking Insights:** Shirikiana na maudhui yanayoangazia msisimko na changamoto za hacking
- **Real-Time Hack News:** Endelea kupata habari za dunia ya hacking kwa wakati halisi
- **Latest Announcements:** Kuwa na taarifa za bounties mpya zinazoanzishwa na masasisho muhimu ya jukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na hackers wakuu leo!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security inatoa **mafunzo ya vitendo ya AI Security** kwa mtazamo wa **engineering-first, maabara ya vitendo**. Kozi zao zimejengwa kwa ajili ya wahandisi wa usalama, wataalamu wa AppSec, na watengenezaji wanaotaka **kujenga, kuvunja, na kuimarisha applications zinazoendeshwa na AI/LLM**.

The **AI Security Certification** inalenga ujuzi wa ulimwengu wa kweli, ikijumuisha:
- Securing LLM and AI-powered applications
- Threat modeling for AI systems
- Embeddings, vector databases, and RAG security
- LLM attacks, abuse scenarios, and practical defenses
- Secure design patterns and deployment considerations

Kozi zote ni **on-demand**, **lab-driven**, na zimeundwa kuzingatia **mizanano ya usalama ya ulimwengu wa kweli**, sio tu nadharia.

👉 Maelezo zaidi kuhusu kozi ya AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** inatoa APIs za wakati halisi kwa haraka na kwa urahisi za **kupata matokeo ya injini za utafutaji**. Wanapiga scraping ya injini za utafutaji, wanashughulikia proxies, kutatua captchas, na kuchambua data yote iliyopangwa kwako.

Usajili kwa moja ya mipangilio ya SerpApi unajumuisha ufikiaji wa zaidi ya APIs 50 tofauti kwa scraping ya injini mbalimbali za utafutaji, ikiwa ni pamoja na Google, Bing, Baidu, Yahoo, Yandex, na zaidi.\
Tofauti na watoa wengine, **SerpApi haiwezi tu kuscrape matokeo ya asili**. Majibu ya SerpApi mara nyingi yanajumuisha matangazo yote, picha na video zilizojumuishwa, knowledge graphs, na vipengele vingine vilivyopo kwenye matokeo ya utafutaji.

Wateja wa sasa wa SerpApi ni pamoja na **Apple, Shopify, and GrubHub**.\
Kwa taarifa zaidi angalia [**blog**](https://serpapi.com/blog/)** yao,** au jaribu mfano kwenye [**playground**](https://serpapi.com/playground)** yao.**\
Unaweza **kuunda akaunti ya bure** [**hapa**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Jifunze teknolojia na ujuzi unaohitajika kufanya utafiti wa udhaifu, penetration testing, na reverse engineering ili kulinda mobile applications na devices. **Tumia ujuzi wa iOS na Android security** kupitia kozi zetu za on-demand na **pata vyeti**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) ni kampuni ya kitaalam ya usalama wa mtandao yenye makao yake **Amsterdam** inayosaidia **kulinda** biashara **hapo kote duniani** dhidi ya tishio jipya la usalama wa mtandao kwa kutoa **huduma za offensive-security** kwa mtazamo **mpya**.

WebSec ni kampuni ya usalama ya kimataifa yenye ofisi huko Amsterdam na Wyoming. Wanatoa **huduma za usalama zote kwa pamoja** ambayo inamaanisha wanafanya kila kitu; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing na mengi zaidi.

Jambo jingine la kuvutia kuhusu WebSec ni kwamba tofauti na wastani wa sekta WebSec ni **kujiamini sana kwa ujuzi wao**, kwa kiwango kwamba **wanahakikisha matokeo bora kabisa**, kama ilivyoonyeshwa kwenye tovuti yao "**If we can't hack it, You don't pay it!**". Kwa taarifa zaidi tazama [**website**](https://websec.net/en/) yao na [**blog**](https://websec.net/blog/)!

Mbali na hayo WebSec pia ni **mshirika aliyejitolea wa HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) huendeleza na kutoa mafunzo ya usalama wa mtandao yenye ufanisi yaliyoandaliwa na kuongozwa na wataalamu wa sekta. Programu zao zinazidi nadharia ili kuwapa timu uelewa wa kina na ujuzi wa utekelezaji, kwa kutumia mazingira maalum yanayoakisi tishio la ulimwengu wa kweli. Kwa maswali ya mafunzo maalum, wasiliana nasi [**hapa**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Kitakachowatofautisha mafunzo yao:**
* Yaliyoundwa mahususi yaliyojengwa pamoja na maabara
* Yanaungwa mkono na zana na majukwaa ya hali ya juu
* Yameundwa na kufundishwa na watendaji wa uwanja

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions inatoa huduma maalum za usalama wa mtandao kwa taasisi za **Elimu** na **FinTech**, ikilenga **penetration testing, cloud security assessments**, na **compliance readiness** (SOC 2, PCI-DSS, NIST). Timu yetu inajumuisha wataalamu **waliothibitishwa wa OSCP na CISSP**, wakileta ujuzi wa kina wa kiufundi na ufahamu wa viwango vya sekta katika kila ushirikiano.

Tunazidi skanseni za kiotomatiki kwa **upimaji wa mikono unaotumiwa na intelijensia** uliobinafsishwa kwa mazingira yenye hatari kubwa. Kuanzia kulinda rekodi za wanafunzi hadi kulinda miamala ya kifedha, tunawasaidia mashirika kujilinda yale yanayofaa zaidi.

_“Ulinzi bora unahitaji kujua mashambulizi; tunatoa usalama kupitia uelewa.”_

Endelea kupata habari za hivi punde katika usalama wa mtandao kwa kutembelea [**blog**](https://www.lasttowersolutions.com/blog) yao.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE inawawezesha DevOps, DevSecOps, na watengenezaji kusimamia, kufuatilia, na kuimarisha Kubernetes clusters kwa ufanisi. Tumia maarifa yetu yanayotokana na AI, fremu ya usalama ya hatua za juu, na GUI ya CloudMaps kuonyesha clusters zako, kuelewa hali zao, na kuchukua hatua kwa kujiamini.

Zaidi ya hayo, K8Studio ni **inayolingana na distributions zote kubwa za kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## Leseni & Angalizo

Angalia huko:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
