# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Nembo za Hacktricks na muundo wa mwendo na_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Endesha HackTricks kwenye kompyuta yako
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
Nakili yako ya HackTricks itakuwa **inapatikana kwa [http://localhost:3337](http://localhost:3337)** baada ya <5 dakika (inahitaji kujenga kitabu, kuwa mvumilivu).

## Wadhamini wa Kampuni

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ni kampuni nzuri ya usalama wa mtandao ambayo kaulimbiu yao ni **HACK THE UNHACKABLE**. Wanatekeleza utafiti wao na kubuni zana zao za hacking ili **kutoa huduma kadhaa muhimu za usalama wa mtandao** kama pentesting, Red teams na mafunzo.

Unaweza kuangalia **blog** yao katika [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** pia inasaidia miradi ya chanzo wazi ya usalama wa mtandao kama HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) ni tukio muhimu zaidi la usalama wa mtandao nchini **Spain** na moja ya muhimu zaidi katika **Europe**. Kwa **kusudi la kukuza maarifa ya kiufundi**, kongamano hili ni mahali pa mkutano lenye shughuli nyingi kwa wataalamu wa teknolojia na usalama wa mtandao katika fani zote.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** ni **#1 Barani Ulaya** ethical hacking na **bug bounty platform.**

**Bug bounty tip**: **jisajili** kwa **Intigriti**, jukwaa la premium la bug bounty lililotengenezwa na hackers, kwa hackers! Jiunge nasi kwenye [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na anza kupata bounties hadi **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kujenga kwa urahisi na ku-automate workflows zinazoendeshwa na zana za jamii zilizoendelea zaidi ulimwenguni.

Pata Ufikiaji Leo:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Jiunge na [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server ili kuwasiliana na hackers wenye uzoefu na bug bounty hunters!

- **Hacking Insights:** Shirikiana na maudhui yanayoingia ndani ya msisimko na changamoto za hacking
- **Real-Time Hack News:** Kuwa updated na dunia ya hacking kupitia habari na maarifa ya wakati halisi
- **Latest Announcements:** Pata taarifa za hivi punde kuhusu bounties mpya zinazozinduliwa na masasisho muhimu ya majukwaa

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na top hackers leo!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - Zana muhimu za penetration testing

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Pata mtazamo wa hacker juu ya web apps, mtandao, na cloud yako**

**Gundua na ripoti udhaifu muhimu unaoweza kutumika na wenye athari za biashara.** Tumia zana zetu 20+ za kawaida ili kupima uso wa mashambulizi, gundua masuala ya usalama yanayokuwezesha kuongeza vibali, na tumia exploits zilizooautomate kukusanya ushahidi muhimu, ukigeuza kazi yako kuwa ripoti za kushawishi.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** inatoa APIs za wakati halisi haraka na kwa urahisi za ku-access search engine results. Wanascape search engines, kushughulikia proxies, kutatua captchas, na kuchambua data zote zilizo-structured kwa niaba yako.

Usajili kwenye mmoja wa mipango ya SerpApi unajumuisha ufikiaji wa zaidi ya API tofauti 50 za kuchapa search engines mbalimbali, ikiwemo Google, Bing, Baidu, Yahoo, Yandex, na zaidi.\
Tofauti na watoa huduma wengine, **SerpApi haichapi tu organic results**. Majibu ya SerpApi mara nyingi yanajumuisha matangazo yote, picha na video zilizo-inline, knowledge graphs, na vipengele vingine vilivyo kwenye matokeo ya utafutaji.

Wateja wa sasa wa SerpApi ni pamoja na **Apple, Shopify, na GrubHub**.\
Kwa habari zaidi angalia [**blog**](https://serpapi.com/blog/)**,** au jaribu mfano katika [**playground**](https://serpapi.com/playground)**.**\
Unaweza **kufungua akaunti ya bure** [**hapa**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Jifunze teknolojia na ujuzi unaohitajika kufanya utafiti wa udhaifu, penetration testing, na reverse engineering ili kulinda mobile applications na vifaa. **Bobea katika usalama wa iOS na Android** kupitia kozi zetu za on-demand na **pata cheti**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) ni kampuni ya kitaalamu ya usalama wa mtandao iliyo katika **Amsterdam** ambayo husaidia **kulinda** biashara **hapo duniani kote** dhidi ya tishio la hivi punde la usalama kwa kutoa **huduma za offensive-security** kwa mtazamo **wa kisasa**.

WebSec ni kampuni ya usalama ya kimataifa yenye ofisi huko Amsterdam na Wyoming. Wanatoa **huduma zote-katika-moja za usalama** ambazo zina maana wanashughulikia kila kitu; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing na mengi zaidi.

Jambo jingine zuri kuhusu WebSec ni kwamba tofauti na wastani wa tasnia WebSec wana **kujiamini mkubwa katika ujuzi wao**, hadi kiwango cha kuwahakikishia matokeo bora kabisa, inasema kwenye tovuti yao "**If we can't hack it, You don't pay it!**". Kwa maelezo zaidi angalia [**website**](https://websec.net/en/) yao na [**blog**](https://websec.net/blog/)!

Mbali na hayo WebSec pia ni **mshabiki wa kujitolea wa HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) ni search engine ya data breach (leak). \
Tunatoa random string search (kama google) juu ya aina zote za data leaks kubwa na ndogo --si tu kubwa-- juu ya data inayotoka vyanzo vingi. \
People search, AI search, organization search, API (OpenAPI) access, theHarvester integration, vipengele vyote ambavyo pentester anahitaji.\
**HackTricks inaendelea kuwa jukwaa bora la kujifunza kwetu sote na tunajivunia kuwa wadhamini wake!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) huunda na kutoa mafunzo ya usalama wa mtandao yenye ufanisi yameundwa na kuongozwa na wataalamu wa tasnia. Programu zao zinaenda zaidi ya nadharia ili kuwapangia timu uelewa wa kina na ujuzi wa utekelezaji, zikitumia mazingira maalum yanayoakisi tishio la ulimwengu wa kweli. Kwa maswali kuhusu mafunzo maalum, wasiliana nasi [**hapa**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Kile kinachofanya mafunzo yao kuwa tofauti:**
* Vilivyojengwa kwa muktadha wa maudhui na maabara
* Zinategemewa na zana na majukwaa ya kiwango cha juu
* Zimetengenezwa na kufundishwa na wataalamu wa vitendo

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions hutoa huduma maalum za usalama wa mtandao kwa taasisi za **Elimu** na **FinTech**, ikilenga **penetration testing, cloud security assessments**, na **compliance readiness** (SOC 2, PCI-DSS, NIST). Timu yetu ni pamoja na wataalamu waliothibitishwa wa **OSCP na CISSP**, wakiwa na utaalamu wa kiufundi na ufahamu wa viwango vya tasnia kwa kila ushirikiano.

Tunazidi skani za otomatiki kwa **upimaji wa mkono ulioongozwa na intelijensia** uliobinafsishwa kwa mazingira ya hatari kubwa. Kuanzia kulinda rekodi za wanafunzi hadi kulinda miamala ya kifedha, tunawasaidia mashirika kulinda yale muhimu zaidi.

_“Ulinzi wa ubora unahitaji kujua mashambulizi, tunatoa usalama kupitia uelewa.”_

Kaa umejulishwa na up-to-date na maendeleo ya hivi punde katika usalama wa mtandao kwa kutembelea [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE inawawezesha DevOps, DevSecOps, na developers kusimamia, kufuatilia, na kuilinda Kubernetes clusters kwa ufanisi. Tumia maarifa yetu yanayoendeshwa na AI, fremu ya usalama ya hali ya juu, na CloudMaps GUI inayofaa kuona clusters zako, kuelewa hali yao, na kuchukua hatua kwa kujiamini.

Pia, K8Studio ni **inayolingana na distributions zote kuu za kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift na zaidi).

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## Leseni na Msamaha

Angalia hizi katika:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Takwimu za Github

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
