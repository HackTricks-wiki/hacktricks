# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Nembo za Hacktricks na muundo wa mwendo na_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Endesha HackTricks ndani ya kompyuta yako
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
Nakili yako ya karibu ya HackTricks itakuwa **available at [http://localhost:3337](http://localhost:3337)** baada ya <5 dakika (inahitaji kujenga kitabu, kuwa mvumilivu).

## Wadhamini wa Kampuni

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ni kampuni nzuri ya cybersecurity ambayo kauli mbiu yake ni **HACK THE UNHACKABLE**. Wanafanya utafiti wao wenyewe na kuendeleza zana zao za hacking ili **kutoa several valuable cybersecurity services** kama pentesting, Red teams na mafunzo.

Unaweza kuangalia blog yao kwenye [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** pia inasaidia miradi ya chanzo huria ya cybersecurity kama HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) ni tukio la muhimu zaidi la cybersecurity nchini **Spain** na mojawapo ya muhimu zaidi katika **Europe**. Kwa **mission of promoting technical knowledge**, kongamano hili ni kitovu cha kukutana kwa wataalamu wa teknolojia na cybersecurity kutoka taaluma zote.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** ni **Europe's #1** ethical hacking na **bug bounty platform.**

**Bug bounty tip**: **jisajili** kwa **Intigriti**, premium **bug bounty platform created by hackers, for hackers**! Jiunge nasi kwenye [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na anza kupata bounties hadi **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kujenga kwa urahisi na automate workflows zinazotumia zana za jamii zilizoadvanced duniani.

Pata Ufikiaji Leo:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server ili kuwasiliana na hackers wenye uzoefu na wadudu wa bug bounty!

- **Hacking Insights:** Shirikiana na maudhui yanayoingia ndani ya msisimko na changamoto za hacking
- **Real-Time Hack News:** Endelea kupata habari za haraka za dunia ya hacking kupitia taarifa za wakati halisi
- **Latest Announcements:** Baki umejulishwa kuhusu bug bounties mpya zinazoanzishwa na masasisho muhimu ya jukwaa

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na top hackers leo!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Pata mtazamo wa hacker kuhusu web apps yako, mtandao, na cloud**

**Gundua na ripoti vulnerabilities muhimu, exploitable vulnerabilities zenye athari halisi kwa biashara.** Tumia zana zetu 20+ za kawaida ili kuchora ramani ya attack surface, gundua masuala ya usalama yanayokuruhusu escalate privileges, na tumia automated exploits kukusanya ushahidi muhimu, ukigeuza kazi yako kuwa ripoti zenye kuhimiza.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** inatoa APIs za haraka na rahisi za wakati halisi ili **kupata search engine results**. Wanapiga scraping search engines, wanashughulikia proxies, kutatua captchas, na kuchambua data zote zenye muundo mzuri kwa niaba yako.

Usajili kwa mojawapo ya mipango ya SerpApi unajumuisha upatikanaji wa APIs zaidi ya 50 tofauti za kuchakata injini mbalimbali za utafutaji, ikiwa ni pamoja na Google, Bing, Baidu, Yahoo, Yandex, na zaidi.\
Tofauti na wasambazaji wengine, **SerpApi doesn’t just scrape organic results**. Majibu ya SerpApi mara kwa mara yanajumuisha matangazo yote, picha na video zilizo inline, knowledge graphs, na vipengele vingine vilivyo katika matokeo ya utafutaji.

Wateja wa sasa wa SerpApi ni pamoja na **Apple, Shopify, and GrubHub**.\
Kwa taarifa zaidi angalia [**blog**](https://serpapi.com/blog/)**,** au jaribu mfano katika [**playground**](https://serpapi.com/playground)**.**\
Unaweza **kuunda akaunti ya bure** [**hapa**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Jifunze teknolojia na ujuzi unaohitajika kufanya vulnerability research, penetration testing, na reverse engineering ili kulinda mobile applications na devices. **Tumia fursa za kujifunza iOS na Android security** kupitia kozi zetu za on-demand na **pata cheti**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) ni kampuni ya kitaalamu ya cybersecurity iliyoko **Amsterdam** ambayo husaidia kulinda biashara **kutoka pande zote za dunia** dhidi ya vitisho vya hivi karibuni vya cybersecurity kwa kutoa **offensive-security services** kwa mtazamo wa kisasa.

WebSec ni kampuni ya usalama ya kimataifa yenye ofisi huko Amsterdam na Wyoming. Wanatoa **all-in-one security services** ambayo inamaanisha wanashughulikia kila kitu; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing na mengi zaidi.

Jambo jingine jema kuhusu WebSec ni kwamba tofauti na wastani wa sekta WebSec ni **wana uhakika sana katika ujuzi wao**, hadi kiwango kwamba **wanahakikishia matokeo bora**, inasema kwenye tovuti yao "**If we can't hack it, You don't pay it!**". Kwa maelezo zaidi angalia [**website yao**](https://websec.net/en/) na [**blog**](https://websec.net/blog/)!

Zaidi ya hayo WebSec pia ni **mshirika aliyejitolea wa HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) huendeleza na kutoa mafunzo madhubuti ya cybersecurity yaliyoundwa na kuendeshwa na wataalamu wa sekta. Programu zao zinazidi nadharia kuwapa timu uelewa wa kina na ujuzi wa utekelezaji, zikitumia mazingira maalum yanayoakisi vitisho vya ulimwengu wa kweli. Kwa uchunguzi wa mafunzo maalum, wasiliana nasi [**hapa**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Kinachowafanya mafunzo yao yawe ya kipekee:**
* Maudhui na maabara zilizojengwa maalum
* Zimetegemezwa na zana na majukwaa ya kiwango cha juu
* Zimeundwa na kufundishwa na wataalamu wa vitendo

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions hutoa huduma maalum za cybersecurity kwa taasisi za **Education** na **FinTech**, kwa kuzingatia **penetration testing, cloud security assessments**, na **compliance readiness** (SOC 2, PCI-DSS, NIST). Timu yetu inajumuisha wataalamu walio na vyeti vya **OSCP and CISSP**, wakiwa na utaalamu wa kina wa kiufundi na ufahamu wa viwango vya tasnia katika kila ushirikiano.

Tunazidi skanning za automated kwa **manual, intelligence-driven testing** iliyobinafsishwa kwa mazingira yenye hatari kubwa. Kuanzia kuimarisha rekodi za wanafunzi hadi kulinda miamala ya kifedha, tunasaidia mashirika kulinda kile kinachothaminiwa zaidi.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Baki umejulishwa na up-to-date na mambo ya hivi karibuni katika cybersecurity kwa kutembelea [**blog yao**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE inawapa DevOps, DevSecOps, na developers uwezo wa kusimamia, kufuatilia, na kulinda Kubernetes clusters kwa ufanisi. Tumia ufahamu unaoendeshwa na AI, mfumo wa usalama wa hali ya juu, na GUI ya CloudMaps kuona clusters zako, kuelewa hali yao, na kuchukua hatua kwa kujiamini.

Zaidi ya hayo, K8Studio ni **inayofanana na distributions zote kuu za kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## Leseni & Majaliwa

Tazama hizo katika:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
