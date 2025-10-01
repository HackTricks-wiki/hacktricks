# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Nembo za Hacktricks na muundo wa mwendo uliofanywa na_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Endesha HackTricks kwenye mashine yako
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
Nakili yako ya HackTricks ya ndani itakuwa **available at [http://localhost:3337](http://localhost:3337)** baada ya <5 dakika (inahitaji kujenga kitabu, tafadhali vumilia).

## Wadhamini wa Kampuni

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ni kampuni bora ya cybersecurity whose slogan is **HACK THE UNHACKABLE**. Wanafanya utafiti wao wenyewe na kuendeleza zana zao za hacking ili kutoa huduma kadhaa muhimu za cybersecurity kama pentesting, Red teams na mafunzo.

Unaweza kuangalia **blog** yao kwenye [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** pia inaunga mkono miradi ya open source ya cybersecurity kama HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) ni tukio muhimu zaidi la cybersecurity huko **Spain** na moja ya muhimu zaidi huko **Europe**. Kwa **lengo la kuendeleza maarifa ya kiufundi**, kongamano hili ni mahali pa kukutana pa moto kwa wataalamu wa teknolojia na cybersecurity wa aina zote.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** ni **Europe's #1** ethical hacking na **bug bounty platform.**

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Jiunge nasi kwenye [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na anza kupata bounties hadi **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kujenga kwa urahisi na **kuendesha workflows** zinazotokana na zana **most advanced** za jamii ya ulimwengu.

Pata Ufikiaji Leo:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Jiunge na [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server ili kuwasiliana na hackers wenye uzoefu na hunters wa bug bounty!

- **Hacking Insights:** Shirikiana na maudhui yanayochunguza msisimko na changamoto za hacking
- **Real-Time Hack News:** Endelea kufuatilia dunia ya hacking kwa habari za wakati halisi na ufahamu
- **Latest Announcements:** Abiri taarifa za hivi punde kuhusu bug bounties zinazoanzishwa na sasisho muhimu za platform

**Jiunge nasi kwenye** [**Discord**](https://discord.com/invite/N3FrSbmwdy) na anza kushirikiana na hackers wakubwa leo!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Pata mtazamo wa hacker juu ya web apps, network, na cloud yako**

**Gundua na ripoti vulnerabilities kali, zinazoweza kutumika na zenye athari za kibiashara.** Tumia zana zetu 20+ maalum ili kuchora uso wa shambulio, kutafuta maswala ya usalama yanayokuruhusu kuongeza privileges, na kutumia exploits za moja kwa moja kukusanya ushahidi muhimu, ukibadilisha kazi yako kuwa ripoti za kuvutia.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** inatoa APIs za haraka na rahisi za wakati halisi za **access search engine results**. Wanachukua data kutoka kwa search engines, wanashughulikia proxies, kutatua captchas, na kuchambua data zote za structured kwa niaba yako.

Usajili wa moja ya mipango ya SerpApi unajumuisha ufikiaji wa zaidi ya APIs 50 tofauti za kuchonga search engines mbalimbali, ikiwa ni pamoja na Google, Bing, Baidu, Yahoo, Yandex, na zaidi.\
Tofauti na wasambazaji wengine, **SerpApi haichongi tu organic results**. Majibu ya SerpApi mara nyingi yanajumuisha matangazo yote, picha na video za ndani, knowledge graphs, na vipengele vingine vinavyopatikana kwenye matokeo ya utafutaji.

Wateja wa sasa wa SerpApi ni pamoja na **Apple, Shopify, and GrubHub**.\
Kwa taarifa zaidi angalia [**blog**](https://serpapi.com/blog/)**,** au jaribu mfano katika [**playground**](https://serpapi.com/playground)**.**\
Unaweza **kuunda akaunti ya bure** [**here**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Jifunze teknolojia na ujuzi unaohitajika kufanya vulnerability research, penetration testing, na reverse engineering ili kulinda mobile applications na devices. **Mstaadi katika iOS na Android security** kupitia kozi zetu za on-demand na **pata certification**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) ni kampuni ya kitaalamu ya cybersecurity yenye makao yake **Amsterdam** ambayo husaidia **kulinda** biashara **kote duniani** dhidi ya tishio jipya la cybersecurity kwa kutoa **offensive-security services** kwa njia ya **kisasa**.

WebSec ni kampuni ya kimataifa ya usalama yenye ofisi huko Amsterdam na Wyoming. Wanatoa **all-in-one security services** ambayo ina maana wanashughulikia kila kitu; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing na mengi zaidi.

Jambo jingine la kuvutia kuhusu WebSec ni kwamba tofauti na wastani wa sekta WebSec ni **kwa ujasiri mkubwa katika ujuzi wao**, hadi kwa kiwango kwamba **wanahakikisha matokeo ya ubora bora**, inasema kwenye tovuti yao "**If we can't hack it, You don't pay it!**". Kwa habari zaidi tazama [**website**](https://websec.net/en/) na [**blog**](https://websec.net/blog/)!

Mbali na hayo WebSec pia ni **mchango thabiti kwa HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) ni injini ya utafutaji ya data breach (leak). \
Tunatoa random string search (like google) juu ya aina zote za data leaks kubwa na ndogo --sio tu kubwa-- juu ya data kutoka vyanzo mbalimbali. \
Utafutaji wa watu, utafutaji kwa AI, utafutaji wa mashirika, API (OpenAPI) access, theHarvester integration, sifa zote ambazo pentester anahitaji.\
**HackTricks inaendelea kuwa jukwaa zuri la kujifunzia kwetu sote na tunajivunia kuitegemea!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) hutoa na kusambaza mafunzo ya cybersecurity yaliyojengwa na kuongozwa na wataalamu wa sekta. Programu zao zinaenda zaidi ya nadharia ili kuwapatia timu uelewa wa kina na ujuzi wa vitendo, kwa kutumia mazingira maalum yanayoakisi tishio la ulimwengu halisi. Kwa maswali ya mafunzo maalum, wasiliana nasi [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Kile kinachowatofautisha katika mafunzo yao:**
* Yaliyotengenezwa maalum yaliyobadilishwa na maabara
* Yanaungwa mkono na zana na platforms za kiwango cha juu
* Yameundwa na kufundishwa na watekelezaji

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions hutoa huduma maalum za cybersecurity kwa taasisi za **Education** na **FinTech**, kwa kuzingatia **penetration testing, cloud security assessments**, na **compliance readiness** (SOC 2, PCI-DSS, NIST). Timu yetu inajumuisha wataalamu waliothibitishwa wa **OSCP and CISSP**, wakileta ujuzi wa kina wa kiufundi na ufahamu wa viwango vya sekta kwa kila kazi.

Tunazidi skana za moja kwa moja kwa **manual, intelligence-driven testing** iliyobinafsishwa kwa mazingira yenye hatari kubwa. Kuanzia kulinda rekodi za wanafunzi hadi kuwalinda miamala ya kifedha, tunasaidia mashirika kutetea yale yanayowalea.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Endelea kupata habari na kusasishwa kuhusu kile kipya katika cybersecurity kwa kutembelea [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.jpg" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE inawawezesha DevOps, DevSecOps, na developers kusimamia, kufuatilia, na kulinda Kubernetes clusters kwa ufanisi. Tumia insights zetu za AI, fremu ya usalama ya juu, na CloudMaps GUI rahisi kuona clusters yako, kuelewa hali yake, na kuchukua hatua kwa ujasiri.

Zaidi ya hayo, K8Studio ni **compatible with all major kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## Leseni & Hukumu

Angalia huko:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
