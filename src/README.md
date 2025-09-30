# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_HackTricks-logo's en bewegingsontwerp deur_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Voer HackTricks plaaslik uit
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
Jou plaaslike kopie van HackTricks sal binne <5 minute **beskikbaar by [http://localhost:3337](http://localhost:3337)** wees (dit moet die boek bou, wees geduldig).

## Korporatiewe Borge

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) is 'n uitstekende kuberveiligheid maatskappy met die slagspreuk **HACK THE UNHACKABLE**. Hulle doen eie navorsing en ontwikkel hul eie hacking tools om **verskeie waardevolle kuberveiligheidsdienste** aan te bied soos pentesting, Red teams en opleiding.

You can check their **blog** in [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** ondersteun ook open source kuberveiligheidsprojekte soos HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) is die mees relevante kuberveiligheidsgebeurtenis in **Spanje** en een van die belangrikste in **Europa**. Met **die missie om tegniese kennis te bevorder**, is hierdie kongres 'n bruisende ontmoetingspunt vir tegnologie- en kuberveiligheidsprofessionals in alle dissiplines.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** is die **Europe's #1** ethical hacking en **bug bounty platform.**

**Bug bounty tip**: **sign up** for **Intigriti**, 'n premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) om maklik workflows te bou en te **automate** wat aangedryf word deur die wêreld se **mees gevorderde** community tools.

Get Access Today:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

- **Hacking Insights:** Engage with content that delves into the thrill and challenges of hacking
- **Real-Time Hack News:** Keep up-to-date with fast-paced hacking world through real-time news and insights
- **Latest Announcements:** Bly ingelig oor die nuutste bug bounties wat van stapel gestuur word en belangrike platform-opdaterings

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Kry 'n hacker se perspektief op jou web apps, netwerk, en cloud**

**Vind en rapporteer kritieke, exploitable kwetsbaarhede met werklike besigheidsimpak.** Gebruik ons 20+ custom tools om die aanvaloppervlak te kaart, sekuriteitskwessies te vind wat jou toelaat om privileges te eskaleer, en gebruik geautomatiseerde exploits om noodsaaklike bewyse in te samel, wat jou harde werk in oortuigende verslae omsit.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bied vinnige en maklike real-time APIs om **toegang tot search engine results** te kry. Hulle scrape search engines, hanteer proxies, los captchas op, en parse alle ryk gestruktureerde data vir jou.

'n Intekening op een van SerpApi se planne sluit toegang in tot meer as 50 verskillende APIs vir die scraping van verskillende search engines, insluitend Google, Bing, Baidu, Yahoo, Yandex, en meer.\
Anders as ander verskaffers, **SerpApi scrape nie net organic results nie**. SerpApi response sluit konsekwent alle ads, inline images en videos, knowledge graphs, en ander elemente en kenmerke aanwesig in die search results.

Huidige SerpApi customers sluit in **Apple, Shopify, and GrubHub**.\
Vir meer inligting kyk na hul [**blog**](https://serpapi.com/blog/)**,** of probeer 'n voorbeeld in hulle [**playground**](https://serpapi.com/playground)**.**\
Jy kan **'n gratis rekening skep** [**here**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Leer die tegnologieë en vaardighede nodig om vulnerability research, penetration testing, en reverse engineering uit te voer om mobiele toepassings en toestelle te beskerm. **Beheers iOS en Android security** deur ons on-demand kursusse en **kry gesertifiseer**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) is 'n professionele kuberveiligheidsmaatskappy gebaseer in **Amsterdam** wat help om **maatskappye regoor die wêreld** te beskerm teen die nuutste kuberveiligheidsbedreigings deur **offensive-security services** met 'n **moderne** benadering te lewer.

WebSec is 'n internasionale security company met kantore in Amsterdam en Wyoming. Hulle bied **all-in-one security services** wat beteken hulle doen alles; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing en nog veel meer.

Nog 'n koel ding oor WebSec is dat, anders as die industrie-gemiddelde, WebSec **baie selfversekerd is in hul vaardighede**, tot so 'n mate dat hulle **die beste kwaliteit resultate waarborg**, soos op hulle webtuiste staan: "**If we can't hack it, You don't pay it!**". Vir meer inligting, kyk na hul [**website**](https://websec.net/en/) en [**blog**](https://websec.net/blog/)!

Benewens bogenoemde is WebSec ook 'n **toegewyde ondersteuner van HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) is 'n data breach (leak) search engine. \
Ons voorsien random string search (like google) oor alle tipes data leaks groot en klein --nie net die groot een nie-- oor data van veelvuldige bronne. \
People search, AI search, organization search, API (OpenAPI) access, theHarvester integration, all features a pentester needs.\
**HackTricks continues to be a great learning platform for us all and we're proud to be sponsoring it!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) ontwikkel en lewer effektiewe kuberveiligheid opleiding wat gebou en gelei word deur industry experts. Hul programme gaan verder as teorie om spanne toe te rus met diep begrip en toepaslike vaardighede, deur custom omgewings te gebruik wat werklike wêreld dreigemente weerspieël. Vir persoonlike opleidingsnavrae, kontak ons [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Wat hul opleiding onderskei:**
* Custom-built inhoud en labs
* Ondersteun deur top-tier tools en platforms
* Ontwerp en aangebied deur praktisyns

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions lewer gespesialiseerde kuberveiligheidsdienste vir **Education** en **FinTech**
instellings, met 'n fokus op **penetration testing, cloud security assessments**, en
**compliance readiness** (SOC 2, PCI-DSS, NIST). Ons span sluit **OSCP and CISSP
certified professionals** in, wat diep tegniese kundigheid en industrie-standaard insigte bring na
elke betrokkenheid.

Ons gaan verder as geautomatiseerde skanderings met **handmatige, intelligence-driven testing** aangepas vir
hoë-ryks omgewings. Van die beveiliging van studenterekords tot die beskerming van finansiële transaksies,
ons help organisasies om te verdedig wat die meeste saak maak.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Bly ingelig en op datum met die nuutste in kuberveiligheid deur ons [**blog**](https://www.lasttowersolutions.com/blog) te besoek.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE bemagtig DevOps, DevSecOps, en developers om Kubernetes clusters doeltreffend te bestuur, te monitor, en te beveilig. Benut ons AI-driven insights, gevorderde security framework, en intuïtiewe CloudMaps GUI om jou clusters te visualiseer, hul toestand te verstaan, en met vertroue op te tree.

Boonop is K8Studio **compatible with all major kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## Lisensie & Vrywaring

Kyk hulle in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
