# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks-logo's en motion-ontwerp deur_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Jou plaaslike kopie van HackTricks sal **available at [http://localhost:3337](http://localhost:3337)** na <5 minute wees (dit moet die boek bou, wees geduldig).

## Korporatiewe Borge

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) is 'n uitstekende kuberveiligheidsmaatskappy met die slagspreuk **HACK THE UNHACKABLE**. Hulle doen hul eie navorsing en ontwikkel hul eie hacking tools om **verskeie waardevolle kuberveiligheidsdienste** aan te bied soos pentesting, Red teams en opleiding.

Jy kan hul **blog** besoek by [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** ondersteun ook kuberveiligheid open source-projekte soos HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) is die mees relevante kuberveiligheidsgebeurtenis in **Spain** en een van die belangrikste in **Europe**. Met die missie om tegniese kennis te bevorder, is hierdie kongres 'n smeltkroes vir tegnologie- en kuberveiligheidsprofessionals in elke dissipline.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** is **Europe's #1** ethical hacking en **bug bounty platform.**

**Bug bounty tip**: **sign up** vir **Intigriti**, 'n premium **bug bounty platform geskep deur hackers, vir hackers**! Sluit by ons aan by [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) vandag, en begin om bounties tot **$100,000** te verdien!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) om maklik workflows te bou en te **outomatiseer** wat aangedryf word deur die wêreld se **mees gevorderde** community tools.

Kry toegang vandag:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Sluit aan by die [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) bediener om met ervare hackers en bug bounty hunters te kommunikeer!

- **Hacking Insights:** Deelname aan inhoud wat die opgewondenheid en uitdagings van hacking ondersoek
- **Real-Time Hack News:** Bly op hoogte van die vinnige wêreld van hacking deur real-time nuus en insigte
- **Latest Announcements:** Bly ingelig oor die nuutste bug bounties wat begin en belangrike platformopdaterings

**Sluit by ons aan op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security lewer **praktiese AI Security training** met 'n **engineering-first, hands-on lab approach**. Ons kursusse is gebou vir security engineers, AppSec professionals, en ontwikkelaars wat wil **bou, breek en veilige real AI/LLM-powered applications**.

Die **AI Security Certification** fokus op werklike vaardighede, insluitend:
- Securing LLM and AI-powered applications
- Threat modeling for AI systems
- Embeddings, vector databases, and RAG security
- LLM attacks, abuse scenarios, and practical defenses
- Secure design patterns and deployment considerations

Alle kursusse is **on-demand**, **lab-driven**, en ontwerp rondom **werklike sekuriteitsafwegings**, nie net teorie nie.

👉 Meer besonderhede oor die AI Security course:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bied vinnige en maklike real-time APIs om **access search engine results**. Hulle scrape search engines, hanteer proxies, los captchas op, en parse al die ryk gestruktureerde data vir jou.

'n Subskripsie op een van SerpApi se planne sluit toegang in tot meer as 50 verskillende APIs vir scraping van verskillende search engines, insluitend Google, Bing, Baidu, Yahoo, Yandex, en meer.\
In teenstelling met ander verskaffers, **SerpApi scrapes nie net organiese resultate nie**. SerpApi response sluit konsekwent alle ads, inline images and videos, knowledge graphs, en ander elemente en funksies wat in die search results teenwoordig is.

Huidige SerpApi kliënte sluit in **Apple, Shopify, and GrubHub**.\
Vir meer inligting, kyk na hul [**blog**](https://serpapi.com/blog/)**,** of probeer 'n voorbeeld in hul [**playground**](https://serpapi.com/playground)**.**\
Jy kan **create a free account** [**here**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Leer die tegnologieë en vaardighede wat benodig word om vulnerability research, penetration testing, en reverse engineering te verrig om mobiele toepassings en toestelle te beskerm. **Meester iOS en Android security** deur ons on-demand kursusse en **kry gesertifiseer**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) is 'n professionele kuberveiligheidsmaatskappy gebaseer in **Amsterdam** wat help om **besighede regoor die wêreld** te beskerm teen die nuutste kuberveiligheidsbedreigings deur **offensive-security services** met 'n **moderne** benadering te bied.

WebSec is 'n internasionale sekuriteitsmaatskappy met kantore in Amsterdam en Wyoming. Hulle bied **all-in-one security services** wat beteken hulle doen alles; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing en nog veel meer.

Nog 'n goeie ding oor WebSec is dat anders as die industrie-gemiddelde WebSec **baie selfversekerd is in hul vaardighede**, tot so 'n mate dat hulle **die beste gehalte resultate waarborg**, staan op hul webwerf "**If we can't hack it, You don't pay it!**". Vir meer info kyk na hul [**website**](https://websec.net/en/) en [**blog**](https://websec.net/blog/)!

Benewens bogenoemde is WebSec ook 'n **toegewese ondersteuner van HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) ontwikkel en lewer effektiewe kuberveiligheidstraining wat gebou en gelei word deur industrie-eksperte. Hul programme gaan verder as teorie om spanne toe te rus met diep begrip en toepaslike vaardighede, deur gebruik te maak van pasgemaakte omgewings wat werklike wêreld bedreigings weerspieël. Vir pasgemaakte opleiding navrae, kontak ons gerus [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Wat hul opleiding onderskei:**
* Pasgemaak-inhoud en labs
* Ondersteun deur top-tier tools en platforms
* Ontwerp en aangebied deur praktisyns

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions lewer gespesialiseerde kuberveiligheidsdienste vir **Education** en **FinTech**
instansies, met 'n fokus op **penetration testing, cloud security assessments**, en
**compliance readiness** (SOC 2, PCI-DSS, NIST). Ons span sluit **OSCP and CISSP
certified professionals** in, wat diep tegniese kundigheid en industrienorm insig bring na
elke betrokkenheid.

Ons gaan verder as geoutomatiseerde skanderings met **handmatige, intelligence-driven testing** toegespitst op hoë-stakes omgewings. Van die beveiliging van studentedossiers tot die beskerming van finansiële transaksies,
help ons organisasies om te verdedig wat die meeste saak maak.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Bly ingelig en op datum met die nuutste in kuberveiligheid deur ons [**blog**](https://www.lasttowersolutions.com/blog) te besoek.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE bemagtig DevOps, DevSecOps, en ontwikkelaars om Kubernetes clusters doeltreffend te bestuur, monitor, en beveilig. Benut ons AI-driven insigte, gevorderde sekuriteitsraamwerk, en intuïtiewe CloudMaps GUI om jou clusters te visualiseer, hul toestand te verstaan, en selfversekerd op te tree.

Boonop is K8Studio **compatible with all major kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## Lisensie & Vrywaring

Kyk na hulle in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
