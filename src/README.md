# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logos & motion design deur_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Run HackTricks Plaaslik
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
Your local copy of HackTricks sal **beskikbaar wees by [http://localhost:3337](http://localhost:3337)** na <5 minutes (dit moet die book bou, wees geduldig).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) is 'n uitstekende cybersecurity-maatskappy wie se slagspreuk **HACK THE UNHACKABLE** is. Hulle doen hul eie navorsing en ontwikkel hul eie hacking tools om **verskeie waardevolle cybersecurity-dienste aan te bied** soos pentesting, Red teams en training.

Jy kan hul **blog** by [**https://blog.stmcyber.com**](https://blog.stmcyber.com) nagaan

**STM Cyber** ondersteun ook cybersecurity open source projects soos HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** is Europa se **#1** ethical hacking en **bug bounty platform.**

**Bug bounty tip**: **teken aan** by **Intigriti**, 'n premium **bug bounty platform geskep deur hackers, vir hackers**! Sluit vandag by ons aan by [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks), en begin bounties verdien tot **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Sluit aan by die [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server om met ervare hackers en bug bounty hunters te kommunikeer!

- **Hacking Insights:** Betrek jou by content wat in die opwinding en uitdagings van hacking delf
- **Real-Time Hack News:** Bly op datum met die vinnige hacking world deur real-time news en insights
- **Latest Announcements:** Bly ingelig oor die nuutste bug bounties wat geloods word en kritieke platform updates

**Sluit by ons aan op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security lewer **praktiese AI Security training** met 'n **engineering-first, hands-on lab approach**. Ons courses is gebou vir security engineers, AppSec professionals en developers wat **regte AI/LLM-gedrewe applications wil bou, breek en beveilig**.

Die **AI Security Certification** fokus op werklike vaardighede, insluitend:
- Securing LLM and AI-powered applications
- Threat modeling for AI systems
- Embeddings, vector databases, and RAG security
- LLM attacks, abuse scenarios, and practical defenses
- Secure design patterns and deployment considerations

Alle courses is **on-demand**, **lab-driven**, en ontwerp rondom **real-world security tradeoffs**, nie net teorie nie.

👉 Meer besonderhede oor die AI Security course:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bied vinnige en maklike real-time APIs om **search engine results te access**. Hulle scrape search engines, hanteer proxies, los captchas op, en parse alle rich structured data vir jou.

'n Subscription op een van SerpApi se plans sluit access in tot meer as 50 verskillende APIs vir scraping van verskillende search engines, insluitend Google, Bing, Baidu, Yahoo, Yandex, en meer.\
Anders as ander providers, **scrape SerpApi nie net organic results nie**. SerpApi responses sluit konsekwent alle ads, inline images en videos, knowledge graphs, en ander elements en features in wat in die search results teenwoordig is.

Huidige SerpApi customers sluit in **Apple, Shopify, en GrubHub**.\
Vir meer information kyk na hul [**blog**](https://serpapi.com/blog/)**,** of probeer 'n example in hul [**playground**](https://serpapi.com/playground)**.**\
Jy kan **'n gratis account skep** [**hier**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Leer die technologies en skills wat nodig is om vulnerability research, penetration testing, en reverse engineering uit te voer om mobile applications en devices te beskerm. **Bemeester iOS en Android security** deur ons on-demand courses en **kry certified**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** is 'n AI-powered security platform om exploitable vulnerabilities te vind voordat attackers dit doen.

**Code security tip**: teken aan vir NaxusAI, 'n slim vulnerability monitoring platform gebou vir developers en security teams! Sluit vandag by ons aan en begin AI gebruik vir **detecting, validating, en fixing real security risks before they reach production**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) is 'n professionele cybersecurity-maatskappy gebaseer in **Amsterdam** wat besighede **oor die hele wêreld** help **beskerm** teen die nuutste cybersecurity threats deur **offensive-security services** met 'n **modern** approach te verskaf.

WebSec is 'n intenational security company met kantore in Amsterdam en Wyoming. Hulle bied **all-in-one security services** wat beteken hulle doen alles; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing en nog baie meer.

Nog 'n cool ding van WebSec is dat, anders as die industry average, WebSec **baie selfvertroue in hul skills het**, tot so 'n mate dat hulle **die beste quality results waarborg**, dit staan op hul website "**If we can't hack it, You don't pay it!**". Vir meer info kyk na hul [**website**](https://websec.net/en/) en [**blog**](https://websec.net/blog/)!

Benewens bogenoemde is WebSec ook 'n **toegewydde ondersteuner van HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) ontwikkel en lewer effektiewe cybersecurity training wat deur
industry experts gebou en gelei word. Hul programmes gaan verder as teorie om teams toe te rus met diep
begrip en bruikbare skills, deur custom environments te gebruik wat real-world
threats weerspieël. Vir custom training navrae, kontak ons [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**What sets their training apart:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions lewer gespesialiseerde cybersecurity services vir **Education** en **FinTech**
institutions, met 'n fokus op **penetration testing, cloud security assessments**, en
**compliance readiness** (SOC 2, PCI-DSS, NIST). Ons team sluit **OSCP en CISSP
gesertifiseerde professionals** in, en bring diep technical expertise en industry-standard insight na
elke engagement.

Ons gaan verder as automated scans met **manual, intelligence-driven testing** wat aangepas is vir
high-stakes environments. Van die beveiliging van student records tot die beskerming van financial transactions,
help ons organisations om te verdedig wat die belangrikste is.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Bly ingelig en op datum met die nuutste in cybersecurity deur ons [**blog**](https://www.lasttowersolutions.com/blog) te besoek.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE stel DevOps, DevSecOps, en developers in staat om Kubernetes clusters doeltreffend te bestuur, monitor, en beveilig. Gebruik ons AI-gedrewe insights, gevorderde security framework, en intuïtiewe CloudMaps GUI om jou clusters te visualiseer, hul state te verstaan, en met selfvertroue op te tree.

Verder is K8Studio **compatible met alle groot kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift en meer).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

<!-- hacktricks-friends:friend:friend-carlospolop:start -->
### [HackTricks Books](https://book.hacktricks.wiki/)

<figure class="sponsor-logo"><img src="https://friends.hacktricks.wiki/assets/17181413/5e15e93e6b8523dac2ad.png" alt="HackTricks Books logo"><figcaption></figcaption></figure>

Dit is 'n teks om die cybersecurity gratis wiki voor te stel: <b>Hacktricks Book </b>. Leer nou alle soorte hacking tricks gratis daaruit!

{{#ref}}
https://book.hacktricks.wiki/
{{#endref}}

---
<!-- hacktricks-friends:friend:friend-carlospolop:end -->

## License & Disclaimer

Kyk dit in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
