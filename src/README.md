# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks-logo's & beweging-ontwerp deur_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Jou plaaslike kopie van HackTricks sal ná <5 minute **beskikbaar wees by [http://localhost:3337](http://localhost:3337)** (dit moet die boek bou, wees geduldig).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) is 'n uitstekende cybersecurity-maatskappy wie se slagspreuk **HACK THE UNHACKABLE** is. Hulle doen hul eie navorsing en ontwikkel hul eie hacking tools om **verskeie waardevolle cybersecurity-dienste aan te bied** soos pentesting, Red teams en opleiding.

Jy kan hul **blog** by [**https://blog.stmcyber.com**](https://blog.stmcyber.com) nagaan

**STM Cyber** ondersteun ook open source cybersecurity-projekte soos HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** is **Europa se #1** ethical hacking en **bug bounty platform.**

**Bug bounty tip**: **teken in** by **Intigriti**, 'n premium **bug bounty platform created by hackers, for hackers**! Sluit vandag by ons aan by [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) en begin bounties verdien tot **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Sluit aan by die [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server om met ervare hackers en bug bounty hunters te kommunikeer!

- **Hacking Insights:** Raak betrokke by content wat die opwinding en uitdagings van hacking uitpak
- **Real-Time Hack News:** Bly op datum met die vinnigbewegende hacking world deur real-time nuus en insigte
- **Latest Announcements:** Bly ingelig oor die nuutste bug bounties wat begin en belangrike platform-opdaterings

**Sluit by ons aan op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security lewer **praktiese AI Security-opleiding** met 'n **engineering-first, hands-on lab approach**. Ons kursusse is gebou vir security engineers, AppSec professionals, en developers wat wil **werklike AI/LLM-aangedrewe applications bou, breek en beveilig**.

Die **AI Security Certification** fokus op werklike vaardighede, insluitend:
- Beveiliging van LLM en AI-aangedrewe applications
- Threat modeling vir AI systems
- Embeddings, vector databases, en RAG security
- LLM attacks, misbruik-scenario's, en praktiese verdediging
- Veilige design patterns en deployment-oorwegings

Alle kursusse is **on-demand**, **lab-driven**, en ontwerp rondom **werklike security tradeoffs**, nie net teorie nie.

👉 Meer besonderhede oor die AI Security-kursus:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bied vinnige en maklike real-time APIs om **search engine results te benader**. Hulle scrape search engines, hanteer proxies, los captchas op, en parse alle ryke gestruktureerde data vir jou.

'n Subskripsie op een van SerpApi se planne sluit toegang in tot meer as 50 verskillende APIs vir scraping van verskillende search engines, insluitend Google, Bing, Baidu, Yahoo, Yandex, en meer.\
Anders as ander providers, **SerpApi scrape nie net organic results nie**. SerpApi responses sluit konsekwent al die ads, inline images and videos, knowledge graphs, en ander elements en features wat in die search results teenwoordig is, in.

Huidige SerpApi customers sluit **Apple, Shopify, en GrubHub** in.\
Vir meer inligting kyk na hul [**blog**](https://serpapi.com/blog/)**,** of probeer 'n voorbeeld in hul [**playground**](https://serpapi.com/playground)**.**\
Jy kan [**hier**](https://serpapi.com/users/sign_up) **'n gratis rekening skep**.

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Leer die tegnologieë en vaardighede wat nodig is om vulnerability research, penetration testing, en reverse engineering uit te voer om mobile applications en devices te beskerm. **Bemeester iOS en Android security** deur ons on-demand kursusse en **kry gesertifiseer**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** is 'n AI-powered security platform om exploitable vulnerabilities te vind voordat attackers dit doen.

**Code security tip**: teken in vir NaxusAI, 'n slim vulnerability monitoring platform gebou vir developers en security teams! Sluit vandag by ons aan en begin AI gebruik vir **die opspoor, validering, en regstel van werklike security risks voordat dit production bereik**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) is 'n professionele cybersecurity-maatskappy gebaseer in **Amsterdam** wat besighede **oor die hele wêreld** help **beskerm** teen die nuutste cybersecurity-bedreigings deur **offensive-security services** met 'n **moderne** benadering te verskaf.

WebSec is 'n internasionale security-maatskappy met kantore in Amsterdam en Wyoming. Hulle bied **all-in-one security services** wat beteken hulle doen alles; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing en nog baie meer.

Nog 'n cool ding van WebSec is dat, anders as die bedryfsgemiddeld, WebSec **baie selfversekerd is in hul vaardighede**, tot so 'n mate dat hulle **die beste gehalte resultate waarborg**, en dit staan op hul webwerf "**If we can't hack it, You don't pay it!**". Vir meer inligting kyk na hul [**website**](https://websec.net/en/) en [**blog**](https://websec.net/blog/)!

Benewens bogenoemde is WebSec ook 'n **toegewyde ondersteuner van HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Gebou vir die veld. Gebou rondom jou.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) ontwikkel en lewer effektiewe cybersecurity-opleiding wat gebou en gelei word deur
bedryfskenners. Hul programme gaan verder as teorie om spanne toe te rus met diep
begrip en uitvoerbare vaardighede, deur pasgemaakte environments te gebruik wat werklike
bedreigings weerspieël. Vir pasgemaakte opleidingsnavrae, kontak ons [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Wat hul opleiding laat uitstaan:**
* Pasgemaakte content en labs
* Gesteun deur topvlak tools en platforms
* Ontwerp en onderrig deur practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions lewer gespesialiseerde cybersecurity-dienste vir **Education** en **FinTech**
instellings, met 'n fokus op **penetration testing, cloud security assessments**, en
**compliance readiness** (SOC 2, PCI-DSS, NIST). Ons span sluit **OSCP en CISSP
gesertifiseerde professionele persone** in, wat diep tegniese kundigheid en bedryfstandaard-insig na
elke betrokkenheid bring.

Ons gaan verder as geoutomatiseerde scans met **manual, intelligence-driven testing** wat aangepas is vir
hoë-insette environments. Van die beveiliging van studente-rekords tot die beskerming van finansiële transaksies,
help ons organisasies om te verdedig wat die belangrikste is.

_“'n Kwaliteit verdediging vereis kennis van die aanval, ons verskaf security deur begrip.”_

Bly ingelig en op datum met die nuutste in cybersecurity deur ons [**blog**](https://www.lasttowersolutions.com/blog) te besoek.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE bemagtig DevOps, DevSecOps, en developers om Kubernetes clusters doeltreffend te bestuur, te monitor en te beveilig. Benut ons AI-driven insights, advanced security framework, en intuïtiewe CloudMaps GUI om jou clusters te visualiseer, hul toestand te verstaan, en met selfvertroue op te tree.

Verder is K8Studio **versoenbaar met alle groot kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift en meer).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## License & Disclaimer

Kyk daarna in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
