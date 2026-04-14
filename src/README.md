# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks-logo's & motion-ontwerp deur_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Jou plaaslike kopie van HackTricks sal **beskikbaar wees by [http://localhost:3337](http://localhost:3337)** na <5 minute (dit moet die boek bou, wees geduldig).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) is 'n uitstekende kuberveiligheidsmaatskappy waarvan die leuse **HACK THE UNHACKABLE** is. Hulle doen hul eie navorsing en ontwikkel hul eie hacking tools om **verskeie waardevolle kuberveiligheidsdienste** aan te bied soos pentesting, Red teams en opleiding.

Jy kan hul **blog** by [**https://blog.stmcyber.com**](https://blog.stmcyber.com) nagaan

**STM Cyber** ondersteun ook oopbron-kuberveiligheidsprojekte soos HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** is Europa se **#1** etiese hacking- en **bug bounty platform.**

**Bug bounty wenk**: **teken in** vir **Intigriti**, 'n premium **bug bounty platform geskep deur hackers, vir hackers**! Sluit vandag by ons aan by [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks), en begin om bounties tot **$100,000** te verdien!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Sluit aan by die [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy)-bediener om met ervare hackers en bug bounty hunters te kommunikeer!

- **Hacking Insights:** Raak betrokke by inhoud wat die opwinding en uitdagings van hacking ondersoek
- **Real-Time Hack News:** Bly op datum met die vinnige hacking-wêreld deur intydse nuus en insigte
- **Latest Announcements:** Bly ingelig oor die nuutste bug bounties wat lanseer en belangrike platform-opdaterings

**Sluit by ons aan op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security lewer **praktiese AI Security-opleiding** met 'n **engineering-first, hands-on lab-benadering**. Ons kursusse is gebou vir sekuriteitsingenieurs, AppSec-professionals en ontwikkelaars wat wil **bou, breek en werklike AI/LLM-aangedrewe toepassings beveilig**.

Die **AI Security Certification** fokus op werklike vaardighede, insluitend:
- Beveiliging van LLM- en AI-aangedrewe toepassings
- Threat modeling vir AI-stelsels
- Embeddings, vector databases, en RAG-sekuriteit
- LLM attacks, misbruik-scenario's, en praktiese verdedigings
- Veilige ontwerp-patrone en ontplooiingsoorwegings

Alle kursusse is **op aanvraag**, **lab-gedrewe**, en ontwerp rondom **werklike sekuriteitsafwegings**, nie net teorie nie.

👉 Meer besonderhede oor die AI Security-kursus:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bied vinnige en maklike intydse APIs om **search engine results** te verkry. Hulle scrape search engines, hanteer proxies, los captchas op, en ontleed alle ryk gestruktureerde data vir jou.

'n Intekening op een van SerpApi se planne sluit toegang in tot meer as 50 verskillende APIs vir die scrapen van verskillende search engines, insluitend Google, Bing, Baidu, Yahoo, Yandex, en meer.\
Anders as ander verskaffers, **scrape SerpApi nie net organiese resultate nie**. SerpApi responses sluit konsekwent alle ads, inline images en videos, knowledge graphs, en ander elemente en kenmerke in wat in die search results teenwoordig is.

Huidige SerpApi-klante sluit **Apple, Shopify, en GrubHub** in.\
Vir meer inligting kyk na hul [**blog**](https://serpapi.com/blog/)**,** of probeer 'n voorbeeld in hul [**playground**](https://serpapi.com/playground)**.**\
Jy kan **'n gratis rekening skep** [**hier**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Leer die tegnologieë en vaardighede wat nodig is om vulnerability research, penetration testing, en reverse engineering uit te voer om mobiele toepassings en toestelle te beskerm. **Bemeester iOS en Android security** deur ons kursusse op aanvraag en **kry gesertifiseer**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) is 'n professionele kuberveiligheidsmaatskappy gebaseer in **Amsterdam** wat help om besighede **oor die hele wêreld** te **beskerm** teen die nuutste kuberveiligheidsdreigemente deur **offensive-security services** met 'n **moderne** benadering te verskaf.

WebSec is 'n internasionale sekuriteitsmaatskappy met kantore in Amsterdam en Wyoming. Hulle bied **all-in-one security services** wat beteken hulle doen alles; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing en nog baie meer.

Nog 'n koel ding van WebSec is dat, anders as die bedryfsgemiddeld, WebSec **baie selfversekerd is in hul vaardighede**, tot so 'n mate dat hulle **die beste gehalte resultate waarborg**, dit staan op hul webwerf "**If we can't hack it, You don't pay it!**". Vir meer inligting kyk na hul [**website**](https://websec.net/en/) en [**blog**](https://websec.net/blog/)!

Benewens bogenoemde is WebSec ook 'n **toegewydde ondersteuner van HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Gebou vir die veld. Gebou rondom jou.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) ontwikkel en lewer effektiewe kuberveiligheidsopleiding wat deur bedryfskenners gebou en gelei word. Hul programme gaan verder as teorie om spanne toe te rus met diep begrip en uitvoerbare vaardighede, deur pasgemaakte omgewings te gebruik wat werklike dreigemente weerspieël. Vir pasgemaakte opleidingsnavrae, kontak ons [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Wat hul opleiding onderskei:**
* Pasgemaakte inhoud en labs
* Gesteun deur topvlak tools en platforms
* Ontwerp en aangebied deur praktisyns

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions lewer gespesialiseerde kuberveiligheidsdienste vir **Onderwys**- en **FinTech**-instellings, met 'n fokus op **penetration testing, cloud security assessments**, en
**compliance readiness** (SOC 2, PCI-DSS, NIST). Ons span sluit **OSCP- en CISSP
gesertifiseerde professionele persone** in, wat diep tegniese kundigheid en bedryfstandaard-insig na
elke betrokkenheid bring.

Ons gaan verder as geoutomatiseerde skanderings met **handmatige, intelligence-driven testing** wat aangepas is vir
hoë-insette omgewings. Van die beveiliging van studenterekords tot die beskerming van finansiële transaksies,
help ons organisasies om te verdedig wat die meeste saak maak.

_“'n Kwaliteitverdediging vereis om die offensief te ken, ons voorsien sekuriteit deur begrip.”_

Bly ingelig en op datum met die nuutste in kuberveiligheid deur ons [**blog**](https://www.lasttowersolutions.com/blog) te besoek.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE bemagtig DevOps, DevSecOps, en ontwikkelaars om Kubernetes clusters doeltreffend te bestuur, monitor en beveilig. Maak gebruik van ons AI-gedrewe insigte, gevorderde sekuriteitsraamwerk, en intuïtiewe CloudMaps GUI om jou clusters te visualiseer, hul toestand te verstaan, en met selfvertroue op te tree.

Verder is K8Studio **versoenbaar met alle groot kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

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
