# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks-logo's en bewegingsontwerp deur_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Laat HackTricks plaaslik loop
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
Jou plaaslike kopie van HackTricks sal **beskikbaar wees by [http://localhost:3337](http://localhost:3337)** ná <5 minute (dit moet die boek bou, wees geduldig).

Alternatiewelik, as jy Docker Compose het, kan jy eenvoudig die volgende vanaf die wortel van die repo uitvoer:
```bash
docker compose up
```
Dit gebruik die ingeslote `docker-compose.yml` om jou plaaslike checkout by [http://localhost:3337](http://localhost:3337) met live reload te bedien.

## HackTricks-vennote

---

## HackTricks-vriende

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) is 'n uitstekende kuberveiligheidsmaatskappy met die slagspreuk **HACK THE UNHACKABLE**. Hulle doen hul eie navorsing en ontwikkel hul eie hacking tools om **verskeie waardevolle kuberveiligheidsdienste aan te bied**, soos pentesting, Red teams en opleiding.

Jy kan hul **blog** by [**https://blog.stmcyber.com**](https://blog.stmcyber.com) lees.

**STM Cyber** ondersteun ook kuberveiligheid-open source-projekte soos HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** is **Europa se nommer 1** etiese hacking- en **bug bounty-platform.**

**Bug bounty-wenk**: **registreer** by **Intigriti**, 'n premium **bug bounty-platform wat deur hackers, vir hackers geskep is**! Sluit vandag by ons aan by [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks), en begin bounties van tot **$100,000** verdien!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security lewer **praktiese AI Security-opleiding** met 'n **engineering-first, hands-on lab-benadering**. Ons kursusse is ontwerp vir security engineers, AppSec-professionele persone en ontwikkelaars wat **werklike AI/LLM-aangedrewe toepassings wil bou, breek en beveilig**.

Die **AI Security Certification** fokus op werklike vaardighede, insluitend:
- Beveiliging van LLM- en AI-aangedrewe toepassings
- Threat modeling vir AI-stelsels
- Embeddings, vector databases en RAG-security
- LLM-aanvalle, misbruikscenario's en praktiese verdediging
- Veilige ontwerppatrone en deployment-oorwegings

Alle kursusse is **on-demand**, **lab-gedrewe** en ontwerp rondom **werklike security tradeoffs**, nie net teorie nie.

👉 Meer besonderhede oor die AI Security-kursus:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bied vinnige en eenvoudige intydse APIs om **toegang tot search engine-resultate te verkry**. Hulle scrape search engines, hanteer proxies, los captchas op en parse al die ryk gestruktureerde data vir jou.

'n Intekening op een van SerpApi se planne sluit toegang tot meer as 50 verskillende APIs in om verskillende search engines te scrape, insluitend Google, Bing, Baidu, Yahoo, Yandex en meer.\
Anders as ander verskaffers, **scrape SerpApi nie net organiese resultate nie**. SerpApi se response sluit konsekwent alle advertensies, inline-beelde en -video's, knowledge graphs en ander elemente en funksies in wat in die search results voorkom.

Huidige SerpApi-kliënte sluit **Apple, Shopify en GrubHub** in.\
Vir meer inligting, besoek hul [**blog**](https://serpapi.com/blog/)**,** of probeer 'n voorbeeld in hul [**playground**](https://serpapi.com/playground)**.**\
Jy kan [**hier**](https://serpapi.com/users/sign_up)** 'n gratis rekening skep.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** lei jou op in offensiewe mobile- en AI-security, aangebied deur aktiewe navorsers – dieselfde span agter die CVE-writeups en praatjies by Black Hat, HITB en Zer0con. Kursusse is self-tempo, gebaseer op labs met werklike teikens en word deur 'n praktiese sertifisering ondersteun.

Die katalogus bestaan uit twee rigtings:

**Mobile Security** – iOS en Android van die app-laag afwaarts: reverse engineering met Ghidra en LLDB, ARM64-exploitation, kernel internals en moderne mitigations (PAC, MTE, SELinux), asook jailbreak- en rooting-meganismes.

**AI Security** – twee volledige kursusse wat die veld dek. Practical AI Security verduidelik hoe LLMs, RAG-pipelines, AI-agents en MCP werk, en hoe om hulle aan te val en te verdedig. Advanced AI Security fokus sterk op bouwerk aan die voorpunt: red teaming van AI-stelsels op skaal met Garak en PyRIT, exploitation van MCP-servers, die plant en opsporing van model-backdoors, asook fine-tuning-aanvalle en -verdediging op Apple Silicon.

Kursusse en sertifiserings:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** is 'n AI-aangedrewe security-platform om exploitable vulnerabilities te vind voordat aanvallers dit doen.

**Code-security-wenk**: registreer by NaxusAI, 'n slim vulnerability-monitoringplatform wat vir ontwikkelaars en security-spanne gebou is! Sluit vandag by ons aan en begin AI gebruik vir **die opsporing, validering en regstelling van werklike security-risks voordat hulle production bereik**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) is 'n professionele kuberveiligheidsmaatskappy gebaseer in **Amsterdam** wat help om besighede **oor die hele wêreld** teen die nuutste kuberveiligheidsbedreigings te **beskerm** deur **offensive-security services** met 'n **moderne** benadering te lewer.

WebSec is 'n internasionale security-maatskappy met kantore in Amsterdam en Wyoming. Hulle bied **all-in-one security services**, wat beteken dat hulle alles doen: pentesting, **security** audits, awareness training, phishing campaigns, code review, exploit development, outsourcing van security experts en nog baie meer.

Nog 'n interessante aspek van WebSec is dat hulle, anders as die bedryfsgemiddelde, **baie selfversekerd in hul vaardighede** is – tot so 'n mate dat hulle **die beste gehalte resultate waarborg**. Dit staan op hul webwerf: "**If we can't hack it, You don't pay it!**". Vir meer inligting, besoek hul [**webwerf**](https://websec.net/en/) en [**blog**](https://websec.net/blog/)!

Benewens bogenoemde is WebSec ook 'n **toegewyde ondersteuner van HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Gebou vir die veld. Gebou rondom jou.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) ontwikkel en lewer effektiewe kuberveiligheidsopleiding wat deur
industriekenners gebou en gelei word. Hul programme gaan verder as teorie om spanne toe te rus met diepgaande
begrip en uitvoerbare vaardighede, deur pasgemaakte omgewings te gebruik wat werklike
bedreigings weerspieël. Vir navrae oor pasgemaakte opleiding, kontak ons [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Wat hul opleiding onderskei:**
* Pasgemaakte inhoud en labs
* Ondersteun deur topvlak-tools en -platforms
* Ontwerp en aangebied deur praktisyns

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions lewer gespesialiseerde kuberveiligheidsdienste aan **Education**- en **FinTech**-
instellings, met 'n fokus op **penetration testing, cloud security assessments** en
**compliance readiness** (SOC 2, PCI-DSS, NIST). Ons span sluit **OSCP- en CISSP-
gesertifiseerde professionele persone** in, wat diepgaande tegniese kundigheid en insig volgens industriestandaarde na
elke opdrag bring.

Ons gaan verder as geoutomatiseerde scans met **manual, intelligence-driven testing** wat aangepas is vir
omgewings met hoë risiko's. Van die beveiliging van studenterekords tot die beskerming van finansiële transaksies,
help ons organisasies om dit wat die belangrikste is, te verdedig.

_“'n Kwaliteitsverdediging vereis kennis van die aanval; ons bied security deur begrip.”_

Bly ingelig en op datum met die nuutste in kuberveiligheid deur ons [**blog**](https://www.lasttowersolutions.com/blog) te besoek.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE stel DevOps-, DevSecOps- en ontwikkelingspanne in staat om Kubernetes-clusters doeltreffend te bestuur, monitor en beveilig. Gebruik ons AI-gedrewe insigte, gevorderde security framework en intuïtiewe CloudMaps GUI om jou clusters te visualiseer, hul toestand te verstaan en met vertroue op te tree.

Boonop is K8Studio **versoenbaar met alle belangrike kubernetes-distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift en meer).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## Lisensie en vrywaring

Lees dit hier:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github-statistieke

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
