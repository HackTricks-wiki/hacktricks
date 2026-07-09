# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logo's & motion design deur_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Jou plaaslike kopie van HackTricks sal na <5 minute **beskikbaar wees by [http://localhost:3337](http://localhost:3337)** (dit moet die book bou, wees asseblief geduldig).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) is 'n uitstekende cybersecurity-maatskappy waarvan die leuse **HACK THE UNHACKABLE** is. Hulle doen hul eie navorsing en ontwikkel hul eie hacking tools om **verskeie waardevolle cybersecurity-dienste** soos pentesting, Red teams en training aan te bied.

Jy kan hul **blog** by [**https://blog.stmcyber.com**](https://blog.stmcyber.com) nagaan

**STM Cyber** ondersteun ook cybersecurity open source-projekte soos HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** is Europa se **#1** ethical hacking- en **bug bounty platform.**

**Bug bounty tip**: **teken aan** by **Intigriti**, 'n premium **bug bounty platform geskep deur hackers, vir hackers**! Sluit vandag by ons aan by [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks), en begin bounties verdien tot **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security lewer **praktiese AI Security training** met 'n **engineering-first, hands-on lab-benadering**. Ons kursusse is gebou vir security engineers, AppSec-professionele en developers wat **regte AI/LLM-aangedrewe applications wil bou, breek en beveilig**.

Die **AI Security Certification** fokus op werklike vaardighede, insluitend:
- Beveiliging van LLM- en AI-aangedrewe applications
- Threat modeling vir AI systems
- Embeddings, vector databases, en RAG security
- LLM attacks, misbruikscenario's, en praktiese verdediging
- Veilige ontwerp-patrone en ontplooiingsoorwegings

Alle kursusse is **op aanvraag**, **lab-gedrewe**, en ontwerp rondom **werklike security tradeoffs**, nie net teorie nie.

👉 Meer besonderhede oor die AI Security-kursus:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bied vinnige en maklike intydse APIs om **search engine results te verkry**. Hulle scrape search engines, hanteer proxies, los captchas op, en ontleed al die ryk gestruktureerde data vir jou.

'n Intekening op een van SerpApi se planne sluit toegang in tot meer as 50 verskillende APIs vir scraping van verskillende search engines, insluitend Google, Bing, Baidu, Yahoo, Yandex, en meer.\
Anders as ander verskaffers, **scrape SerpApi nie net organiese resultate nie**. SerpApi responses sluit konsekwent alle ads, inline images en videos, knowledge graphs, en ander elemente en funksies wat in die search results teenwoordig is, in.

Huidige SerpApi-klante sluit **Apple, Shopify, en GrubHub** in.\
Vir meer inligting kyk na hul [**blog**](https://serpapi.com/blog/)**,** of probeer 'n voorbeeld in hul [**playground**](https://serpapi.com/playground)**.**\
Jy kan **'n gratis account skep** [**hier**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** lei jou op in offensive mobile en AI security, aangebied deur aktiewe researchers – dieselfde span agter die CVE-writeups en praatjies by Black Hat, HITB, en Zer0con. Kursusse is self-tempo, gebou rondom labs op regte targets, en ondersteun deur 'n hands-on sertifisering.

Die katalogus loop oor twee spore:

**Mobile Security** – iOS en Android van die app layer af af: reverse engineering met Ghidra en LLDB, ARM64 exploitation, kernel internals en moderne mitigations (PAC, MTE, SELinux), jailbreak en rooting meganika.

**AI Security** – twee volledige kursusse wat die veld dek. Practical AI Security behandel hoe LLMs, RAG pipelines, AI agents en MCP werk, en hoe om hulle aan te val en te verdedig. Advanced AI Security gaan bou-swaar by die voorpunt: red teaming van AI systems op skaal met Garak en PyRIT, exploitation van MCP servers, plant en opspoor van model backdoors, en fine-tuning attacks en verdediging op Apple Silicon.

Kursusse en sertifiseringe:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** is 'n AI-aangedrewe security platform om exploitable vulnerabilities te vind voor attackers dit doen.

**Code security tip**: teken aan by NaxusAI, 'n slim vulnerability monitoring platform gebou vir developers en security teams! Sluit vandag by ons aan en begin AI gebruik vir **opsporing, validasie, en herstel van regte security risks voordat hulle production bereik**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) is 'n professionele cybersecurity-maatskappy gebaseer in **Amsterdam** wat besighede **oor die hele wêreld** help **beskerm** teen die nuutste cybersecurity-bedreigings deur **offensive-security services** met 'n **moderne** benadering te verskaf.

WebSec is 'n internasionale security-maatskappy met kantore in Amsterdam en Wyoming. Hulle bied **all-in-one security services** aan, wat beteken hulle doen alles; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing en nog baie meer.

Nog 'n cool ding van WebSec is dat, anders as die bedryfsgemiddeld, WebSec **baie selfversekerd is in hul vaardighede**, tot so 'n mate dat hulle **die beste kwaliteit resultate waarborg**; dit staan op hul webwerf "**If we can't hack it, You don't pay it!**". Vir meer inligting kyk na hul [**website**](https://websec.net/en/) en [**blog**](https://websec.net/blog/)!

Benewens bogenoemde is WebSec ook 'n **toegewijde ondersteuner van HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Gebou vir die veld. Gebou rondom jou.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) ontwikkel en lewer effektiewe cybersecurity training wat deur
bedryfskenners gebou en gelei word. Hul programme gaan verder as teorie om teams toe te rus met diep
begrip en uitvoerbare vaardighede, met behulp van custom environments wat werklike
bedreigings weerspieël. Vir custom training-navrae, kontak ons [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Wat hul training laat uitstaan:**
* Custom-built content en labs
* Gesteun deur topklas tools en platforms
* Ontwerp en onderrig deur practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions lewer gespesialiseerde cybersecurity-dienste vir **Education** en **FinTech**
instansies, met 'n fokus op **penetration testing, cloud security assessments**, en
**compliance readiness** (SOC 2, PCI-DSS, NIST). Ons span sluit **OSCP en CISSP
gesertifiseerde professionele persone** in, wat diep tegniese kundigheid en bedryfstandaard-insig na
elke betrokkenheid bring.

Ons gaan verder as outomatiese scans met **manual, intelligence-driven testing** wat aangepas is vir
hoë-insette omgewings. Van die beveiliging van studenterekords tot die beskerming van finansiële transaksies,
help ons organisasies om dit wat die meeste saak maak, te verdedig.

_“'n Kwaliteitverdediging vereis om die aanval te ken; ons bied security deur begrip.”_

Bly ingelig en op datum met die nuutste in cybersecurity deur ons [**blog**](https://www.lasttowersolutions.com/blog) te besoek.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE bemagtig DevOps, DevSecOps, en developers om Kubernetes clusters doeltreffend te bestuur, te monitor en te beveilig. Gebruik ons AI-gedrewe insigte, gevorderde security-raamwerk, en intuïtiewe CloudMaps GUI om jou clusters te visualiseer, hul toestand te verstaan, en met selfvertroue op te tree.

Boonop is K8Studio **kompatibel met alle groot kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift en meer).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## License & Disclaimer

Kyk dit na in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
