# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks-logo's en bewegingsontwerp deur_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Laat HackTricks plaaslik loop

```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks

# Select the language you want to use
export HT_LANG="master" # Leave master for English
# "af" for Afrikaans
# "de" for German
# "el" for Greek
# "es" for Spanish
# "fr" for French
# "hi" for Hindi
# "it" for Italian
# "ja" for Japanese
# "ko" for Korean
# "pl" for Polish
# "pt" for Portuguese
# "sr" for Serbian
# "sw" for Swahili
# "tr" for Turkish
# "uk" for Ukrainian
# "vi" for Vietnamese
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```

Jou plaaslike kopie van HackTricks sal ná <5 minute **beskikbaar wees by [http://localhost:3337](http://localhost:3337)** (die boek moet gebou word, wees geduldig).

Alternatiewelik, as jy Docker Compose het, kan jy eenvoudig die volgende vanaf die repo-wortel uitvoer:

```bash
docker compose up
```

Dit gebruik die gebundelde `docker-compose.yml` om die tak wat tans op die gasheer uitgecheck is, met live reload by [http://localhost:3337](http://localhost:3337) te bedien. Om tale te verander wanneer jy Compose gebruik, check die verlangde taaltak uit voordat jy die diens begin.

## HackTricks-vennote

---

## HackTricks-vriende

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber bied penetrasietoetsing, sekuriteitsoudits, exploit- en navorsingswerk, nutsmiddels en sekuriteitsbewustheidsdienste. Die webwerf beskryf ’n span penetrasietoetsers, programmeerders en sekuriteitsnavorsers met meer as ’n dekade se ervaring.<sup>[[1]](#references)</sup>

Jy kan hul **blog** by [**https://blog.stmcyber.com**](https://blog.stmcyber.com) besoek.

**STM Cyber** ondersteun ook open source-kubersekuriteitsprojekte soos HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti is ’n crowdsourced-sekuriteitsverskaffer wat bug bounty- en penetrasietoetsingsdienste deur ’n wêreldwye gemeenskap van navorsers aanbied. Die platform kombineer deurlopende bug bounty-dekking met PTaaS op aanvraag en bestuurde kwesbaarheidsopenbaarmakingsprogramme.<sup>[[2]](#references)</sup>

**Bug bounty-wenk**: Sluit by Intigriti aan via [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) en verken sy bug bounty-programme.

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security bied selfgerigte, praktiese AI-sekuriteitsopleiding vir sekuriteitsingenieurs, AppSec-professionele persone en ontwikkelaars. Sy AI Security Certification dek die grondbeginsels van LLMs en agents, RAG en vektordatabasisse, bedreigingsmodellering, prompt-injection- en MCP-aanvalle, en verdedigende argitektuur.<sup>[[3]](#references)</sup>

👉 Meer besonderhede oor die AI Security-kursus:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bied APIs vir Google en ander soekenjins en lewer gestruktureerde SERP-data met kenmerke soos ligginggebaseerde resultate, Maps, Shopping en Knowledge Graph-resultate.<sup>[[4]](#references)</sup>

Vir meer inligting, besoek hul [**blog**](https://serpapi.com/blog/), probeer ’n voorbeeld in hul [**playground**](https://serpapi.com/playground), of [**skep ’n gratis rekening**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** bied selfgerigte kursusse oor mobiele en AI-sekuriteit. Die kursuskatalogus dek ouditering en reversing van mobiele toepassings met nutsmiddels soos Ghidra, Frida en LLDB, asook AI/LLM-aanval- en verdedigingslaboratoriums.<sup>[[5]](#references)[[6]](#references)</sup>

Blaai deur die [8kSec Academy-kursuskatalogus](https://academy.8ksec.io/).

---

### [NaxusAI – Autonomous Offensive Security](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt="NaxusAI logo"><figcaption></figcaption></figure>

**Naxus** is ’n AI-aangedrewe offensiewe-sekuriteitsplatform vir volledige eksterne aanvaloppervlakskanderings, oudits van mobiele apps, web black-box-toetsing en bronkodehersienings. Sy agents valideer uitbuitbare bevindings en lewer naspeurbare bewyse, proof-of-concept-exploits en uitvoerbare remediëringsaanbevelings.<sup>[[7]](#references)</sup>

**Sekuriteitsouditwenk**: Gebruik Naxus vir end-tot-end outonome oudits van eksterne bates, mobiele apps, webapps en bronkode.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec bied penetrasietoetsing, sekuriteitsintekeninge, personeelvoorsiening en kwesbaarheidsbeoordelingsdienste. Volgens sy webwerf doen dit internasionaal sake en dek dit offensiewe sekuriteit, defensiewe sekuriteit en werk oor governance, risk en compliance.<sup>[[8]](#references)</sup>

Vir meer inligting, besoek hul [**webwerf**](https://websec.net/en/) of [**blog**](https://websec.net/blog/).

Benewens bogenoemde is WebSec ook ’n **toegewyde ondersteuner van HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Gebou vir die veld. Om jou behoeftes te pas.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) bied kubersekuriteitsopleiding onder leiding van kundiges, met pasgemaakte inhoud en laboratoriums gegrond op werklike infrastruktuur. Die programme word volgens organisatoriese behoeftes aangepas en strek van assessering tot implementering.<sup>[[9]](#references)</sup> Vir navrae oor pasgemaakte opleiding, kontak hulle [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Wat hul opleiding onderskei:**
* Pasgemaakte inhoud en laboratoriums
* Ondersteun deur topgehalte-nutsmiddels en -platforms
* Ontwerp en aangebied deur praktisyns

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions fokus op kubersekuriteitskonsultasie vir **onderwys** en **FinTech**, insluitend wolkassesserings, interne en eksterne penetrasietoetse, kwesbaarheidsbeoordelings en ondersteuning met voldoening.<sup>[[10]](#references)</sup>

Bly ingelig en op hoogte van die jongste nuus in kubersekuriteit deur ons [**blog**](https://www.lasttowersolutions.com/blog) te besoek.

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio is ’n Kubernetes-IDE vir rekenaars met CloudMaps-visualisering, navigasie tussen verskeie clusters, RBAC, Helm, logs, YAML- en terminaalaansigte. Die verskaffer sê dit koppel via kubeconfig sonder om agents te installeer en ondersteun macOS, Windows, Linux en geïsoleerde clusters.<sup>[[11]](#references)</sup>

---

## Lisensie en vrywaring

Sien die HackTricks Values & FAQ-inskrywing in die verwysings hieronder.

## Github-statistieke

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [AI-sekuriteitsertifisering – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Praktiese AI-sekuriteit: Aanvalle, verdediging en toepassings](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Intigriti HackTricks-verwysing](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [WebSec-borgskapvideo](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cyber Helmets-kursusse](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks-waardes en FAQ](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
