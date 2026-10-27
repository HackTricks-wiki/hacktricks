# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks-logo's en bewegingsontwerp deur_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_.

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

Jou plaaslike kopie van HackTricks sal **beskikbaar wees by [http://localhost:3337](http://localhost:3337)** ná <5 minute (die boek moet bou; wees geduldig).

Alternatiewelik, as jy Docker Compose het, kan jy eenvoudig die volgende vanaf die repo-wortel uitvoer:

```bash
docker compose up
```

Dit gebruik die gebundelde `docker-compose.yml` om die tak wat tans op die gasheer uitgecheck is by [http://localhost:3337](http://localhost:3337) met lewendige herlaai te bedien. Om tale te verander wanneer jy Compose gebruik, check die gewenste taaltak uit voordat jy die diens begin.

## HackTricks-vennote

---

## HackTricks-vriende

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber bied penetrasietoetsing, sekuriteitsoudits, exploit- en navorsingswerk, nutsmiddels en sekuriteitsbewustheidsdienste. Volgens hul webwerf bestaan die span uit penetrasietoetsers, programmeerders en sekuriteitsnavorsers met meer as ’n dekade se ervaring.<sup>[[1]](#references)</sup>

Jy kan hul **blog** hier besoek: [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** ondersteun ook kuberveiligheidsprojekte met oopbron, soos HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti is ’n skaregebaseerde sekuriteitsverskaffer wat bug bounty- en penetrasietoetsingsdienste deur ’n wêreldwye gemeenskap van navorsers aanbied. Sy platform kombineer deurlopende bug bounty-dekking met PTaaS op aanvraag en bestuurde programme vir die openbaarmaking van kwesbaarhede.<sup>[[2]](#references)</sup>

**Bug bounty-wenk**: Sluit by Intigriti aan via [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) en verken sy bug bounty-programme.

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security bied selfstudie, praktiese AI-sekuriteitsopleiding vir sekuriteitsingenieurs, AppSec-professionele persone en ontwikkelaars. Sy AI Security Certification dek die grondbeginsels van LLM en agente, RAG en vektordatabasisse, bedreigingsmodellering, prompt-injection- en MCP-aanvalle, en verdedigende argitektuur.<sup>[[3]](#references)</sup>

👉 Meer besonderhede oor die AI Security-kursus:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bied API’s vir Google en ander soekenjins en lewer gestruktureerde SERP-data met funksies soos liggingbewuste resultate, Maps, Shopping en Knowledge Graph-resultate.<sup>[[4]](#references)</sup>

Besoek hul [**blog**](https://serpapi.com/blog/) vir meer inligting, probeer ’n voorbeeld in hul [**playground**](https://serpapi.com/playground), of [**skep ’n gratis rekening**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** bied selfstudiekursusse in mobiele sekuriteit en AI-sekuriteit. Die katalogus dek ouditering en reversing van mobiele toepassings met nutsmiddels soos Ghidra, Frida en LLDB, asook AI/LLM-aanval- en verdedigingslaboratoriums.<sup>[[5]](#references)[[6]](#references)</sup>

Blaai deur die [8kSec Academy-kursuskatalogus](https://academy.8ksec.io/).

---

### [NaxusAI – AI Powered Security Scanner](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** bemark ’n offensiewe AI-platform wat kode en infrastruktuur karteer en dan statiese en dinamiese agente gebruik om uitbuitbare swakhede met bewys-van-konsep-bewyse en riglyne vir remediëring te vind en te bekragtig.<sup>[[7]](#references)</sup>

**Kode-sekuriteitswenk**: Verken Naxus vir die ontdekking van kwesbaarhede in kode en infrastruktuur.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec bied penetrasietoetsing, sekuriteitsintekeninge, personeelvoorsiening en kwesbaarheidsbeoordelingsdienste. Volgens hul webwerf werk hulle internasionaal en dek hulle offensiewe sekuriteit, verdedigende sekuriteit, asook bestuur, risiko en voldoening.<sup>[[8]](#references)</sup>

Besoek hul [**webwerf**](https://websec.net/en/) of [**blog**](https://websec.net/blog/) vir meer inligting.

Benewens bogenoemde is WebSec ook ’n **toegewyde ondersteuner van HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Gebou vir die veld. Gebou rondom jou.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) bied kuberveiligheidsopleiding onder leiding van kundiges, met pasgemaakte inhoud en laboratoriums wat op werklike infrastruktuur gegrond is. Hul programme word by organisatoriese behoeftes aangepas en strek van assessering tot implementering.<sup>[[9]](#references)</sup> Vir navrae oor pasgemaakte opleiding, kontak hulle [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Wat hul opleiding onderskei:**
* Pasgemaakte inhoud en laboratoriums
* Ondersteun deur topgehalte-nutsmiddels en platforms
* Ontwerp en aangebied deur praktisyns

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions fokus op kuberveiligheidsadvies vir **Onderwys** en **FinTech**, insluitend wolkassesserings, interne en eksterne penetrasietoetse, kwesbaarheidsbeoordelings en voldoeningsondersteuning.<sup>[[10]](#references)</sup>

Bly ingelig en op hoogte van die jongste kuberveiligheidsnuus deur ons [**blog**](https://www.lasttowersolutions.com/blog) te besoek.

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio is ’n Kubernetes-IDE vir rekenaars met CloudMaps-visualisering, multi-klusternavigasie, RBAC, Helm, logs, YAML- en terminaalaansigte. Die verskaffer sê dit koppel via kubeconfig sonder om agente te installeer en ondersteun macOS, Windows, Linux en geïsoleerde klusters.<sup>[[11]](#references)</sup>

---

## Lisensie en vrywaring

Sien die HackTricks Values & FAQ-inskrywing in die verwysings hieronder.

## Github-statistieke

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [AI Security Certification – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Practical AI Security: Attacks, Defenses, and Applications](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Intigriti HackTricks referral](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [WebSec sponsorship video](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cyber Helmets courses](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks Values & FAQ](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
