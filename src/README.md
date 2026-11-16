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

Jou plaaslike kopie van HackTricks sal ná <5 minute **beskikbaar wees by [http://localhost:3337](http://localhost:3337)** (die boek moet eers gebou word; wees geduldig).

As jy Docker Compose het, kan jy ook eenvoudig die volgende vanaf die repo-wortel uitvoer:

```bash
docker compose up
```

Hierdie gebruik die gebundelde `docker-compose.yml` om die tak wat tans op die gasheer uitgecheck is by [http://localhost:3337](http://localhost:3337) met lewendige herlaai te bedien. Om tale te verander wanneer jy Compose gebruik, check die gewenste taaltak uit voordat jy die diens begin.

## HackTricks-vennote

---

## HackTricks-vriende

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber bied penetrasietoetsing, sekuriteitsoudits, exploit- en navorsingswerk, nutsmiddels en sekuriteitsbewustheidsdienste. Die webwerf beskryf ’n span penetrasietoetsers, programmeerders en sekuriteitsnavorsers met meer as ’n dekade se ervaring.<sup>[[1]](#references)</sup>

Jy kan hul **blog** by [**https://blog.stmcyber.com**](https://blog.stmcyber.com) besoek.

**STM Cyber** ondersteun ook kuberveiligheidsprojekte met oop bronkode soos HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti is ’n skarebron-sekuriteitsverskaffer wat bug bounty- en penetrasietoetsingsdienste deur ’n wêreldwye navorsersgemeenskap aanbied. Sy platform kombineer deurlopende bug bounty-dekking met PTaaS op aanvraag en bestuurde programme vir die bekendmaking van kwesbaarhede.<sup>[[2]](#references)</sup>

**Bug bounty-wenk**: Sluit by Intigriti aan via [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) en verken sy bug bounty-programme.

---

### [Modern Security – KI- en toepassingssekuriteitsopleidingsplatform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security bied selfgerigte, praktiese KI-sekuriteitsopleiding vir sekuriteitsingenieurs, AppSec-professionele persone en ontwikkelaars. Die KI-sekuriteitsertifisering dek die grondbeginsels van LLM’s en agente, RAG en vektordatabasisse, bedreigingsmodellering, prompt-injection- en MCP-aanvalle, en verdedigende argitektuur.<sup>[[3]](#references)</sup>

👉 Meer besonderhede oor die KI-sekuriteitskursus:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bied API’s vir Google en ander soekenjins, en lewer gestruktureerde SERP-data met funksies soos liggingbewuste resultate, Maps-, Shopping- en Knowledge Graph-resultate.<sup>[[4]](#references)</sup>

Besoek hul [**blog**](https://serpapi.com/blog/) vir meer inligting, probeer ’n voorbeeld in hul [**speelruimte**](https://serpapi.com/playground), of [**skep ’n gratis rekening**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – Diepgaande mobiele- en KI-sekuriteitskursusse](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** bied selfgerigte kursusse oor mobiele en KI-sekuriteit. Die kursuskatalogus dek ouditering en reverse engineering van mobiele toepassings met nutsmiddels soos Ghidra, Frida en LLDB, asook KI/LLM-aanval- en verdedigingslaboratoriums.<sup>[[5]](#references)[[6]](#references)</sup>

Blaai deur die [8kSec Academy-kursuskatalogus](https://academy.8ksec.io/).

---

### [NaxusAI – Outonome offensiewe sekuriteit](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt="NaxusAI logo"><figcaption></figcaption></figure>

**Naxus** is ’n KI-aangedrewe offensiewe-sekuriteitsplatform vir volledige eksterne aanvaloppervlakte-skanderings, oudits van mobiele toepassings, black-box-toetsing van webtoepassings en bronkode-oorsigte. Sy agente bevestig uitbuitbare bevindings en lewer naspeurbare bewyse, proof-of-concept-exploits en uitvoerbare remediëring.<sup>[[7]](#references)</sup>

**Sekuriteitsouditwenk**: Gebruik Naxus vir end-tot-end outonome oudits van eksterne bates, mobiele toepassings, webtoepassings en bronkode.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec bied penetrasietoetsing, sekuriteitsintekeninge, personeelvoorsiening en kwesbaarheidsbepalingsdienste. Volgens sy webwerf bedryf dit internasionaal en dek dit offensiewe sekuriteit, verdedigende sekuriteit en werk oor bestuur, risiko en nakoming.<sup>[[8]](#references)</sup>

Besoek hul [**webwerf**](https://websec.net/en/) of [**blog**](https://websec.net/blog/) vir meer inligting.

Benewens bogenoemde is WebSec ook ’n **toegewyde ondersteuner van HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Gebou vir die veld. Gebou rondom jou.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) bied kuberveiligheidsopleiding onder leiding van kundiges, met pasgemaakte inhoud en laboratoriums wat op werklike infrastruktuur gegrond is. Die programme word by organisatoriese behoeftes aangepas en strek van assessering tot implementering.<sup>[[9]](#references)</sup> Vir navrae oor pasgemaakte opleiding, kontak hulle [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Wat hul opleiding onderskei:**
* Pasgemaakte inhoud en laboratoriums
* Gesteun deur toonaangewende nutsmiddels en platforms
* Ontwerp en aangebied deur praktisyns

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions fokus op kuberveiligheidskonsultasie vir **Onderwys** en **FinTech**, insluitend wolkassesserings, interne en eksterne penetrasietoetse, kwesbaarheidsbepalings en ondersteuning met nakoming.<sup>[[10]](#references)</sup>

Bly ingelig en op hoogte van die jongste nuus oor kuberveiligheid deur ons [**blog**](https://www.lasttowersolutions.com/blog) te besoek.

---

### [Beaki — Kos wat by jou pas](https://www.beaki.app/)

<figure class="sponsor-logo"><img src="images/beaki-logo.png" alt="Beaki logo"><figcaption></figcaption></figure>

**Beaki** is ’n gepersonaliseerde voedselskandeerder, kalorie-teller en voedingsnaspoorder. Skandeer strepieskodes en supermarkrakke, neem foto’s van of beskryf maaltye en restaurantspyskaarte, en kry verklaarbare tellings wat deur jou doelwitte, dieet, allergieë en gesondheidsprofiel bepaal word. Beaki hou ook kalorieë en makrovoedingstowwe dop en skep gepersonaliseerde maaltydplanne met inkopielyste.<sup>[[11]](#references)</sup>

[**Laai Beaki gratis af**](https://www.beaki.app/?utm_source=hacktricks&utm_medium=partner&utm_campaign=hacktricks) op Android of iPhone.

---

## Lisensie en vrywaring

Sien die HackTricks-waarde- en FAQ-inskrywing in Verwysings hieronder.

## Github-statistieke

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [KI-sekuriteitsertifisering – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Praktiese KI-sekuriteit: Aanvalle, verdediging en toepassings](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [Beaki](https://www.beaki.app/)
- [12] [Intigriti HackTricks-verwysing](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [WebSec-borgskapvideo](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cyber Helmets-kursusse](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks-waardes en FAQ](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
