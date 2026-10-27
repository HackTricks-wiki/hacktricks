# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logotipi Hacktricks-a i motion dizajn:_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Pokrenite HackTricks lokalno

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

Vaša lokalna kopija HackTricks biće **dostupna na [http://localhost:3337](http://localhost:3337)** za manje od 5 minuta (potrebno je da se knjiga izgradi, budite strpljivi).

Ako imate Docker Compose, možete jednostavno pokrenuti sledeće iz korena repozitorijuma:

```bash
docker compose up
```

Ovo koristi priloženi `docker-compose.yml` za posluživanje grane koja je trenutno checkout-ovana na hostu na adresi [http://localhost:3337](http://localhost:3337), uz live reload. Da biste promenili jezik pri korišćenju Compose-a, checkout-ujte željenu jezičku granu pre pokretanja servisa.

## HackTricks partneri

---

## HackTricks prijatelji

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber pruža usluge penetration testinga, bezbednosnih provera, razvoja exploita i istraživanja, alate i usluge podizanja svesti o bezbednosti. Na njihovom sajtu opisan je tim penetration testera, programera i bezbednosnih istraživača sa više od decenije iskustva.<sup>[[1]](#references)</sup>

Njihov **blog** možete pogledati na adresi [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** takođe podržava open-source projekte iz oblasti sajber bezbednosti kao što je HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti je pružalac crowdsourced bezbednosnih usluga koji putem globalne zajednice istraživača nudi bug bounty i penetration-testing usluge. Njihova platforma objedinjuje kontinuirano bug bounty pokriće sa PTaaS uslugama na zahtev i upravljanim programima za prijavu ranjivosti.<sup>[[2]](#references)</sup>

**Bug bounty savet**: Pridružite se Intigriti-ju putem [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) i istražite njihove bug bounty programe.

---

### [Modern Security – Platforma za obuku iz AI i bezbednosti aplikacija](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security nudi samostalnu, praktičnu obuku iz AI bezbednosti za bezbednosne inženjere, AppSec stručnjake i programere. Njihova AI Security Certification obuhvata osnove LLM-a i agenata, RAG i vektorske baze podataka, modelovanje pretnji, prompt-injection i MCP napade i odbrambenu arhitekturu.<sup>[[3]](#references)</sup>

👉 Više detalja o kursu AI Security:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** pruža API-je za Google i druge pretraživače, vraćajući strukturirane SERP podatke sa funkcijama kao što su rezultati prilagođeni lokaciji, Maps, Shopping i Knowledge Graph rezultati.<sup>[[4]](#references)</sup>

Više informacija potražite na njihovom [**blogu**](https://serpapi.com/blog/), isprobajte primer u njihovom [**playground-u**](https://serpapi.com/playground) ili [**napravite besplatan nalog**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – Detaljni kursevi iz mobilne i AI bezbednosti](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** nudi samostalne kurseve iz mobilne i AI bezbednosti. Katalog obuhvata audit i reverse engineering mobilnih aplikacija pomoću alata kao što su Ghidra, Frida i LLDB, kao i AI/LLM laboratorije za napade i odbranu.<sup>[[5]](#references)[[6]](#references)</sup>

Pogledajte [katalog kurseva 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – bezbednosni skener pokretan AI-jem](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** predstavlja platformu za ofanzivni AI koja mapira kod i infrastrukturu, a zatim koristi statičke i dinamičke agente za pronalaženje i proveru iskoristivih slabosti, uz dokaze u vidu proof-of-concept primera i smernice za otklanjanje problema.<sup>[[7]](#references)</sup>

**Savet za bezbednost koda**: Istražite Naxus za otkrivanje ranjivosti u kodu i infrastrukturi.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec pruža usluge penetration testinga, bezbednosne pretplate, kadrovske usluge i procenu ranjivosti. Na njihovom sajtu navode da posluju na međunarodnom nivou i da pokrivaju ofanzivnu i defanzivnu bezbednost, kao i upravljanje, rizike i usklađenost.<sup>[[8]](#references)</sup>

Više informacija potražite na njihovom [**veb-sajtu**](https://websec.net/en/) ili [**blogu**](https://websec.net/blog/).

Pored navedenog, WebSec je i **posvećeni podržavalac HackTricks-a.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Namenjeno terenu. Prilagođeno vama.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) pruža obuku iz sajber bezbednosti koju vode stručnjaci, uz namenski kreiran sadržaj i laboratorije zasnovane na stvarnim infrastrukturama. Njihovi programi prilagođeni su potrebama organizacija i obuhvataju sve, od procene do implementacije.<sup>[[9]](#references)</sup> Za upite o prilagođenoj obuci obratite im se [**ovde**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Po čemu se njihova obuka izdvaja:**
* Namenski kreiran sadržaj i laboratorije
* Podrška vrhunskih alata i platformi
* Osmislili su je i vode praktičari

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions usredsređen je na savetovanje u oblasti sajber bezbednosti za **obrazovanje** i **FinTech**, uključujući procene cloud okruženja, interne i eksterne penetration testove, procene ranjivosti i podršku za usklađenost.<sup>[[10]](#references)</sup>

Budite informisani o najnovijim dešavanjima u sajber bezbednosti i pratite naš [**blog**](https://www.lasttowersolutions.com/blog).

---

### [K8Studio - Pametniji GUI za upravljanje Kubernetes-om.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio je desktop IDE za Kubernetes sa vizualizacijom CloudMaps, navigacijom kroz više klastera, RBAC-om, Helm-om, logovima, YAML-om i prikazima terminala. Dobavljač navodi da se povezuje putem kubeconfig-a bez instaliranja agenata i da podržava macOS, Windows, Linux i izolovane klastere bez mrežne veze.<sup>[[11]](#references)</sup>

---

## Licenca i odricanje od odgovornosti

Pogledajte unos HackTricks Values & FAQ u odeljku References ispod.

## Github statistika

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [AI Security Certification – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Praktična AI bezbednost: napadi, odbrane i primene](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Intigriti HackTricks preporuka](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Video o sponzorstvu WebSec-a](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Kursevi Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [Vrednosti i česta pitanja o HackTricks-u](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
