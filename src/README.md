# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_HackTricks logotipi i motion dizajn autora_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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

Vaša lokalna kopija HackTricks-a biće **dostupna na [http://localhost:3337](http://localhost:3337)** za manje od 5 minuta (potrebno je da se knjiga izgradi, budite strpljivi).

Alternativno, ako imate Docker Compose, možete samo pokrenuti sledeće iz korena repozitorijuma:

```bash
docker compose up
```

Ovo koristi priloženi `docker-compose.yml` da posluži trenutno izabranu granu sa hosta na adresi [http://localhost:3337](http://localhost:3337), uz automatsko osvežavanje. Da biste promenili jezik pri korišćenju Compose-a, izaberite željenu jezičku granu pre pokretanja servisa.

## HackTricks partneri

---

## Prijatelji HackTricks-a

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber pruža usluge testiranja penetracije, bezbednosnih revizija, razvoja exploita i istraživačkog rada, alata i podizanja svesti o bezbednosti. Na njihovom sajtu opisan je tim testera penetracije, programera i istraživača bezbednosti sa više od decenije iskustva.<sup>[[1]](#references)</sup>

Možete pogledati njihov **blog** na adresi [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** takođe podržava projekte otvorenog koda u oblasti sajber bezbednosti, kao što je HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti je pružalac usluga bezbednosti zasnovanih na zajednici, koji nudi bug bounty programe i usluge testiranja penetracije putem globalne zajednice istraživača. Njegova platforma kombinuje kontinuiranu pokrivenost bug bounty programima sa PTaaS uslugama na zahtev i upravljanim programima za prijavljivanje ranjivosti.<sup>[[2]](#references)</sup>

**Bug bounty savet**: Pridružite se Intigriti-ju preko [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) i istražite njihove bug bounty programe.

---

### [Modern Security – Platforma za obuku iz AI i bezbednosti aplikacija](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security nudi samostalnu praktičnu obuku iz AI bezbednosti za bezbednosne inženjere, stručnjake za AppSec i programere. Njihov sertifikat iz AI bezbednosti obuhvata osnove LLM-a i agenata, RAG i vektorske baze podataka, modelovanje pretnji, napade prompt injection i MCP, kao i odbrambenu arhitekturu.<sup>[[3]](#references)</sup>

👉 Više detalja o kursu AI Security:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** pruža API-je za Google i druge pretraživače, koji vraćaju strukturirane SERP podatke sa funkcijama kao što su rezultati prilagođeni lokaciji, Maps, Shopping i Knowledge Graph rezultati.<sup>[[4]](#references)</sup>

Za više informacija pogledajte njihov [**blog**](https://serpapi.com/blog/), isprobajte primer u njihovom [**playground-u**](https://serpapi.com/playground) ili [**napravite besplatan nalog**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – Detaljni kursevi iz bezbednosti mobilnih uređaja i AI-ja](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** nudi samostalne kurseve iz bezbednosti mobilnih uređaja i AI-ja. Katalog obuhvata reviziju i reverse engineering mobilnih aplikacija pomoću alata kao što su Ghidra, Frida i LLDB, kao i laboratorijske vežbe za napade i odbranu u oblasti AI/LLM-a.<sup>[[5]](#references)[[6]](#references)</sup>

Pogledajte [katalog kurseva 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – Autonomna ofanzivna bezbednost](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt="Логотип бренда NaxusAI"><figcaption></figcaption></figure>

**Naxus** je platforma za ofanzivnu bezbednost pokretana AI-jem, namenjena sveobuhvatnom skeniranju spoljne površine napada, revizijama mobilnih aplikacija, black-box testiranju veb-aplikacija i pregledima izvornog koda. Njeni agenti proveravaju nalaze koji se mogu iskoristiti i pružaju dokaze koji se mogu pratiti, proof-of-concept exploite i konkretne preporuke za otklanjanje problema.<sup>[[7]](#references)</sup>

**Savet za bezbednosnu reviziju**: Koristite Naxus za autonomne revizije od početka do kraja, koje obuhvataju spoljne resurse, mobilne aplikacije, veb-aplikacije i izvorni kod.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec pruža usluge testiranja penetracije, bezbednosne pretplate, zapošljavanje stručnjaka i procene ranjivosti. Na njihovom sajtu piše da posluju širom sveta i da se bave ofanzivnom i defanzivnom bezbednošću, kao i upravljanjem, rizikom i usklađenošću.<sup>[[8]](#references)</sup>

Za više informacija posetite njihov [**veb-sajt**](https://websec.net/en/) ili [**blog**](https://websec.net/blog/).

Pored navedenog, WebSec je i **posvećeni podržavalac HackTricks-a.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="Логотип бренда cyberhelmets"><figcaption></figcaption></figure>


**Napravljeno za rad na terenu. Prilagođeno vama.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) pruža obuku iz sajber bezbednosti koju vode stručnjaci, uz posebno osmišljen sadržaj i laboratorijske vežbe zasnovane na stvarnim infrastrukturama. Njihovi programi prilagođeni su potrebama organizacija i obuhvataju sve, od procene do implementacije.<sup>[[9]](#references)</sup> Za upite o prilagođenoj obuci obratite im se [**ovde**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Po čemu se njihova obuka izdvaja:**
* Posebno osmišljen sadržaj i laboratorijske vežbe
* Podrška vrhunskih alata i platformi
* Osmislili su je praktičari, koji je i predaju

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="Логотип бренда lasttower"><figcaption></figcaption></figure>

Last Tower Solutions se bavi savetovanjem u oblasti sajber bezbednosti za **obrazovanje** i **FinTech**, uključujući procene cloud okruženja, interna i eksterna testiranja penetracije, procene ranjivosti i podršku za usklađenost.<sup>[[10]](#references)</sup>

Budite informisani o najnovijim dešavanjima u sajber bezbednosti tako što ćete posetiti naš [**blog**](https://www.lasttowersolutions.com/blog).

---

### [Beaki — Hrana po tvojoj meri](https://www.beaki.app/)

<figure class="sponsor-logo"><img src="images/beaki-logo.png" alt="Логотип бренда Beaki"><figcaption></figcaption></figure>

**Beaki** je personalizovani skener hrane, brojač kalorija i alat za praćenje ishrane. Skenirajte bar-kodove i police u prodavnicama, fotografišite ili opišite obroke i jelovnike restorana i dobijte objašnjive ocene prilagođene vašim ciljevima, načinu ishrane, alergijama i zdravstvenom profilu. Beaki prati i kalorije i makronutrijente, kao i pravi personalizovane planove obroka sa spiskovima za kupovinu.<sup>[[11]](#references)</sup>

[**Besplatno preuzmite Beaki**](https://www.beaki.app/?utm_source=hacktricks&utm_medium=partner&utm_campaign=hacktricks) za Android ili iPhone.

---

## Licenca i odricanje od odgovornosti

Pogledajte stavku HackTricks Values & FAQ u odeljku References ispod.

## GitHub statistika

![Статистика пројекта HackTricks на GitHub-у](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [Sertifikat iz AI Security – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Praktična AI bezbednost: napadi, odbrane i primene](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [Beaki](https://www.beaki.app/)
- [12] [Intigriti HackTricks preporuka](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Video o sponzorstvu WebSec-a](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Kursevi Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [Vrednosti i česta pitanja o HackTricks-u](welcome/hacktricks-values-and-faq.md)

{{#include banners/hacktricks-training.md}}
