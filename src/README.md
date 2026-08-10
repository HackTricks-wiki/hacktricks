# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logotipi HackTricks-a i motion design:_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
Vaša lokalna kopija HackTricks biće dostupna na adresi [http://localhost:3337](http://localhost:3337) za manje od 5 minuta (potrebno je da se knjiga izgradi, budite strpljivi).

Ako imate Docker Compose, alternativno možete samo da pokrenete sledeće iz korena repozitorijuma:
```bash
docker compose up
```
Ovo koristi priloženi `docker-compose.yml` za posluživanje grane koja je trenutno checkout-ovana na hostu na adresi [http://localhost:3337](http://localhost:3337), uz live reload. Da biste promenili jezik prilikom korišćenja Compose-a, checkout-ujte željenu jezičku granu pre pokretanja servisa.

## HackTricks Partneri

---

## HackTricks Prijatelji

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber pruža penetration testing, bezbednosne revizije, exploit i istraživačke usluge, alate i usluge podizanja bezbednosne svesti. Na njihovom sajtu je opisan tim penetration testera, programera i bezbednosnih istraživača sa više od deset godina iskustva.<sup>[[1]](#references)</sup>

Njihov **blog** možete posetiti na adresi [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** takođe podržava open source projekte iz oblasti cybersecurity-ja, kao što je HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti je crowdsourced security provajder koji putem globalne zajednice istraživača nudi bug bounty i penetration-testing usluge. Njihova platforma kombinuje kontinuiranu bug bounty pokrivenost sa PTaaS uslugama na zahtev i upravljanim programima za prijavljivanje ranjivosti.<sup>[[2]](#references)</sup>

**Bug bounty savet**: Pridružite se Intigriti-ju putem adrese [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) i istražite njihove bug bounty programe.

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security nudi praktičnu AI security obuku sopstvenim tempom za security inženjere, AppSec stručnjake i developere. Njihova AI Security Certification obuhvata osnove LLM-ova i agenata, RAG i vektorske baze podataka, threat modeling, prompt-injection i MCP napade, kao i defanzivnu arhitekturu.<sup>[[3]](#references)</sup>

👉 Više detalja o AI Security kursu:
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** pruža API-je za Google i druge pretraživače, vraćajući strukturirane SERP podatke sa funkcijama kao što su rezultati prilagođeni lokaciji, Maps, Shopping i Knowledge Graph rezultati.<sup>[[4]](#references)</sup>

Za više informacija pogledajte njihov [**blog**](https://serpapi.com/blog/), isprobajte primer u njihovom [**playground-u**](https://serpapi.com/playground) ili [**kreirajte besplatan nalog**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** nudi mobile i AI-security kurseve koje možete pratiti sopstvenim tempom. Katalog obuhvata auditing i reverse engineering mobilnih aplikacija pomoću alata kao što su Ghidra, Frida i LLDB, kao i AI/LLM attack i defense laboratorije.<sup>[[5]](#references)[[6]](#references)</sup>

Pogledajte [katalog kurseva 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – AI Powered Security Scanner](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** promoviše offensive-AI platformu koja mapira kod i infrastrukturu, a zatim koristi statičke i dinamičke agente za pronalaženje i validaciju iskoristivih slabosti, uz proof-of-concept dokaze i smernice za sanaciju.<sup>[[7]](#references)</sup>

**Savet za bezbednost koda**: Istražite Naxus za otkrivanje ranjivosti usmereno na kod i infrastrukturu.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec pruža penetration testing, security subscriptions, staffing i usluge procene ranjivosti. Na njihovom sajtu piše da posluju međunarodno i da pokrivaju offensive security, defensive security, kao i poslove iz oblasti governance, risk i compliance.<sup>[[8]](#references)</sup>

Za više informacija posetite njihov [**website**](https://websec.net/en/) ili [**blog**](https://websec.net/blog/).

Pored navedenog, WebSec je i **posvećeni podržavalac HackTricks-a.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Napravljeno za teren. Kreirano prema vašim potrebama.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) pruža cybersecurity obuku koju vode stručnjaci, sa prilagođenim sadržajem i laboratorijama zasnovanim na stvarnim infrastrukturama. Njihovi programi su prilagođeni potrebama organizacija i obuhvataju sve, od procene do implementacije.<sup>[[9]](#references)</sup> Za upite o prilagođenoj obuci obratite im se [**ovde**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Po čemu se njihova obuka izdvaja:**
* Prilagođeni sadržaj i laboratorije
* Podrška vrhunskih alata i platformi
* Kreiraju i predaju je praktičari

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions se fokusira na cybersecurity konsalting za oblasti **obrazovanja** i **FinTech-a**, uključujući procene cloud okruženja, interne i eksterne penetration testove, procene ranjivosti i podršku za compliance.<sup>[[10]](#references)</sup>

Budite informisani i u toku sa najnovijim dešavanjima u cybersecurity-ju tako što ćete posetiti naš [**blog**](https://www.lasttowersolutions.com/blog).

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio je desktop Kubernetes IDE sa CloudMaps vizualizacijom, navigacijom kroz više klastera, RBAC-om, Helm-om, logovima, YAML-om i terminalskim prikazima. Vendor navodi da se povezuje putem kubeconfig-a bez instaliranja agenata i da podržava macOS, Windows, Linux i air-gapped klastere.<sup>[[11]](#references)</sup>

---

## Licenca i odricanje odgovornosti

Pogledajte stavku HackTricks Values & FAQ u odeljku References ispod.

## Github statistika

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [AI Security Certification – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Praktična AI Security: napadi, odbrane i primene](https://academy.8ksec.io/course/practical-ai-security)
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
