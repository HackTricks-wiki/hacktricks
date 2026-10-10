# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logotipe i motion dizajn za Hacktricks izradio je_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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

Vaša lokalna kopija HackTricks biće **dostupna na [http://localhost:3337](http://localhost:3337)** za manje od 5 minuta (potrebno je da se knjiga izgradi, budite strpljivi).

Ako imate Docker Compose, možete jednostavno pokrenuti sledeće iz korena repozitorijuma:

```bash
docker compose up
```

Ovo koristi priloženi `docker-compose.yml` za posluživanje grane koja je trenutno aktivna na hostu, na adresi [http://localhost:3337](http://localhost:3337), uz automatsko osvežavanje. Da biste promenili jezik pri korišćenju Compose-a, pre pokretanja servisa pređite na željenu jezičku granu.

## HackTricks Partneri

---

## HackTricks Prijatelji

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber pruža usluge penetration testinga, bezbednosnih revizija, razvoja exploita i istraživanja, alate i usluge za podizanje bezbednosne svesti. Na njihovom sajtu se navodi da tim čine penetration testeri, programeri i istraživači bezbednosti sa više od decenije iskustva.<sup>[[1]](#references)</sup>

Pogledajte njihov **blog** na adresi [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** takođe podržava projekte otvorenog koda u oblasti sajber-bezbednosti, kao što je HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti je pružalac crowdsourced bezbednosnih usluga koji nudi bug bounty i penetration testing usluge putem globalne zajednice istraživača. Njegova platforma objedinjuje kontinuirano bug bounty pokriće, PTaaS na zahtev i upravljane programe za prijavu ranjivosti.<sup>[[2]](#references)</sup>

**Bug bounty savet**: Pridružite se Intigriti-ju preko [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) i istražite njihove bug bounty programe.

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security nudi praktičnu obuku iz AI bezbednosti sopstvenim tempom za bezbednosne inženjere, AppSec stručnjake i programere. Njihova AI Security Certification obuhvata osnove LLM-a i agenata, RAG i vektorske baze podataka, modelovanje pretnji, prompt-injection i MCP napade, kao i odbrambenu arhitekturu.<sup>[[3]](#references)</sup>

👉 Više detalja o kursu AI Security:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** pruža API-je za Google i druge pretraživače, koji vraćaju strukturirane SERP podatke sa funkcijama kao što su rezultati prilagođeni lokaciji, Maps, Shopping i Knowledge Graph.<sup>[[4]](#references)</sup>

Za više informacija pogledajte njihov [**blog**](https://serpapi.com/blog/), isprobajte primer u njihovom [**playground-u**](https://serpapi.com/playground) ili [**napravite besplatan nalog**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** nudi kurseve iz bezbednosti mobilnih sistema i AI-ja koje možete pohađati sopstvenim tempom. Katalog obuhvata reviziju i reverse engineering mobilnih aplikacija pomoću alata kao što su Ghidra, Frida i LLDB, kao i laboratorijske vežbe za napade i odbranu u oblasti AI/LLM-a.<sup>[[5]](#references)[[6]](#references)</sup>

Pogledajte [katalog kurseva 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – AI Powered Security Scanner](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** reklamira platformu za ofanzivni AI koja mapira kod i infrastrukturu, a zatim koristi statičke i dinamičke agente za pronalaženje i proveru iskoristivih slabosti, uz dokaze u vidu proof-of-concept primera i smernice za njihovo otklanjanje.<sup>[[7]](#references)</sup>

**Savet za bezbednost koda**: Istražite Naxus za pronalaženje ranjivosti u kodu i infrastrukturi.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec pruža usluge penetration testinga, bezbednosne pretplate, kadrovske usluge i procene ranjivosti. Na njihovom sajtu se navodi da posluju na međunarodnom nivou i da pokrivaju ofanzivnu bezbednost, odbrambenu bezbednost i upravljanje, rizik i usklađenost.<sup>[[8]](#references)</sup>

Za više informacija posetite njihovu [**veb-stranicu**](https://websec.net/en/) ili [**blog**](https://websec.net/blog/).

Pored navedenog, WebSec je i **posvećeni podržavalac HackTricks-a.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Stvorena za rad na terenu. Stvorena oko vas.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) pruža obuku iz sajber-bezbednosti koju vode stručnjaci, uz namenski izrađene sadržaje i laboratorijske vežbe zasnovane na stvarnoj infrastrukturi. Njihovi programi prilagođeni su potrebama organizacije i obuhvataju sve, od procene do implementacije.<sup>[[9]](#references)</sup> Za upite o prilagođenoj obuci obratite se [**ovde**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Po čemu se njihova obuka izdvaja:**
* Namenski izrađeni sadržaji i laboratorijske vežbe
* Podržana vrhunskim alatima i platformama
* Osmislili su je i vode praktičari

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions se bavi savetovanjem o sajber-bezbednosti za sektore **obrazovanja** i **FinTech-a**, uključujući procene cloud okruženja, interne i eksterne penetration testove, procene ranjivosti i podršku za usklađenost.<sup>[[10]](#references)</sup>

Budite informisani o najnovijim dešavanjima u sajber-bezbednosti tako što ćete posetiti naš [**blog**](https://www.lasttowersolutions.com/blog).

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio je desktop IDE za Kubernetes sa vizualizacijom CloudMaps, navigacijom kroz više klastera, RBAC-om, Helm-om, prikazom logova, YAML-a i terminala. Dobavljač navodi da se povezuje preko kubeconfig-a bez instaliranja agenata i da podržava macOS, Windows, Linux i izolovane klastere bez pristupa mreži.<sup>[[11]](#references)</sup>

---

## Licenca i odricanje od odgovornosti

Pogledajte stavku HackTricks Values & FAQ u odeljku References ispod.

## Github statistika

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [Sertifikacija iz AI bezbednosti – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
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
- [16] [HackTricks Values & FAQ](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
