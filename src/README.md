# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logotipe i motion design za HackTricks izradio je_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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

Ako imate Docker Compose, možete jednostavno da pokrenete sledeće iz korena repozitorijuma:

```bash
docker compose up
```

Ovo koristi priloženi `docker-compose.yml` da posluži granu koja je trenutno checkout-ovana na hostu na adresi [http://localhost:3337](http://localhost:3337), uz live reload. Da biste promenili jezik kada koristite Compose, checkout-ujte željenu jezičku granu pre pokretanja servisa.

## HackTricks partneri

---

## HackTricks prijatelji

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber pruža usluge penetration testinga, bezbednosnih audita, rada na exploitima i istraživanju, alate i usluge za podizanje svesti o bezbednosti. Na njihovom sajtu se navodi da tim čine penetration testeri, programeri i istraživači bezbednosti sa više od decenije iskustva.<sup>[[1]](#references)</sup>

Možete pogledati njihov **blog** na adresi [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** takođe podržava open-source projekte iz oblasti sajber-bezbednosti, kao što je HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti je crowdsourced pružalac usluga bezbednosti koji preko globalne zajednice istraživača nudi bug bounty i penetration-testing usluge. Njihova platforma objedinjuje kontinuirano bug bounty pokriće, PTaaS na zahtev i upravljane programe za prijavu ranjivosti.<sup>[[2]](#references)</sup>

**Bug bounty savet**: Pridružite se Intigriti preko [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) i istražite njihove bug bounty programe.

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security nudi samostalne, praktične obuke iz AI bezbednosti za bezbednosne inženjere, AppSec stručnjake i programere. Njihova AI Security Certification obuhvata osnove LLM-a i agenata, RAG i vektorske baze podataka, threat modeling, prompt-injection i MCP napade i odbrambenu arhitekturu.<sup>[[3]](#references)</sup>

👉 Više informacija o kursu AI Security:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** pruža API-je za Google i druge pretraživače, vraćajući strukturirane SERP podatke sa funkcijama kao što su rezultati prilagođeni lokaciji, Maps, Shopping i Knowledge Graph.<sup>[[4]](#references)</sup>

Za više informacija pogledajte njihov [**blog**](https://serpapi.com/blog/), isprobajte primer u njihovom [**playground-u**](https://serpapi.com/playground) ili [**napravite besplatan nalog**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** nudi samostalne kurseve iz oblasti mobilne i AI bezbednosti. Katalog obuhvata auditovanje i reverse engineering mobilnih aplikacija pomoću alata kao što su Ghidra, Frida i LLDB, kao i laboratorije za AI/LLM napade i odbranu.<sup>[[5]](#references)[[6]](#references)</sup>

Pogledajte [katalog kurseva 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – Autonomous Offensive Security](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt="NaxusAI logo"><figcaption></figcaption></figure>

**Naxus** je platforma za ofanzivnu bezbednost zasnovana na AI-ju, namenjena potpunom skeniranju spoljne attack surface, auditima mobilnih aplikacija, black-box testiranju web aplikacija i pregledima izvornog koda. Njeni agenti potvrđuju nalaze koji se mogu iskoristiti i pružaju proverljive dokaze, proof-of-concept exploite i praktične preporuke za otklanjanje problema.<sup>[[7]](#references)</sup>

**Savet za bezbednosni audit**: Koristite Naxus za autonomne audite od početka do kraja, koji obuhvataju spoljne resurse, mobilne aplikacije, web aplikacije i izvorni kod.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec pruža penetration testing, bezbednosne pretplatničke usluge, kadrovska rešenja i procene ranjivosti. Na njihovom sajtu se navodi da posluju na međunarodnom nivou i pokrivaju ofanzivnu bezbednost, odbrambenu bezbednost i upravljanje, rizike i usklađenost.<sup>[[8]](#references)</sup>

Za više informacija posetite njihov [**sajt**](https://websec.net/en/) ili [**blog**](https://websec.net/blog/).

Pored navedenog, WebSec je i **posvećeni podržavalac HackTricks-a.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Namenjeno terenskom radu. Prilagođeno vama.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) pruža obuke iz sajber-bezbednosti koje vode stručnjaci, sa prilagođenim sadržajem i laboratorijama zasnovanim na stvarnoj infrastrukturi. Njihovi programi prilagođeni su potrebama organizacija i obuhvataju sve, od procene do implementacije.<sup>[[9]](#references)</sup> Za upite o prilagođenim obukama, obratite se [**ovde**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Po čemu se njihove obuke izdvajaju:**
* Prilagođen sadržaj i laboratorije
* Podrška vrhunskih alata i platformi
* Kreiraju ih i vode stručnjaci iz prakse

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions se bavi savetovanjem o sajber-bezbednosti za oblasti **obrazovanja** i **FinTech-a**, uključujući procene cloud okruženja, interne i eksterne penetration testove, procene ranjivosti i podršku za usklađenost.<sup>[[10]](#references)</sup>

Budite informisani o najnovijim dešavanjima u sajber-bezbednosti tako što ćete posetiti naš [**blog**](https://www.lasttowersolutions.com/blog).

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio je desktop IDE za Kubernetes sa vizualizacijom CloudMaps, navigacijom kroz više klastera, RBAC-om, Helm-om, logovima, YAML-om i prikazima terminala. Prema navodima proizvođača, povezuje se putem kubeconfig-a bez instaliranja agenata i podržava macOS, Windows, Linux i klastere bez mrežne veze.<sup>[[11]](#references)</sup>

---

## Licenca i odricanje od odgovornosti

Pogledajte članak HackTricks Values & FAQ u odeljku References ispod.

## Github statistika

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [Sertifikacija AI Security – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
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
