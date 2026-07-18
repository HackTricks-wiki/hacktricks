# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logotipe i motion design za Hacktricks napravio je_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Pokreni HackTricks lokalno
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
Vaša lokalna kopija HackTricks biće dostupna na **[http://localhost:3337](http://localhost:3337)** za manje od 5 minuta (potrebno je da se knjiga izgradi, budite strpljivi).

Alternativno, ako imate Docker Compose, jednostavno pokrenite sledeće iz korena repozitorijuma:
```bash
docker compose up
```
Ovo koristi priloženi `docker-compose.yml` za posluživanje grane koja je trenutno checkout-ovana na hostu na adresi [http://localhost:3337](http://localhost:3337), uz live reload. Da biste promenili jezik pri korišćenju Compose-a, checkout-ujte željenu jezičku granu pre pokretanja servisa.

## HackTricks partneri

---

## HackTricks prijatelji

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) je odlična kompanija za cybersecurity čiji je slogan **HACK THE UNHACKABLE**. Sprovode sopstvena istraživanja i razvijaju sopstvene hacking alate kako bi **ponudili nekoliko vrednih cybersecurity usluga**, kao što su pentesting, Red team angažmani i obuke.

Njihov **blog** možete pogledati na adresi [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** takođe podržava open source cybersecurity projekte kao što je HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** je **etičko hacking i bug bounty platforma broj 1 u Evropi.**

**Bug bounty savet**: **registrujte se** na **Intigriti**, premium **bug bounty platformu koju su napravili hakeri za hakere**! Pridružite nam se danas na adresi [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) i počnite da zarađujete bounty-je u vrednosti do **100.000 USD**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security pruža **praktične AI Security obuke** uz **inženjerski, praktičan pristup zasnovan na laboratorijskim vežbama**. Naši kursevi su namenjeni security inženjerima, AppSec profesionalcima i developerima koji žele da **izgrade, razbiju i zaštite stvarne aplikacije pokretane AI/LLM tehnologijom**.

**AI Security Certification** fokusira se na veštine iz stvarnog sveta, uključujući:
- Zaštitu LLM i AI-powered aplikacija
- Threat modeling za AI sisteme
- Embeddings, vector baze podataka i RAG bezbednost
- LLM napade, scenarije zloupotrebe i praktične odbrane
- Obrasce bezbednog dizajna i aspekte deployment-a

Svi kursevi su **on-demand**, **zasnovani na laboratorijskim vežbama** i osmišljeni oko **bezbednosnih kompromisa iz stvarnog sveta**, a ne samo teorije.

👉 Više detalja o AI Security kursu:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** nudi brze i jednostavne real-time API-je za **pristup rezultatima pretraživača**. Oni scrape-uju pretraživače, upravljaju proxy-jima, rešavaju captcha izazove i parsiraju sve bogate strukturirane podatke umesto vas.

Pretplata na neki od SerpApi planova uključuje pristup za više od 50 različitih API-ja za scraping različitih pretraživača, uključujući Google, Bing, Baidu, Yahoo, Yandex i druge.\
Za razliku od drugih provajdera, **SerpApi ne scrape-uje samo organske rezultate**. SerpApi odgovori dosledno uključuju sve oglase, inline slike i video-snimke, knowledge graph-ove i druge elemente i funkcije prisutne u rezultatima pretrage.

Trenutni SerpApi korisnici uključuju **Apple, Shopify i GrubHub**.\
Za više informacija pogledajte njihov [**blog**](https://serpapi.com/blog/)**,** ili isprobajte primer u njihovom [**playground-u**](https://serpapi.com/playground)**.**\
Možete **kreirati besplatan nalog** [**ovde**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** obučava vas za offensive mobile i AI security, uz predavanja aktivnih istraživača – istog tima koji stoji iza CVE writeup-ova i predavanja na konferencijama Black Hat, HITB i Zer0con. Kursevi se prate sopstvenim tempom, zasnovani su na laboratorijskim vežbama na stvarnim metama i podržani praktičnom sertifikacijom.

Katalog obuhvata dva pravca:

**Mobile Security** – iOS i Android, od nivoa aplikacije naniže: reverse engineering pomoću Ghidra-e i LLDB-a, ARM64 exploitation, kernel internals i moderne mitigacije (PAC, MTE, SELinux), mehanizmi jailbreak-a i root-ovanja.

**AI Security** – dva kompletna kursa koja pokrivaju ovu oblast. Practical AI Security objašnjava kako rade LLM-ovi, RAG pipeline-ovi, AI agenti i MCP, kao i kako ih napadati i braniti. Advanced AI Security je izrazito praktičan i fokusiran na najnovije tehnike: red teaming AI sistema u velikom obimu pomoću alata Garak i PyRIT, exploitovanje MCP servera, postavljanje i detektovanje backdoor-a u modelima, kao i fine-tuning napade i odbrane na Apple Silicon platformi.

Kursevi i sertifikacije:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** je AI-powered security platforma za pronalaženje exploitable ranjivosti pre nego što ih napadači otkriju.

**Savet za code security**: registrujte se na NaxusAI, pametnu platformu za monitoring ranjivosti namenjenu developerima i security timovima! Pridružite nam se danas i počnite da koristite AI za **detektovanje, validaciju i otklanjanje stvarnih security rizika pre nego što dospeju u production**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) je profesionalna cybersecurity kompanija sa sedištem u **Amsterdamu** koja pomaže u **zaštiti** kompanija **širom sveta** od najnovijih cybersecurity pretnji pružanjem **offensive-security usluga** uz **moderan** pristup.

WebSec je internacionalna security kompanija sa kancelarijama u Amsterdamu i Wyomingu. Nude **all-in-one security usluge**, što znači da rade sve: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing i još mnogo toga.

Još jedna zanimljiva stvar u vezi sa WebSec-om jeste to što su, za razliku od proseka u industriji, **veoma sigurni u svoje veštine**, u toj meri da **garantuju rezultate najboljeg kvaliteta**. Na njihovom sajtu piše: "**If we can't hack it, You don't pay it!**". Za više informacija pogledajte njihov [**website**](https://websec.net/en/) i [**blog**](https://websec.net/blog/)!

Pored navedenog, WebSec je i **posvećeni podržavalac HackTricks-a.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Napravljeno za teren. Prilagođeno vama.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) razvija i pruža efikasne cybersecurity obuke koje osmišljavaju i vode
stručnjaci iz industrije. Njihovi programi prevazilaze teoriju i opremaju timove detaljnim
razumevanjem i praktičnim veštinama, koristeći prilagođena okruženja koja odražavaju pretnje
iz stvarnog sveta. Za upite o prilagođenim obukama obratite nam se [**ovde**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Po čemu se njihove obuke izdvajaju:**
* Sadržaj i laboratorijske vežbe izrađeni po meri
* Podrška vrhunskih alata i platformi
* Dizajnirali su ih i predaju ih praktičari

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions pruža specijalizovane cybersecurity usluge obrazovnim i **FinTech**
institucijama, sa fokusom na **penetration testing, cloud security assessments** i
**compliance readiness** (SOC 2, PCI-DSS, NIST). Naš tim uključuje **OSCP i CISSP
sertifikovane profesionalce**, koji svakom angažmanu donose duboku tehničku stručnost i uvid
zasnovan na industrijskim standardima.

Prevazilazimo automatizovane scan-ove pomoću **manualnog, intelligence-driven testiranja**, prilagođenog
okruženjima visokog rizika. Od zaštite evidencija studenata do zaštite finansijskih transakcija,
pomažemo organizacijama da zaštite ono što je najvažnije.

_„Kvalitetna odbrana zahteva poznavanje napada; mi pružamo bezbednost kroz razumevanje.“_

Budite informisani i u toku sa najnovijim dešavanjima u cybersecurity-ju tako što ćete posetiti naš [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE omogućava DevOps, DevSecOps timovima i developerima da efikasno upravljaju, nadgledaju i štite Kubernetes klastere. Iskoristite naše AI-driven uvide, napredni security framework i intuitivni CloudMaps GUI da vizuelizujete svoje klastere, razumete njihovo stanje i pouzdano preduzimate akcije.

Pored toga, K8Studio je **kompatibilan sa svim glavnim Kubernetes distribucijama** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift i drugim).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## Licenca i odricanje odgovornosti

Pogledajte ih ovde:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## GitHub statistika

![HackTricks GitHub statistika](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
