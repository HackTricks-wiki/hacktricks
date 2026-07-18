# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logotipe i motion design za HackTricks izradio_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Pokrenite HackTricks lokalno
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
Vaša lokalna kopija HackTricks biće dostupna na adresi [http://localhost:3337](http://localhost:3337) za manje od 5 minuta (potrebno je da se knjiga izgradi, budite strpljivi).

Ako imate Docker Compose, možete jednostavno pokrenuti sledeće iz korena repozitorijuma:
```bash
docker compose up
```
Ovo koristi priloženi `docker-compose.yml` da posluži vaš lokalni checkout na adresi [http://localhost:3337](http://localhost:3337) uz live reload.

## HackTricks Partneri

---

## HackTricks Prijatelji

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) je odlična kompanija za cybersecurity čiji je slogan **HACK THE UNHACKABLE**. Sprovode sopstvena istraživanja i razvijaju sopstvene hacking alate kako bi **ponudili nekoliko vrednih cybersecurity usluga**, kao što su pentesting, Red teams i obuka.

Njihov **blog** možete pogledati na adresi [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** takođe podržava open source projekte iz oblasti cybersecurity-ja, kao što je HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** je **etički hacking i bug bounty platforma broj 1 u Evropi.**

**Bug bounty savet**: **registrujte se** na **Intigriti**, premium **bug bounty platformu koju su napravili hakeri za hakere**! Pridružite nam se danas na adresi [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) i počnite da zarađujete nagrade do **100.000 $**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security pruža **praktičnu AI Security obuku** sa pristupom koji je usmeren na **engineering** i praktičan rad u lab okruženju. Naši kursevi su namenjeni security inženjerima, AppSec profesionalcima i developerima koji žele da **izgrade, razbiju i zaštite stvarne AI/LLM aplikacije**.

**AI Security Certification** se fokusira na veštine iz stvarnog sveta, uključujući:
- Zaštitu LLM i AI aplikacija
- Threat modeling za AI sisteme
- Embeddings, vector baze podataka i RAG security
- LLM napade, scenarije zloupotrebe i praktične odbrane
- Obrasce secure dizajna i razmatranja pri deployment-u

Svi kursevi su **dostupni na zahtev**, zasnovani na **lab vežbama** i osmišljeni oko **stvarnih bezbednosnih kompromisa**, a ne samo teorije.

👉 Više detalja o AI Security kursu:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** nudi brze i jednostavne API-je u realnom vremenu za **pristup rezultatima pretraživača**. Oni scrape-uju pretraživače, upravljaju proxy-jima, rešavaju captche i parsiraju sve bogate strukturirane podatke umesto vas.

Pretplata na jedan od SerpApi planova uključuje pristup za više od 50 različitih API-ja za scraping različitih pretraživača, uključujući Google, Bing, Baidu, Yahoo, Yandex i druge.\
Za razliku od drugih provajdera, **SerpApi ne scrape-uje samo organske rezultate**. SerpApi odgovori dosledno uključuju sve oglase, inline slike i video-snimke, knowledge graph-ove i druge elemente i funkcije prisutne u rezultatima pretrage.

Među trenutnim SerpApi korisnicima su **Apple, Shopify i GrubHub**.\
Za više informacija pogledajte njihov [**blog**](https://serpapi.com/blog/)**,** ili isprobajte primer u njihovom [**playground-u**](https://serpapi.com/playground)**.**\
Možete **kreirati besplatan nalog** [**ovde**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – Detaljni kursevi iz Mobile & AI Security oblasti](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** obučava vas za ofanzivnu mobile i AI security oblast, uz predavanja aktivnih istraživača – istog tima koji stoji iza CVE writeup-ova i predavanja na konferencijama Black Hat, HITB i Zer0con. Kursevi se odvijaju sopstvenim tempom, zasnovani su na labovima sa stvarnim metama i podržani praktičnom sertifikacijom.

Katalog obuhvata dva pravca:

**Mobile Security** – iOS i Android, od nivoa aplikacije naniže: reverse engineering uz Ghidra i LLDB, ARM64 exploitation, kernel internals i moderne mitigacije (PAC, MTE, SELinux), mehanizmi jailbreak-a i rootovanja.

**AI Security** – dva kompletna kursa koja pokrivaju ovu oblast. Practical AI Security objašnjava kako rade LLM-ovi, RAG pipeline-ovi, AI agenti i MCP, kao i kako ih napasti i zaštititi. Advanced AI Security je usmeren na intenzivnu praktičnu izgradnju na granici mogućnosti: red teaming AI sistema u velikom obimu uz Garak i PyRIT, exploitation MCP servera, postavljanje i otkrivanje model backdoor-a, kao i fine-tuning napade i odbrane na Apple Silicon-u.

Kursevi i sertifikacije:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** je AI-powered security platforma za pronalaženje exploitable ranjivosti pre nego što ih napadači otkriju.

**Savet za code security**: registrujte se na NaxusAI, pametnu platformu za monitoring ranjivosti namenjenu developerima i security timovima! Pridružite nam se danas i počnite da koristite AI za **otkrivanje, validaciju i otklanjanje stvarnih security rizika pre nego što dospeju u produkciju**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) je profesionalna cybersecurity kompanija sa sedištem u **Amsterdamu**, koja pomaže **u zaštiti** kompanija **širom sveta** od najnovijih cybersecurity pretnji pružanjem **offensive-security usluga** uz **moderan** pristup.

WebSec je međunarodna security kompanija sa kancelarijama u Amsterdamu i Wyomingu. Nude **all-in-one security usluge**, što znači da rade sve: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Outsourcing Security Experts i još mnogo toga.

Još jedna zanimljiva stvar u vezi sa WebSec-om jeste to što je, za razliku od proseka u industriji, WebSec **veoma siguran u svoje veštine**, u tolikoj meri da **garantuje rezultate najboljeg kvaliteta**. Na njihovom sajtu piše: "**If we can't hack it, You don't pay it!**". Za više informacija pogledajte njihovu [**web-stranicu**](https://websec.net/en/) i [**blog**](https://websec.net/blog/)!

Pored navedenog, WebSec je i **posvećeni podržavalac HackTricks-a.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Napravljeno za teren. Prilagođeno vama.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) razvija i pruža efikasnu cybersecurity obuku koju kreiraju i vode
stručnjaci iz industrije. Njihovi programi prevazilaze teoriju i opremaju timove dubokim
razumevanjem i praktičnim veštinama, uz korišćenje prilagođenih okruženja koja odražavaju pretnje iz stvarnog sveta. Za upite o prilagođenoj obuci obratite nam se [**ovde**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Po čemu se njihova obuka izdvaja:**
* Sadržaj i labovi napravljeni po meri
* Podrška vrhunskih alata i platformi
* Dizajnirali i predaju praktičari

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions pruža specijalizovane cybersecurity usluge institucijama iz oblasti **obrazovanja** i **FinTech-a**, sa fokusom na **penetration testing, cloud security assessments** i
**spremnost za usklađenost** (SOC 2, PCI-DSS, NIST). Naš tim čine **OSCP i CISSP
sertifikovani profesionalci**, koji svakom angažmanu donose duboko tehničko znanje i uvid u standarde industrije.

Prevazilazimo automatizovane skenove uz **ručno testiranje zasnovano na obaveštajnim podacima**, prilagođeno
okruženjima visokog rizika. Od zaštite evidencija studenata do zaštite finansijskih transakcija,
pomažemo organizacijama da odbrane ono što je najvažnije.

_„Kvalitetna odbrana zahteva poznavanje napada; mi pružamo sigurnost kroz razumevanje.“_

Budite informisani i u toku sa najnovijim dešavanjima u cybersecurity-ju tako što ćete posetiti naš [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - Pametniji GUI za upravljanje Kubernetes-om.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE omogućava DevOps, DevSecOps timovima i developerima da efikasno upravljaju, nadgledaju i štite Kubernetes klastere. Iskoristite naše AI-driven uvide, napredni security framework i intuitivni CloudMaps GUI da vizualizujete svoje klastere, razumete njihovo stanje i delujete sa sigurnošću.

Pored toga, K8Studio je **kompatibilan sa svim glavnim kubernetes distribucijama** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift i drugim).

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

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
