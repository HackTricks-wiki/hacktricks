# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logotipi i motion design od_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Pokreni HackTricks lokalno
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
Your local copy of HackTricks će biti **dostupan na [http://localhost:3337](http://localhost:3337)** nakon <5 minutes (treba da izgradi knjigu, budite strpljivi).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) je odlična cybersecurity kompanija čiji je slogan **HACK THE UNHACKABLE**. Oni rade sopstvena istraživanja i razvijaju sopstvene hacking alate kako bi **ponudili nekoliko vrednih cybersecurity usluga** kao što su pentesting, Red teams i obuka.

Možete pogledati njihov **blog** na [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** takođe podržava open source cybersecurity projekte kao što je HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** je **Europe's #1** ethical hacking i **bug bounty platform.**

**Bug bounty tip**: **registrujte se** za **Intigriti**, premium **bug bounty platform created by hackers, for hackers**! Pridružite nam se na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) danas, i počnite da zarađujete nagrade do **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Pridružite se [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) serveru da biste komunicirali sa iskusnim hackerima i bug bounty hunterima!

- **Hacking Insights:** Uključite se u sadržaj koji istražuje uzbuđenje i izazove hackinga
- **Real-Time Hack News:** Budite u toku sa brzim hacking svetom kroz vesti i uvide u realnom vremenu
- **Latest Announcements:** Budite informisani o najnovijim bug bounty programima i važnim ažuriranjima platforme

**Pridružite nam se na** [**Discord**](https://discord.com/invite/N3FrSbmwdy) i počnite da sarađujete sa vrhunskim hackerima danas!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security pruža **praktičnu AI Security obuku** sa **engineering-first, hands-on lab** pristupom. Naši kursevi su napravljeni za security inženjere, AppSec profesionalce i developere koji žele da **grade, razbijaju i štite stvarne AI/LLM-powered aplikacije**.

**AI Security Certification** se fokusira na veštine iz stvarnog sveta, uključujući:
- Zaštitu LLM i AI-powered aplikacija
- Threat modeling za AI sisteme
- Embeddings, vector databases, i RAG security
- LLM attacks, abuse scenarios, i praktične odbrane
- Sigurne design obrasce i razmatranja pri deployment-u

Svi kursevi su **on-demand**, **lab-driven**, i dizajnirani oko **real-world security tradeoffs**, ne samo teorije.

👉 Više detalja o AI Security kursu:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** nudi brze i jednostavne real-time API-je za **pristup rezultatima search engine-a**. Oni scrape-uju search engine-e, upravljaju proxy-ima, rešavaju captchas i parsiraju sve bogate strukturirane podatke za vas.

Pretplata na jedan od SerpApi planova uključuje pristup za više od 50 različitih API-ja za scraping različitih search engine-a, uključujući Google, Bing, Baidu, Yahoo, Yandex i druge.\
Za razliku od drugih provajdera, **SerpApi ne scrape-uje samo organic rezultate**. SerpApi odgovori dosledno uključuju sve oglase, inline slike i videe, knowledge graphs i druge elemente i funkcije prisutne u rezultatima pretrage.

Trenutni SerpApi korisnici uključuju **Apple, Shopify i GrubHub**.\
Za više informacija pogledajte njihov [**blog**](https://serpapi.com/blog/)**,** ili isprobajte primer u njihovom [**playground**](https://serpapi.com/playground)**.**\
Možete **napraviti besplatan nalog** [**ovde**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Naučite tehnologije i veštine potrebne za vulnerability research, penetration testing, i reverse engineering kako biste zaštitili mobilne aplikacije i uređaje. **Ovladajte iOS i Android security** kroz naše on-demand kurseve i **dobijte sertifikat**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) je profesionalna cybersecurity kompanija sa sedištem u **Amsterdamu** koja pomaže u **zaštiti** biznisa **širom sveta** od najnovijih cybersecurity pretnji pružajući **offensive-security services** sa **modernim** pristupom.

WebSec je međunarodna security kompanija sa kancelarijama u Amsterdamu i Wyomingu. Nude **all-in-one security services** što znači da rade sve; Pentesting, **Security** Audite, Awareness obuke, Phishing kampanje, Code Review, Exploit Development, Security Experts Outsourcing i mnogo više.

Još jedna cool stvar kod WebSec-a je da, za razliku od proseka u industriji, WebSec ima **veliko poverenje u svoje veštine**, do te mere da **garantuju najbolji kvalitet rezultata**, a na njihovom sajtu piše "**If we can't hack it, You don't pay it!**". Za više informacija pogledajte njihov [**website**](https://websec.net/en/) i [**blog**](https://websec.net/blog/)!

Pored navedenog, WebSec je takođe i **posvećen supporter HackTricks-a.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Napravljen za teren. Napravljen oko vas.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) razvija i isporučuje efikasnu cybersecurity obuku napravljenu i vođenu od strane
industry eksperata. Njihovi programi idu dalje od teorije kako bi opremili timove dubokim
razumevanjem i primenljivim veštinama, koristeći custom okruženja koja odražavaju stvarne
pretnje. Za upite o custom obuci, javite nam se [**ovde**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Šta izdvaja njihovu obuku:**
* Custom-built sadržaj i laboratorije
* Podržano top-tier alatima i platformama
* Dizajnirano i predavano od strane praktičara

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions pruža specijalizovane cybersecurity usluge za institucije iz oblasti **Education** i **FinTech**
, sa fokusom na **penetration testing, cloud security assessments**, i
**compliance readiness** (SOC 2, PCI-DSS, NIST). Naš tim uključuje **OSCP i CISSP
sertifikovane profesionalce**, koji donose duboku tehničku ekspertizu i industrijski standardan uvid u
svaki angažman.

Idemo dalje od automatizovanih skenova uz **ručno, intelligence-driven testiranje** prilagođeno
okruženjima visokog rizika. Od zaštite studentskih podataka do zaštite finansijskih transakcija,
pomažemo organizacijama da brane ono što je najvažnije.

_“Kvalitetna odbrana zahteva poznavanje napada, mi pružamo sigurnost kroz razumevanje.”_

Budite informisani i u toku sa najnovijim iz sveta cybersecurity-a posetom našem [**blogu**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE osnažuje DevOps, DevSecOps i developere da efikasno upravljaju, nadgledaju i obezbeđuju Kubernetes klastere. Iskoristite naše AI-driven uvide, napredni security framework i intuitivni CloudMaps GUI da vizuelizujete svoje klastere, razumete njihovo stanje i delujete sa sigurnošću.

Pored toga, K8Studio je **kompatibilan sa svim glavnim kubernetes distribucijama** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift i druge).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## License & Disclaimer

Pogledajte ih na:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
