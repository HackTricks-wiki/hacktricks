# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logo i animacija Hacktricks-a od_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Your local copy of HackTricks će biti **dostupan na [http://localhost:3337](http://localhost:3337)** nakon <5 minuta (treba da izgradi knjigu, budite strpljivi).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) je odlična kompanija za sajber bezbednost čiji je slogan **HACK THE UNHACKABLE**. Oni sprovode sopstvena istraživanja i razvijaju sopstvene hacking alate kako bi **ponudili nekoliko vrednih usluga sajber bezbednosti** kao što su pentesting, Red teams i obuke.

Možete proveriti njihov **blog** na [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** takođe podržava open source projekte iz oblasti sajber bezbednosti kao što je HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** je **Evropska #1** platforma za ethical hacking i **bug bounty platforma.**

**Bug bounty tip**: **registrujte se** za **Intigriti**, premium **bug bounty platformu kreiranu od strane hakera, za hakere**! Pridružite nam se danas na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) i počnite da zarađujete nagrade do **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Pridružite se serveru [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) da biste komunicirali sa iskusnim hakerima i bug bounty hunterima!

- **Hacking Insights:** Angažujte se sa sadržajem koji se bavi uzbuđenjem i izazovima hackinga
- **Real-Time Hack News:** Pratite najnovije vesti iz brze hacking sveta kroz vesti i uvide u realnom vremenu
- **Latest Announcements:** Budite u toku sa najnovijim bug bounty programima i važnim ažuriranjima platforme

**Pridružite nam se na** [**Discord**](https://discord.com/invite/N3FrSbmwdy) i počnite danas da sarađujete sa vrhunskim hakerima!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security isporučuje **praktičnu AI Security obuku** sa **engineering-first, hands-on lab pristupom**. Naši kursevi su napravljeni za security inženjere, AppSec profesionalce i developere koji žele da **grade, razbijaju i obezbede realne AI/LLM-pogonjene aplikacije**.

**AI Security Certification** se fokusira na veštine iz stvarnog sveta, uključujući:
- Obezbeđivanje LLM i AI-pogonjenih aplikacija
- Threat modeling za AI sisteme
- Embeddings, vector databases i RAG security
- LLM attacks, abuse scenarije i praktične odbrane
- Bezbedne dizajn obrasce i razmatranja pri deployment-u

Svi kursevi su **on-demand**, **lab-driven**, i dizajnirani oko **real-world security tradeoffs**, ne samo teorije.

👉 Više detalja o AI Security kursu:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** nudi brze i jednostavne real-time API-je za **pristup rezultatima pretrage**. Oni scrape-uju search engine-e, obrađuju proksije, rešavaju captcha-e i parsiraju sve bogate strukturirane podatke za vas.

Pretplata na jedan od SerpApi planova uključuje pristup ka više od 50 različitih API-ja za scraping različitih search engine-a, uključujući Google, Bing, Baidu, Yahoo, Yandex i još mnogo toga.\
Za razliku od drugih provajdera, **SerpApi ne scrape-uje samo organske rezultate**. SerpApi odgovori dosledno uključuju sve oglase, inline slike i video zapise, knowledge graph-ove i druge elemente i funkcije prisutne u rezultatima pretrage.

Trenutni SerpApi korisnici uključuju **Apple, Shopify i GrubHub**.\
Za više informacija pogledajte njihov [**blog**](https://serpapi.com/blog/)**,** ili isprobajte primer u njihovom [**playground-u**](https://serpapi.com/playground)**.**\
Možete **kreirati besplatan nalog** [**ovde**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Naučite tehnologije i veštine potrebne za vulnerability research, penetration testing i reverse engineering kako biste zaštitili mobilne aplikacije i uređaje. **Ovladajte iOS i Android bezbednošću** kroz naše on-demand kurseve i **dobićete sertifikat**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** je AI-pogonjena platforma za bezbednost koja pronalazi exploitable vulnerabilities pre napadača.

**Code security tip**: registrujte se za NaxusAI, pametnu platformu za praćenje ranjivosti napravljenu za developere i security timove! Pridružite nam se danas i počnite da koristite AI za **otkrivanje, validaciju i popravljanje stvarnih bezbednosnih rizika pre nego što stignu u production**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) je profesionalna kompanija za sajber bezbednost sa sedištem u **Amsterdamu** koja pomaže u **zaštiti** biznisa **širom sveta** od najnovijih sajber pretnji pružajući **offensive-security usluge** sa **modernim** pristupom.

WebSec je međunarodna bezbednosna kompanija sa kancelarijama u Amsterdamu i Vajomingu. Nude **all-in-one security services** što znači da rade sve; Pentesting, **Security** audite, awareness obuke, phishing kampanje, code review, exploit development, outsourcing security eksperata i mnogo više.

Još jedna sjajna stvar kod WebSec-a je to što, za razliku od proseka u industriji, WebSec je **veoma siguran u svoje veštine**, do te mere da **garantuju najbolje rezultate kvaliteta**, na njihovom sajtu piše "**If we can't hack it, You don't pay it!**". Za više informacija pogledajte njihov [**website**](https://websec.net/en/) i [**blog**](https://websec.net/blog/)!

Pored navedenog, WebSec je takođe **posvećen podržavalac HackTricks-a.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Napravljeno za teren. Napravljeno oko vas.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) razvija i isporučuje efikasnu obuku iz sajber bezbednosti, kreiranu i vođenu od strane stručnjaka iz industrije. Njihovi programi idu dalje od teorije i opremaju timove dubokim razumevanjem i praktičnim veštinama, koristeći prilagođena okruženja koja odražavaju realne pretnje. Za upite o prilagođenoj obuci, kontaktirajte nas [**ovde**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Šta izdvaja njihovu obuku:**
* Prilagođen sadržaj i laboratorije
* Potpomognuto alatima i platformama vrhunskog nivoa
* Dizajnirano i predavano od strane praktičara

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions pruža specijalizovane usluge sajber bezbednosti za institucije iz oblasti **obrazovanja** i **FinTech-a**, sa fokusom na **penetration testing, cloud security assessments** i
**compliance readiness** (SOC 2, PCI-DSS, NIST). Naš tim uključuje **OSCP i CISSP
sertifikovane profesionalce**, donoseći duboku tehničku ekspertizu i uvid usklađen sa industrijskim standardima u
svaki angažman.

Idemo dalje od automatizovanih skenova sa **manuelnim, intelligence-driven testiranjem** prilagođenim
okruženjima visokog rizika. Od zaštite studentskih zapisa do zaštite finansijskih transakcija,
pomažemo organizacijama da brane ono što je najvažnije.

_“Kvalitetna odbrana zahteva poznavanje napada, mi obezbeđujemo bezbednost kroz razumevanje.”_

Budite informisani i u toku sa najnovijim vestima iz sajber bezbednosti posetom našem [**blogu**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE omogućava DevOps, DevSecOps i developerima da efikasno upravljaju, nadgledaju i obezbeđuju Kubernetes klastere. Iskoristite naše AI-driven uvide, napredni security framework i intuitivni CloudMaps GUI da vizualizujete svoje klastere, razumete njihovo stanje i delujete sa sigurnošću.

Pored toga, K8Studio je **kompatibilan sa svim glavnim kubernetes distribucijama** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift i još mnogo toga).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## License & Disclaimer

Proverite ih na:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
