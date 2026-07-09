# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logotipi i motion dizajn by_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Vaša lokalna kopija HackTricks-a biće **dostupna na [http://localhost:3337](http://localhost:3337)** nakon <5 minuta (potrebno je da se knjiga izgradi, budite strpljivi).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) je sjajna kompanija za sajber bezbednost čiji je slogan **HACK THE UNHACKABLE**. Oni sprovode sopstvena istraživanja i razvijaju sopstvene hacking alate kako bi **pružili nekoliko vrednih sajber bezbednosnih usluga** kao što su pentesting, Red teams i obuka.

Možete pogledati njihov **blog** na [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** takođe podržava projekte otvorenog koda za sajber bezbednost kao što je HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** je **evropska broj 1** platforma za etičko hakovanje i **bug bounty platforma.**

**Bug bounty savet**: **prijavite se** za **Intigriti**, premium **bug bounty platformu koju su napravili hakeri, za hakere**! Pridružite nam se danas na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) i počnite da zarađujete nagrade do **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Pridružite se [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) serveru da biste komunicirali sa iskusnim hakerima i bug bounty hunterima!

- **Hacking Insights:** Uključite se u sadržaj koji istražuje uzbuđenje i izazove hakovanja
- **Real-Time Hack News:** Budite u toku sa brzim svetom hakovanja kroz vesti i uvide u realnom vremenu
- **Latest Announcements:** Budite informisani o najnovijim bug bounty programima koji se pokreću i važnim ažuriranjima platforme

**Pridružite nam se na** [**Discord**](https://discord.com/invite/N3FrSbmwdy) i počnite da sarađujete sa vrhunskim hakerima danas!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security nudi **praktičnu AI Security obuku** sa **engineering-first, hands-on lab pristupom**. Naši kursevi su napravljeni za security inženjere, AppSec profesionalce i developere koji žele da **grade, razbijaju i obezbeđuju prave AI/LLM aplikacije**.

**AI Security Certification** se fokusira na veštine iz stvarnog sveta, uključujući:
- Obezbeđivanje LLM i AI-powered aplikacija
- Threat modeling za AI sisteme
- Embeddings, vector databases i RAG security
- LLM attacks, abuse scenarios i praktične odbrane
- Bezbedne dizajn obrasce i aspekte implementacije

Svi kursevi su **on-demand**, **lab-driven** i dizajnirani oko **stvarnih bezbednosnih kompromisa**, a ne samo teorije.

👉 Više detalja o AI Security kursu:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** nudi brze i jednostavne real-time API-je za **pristup rezultatima pretrage**. Oni scrape-uju search engine-ove, rukuju proxy-ima, rešavaju captcha-e i parsiraju sve bogate strukturirane podatke za vas.

Pretplata na jedan od SerpApi planova uključuje pristup za više od 50 različitih API-ja za scraping različitih search engine-ova, uključujući Google, Bing, Baidu, Yahoo, Yandex i druge.\
Za razliku od drugih provajdera, **SerpApi ne scrape-uje samo organske rezultate**. SerpApi odgovori dosledno uključuju sve oglase, inline slike i video zapise, knowledge graph-ove i druge elemente i funkcije prisutne u rezultatima pretrage.

Trenutni SerpApi klijenti uključuju **Apple, Shopify i GrubHub**.\
Za više informacija pogledajte njihov [**blog**](https://serpapi.com/blog/)**,** ili isprobajte primer u njihovom [**playground**](https://serpapi.com/playground)**.**\
Možete **napraviti besplatan nalog** [**ovde**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** vas obučava u ofanzivnoj mobile i AI security oblasti, uz predavanja aktivnih istraživača – istog tima iza CVE writeup-ova i predavanja na Black Hat, HITB i Zer0con. Kursevi su self-paced, zasnovani na labovima na stvarnim metama, i podržani praktičnom sertifikacijom.

Katalog ima dve staze:

**Mobile Security** – iOS i Android od app layer-a nadole: reverse engineering sa Ghidra i LLDB, ARM64 exploitation, kernel internals i moderne mitigacije (PAC, MTE, SELinux), jailbreak i rooting mehanizmi.

**AI Security** – dva kompletna kursa koji pokrivaju celu oblast. Practical AI Security objašnjava kako rade LLM-ovi, RAG pipeline-ovi, AI agenti i MCP, i kako ih napasti i braniti. Advanced AI Security ide dublje i više ka build-heavy pristupu na granici: red teaming AI sistema u velikom obimu sa Garak i PyRIT, exploitation MCP servera, postavljanje i otkrivanje model backdoor-ova, i attack i defense fine-tuning na Apple Silicon.

Kursevi i sertifikacije:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** je AI-powered sigurnosna platforma za pronalaženje iskorišćivih ranjivosti pre nego što to urade napadači.

**Code security tip**: prijavite se za NaxusAI, pametnu platformu za praćenje ranjivosti napravljenu za developere i security timove! Pridružite nam se danas i počnite da koristite AI za **otkrivanje, validaciju i popravljanje stvarnih bezbednosnih rizika pre nego što stignu u production**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) je profesionalna kompanija za sajber bezbednost sa sedištem u **Amsterdamu** koja pomaže u **zaštiti** biznisa **širom sveta** od najnovijih sajber pretnji pružanjem **offensive-security usluga** sa **modernim** pristupom.

WebSec je međunarodna kompanija za bezbednost sa kancelarijama u Amsterdamu i Vajomingu. Nude **all-in-one security services**, što znači da rade sve; Pentesting, **Security** audite, awareness treninge, phishing kampanje, code review, exploit development, outsourcing security eksperata i mnogo više.

Još jedna sjajna stvar kod WebSec-a je to što, za razliku od industrijskog proseka, WebSec je **veoma siguran u svoje veštine**, do te mere da **garantuju najbolje rezultate**, a na njihovom sajtu piše "**If we can't hack it, You don't pay it!**". Za više informacija pogledajte njihov [**website**](https://websec.net/en/) i [**blog**](https://websec.net/blog/)!

Pored navedenog, WebSec je takođe **posvećen podržavalac HackTricks-a.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) razvija i isporučuje efikasnu obuku za sajber bezbednost, izrađenu i vođenu od strane
stručnjaka iz industrije. Njihovi programi idu dalje od teorije i opremaju timove dubokim
razumevanjem i primenljivim veštinama, koristeći prilagođena okruženja koja odražavaju pretnje
iz stvarnog sveta. Za upite o prilagođenoj obuci, obratite nam se [**ovde**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Šta izdvaja njihovu obuku:**
* Prilagođen sadržaj i labovi
* Podržano vrhunskim alatima i platformama
* Osmišljeno i predavano od strane praktičara

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions pruža specijalizovane usluge sajber bezbednosti za institucije iz oblasti **obrazovanja** i **FinTech**
sektora, sa fokusom na **penetration testing, procene cloud bezbednosti** i
**usklađenost** (SOC 2, PCI-DSS, NIST). Naš tim uključuje **OSCP i CISSP
sertifikovane profesionalce**, koji unose duboku tehničku ekspertizu i uvid po industrijskim standardima u
svaki angažman.

Idemo dalje od automatizovanih skenova uz **ručno, intelligence-driven testiranje** prilagođeno
okruženjima visokog rizika. Od zaštite studentskih evidencija do zaštite finansijskih transakcija,
pomažemo organizacijama da odbrane ono što je najvažnije.

_“Kvalitetna odbrana zahteva poznavanje napada, mi pružamo bezbednost kroz razumevanje.”_

Budite informisani i u toku sa najnovijim vestima iz sajber bezbednosti posetom našem [**blogu**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE osnažuje DevOps, DevSecOps i developere da efikasno upravljaju, nadgledaju i obezbeđuju Kubernetes klastere. Iskoristite naše AI-driven uvide, napredni bezbednosni framework i intuitivni CloudMaps GUI da vizualizujete svoje klastere, razumete njihovo stanje i delujete sa samopouzdanjem.

Pored toga, K8Studio je **kompatibilan sa svim glavnim kubernetes distribucijama** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift i više).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## License & Disclaimer

Pogledajte ih u:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
