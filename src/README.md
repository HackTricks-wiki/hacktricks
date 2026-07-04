# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logoi i motion dizajn od_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Vaša lokalna kopija HackTricks biće **dostupna na [http://localhost:3337](http://localhost:3337)** nakon <5 minuta (potrebno je da se knjiga izgradi, budite strpljivi).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) je odlična kompanija za sajber bezbednost čiji je slogan **HACK THE UNHACKABLE**. Oni sprovode sopstvena istraživanja i razvijaju sopstvene hacking alate kako bi **ponudili nekoliko vrednih usluga sajber bezbednosti** kao što su pentesting, Red teams i obuka.

Možete pogledati njihov **blog** na [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** takođe podržava open source projekte za sajber bezbednost kao što je HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** je **broj 1 u Evropi** za ethical hacking i **bug bounty platforma.**

**Bug bounty savet**: **registrujte se** na **Intigriti**, premium **bug bounty platformu kreiranu od strane hakera, za hakere**! Pridružite nam se danas na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) i počnite da zarađujete nagrade do **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Pridružite se [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) serveru da komunicirate sa iskusnim hakerima i bug bounty hunterima!

- **Hacking Insights:** Angažujte se sa sadržajem koji se bavi uzbuđenjem i izazovima hackinga
- **Real-Time Hack News:** Ostanite u toku sa brzim tempom hacking sveta kroz vesti i uvide u realnom vremenu
- **Latest Announcements:** Budite informisani o najnovijim bug bounty programima i važnim ažuriranjima platforme

**Pridružite nam se na** [**Discord**](https://discord.com/invite/N3FrSbmwdy) i počnite da sarađujete sa vrhunskim hakerima već danas!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security pruža **praktičnu AI Security obuku** sa **engineering-first, hands-on lab pristupom**. Naši kursevi su napravljeni za security inženjere, AppSec profesionalce i developere koji žele da **izgrade, slome i obezbede stvarne AI/LLM-powered aplikacije**.

**AI Security Certification** je fokusiran na veštine iz stvarnog sveta, uključujući:
- Obezbeđivanje LLM i AI-powered aplikacija
- Threat modeling za AI sisteme
- Embeddings, vector databases i RAG security
- LLM attacks, abuse scenarije i praktične odbrane
- Bezbedne design patterns i razmatranja pri deploymentu

Svi kursevi su **na zahtev**, **vođeni laboratorijom**, i dizajnirani oko **stvarnih bezbednosnih kompromisa**, a ne samo teorije.

👉 Više detalja o AI Security kursu:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** nudi brze i jednostavne real-time API-je za **pristup rezultatima pretrage**. Oni scrape-uju search engine-ove, upravljaju proxyjima, rešavaju captche i parsiraju sve bogate strukturirane podatke umesto vas.

Pretplata na jedan od SerpApi planova uključuje pristup više od 50 različitih API-ja za scrapovanje različitih search engine-ova, uključujući Google, Bing, Baidu, Yahoo, Yandex i druge.\
Za razliku od drugih provajdera, **SerpApi ne scrape-uje samo organske rezultate**. SerpApi odgovori dosledno uključuju sve oglase, inline slike i videe, knowledge graph-ove i druge elemente i funkcije prisutne u rezultatima pretrage.

Trenutni SerpApi korisnici uključuju **Apple, Shopify i GrubHub**.\
Za više informacija pogledajte njihov [**blog**](https://serpapi.com/blog/)**,** ili isprobajte primer u njihovom [**playground**](https://serpapi.com/playground)**.**\
Možete **kreirati besplatan nalog** [**ovde**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Naučite tehnologije i veštine potrebne za vulnerability research, penetration testing i reverse engineering kako biste zaštitili mobilne aplikacije i uređaje. **Savladajte iOS i Android security** kroz naše kurseve na zahtev i **dobijte sertifikat**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** je AI-powered security platforma za pronalaženje exploitable vulnerability pre nego što to urade napadači.

**Code security savet**: registrujte se na NaxusAI, pametnu platformu za praćenje vulnerability namenjenu developerima i security timovima! Pridružite nam se danas i počnite da koristite AI za **detektovanje, validaciju i popravljanje stvarnih bezbednosnih rizika pre nego što stignu u production**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) je profesionalna kompanija za sajber bezbednost sa sedištem u **Amsterdamu** koja pomaže u **zaštiti** biznisa **širom sveta** od najnovijih pretnji sajber bezbednosti pružajući **offensive-security usluge** sa **modernim** pristupom.

WebSec je intenationalna security kompanija sa kancelarijama u Amsterdamu i Vajomingu. Nude **all-in-one security services** što znači da rade sve; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing i mnogo više.

Još jedna sjajna stvar kod WebSec-a je to što su, za razliku od proseka u industriji, veoma **samouvereni u svoje veštine**, do te mere da **garantuju najbolji kvalitet rezultata**, a na njihovom sajtu piše "**If we can't hack it, You don't pay it!**". Za više informacija pogledajte njihov [**website**](https://websec.net/en/) i [**blog**](https://websec.net/blog/)!

Pored navedenog, WebSec je takođe **posvećeni podržavalac HackTricks-a.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Napravljen za teren. Napravljen oko vas.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) razvija i isporučuje efikasnu cybersecurity obuku koju grade i vode
stručnjaci iz industrije. Njihovi programi idu dalje od teorije kako bi timovima obezbedili duboko
razumevanje i primenljive veštine, koristeći prilagođena okruženja koja odražavaju pretnje iz stvarnog sveta.
Za upite o prilagođenoj obuci, kontaktirajte nas [**ovde**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Šta izdvaja njihovu obuku:**
* Prilagođen sadržaj i laboratorije
* Potkrepljeno vrhunskim alatima i platformama
* Dizajnirano i predavano od strane praktičara

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions pruža specijalizovane cybersecurity usluge za institucije iz oblasti **obrazovanja** i **FinTech**
sa fokusom na **penetration testing, cloud security assessments**, i
**spremnost za usklađenost** (SOC 2, PCI-DSS, NIST). Naš tim uključuje **OSCP i CISSP
sertifikovane profesionalce**, donoseći duboku tehničku ekspertizu i uvid zasnovan na industrijskim standardima u
svaki angažman.

Idemo dalje od automatizovanih skeniranja sa **manuelnim, inteligencijom vođenim testiranjem** prilagođenim
okruženjima visokih uloga. Od zaštite studentskih evidencija do obezbeđivanja finansijskih transakcija,
pomažemo organizacijama da brane ono što je najvažnije.

_“Kvalitetna odbrana zahteva poznavanje napada, mi obezbeđujemo sigurnost kroz razumevanje.”_

Budite informisani i u toku sa najnovijim u cybersecurity tako što ćete posetiti naš [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE osnažuje DevOps, DevSecOps i developere da efikasno upravljaju, nadgledaju i obezbeđuju Kubernetes klastere. Iskoristite naše AI-driven uvide, napredni security framework i intuitivni CloudMaps GUI da vizualizujete svoje klastere, razumete njihovo stanje i delujete sa sigurnošću.

Takođe, K8Studio je **kompatibilan sa svim glavnim kubernetes distribucijama** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift i druge).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

<!-- hacktricks-friends:friend:friend-carlospolop:start -->
### [HackTricks Books](https://book.hacktricks.wiki/)

<figure class="sponsor-logo"><img src="https://friends.hacktricks.wiki/assets/17181413/5e15e93e6b8523dac2ad.png" alt="HackTricks Books logo"><figcaption></figcaption></figure>

Ovo je tekst za predstavljanje besplatne sajber bezbednosne wiki stranice: <b>Hacktricks Book </b>. Naučite sve vrste hacking trikova besplatno uz nju sada!

{{#ref}}
https://book.hacktricks.wiki/
{{#endref}}

---
<!-- hacktricks-friends:friend:friend-carlospolop:end -->

## License & Disclaimer

Pogledajte ih u:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
