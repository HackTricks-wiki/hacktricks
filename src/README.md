# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logotipi i motion dizajn od_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Vaša lokalna kopija HackTricks biće **available at [http://localhost:3337](http://localhost:3337)** za manje od 5 minuta (potrebno je da se knjiga izgradi, budite strpljivi).

## Korporativni sponzori

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) je odlična kompanija za sajber bezbednost čiji je slogan **HACK THE UNHACKABLE**. Oni sprovode sopstvena istraživanja i razvijaju sopstvene hacking alate kako bi **ponudili nekoliko vrednih usluga sajber bezbednosti** kao što su pentesting, Red teams i obuka.

Možete pogledati njihov **blog** na [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** takođe podržava open source projekte iz oblasti sajber bezbednosti poput HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) je najrelevantniji događaj iz oblasti sajber bezbednosti u **Španiji** i jedan od najvažnijih u **Evropi**. Sa **misijom promovisanja tehničkog znanja**, ovaj kongres je vreli susret za profesionalce iz tehnologije i sajber bezbednosti u svim disciplinama.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** je vodeća platforma za ethical hacking i bug bounty u Evropi.

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Pridružite nam se na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) danas i počnite zarađivati nagrade do **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) da lako gradite i **automatizujete workflows** pokretane najnaprednijim alatima iz zajednice.

Get Access Today:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

- **Hacking Insights:** Engage with content that delves into the thrill and challenges of hacking
- **Real-Time Hack News:** Keep up-to-date with fast-paced hacking world through real-time news and insights
- **Latest Announcements:** Stay informed with the newest bug bounties launching and crucial platform updates

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Get a hacker's perspective on your web apps, network, and cloud**

**Find and report critical, exploitable vulnerabilities with real business impact.** Koristite naših 20+ prilagođenih alata da mapirate the attack surface, pronađete sigurnosne probleme koji omogućavaju eskalaciju privilegija, i koristite automated exploits da prikupite ključne dokaze, pretvarajući vaš naporan rad u ubedljive izveštaje.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** nudi brze i jednostavne real-time APIs za pristup rezultatima pretrage. Oni scrape-uju pretraživače, upravljaju proxy-ima, rešavaju captchas, i parsiraju sve bogate strukturirane podatke za vas.

Pretplata na jedan od SerpApi planova uključuje pristup više od 50 različitih API-ja za scraping različitih pretraživača, uključujući Google, Bing, Baidu, Yahoo, Yandex i druge.\
Za razliku od drugih provajdera, **SerpApi ne samo da skrepuje organic results**. Odgovori SerpApi-a dosledno uključuju sve oglase, inline slike i video zapise, knowledge graphs i ostale elemente i funkcije prisutne u rezultatima pretrage.

Među trenutnim SerpApi korisnicima su **Apple, Shopify, i GrubHub**.\
Za više informacija pogledajte njihov [**blog**](https://serpapi.com/blog/)**,** ili isprobajte primer u njihovom [**playground**](https://serpapi.com/playground)**.**\
Možete **kreirati besplatan nalog** [**ovde**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Naučite tehnologije i veštine potrebne za izvođenje vulnerability research, penetration testing, i reverse engineering kako biste zaštitili mobilne aplikacije i uređaje. **Savladajte iOS i Android security** kroz naše on-demand kurseve i **dobijte sertifikat**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) je profesionalna kompanija za sajber bezbednost sa sedištem u **Amsterdamu** koja pomaže u **zaštiti** biznisa **široko po svetu** od najnovijih sajber pretnji pružajući **offensive-security services** sa **modernim** pristupom.

WebSec je internacionalna security kompanija sa kancelarijama u Amsterdamu i Wyoming-u. Oni nude **all-in-one security services** što znači da rade sve; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing i mnogo više.

Još jedna sjajna stvar u vezi sa WebSec je da, za razliku od proseka u industriji, WebSec je **veoma samouveren u svoje veštine**, do te mere da **garantuju najbolje rezultate**, kako stoji na njihovom sajtu "**If we can't hack it, You don't pay it!**". Za više informacija pogledajte njihov [**website**](https://websec.net/en/) i [**blog**](https://websec.net/blog/)!

Pored svega navedenog, WebSec je takođe **posvećeni podržavalac HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) je data breach (leak) search engine. \
Pružamo random string search (kao google) preko svih tipova data leaks velikih i malih --ne samo velikih-- preko podataka iz više izvora. \
People search, AI search, organization search, API (OpenAPI) access, theHarvester integration, sve funkcije koje pentester treba.\
**HackTricks i dalje predstavlja odličnu platformu za učenje za sve nas i ponosni smo što je sponzorišemo!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/courses/?ref=hacktricks) razvija i isporučuje efikasnu cybersecurity obuku kreiranu i vođenu od strane stručnjaka iz industrije. Njihovi programi idu dalje od teorije kako bi opremili timove dubokim razumevanjem i primenljivim veštinama, koristeći prilagođena okruženja koja odražavaju realne pretnje.
Za upite o prilagođenim treninzima, kontaktirajte nas [**ovde**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Šta izdvaja njihovu obuku:**
* Prilagođen sadržaj i laboratorije
* Podržano vrhunskim alatima i platformama
* Dizajnirano i predavano od strane praktičara

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions pruža specijalizovane usluge sajber bezbednosti za **Education** i **FinTech**
institucije, sa fokusom na **penetration testing, cloud security assessments**, i
**compliance readiness** (SOC 2, PCI-DSS, NIST). Naš tim uključuje **OSCP and CISSP
certified professionals**, koji donose duboku tehničku ekspertizu i uvid u industrijske standarde u
svakom angažmanu.

Mi idemo dalje od automatizovanih skeniranja sa **manual, intelligence-driven testing** prilagođenim
za okruženja visokog rizika. Od zaštite studentskih podataka do očuvanja finansijskih transakcija,
pomažemo organizacijama da brane ono što je najvažnije.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Ostanite informisani i u toku sa najnovijim u sajber bezbednosti posetom našem [**blogu**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.jpg" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE omogućava DevOps, DevSecOps i developerima da efikasno upravljaju, nadgledaju i osiguraju Kubernetes klastere. Iskoristite naše AI-driven uvide, napredni security framework i intuitivni CloudMaps GUI da vizualizujete vaše klastere, razumete njihovo stanje i delujete sa samopouzdanjem.

Pored toga, K8Studio je **kompatibilan sa svim glavnim kubernetes distribucijama** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift i više).

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## License & Disclaimer

Proverite ih u:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
