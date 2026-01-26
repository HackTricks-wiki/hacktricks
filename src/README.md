# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logotipi & motion dizajn od_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Vaša lokalna kopija HackTricks biće **dostupna na [http://localhost:3337](http://localhost:3337)** za manje od 5 minuta (mora da izgradi knjigu, budite strpljivi).

## Korporativni sponzori

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) je odlična cybersecurity kompanija čiji je slogan **HACK THE UNHACKABLE**. Sprovode sopstvena istraživanja i razvijaju sopstvene hacking alate da bi ponudili nekoliko vrednih cybersecurity usluga kao što su pentesting, Red teams i obuke.

Možete pogledati njihov **blog** na [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** takođe podržava cybersecurity open source projekte kao što je HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) je najrelevantniji cybersecurity događaj u **Španiji** i jedan od najvažnijih u **Evropi**. Sa **misijom promovisanja tehničkog znanja**, ovaj kongres je ključna tačka susreta za profesionalce iz tehnologije i cybersecurity-a iz svih oblasti.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** je **#1 u Evropi** platforma za ethical hacking i **bug bounty**.

**Saveti za bug bounty**: **prijavite se** na **Intigriti**, premium **bug bounty platformu kreiranu od hakera, za hakere**! Pridružite nam se na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) danas i počnite da zarađujete nagrade do **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) da lako gradite i **automatizujete tokove rada** vođene najnaprednijim alatima zajednice.

Pribavite pristup danas:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

- **Hacking Insights:** Uključite se u sadržaj koji zadire u uzbuđenje i izazove hackinga
- **Real-Time Hack News:** Budite u toku sa brzim svetom hackinga kroz real-time vesti i uvide
- **Latest Announcements:** Ostanite informisani o najnovijim bug bounty programima i važnim ažuriranjima platforme

**Pridružite nam se na** [**Discord**](https://discord.com/invite/N3FrSbmwdy) i počnite da sarađujete sa top hackers već danas!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security pruža **praktičnu AI Security obuku** sa **inženjerski-orijentisanim, hands-on laboratorijskim pristupom**. Naši kursevi su namenjeni security inženjerima, AppSec profesionalcima i developerima koji žele da **prave, razbijaju i osiguravaju stvarne aplikacije pokretane AI/LLM**.

The **AI Security Certification** focuses on real-world skills, including:
- Osiguravanje LLM i AI-pokretanih aplikacija
- Threat modeling za AI sisteme
- Embeddings, vector databases, and RAG security
- LLM attacks, abuse scenarios, and practical defenses
- Secure design patterns and deployment considerations

Svi kursevi su **on-demand**, **lab-driven**, i dizajnirani oko **stvarnih sigurnosnih kompromisa**, ne samo teorije.

👉 Više informacija o AI Security kursu:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** nudi brze i jednostavne real-time APIs za **pristup rezultatima pretrage**. Oni skrapuju pretraživače, upravljaju proxy-ima, rešavaju captchas, i parsiraju sve bogate strukturirane podatke za vas.

Pretplata na jedan od SerpApi planova uključuje pristup preko 50 različitih API-ja za skrapovanje različitih pretraživača, uključujući Google, Bing, Baidu, Yahoo, Yandex i više.\
Za razliku od drugih provajdera, **SerpApi ne skrapuje samo organske rezultate**. SerpApi odgovori dosledno uključuju sve oglase, inline slike i video zapise, knowledge graphs i druge elemente i funkcije prisutne u rezultatima pretrage.

Trenutni korisnici SerpApi uključuju **Apple, Shopify, and GrubHub**.\
Za više informacija pogledajte njihov [**blog**](https://serpapi.com/blog/)**,** ili isprobajte primer u njihovom [**playground**](https://serpapi.com/playground)**.**\
Možete **napraviti besplatan nalog** [**ovde**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Naučite tehnologije i veštine potrebne za istraživanje ranjivosti, penetration testing, i reverse engineering kako biste zaštitili mobilne aplikacije i uređaje. **Ovladajte iOS i Android security** kroz naše on-demand kurseve i **steknite sertifikat**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) je profesionalna cybersecurity kompanija sa sedištem u **Amsterdamu** koja pomaže u zaštiti preduzeća **po celom svetu** od najnovijih cybersecurity pretnji pružajući **offensive-security usluge** sa **modernim** pristupom.

WebSec je međunarodna security kompanija sa kancelarijama u Amsterdamu i Wyomingu. Nude **all-in-one security services** što znači da rade sve; pentesting, **Security** Audits, Awareness Trainings, Phishing Campaigns, Code Review, Exploit Development, Security Experts Outsourcing i mnogo više.

Još jedna zanimljiva stvar kod WebSec-a je da, za razliku od proseka u industriji, WebSec je **veoma samouveren u svoje veštine**, do te mere da **garantuju najbolje rezultate**, kako stoji na njihovom sajtu "**If we can't hack it, You don't pay it!**". Za više informacija pogledajte njihov [**website**](https://websec.net/en/) i [**blog**](https://websec.net/blog/)!

Pored navedenog, WebSec je takođe a **committed supporter of HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


Pravljeno za praksu. Prilagođeno vama.\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) razvija i isporučuje efikasne cybersecurity obuke koje su kreirane i vođene od strane industrijskih stručnjaka. Njihovi programi prelaze teoriju kako bi opremili timove dubokim razumevanjem i praktičnim veštinama, koristeći prilagođena okruženja koja odražavaju stvarne pretnje. Za upite o prilagođenim obukama, obratite nam se [**ovde**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Šta izdvaja njihove obuke:**
* Prilagođen sadržaj i laboratorije
* Podržano vrhunskim alatima i platformama
* Dizajnirano i predavano od strane praktičara

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions pruža specijalizovane cybersecurity usluge za institucije u sektoru **obrazovanja** i **FinTech-a**, sa fokusom na **penetration testing, cloud security assessments**, i **compliance readiness** (SOC 2, PCI-DSS, NIST). Naš tim uključuje **OSCP and CISSP certified professionals**, donoseći duboku tehničku stručnost i industrijski standardizovan uvid u svaku angažovanost.

Prevazilazimo automatske skenove kroz **manual, intelligence-driven testing** prilagođeno okruženjima visokog rizika. Od zaštite studentskih zapisa do zaštite finansijskih transakcija, pomažemo organizacijama da brane ono što je najvažnije.

_“Kvalitetna odbrana zahteva poznavanje napada, mi obezbeđujemo sigurnost kroz razumevanje.”_

Ostanite informisani i u toku sa najnovijim iz oblasti cybersecurity posetom našeg [**bloga**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE daje moć DevOps, DevSecOps i developerima da efikasno upravljaju, nadgledaju i osiguraju Kubernetes klastere. Iskoristite naše AI-driven uvide, napredni security framework i intuitivni CloudMaps GUI za vizualizaciju vaših klastera, razumevanje njihovog stanja i delovanje sa poverenjem.

Pored toga, K8Studio je **kompatibilan sa svim glavnim kubernetes distribucijama** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## Licenca i odricanje odgovornosti

Proverite ih u:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github statistika

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
