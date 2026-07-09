# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logotipi i motion dizajn by_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Vaša lokalna kopija HackTricks-a će biti **dostupna na [http://localhost:3337](http://localhost:3337)** nakon <5 minuta (potrebno je da se knjiga izgradi, budite strpljivi).

## HackTricks Partneri

---

## HackTricks Prijatelji

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) je odlična kompanija za sajber bezbednost čiji je slogan **HACK THE UNHACKABLE**. Oni sprovode sopstvena istraživanja i razvijaju sopstvene alate za hakovanje kako bi **ponudili nekoliko vrednih usluga sajber bezbednosti** kao što su pentesting, Red teams i obuka.

Možete pogledati njihov **blog** na [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** takođe podržava open source projekte za sajber bezbednost kao što je HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** je **Evropska #1** platforma za etičko hakovanje i **bug bounty platforma.**

**Bug bounty savet**: **registrujte se** za **Intigriti**, premium **bug bounty platformu kreiranu od strane hakera, za hakere**! Pridružite nam se danas na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) i počnite da zarađujete nagrade do **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security pruža **praktičnu obuku za AI bezbednost** sa **inženjerskim, hands-on laboratorijskim pristupom**. Naši kursevi su napravljeni za bezbednosne inženjere, AppSec profesionalce i developere koji žele da **grade, razbijaju i obezbede prave AI/LLM aplikacije**.

**AI Security Certification** je fokusiran na veštine iz stvarnog sveta, uključujući:
- Obezbeđivanje LLM i AI-pokretanih aplikacija
- Threat modeling za AI sisteme
- Embeddings, vector databases i RAG bezbednost
- LLM napade, scenarije zloupotrebe i praktične odbrane
- Bezbedne obrasce dizajna i razmatranja pri deployment-u

Svi kursevi su **on-demand**, **vođeni laboratorijama** i dizajnirani oko **stvarnih bezbednosnih kompromisa**, a ne samo teorije.

👉 Više detalja o kursu AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** nudi brze i jednostavne real-time API-je za **pristup rezultatima pretraživača**. Oni scrape-uju pretraživače, obrađuju proksije, rešavaju captchas i parsiraju sve bogate strukturirane podatke za vas.

Pretplata na jedan od SerpApi planova uključuje pristup više od 50 različitih API-ja za scraping različitih pretraživača, uključujući Google, Bing, Baidu, Yahoo, Yandex i druge.\
Za razliku od drugih provajdera, **SerpApi ne scrape-uje samo organske rezultate**. SerpApi odgovori dosledno uključuju sve oglase, inline slike i video zapise, knowledge graphs i druge elemente i funkcije prisutne u rezultatima pretrage.

Trenutni SerpApi klijenti uključuju **Apple, Shopify i GrubHub**.\
Za više informacija pogledajte njihov [**blog**](https://serpapi.com/blog/)**,** ili isprobajte primer u njihovom [**playground**](https://serpapi.com/playground)**.**\
Možete **otvoriti besplatan nalog** [**ovde**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** vas obučava u ofanzivnoj mobilnoj i AI bezbednosti, uz predavanja aktivnih istraživača – istog tima iza CVE writeups i predavanja na Black Hat, HITB i Zer0con. Kursevi su samostalnog tempa, zasnovani na laboratorijama na stvarnim ciljevima i podržani praktičnom sertifikacijom.

Katalog ima dva pravca:

**Mobile Security** – iOS i Android od sloja aplikacije naniže: reverse engineering sa Ghidra i LLDB, ARM64 exploitation, kernel internals i moderne mitigacije (PAC, MTE, SELinux), jailbreak i rooting mehanizmi.

**AI Security** – dva kompletna kursa koji pokrivaju celu oblast. Practical AI Security objašnjava kako rade LLMs, RAG pipelines, AI agents i MCP, i kako ih napadati i braniti. Advanced AI Security ide dublje i više ka izgradnji: red teaming AI sistema u velikom obimu sa Garak i PyRIT, eksploatacija MCP servera, postavljanje i detekcija backdoor-a modela, i fine-tuning napadi i odbrane na Apple Silicon.

Kursevi i sertifikacije:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** je AI-pokretana bezbednosna platforma za pronalaženje iskoristivih ranjivosti pre nego što to urade napadači.

**Code security savet**: registrujte se za NaxusAI, pametnu platformu za praćenje ranjivosti napravljenu za developere i bezbednosne timove! Pridružite nam se danas i počnite da koristite AI za **otkrivanje, validaciju i ispravljanje stvarnih bezbednosnih rizika pre nego što stignu do produkcije**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) je profesionalna kompanija za sajber bezbednost sa sedištem u **Amsterdamu** koja pomaže u **zaštiti** kompanija **širom sveta** od najnovijih sajber pretnji pružanjem **offensive-security usluga** uz **moderan** pristup.

WebSec je međunarodna bezbednosna kompanija sa kancelarijama u Amsterdamu i Vajomingu. Nude **all-in-one security services** što znači da rade sve; Pentesting, **Security** revizije, Awareness obuke, Phishing kampanje, Code Review, razvoj exploit-a, outsourcing bezbednosnih eksperata i mnogo više.

Još jedna sjajna stvar kod WebSec-a je to što su, za razliku od proseka u industriji, **veoma sigurni u svoje veštine**, do te mere da **garantuju najbolje kvalitetne rezultate**, a na njihovom sajtu piše "**If we can't hack it, You don't pay it!**". Za više informacija pogledajte njihov [**website**](https://websec.net/en/) i [**blog**](https://websec.net/blog/)!

Pored navedenog, WebSec je takođe **posvećen podržavalac HackTricks-a.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Napravljen za teren. Napravljen oko vas.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) razvija i isporučuje efikasnu obuku za sajber bezbednost, kreiranu i vođenu od strane
stručnjaka iz industrije. Njihovi programi idu dalje od teorije i opremaju timove dubokim
razumevanjem i primenljivim veštinama, koristeći prilagođena okruženja koja odražavaju realne
pretnje. Za upite o prilagođenoj obuci, kontaktirajte nas [**ovde**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Šta izdvaja njihovu obuku:**
* Prilagođeni sadržaj i laboratorije
* Podržano vrhunskim alatima i platformama
* Dizajnirano i predavano od strane praktičara

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions pruža specijalizovane usluge sajber bezbednosti za institucije iz oblasti **obrazovanja** i **FinTech**
, sa fokusom na **penetration testing, cloud security assessments**, i
**spremnost za usklađenost** (SOC 2, PCI-DSS, NIST). Naš tim uključuje **OSCP i CISSP
sertifikovane profesionalce**, donoseći duboku tehničku ekspertizu i uvid u skladu sa industrijskim standardima na
svakom angažovanju.

Idemo dalje od automatizovanih skeniranja uz **ručno, intelligence-driven testiranje** prilagođeno
okruženjima sa visokim ulozima. Od obezbeđivanja studentskih evidencija do zaštite finansijskih transakcija,
pomažemo organizacijama da odbrane ono što je najvažnije.

_“Kvalitetna odbrana zahteva poznavanje napada, mi pružamo bezbednost kroz razumevanje.”_

Budite informisani i u toku sa najnovijim dešavanjima u sajber bezbednosti posetom našem [**blogu**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE omogućava DevOps, DevSecOps i developerima da efikasno upravljaju, nadgledaju i obezbeđuju Kubernetes klastere. Iskoristite naše AI-driven uvide, napredni bezbednosni okvir i intuitivni CloudMaps GUI da vizualizujete svoje klastere, razumete njihovo stanje i delujete sa samopouzdanjem.

Štaviše, K8Studio je **kompatibilan sa svim glavnim kubernetes distribucijama** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift i druge).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## Licenca i odricanje odgovornosti

Pogledajte ih na:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github statistika

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
