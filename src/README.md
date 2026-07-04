# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Loghi e motion design di Hacktricks di_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Esegui HackTricks in locale
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
La tua copia locale di HackTricks sarà **disponibile su [http://localhost:3337](http://localhost:3337)** dopo <5 minuti (deve compilare il libro, abbi pazienza).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) è una grande azienda di cybersecurity il cui slogan è **HACK THE UNHACKABLE**. Svolgono ricerche proprie e sviluppano i propri strumenti di hacking per **offrire diversi servizi di cybersecurity di grande valore** come pentesting, Red teams e training.

Puoi consultare il loro **blog** su [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** supporta anche progetti open source di cybersecurity come HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** è la **piattaforma di ethical hacking e bug bounty numero 1 in Europa.**

**Bug bounty tip**: **iscriviti** a **Intigriti**, una premium **bug bounty platform creata da hacker, per hacker**! Unisciti a noi su [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) oggi, e inizia a guadagnare bounty fino a **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Unisciti al server [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) per comunicare con hacker esperti e bug bounty hunter!

- **Hacking Insights:** Interagisci con contenuti che approfondiscono il brivido e le sfide dell'hacking
- **Real-Time Hack News:** Rimani aggiornato sul mondo dell'hacking attraverso notizie e insight in tempo reale
- **Latest Announcements:** Rimani informato sui nuovi bug bounty in lancio e sugli aggiornamenti cruciali della piattaforma

**Unisciti a noi su** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e inizia oggi a collaborare con i migliori hacker!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security offre **training pratico di AI Security** con un approccio **engineering-first, hands-on lab**. I nostri corsi sono pensati per security engineer, professionisti AppSec e sviluppatori che vogliono **costruire, rompere e proteggere applicazioni reali basate su AI/LLM**.

La **AI Security Certification** si concentra su competenze del mondo reale, tra cui:
- Protezione di applicazioni basate su LLM e AI
- Threat modeling per sistemi AI
- Embeddings, vector database e sicurezza RAG
- Attacchi LLM, scenari di abuso e difese pratiche
- Design pattern sicuri e considerazioni di deployment

Tutti i corsi sono **on-demand**, **lab-driven** e progettati attorno a **compromessi di sicurezza del mondo reale**, non solo teoria.

👉 Maggiori dettagli sul corso AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** offre API rapide e semplici in tempo reale per **accedere ai risultati dei motori di ricerca**. Eseguono lo scraping dei motori di ricerca, gestiscono proxy, risolvono captcha e analizzano per te tutti i dati strutturati ricchi.

Un abbonamento a uno dei piani SerpApi include l'accesso a oltre 50 API diverse per fare scraping di motori di ricerca differenti, tra cui Google, Bing, Baidu, Yahoo, Yandex e altri.\
A differenza di altri provider, **SerpApi non si limita a fare scraping dei risultati organici**. Le risposte di SerpApi includono costantemente tutti gli annunci, immagini e video inline, knowledge graph e altri elementi e funzionalità presenti nei risultati di ricerca.

Tra gli attuali clienti di SerpApi ci sono **Apple, Shopify e GrubHub**.\
Per maggiori informazioni dai un'occhiata al loro [**blog**](https://serpapi.com/blog/)**,** oppure prova un esempio nel loro [**playground**](https://serpapi.com/playground)**.**\
Puoi **creare un account gratuito** [**qui**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Impara le tecnologie e le competenze necessarie per svolgere vulnerability research, penetration testing e reverse engineering per proteggere applicazioni e dispositivi mobili. **Padroneggia la sicurezza di iOS e Android** attraverso i nostri corsi on-demand e **ottieni la certificazione**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** è una piattaforma di sicurezza basata su AI per trovare vulnerabilità sfruttabili prima che lo facciano gli attaccanti.

**Code security tip**: iscriviti a NaxusAI, una piattaforma intelligente di monitoraggio delle vulnerabilità pensata per sviluppatori e team di sicurezza! Unisciti a noi oggi e inizia a usare l'AI per **rilevare, validare e correggere reali rischi di sicurezza prima che raggiungano la produzione**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) è una società professionale di cybersecurity con sede ad **Amsterdam** che aiuta a **proteggere** aziende **in tutto il mondo** contro le più recenti minacce di cybersecurity fornendo servizi di **offensive-security** con un approccio **moderno**.

WebSec è una società di sicurezza intenazionale con uffici ad Amsterdam e Wyoming. Offre servizi di sicurezza **all-in-one**, il che significa che fa tutto: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing e molto altro.

Un'altra cosa interessante di WebSec è che, a differenza della media del settore, WebSec è **molto fiduciosa nelle proprie capacità**, al punto da **garantire i risultati della migliore qualità**; sul loro sito affermano "**If we can't hack it, You don't pay it!**". Per maggiori informazioni dai un'occhiata al loro [**website**](https://websec.net/en/) e [**blog**](https://websec.net/blog/)!

Oltre a quanto sopra, WebSec è anche un **sostenitore convinto di HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Costruito per il campo. Costruito attorno a te.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) sviluppa e offre formazione efficace in cybersecurity costruita e guidata da
esperti del settore. I loro programmi vanno oltre la teoria per dotare i team di una comprensione profonda
e di competenze pratiche, usando ambienti personalizzati che riflettono minacce del mondo reale.
Per richieste di formazione personalizzata, contattaci [**qui**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Cosa distingue la loro formazione:**
* Contenuti e lab costruiti su misura
* Supportati da strumenti e piattaforme di alto livello
* Progettati e insegnati da professionisti

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions offre servizi specializzati di cybersecurity per istituzioni **Education** e **FinTech**
, con un focus su **penetration testing, cloud security assessments** e
**compliance readiness** (SOC 2, PCI-DSS, NIST). Il nostro team include professionisti
certificati **OSCP e CISSP**, portando una profonda competenza tecnica e una visione
standard del settore in ogni engagement.

Andiamo oltre le scansioni automatizzate con test **manuali, guidati dall'intelligence**, adattati
ad ambienti ad alto rischio. Dalla protezione dei registri degli studenti alla protezione delle transazioni finanziarie,
aiutiamo le organizzazioni a difendere ciò che conta di più.

_“Una difesa di qualità richiede di conoscere l'offesa, noi forniamo sicurezza attraverso la comprensione.”_

Rimani informato e aggiornato sulle ultime novità in cybersecurity visitando il nostro [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE consente a DevOps, DevSecOps e sviluppatori di gestire, monitorare e proteggere in modo efficiente i cluster Kubernetes. Sfrutta i nostri insight guidati dall'AI, il framework di sicurezza avanzato e l'intuitiva GUI CloudMaps per visualizzare i tuoi cluster, comprenderne lo stato e agire con fiducia.

Inoltre, K8Studio è **compatibile con tutte le principali distribuzioni kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift e altre).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

<!-- hacktricks-friends:friend:friend-carlospolop:start -->
### [HackTricks Books](https://book.hacktricks.wiki/)

<figure class="sponsor-logo"><img src="https://friends.hacktricks.wiki/assets/17181413/5e15e93e6b8523dac2ad.png" alt="HackTricks Books logo"><figcaption></figcaption></figure>

Questo è un testo per presentare la wiki gratuita di cybersecurity: <b>Hacktricks Book </b>. Impara gratis da qui ogni tipo di hacking trick adesso!

{{#ref}}
https://book.hacktricks.wiki/
{{#endref}}

---
<!-- hacktricks-friends:friend:friend-carlospolop:end -->

## License & Disclaimer

Controllali in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
