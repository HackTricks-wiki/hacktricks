# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Loghi e motion design di Hacktricks realizzati da_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Esegui HackTricks localmente
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
La tua copia locale di HackTricks sarà **disponibile su [http://localhost:3337](http://localhost:3337)** dopo <5 minuti (deve buildare il libro, sii paziente).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) è una grande azienda di cybersecurity il cui slogan è **HACK THE UNHACKABLE**. Svolgono ricerche proprie e sviluppano i propri hacking tools per **offer several valuable cybersecurity services** come pentesting, Red teams e training.

Puoi consultare il loro **blog** su [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** supporta anche progetti open source di cybersecurity come HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) è l'evento di cybersecurity più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **the mission of promoting technical knowledge**, questo congresso è un vivace punto d'incontro per professionisti della tecnologia e della cybersecurity in ogni disciplina.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** è la **Europe's #1** ethical hacking e **bug bounty platform.**

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Unisciti a noi su [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) oggi, e inizia a guadagnare bounties fino a **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) per costruire facilmente e **automatizzare workflows** alimentati dagli strumenti comunitari più **advanced** al mondo.

Get Access Today:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server per comunicare con hacker esperti e bug bounty hunters!

- **Hacking Insights:** Approfondisci contenuti che esplorano il brivido e le sfide dell'hacking
- **Real-Time Hack News:** Rimani aggiornato sul mondo dell'hacking attraverso notizie e approfondimenti in tempo reale
- **Latest Announcements:** Rimani informato sui nuovi bug bounties in lancio e sugli aggiornamenti cruciali della piattaforma

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e inizia a collaborare con i migliori hacker oggi!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Get a hacker's perspective on your web apps, network, and cloud**

Trova e segnala vulnerabilità critiche ed exploitabili con reale impatto sul business. Usa i nostri 20+ custom tools per mappare la attack surface, trovare problemi di sicurezza che permettono di escalate privileges, e utilizzare exploit automatizzati per raccogliere prove essenziali, trasformando il tuo lavoro in report persuasivi.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** offre API real-time veloci e semplici per accedere ai risultati dei motori di ricerca. Scansionano search engines, gestiscono proxies, risolvono captchas e parsano tutti i dati strutturati ricchi per te.

Un abbonamento a uno dei piani di SerpApi include accesso a oltre 50 diverse API per scraping di differenti motori di ricerca, inclusi Google, Bing, Baidu, Yahoo, Yandex e altri.\
A differenza di altri provider, **SerpApi non si limita a fare scraping dei risultati organici**. Le risposte SerpApi includono costantemente tutti gli ads, immagini e video inline, knowledge graphs e altri elementi e feature presenti nei risultati di ricerca.

I clienti attuali di SerpApi includono **Apple, Shopify, and GrubHub**.\
Per maggiori informazioni visita il loro [**blog**](https://serpapi.com/blog/)**,** oppure prova un esempio nel loro [**playground**](https://serpapi.com/playground)**.**\
Puoi **create a free account** [**here**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Impara le tecnologie e le competenze necessarie per svolgere vulnerability research, penetration testing e reverse engineering per proteggere applicazioni e dispositivi mobili. **Master iOS and Android security** tramite i nostri corsi on-demand e **get certified**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) è una società professionale di cybersecurity con sede ad **Amsterdam** che aiuta a proteggere le aziende **all over the world** contro le più recenti minacce di cybersecurity offrendo **offensive-security services** con un approccio **modern**.

WebSec è un'azienda di security internazionale con uffici ad Amsterdam e Wyoming. Offrono **all-in-one security services** il che significa che fanno tutto; Pentesting, **Security** Audits, Awareness Trainings, campagne di Phishing, Code Review, Exploit Development, Security Experts Outsourcing e molto altro.

Un altro aspetto interessante di WebSec è che, a differenza della media del settore, WebSec è **very confident in their skills**, a tal punto che **guarantee the best quality results**, come dichiarano sul loro sito "**If we can't hack it, You don't pay it!**". Per maggiori informazioni visita il loro [**website**](https://websec.net/en/) e il loro [**blog**](https://websec.net/blog/)!

In aggiunta a quanto sopra, WebSec è anche un **committed supporter of HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) è un motore di ricerca per data breach (leak). \
Offriamo random string search (like google) su tutti i tipi di data leaks grandi e piccoli -- non solo i grandi -- su dati provenienti da molteplici fonti. \
People search, AI search, organization search, API (OpenAPI) access, theHarvester integration, tutte le feature di cui un pentester ha bisogno.\
**HackTricks continua ad essere una grande piattaforma di apprendimento per tutti noi e siamo orgogliosi di sponsorizzarla!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) sviluppa e fornisce training di cybersecurity efficaci creati e guidati da esperti del settore. I loro programmi vanno oltre la teoria per fornire ai team una profonda comprensione e competenze pratiche, utilizzando ambienti personalizzati che riflettono minacce reali. Per richieste di training personalizzati contattaci [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**What sets their training apart:**
* Contenuti e lab su misura
* Supportati da top-tier tools e platforms
* Progettati e tenuti da practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions fornisce servizi di cybersecurity specializzati per istituzioni **Education** e **FinTech**, con un focus su **penetration testing, cloud security assessments**, e **compliance readiness** (SOC 2, PCI-DSS, NIST). Il nostro team include professionisti certificati **OSCP and CISSP**, che portano approfondita expertise tecnica e insight standard di settore in ogni engagement.

Andiamo oltre gli scan automatizzati con **manual, intelligence-driven testing** su misura per ambienti ad alto rischio. Dal proteggere i dati degli studenti al salvaguardare le transazioni finanziarie, aiutiamo le organizzazioni a difendere ciò che conta di più.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Rimani informato con le ultime novità in cybersecurity visitando il loro [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.jpg" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE consente a DevOps, DevSecOps e sviluppatori di gestire, monitorare e mettere in sicurezza cluster Kubernetes in modo efficiente. Sfrutta i nostri insights AI-driven, advanced security framework e l'intuitiva GUI CloudMaps per visualizzare i cluster, comprendere il loro stato e agire con fiducia.

Inoltre, K8Studio è **compatible with all major kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## License & Disclaimer

Controllali in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
