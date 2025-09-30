# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Loghi e motion design di_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
La tua copia locale di HackTricks sarà **disponibile su [http://localhost:3337](http://localhost:3337)** dopo meno di 5 minuti (deve costruire il libro, sii paziente).

## Sponsor Aziendali

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) è una grande azienda di cybersecurity il cui slogan è **HACK THE UNHACKABLE**. Svolgono ricerche proprie e sviluppano strumenti di hacking per **offrire diversi servizi di cybersecurity di valore** come pentesting, Red teams e formazione.

Puoi consultare il loro **blog** su [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** supporta anche progetti open source di cybersecurity come HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) è l'evento di cybersecurity più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto d'incontro vivace per professionisti della tecnologia e della cybersecurity in ogni disciplina.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** è il **#1 in Europa** per ethical hacking e **bug bounty platform.**

**Bug bounty tip**: **iscriviti** a **Intigriti**, una premium **bug bounty platform creata da hacker, per hacker**! Unisciti a noi su [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) oggi e inizia a guadagnare bounty fino a **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) per creare facilmente e **automatizzare workflow** alimentati dagli strumenti comunitari più **avanzati** al mondo.

Ottieni accesso oggi:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Unisciti al server [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) per comunicare con hacker esperti e bug bounty hunters!

- **Hacking Insights:** Condividi contenuti che approfondiscono il brivido e le sfide dell'hacking
- **Real-Time Hack News:** Rimani aggiornato sul mondo dell'hacking in tempo reale con notizie e approfondimenti
- **Latest Announcements:** Vieni informato sui nuovi bug bounty in lancio e sugli aggiornamenti importanti delle piattaforme

**Unisciti a noi su** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e inizia a collaborare con i migliori hacker oggi stesso!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Ottieni la prospettiva di un hacker sulle tue web app, rete e cloud**

**Individua e segnala vulnerabilità critiche sfruttabili con reale impatto sul business.** Usa i nostri 20+ strumenti personalizzati per mappare la superficie d'attacco, trovare problemi di sicurezza che permettono escalation di privilegi e usare exploit automatizzati per raccogliere prove essenziali, trasformando il tuo lavoro in report persuasivi.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** offre API in tempo reale veloci e facili per **accedere ai risultati dei motori di ricerca**. Effettuano scraping dei motori di ricerca, gestiscono proxy, risolvono captcha e parsano tutti i dati strutturati per te.

Un abbonamento a uno dei piani di SerpApi include l'accesso a oltre 50 API diverse per lo scraping di differenti search engine, inclusi Google, Bing, Baidu, Yahoo, Yandex e altri.\
A differenza di altri provider, **SerpApi non si limita a fare scraping dei risultati organici**. Le risposte di SerpApi includono sempre annunci, immagini inline e video, knowledge graph e altri elementi presenti nei risultati di ricerca.

Tra i clienti attuali di SerpApi ci sono **Apple, Shopify e GrubHub**.\
Per maggiori informazioni visita il loro [**blog**](https://serpapi.com/blog/)**,** o prova un esempio nel loro [**playground**](https://serpapi.com/playground)**.**\
Puoi **creare un account gratuito** [**qui**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Impara le tecnologie e le competenze necessarie per svolgere vulnerability research, penetration testing e reverse engineering per proteggere applicazioni e dispositivi mobili. **Padroneggia la security iOS e Android** attraverso i nostri corsi on-demand e **ottieni la certificazione**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) è una società professionale di cybersecurity con sede ad **Amsterdam** che aiuta a **proteggere** le aziende **in tutto il mondo** contro le più recenti minacce fornendo **offensive-security services** con un approccio **moderno**.

WebSec è una società internazionale con uffici ad Amsterdam e in Wyoming. Offrono **servizi di sicurezza tutto-in-uno** che coprono: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campaigns, Code Review, Exploit Development, Outsourcing di Security Experts e molto altro.

Un'altra cosa interessante di WebSec è che, a differenza della media del settore, WebSec è **molto fiduciosa nelle proprie capacità**, a tal punto da **garantire i migliori risultati di qualità**, come si legge sul loro sito: "**If we can't hack it, You don't pay it!**". Per maggiori info dai un'occhiata al loro [**website**](https://websec.net/en/) e al loro [**blog**](https://websec.net/blog/)!

In aggiunta, WebSec è anche un **sostenitore impegnato di HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) è un motore di ricerca per data breach (leak). \
Forniamo ricerca per stringhe casuali (come google) su tutti i tipi di data leak grandi e piccoli --non solo i grandi-- su dati provenienti da più fonti. \
Ricerca persone, ricerca AI, ricerca organizzazioni, accesso API (OpenAPI), integrazione con theHarvester, tutte le funzionalità di cui un pentester ha bisogno.\
**HackTricks continua a essere una grande piattaforma di apprendimento per tutti noi e siamo orgogliosi di sponsorizzarla!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) sviluppa e offre training di cybersecurity efficaci costruiti e guidati da esperti del settore. I loro programmi vanno oltre la teoria per dotare i team di una profonda comprensione e competenze pratiche, usando ambienti personalizzati che riflettono minacce del mondo reale. Per richieste di training su misura, contattaci [**qui**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Cosa distingue il loro training:**
* Contenuti e lab personalizzati
* Supportati da tool e piattaforme di alto livello
* Progettati e insegnati da practitioner

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions offre servizi di cybersecurity specializzati per istituzioni di **Education** e **FinTech**, con focus su **penetration testing, cloud security assessments**, e **compliance readiness** (SOC 2, PCI-DSS, NIST). Il nostro team include professionisti certificati **OSCP e CISSP**, portando competenze tecniche profonde e insight secondo gli standard del settore in ogni engagement.

Andiamo oltre gli scan automatici con **test manuali guidati dall'intelligence** su misura per ambienti ad alto rischio. Dal proteggere i record degli studenti al tutelare le transazioni finanziarie, aiutiamo le organizzazioni a difendere ciò che conta di più.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Rimani informato con le ultime novità in cybersecurity visitando il nostro [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE permette a DevOps, DevSecOps e sviluppatori di gestire, monitorare e mettere in sicurezza cluster Kubernetes in modo efficiente. Sfrutta i nostri insight guidati dall'AI, un advanced security framework e l'intuitiva CloudMaps GUI per visualizzare i cluster, comprenderne lo stato e agire con sicurezza.

Inoltre, K8Studio è **compatibile con tutte le principali distribuzioni di kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift e altro).

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
