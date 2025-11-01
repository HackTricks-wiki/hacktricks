# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks loghi e motion design di_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
La tua copia locale di HackTricks sarà **available at [http://localhost:3337](http://localhost:3337)** dopo <5 minuti (deve generare il libro, sii paziente).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) è una grande azienda di cybersecurity il cui slogan è **HACK THE UNHACKABLE**. Svolgono le proprie ricerche e sviluppano i propri strumenti di hacking per **offrire diversi servizi di cybersecurity di valore** come pentesting, Red teams e formazione.

You can check their **blog** in [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** supporta anche progetti open source di cybersecurity come HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) è l'evento di cybersecurity più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto d'incontro bollente per professionisti della tecnologia e della cybersecurity in tutte le discipline.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** è la **Europe's #1** piattaforma per ethical hacking e **bug bounty.**

**Bug bounty tip**: **sign up** for **Intigriti**, una piattaforma **bug bounty** premium creata da hackers, per hackers! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) per creare facilmente e **automatizzare workflow** alimentati dagli strumenti della community più **avanzati** al mondo.

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

**Find and report critical, exploitable vulnerabilities with real business impact.** Usa i nostri oltre 20 strumenti personalizzati per mappare la superficie d'attacco, trovare problemi di sicurezza che permettono di escalationare privilegi, e utilizzare exploit automatizzati per raccogliere prove essenziali, trasformando il tuo lavoro in report persuasivi.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** offre API veloci e semplici in tempo reale per **accedere ai risultati dei motori di ricerca**. Si occupano di scraping dei motori di ricerca, gestione proxy, risoluzione di captcha e parsing di tutti i dati strutturati ricchi per te.

Un abbonamento a uno dei piani di SerpApi include l'accesso a oltre 50 diverse API per lo scraping di vari motori di ricerca, inclusi Google, Bing, Baidu, Yahoo, Yandex, e altri.\
A differenza di altri provider, **SerpApi non si limita a scrappare i risultati organici**. Le risposte di SerpApi includono costantemente tutte le ads, immagini e video inline, knowledge graph e altri elementi e feature presenti nei risultati di ricerca.

Tra i clienti attuali di SerpApi ci sono **Apple, Shopify, and GrubHub**.\
Per maggiori informazioni consulta il loro [**blog**](https://serpapi.com/blog/)**,** oppure prova un esempio nel loro [**playground**](https://serpapi.com/playground)**.**\
Puoi **creare un account gratuito** [**here**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Impara le tecnologie e le competenze necessarie per svolgere vulnerability research, penetration testing e reverse engineering per proteggere applicazioni e dispositivi mobili. **Master iOS and Android security** attraverso i nostri corsi on-demand e **ottieni una certificazione**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) è una società professionale di cybersecurity con sede ad **Amsterdam** che aiuta a **proteggere** le aziende **in tutto il mondo** contro le più recenti minacce informatiche fornendo **offensive-security services** con un approccio **moderno**.

WebSec è una società di security internazionale con uffici ad Amsterdam e Wyoming. Offrono **servizi di sicurezza all-in-one**, il che significa che fanno tutto; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing e molto altro.

Un'altra cosa interessante di WebSec è che, a differenza della media del settore, WebSec è **molto fiduciosa nelle proprie competenze**, a tal punto che **garantiscono i migliori risultati**, come affermano sul loro sito "**If we can't hack it, You don't pay it!**". Per più informazioni dai un'occhiata al loro [**website**](https://websec.net/en/) e al loro [**blog**](https://websec.net/blog/)!

In aggiunta a quanto sopra WebSec è anche un **sostenitore impegnato di HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) sviluppa e fornisce formazione di cybersecurity efficace creata e guidata da esperti del settore. I loro programmi vanno oltre la teoria per fornire ai team una profonda comprensione e competenze pratiche, utilizzando ambienti personalizzati che riflettono le minacce del mondo reale. Per richieste di formazione personalizzata, contattaci [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**What sets their training apart:**
* Contenuti e laboratori costruiti su misura
* Supportato da strumenti e piattaforme di primo livello
* Progettato e insegnato da practitioner

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions fornisce servizi di cybersecurity specializzati per istituzioni nel settore **Education** e **FinTech**, con un focus su **penetration testing, cloud security assessments**, e **compliance readiness** (SOC 2, PCI-DSS, NIST). Il nostro team include professionisti certificati **OSCP and CISSP**, che apportano profonda esperienza tecnica e conoscenza degli standard del settore in ogni incarico.

Andiamo oltre gli scan automatici con **test manuali, guidati da intelligence**, su misura per ambienti ad alto rischio. Dal proteggere i registri degli studenti al tutelare le transazioni finanziarie, aiutiamo le organizzazioni a difendere ciò che conta di più.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Rimani informato e aggiornato sulle ultime novità in cybersecurity visitando il loro [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE abilita DevOps, DevSecOps e sviluppatori a gestire, monitorare e mettere in sicurezza cluster Kubernetes in modo efficiente. Sfrutta i nostri insight basati su AI, un framework di sicurezza avanzato e l'intuitiva CloudMaps GUI per visualizzare i cluster, comprenderne lo stato e agire con fiducia.

Inoltre, K8Studio è **compatible with all major kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## License & Disclaimer

Check them in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
