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
La tua copia locale di HackTricks sarà **available at [http://localhost:3337](http://localhost:3337)** dopo meno di 5 minuti (deve buildare il libro, abbi pazienza).

## Sponsor aziendali

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) è una grande azienda di cybersecurity il cui slogan è **HACK THE UNHACKABLE**. Svolgono ricerche proprie e sviluppano i propri hacking tools per **offrire diversi servizi di cybersecurity** come pentesting, Red teams e formazione.

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

**Intigriti** è la **piattaforma #1 in Europa** per ethical hacking e **bug bounty**.

**Suggerimento per bug bounty**: **iscriviti** a **Intigriti**, una piattaforma premium di **bug bounty** creata da hacker, per hacker! Unisciti a noi su [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) oggi e inizia a guadagnare ricompense fino a **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) per costruire facilmente e **automatizzare workflow** alimentati dagli strumenti community più **avanzati** al mondo.

Ottieni accesso oggi:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Unisciti al server [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) per comunicare con hacker esperti e bug bounty hunters!

- **Approfondimenti sull'hacking:** Partecipa a contenuti che esplorano il brivido e le sfide dell'hacking
- **Notizie di hacking in tempo reale:** Rimani aggiornato sul mondo dell'hacking con news e approfondimenti in tempo reale
- **Ultimi annunci:** Resta informato sui nuovi bug bounty in lancio e sugli aggiornamenti cruciali delle piattaforme

**Unisciti a noi su** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e inizia a collaborare con i migliori hacker oggi!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security offre **formazione pratica in AI Security** con un approccio **engineering-first** e laboratori hands-on. I nostri corsi sono pensati per security engineers, professionisti AppSec e sviluppatori che vogliono **build, break, e secure applicazioni reali potenziate da AI/LLM**.

La **AI Security Certification** si concentra su competenze pratiche, tra cui:
- Securing LLM and AI-powered applications
- Threat modeling per sistemi AI
- Embeddings, vector databases, e sicurezza RAG
- Attacchi LLM, scenari di abuso e difese pratiche
- Pattern di design sicuri e considerazioni di deployment

Tutti i corsi sono **on-demand**, **lab-driven**, e progettati attorno a **tradeoff reali di sicurezza**, non solo teoria.

👉 Maggiori dettagli sul corso AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** offre API veloci e semplici in tempo reale per **accedere ai risultati dei motori di ricerca**. Si occupano di scraping dei motori di ricerca, gestione dei proxy, risoluzione dei captcha e parsing di tutti i dati strutturati per te.

Un abbonamento a uno dei piani di SerpApi include l'accesso a oltre 50 diverse API per lo scraping di vari motori di ricerca, inclusi Google, Bing, Baidu, Yahoo, Yandex e altri.\
A differenza di altri provider, **SerpApi non si limita a scrapeare i risultati organici**. Le risposte di SerpApi includono costantemente annunci, immagini e video inline, knowledge graph e altri elementi presenti nei risultati di ricerca.

Tra i clienti attuali di SerpApi ci sono **Apple, Shopify e GrubHub**.\
Per maggiori informazioni consulta il loro [**blog**](https://serpapi.com/blog/)**,** o prova un esempio nel loro [**playground**](https://serpapi.com/playground)**.**\
Puoi **creare un account gratuito** [**qui**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Impara le tecnologie e le competenze necessarie per svolgere vulnerability research, penetration testing e reverse engineering per proteggere applicazioni e dispositivi mobili. **Masterizza la sicurezza iOS e Android** attraverso i nostri corsi on-demand e **ottieni certificazione**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) è una società professionale di cybersecurity con sede ad **Amsterdam** che aiuta a **proteggere** aziende **in tutto il mondo** dalle più recenti minacce informatiche offrendo **servizi offensive-security** con un approccio **moderno**.

WebSec è una società internazionale con uffici ad Amsterdam e in Wyoming. Offrono **servizi di sicurezza all-in-one**, il che significa che fanno tutto: Pentesting, audit di **Security**, awareness training, campagne di phishing, code review, exploit development, outsourcing di esperti di sicurezza e molto altro.

Un altro aspetto interessante di WebSec è che, a differenza della media del settore, WebSec è **molto sicura delle proprie capacità**, a tal punto che **garantiscono i migliori risultati**, come affermano sul loro sito: "**If we can't hack it, You don't pay it!**". Per ulteriori informazioni dai un'occhiata al loro [**sito**](https://websec.net/en/) e al loro [**blog**](https://websec.net/blog/)!

In aggiunta a quanto sopra, WebSec è anche un **sostenitore impegnato di HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) sviluppa e offre formazione cybersecurity efficace, creata e guidata da esperti del settore. I loro programmi vanno oltre la teoria per fornire team con una profonda comprensione e competenze pratiche, utilizzando ambienti personalizzati che rispecchiano le minacce del mondo reale. Per richieste di formazione personalizzata, contattaci [**qui**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Cosa distingue la loro formazione:**
* Contenuti e lab creati su misura
* Supportati da tool e piattaforme di prima fascia
* Progettati e insegnati da practitioner

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions offre servizi di cybersecurity specializzati per istituzioni dell'**Education** e del **FinTech**, con un focus su **penetration testing, cloud security assessments** e **compliance readiness** (SOC 2, PCI-DSS, NIST). Il nostro team include professionisti certificati **OSCP e CISSP**, che portano competenze tecniche approfondite e una visione conforme agli standard di settore in ogni engagement.

Andiamo oltre gli scan automatici con **test manuali e intelligence-driven** su misura per ambienti ad alto rischio. Dal proteggere i registri degli studenti al tutelare le transazioni finanziarie, aiutiamo le organizzazioni a difendere ciò che conta di più.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Rimani informato e aggiornato sulle ultime novità in cybersecurity visitando il nostro [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE permette a DevOps, DevSecOps e sviluppatori di gestire, monitorare e mettere in sicurezza cluster Kubernetes in modo efficiente. Sfrutta i nostri insight basati su AI, un framework di sicurezza avanzato e l'intuitiva CloudMaps GUI per visualizzare i cluster, comprenderne lo stato e agire con fiducia.

Inoltre, K8Studio è **compatibile con tutte le principali distribuzioni kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift e altro).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## Licenza e Disclaimer

Controllali in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Statistiche Github

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
