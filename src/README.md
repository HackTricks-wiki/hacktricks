# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logo e motion design di Hacktricks by_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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

## Sponsor aziendali

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) è un’ottima azienda di cybersecurity il cui slogan è **HACK THE UNHACKABLE**. Svolgono le proprie ricerche e sviluppano i propri strumenti di hacking per **offrire diversi servizi di cybersecurity di valore** come pentesting, Red teams e formazione.

Puoi consultare il loro **blog** su [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** supporta anche progetti open source di cybersecurity come HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** è la **piattaforma di ethical hacking e bug bounty #1 in Europa.**

**Bug bounty tip**: **iscriviti** a **Intigriti**, una piattaforma **bug bounty premium creata da hacker, per hacker**! Unisciti a noi oggi su [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) e inizia a guadagnare bounty fino a **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Unisciti al server [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) per comunicare con hacker esperti e bug bounty hunter!

- **Hacking Insights:** Interagisci con contenuti che approfondiscono l’emozione e le sfide dell’hacking
- **Real-Time Hack News:** Rimani aggiornato sul mondo dell’hacking in rapida evoluzione tramite notizie e approfondimenti in tempo reale
- **Latest Announcements:** Rimani informato sui nuovi bug bounty lanciati e sugli aggiornamenti cruciali della piattaforma

**Unisciti a noi su** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e inizia a collaborare oggi con i migliori hacker!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security offre **formazione pratica sulla sicurezza AI** con un approccio **hands-on in laboratorio, orientato all’ingegneria**. I nostri corsi sono pensati per security engineer, professionisti AppSec e developer che vogliono **costruire, rompere e mettere in sicurezza applicazioni reali basate su AI/LLM**.

La **AI Security Certification** si concentra su competenze del mondo reale, tra cui:
- Mettere in sicurezza applicazioni LLM e AI-powered
- Threat modeling per sistemi AI
- Embeddings, vector databases e sicurezza RAG
- Attacchi LLM, scenari di abuso e difese pratiche
- Pattern di progettazione sicura e considerazioni di deployment

Tutti i corsi sono **on-demand**, **lab-driven** e progettati attorno a **compromessi di sicurezza del mondo reale**, non solo teoria.

👉 Maggiori dettagli sul corso AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** offre API in tempo reale, rapide e semplici per **accedere ai risultati dei motori di ricerca**. Effettua scraping dei motori di ricerca, gestisce i proxy, risolve i captcha e analizza per te tutti i dati strutturati ricchi.

Un abbonamento a uno dei piani di SerpApi include l’accesso a oltre 50 API diverse per fare scraping di vari motori di ricerca, tra cui Google, Bing, Baidu, Yahoo, Yandex e altri.\
A differenza di altri provider, **SerpApi non si limita a fare scraping dei risultati organici**. Le risposte di SerpApi includono costantemente tutti gli annunci, immagini e video inline, knowledge graph e altri elementi e funzionalità presenti nei risultati di ricerca.

Tra i clienti attuali di SerpApi ci sono **Apple, Shopify e GrubHub**.\
Per maggiori informazioni consulta il loro [**blog**](https://serpapi.com/blog/)**,** oppure prova un esempio nel loro [**playground**](https://serpapi.com/playground)**.**\
Puoi **creare un account gratuito** [**qui**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Impara le tecnologie e le competenze necessarie per svolgere vulnerability research, penetration testing e reverse engineering per proteggere applicazioni e dispositivi mobile. **Padroneggia la sicurezza iOS e Android** attraverso i nostri corsi on-demand e **ottieni la certificazione**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) è una società professionale di cybersecurity con sede ad **Amsterdam** che aiuta a **proteggere** aziende **in tutto il mondo** dalle ultime minacce di cybersecurity fornendo **servizi di offensive-security** con un approccio **moderno**.

WebSec è un’azienda di sicurezza internazionale con uffici ad Amsterdam e Wyoming. Offre **servizi di sicurezza tutto in uno**, il che significa che fa tutto: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing e molto altro.

Un altro aspetto interessante di WebSec è che, a differenza della media del settore, WebSec è **molto sicura delle proprie competenze**, al punto da **garantire i migliori risultati di qualità**; sul loro sito affermano: "**If we can't hack it, You don't pay it!**". Per maggiori informazioni dai un’occhiata al loro [**website**](https://websec.net/en/) e [**blog**](https://websec.net/blog/)!

Oltre a quanto sopra, WebSec è anche un **sostenitore convinto di HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Costruito per il campo. Costruito attorno a te.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) sviluppa e fornisce una formazione efficace in cybersecurity, costruita e guidata da esperti del settore. I loro programmi vanno oltre la teoria per fornire ai team una comprensione approfondita e competenze concrete, usando ambienti personalizzati che rispecchiano minacce del mondo reale. Per richieste di formazione personalizzata, contattaci [**qui**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Cosa distingue la loro formazione:**
* Contenuti e laboratori creati su misura
* Supportati da strumenti e piattaforme di alto livello
* Progettati e insegnati da professionisti

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions offre servizi specializzati di cybersecurity per istituzioni di **Education** e **FinTech**
, con un focus su **penetration testing, cloud security assessments** e
**compliance readiness** (SOC 2, PCI-DSS, NIST). Il nostro team include professionisti
certificati **OSCP e CISSP**, che apportano una profonda competenza tecnica e una visione
allineata agli standard del settore in ogni incarico.

Andiamo oltre le scansioni automatizzate con **testing manuale, guidato dall’intelligence**, adattato
ad ambienti ad alto rischio. Dalla protezione dei dati degli studenti alla tutela delle transazioni finanziarie,
aiutiamo le organizzazioni a difendere ciò che conta di più.

_“Una difesa di qualità richiede di conoscere l’offensiva; forniamo sicurezza attraverso la comprensione.”_

Rimani informato e aggiornato sulle ultime novità in cybersecurity visitando il nostro [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE consente a DevOps, DevSecOps e developer di gestire, monitorare e mettere in sicurezza i cluster Kubernetes in modo efficiente. Sfrutta le nostre analisi guidate dall’AI, il framework di sicurezza avanzato e l’intuitiva interfaccia CloudMaps GUI per visualizzare i tuoi cluster, comprenderne lo stato e agire con fiducia.

Inoltre, K8Studio è **compatibile con tutte le principali distribuzioni kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift e altre).

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
