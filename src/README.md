# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_I loghi e il motion design di HackTricks sono di_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Eseguire HackTricks in locale
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
La tua copia locale di HackTricks sarà **disponibile all'indirizzo [http://localhost:3337](http://localhost:3337)** entro <5 minuti (è necessario compilare il libro, porta pazienza).

In alternativa, se hai Docker Compose, puoi semplicemente eseguire quanto segue dalla radice della repo:
```bash
docker compose up
```
Questo usa il `docker-compose.yml` incluso per servire la tua copia locale all'indirizzo [http://localhost:3337](http://localhost:3337) con live reload.

## Partner di HackTricks

---

## Amici di HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) è un'ottima azienda di cybersecurity il cui slogan è **HACK THE UNHACKABLE**. Conducono ricerche proprie e sviluppano i propri hacking tools per **offrire diversi preziosi servizi di cybersecurity**, come pentesting, Red teams e formazione.

Puoi consultare il loro **blog** su [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** supporta anche progetti open source di cybersecurity come HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** è la **piattaforma europea numero 1** di ethical hacking e **bug bounty.**

**Consiglio sul bug bounty**: **iscriviti** a **Intigriti**, una piattaforma **bug bounty premium creata da hacker per hacker**! Unisciti a noi su [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) oggi stesso e inizia a guadagnare ricompense fino a **100.000 $**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – Piattaforma di formazione su AI e Application Security](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security offre **formazione pratica in AI Security** con un **approccio pratico e orientato all'ingegneria, basato su laboratori**. I nostri corsi sono pensati per security engineer, professionisti AppSec e sviluppatori che vogliono **creare, attaccare e proteggere applicazioni reali basate su AI/LLM**.

La **certificazione AI Security** si concentra su competenze pratiche del mondo reale, tra cui:
- Protezione di applicazioni basate su LLM e AI
- Threat modeling per sistemi AI
- Embeddings, database vettoriali e sicurezza RAG
- Attacchi LLM, scenari di abuso e difese pratiche
- Pattern di progettazione sicuri e considerazioni sul deployment

Tutti i corsi sono **on-demand**, **basati su laboratori** e progettati intorno ai **compromessi di sicurezza del mondo reale**, non solo alla teoria.

👉 Maggiori dettagli sul corso AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** offre API rapide e semplici in tempo reale per **accedere ai risultati dei motori di ricerca**. Esegue lo scraping dei motori di ricerca, gestisce i proxy, risolve i captcha e analizza per te tutti i dati strutturati avanzati.

Un abbonamento a uno dei piani SerpApi include l'accesso a più di 50 API diverse per eseguire lo scraping di vari motori di ricerca, tra cui Google, Bing, Baidu, Yahoo, Yandex e altri.\
A differenza di altri provider, **SerpApi non esegue lo scraping solo dei risultati organici**. Le risposte di SerpApi includono costantemente tutti gli annunci, le immagini e i video inline, i knowledge graph e altri elementi e funzionalità presenti nei risultati di ricerca.

Tra gli attuali clienti di SerpApi figurano **Apple, Shopify e GrubHub**.\
Per maggiori informazioni, consulta il loro [**blog**](https://serpapi.com/blog/)**,** oppure prova un esempio nel loro [**playground**](https://serpapi.com/playground)**.**\
Puoi **creare un account gratuito** [**qui**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – Corsi approfonditi di Mobile e AI Security](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** ti forma nella sicurezza offensiva mobile e AI, con corsi tenuti da ricercatori attivi: lo stesso team che ha realizzato i writeup delle CVE e tenuto talk a Black Hat, HITB e Zer0con. I corsi sono autogestiti, organizzati intorno a laboratori su target reali e supportati da una certificazione pratica.

Il catalogo è suddiviso in due percorsi:

**Mobile Security** – iOS e Android, dal livello applicativo verso il basso: reverse engineering con Ghidra e LLDB, exploitation ARM64, internals del kernel e mitigazioni moderne (PAC, MTE, SELinux), meccanismi di jailbreak e rooting.

**AI Security** – due corsi completi che coprono l'intero ambito. Practical AI Security spiega come funzionano LLM, pipeline RAG, AI agent e MCP e come attaccarli e difenderli. Advanced AI Security è fortemente orientato alla pratica e affronta le tecniche più avanzate: red teaming di sistemi AI su larga scala con Garak e PyRIT, exploitation di server MCP, installazione e rilevamento di backdoor nei modelli e attacchi e difese tramite fine-tuning su Apple Silicon.

Corsi e certificazioni:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – Security Scanner basato su AI](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** è una piattaforma di sicurezza basata su AI che individua le vulnerabilità sfruttabili prima degli attaccanti.

**Consiglio sulla sicurezza del codice**: iscriviti a NaxusAI, una piattaforma intelligente di monitoraggio delle vulnerabilità pensata per sviluppatori e security team! Unisciti a noi oggi stesso e inizia a usare l'AI per **rilevare, convalidare e correggere i rischi reali per la sicurezza prima che raggiungano la produzione**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) è un'azienda professionale di cybersecurity con sede ad **Amsterdam**, che aiuta a **proteggere** le aziende **in tutto il mondo** dalle più recenti minacce informatiche, fornendo **servizi di offensive security** con un approccio **moderno**.

WebSec è un'azienda internazionale di sicurezza con uffici ad Amsterdam e Wyoming. Offre **servizi di sicurezza all-in-one**, occupandosi di tutto: Pentesting, audit di **Security**, formazione sulla consapevolezza, campagne di phishing, code review, exploit development, outsourcing di security expert e molto altro.

Un altro aspetto interessante di WebSec è che, a differenza della media del settore, WebSec è **molto sicura delle proprie competenze**, al punto da **garantire risultati della massima qualità**. Sul loro sito si legge: "**If we can't hack it, You don't pay it!**". Per maggiori informazioni, visita il loro [**sito web**](https://websec.net/en/) e il loro [**blog**](https://websec.net/blog/)!

Inoltre, WebSec è anche un **sostenitore convinto di HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Creato per il campo. Costruito intorno a te.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) sviluppa e offre formazione efficace in cybersecurity, creata e guidata da
esperti del settore. I loro programmi vanno oltre la teoria per fornire ai team una conoscenza approfondita
e competenze concrete, utilizzando ambienti personalizzati che riflettono le minacce del mondo reale.
Per richieste di formazione personalizzata, contattaci [**qui**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Cosa distingue la loro formazione:**
* Contenuti e laboratori creati su misura
* Supportati da strumenti e piattaforme di alto livello
* Progettati e tenuti da professionisti del settore

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions offre servizi specializzati di cybersecurity per istituzioni del settore **Education** e **FinTech**, con particolare attenzione a **penetration testing, valutazioni della sicurezza cloud** e **preparazione alla compliance** (SOC 2, PCI-DSS, NIST). Il nostro team comprende **professionisti certificati OSCP e CISSP**, che mettono a disposizione competenze tecniche approfondite e una conoscenza degli standard di settore per ogni incarico.

Andiamo oltre le scansioni automatizzate con **test manuali basati sull'intelligence**, personalizzati per ambienti ad alto rischio. Dalla protezione dei dati degli studenti alla sicurezza delle transazioni finanziarie, aiutiamo le organizzazioni a difendere ciò che conta di più.

_“Una difesa di qualità richiede la conoscenza dell'offesa; forniamo sicurezza attraverso la comprensione.”_

Rimani informato e aggiornato sulle ultime novità in cybersecurity visitando il nostro [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - La GUI più intelligente per gestire Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE permette a DevOps, DevSecOps e sviluppatori di gestire, monitorare e proteggere i cluster Kubernetes in modo efficiente. Sfrutta i nostri insight basati su AI, il framework di sicurezza avanzato e la GUI intuitiva CloudMaps per visualizzare i tuoi cluster, comprenderne lo stato e agire con sicurezza.

Inoltre, K8Studio è **compatibile con tutte le principali distribuzioni kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift e altre).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## Licenza e disclaimer

Consultali qui:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Statistiche Github

![Statistiche Github di HackTricks](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
