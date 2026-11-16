# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Loghi e motion design di Hacktricks a cura di_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Eseguire HackTricks in locale

```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks

# Select the language you want to use
export HT_LANG="master" # Leave master for English
# "af" for Afrikaans
# "de" for German
# "el" for Greek
# "es" for Spanish
# "fr" for French
# "hi" for Hindi
# "it" for Italian
# "ja" for Japanese
# "ko" for Korean
# "pl" for Polish
# "pt" for Portuguese
# "sr" for Serbian
# "sw" for Swahili
# "tr" for Turkish
# "uk" for Ukrainian
# "vi" for Vietnamese
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```

La tua copia locale di HackTricks sarà **disponibile su [http://localhost:3337](http://localhost:3337)** entro <5 minuti (deve compilare il libro, porta pazienza).

In alternativa, se hai Docker Compose, puoi semplicemente eseguire quanto segue dalla root del repository:

```bash
docker compose up
```

Questo usa il `docker-compose.yml` incluso per pubblicare, all’indirizzo [http://localhost:3337](http://localhost:3337) e con live reload, il branch attualmente selezionato sull’host. Per cambiare lingua quando usi Compose, seleziona il branch della lingua desiderata prima di avviare il servizio.

## Partner di HackTricks

---

## Amici di HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber offre penetration testing, audit di sicurezza, attività di exploit e ricerca, strumenti e servizi di sensibilizzazione sulla sicurezza. Il suo sito descrive un team di penetration tester, programmatori e ricercatori di sicurezza con oltre un decennio di esperienza.<sup>[[1]](#references)</sup>

Puoi consultare il loro **blog** su [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** supporta anche progetti open source di cybersecurity come HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti è un fornitore di sicurezza crowdsourced che offre servizi di bug bounty e penetration testing tramite una community globale di ricercatori. La sua piattaforma combina una copertura continua di bug bounty con PTaaS on demand e programmi gestiti di divulgazione delle vulnerabilità.<sup>[[2]](#references)</sup>

**Consiglio sul bug bounty**: registrati a Intigriti tramite [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) ed esplora i suoi programmi di bug bounty.

---

### [Modern Security – Piattaforma di formazione su AI e sicurezza delle applicazioni](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security offre corsi pratici e autogestiti sulla sicurezza dell’AI, rivolti a security engineer, professionisti AppSec e sviluppatori. La sua certificazione AI Security tratta le basi di LLM e agenti, RAG e database vettoriali, threat modeling, attacchi di prompt injection e MCP e architettura difensiva.<sup>[[3]](#references)</sup>

👉 Maggiori dettagli sul corso AI Security:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** fornisce API per Google e altri motori di ricerca, restituendo dati SERP strutturati con funzionalità quali risultati basati sulla posizione, Maps, Shopping e risultati del Knowledge Graph.<sup>[[4]](#references)</sup>

Per saperne di più, consulta il loro [**blog**](https://serpapi.com/blog/), prova un esempio nel loro [**playground**](https://serpapi.com/playground) oppure [**crea un account gratuito**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – Corsi approfonditi di sicurezza mobile e AI](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** offre corsi autogestiti sulla sicurezza mobile e AI. Il catalogo tratta l’audit e il reverse engineering delle applicazioni mobile con strumenti come Ghidra, Frida e LLDB, oltre a laboratori sugli attacchi e le difese di AI/LLM.<sup>[[5]](#references)[[6]](#references)</sup>

Consulta il [catalogo dei corsi di 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – Sicurezza offensiva autonoma](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt="NaxusAI logo"><figcaption></figcaption></figure>

**Naxus** è una piattaforma di sicurezza offensiva basata sull’AI che esegue scansioni complete della superficie d’attacco esterna, audit di app mobile, test black-box di applicazioni web e revisioni del codice sorgente. I suoi agenti verificano i risultati sfruttabili e forniscono prove tracciabili, exploit proof-of-concept e indicazioni concrete per la correzione.<sup>[[7]](#references)</sup>

**Consiglio per gli audit di sicurezza**: usa Naxus per audit autonomi end-to-end di asset esterni, app mobile, applicazioni web e codice sorgente.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec offre penetration testing, abbonamenti di sicurezza, servizi di staffing e valutazioni delle vulnerabilità. Il suo sito dichiara di operare a livello internazionale e di occuparsi di sicurezza offensiva, sicurezza difensiva e attività di governance, rischio e conformità.<sup>[[8]](#references)</sup>

Per saperne di più, visita il loro [**sito web**](https://websec.net/en/) o il loro [**blog**](https://websec.net/blog/).

Oltre a quanto indicato sopra, WebSec è anche un **sostenitore convinto di HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Progettato per il campo. Pensato per te.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) offre formazione sulla cybersecurity tenuta da esperti, con contenuti e laboratori realizzati su misura e basati su infrastrutture reali. I suoi programmi sono adattati alle esigenze delle organizzazioni e coprono tutte le fasi, dalla valutazione all’implementazione.<sup>[[9]](#references)</sup> Per richiedere una formazione personalizzata, contattali [**qui**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Cosa rende unica la loro formazione:**
* Contenuti e laboratori realizzati su misura
* Basata su strumenti e piattaforme di alto livello
* Progettata e tenuta da professionisti del settore

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions si occupa di consulenza in cybersecurity per **istruzione** e **FinTech**, offrendo valutazioni cloud, penetration test interni ed esterni, valutazioni delle vulnerabilità e supporto per la conformità.<sup>[[10]](#references)</sup>

Resta informato e aggiornato sulle ultime novità in ambito cybersecurity visitando il nostro [**blog**](https://www.lasttowersolutions.com/blog).

---

### [Beaki — Cibo su misura per te](https://www.beaki.app/)

<figure class="sponsor-logo"><img src="images/beaki-logo.png" alt="Beaki logo"><figcaption></figcaption></figure>

**Beaki** è uno scanner di alimenti personalizzato, un contacalorie e un tracker nutrizionale. Scansiona i codici a barre e gli scaffali dei supermercati, fotografa o descrivi i pasti e i menu dei ristoranti e ottieni punteggi spiegabili, adattati ai tuoi obiettivi, alla tua dieta, alle tue allergie e al tuo profilo di salute. Beaki tiene anche traccia di calorie e macronutrienti e crea piani alimentari personalizzati con liste della spesa.<sup>[[11]](#references)</sup>

[**Scarica Beaki gratis**](https://www.beaki.app/?utm_source=hacktricks&utm_medium=partner&utm_campaign=hacktricks) su Android o iPhone.

---

## Licenza e dichiarazione di non responsabilità

Consulta la voce Valori e FAQ di HackTricks nei riferimenti qui sotto.

## Statistiche GitHub

![Statistiche GitHub di HackTricks](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [Certificazione AI Security – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Sicurezza pratica dell’AI: attacchi, difese e applicazioni](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [Beaki](https://www.beaki.app/)
- [12] [Referral Intigriti HackTricks](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Video sulla sponsorizzazione WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Corsi Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [Valori e FAQ di HackTricks](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
