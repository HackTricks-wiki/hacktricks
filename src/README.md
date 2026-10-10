# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Loghi e motion design di Hacktricks_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```

La tua copia locale di HackTricks sarà **disponibile su [http://localhost:3337](http://localhost:3337)** dopo <5 minuti (è necessario compilare il libro, attendi con pazienza).

In alternativa, se hai Docker Compose, puoi semplicemente eseguire quanto segue dalla root del repository:

```bash
docker compose up
```

Questo utilizza il `docker-compose.yml` incluso per servire il branch attualmente selezionato sull’host all’indirizzo [http://localhost:3337](http://localhost:3337), con ricaricamento live. Per cambiare lingua usando Compose, effettuate il checkout del branch della lingua desiderata prima di avviare il servizio.

## Partner di HackTricks

---

## Amici di HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber offre penetration testing, audit di sicurezza, attività di exploit e ricerca, strumenti e servizi di sensibilizzazione sulla sicurezza. Il suo sito descrive un team di penetration tester, programmatori e ricercatori di sicurezza con oltre dieci anni di esperienza.<sup>[[1]](#references)</sup>

Potete consultare il loro **blog** all’indirizzo [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** sostiene anche progetti open source di cybersecurity come HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti è un provider di sicurezza crowdsourced che offre servizi di bug bounty e penetration testing tramite una community globale di ricercatori. La sua piattaforma combina una copertura continuativa di bug bounty con servizi PTaaS on-demand e programmi gestiti di divulgazione delle vulnerabilità.<sup>[[2]](#references)</sup>

**Consiglio sul bug bounty**: iscrivetevi a Intigriti tramite [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) ed esplorate i suoi programmi di bug bounty.

---

### [Modern Security – Piattaforma di formazione sulla sicurezza AI e delle applicazioni](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security offre formazione pratica e autogestita sulla sicurezza AI per security engineer, professionisti AppSec e sviluppatori. La sua certificazione AI Security tratta le nozioni fondamentali su LLM e agenti, RAG e database vettoriali, threat modeling, attacchi di prompt injection e MCP e architetture difensive.<sup>[[3]](#references)</sup>

👉 Maggiori dettagli sul corso AI Security:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** fornisce API per Google e altri motori di ricerca, restituendo dati SERP strutturati con funzionalità come risultati basati sulla posizione, Maps, Shopping e risultati del Knowledge Graph.<sup>[[4]](#references)</sup>

Per maggiori informazioni, consultate il loro [**blog**](https://serpapi.com/blog/), provate un esempio nel loro [**playground**](https://serpapi.com/playground) o [**create un account gratuito**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – Corsi approfonditi di sicurezza mobile e AI](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** offre corsi autogestiti sulla sicurezza mobile e AI. Il catalogo comprende audit e reversing di applicazioni mobile con strumenti come Ghidra, Frida e LLDB, oltre a laboratori di attacco e difesa AI/LLM.<sup>[[5]](#references)[[6]](#references)</sup>

Consultate il [catalogo dei corsi di 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – Scanner di sicurezza basato sull’AI](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** propone una piattaforma di offensive AI che mappa codice e infrastruttura, quindi utilizza agenti statici e dinamici per individuare e convalidare vulnerabilità sfruttabili, fornendo prove proof-of-concept e indicazioni per la correzione.<sup>[[7]](#references)</sup>

**Consiglio sulla sicurezza del codice**: esplorate Naxus per individuare vulnerabilità nel codice e nell’infrastruttura.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec offre servizi di penetration testing, abbonamenti di sicurezza, staffing e valutazione delle vulnerabilità. Il suo sito afferma che opera a livello internazionale e si occupa di sicurezza offensiva e difensiva, nonché di governance, gestione del rischio e conformità.<sup>[[8]](#references)</sup>

Per maggiori informazioni, visitate il loro [**sito web**](https://websec.net/en/) o il loro [**blog**](https://websec.net/blog/).

Oltre a quanto sopra, WebSec è anche un **sostenitore convinto di HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Progettata per il campo. Pensata per voi.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) offre formazione in cybersecurity tenuta da esperti, con contenuti e laboratori personalizzati basati su infrastrutture reali. I suoi programmi sono adattati alle esigenze delle organizzazioni e coprono tutte le fasi, dalla valutazione all’implementazione.<sup>[[9]](#references)</sup> Per richiedere una formazione personalizzata, contattateli [**qui**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Cosa distingue la loro formazione:**
* Contenuti e laboratori personalizzati
* Supporto di strumenti e piattaforme di alto livello
* Ideata e tenuta da professionisti del settore

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions si occupa di consulenza sulla cybersecurity per i settori **Education** e **FinTech**, includendo valutazioni cloud, penetration test interni ed esterni, valutazioni delle vulnerabilità e supporto alla conformità.<sup>[[10]](#references)</sup>

Per rimanere informati e aggiornati sulle ultime novità in materia di cybersecurity, visitate il nostro [**blog**](https://www.lasttowersolutions.com/blog).

---

### [K8Studio - L’interfaccia grafica più intelligente per gestire Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio è un IDE desktop per Kubernetes con visualizzazione CloudMaps, navigazione multi-cluster, RBAC, Helm, log, YAML e viste terminale. Il fornitore afferma che si connette tramite kubeconfig senza installare agenti e supporta macOS, Windows, Linux e cluster air-gapped.<sup>[[11]](#references)</sup>

---

## Licenza e disclaimer

Consultate la voce HackTricks Values & FAQ nella sezione References qui sotto.

## Statistiche Github

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [Certificazione AI Security – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Sicurezza AI pratica: attacchi, difese e applicazioni](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Referral Intigriti HackTricks](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Video sulla sponsorizzazione di WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Corsi Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [Valori e FAQ di HackTricks](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
