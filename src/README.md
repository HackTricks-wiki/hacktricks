# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Loghi e motion design di HackTricks a cura di_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Esegui HackTricks in locale
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
La tua copia locale di HackTricks sarà disponibile all'indirizzo [http://localhost:3337](http://localhost:3337) dopo <5 minuti (è necessario creare il libro, porta pazienza).

In alternativa, se hai Docker Compose, puoi semplicemente eseguire quanto segue dalla root del repository:
```bash
docker compose up
```
Utilizza il `docker-compose.yml` incluso per servire il branch attualmente selezionato sull'host all'indirizzo [http://localhost:3337](http://localhost:3337), con live reload. Per cambiare lingua quando utilizzi Compose, seleziona il branch della lingua desiderata prima di avviare il servizio.

## Partner di HackTricks

---

## Amici di HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber offre servizi di penetration testing, security audit, exploit e ricerca, strumenti e formazione sulla sicurezza. Il suo sito descrive un team di penetration tester, programmatori e security researcher con oltre un decennio di esperienza.<sup>[[1]](#references)</sup>

Puoi consultare il loro **blog** all'indirizzo [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** supporta inoltre progetti open source di cybersecurity come HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti è un fornitore di servizi di sicurezza crowdsourced che offre bug bounty e penetration testing tramite una community globale di researcher. La sua piattaforma combina una copertura bug bounty continua con PTaaS on-demand e programmi gestiti di vulnerability disclosure.<sup>[[2]](#references)</sup>

**Consiglio sul bug bounty**: iscriviti a Intigriti tramite [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) ed esplora i suoi programmi bug bounty.

---

### [Modern Security – Piattaforma di formazione su AI e application security](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security offre formazione pratica e autonoma sulla sicurezza dell'AI per security engineer, professionisti AppSec e sviluppatori. La sua AI Security Certification tratta i fondamenti di LLM e agent, RAG e vector database, threat modeling, attacchi di prompt injection e MCP e architetture difensive.<sup>[[3]](#references)</sup>

👉 Maggiori dettagli sul corso di AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** fornisce API per Google e altri motori di ricerca, restituendo dati SERP strutturati con funzionalità come risultati basati sulla posizione, Maps, Shopping e Knowledge Graph.<sup>[[4]](#references)</sup>

Per maggiori informazioni, consulta il loro [**blog**](https://serpapi.com/blog/), prova un esempio nel loro [**playground**](https://serpapi.com/playground) oppure [**crea un account gratuito**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – Corsi approfonditi di mobile e AI security](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** offre corsi autonomi di mobile e AI security. Il catalogo tratta l'auditing e il reversing di applicazioni mobile con strumenti come Ghidra, Frida e LLDB, oltre a laboratori di attacco e difesa per AI/LLM.<sup>[[5]](#references)[[6]](#references)</sup>

Consulta il [catalogo dei corsi di 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – Scanner di sicurezza basato sull'AI](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** commercializza una piattaforma di offensive AI che mappa codice e infrastruttura, quindi utilizza agent statici e dinamici per individuare e validare vulnerabilità sfruttabili, fornendo prove proof-of-concept e indicazioni per la remediation.<sup>[[7]](#references)</sup>

**Consiglio sulla sicurezza del codice**: esplora Naxus per la scoperta di vulnerabilità focalizzata su codice e infrastruttura.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec offre servizi di penetration testing, security subscription, staffing e vulnerability assessment. Il suo sito afferma che opera a livello internazionale e si occupa di sicurezza offensiva, sicurezza difensiva e attività di governance, risk e compliance.<sup>[[8]](#references)</sup>

Per maggiori informazioni, visita il loro [**sito web**](https://websec.net/en/) o il loro [**blog**](https://websec.net/blog/).

Oltre a quanto sopra, WebSec è anche un **sostenitore convinto di HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Creato per il campo. Costruito intorno a te.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) offre formazione in cybersecurity condotta da esperti, con contenuti e laboratori personalizzati basati su infrastrutture reali. I suoi programmi sono adattati alle esigenze organizzative e coprono l'intero percorso, dall'assessment all'implementazione.<sup>[[9]](#references)</sup> Per richieste di formazione personalizzata, contattali [**qui**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Cosa distingue la loro formazione:**
* Contenuti e laboratori personalizzati
* Supportati da strumenti e piattaforme di alto livello
* Progettati e tenuti da professionisti del settore

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions si concentra sulla consulenza cybersecurity per **Education** e **FinTech**, includendo cloud assessment, penetration test interni ed esterni, vulnerability assessment e supporto alla compliance.<sup>[[10]](#references)</sup>

Resta informato e aggiornato sulle ultime novità in materia di cybersecurity visitando il nostro [**blog**](https://www.lasttowersolutions.com/blog).

---

### [K8Studio - La GUI più intelligente per gestire Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio è un IDE desktop per Kubernetes con visualizzazione CloudMaps, navigazione multi-cluster, RBAC, Helm, log, YAML e viste terminal. Il fornitore afferma che si connette tramite kubeconfig senza installare agent e supporta macOS, Windows, Linux e cluster air-gapped.<sup>[[11]](#references)</sup>

---

## Licenza e disclaimer

Consulta la voce HackTricks Values & FAQ nelle References sottostanti.

## Statistiche GitHub

![Statistiche GitHub di HackTricks](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [Certificazione AI Security – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [AI Security pratica: attacchi, difese e applicazioni](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Referral Intigriti HackTricks](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Video sulla sponsorizzazione di WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Corsi Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks Values & FAQ](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
