# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_I loghi e il design in movimento di Hacktricks sono di_ [_@ppiernacho_](https://www.instagram.com/ppieranacho/)_._

### Esegui HackTricks Localmente
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
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "cd /app && git config --global --add safe.directory /app && git checkout $LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
La tua copia locale di HackTricks sarà **disponibile su [http://localhost:3337](http://localhost:3337)** dopo <5 minuti (deve costruire il libro, sii paziente).

## Sponsor Aziendali

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) è una grande azienda di cybersecurity il cui slogan è **HACK THE UNHACKABLE**. Eseguono le proprie ricerche e sviluppano i propri strumenti di hacking per **offrire diversi servizi di cybersecurity di valore** come pentesting, Red teams e formazione.

Puoi controllare il loro **blog** su [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** supporta anche progetti open source di cybersecurity come HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) è l'evento di cybersecurity più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro fervente per professionisti della tecnologia e della cybersecurity in ogni disciplina.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** è la **piattaforma di ethical hacking e bug bounty #1 in Europa.**

**Suggerimento bug bounty**: **iscriviti** a **Intigriti**, una premium **piattaforma di bug bounty creata da hacker, per hacker**! Unisciti a noi su [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) oggi e inizia a guadagnare ricompense fino a **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) per costruire e **automatizzare flussi di lavoro** facilmente, alimentati dagli strumenti comunitari **più avanzati** al mondo.

Accedi oggi:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Unisciti al server [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) per comunicare con hacker esperti e cacciatori di bug bounty!

- **Approfondimenti sul hacking:** Interagisci con contenuti che approfondiscono l'emozione e le sfide dell'hacking
- **Notizie di hacking in tempo reale:** Rimani aggiornato con il mondo frenetico dell'hacking attraverso notizie e approfondimenti in tempo reale
- **Ultimi annunci:** Rimani informato sulle nuove ricompense bug che vengono lanciate e sugli aggiornamenti cruciali della piattaforma

**Unisciti a noi su** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e inizia a collaborare con i migliori hacker oggi!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - Il toolkit essenziale per il penetration testing

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Ottieni la prospettiva di un hacker sulle tue app web, rete e cloud**

**Trova e segnala vulnerabilità critiche e sfruttabili con un impatto reale sul business.** Usa i nostri oltre 20 strumenti personalizzati per mappare la superficie di attacco, trovare problemi di sicurezza che ti permettano di elevare i privilegi e utilizzare exploit automatizzati per raccogliere prove essenziali, trasformando il tuo duro lavoro in report persuasivi.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** offre API in tempo reale veloci e facili per **accedere ai risultati dei motori di ricerca**. Scrapeano i motori di ricerca, gestiscono i proxy, risolvono i captcha e analizzano tutti i dati strutturati ricchi per te.

Un abbonamento a uno dei piani di SerpApi include l'accesso a oltre 50 diverse API per lo scraping di diversi motori di ricerca, tra cui Google, Bing, Baidu, Yahoo, Yandex e altri.\
A differenza di altri fornitori, **SerpApi non si limita a scrapeare i risultati organici**. Le risposte di SerpApi includono costantemente tutti gli annunci, immagini e video inline, grafici di conoscenza e altri elementi e funzionalità presenti nei risultati di ricerca.

I clienti attuali di SerpApi includono **Apple, Shopify e GrubHub**.\
Per ulteriori informazioni, dai un'occhiata al loro [**blog**](https://serpapi.com/blog/)**,** o prova un esempio nel loro [**playground**](https://serpapi.com/playground)**.**\
Puoi **creare un account gratuito** [**qui**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – Corsi di Sicurezza Mobile Approfonditi](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Impara le tecnologie e le competenze necessarie per eseguire ricerche sulle vulnerabilità, penetration testing e reverse engineering per proteggere le applicazioni e i dispositivi mobili. **Diventa esperto in sicurezza iOS e Android** attraverso i nostri corsi on-demand e **ottieni una certificazione**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) è un'azienda di cybersecurity professionale con sede ad **Amsterdam** che aiuta **a proteggere** le aziende **in tutto il mondo** contro le ultime minacce di cybersecurity fornendo **servizi di sicurezza offensiva** con un approccio **moderno**.

WebSec è un'azienda di sicurezza internazionale con uffici ad Amsterdam e Wyoming. Offrono **servizi di sicurezza all-in-one**, il che significa che fanno tutto; Pentesting, **Audit** di Sicurezza, Formazione sulla Consapevolezza, Campagne di Phishing, Revisione del Codice, Sviluppo di Exploit, Outsourcing di Esperti di Sicurezza e molto altro.

Un'altra cosa interessante di WebSec è che, a differenza della media del settore, WebSec è **molto sicura delle proprie competenze**, tanto da **garantire i migliori risultati di qualità**, come dichiarato sul loro sito web "**Se non possiamo hackarlo, non lo paghi!**". Per ulteriori informazioni, dai un'occhiata al loro [**sito web**](https://websec.net/en/) e [**blog**](https://websec.net/blog/)!

In aggiunta a quanto sopra, WebSec è anche un **sostenitore impegnato di HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) è un motore di ricerca per violazioni di dati (leak). \
Forniamo ricerca di stringhe casuali (come google) su tutti i tipi di leak di dati grandi e piccoli --non solo i più grandi-- su dati provenienti da più fonti. \
Ricerca di persone, ricerca AI, ricerca di organizzazioni, accesso API (OpenAPI), integrazione theHarvester, tutte le funzionalità di cui un pentester ha bisogno.\
**HackTricks continua a essere una grande piattaforma di apprendimento per tutti noi e siamo orgogliosi di sponsorizzarla!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

## Licenza e Dichiarazione di Non Responsabilità

Controllali in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Statistiche Github

![Statistiche Github di HackTricks](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
