# Detecting Phishing

{{#include ../../banners/hacktricks-training.md}}

## Introduction

To detect a phishing attempt it's important to **understand the phishing techniques that are being used nowadays**. On the parent page of this post, you can find this information, so if you aren't aware of which techniques are being used today I recommend you to go to the parent page and read at least that section.

This post is based on the idea that the **attaccanti cercheranno in qualche modo di imitare o usare il dominio della vittima**. If your domain is called `example.com` and you are phished using a completely different domain name for some reason like `youwonthelottery.com`, these techniques aren't going to uncover it.

## Domain name variations

È piuttosto **facile** **scoprire** quei tentativi di **phishing** che useranno un **nome di dominio simile** all'interno dell'email.\
Basta **generare una lista dei nomi di phishing più probabili** che un attaccante potrebbe utilizzare e **controllare** se è **registrato** o semplicemente verificare se esiste qualche **IP** che lo sta usando.

### Finding suspicious domains

A questo scopo puoi usare uno qualsiasi dei seguenti tool. Nota che questi strumenti effettueranno automaticamente richieste DNS per verificare se il dominio ha un IP assegnato:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Suggerimento: Se generi una lista di candidati, inseriscila anche nei log del tuo resolver DNS per rilevare **NXDOMAIN lookups dall'interno della tua org** (utenti che cercano di raggiungere un typo prima che l'attaccante lo registri). Se la policy lo consente, sinkhole o pre-block questi domini.

### Bitflipping

**You can find a short the explanation of this technique in the parent page. Or read the original research in** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Per esempio, una modifica di 1 bit nel dominio microsoft.com può trasformarlo in _windnws.com._\
**Gli attaccanti possono registrare quanti più domini bit-flipping possibile correlati alla vittima per reindirizzare utenti legittimi alla loro infrastruttura**.

**Tutti i possibili nomi di dominio bit-flipping dovrebbero essere monitorati.**

Se devi anche considerare lookalike homoglyph/IDN (ad es., mescolare caratteri Latini/Cirillici), controlla:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Basic checks

Una volta che hai una lista di potenziali nomi di dominio sospetti dovresti **controllarli** (principalmente le porte HTTP e HTTPS) per **vedere se stanno usando qualche login form simile** a quelli del dominio della vittima.\
Potresti anche verificare la porta 3333 per vedere se è aperta ed esegue un'istanza di `gophish`.\
È anche interessante sapere **da quanto tempo ciascun dominio sospetto è stato registrato**: più è giovane, più è rischioso.\
Puoi anche ottenere **screenshot** della pagina web HTTP e/o HTTPS sospetta per vedere se è sospetta e in tal caso **accedervi per esaminarla più a fondo**.

### Advanced checks

Se vuoi fare un passo in più ti raccomanderei di **monitorare quei domini sospetti e cercarne di nuovi** di tanto in tanto (ogni giorno? ci vuole solo qualche secondo/minuto). Dovresti anche **controllare** le **porte** aperte degli IP correlati e **cercare istanze di `gophish` o tool simili** (sì, anche gli attaccanti commettono errori) e **monitorare le pagine HTTP e HTTPS dei domini e sottodomini sospetti** per vedere se hanno copiato qualche login form dalle pagine della vittima.\
Per **automatizzare questo** consiglierei di avere una lista dei login form dei domini della vittima, spiderare le pagine sospette e confrontare ogni login form trovato all'interno dei domini sospetti con ogni login form del dominio della vittima usando qualcosa come `ssdeep`.\
Se hai localizzato i login form dei domini sospetti, puoi provare a **inviare credenziali fittizie** e **verificare se ti reindirizzano al dominio della vittima**.

---

### Hunting by favicon and web fingerprints (Shodan/ZoomEye/Censys)

Molti kit di phishing riutilizzano i favicon del brand che imitano. Gli scanner a livello Internet calcolano un MurmurHash3 del favicon codificato in base64. Puoi generare l'hash e pivotare su di esso:

Python example (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Interroga Shodan: `http.favicon.hash:309020573`
- Con gli strumenti: guarda tool della community come favfreak per generare hashes e dorks per Shodan/ZoomEye/Censys.

Note
- I favicon vengono riutilizzati; tratta le corrispondenze come lead e valida il contenuto e i certs prima di agire.
- Combina con domain-age e keyword heuristics per maggiore precisione.

### Ricerca telemetria URL (urlscan.io)

`urlscan.io` memorizza screenshot storici, DOM, requests e metadata TLS degli URL inviati. Puoi cercare brand abuse e clone:

Esempi di query (UI o API):
- Trova lookalike escludendo i tuoi domini legittimi: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Trova siti che hotlinkano i tuoi asset: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Restringi ai risultati recenti: aggiungi `AND date:>now-7d`

Esempio API:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Dal JSON, pivot on:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` per individuare certificati molto nuovi per lookalikes
- `task.source` valori come `certstream-suspicious` per collegare i riscontri al CT monitoring

### Domain age via RDAP (scriptable)

RDAP restituisce eventi di creazione leggibili dalle macchine. Utile per segnalare **domini appena registrati (NRDs)**.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Arricchisci la tua pipeline taggando i domini con fasce d'età di registrazione (es. <7 giorni, <30 giorni) e prioritizza la triage di conseguenza.

### Fingerprint TLS/JAx per individuare infrastrutture AiTM

Il moderno credential-phishing utilizza sempre più spesso proxy inversi **Adversary-in-the-Middle (AiTM)** (es. Evilginx) per rubare i token di sessione. Puoi aggiungere rilevazioni lato rete:

- Registra i fingerprint TLS/HTTP (JA3/JA4/JA4S/JA4H) in uscita. Alcune build di Evilginx sono state osservate con valori JA4 client/server stabili. Allerta sui fingerprint noti come malevoli solo come indicatore debole e conferma sempre con il contenuto e l'intelligence sui domini.
- Registra proattivamente i metadata dei certificati TLS (issuer, numero di SAN, uso di wildcard, validità) per host lookalike scoperti tramite CT o urlscan e correlali con l'età DNS e la geolocalizzazione.

> Nota: considera i fingerprint come arricchimento, non come unici blocchi; i framework evolvono e possono randomizzare o offuscare.

### Nomi di dominio che contengono keyword

La pagina principale menziona anche una tecnica di variazione del nome di dominio che consiste nell'inserire il **nome di dominio della vittima all'interno di un dominio più grande** (es. paypal-financial.com per paypal.com).

#### Certificate Transparency

Non è possibile adottare il precedente approccio "Brute-Force", ma è invece possibile scoprire questi tentativi di phishing anche grazie a Certificate Transparency. Ogni volta che un certificato viene emesso da una CA, i dettagli sono resi pubblici. Questo significa che leggendo la certificate transparency o monitorandola è possibile trovare domini che usano una keyword all'interno del loro nome. Per esempio, se un attaccante genera un certificato di [https://paypal-financial.com](https://paypal-financial.com), vedendo il certificato è possibile trovare la keyword "paypal" e sapere che un dominio sospetto è in uso.

Il post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) suggerisce che puoi usare Censys per cercare certificati contenenti una specifica keyword e filtrare per data (solo certificati "nuovi") e per CA issuer "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Tuttavia, puoi fare la "stessa cosa" usando il sito web gratuito [**crt.sh**](https://crt.sh). Puoi **cercare la keyword** e **filtrare** i risultati **per data e CA** se desideri.

![](<../../images/image (519).png>)

Usando quest'ultima opzione puoi anche utilizzare il campo Matching Identities per vedere se qualche identity del dominio reale corrisponde a uno dei domini sospetti (nota che un dominio sospetto può essere un falso positivo).

**Un'altra alternativa** è il fantastico progetto chiamato [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream fornisce uno stream in tempo reale di certificati appena generati che puoi usare per rilevare keyword specifiche in (quasi) tempo reale. Infatti, c'è un progetto chiamato [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) che fa proprio questo.

Practical tip: quando triaghi i ritrovamenti CT, prioritizza NRD, registrar non affidabili/sconosciuti, WHOIS con privacy-proxy e certificati con tempi `NotBefore` molto recenti. Mantieni una allowlist dei domini/marchi di tua proprietà per ridurre il rumore.

#### **Nuovi domini**

**Un'ultima alternativa** è raccogliere una lista di **domini appena registrati** per alcuni TLD ([Whoxy](https://www.whoxy.com/newly-registered-domains/) fornisce questo servizio) e **controllare le keyword in questi domini**. Tuttavia, i domini lunghi di solito usano uno o più sottodomini, quindi la keyword potrebbe non apparire all'interno del FLD e non riuscirai a trovare il sottodominio di phishing.

Heuristica aggiuntiva: considera con sospetto alcune **TLD da estensione file** (es., `.zip`, `.mov`) negli avvisi. Questi vengono comunemente confusi con nomi di file nelle esche; combina il segnale del TLD con keyword del brand e l'età NRD per maggiore precisione.

## Riferimenti

- urlscan.io – Search API reference: https://urlscan.io/docs/search/
- APNIC Blog – JA4+ network fingerprinting (includes Evilginx example): https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/

{{#include ../../banners/hacktricks-training.md}}
