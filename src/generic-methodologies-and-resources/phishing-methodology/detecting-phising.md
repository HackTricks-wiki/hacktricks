# Rilevare il Phishing

{{#include ../../banners/hacktricks-training.md}}

## Introduzione

Per rilevare un tentativo di phishing è importante **comprendere le tecniche di phishing utilizzate al giorno d'oggi**. Nella pagina principale di questo post puoi trovare queste informazioni; quindi, se non conosci le tecniche utilizzate oggi, ti consiglio di visitare la pagina principale e leggere almeno quella sezione.

Questo post si basa sull'idea che gli **attaccanti cercheranno in qualche modo di imitare o utilizzare il nome del dominio della vittima**. Se il tuo dominio si chiama `example.com` e subisci un phishing utilizzando, per qualche motivo, un nome di dominio completamente diverso come `youwonthelottery.com`, queste tecniche non riusciranno a scoprirlo.

## Variazioni del nome di dominio

È abbastanza **facile** **scoprire** quei tentativi di **phishing** che utilizzano un nome di dominio **simile** all'interno dell'email.\
È sufficiente **generare un elenco dei nomi di phishing più probabili** che un attaccante potrebbe utilizzare e **verificare** se sono **registrati**, oppure controllare semplicemente se esiste un **IP** che li utilizza.

### Individuazione di domini sospetti

A questo scopo puoi utilizzare uno dei seguenti strumenti. Nota che questi strumenti eseguiranno automaticamente anche richieste DNS per verificare se al dominio è assegnato un IP:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Suggerimento: se generi un elenco di candidati, inseriscilo anche nei log del tuo resolver DNS per rilevare **ricerche NXDOMAIN provenienti dall'interno della tua organizzazione** (utenti che cercano di raggiungere un typo prima che l'attaccante lo registri effettivamente). Inserisci questi domini in un sinkhole o blocca preventivamente tali domini, se consentito dalle policy.

### Bitflipping

**Puoi trovare una breve spiegazione di questa tecnica nella pagina principale. Oppure leggere la ricerca originale su** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[1]](#references)</sup>

Ad esempio, una modifica di 1 bit nel dominio microsoft.com può trasformarlo in _windnws.com._\
**Gli attaccanti possono registrare il maggior numero possibile di domini bit-flipping correlati alla vittima per reindirizzare gli utenti legittimi verso la propria infrastruttura**.<sup>[[1]](#references)</sup>

**Tutti i possibili nomi di dominio bit-flipping dovrebbero essere monitorati.**

Se devi considerare anche gli homoglyph/lookalike IDN (ad esempio, la combinazione di caratteri latini e cirillici), consulta:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Controlli di base

Una volta ottenuto un elenco di potenziali nomi di dominio sospetti, dovresti **controllarli** (principalmente sulle porte HTTP e HTTPS) per **verificare se utilizzano un modulo di login simile** a quello di uno dei domini della vittima.\
Potresti anche controllare la porta 3333 per verificare se è aperta e se esegue un'istanza di `gophish`.\
È inoltre utile sapere **quanto è vecchio ciascun dominio sospetto individuato**: più è recente, maggiore è il rischio.\
Puoi anche ottenere **screenshot** della pagina web sospetta HTTP e/o HTTPS per verificare se è sospetta e, in tal caso, **accedervi per esaminarla più a fondo**.

### Controlli avanzati

Se vuoi spingerti oltre, ti consiglio di **monitorare periodicamente questi domini sospetti e cercarne altri** (ogni giorno? richiede solo pochi secondi/minuti). Dovresti inoltre **controllare** le **porte** aperte degli IP correlati e **cercare istanze di `gophish` o strumenti simili** (sì, anche gli attaccanti commettono errori), oltre a **monitorare le pagine web HTTP e HTTPS dei domini e sottodomini sospetti** per verificare se hanno copiato un modulo di login dalle pagine web della vittima.\
Per **automatizzare questa attività**, ti consiglio di avere un elenco dei moduli di login dei domini della vittima, eseguire lo spidering delle pagine web sospette e confrontare ogni modulo di login trovato nei domini sospetti con ciascun modulo di login del dominio della vittima utilizzando qualcosa come `ssdeep`.\
Se hai individuato i moduli di login dei domini sospetti, puoi provare a **inviare credenziali fittizie** e **verificare se il reindirizzamento porta al dominio della vittima**.

---

### Ricerca tramite favicon e fingerprint web (Shodan/ZoomEye/Censys)

Molti kit di phishing riutilizzano le favicon del brand che impersonano. Gli scanner dell'intera Internet calcolano un MurmurHash3 della favicon codificata in base64. Puoi generare l'hash ed eseguire il pivot su di esso:

Esempio Python (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Query Shodan: `http.favicon.hash:309020573`
- Con strumenti: esamina tool della community come favfreak per generare hash e dork per Shodan/ZoomEye/Censys.

Note
- I favicon vengono riutilizzati; considera le corrispondenze come indizi e convalida contenuti e certificati prima di agire.
- Combina questi dati con euristiche relative all'età del dominio e alle parole chiave per una maggiore precisione.

### Ricerca della telemetria degli URL (urlscan.io)

`urlscan.io` memorizza screenshot storici, DOM, richieste e metadati TLS degli URL inviati. Puoi cercare casi di abuso del brand e cloni:<sup>[[2]](#references)</sup>

Query di esempio (UI o API):
- Trova lookalike escludendo i tuoi domini legittimi: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Trova i siti che usano in hotlink i tuoi asset: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Limita i risultati recenti: aggiungi `AND date:>now-7d`

Esempio di API:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Dal JSON, esegui il pivot su:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` per individuare certificati molto recenti relativi a lookalike
- valori di `task.source` come `certstream-suspicious` per collegare i risultati al monitoraggio CT

### Età del dominio tramite RDAP (scriptable)

RDAP restituisce eventi di creazione leggibili dalle macchine. Utile per segnalare i **domini registrati di recente (NRD)**.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Arricchisci la tua pipeline assegnando ai domini categorie basate sull'anzianità di registrazione (ad es., <7 giorni, <30 giorni) e assegna loro una priorità di triage di conseguenza.

### Fingerprint TLS/JAx per individuare l'infrastruttura AiTM

Il credential-phishing moderno utilizza sempre più reverse proxy **Adversary-in-the-Middle (AiTM)** (ad es., Evilginx) per rubare session token. Puoi aggiungere rilevamenti lato rete:

- Registra i fingerprint TLS/HTTP (JA3/JA4/JA4S/JA4H) in uscita. È stato osservato che alcune build di Evilginx presentano valori JA4 client/server stabili. Genera alert solo sui fingerprint noti come dannosi, considerandoli un segnale debole, e conferma sempre con informazioni sul contenuto e sui domini.<sup>[[3]](#references)</sup>
- Registra proattivamente i metadati dei certificati TLS (issuer, numero di SAN, uso di wildcard, validità) per gli host simili individuati tramite CT o urlscan e correla questi dati con l'anzianità del DNS e la geolocalizzazione.

> Nota: considera i fingerprint come arricchimento, non come unici elementi per bloccare il traffico; i framework evolvono e possono randomizzarli o offuscarli.

### Nomi di dominio che utilizzano keyword

La pagina principale menziona anche una tecnica di variazione del nome di dominio che consiste nell'inserire il **nome di dominio della vittima all'interno di un dominio più grande** (ad es., paypal-financial.com per paypal.com).

#### Certificate Transparency

Non è possibile adottare il precedente approccio di "Brute-Force", ma è **possibile scoprire tali tentativi di phishing** anche grazie alla certificate transparency. Ogni volta che un certificato viene emesso da una CA, i relativi dettagli vengono resi pubblici. Ciò significa che, leggendo o monitorando la certificate transparency, è **possibile trovare domini che utilizzano una keyword nel proprio nome**. Ad esempio, se un attacker genera un certificato per [https://paypal-financial.com](https://paypal-financial.com), esaminando il certificato è possibile trovare la keyword "paypal" e sapere che viene utilizzata un'email sospetta.

Il post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) suggerisce di usare Censys per cercare certificati associati a una keyword specifica e filtrare per data (solo certificati "nuovi") e per issuer della CA "Let's Encrypt":<sup>[[4]](#references)</sup>

![https://0xpatrik.com/phishing-domains/](<../../images/image (1115).png>)

Tuttavia, puoi fare "la stessa cosa" usando il servizio web gratuito [**crt.sh**](https://crt.sh). Puoi **cercare la keyword** e **filtrare** i risultati **per data e CA**, se lo desideri.

![Nomi di dominio che utilizzano keyword - Certificate Transparency: Tuttavia, puoi fare "la stessa cosa" usando il servizio web gratuito crt.sh. Puoi cercare la keyword e filtrare i risultati per data e...](<../../images/image (519).png>)

Con quest'ultima opzione puoi anche usare il campo Matching Identities per verificare se un'identità del dominio reale corrisponde a uno dei domini sospetti (nota che un dominio sospetto può essere un falso positivo).

**Un'altra alternativa** è l'eccellente progetto chiamato [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream fornisce uno stream in tempo reale dei certificati appena generati, che puoi usare per rilevare keyword specificate in tempo quasi reale. Esiste infatti un progetto chiamato [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) che fa proprio questo.

Suggerimento pratico: durante il triage dei risultati CT, assegna la priorità agli NRD, ai registrar non attendibili/sconosciuti, ai WHOIS con privacy proxy e ai certificati con valori `NotBefore` molto recenti. Mantieni un allowlist dei domini/brand di tua proprietà per ridurre il rumore.

#### **Nuovi domini**

**Un'ultima alternativa** consiste nel raccogliere un elenco di **domini registrati di recente** per alcuni TLD ([Whoxy](https://www.whoxy.com/newly-registered-domains/) fornisce questo servizio) e **controllare le keyword presenti in questi domini**. Tuttavia, i domini lunghi utilizzano solitamente uno o più subdomain; pertanto, la keyword potrebbe non comparire all'interno dell'FLD e non sarà possibile trovare il subdomain di phishing.

Heuristica aggiuntiva: considera con maggiore sospetto nei tuoi alert alcuni **TLD con estensione di file** (ad es., `.zip`, `.mov`). Questi vengono comunemente confusi con nomi di file nei lure; combina il segnale del TLD con le keyword del brand e l'anzianità dell'NRD per ottenere una maggiore precisione.

## Riferimenti

- [1] [Hijacking del traffico verso windows.com di Microsoft con il bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [2] [urlscan.io – Riferimento della Search API](https://urlscan.io/docs/search/)
- [3] [Blog APNIC – Fingerprinting di rete JA4+](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [4] [Individuare il phishing: strumenti e tecniche](https://0xpatrik.com/phishing-domains/)

{{#include ../../banners/hacktricks-training.md}}
