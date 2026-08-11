# Rilevare il Phishing

{{#include ../../banners/hacktricks-training.md}}

## Introduzione

Per rilevare un tentativo di phishing è importante **comprendere le tecniche di phishing utilizzate al giorno d'oggi**. Nella pagina principale di questo post puoi trovare queste informazioni; quindi, se non conosci le tecniche utilizzate oggi, ti consiglio di visitare la pagina principale e leggere almeno quella sezione.

Questo post si basa sull'idea che gli **attaccanti cercheranno in qualche modo di imitare o utilizzare il nome di dominio della vittima**. Se il tuo dominio si chiama `example.com` e subisci un phishing che utilizza, per qualche motivo, un nome di dominio completamente diverso come `youwonthelottery.com`, queste tecniche non riusciranno a rilevarlo.

## Variazioni del nome di dominio

È abbastanza **facile** **rilevare** quei tentativi di **phishing** che utilizzano un nome di **dominio simile** all'interno dell'email.\
È sufficiente **generare un elenco dei nomi di phishing più probabili** che un attaccante potrebbe utilizzare e **controllare** se sono **registrati**, oppure verificare semplicemente se esiste un qualsiasi **IP** che li utilizza.

### Ricerca di domini sospetti

A questo scopo, puoi utilizzare uno dei seguenti strumenti. Entrambi risolvono i domini candidati per verificare se sono in uso.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Suggerimento: se generi un elenco di candidati, inseriscilo anche nei log del tuo resolver DNS per rilevare **query NXDOMAIN provenienti dall'interno della tua org** (utenti che cercano di raggiungere un typo prima che l'attaccante lo registri effettivamente). Usa un Sinkhole o blocca preventivamente questi domini se le policy lo consentono.

### Bitflipping

**Per una breve spiegazione, consulta la pagina principale; per la ricerca primaria sul bitsquatting di Windows.com, consulta l'analisi di [Remy Hax](https://remyhax.xyz/posts/bitsquatting-windows/) e il report di [BleepingComputer](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Ad esempio, una modifica di 1 bit nel dominio microsoft.com può trasformarlo in _windnws.com._\
**Gli attaccanti possono registrare il maggior numero possibile di domini bit-flipping correlati alla vittima per reindirizzare gli utenti legittimi verso la propria infrastruttura**.<sup>[[1]](#references)[[2]](#references)</sup>

**È necessario monitorare anche tutti i possibili nomi di dominio bit-flipping.**

Se devi considerare anche gli homoglyph/lookalike IDN (ad esempio, la combinazione di caratteri latini e cirillici), consulta:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Controlli di base

Dopo aver ottenuto un elenco di potenziali nomi di dominio sospetti, dovresti **controllarli** (principalmente le porte HTTP e HTTPS) per **verificare se utilizzano qualche form di login simile** a quelli del dominio della vittima.\
Potresti anche controllare la porta 3333 per verificare se è aperta e sta eseguendo un'istanza di `gophish`.\
È inoltre interessante sapere **quanto è vecchio ciascun dominio sospetto individuato**: più è recente, maggiore è il rischio.\
Puoi anche ottenere **screenshot** della pagina web sospetta HTTP e/o HTTPS per verificare se è sospetta e, in tal caso, **accedervi per esaminarla più a fondo**.

### Controlli avanzati

Se vuoi fare un passo ulteriore, ti consiglio di **monitorare questi domini sospetti e cercarne altri** periodicamente (ogni giorno? richiede solo pochi secondi/minuti). Dovresti anche **controllare** le **porte** aperte degli IP correlati e **cercare istanze di `gophish` o strumenti simili** (sì, anche gli attaccanti commettono errori), oltre a **monitorare le pagine web HTTP e HTTPS dei domini e sottodomini sospetti** per verificare se hanno copiato qualche form di login dalle pagine web della vittima.\
Per **automatizzare questa attività**, ti consiglio di avere un elenco dei form di login dei domini della vittima, eseguire lo spidering delle pagine web sospette e confrontare ogni form di login trovato nei domini sospetti con ogni form di login del dominio della vittima utilizzando strumenti come `ssdeep`.\
Se hai individuato i form di login dei domini sospetti, puoi provare a **inviare credenziali fittizie** e **verificare se ti reindirizzano al dominio della vittima**.

---

### Ricerca tramite favicon e web fingerprint (Shodan/Censys)

Molti phishing kit riutilizzano le favicon del brand che impersonano. Shodan calcola l'hash dei dati della favicon codificati in base64 con MurmurHash3, mentre Censys espone i propri campi hash delle favicon.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Puoi generare un hash compatibile con Shodan ed eseguire un pivot su di esso:

Esempio Python (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Query Shodan: `http.favicon.hash:309020573`
- With tooling: consulta strumenti community come favfreak per calcolare gli hash e generare Shodan dorks.<sup>[[16]](#references)</sup>

Note
- I favicon vengono riutilizzati; considera le corrispondenze come indizi e convalida contenuti e certificati prima di agire.
- Combina questi dati con l'età del dominio e le euristiche basate sulle parole chiave per una maggiore precisione.

### Ricerca di telemetry degli URL (urlscan.io)

`urlscan.io` memorizza screenshot storici, DOM, richieste e metadati TLS degli URL inviati. Puoi cercare abusi del brand e cloni:<sup>[[8]](#references)</sup>

Query di esempio (UI o API):
- Trova siti simili escludendo i tuoi domini legittimi: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Trova siti che effettuano hotlinking delle tue risorse: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Limita ai risultati recenti: aggiungi `AND date:>now-7d`

Esempio di API:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Dal JSON, usa come pivot:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` per individuare certificati molto nuovi per i lookalike
- valori di `task.source` come `certstream-suspicious` per collegare i risultati al monitoraggio CT

### Età del dominio tramite RDAP (scriptable)

RDAP restituisce eventi di registrazione leggibili dalle macchine. È utile per segnalare i **domini registrati di recente (NRD)**.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Arricchisci la tua pipeline aggiungendo ai domini tag relativi a fasce di anzianità della registrazione (ad es. <7 giorni, <30 giorni) e assegna loro la priorità di triage di conseguenza.

### Fingerprint TLS/JAx per individuare l'infrastruttura AiTM

Il credential-phishing può utilizzare reverse proxy **Adversary-in-the-Middle (AiTM)** (ad es. Evilginx) per rubare i token di sessione.<sup>[[11]](#references)</sup> Puoi aggiungere rilevamenti a livello di rete:

- Registra i fingerprint TLS/HTTP (JA3/JA4/JA4S/JA4H) in uscita. Alcune build di Evilginx sono state osservate con valori JA4 client/server stabili. Genera un alert sui fingerprint noti come dannosi solo come segnale debole e conferma sempre con il contenuto e le informazioni sul dominio.<sup>[[12]](#references)</sup>
- Registra proattivamente i metadati dei certificati TLS (issuer, numero di SAN, uso di wildcard, validità) per gli host simili individuati tramite CT o urlscan e correla questi dati con l'età del DNS e la geolocalizzazione.

> Nota: considera i fingerprint come arricchimento, non come unici blocchi; i framework evolvono e possono randomizzare o offuscare i fingerprint.

### Nomi di dominio che utilizzano keyword

La pagina principale menziona anche una tecnica di variazione del nome di dominio che consiste nell'inserire il **nome di dominio della vittima all'interno di un dominio più grande** (ad es. paypal-financial.com per paypal.com).

#### Certificate Transparency

I log di Certificate Transparency (CT) espongono le identità dei certificati; la ricerca di nomi Subject o SAN contenenti keyword di brand può rivelare domini simili (ad esempio, un certificato per `paypal-financial.com` espone la keyword `paypal`). Filtra i risultati per data di emissione e CA quando è utile e valida i candidati, perché le corrispondenze delle keyword possono produrre falsi positivi.<sup>[[13]](#references)</sup>

L'originale [phishing-domain hunting write-up](https://0xpatrik.com/phishing-domains/) di Patrik Hudak illustra questo workflow in Censys, inclusi i filtri per la data del certificato e l'issuer, come Let's Encrypt.<sup>[[13]](#references)</sup>

![Risultati della ricerca di certificati Censys utilizzati per identificare domini simili](<../../images/image (1115).png>)

Puoi anche utilizzare il servizio gratuito [**crt.sh**](https://crt.sh) per cercare una keyword e filtrare i risultati per data e CA.<sup>[[13]](#references)</sup>

![Ricerca di keyword in crt.sh per individuare identità di certificati sospette](<../../images/image (519).png>)

Il campo Matching Identities può aiutare a confrontare le identità del dominio reale con quelle dei domini sospetti, ma considera le corrispondenze come indizi e non come prove.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) trasmette gli aggiornamenti CT quasi in tempo reale, mentre [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) utilizza questo stream per assegnare un punteggio ai nomi di certificati sospetti.<sup>[[14]](#references)[[15]](#references)</sup>

Suggerimento pratico: durante il triage dei risultati CT, assegna la priorità agli NRD, ai registrar non affidabili o sconosciuti, al WHOIS con privacy proxy e ai certificati con valori `NotBefore` molto recenti. Mantieni una allowlist dei domini/brand di tua proprietà per ridurre il rumore.

#### **Nuovi domini**

Una seconda opzione consiste nel raccogliere i domini registrati di recente per TLD (ad esempio tramite [Whoxy](https://www.whoxy.com/newly-registered-domains/)) e filtrare in base alle keyword dei brand. Questo approccio non rileva il phishing ospitato su sottodomini quando la keyword è assente dal dominio registrato.<sup>[[13]](#references)</sup>

Euristica aggiuntiva: considera con maggiore sospetto alcuni **TLD con estensioni di file** (ad es. `.zip`, `.mov`) durante la generazione degli alert. Questi TLD vengono spesso confusi con nomi di file nei lure; combina il segnale del TLD con le keyword dei brand e l'età dell'NRD per ottenere una maggiore precisione.

## References

- [1] [Remy Hax – Bitsquatting di Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Hijacking del traffico verso windows.com di Microsoft tramite bit flipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Approfondimento: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [Documentazione di mmh3](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Dataset delle proprietà web delle piattaforme](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Riferimento della Search API](https://urlscan.io/docs/search/)
- [9] [Guida al Registration Data Access Protocol](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: risposte JSON per il Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Strategie per i token: come prevenire, rilevare e rispondere al furto di token cloud](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – Fingerprinting di rete JA4+](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Individuare il phishing: strumenti e tecniche](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Presentazione di CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
