# Rilevare il phishing

{{#include ../../banners/hacktricks-training.md}}

## Introduzione

Per rilevare un tentativo di phishing è importante **capire le tecniche di phishing utilizzate oggi**. Nella pagina principale di questo post trovi queste informazioni; se non conosci le tecniche usate al giorno d’oggi, ti consiglio di visitare la pagina principale e leggere almeno quella sezione.

Questo post si basa sull’idea che **gli aggressori cercheranno in qualche modo di imitare o usare il nome di dominio della vittima**. Se il tuo dominio è `example.com` e subisci un tentativo di phishing tramite un nome di dominio completamente diverso, per esempio `youwonthelottery.com`, queste tecniche non riusciranno a individuarlo.

## Variazioni dei nomi di dominio

È piuttosto **facile** **individuare** i tentativi di **phishing** che usano un nome di **dominio simile** all’interno dell’email.\
È sufficiente **generare un elenco dei nomi di phishing più probabili** che un aggressore potrebbe usare e **controllare** se sono **registrati** oppure semplicemente verificare se c’è un **IP** che li utilizza.

### Individuare domini sospetti

A questo scopo puoi usare uno dei seguenti strumenti. Entrambi risolvono i domini candidati per verificare se sono in uso.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Suggerimento: se generi un elenco di candidati, inseriscilo anche nei log del tuo resolver DNS per rilevare **query NXDOMAIN provenienti dall’interno della tua organizzazione** (utenti che cercano di raggiungere un dominio scritto in modo errato prima che l’aggressore lo registri). Se le policy lo consentono, metti questi domini in sinkhole o blocchiali in anticipo.

### Bitflipping

**Per una breve spiegazione, consulta la pagina principale; per la ricerca originale sul bitsquatting di Windows.com, consulta [l’analisi di Remy Hax](https://remyhax.xyz/posts/bitsquatting-windows/) e [il report di BleepingComputer](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Per esempio, una modifica di 1 bit nel dominio microsoft.com può trasformarlo in _windnws.com._\
**Gli aggressori potrebbero registrare quanti più domini ottenuti tramite bit-flipping possibile, correlati alla vittima, per reindirizzare gli utenti legittimi alla propria infrastruttura**.<sup>[[1]](#references)[[2]](#references)</sup>

**È opportuno monitorare anche tutti i possibili nomi di dominio ottenuti tramite bit-flipping.**

Se devi considerare anche i lookalike basati su omoglifi/IDN (per esempio, la combinazione di caratteri latini e cirillici), consulta:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Controlli di base

Dopo aver ottenuto un elenco di potenziali domini sospetti, dovresti **controllarli** (principalmente sulle porte HTTP e HTTPS) per **verificare se usano un modulo di login simile a quello di uno dei domini della vittima**.\
Puoi anche controllare la porta 3333 per verificare se è aperta e se esegue un’istanza di `gophish`.\
È inoltre utile sapere **quanto è vecchio ciascun dominio sospetto individuato**: più è recente, maggiore è il rischio.\
Puoi anche acquisire **screenshot** delle pagine web sospette HTTP e/o HTTPS per verificarne la sospettosità e, in tal caso, **visitarle per approfondire l’analisi**.

### Controlli avanzati

Se vuoi fare un passo in più, ti consiglio di **monitorare questi domini sospetti e cercarne altri** periodicamente (ogni giorno? bastano pochi secondi/minuti). Dovresti anche **controllare** le **porte** aperte degli IP correlati e **cercare istanze di `gophish` o strumenti simili** (sì, anche gli aggressori commettono errori), oltre a **monitorare le pagine web HTTP e HTTPS dei domini e sottodomini sospetti** per verificare se hanno copiato un modulo di login dalle pagine web della vittima.\
Per **automatizzare questa attività**, ti consiglio di creare un elenco dei moduli di login dei domini della vittima, eseguire crawling delle pagine web sospette e confrontare ogni modulo di login trovato nei domini sospetti con ciascun modulo di login del dominio della vittima usando strumenti come `ssdeep`.\
Se hai individuato i moduli di login dei domini sospetti, puoi provare a **inviare credenziali fittizie** e **verificare se vieni reindirizzato al dominio della vittima**.

---

### Ricerca tramite favicon e impronte web (Shodan/Censys)

Molti kit di phishing riutilizzano le favicon del brand che imitano. Shodan calcola l’hash dei dati della favicon codificati in base64 usando MurmurHash3, mentre Censys espone i propri campi per gli hash delle favicon.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Puoi generare un hash compatibile con Shodan e usarlo per effettuare ricerche pivot:

Esempio Python (mmh3):

```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```

- Query Shodan: `http.favicon.hash:309020573`
- Con gli strumenti: consulta tool della community come favfreak per calcolare gli hash e generare dork Shodan.<sup>[[16]](#references)</sup>

Note
- Le favicon vengono riutilizzate; considera i match come indizi e verifica contenuti e certificati prima di agire.
- Combina euristiche basate sull'età del dominio e sulle parole chiave per ottenere una maggiore precisione.

### Ricerca di telemetria URL (urlscan.io)

`urlscan.io` archivia screenshot storici, DOM, richieste e metadati TLS degli URL inviati. Puoi cercare casi di abuso del brand e cloni:<sup>[[8]](#references)</sup>

Query di esempio (UI o API):
- Trova domini simili escludendo quelli legittimi: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Trova siti che incorporano direttamente le tue risorse: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Limita i risultati più recenti: aggiungi `AND date:>now-7d`

Esempio API:

```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
  -H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```

Dal JSON, usa questi campi per approfondire:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` per individuare certificati molto recenti usati per domini simili
- valori di `task.source` come `certstream-suspicious` per collegare i risultati al monitoraggio CT

### Età del dominio tramite RDAP (automatizzabile con script)

RDAP restituisce eventi di registrazione leggibili dalle macchine. È utile per segnalare i **domini registrati di recente (NRD)**.<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
  jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```

Arricchisci la tua pipeline assegnando ai domini categorie in base all'età della registrazione (ad esempio, <7 giorni, <30 giorni) e stabilendo le priorità del triage di conseguenza.

### Fingerprint TLS/JAx per individuare infrastrutture AiTM

Il phishing delle credenziali può usare reverse proxy **Adversary-in-the-Middle (AiTM)** (ad esempio, Evilginx) per rubare token di sessione.<sup>[[11]](#references)</sup> Puoi aggiungere rilevamenti lato rete:

- Registra i fingerprint TLS/HTTP (JA3/JA4/JA4S/JA4H) in uscita. Alcune build di Evilginx sono state osservate con valori JA4 client/server stabili. Genera avvisi solo per fingerprint noti come dannosi, considerandoli un segnale debole, e verifica sempre con informazioni sui contenuti e sui domini.<sup>[[12]](#references)</sup>
- Registra proattivamente i metadati dei certificati TLS (emittente, numero di SAN, uso di wildcard, validità) per gli host simili individuati tramite CT o urlscan e correla i dati con l'età DNS e la geolocalizzazione.

> Nota: considera i fingerprint come arricchimento, non come unici criteri di blocco; i framework evolvono e possono randomizzare o offuscare i fingerprint.

### Nomi di dominio che usano parole chiave

La pagina principale menziona anche una tecnica di variazione dei nomi di dominio che consiste nell'inserire il **nome di dominio della vittima all'interno di un dominio più grande** (ad esempio, paypal-financial.com per paypal.com).

#### Certificate Transparency

I log di Certificate Transparency (CT) espongono le identità dei certificati: cercare parole chiave relative ai brand nei nomi Subject o SAN può rivelare domini simili (ad esempio, un certificato per `paypal-financial.com` espone la parola chiave `paypal`). Se utile, filtra i risultati per data di emissione e CA e convalida i candidati, perché le corrispondenze per parola chiave possono essere falsi positivi.<sup>[[13]](#references)</sup>

L'articolo originale di Patrik Hudak sulla [ricerca di domini di phishing](https://0xpatrik.com/phishing-domains/) illustra questo flusso di lavoro in Censys, compresi i filtri per la data e l'emittente del certificato, come Let's Encrypt.<sup>[[13]](#references)</sup>

![Risultati della ricerca di certificati in Censys usati per identificare domini simili](<../../images/image (1115).png>)

Puoi anche usare il servizio gratuito [**crt.sh**](https://crt.sh) per cercare una parola chiave e filtrare i risultati per data e CA.<sup>[[13]](#references)</sup>

![Ricerca di parole chiave in crt.sh per individuare identità di certificati sospette](<../../images/image (519).png>)

Il campo Matching Identities può aiutare a confrontare le identità del dominio reale con quelle dei domini sospetti, ma considera le corrispondenze come piste da approfondire, non come prove.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) trasmette gli aggiornamenti CT quasi in tempo reale, mentre [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) elabora il flusso per assegnare un punteggio ai nomi di certificati sospetti.<sup>[[14]](#references)[[15]](#references)</sup>

Consiglio pratico: durante il triage dei risultati CT, assegna priorità a NRD, registrar non attendibili o sconosciuti, WHOIS con privacy proxy e certificati con valori `NotBefore` molto recenti. Mantieni una allowlist dei domini e dei brand di tua proprietà per ridurre il rumore.

#### **Nuovi domini**

Un'altra opzione consiste nel raccogliere i domini registrati di recente per TLD (ad esempio, tramite [Whoxy](https://www.whoxy.com/newly-registered-domains/)) e filtrare i risultati in base alle parole chiave dei brand. Questo metodo non rileva il phishing ospitato su sottodomini quando la parola chiave non è presente nel dominio registrato.<sup>[[13]](#references)</sup>

Un'euristica aggiuntiva: considera alcuni **TLD con estensione di file** (ad esempio, `.zip`, `.mov`) particolarmente sospetti negli avvisi. Spesso vengono confusi con nomi di file nei messaggi-esca; combina il segnale del TLD con le parole chiave dei brand e l'età NRD per ottenere una maggiore precisione.

## References

- [1] [Remy Hax – Bitsquatting Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Dirottamento del traffico verso windows.com di Microsoft tramite bit flipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Approfondimento: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [Documentazione mmh3](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Dataset delle proprietà web della piattaforma](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Riferimento API di ricerca](https://urlscan.io/docs/search/)
- [9] [Guida al Registration Data Access Protocol](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: risposte JSON per il Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Tattiche per i token: come prevenire, rilevare e rispondere al furto di token cloud](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [Blog APNIC – Fingerprinting di rete JA4+](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Trovare il phishing: strumenti e tecniche](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Presentazione di CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
