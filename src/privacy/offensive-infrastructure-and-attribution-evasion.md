# Infrastruttura offensiva ed evasione dell’attribuzione

{{#include ../banners/hacktricks-training.md}}

Un operatore raramente ottiene un anonimato significativo usando un solo proxy. Le campagne reali costruiscono un **grafo di separazione**: l’operatore raggiunge un nodo di accesso, i nodi di transito nascondono quel nodo all’uscita, i redirector proteggono il vero C2 e i nomi usa e getta puntano al punto di accesso pubblico.

Consulta il [Catalogo delle tecniche di accesso anonimo a Internet](anonymous-internet-access-techniques.md) per una panoramica standardizzata di vantaggi e svantaggi, distribuzione e rilevamento di ogni percorso. Questa pagina approfondisce la composizione di infrastrutture avversarie.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

L'ultimo indirizzo visto da un target è quindi una prova del percorso, non la prova di chi controllava la tastiera. MITRE associa i componenti principali a Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) e Web Service (T1102).<sup>[[1]](#references)</sup>

## Classi di infrastruttura

| Classe | Perché un attore la usa | Esposizione persistente | Miglior punto di correlazione per i defender |
|---|---|---|---|
| VPS/cloud a noleggio | Rapido, prevedibile, instradabile, facile da ricostruire | tenant, fatturazione, console, cronologia degli accessi sorgente e delle immagini | eventi dell'account/control plane e fingerprint del server ricorrente |
| VPN commerciale/Tor | Ampio insieme di egress condivisi; nessuna amministrazione dei server | visibilità del provider/guard e timing end-to-end | comportamento verso la destinazione, evidenze sugli endpoint e correlazione dei flussi |
| Proxy residenziale/mobile | ASN consumer e plausibilità geografica | registri di broker/clienti; comportamento di proxyware o host infetti | spostamenti impossibili, protocolli proxy e variazione degli indirizzi per sessione |
| Server/router/IoT compromesso | Sfrutta la reputazione e la giurisdizione della vittima | implant, flusso di gestione e controller upstream ricorrente | telemetria del dispositivo e topologia ORB, non un singolo IP di uscita |
| CDN/redirector | Separa l'edge pubblico dal C2 back-end | grammatica TLS/HTTP, certificato, routing e artefatti dell'account cloud | correlazione edge-origin e clustering della forma delle richieste |
| Servizio web legittimo | Si confonde con il traffico consentito verso GitHub/cloud/social | token API, identificatori di tenant/oggetti e lineage insolito dei processi | processo sull'endpoint e semantica del servizio/API |
| Percorso fisico/cellulare/satellitare | Modifica l'origine fisica apparente | dati RF, dell'operatore, dell'abbonato, del dispositivo e della posizione | combinazione di evidenze radio/fisiche e di rete |

## Reti di relay box operative

Una **rete ORB** è una flotta di proxy gestita e usata come servizio intermedio. Mandiant le suddivide in reti provisioned di server presi in leasing, reti non-provisioned di router/IoT compromessi e reti ibride. Una topologia matura ha quattro ruoli logici:<sup>[[2]](#references)</sup>

1. **Server di amministrazione (ACOS):** mantiene inventario, credenziali, stato e policy di routing.
2. **Nodo di accesso/relay:** autentica clienti o operatori; è il punto d'ingresso stabile verso una mesh in evoluzione.
3. **Nodi di transito:** uno o più sistemi presi in leasing o compromessi inoltrano connessioni opache.
4. **Nodo di uscita/staging:** presenta l'indirizzo sorgente finale ai target di ricognizione, sfruttamento o C2.

La mesh può selezionare le uscite in base a paese, ASN, latenza o disponibilità e sostituire i nodi non funzionanti. Più gruppi di minaccia possono noleggiare la stessa rete. Mandiant ha osservato che un indirizzo IPv4 è rimasto associato ad alcune ORB per appena 31 giorni; raccomanda quindi di considerare la **rete come un'entità in evoluzione simile a un attore**, invece di bloccare elenchi obsoleti di IP.<sup>[[2]](#references)</sup>

### Cosa offre e cosa lascia trapelare

- Il target vede un'uscita che può essere geograficamente vicina e sembrare residenziale.
- L'uscita vede il target e l'hop precedente, ma non necessariamente l'operatore.
- Il servizio di accesso vede il cliente e la richiesta di routing. Una mesh gestita in modo indipendente può tenere il cliente separato dalle uscite, ma crea un registro potente nelle mani di una controparte.
- Porte ricorrenti, ordine degli handshake, banner del server, certificati, finestre di uptime e relazioni con i controller possono esporre la flotta anche mentre gli IP ruotano.
- Un router compromesso spesso non dispone di telemetria degli endpoint, ma il suo ISP conserva comunque dati dell'abbonato e dei flussi; un sequestro espone artefatti dell'implant/configurazione.

{% hint style="info" %}
Per un'esercitazione autorizzata, riproduci la topologia con VM o router di proprietà dell'organizzazione e conserva la mappa di attribuzione del controller. Non reclutare proxy aperti o dispositivi di terzi. La [guida al lab](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) crea la stessa struttura di hop visibile ai defender senza danneggiare un intermediario.
{% endhint %}

## Reti di proxy residenziali e mobili

I servizi di proxy residenziali assegnano le sessioni a indirizzi di connessioni broadband consumer; i proxy mobili effettuano l'egress tramite pool NAT degli operatori. Le risorse possono provenire da dispositivi registrati esplicitamente, SDK/proxyware inclusi in applicazioni consumer, rivenditori o malware. Queste origini non sono equivalenti: senza consenso informato, un servizio per la privacy diventa infrastruttura compromessa.

Le modalità di rotazione influiscono sul rilevamento:

- la **rotazione per richiesta** produce rapide discontinuità di IP e ASN/geografia, mentre l'identità ai livelli superiori resta stabile;
- le **sticky session** mantengono un'uscita per minuti o ore, somigliando a un normale abbonato;
- i **gateway backconnect** espongono al cliente un endpoint del broker e scelgono internamente le uscite;
- i **pool mobili** collocano molti abbonati reali dietro un numero ridotto di indirizzi NAT degli operatori, rendendo costoso bloccare un IP.

I defender dovrebbero correlare l'IP con la sessione autenticata, il fingerprint TLS/client, l'ordine HTTP, il cookie del dispositivo e il comportamento. Un accesso residenziale apparentemente locale seguito da un accesso da un altro paese, mentre tutte le caratteristiche ai livelli superiori restano identiche, è un segnale più forte della sola reputazione. Al contrario, la condivisione degli indirizzi e il passaggio tra celle mobili causano variazioni legittime; quindi non considerare mai la classificazione residenziale/proxy come una conclusione definitiva.

### Piani di controllo del proxyware e sovrapposizione tra rivenditori

Non modellare un pool residenziale come un elenco piatto di uscite. L'analisi dell'ecosistema IPIDEA ha rivelato un **piano di controllo a due livelli** riutilizzabile: un SDK incorporato invia prima i metadati del dispositivo/registrazione a un dominio Tier One e riceve le coppie IP:porta `connect`/`proxy` del Tier Two, insieme alle informazioni di pianificazione. Il nodo interroga periodicamente la porta connect del Tier Two per un task codificato, apre una seconda connessione alla porta proxy abbinata e inoltra i byte forniti alla destinazione richiesta. SDK e marchi di proxy apparentemente diversi avevano domini di discovery separati, ma convergevano su un'infrastruttura Tier Two condivisa e su pool di uscite sovrapposti tramite proprietà comune e relazioni con i rivenditori.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Questo produce pivot di hunting più durevoli rispetto a un blocco di IP residenziali:<sup>[[13]](#references)</sup>

- un processo imprevisto di utility, VPN, gioco o dispositivo embedded invia un ID dispositivo/chiave cliente stabile e riceve un elenco di server variabile;
- l'endpoint interroga un IP diretto su una porta insolita, poi si connette a un'altra porta sullo stesso indirizzo subito prima di aprire un socket verso una nuova destinazione;
- diversi brand apparenti condividono indirizzi Tier Two, grammatica del protocollo, codice SDK o sovrapposizioni di exit node;
- applicazioni distinte che contattano domini Tier One diversi ricevono indirizzi dallo stesso pool Tier Two.

La sovrapposizione limita anche l'attribuzione: vedere un IP nel pool pubblicizzato di un vendor non dimostra quale reseller, cliente o threat actor lo abbia usato in quel momento. Conserva i timestamp dei flussi, la lineage dei processi, i corpi delle risposte Tier One e gli identificatori delle task Tier Two.<sup>[[13]](#references)</sup> In un'esercitazione autorizzata, emula questa gerarchia solo con endpoint di proprietà dell'organizzazione; non registrare mai dispositivi consumer o proxyware di terze parti.

## Catene di proxy multi-hop

MITRE distingue i proxy esterni dai **proxy multi-hop (T1090.003)**. La proprietà importante non è il numero di hop, ma la separazione delle conoscenze e dell'amministrazione.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Se una stessa parte gestisce A e B, i log condivisi o la tempistica dei flussi possono consentire di ricostruire il circuito. Aggiungere VPN commerciali in sequenza dallo stesso endpoint/account può aumentare la latenza, lasciando però invariati gli elementi comuni relativi a identità, pagamenti e tempistiche. Tor riduce questo problema usando relay selezionati in modo indipendente e un design client condiviso, ma una rete interattiva a bassa latenza non può garantire protezione da un osservatore che misura entrambe le estremità.

Tra i problemi più comuni ci sono il bypass di DNS o IPv6, le applicazioni che aprono socket autonomamente, il traffico di gestione che raggiunge direttamente i relay, le attività sincronizzate, il riutilizzo delle chiavi SSH e l'accesso ad account che consentono di identificare l'utente. La verifica corretta consiste in un test di failover: arrestare ogni relay a turno e dimostrare che il workload non può ripiegare su un percorso in chiaro.

### Collasso dei tunnel e leak a monte

Un'architettura a relay è spesso più facile da attribuire quando si guasta. Unit 42 ha documentato un percorso di spionaggio a più livelli che usava VPS esposti alle vittime, VPS relay, proxy residenziali, Tor e altri servizi proxy; quando un tunnel veniva omesso o collassava, l'infrastruttura nascosta a monte si connetteva direttamente ai sistemi relay e a quelli esposti alle vittime. La stessa indagine ha usato anche un certificato X.509 esposto brevemente sull'infrastruttura a monte come pivot tra livelli.<sup>[[14]](#references)</sup>

Mantieni separati il **piano dati** (`victim <-> exit`) e il **piano di controllo** (`operator/upstream -> relay administration`). Conserva i log di ingresso e autenticazione a ogni livello sotto il tuo controllo, le cronologie dei certificati e le connessioni brevi non riuscite, non solo le sessioni C2 riuscite. Una sorgente che compare solo durante le interruzioni dei relay o amministra direttamente più nodi esposti alle vittime è un candidato a essere un upstream più plausibile di un normale exit, ma il suo ASN/geolocation resta un'ipotesi, non una prova dell'identità dell'operatore.

Un lab autorizzato dovrebbe far sì che il workload fallisca in modo sicuro. Per un workload isolato in un network namespace Linux, la prima route deve usare il tunnel; dopo averlo rimosso, sia la richiesta sia la ricerca della route devono fallire invece di selezionare l'uplink fisico:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Ripeti il test per DNS e IPv6 e a ogni confine del relay. Se una qualsiasi sonda ha esito positivo, registra l’interfaccia/l’indirizzo sorgente effettivo prima di correggere il policy routing o il firewall; quell’osservazione è l’attribution leak che un investigatore potrebbe rilevare.

## Livelli di redirector e modellazione del traffico

Un **redirector** pubblico accetta il traffico che corrisponde a una grammatica specifica dell’operazione e lo inoltra a un team server protetto. Tutto il resto può essere rifiutato o ricevere contenuti innocui.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Più livelli limitano l'esposizione: bruciare un dominio pubblico non deve necessariamente esporre il team server. Le CDN aggiungono capacità anycast e un dominio esterno affidabile, ma l'account CDN e i log edge diventano punti di attribuzione. Fingerprint TLS, cronologia dei certificati, percorsi distintivi/ordine degli header, dimensioni delle risposte, comportamento dei redirect e allowlist dell'origine possono raggruppare front apparentemente non correlati.

Per il rilevamento, registra i campi del reverse proxy prima della normalizzazione, confronta SNI/Host/authority, esamina combinazioni rare di header, raggruppa i corpi delle risposte e i fingerprint TLS e cerca sovrapposizioni di configurazione nei log di audit di cloud/CDN. Nei red team autorizzati, evita di copiare un marchio reale o di raccogliere credenziali tramite terze parti non correlate.

## Domain fronting e domainless fronting

Con il classico **domain fronting (T1090.004)**, la connessione TLS annuncia in SNI un dominio front consentito, mentre l'HTTP `Host` o l'HTTP/2 `:authority` crittografati richiedono un diverso dominio back-end. Una CDN collaborativa instrada in base al valore interno. Un osservatore di rete senza decrittazione TLS vede il front; la CDN vede entrambi i valori e l'origine. Nelle varianti domainless, SNI può essere vuoto mentre un altro campo di instradamento seleziona la destinazione.<sup>[[4]](#references)</sup>

Non è un'impersonificazione magica: funziona solo se l'intermediario consente intenzionalmente o accidentalmente la discordanza e sa instradare il nome interno. I principali provider hanno limitato il fronting tra account diversi. Encrypted ClientHello (ECH) modifica ciò che un osservatore sul percorso può vedere, ma non cancella i record della CDN, dell'endpoint o dell'applicazione.

I punti di rilevamento includono:

- la genealogia dei processi dell'endpoint e una destinazione non prevista per quell'applicazione;
- la discordanza tra SNI e authority HTTP, dove l'ispezione TLS è legale e disponibile;
- log CDN che mostrano un tenant/front instradato verso un'altra authority/origine;
- sessioni insolitamente lunghe o periodiche verso un servizio normalmente interattivo;
- dimensioni e cadenza stabili dei flussi crittografati nonostante il cambio dei domini front.

Il laboratorio sicuro simula la discordanza di instradamento su un reverse proxy di proprietà; non abusa di una CDN pubblica.

## Risoluzione dinamica: DDNS, DGA e fast flux

La risoluzione dinamica separa un servizio logico dall'infrastruttura fissa:

- **DDNS:** un client autenticato aggiorna un nome stabile quando il suo indirizzo cambia.
- **DGA:** endpoint e controller ricavano entrambi possibili nomi di dominio da un seed basato su tempo/chiave; l'operatore ne registra un piccolo sottoinsieme.
- **Fast flux:** un nome restituisce un insieme in rapido cambiamento di indirizzi compromessi/proxy, spesso con TTL bassi.
- **Double flux:** ruotano sia gli indirizzi del servizio sia quelli dei name server autorevoli, nascondendo anche il livello di controllo.

Il fast flux è un modello di distribuzione del carico usato a fini avversari, non semplicemente «molte risposte DNS». Gli indizi più solidi combinano TTL basso, elevato numero di indirizzi unici, ampia dispersione per ASN/geografia, breve durata dei nodi, comportamento applicativo ripetuto e cronologia di registrazione sospetta. Le CDN presentano legittimamente diverse di queste caratteristiche. MITRE raccomanda di correlare il comportamento DNS con il processo e le connessioni successive.<sup>[[5]](#references)</sup>

Una DGA può essere rilevata tramite entropia lessicale, schemi di consonanti/cifre, raffiche di NXDOMAIN, domini comparsi per la prima volta in modo sincronizzato e contesto del processo. Le DGA basate su wordlist e i modelli generativi aggirano semplici regole basate sull'entropia, rendendo più importanti il raggruppamento temporale a livello di flotta e la genealogia degli endpoint.

## Domini compromessi e domain shadowing

Un attore può dirottare un account di registrar/DNS, assumere il controllo di un sottodominio abbandonato o aggiungere record sotto un dominio altrimenti affidabile. Il **domain shadowing** mantiene intatto il dominio apex legittimo, mentre numerosi sottodomini controllati dall'attaccante puntano a host di delivery o C2 variabili. Sfrutta l'età e la reputazione del dominio e può eludere il blocco dell'intero dominio.<sup>[[6]](#references)</sup>

I difensori necessitano di log di audit del registrar e del DNS autorevole, MFA, lock di registry/registrar, avvisi per nuove deleghe/token API/name server, monitoraggio della certificate transparency e un inventario delle risorse cloud referenziate dal DNS. Esamina la risoluzione e la cronologia dei certificati di un sottodominio indipendentemente dalla reputazione del dominio apex.

## Web service e dead-drop resolver

Un **dead-drop resolver (T1102.001)** conserva un puntatore codificato al C2 corrente in un post, profilo, documento, repository, oggetto cloud o campo blockchain legittimo. Il malware recupera l'oggetto pubblico, decodifica un dominio/IP e contatta la fase successiva. Le varianti bidirezionali scambiano comandi o file tramite API di servizi.<sup>[[7]](#references)</sup>

Una variante di resolver specifica per GitHub usa l'API Issues Search solo quando un canale repository autenticato non funziona. Il client cerca issue corrispondenti alla data corrente, al repository e al tipo di issue, segue l'URL dei commenti di ciascuna issue ed estrae il testo cifrato tra i marcatori `<!--` e `-->`. Dopo la decrittazione specifica per host e basata sulla data, campi come `Owner`, `LicRepo` e `LicToken` sostituiscono il proprietario, il percorso e il token del repository primario. Questo consente all'operatore di ruotare credenziali ed endpoint senza sostituire il client; il commento dell'issue funge da resolver, mentre i file del repository restano il canale di tasking.<sup>[[15]](#references)</sup>

Questo offre resilienza e nasconde il C2 back-end dall'analisi statica dei binari. Crea anche identificatori stabili di oggetti, tenant, repository, API e schemi di accesso. I difensori dovrebbero correlare:

1. il processo che ha contattato il servizio;
2. il percorso API/oggetto esatto e l'hash della risposta;
3. l'attività di decodifica o elaborazione delle stringhe;
4. la nuova connessione in uscita poco dopo; e
5. lo stesso comportamento altrove nella flotta.

Bloccare GitHub, l'archiviazione cloud o i social media è raramente praticabile. Le policy di egress consapevoli del servizio e la correlazione a livello di processo sono più efficaci del solo blocco dei domini.

## Persona, account e compartimenti di approvvigionamento

L'anonimato dell'infrastruttura viene meno quando una persona, un'email di recupero, un telefono, un pagamento, un browser o un IP amministrativo collega diversi compartimenti. Operazioni legate a stati hanno creato profili social, identità email e account cloud molto prima di utilizzarli; ATT&CK registra questa tattica come Establish Accounts (T1585), con sottotecniche social, email e cloud.<sup>[[8]](#references)</sup>

Un difensore o investigatore costruisce un grafo basato su:

- orario di creazione e primo accesso, impostazioni locali, fuso orario e orari di attività;
- dati di recupero, dispositivi MFA, documenti d'identità e strumenti di pagamento;
- fingerprint del browser/TLS e cronologia delle reti di origine;
- riutilizzo degli avatar, provenienza delle immagini, stile di scrittura e crescita del grafo sociale;
- registrante del dominio, name server, certificato, ID analytics o commit del repository condivisi;
- azioni sul piano di gestione che aggirano l'architettura dei relay pubblici.

Per un red team autorizzato, le persone sintetiche devono essere documentate al responsabile dell'esercitazione, usare canali di recupero/pagamento di proprietà dell'organizzazione, evitare di impersonare persone reali non coinvolte e avere una procedura di dismissione pianificata. Il SOC può restare all'oscuro; l'operazione non deve diventare priva di responsabilità.

## Schemi compositi emergenti da considerare nel threat modeling

Queste sono **composizioni guidate dai difensori**, non affermazioni che un attore nominato abbia implementato ciascun progetto specifico. Combinano primitive già osservate e sono utili come ipotesi per i purple team.

### Tasking asimmetrico a senso unico

I comandi arrivano tramite una fonte pubblica, broadcast o append-only, mentre i risultati escono attraverso un canale non correlato dopo un ritardo. Tra gli esempi delle primitive figurano la comunicazione unidirezionale tramite web service e i dead drop. La separazione impedisce a un singolo flusso di apparire bidirezionale e ostacola la semplice correlazione richiesta/risposta.<sup>[[9]](#references)</sup>

**Rilevamento:** conserva i dati di lettura a livello di oggetto, poi correla le modifiche di stato del processo e i trasferimenti in uscita successivi su una finestra temporale più ampia. Cerca un processo raro che legga lo stesso oggetto pubblico anche quando non segue una risposta immediata.

### Promozione dei canali a più fasi

Una prima fase poco appariscente effettua l'inventario e promuove solo i sistemi selezionati a un secondo canale non correlato. Il secondo endpoint, protocollo e processo potrebbero non condividere alcuna infrastruttura con il primo. Questo limita l'esposizione dell'infrastruttura più sofisticata ed è modellato esplicitamente da ATT&CK T1104.<sup>[[10]](#references)</sup>

**Rilevamento:** correla `processo di rete iniziale -> stato scaricato/configurato -> nuovo processo o injection -> destinazione non correlata`; non chiudere l'incidente dopo aver bloccato il primo dominio.

### Traduzione dei relay tra protocolli

Hop diversi traducono HTTPS, QUIC, WebSocket, DNS, SSH o un'API di message queue, invece di inoltrare i pacchetti in modo trasparente. La traduzione elimina un singolo fingerprint di protocollo end-to-end, ma crea gateway con tempi, buffering e conversione semantica distintivi. Il protocol tunneling (T1572) può essere combinato con proxy e impersonificazione di servizi.<sup>[[11]](#references)</sup>

**Rilevamento:** cerca host gateway che ricevono un protocollo e ne avviano un altro con una stretta corrispondenza tra byte e tempi; confronta l'intento dell'endpoint con il protocollo effettivamente trasportato.

### Attivazione passiva sui dispositivi edge

Invece di inviare beacon, un impianto monitora il traffico che raggiunge già un router/VPN e si attiva solo in presenza di un valore magico, uno schema di porte sorgente o un token autenticato. Il traffico normale continua verso il servizio reale. ATT&CK definisce questa tecnica Traffic Signaling (T1205) e riporta esempi documentati relativi a dispositivi di rete e APT.<sup>[[12]](#references)</sup>

**Rilevamento:** integrità di firmware/file, acquisizione di pacchetti grezzi durante un'indagine autorizzata, filtri socket inattesi e comportamento differenziale del servizio. L'assenza di un beacon periodico non dimostra che un dispositivo edge sia pulito.

### Rotazione di origini serverless ed effimere

Un front mantiene un'identità logica stabile, mentre funzioni/container di breve durata gestiscono singole fasi in diverse regioni/account. Questo riduce la permanenza su disco e gli IP di origine fissi, ma i dati di telemetria relativi a creazione sul piano di controllo, image/layer, ruolo, secret, ID richiesta e fatturazione diventano il grafo persistente.

**Rilevamento:** conserva i log di audit e di invocazione cloud al di fuori del workload; raggruppa template di deployment, ruoli, chiavi d'ambiente e relazioni front-origine.

### Diversità dei livelli di privacy

Un'operazione può evitare intenzionalmente un'unica catena omogenea: per esempio, un canale usa un relay a noleggio, il tasking usa un oggetto pubblico, un'uscita passa da un link cellulare di laboratorio di proprietà e l'amministrazione usa una rete separata dell'organizzazione. Questo riduce il valore della compromissione di un singolo provider, ma aumenta il rischio di correlazione temporale tra livelli e di errori operativi.

**Rilevamento:** crea timeline della campagna attraverso sensori di identità, DNS, SaaS, rete e cloud. Cerca transizioni di stato sincronizzate invece di indicatori identici.

### Dead drop decentralizzati o basati su transparency log

Un attore può inserire un piccolo puntatore cifrato in qualsiasi sistema pubblico durevole append-only, archivio content-addressed o feed simile a un transparency log. L'oggetto pubblico è resiliente, ma l'indice/hash del contenuto esatto e il comportamento di polling del client diventano identificatori stabili.

**Rilevamento:** registra gli identificatori completi di API/oggetto e gli hash delle risposte; genera avvisi quando processi non standard interrogano oggetti immutabili e poi decodificano dati o avviano nuove connessioni.

### Operazioni store-and-forward ritardate

Il C2 interattivo crea forti correlazioni temporali. Un progetto store-and-forward raggruppa job cifrati e restituisce i risultati minuti o ore dopo tramite una coda diversa o un trasferimento fisico. Sacrifica la reattività per ridurre la correlazione temporale end-to-end.

**Rilevamento:** amplia le finestre di correlazione, modella gli accessi periodici alle code ed esamina lo staging sugli endpoint. Il batching sposta il segnale dai tempi dei pacchetti al comportamento pianificato di processi/file; non lo cancella.

## Revisione del progetto: ragiona in termini di osservatori

Per ogni percorso, compila questa tabella prima del deployment e dopo la raccolta:

| Livello | Vede la sorgente? | Vede la destinazione? | Vede il contenuto? | Identificatori stabili | Conservazione/responsabile legale |
|---|---:|---:|---:|---|---|
| rete locale/operatore | | | | | |
| servizio di ingresso/accesso | | | | | |
| operatore/i di transito | | | | | |
| uscita/redirector/CDN | | | | | |
| DNS autorevole/registrar | | | | | |
| obiettivo | | | | | |
| provider di account/pagamento | | | | | |

Se un singolo provider ordinario può compilare ogni colonna, l'architettura nasconde le attività al target, ma non garantisce una separazione solida. Se nessun responsabile interno può ricondurre le attività a un incarico, l'architettura non è adatta a un red team professionale.

## References

- [1] [MITRE ATT&CK — Acquisire infrastruttura (T1583), Compromettere infrastruttura (T1584) e Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Attori di spionaggio legati alla Cina usano reti ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Proxy multi-hop (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromettere infrastruttura: domini (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web service: dead-drop resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Creare account (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web service: comunicazione unidirezionale (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Canali multi-fase (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Tunneling di protocollo (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Interruzione della più grande rete proxy residenziale al mondo](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Le campagne Shadow: indagine sullo spionaggio globale](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - La campagna Blinder Tunnel prende di mira le infrastrutture irachene](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
