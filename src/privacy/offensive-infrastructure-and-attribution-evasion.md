# Infrastruttura offensiva ed elusione dell'attribuzione

{{#include ../banners/hacktricks-training.md}}

Un operatore raramente ottiene un anonimato significativo tramite un singolo proxy. Le campagne reali costruiscono un **grafo di separazione**: l'operatore raggiunge un nodo di accesso, i nodi di transito nascondono tale nodo all'uscita, i redirector proteggono il vero C2 e i nomi usa e getta puntano all'edge pubblico.

Usa il [Catalogo delle tecniche di accesso anonimo a Internet](anonymous-internet-access-techniques.md) per una panoramica normalizzata di vantaggi/svantaggi, deployment e rilevamento di ogni percorso. Questa pagina approfondisce la composizione dell'infrastruttura avversaria.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
L'ultimo indirizzo osservato da un target è quindi una prova del percorso, non la dimostrazione di chi controllasse la tastiera. MITRE associa i componenti principali a Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) e Web Service (T1102).<sup>[[1]](#references)</sup>

## Classi di infrastruttura

| Classe | Perché un attore la usa | Esposizione persistente | Miglior pivot del defender |
|---|---|---|---|
| VPS/cloud a noleggio | Rapidi, prevedibili, instradabili e facili da ricostruire | tenant, fatturazione, console, accessi di origine e cronologia delle immagini | eventi dell'account/control plane e fingerprint ricorrente del server |
| VPN commerciale/Tor | Ampio insieme di egress condivisi; nessuna amministrazione del server | visibilità del provider/guard e timing end-to-end | comportamento della destinazione, evidenze sugli endpoint e correlazione dei flussi |
| Proxy residential/mobile | ASN consumer e plausibilità geografica | registri del broker/cliente; comportamento di proxyware o host infetti | impossible travel, protocolli proxy e variazioni degli indirizzi per sessione |
| Server/router/IoT compromesso | Sfrutta la reputazione e la giurisdizione della vittima | implant, flusso di gestione e controller upstream ricorrente | telemetria del dispositivo e topologia ORB, non un singolo exit IP |
| CDN/redirector | Separa l'edge pubblico dal C2 back-end | grammatica TLS/HTTP, certificato, routing e artefatti dell'account cloud | correlazione edge-to-origin e clustering della forma delle richieste |
| Web service legittimo | Si confonde con il traffico GitHub/cloud/social consentito | API token, identificatori di tenant/oggetto e lineage insolito dei processi | processo dell'endpoint insieme alla semantica del servizio/API |
| Percorso fisico/cellulare/satellitare | Modifica l'origine fisica apparente | registri RF, dell'operatore, dell'abbonato, del dispositivo e della posizione | evidenze radio/fisiche e di rete combinate |

## Reti di relay box operative

Una **rete ORB** è una flotta di proxy gestita e utilizzata come servizio intermedio. Mandiant le divide in reti provisioned, composte da server presi in leasing, reti non-provisioned, composte da router/IoT compromessi, e reti ibride. Una topologia matura ha quattro ruoli logici:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** mantiene inventario, credenziali, stato e policy di routing.
2. **Access/relay node:** autentica clienti o operatori; è l'ingresso stabile verso una mesh in cambiamento.
3. **Traversal nodes:** uno o più sistemi presi in leasing o compromessi inoltrano connessioni opache.
4. **Exit/staging node:** presenta l'indirizzo sorgente finale a reconnaissance, exploitation o ai target C2.

La mesh può selezionare gli exit in base a paese, ASN, latenza o disponibilità e sostituire i nodi non integri. Più threat group possono prendere in affitto la stessa rete. Mandiant ha osservato un indirizzo IPv4 rimanere associato ad alcuni ORB per appena 31 giorni; raccomanda quindi di trattare la **rete come un'entità in evoluzione simile a un attore**, invece di bloccare un elenco obsoleto di IP.<sup>[[2]](#references)</sup>

### Cosa offre e cosa espone

- Il target vede un exit che può essere geograficamente vicino e apparentemente residential.
- L'exit vede il target e l'hop precedente, ma non necessariamente l'operatore.
- Il servizio di accesso vede il cliente e la richiesta di routing. Una mesh gestita in modo indipendente può mantenere il cliente separato dagli exit, ma crea un potente registro della controparte.
- Porte ricorrenti, ordine dell'handshake, banner dei server, certificati, finestre di uptime e relazioni con i controller possono esporre la flotta anche mentre gli IP ruotano.
- Un router compromesso spesso non dispone di telemetria dell'endpoint, ma il suo ISP conserva comunque dati sull'abbonato e sui flussi; un sequestro espone artefatti dell'implant e della configurazione.

{% hint style="info" %}
Per un esercizio autorizzato, riproduci la topologia con VM o router di proprietà dell'organizzazione e conserva la mappa di attribuzione del controller. Non reclutare proxy aperti o dispositivi di terze parti. La [lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) crea la stessa struttura di hop visibile al defender senza danneggiare un intermediario.
{% endhint %}

## Reti di proxy residential e mobile

I servizi di proxy residential assegnano le sessioni a indirizzi della banda larga consumer; i proxy mobile effettuano l'egress attraverso pool di carrier NAT. L'offerta può provenire da appliance espressamente arruolate, SDK/proxyware integrati in applicazioni consumer, reseller o malware. Queste origini non sono equivalenti: l'assenza di consenso informato trasforma un servizio per la privacy in infrastruttura compromessa.

Le modalità di rotazione influenzano il rilevamento:

- la **rotazione per richiesta** produce rapide discontinuità di IP, ASN e geografia mentre l'identità ai livelli superiori rimane stabile;
- le **sticky session** mantengono un exit per minuti o ore, facendolo somigliare a un normale abbonato;
- i **backconnect gateway** espongono al cliente un endpoint del broker e scelgono internamente gli exit;
- i **pool mobile** collocano molti abbonati reali dietro un piccolo insieme di indirizzi carrier NAT, rendendo costoso un blocco IP.

I defender dovrebbero correlare l'IP con la sessione autenticata, il fingerprint TLS/client, l'ordine HTTP, il cookie del dispositivo e il comportamento. Un accesso residential apparentemente locale seguito da un altro paese, mentre tutte le funzionalità ai livelli superiori rimangono identiche, è un indicatore più forte della sola reputazione. Al contrario, la condivisione degli indirizzi e il passaggio tra celle mobile creano una rotazione legittima; non trattare quindi mai la classificazione residential/proxy come un verdetto.

## Catene di proxy multi-hop

MITRE distingue i proxy esterni dai **multi-hop proxy (T1090.003)**. La proprietà importante non è il numero di hop, ma la separazione delle conoscenze e dell'amministrazione.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Se una delle parti gestisce A e B, i log condivisi o la temporizzazione del flusso possono ricostruire il circuito. Aggiungere VPN commerciali sequenziali dallo stesso endpoint/account può aumentare la latenza, lasciando però elementi comuni relativi all'identità, al pagamento e alla temporizzazione. Tor riduce questo problema con relay selezionati in modo indipendente e un design client condiviso, ma una rete interattiva a bassa latenza non può garantire resistenza a un osservatore che misura entrambe le estremità.

I problemi comuni sono i bypass DNS o IPv6, le applicazioni che aprono i propri socket, il traffico di gestione che raggiunge direttamente i relay, l'attività sincronizzata, il riutilizzo delle chiavi SSH e l'accesso ad account identificativi. La verifica corretta è un failure test: arrestare ogni relay a turno e dimostrare che il carico di lavoro non può ricadere su un percorso in chiaro.

## Livelli di redirector e traffic shaping

Un **redirector** pubblico accetta il traffico che corrisponde a una grammatica specifica dell'operazione e lo inoltra a un team server protetto. Tutto il resto può essere rifiutato o può ricevere contenuti innocui.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Più livelli limitano l'esposizione: bruciare un dominio pubblico non deve necessariamente esporre il team server. Le CDN aggiungono capacità anycast e un dominio esterno affidabile, ma l'account CDN e gli edge log diventano punti di attribuzione. TLS fingerprint, cronologia dei certificati, percorsi distintivi/ordine degli header, dimensioni delle risposte, comportamento dei redirect e allowlist dell'origine possono raggruppare front apparentemente non correlati.

Per il rilevamento, registra i campi del reverse proxy prima della normalizzazione, confronta SNI/Host/authority, analizza le combinazioni rare di header, raggruppa i response body e i TLS fingerprint e cerca nei log di audit cloud/CDN sovrapposizioni di configurazione. Per i red team autorizzati, evita di copiare un brand reale o di collocare la raccolta di credenziali dietro una terza parte non correlata.

## Domain fronting e domainless fronting

Con il **domain fronting classico (T1090.004)**, la connessione TLS pubblicizza un dominio front consentito in SNI, mentre l'`Host` HTTP crittografato o l'`authority` HTTP/2 `:authority` richiede un dominio back-end diverso. Una CDN collaborante instrada in base al valore interno. Un osservatore di rete senza decrittografia TLS vede il front; la CDN vede entrambi i valori e l'origine. Nelle varianti domainless, SNI può essere vuoto mentre un altro campo di routing seleziona la destinazione.<sup>[[4]](#references)</sup>

Non si tratta di una magica impersonificazione: funziona solo quando l'intermediario consente intenzionalmente o accidentalmente la discrepanza e sa come instradare il nome interno. I principali provider hanno limitato il fronting tra account diversi. Encrypted ClientHello (ECH) modifica ciò che un osservatore sul percorso può vedere, ma non elimina i record della CDN, dell'endpoint o dell'applicazione.

I punti di rilevamento includono:

- l'ascendenza del processo sull'endpoint e una destinazione non prevista per quell'applicazione;
- discrepanze tra SNI e authority HTTP, quando l'ispezione TLS è lecita e disponibile;
- log CDN che mostrano un tenant/front che instrada verso un'altra authority/origine;
- sessioni insolitamente longeve o periodiche verso un servizio normalmente interattivo;
- dimensioni e cadenza stabili dei flussi crittografati attraverso domini front variabili.

Il laboratorio sicuro simula la discrepanza di routing su un reverse proxy di proprietà; non abusa di una CDN pubblica.

## Risoluzione dinamica: DDNS, DGA e fast flux

La risoluzione dinamica disaccoppia un servizio logico dall'infrastruttura fissa:

- **DDNS:** un client autenticato aggiorna un nome stabile dopo la modifica del proprio indirizzo.
- **DGA:** endpoint e controller derivano entrambi nomi di dominio candidati da un seed temporale/chiave; l'operatore registra un piccolo sottoinsieme.
- **Fast flux:** un nome restituisce un insieme in rapida variazione di indirizzi compromessi/proxy, spesso con TTL bassi.
- **Double flux:** ruotano sia gli indirizzi dei servizi sia quelli dei name server autorevoli, nascondendo anche il control layer.

Il fast flux è un pattern di distribuzione del carico usato in modo avversario, non semplicemente “molte risposte DNS”. Prove più solide combinano TTL bassi, un numero elevato di indirizzi unici, ampia dispersione di ASN/geografia, breve durata dei nodi, comportamento applicativo ripetuto e cronologia di registrazione sospetta. Le CDN condividono legittimamente diverse di queste proprietà. MITRE raccomanda di correlare il comportamento DNS con il processo e le connessioni successive.<sup>[[5]](#references)</sup>

Una DGA può essere rilevata tramite entropia lessicale, pattern di consonanti/cifre, raffiche di NXDOMAIN, domini visti per la prima volta in modo sincronizzato e contesto del processo. Le DGA basate su wordlist e i modelli generativi eludono le semplici regole basate sull'entropia, rendendo più importante il raggruppamento temporale a livello di flotta e la lineage dell'endpoint.

## Domini compromessi e domain shadowing

Un attore può dirottare un account registrar/DNS, prendere il controllo di un sottodominio abbandonato o aggiungere record sotto un dominio altrimenti affidabile. Il **domain shadowing** conserva l'apice legittimo mentre grandi quantità di sottodomini controllati dall'attaccante puntano a host di delivery o C2 variabili. Sfrutta anzianità e reputazione e può eludere il blocco a livello di dominio.<sup>[[6]](#references)</sup>

I difensori hanno bisogno dei log di audit del registrar e del DNS autorevole, di MFA, dei lock di registry/registrar, di alert per nuove deleghe/token API/name server, del monitoraggio della certificate transparency e di un inventario delle risorse cloud referenziate dal DNS. Analizza la risoluzione e la cronologia dei certificati di un sottodominio indipendentemente dalla reputazione dell'apice.

## Web services e dead-drop resolver

Un **dead-drop resolver (T1102.001)** conserva un puntatore codificato al C2 corrente all'interno di un post, profilo, documento, repository, cloud object o campo blockchain legittimo. Il malware recupera l'oggetto pubblico, decodifica un dominio/IP e contatta lo stage successivo. Le varianti bidirezionali scambiano comandi o file tramite API di servizio.<sup>[[7]](#references)</sup>

Questo garantisce resilienza e nasconde il C2 back-end dall'analisi statica dei binari. Crea inoltre identificatori stabili di oggetti, tenant, repository, API e pattern di accesso. I difensori dovrebbero correlare:

1. il processo che ha contattato il servizio;
2. il percorso API/oggetto esatto e l'hash della risposta;
3. l'attività di decoding o di elaborazione delle stringhe;
4. la nuova connessione in uscita poco dopo; e
5. il comportamento identico altrove nella flotta.

Bloccare tutto GitHub, il cloud storage o i social media è raramente praticabile. Una policy di egress consapevole del servizio e la correlazione a livello di processo sono più efficaci del blocco basato solo sul dominio.

## Personas, account e compartimenti di procurement

L'anonimato dell'infrastruttura fallisce quando una persona, un'email di recupero, un telefono, un pagamento, un browser o un IP amministrativo collega compartimenti diversi. Le operazioni collegate a Stati hanno coltivato profili social, identità email e account cloud molto prima del loro utilizzo; ATT&CK registra questo come Establish Accounts (T1585), incluse le sottotecniche social, email e cloud.<sup>[[8]](#references)</sup>

Un difensore o investigatore costruisce un grafo a partire da:

- momento della creazione e del primo login, locale, fuso orario e orario di lavoro;
- campi di recupero, dispositivi MFA, documenti d'identità e strumenti di pagamento;
- browser/TLS fingerprint e cronologia delle reti sorgente;
- riutilizzo degli avatar, provenienza delle immagini, stile di scrittura e crescita del grafo sociale;
- registrant di dominio, name server, certificato, analytics ID o commit del repository condivisi;
- azioni del management plane che aggirano l'architettura pubblica di relay.

Per un red team autorizzato, le personas sintetiche devono essere documentate al responsabile dell'esercitazione, utilizzare canali di recupero/pagamento di proprietà dell'organizzazione, evitare di impersonare persone reali non coinvolte e prevedere il ritiro. Il SOC può rimanere cieco; l'operazione non deve diventare priva di responsabilità.

## Pattern composti emergenti da modellare nelle minacce

Quelli seguenti sono **composizioni guidate dal difensore**, non affermazioni secondo cui un attore nominato abbia implementato ciascun design esatto. Combinano primitive già osservate e sono utili come ipotesi di purple team.

### Tasking asimmetrico unidirezionale

I comandi arrivano tramite una fonte pubblica, broadcast o append-only, mentre i risultati escono tramite un canale non correlato dopo un ritardo. Esempi della primitiva includono la comunicazione unidirezionale tramite web service e i dead drop. La separazione impedisce che un singolo flusso appaia bidirezionale e ostacola la semplice correlazione request/response.<sup>[[9]](#references)</sup>

**Rilevamento:** conserva le letture a livello di oggetto, quindi correla i cambiamenti di stato del processo e i successivi trasferimenti in uscita su una finestra più ampia. Cerca un processo raro che legge lo stesso oggetto pubblico anche quando non segue una risposta immediata.

### Promozione del canale multi-stage

Un primo stage silenzioso esegue l'inventario e promuove solo i sistemi selezionati a un canale di secondo stage non correlato. Il secondo endpoint, protocollo e processo possono non condividere alcuna infrastruttura con il primo. Questo limita l'esposizione dell'infrastruttura capace ed è modellato esplicitamente come ATT&CK T1104.<sup>[[10]](#references)</sup>

**Rilevamento:** collega `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; non chiudere l'incidente dopo aver bloccato il primo dominio.

### Traduzione del relay cross-protocol

Hop diversi traducono HTTPS, QUIC, WebSocket, DNS, SSH o un'API message-queue invece di inoltrare i pacchetti in modo trasparente. La traduzione rimuove un singolo fingerprint di protocollo end-to-end, ma crea gateway con timing, buffering e conversione semantica distintivi. Il protocol tunneling (T1572) può essere combinato con proxy e service impersonation.<sup>[[11]](#references)</sup>

**Rilevamento:** cerca host gateway che ricevono un protocollo e ne avviano un altro con comportamento byte/tempo strettamente correlato; confronta l'intento dell'endpoint con il protocollo effettivamente trasportato.

### Attivazione passiva sui dispositivi edge

Invece di eseguire beaconing, un implant monitora il traffico che raggiunge già un router/VPN e si attiva solo in presenza di un valore magico, di un pattern di source port o di un token autenticato. Il traffico normale continua verso il servizio reale. ATT&CK definisce questo Traffic Signaling (T1205), con esempi documentati relativi a dispositivi di rete e APT.<sup>[[12]](#references)</sup>

**Rilevamento:** integrità del firmware/file, cattura dei pacchetti raw durante un hunt autorizzato, socket filter inattesi e comportamento differenziale del servizio. L'assenza di un beacon periodico non dimostra che un dispositivo edge sia pulito.

### Rotazione delle origini serverless ed effimere

Un front mantiene un'identità logica stabile mentre funzioni/container di breve durata gestiscono singoli stage in diverse regioni/account. Questo riduce la durata su disco e gli IP di origine fissi, ma la creazione nel control plane, l'immagine/layer, il ruolo, il secret, il request ID e la telemetria di billing diventano il grafo persistente.

**Rilevamento:** conserva i log di audit e di invocation cloud al di fuori del workload; raggruppa i template di deployment, i ruoli, le chiavi d'ambiente e le relazioni front-to-origin.

### Diversità dei privacy layer

Un'operazione può evitare deliberatamente una catena omogenea: per esempio, un canale usa un relay in leasing, il tasking usa un oggetto pubblico, un'uscita proviene da un collegamento cellulare di laboratorio di proprietà e l'amministrazione usa una rete separata dell'organizzazione. Questo riduce il valore della compromissione di un singolo provider, ma aumenta il rischio di correlazione temporale cross-layer e di errori operativi.

**Rilevamento:** costruisci timeline della campagna tra sensori di identità, DNS, SaaS, rete e cloud. Cerca transizioni di stato sincronizzate invece di indicatori identici.

### Dead drop decentralizzati o basati su transparency log

Un attore può collocare un piccolo puntatore crittografato in qualsiasi sistema pubblico durevole append-only, content-addressed store o feed simile alla transparency. L'oggetto pubblico è resiliente, ma il suo indice/hash del contenuto esatto e il comportamento di polling del client diventano identificatori stabili.

**Rilevamento:** registra gli identificatori completi di API/oggetto e gli hash delle risposte; genera alert per processi non standard che eseguono il polling di oggetti immutabili seguito da decoding o da nuove connessioni.

### Operazioni store-and-forward ritardate

Il C2 interattivo crea una forte correlazione temporale. Un design store-and-forward raggruppa i job crittografati e restituisce i risultati dopo minuti o ore tramite una coda diversa o un trasferimento fisico. Sacrifica la reattività per indebolire il timing end-to-end.

**Rilevamento:** estendi le finestre di correlazione, modella l'accesso periodico alle code ed esamina lo staging sugli endpoint. Il batching sposta il segnale dal timing dei pacchetti al comportamento pianificato di processi/file; non lo elimina.

## Revisione del design: ragiona in termini di osservatori

Per ogni percorso, compila questa tabella prima del deployment e dopo la raccolta:

| Layer | Vede la sorgente? | Vede la destinazione? | Vede il contenuto? | Identificatori stabili | Proprietario della conservazione/aspetto legale |
|---|---:|---:|---:|---|---|
| rete locale/carrier | | | | | |
| servizio di ingresso/accesso | | | | | |
| operatore/i di traversal | | | | | |
| exit/redirector/CDN | | | | | |
| DNS autorevole/registrar | | | | | |
| target | | | | | |
| provider dell'account/pagamento | | | | | |

Se un singolo provider ordinario può compilare ogni colonna, l'architettura garantisce occultamento rispetto al target, ma non una separazione robusta. Se nessun controller interno può ricondurre l'attività a un engagement, l'architettura non è adatta al red teaming professionale.

## References

- [1] [MITRE ATT&CK — Acquisire infrastruttura (T1583), Compromettere infrastruttura (T1584) e Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Gli attori di spionaggio China-nexus usano reti ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromettere infrastruttura: domini (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Stabilire account (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: comunicazione unidirezionale (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
{{#include ../banners/hacktricks-training.md}}
