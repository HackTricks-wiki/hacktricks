# Infrastruttura offensiva ed elusione dell'attribuzione

Un operatore raramente ottiene un anonimato significativo tramite un singolo proxy. Le campagne reali costruiscono un **grafo di separazione**: l'operatore raggiunge un nodo di accesso, i nodi di transito nascondono quel nodo dall'uscita, i redirector proteggono il vero C2 e i nomi usa e getta puntano all'edge pubblico.

Usa il [Catalogo delle tecniche di accesso anonimo a Internet](anonymous-internet-access-techniques.md) per una panoramica normalizzata di vantaggi/svantaggi, deployment e rilevamento di ogni percorso. Questa pagina approfondisce la composizione dell'infrastruttura avversaria.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
L'ultimo indirizzo osservato da un target è quindi una prova del percorso, non la dimostrazione di chi controllasse la tastiera. MITRE associa i componenti principali a Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) e Web Service (T1102).<sup>[[1]](#references)</sup>

## Classi di infrastruttura

| Classe | Perché un attore la utilizza | Esposizione persistente | Miglior pivot del defender |
|---|---|---|---|
| VPS/cloud noleggiato | Rapido, prevedibile, instradabile, facile da ricostruire | tenant, fatturazione, console, accessi alla sorgente e cronologia delle immagini | eventi dell'account/control plane e fingerprint ripetuto del server |
| VPN/Tor commerciale | Ampio insieme di egress condivisi; nessuna amministrazione del server | visibilità del provider/guard e temporizzazione end-to-end | comportamento della destinazione, evidenze sull'endpoint e correlazione dei flussi |
| Proxy residenziale/mobile | ASN consumer e plausibilità geografica | registri del broker/cliente; comportamento di proxyware o host infetti | impossible travel, protocolli proxy e variazione degli indirizzi per sessione |
| Server/router/IoT compromesso | Sfrutta la reputazione e la giurisdizione della vittima | implant, flusso di gestione e controller upstream ripetuto | telemetria del dispositivo e topologia ORB, non un solo IP di uscita |
| CDN/redirector | Separa l'edge pubblico dal C2 di back-end | grammatica TLS/HTTP, certificato, routing e artefatti dell'account cloud | correlazione edge-origin e clustering della forma delle richieste |
| Web service legittimo | Si confonde con il traffico GitHub/cloud/social consentito | token API, identificatori di tenant/oggetto e lineage insolito dei processi | processo dell'endpoint più semantica del service/API |
| Percorso fisico/cellulare/satellitare | Modifica l'origine fisica apparente | registri RF, dell'operatore, dell'abbonato, del dispositivo e della posizione | evidenze radio/fisiche e di rete combinate |

## Reti di relay box operative

Una **rete ORB** è una flotta di proxy gestita utilizzata come service intermedio. Mandiant le divide in reti provisioned di server noleggiati, reti non-provisioned di router/IoT compromessi e reti ibride. Una topologia matura presenta quattro ruoli logici:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** mantiene inventario, credenziali, stato e policy di routing.
2. **Access/relay node:** autentica clienti o operatori; è l'ingresso stabile verso una mesh variabile.
3. **Traversal nodes:** uno o più sistemi noleggiati o compromessi inoltrano connessioni opache.
4. **Exit/staging node:** presenta l'indirizzo sorgente finale alle attività di reconnaissance, exploitation o ai target C2.

La mesh può selezionare gli exit in base a paese, ASN, latenza o disponibilità e sostituire i nodi non funzionanti. Più threat group possono noleggiare la stessa rete. Mandiant ha osservato che un indirizzo IPv4 rimaneva associato ad alcuni ORB per appena 31 giorni; raccomanda quindi di trattare la **rete come un'entità in evoluzione simile a un attore**, invece di bloccare un elenco obsoleto di IP.<sup>[[2]](#references)</sup>

### Cosa offre e cosa rivela

- Il target vede un exit che può essere geograficamente vicino e apparentemente residenziale.
- L'exit vede il target e l'hop precedente, non necessariamente l'operatore.
- L'access service vede il cliente e la richiesta di routing. Una mesh gestita in modo indipendente può mantenere il cliente separato dagli exit, ma crea un potente registro della controparte.
- Porte ripetute, ordine dell'handshake, banner del server, certificati, finestre di uptime e relazioni con i controller possono rivelare la flotta anche mentre gli IP ruotano.
- Un router compromesso spesso non dispone di telemetria dell'endpoint, ma il suo ISP possiede comunque dati sull'abbonato e sui flussi; un sequestro espone artefatti di implant/configurazione.

{% hint style="info" %}
Per un'esercitazione autorizzata, riproduci la topologia con VM o router di proprietà dell'organizzazione e conserva la mappa di attribuzione del controller. Non reclutare proxy aperti o dispositivi di terze parti. La [guida del laboratorio](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) crea la stessa struttura di hop visibile al defender senza vittimizzare un intermediario.
{% endhint %}

## Reti di proxy residenziali e mobile

I service di proxy residenziali assegnano le sessioni ad indirizzi della banda larga consumer; i proxy mobile effettuano l'egress tramite pool NAT degli operatori. L'offerta può provenire da appliance esplicitamente arruolate, SDK/proxyware integrati in applicazioni consumer, reseller o malware. Queste origini non sono equivalenti: l'assenza di consenso informato trasforma un service per la privacy in un'infrastruttura compromessa.

Le modalità di rotazione influenzano il rilevamento:

- la **rotazione per richiesta** produce rapide discontinuità di IP e ASN/geografia mentre l'identità ai livelli superiori rimane stabile;
- le **sticky session** mantengono un exit per minuti o ore, somigliando a un normale abbonato;
- i **backconnect gateway** espongono al cliente un endpoint del broker e scelgono internamente gli exit;
- i **pool mobile** collocano molti abbonati reali dietro un piccolo insieme di indirizzi NAT degli operatori, rendendo costoso un blocco IP.

I defender dovrebbero correlare l'IP con sessione autenticata, fingerprint TLS/client, ordine HTTP, cookie del dispositivo e comportamento. Un login residenziale apparentemente locale seguito da un altro paese, mentre tutte le caratteristiche ai livelli superiori rimangono identiche, è un'indicazione più forte della sola reputazione. Al contrario, la condivisione degli indirizzi e il passaggio tra celle mobile creano variazioni legittime; non trattare quindi mai la classificazione residenziale/proxy come un verdetto.

## Catene di proxy multi-hop

MITRE distingue i proxy esterni dai **multi-hop proxies (T1090.003)**. La proprietà importante non è il numero di hop, ma la separazione della conoscenza e dell'amministrazione.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Se una delle parti gestisce A e B, i log condivisi o il timing dei flussi possono ricostruire il circuito. L'aggiunta di VPN commerciali sequenziali dallo stesso endpoint/account può aumentare la latenza, lasciando però comuni identità, dati di pagamento ed evidenze temporali. Tor riduce questo problema con relay selezionati indipendentemente e un design client condiviso, ma una rete interattiva a bassa latenza non può garantire resistenza a un osservatore che misura entrambe le estremità.

I guasti più comuni sono il bypass di DNS o IPv6, le applicazioni che aprono i propri socket, il traffico di gestione che raggiunge direttamente i relay, l'attività sincronizzata, il riutilizzo delle chiavi SSH e l'accesso ad account identificativi. La verifica corretta è un failure test: arrestare ogni relay a turno e dimostrare che il workload non può ripiegare su un percorso in chiaro.

## Livelli di redirector e traffic shaping

Un **redirector** pubblico accetta il traffico che corrisponde a una grammatica specifica dell'operazione e lo inoltra a un team server protetto. Tutto il resto può essere rifiutato o può ricevere contenuti innocui.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Più livelli limitano l'esposizione: bruciare un dominio pubblico non deve necessariamente esporre il team server. Le CDN aggiungono capacità anycast e un dominio esterno reputabile, ma l'account CDN e gli edge log diventano punti di attribuzione. TLS fingerprint, cronologia dei certificati, path distintivi/ordine degli header, dimensioni delle risposte, comportamento dei redirect e allowlist dell'origin possono raggruppare front apparentemente non correlati.

Per il rilevamento, registrare i campi del reverse proxy prima della normalizzazione, confrontare SNI/Host/authority, esaminare combinazioni rare di header, raggruppare i response body e i TLS fingerprint e cercare sovrapposizioni di configurazione nei log di audit cloud/CDN. Per i red team autorizzati, evitare di copiare un brand reale o di collocare la raccolta di credenziali dietro una terza parte non correlata.

## Domain fronting e domainless fronting

Con il **domain fronting (T1090.004)** classico, la connessione TLS pubblicizza un dominio front consentito in SNI, mentre l'HTTP `Host` cifrato o l'HTTP/2 `:authority` richiede un dominio back-end diverso. Una CDN cooperante effettua il routing in base al valore interno. Un osservatore di rete senza decrittazione TLS vede il front; la CDN vede entrambi i valori e l'origin. Nelle varianti domainless, SNI può essere vuoto mentre un altro campo di routing seleziona la destinazione.<sup>[[4]](#references)</sup>

Non si tratta di una magia di impersonation: funziona solo quando l'intermediario consente intenzionalmente o accidentalmente il mismatch e sa come effettuare il routing del nome interno. I principali provider hanno limitato il fronting tra account diversi. Encrypted ClientHello (ECH) modifica ciò che un osservatore on-path può vedere, ma non elimina i log della CDN, dell'endpoint o dell'applicazione.

I punti di rilevamento includono:

- ancestry del processo sull'endpoint e destinazione non prevista per quell'applicazione;
- mismatch tra SNI e authority HTTP quando la TLS inspection è lecita e disponibile;
- log CDN che mostrano un tenant/front con routing verso un'altra authority/origin;
- sessioni insolitamente lunghe o periodiche verso un servizio normalmente interattivo;
- dimensioni e cadenza stabili dei flussi cifrati tra domini front variabili.

Il laboratorio sicuro simula il routing mismatch su un reverse proxy di proprietà; non abusa di una CDN pubblica.

## Dynamic resolution: DDNS, DGA e fast flux

La dynamic resolution disaccoppia un servizio logico dall'infrastruttura fissa:

- **DDNS:** un client autenticato aggiorna un nome stabile dopo la variazione del proprio indirizzo.
- **DGA:** endpoint e controller ricavano entrambi domini candidati da un seed temporale/chiave; l'operatore registra un piccolo sottoinsieme.
- **Fast flux:** un nome restituisce un insieme in rapida variazione di indirizzi compromessi/proxy, spesso con TTL bassi.
- **Double flux:** ruotano sia gli indirizzi dei servizi sia quelli dei name server autorevoli, nascondendo anche il control layer.

Il fast flux è un pattern di distribuzione del carico usato in modo avversario, non semplicemente “molte risposte DNS”. Un'evidenza più forte combina TTL bassi, un numero elevato di indirizzi unici, ampia dispersione di ASN/geografia, breve durata dei nodi, comportamento applicativo ripetuto e cronologia di registrazione sospetta. Le CDN condividono legittimamente diverse di queste proprietà. MITRE raccomanda di correlare il comportamento DNS con il processo e le connessioni successive.<sup>[[5]](#references)</sup>

Una DGA può essere rilevata tramite entropia lessicale, pattern di consonanti/cifre, raffiche di NXDOMAIN, domini sincronizzati al first-seen e contesto del processo. Le DGA basate su wordlist e i modelli generativi eludono le semplici regole sull'entropia, rendendo più importanti il clustering temporale a livello di flotta e la lineage dell'endpoint.

## Domini compromessi e domain shadowing

Un attore può dirottare un account registrar/DNS, prendere il controllo di un dangling subdomain o aggiungere record al di sotto di un dominio altrimenti reputabile. Il **domain shadowing** preserva l'apex legittimo mentre un gran numero di subdomini controllati dall'attaccante punta verso host di delivery o C2 variabili. Sfrutta anzianità e reputazione e può eludere il blocking a livello di dominio.<sup>[[6]](#references)</sup>

I defender necessitano di log di audit del registrar e del DNS autorevole, MFA, registry/registrar lock, alert per nuove deleghe/token API/name server, monitoraggio della certificate transparency e un inventario delle risorse cloud referenziate dal DNS. Analizzare la resolution e la cronologia dei certificati di un subdominio indipendentemente dalla reputazione dell'apex.

## Web services e dead-drop resolver

Un **dead-drop resolver (T1102.001)** memorizza un puntatore codificato al C2 corrente all'interno di un post, profilo, documento, repository, cloud object o campo blockchain legittimo. Il malware recupera l'oggetto pubblico, decodifica un dominio/IP e contatta lo stage successivo. Le varianti bidirezionali scambiano comandi o file tramite le API del servizio.<sup>[[7]](#references)</sup>

Ciò garantisce resilienza e nasconde il back-end C2 dall'analisi statica del binario. Crea inoltre identificatori stabili di oggetti, tenant, repository, API e pattern di accesso. I defender dovrebbero correlare:

1. il processo che ha contattato il servizio;
2. il path API/oggetto esatto e l'hash della risposta;
3. l'attività di decoding o di elaborazione delle stringhe;
4. la nuova connessione outbound poco dopo; e
5. il comportamento identico altrove nella flotta.

Bloccare tutto GitHub, il cloud storage o i social media è raramente praticabile. Una policy di egress consapevole del servizio e la correlazione a livello di processo superano il blocking basato solo sul dominio.

## Personas, account e compartimentazione degli acquisti

L'anonimato dell'infrastruttura fallisce quando una persona, un'email di recupero, un telefono, un pagamento, un browser o un IP amministrativo collega i compartimenti. Le operazioni collegate a stati hanno coltivato profili social, identità email e account cloud molto prima dell'utilizzo; ATT&CK lo registra come Establish Accounts (T1585), incluse le sottotecniche social, email e cloud.<sup>[[8]](#references)</sup>

Un defender o investigatore costruisce un grafo a partire da:

- orario di creazione e del primo login, locale, fuso orario e calendario lavorativo;
- campi di recupero, dispositivi MFA, documenti d'identità e strumenti di pagamento;
- browser/TLS fingerprint e cronologia della rete sorgente;
- riutilizzo dell'avatar, provenienza delle immagini, stile di scrittura e crescita del grafo sociale;
- registrant del dominio, name server, certificato, analytics ID o commit del repository condivisi;
- azioni sul management plane che aggirano l'architettura pubblica di relay.

Per un red team autorizzato, le personas sintetiche devono essere documentate presso il responsabile dell'esercitazione, utilizzare canali di recupero/pagamento di proprietà dell'organizzazione, evitare di impersonare persone reali estranee e prevedere il retirement. Il SOC può rimanere all'oscuro; l'operazione non deve diventare priva di accountability.

## Emerging compound patterns da includere nel threat model

I seguenti sono **assemblaggi guidati dai defender**, non affermazioni secondo cui un attore nominato abbia implementato ciascun design esatto. Combinano primitive già osservate e sono utili come ipotesi di purple team.

### Asymmetric one-way tasking

I comandi arrivano tramite una sorgente pubblica, broadcast o append-only, mentre i risultati escono tramite un canale non correlato dopo un ritardo. Esempi della primitiva includono la comunicazione one-way tramite web service e i dead drop. La separazione impedisce a un singolo flusso di apparire bidirezionale e ostacola la semplice correlazione request/response.<sup>[[9]](#references)</sup>

**Rilevamento:** conservare le letture a livello di oggetto, quindi correlare i cambiamenti di stato del processo e i successivi trasferimenti outbound su una finestra più ampia. Cercare un processo raro che legge lo stesso oggetto pubblico anche quando non segue alcuna risposta immediata.

### Multi-stage channel promotion

Un primo stage silenzioso esegue l'inventario e promuove solo i sistemi selezionati verso un canale di secondo stage non correlato. Il secondo endpoint, protocollo e processo possono non condividere alcuna infrastruttura con il primo. Ciò limita l'esposizione dell'infrastruttura capace ed è modellato esplicitamente come ATT&CK T1104.<sup>[[10]](#references)</sup>

**Rilevamento:** collegare `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; non chiudere l'incident dopo aver bloccato il primo dominio.

### Cross-protocol relay translation

Hop diversi traducono HTTPS, QUIC, WebSocket, DNS, SSH o un'API message-queue invece di inoltrare i pacchetti in modo trasparente. La traduzione rimuove un singolo protocol fingerprint end-to-end, ma crea gateway con timing, buffering e conversione semantica distintivi. Il protocol tunneling (T1572) può essere combinato con proxy e service impersonation.<sup>[[11]](#references)</sup>

**Rilevamento:** cercare host gateway che ricevono un protocollo e ne avviano un altro con comportamento byte/time strettamente correlato; confrontare l'intento dell'endpoint con il protocollo effettivamente trasportato.

### Passive activation on edge devices

Invece di eseguire beaconing, un implant monitora il traffico che raggiunge già un router/VPN e si attiva solo in presenza di un magic value, un pattern di source port o un token autenticato. Il traffico normale continua verso il servizio reale. ATT&CK lo definisce Traffic Signaling (T1205), con esempi documentati relativi a network device e APT.<sup>[[12]](#references)</sup>

**Rilevamento:** integrità del firmware/file, raw packet capture durante un hunt autorizzato, socket filter inattesi e comportamento differenziale del servizio. L'assenza di un beacon periodico non dimostra che un edge device sia pulito.

### Serverless and ephemeral origin rotation

Un front mantiene un'identità logica stabile mentre funzioni/container a breve durata gestiscono singoli stage in più regioni/account. Ciò riduce la permanenza su disco e gli IP origin fissi, ma la creazione sul control plane, l'immagine/layer, il ruolo, il secret, il request ID e la telemetria di billing diventano il grafo duraturo.

**Rilevamento:** conservare i log di audit e invocation cloud al di fuori del workload; raggruppare template di deployment, ruoli, chiavi d'ambiente e relazioni front-to-origin.

### Privacy-layer diversity

Un'operazione può evitare intenzionalmente una singola catena omogenea: per esempio, un canale usa un relay affittato, il tasking usa un oggetto pubblico, un'uscita proviene da un collegamento cellulare di laboratorio di proprietà e l'amministrazione utilizza una rete separata dell'organizzazione. Ciò riduce il valore della compromissione di un singolo provider, ma aumenta il rischio di correlazione temporale tra i layer e di errori operativi.

**Rilevamento:** costruire timeline della campagna tra sensori di identity, DNS, SaaS, rete e cloud. Cercare transizioni di stato sincronizzate anziché indicatori identici.

### Decentralized or transparency-log dead drops

Un attore può inserire un piccolo puntatore cifrato in qualsiasi sistema pubblico durevole append-only, content-addressed store o feed simile a un transparency log. L'oggetto pubblico è resiliente, ma il suo indice/content hash esatto e il comportamento di polling del client diventano identificatori stabili.

**Rilevamento:** registrare identificatori completi di API/oggetto e hash delle risposte; generare alert per processi non standard che interrogano oggetti immutabili seguiti da decoding o nuove connessioni.

### Delayed store-and-forward operations

Il C2 interattivo crea una forte correlazione temporale. Un design store-and-forward raggruppa job cifrati e restituisce i risultati dopo minuti o ore tramite una coda diversa o un trasferimento fisico. Sacrifica la reattività per indebolire il timing end-to-end.

**Rilevamento:** estendere le finestre di correlazione, modellare l'accesso periodico alle code ed esaminare lo staging sugli endpoint. Il batching sposta il segnale dal packet timing al comportamento pianificato di processi/file; non lo elimina.

## Design review: ragionare in termini di osservatori

Per ogni path, compilare questa tabella prima del deployment e dopo la raccolta:

| Layer | Vede la sorgente? | Vede la destinazione? | Vede il contenuto? | Identificatori stabili | Retention/data owner legale |
|---|---:|---:|---:|---|---|
| rete locale/carrier | | | | | |
| servizio di ingresso/accesso | | | | | |
| operatore/i di transito | | | | | |
| exit/redirector/CDN | | | | | |
| DNS autorevole/registrar | | | | | |
| target | | | | | |
| provider di account/pagamenti | | | | | |

Se un singolo provider ordinario può compilare ogni colonna, l'architettura offre concealment dal target ma non una separazione robusta. Se nessun controller interno può ricondurre l'attività a un engagement, l'architettura non è adatta al red teaming professionale.

## References

- [1] [MITRE ATT&CK — Acquisizione dell'infrastruttura (T1583), compromissione dell'infrastruttura (T1584) e proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Gli attori di espionage legati alla Cina usano reti ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromissione dell'infrastruttura: domini (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
