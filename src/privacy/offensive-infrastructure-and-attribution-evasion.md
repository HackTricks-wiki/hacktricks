# Infrastruttura offensiva ed elusione dell'attribuzione

{{#include ../banners/hacktricks-training.md}}

Un operator raramente ottiene un anonimato significativo tramite un singolo proxy. Le campagne reali costruiscono un **grafo di separazione**: l'operator raggiunge un nodo di accesso, i nodi di transito nascondono tale nodo all'uscita, i redirector proteggono il vero C2 e i nomi usa e getta puntano all'edge pubblico.

Consulta il [Catalogo delle tecniche di accesso anonimo a Internet](anonymous-internet-access-techniques.md) per una panoramica normalizzata di vantaggi/svantaggi, deployment e rilevamento di ogni percorso. Questa pagina approfondisce la composizione dell'infrastruttura avversaria.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
L'ultimo indirizzo osservato da un target è quindi una prova del percorso, non la dimostrazione di chi controllasse la tastiera. MITRE associa i componenti principali a Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) e Web Service (T1102).<sup>[[1]](#references)</sup>

## Classi dell'infrastruttura

| Classe | Perché un attore la usa | Esposizione duratura | Miglior pivot del defender |
|---|---|---|---|
| VPS/cloud noleggiati | Rapidi, prevedibili, instradabili e facili da ricreare | tenant, fatturazione, console, accessi d'origine e cronologia delle immagini | eventi dell'account/control plane e fingerprint ripetuti del server |
| VPN commerciale/Tor | Ampio insieme di egress condivisi; nessuna amministrazione del server | visibilità del provider/guard e timing end-to-end | comportamento della destinazione, evidenze sull'endpoint e correlazione dei flussi |
| Proxy residenziale/mobile | ASN consumer e plausibilità geografica | registri del broker/cliente; comportamento di proxyware o host infetti | impossible travel, protocolli proxy e variazione degli indirizzi per sessione |
| Server/router/IoT compromesso | Sfrutta la reputazione e la giurisdizione della vittima | implant, flusso di gestione e controller upstream ricorrente | telemetria del dispositivo e topologia ORB, non un singolo exit IP |
| CDN/redirector | Separa l'edge pubblico dal C2 back-end | grammatica TLS/HTTP, certificato, routing e artefatti dell'account cloud | correlazione edge-to-origin e clustering della forma delle richieste |
| Web service legittimo | Si confonde con il traffico GitHub/cloud/social consentito | API token, identificatori di tenant/oggetto e catena di origine dei processi insolita | processo dell'endpoint più semantica del service/API |
| Percorso fisico/cellulare/satellitare | Cambia l'origine fisica apparente | registri RF, dell'operatore, dell'abbonato, del dispositivo e della posizione | evidenze radio/fisiche e di rete combinate |

## Reti di relay box operative

Una **rete ORB** è una flotta di proxy gestita e usata come servizio intermedio. Mandiant le divide in reti provisioned di server in leasing, reti non-provisioned di router/IoT compromessi e reti ibride. Una topologia matura presenta quattro ruoli logici:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** mantiene inventario, credenziali, stato e policy di routing.
2. **Access/relay node:** autentica clienti o operatori; è l'ingresso stabile verso una mesh in cambiamento.
3. **Traversal nodes:** uno o più sistemi in leasing o compromessi inoltrano connessioni opache.
4. **Exit/staging node:** presenta l'indirizzo sorgente finale alle attività di reconnaissance, exploitation o ai target C2.

La mesh può selezionare gli exit in base a paese, ASN, latenza o disponibilità e ruotare i nodi non integri. Più threat group possono noleggiare la stessa rete. Mandiant ha osservato un indirizzo IPv4 rimanere associato ad alcuni ORB per appena 31 giorni; raccomanda quindi di trattare la **rete come un'entità in evoluzione simile a un attore**, invece di bloccare una lista obsoleta di IP.<sup>[[2]](#references)</sup>

### Cosa offre e cosa leaks

- Il target vede un exit che può essere geograficamente vicino e apparentemente residenziale.
- L'exit vede il target e l'hop precedente, ma non necessariamente l'operatore.
- Il servizio di accesso vede il cliente e la richiesta di routing. Una mesh gestita indipendentemente può mantenere il cliente separato dagli exit, ma crea un potente registro della controparte.
- Porte ripetute, ordine dell'handshake, banner del server, certificati, finestre di uptime e relazioni con i controller possono esporre la flotta anche mentre gli IP ruotano.
- Un router compromesso spesso non dispone di telemetria dell'endpoint, ma il suo ISP conserva comunque dati sull'abbonato e sui flussi; un sequestro espone artefatti di implant/configurazione.

{% hint style="info" %}
Per un'esercitazione autorizzata, riproduci la topologia con VM o router di proprietà dell'organizzazione e conserva la mappa di attribuzione del controller. Non reclutare proxy aperti o dispositivi di terze parti. La [guida del laboratorio](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) crea la stessa struttura di hop visibile al defender senza vittimizzare un intermediario.
{% endhint %}

## Reti di proxy residenziali e mobili

I servizi di proxy residenziali assegnano le sessioni a indirizzi della banda larga consumer; i proxy mobili effettuano l'egress attraverso pool NAT degli operatori. L'offerta può provenire da appliance esplicitamente arruolate, SDK/proxyware integrati in applicazioni consumer, reseller o malware. Queste origini non sono equivalenti: l'assenza di consenso informato trasforma un servizio per la privacy in infrastruttura compromessa.

Le modalità di rotazione influenzano il rilevamento:

- la **rotazione per richiesta** produce rapide discontinuità di IP e ASN/geografia mentre l'identità ai livelli superiori rimane stabile;
- le **sticky sessions** mantengono un exit per minuti o ore, facendolo sembrare un normale abbonato;
- i **backconnect gateway** espongono al cliente un endpoint del broker e scelgono internamente gli exit;
- i **mobile pool** collocano molti abbonati reali dietro un piccolo insieme di indirizzi NAT dell'operatore, rendendo costoso un blocco IP.

I defender dovrebbero correlare l'IP con la sessione autenticata, il fingerprint TLS/client, l'ordinamento HTTP, il cookie del dispositivo e il comportamento. Un login residenziale apparentemente locale seguito da un altro paese, mentre tutte le caratteristiche dei livelli superiori rimangono identiche, è un indicatore più forte della sola reputazione. Al contrario, la condivisione degli indirizzi e l'handoff mobile generano churn legittimo, quindi non trattare mai la classificazione residenziale/proxy come un verdetto.

### Control plane di proxyware e sovrapposizione dei reseller

Non modellare un pool residenziale come un semplice elenco di exit. L'analisi dell'ecosistema IPIDEA ha esposto un **control plane a due livelli** riutilizzabile: un SDK integrato segnala prima i metadati del dispositivo/arruolamento a un dominio Tier One e riceve la programmazione più coppie IP:porta `connect`/`proxy` del Tier Two. Il nodo interroga periodicamente la porta connect del Tier Two per un task codificato, apre una seconda connessione alla porta proxy associata e inoltra i byte forniti verso la destinazione richiesta. SDK e brand proxy nominalmente diversi avevano domini di discovery separati, ma converge­vano su un'infrastruttura Tier Two condivisa e su pool di exit sovrapposti tramite proprietà comuni e relazioni di reseller.<sup>[[13]](#references)</sup>
```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```
Questo produce pivot di hunting più durevoli rispetto a un blocco IP residenziale:<sup>[[13]](#references)</sup>

- un processo imprevisto di utility, VPN, gioco o dispositivo embedded invia un ID stabile del dispositivo/una chiave cliente e riceve un elenco di server variabile;
- l'endpoint interroga un IP diretto su una porta insolita, quindi si connette immediatamente a un'altra porta sullo stesso indirizzo prima di aprire un nuovo socket di destinazione;
- diversi brand apparenti condividono indirizzi Tier Two, la sintassi del protocollo, codice SDK o una sovrapposizione di exit-node;
- applicazioni distinte che contattano domini Tier One diversi ricevono indirizzi dallo stesso pool Tier Two.

La sovrapposizione limita inoltre l'attribuzione: vedere un IP nel pool pubblicizzato di un vendor non dimostra quale reseller, cliente o threat actor lo abbia utilizzato nel momento rilevante. Conserva i timestamp dei flussi, la process lineage, i response body Tier One e gli identificatori delle attività Tier Two.<sup>[[13]](#references)</sup> In un esercizio autorizzato, emula questa gerarchia solo con endpoint di proprietà dell'organizzazione; non registrare mai dispositivi consumer o proxyware di terze parti.

## Catene di proxy multi-hop

MITRE distingue i proxy esterni dai **multi-hop proxy (T1090.003)**. La proprietà importante non è il numero di hop, ma la separazione delle conoscenze e dell'amministrazione.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Se una delle parti gestisce A e B, i log condivisi o la temporizzazione del flusso possono ricostruire il circuito. L'aggiunta di VPN commerciali sequenziali dallo stesso endpoint/account può aumentare la latenza lasciando però inalterate le evidenze comuni relative a identità, pagamento e tempistiche. Tor riduce questo problema con relay selezionati indipendentemente e un design client condiviso, ma una rete interattiva a bassa latenza non può garantire resistenza a un osservatore che misura entrambe le estremità.

I problemi comuni sono il bypass tramite DNS o IPv6, le applicazioni che aprono socket propri, il traffico di gestione che raggiunge direttamente i relay, l'attività sincronizzata, il riutilizzo delle chiavi SSH e l'accesso ad account identificativi. La verifica corretta è un failure test: arrestare ogni relay a turno e dimostrare che il workload non può ripiegare su un percorso in chiaro.

### Collasso del tunnel e leakage upstream

Un'architettura a relay è spesso più attribuibile quando si guasta. Unit 42 ha documentato un percorso di spionaggio multi-tier che utilizzava VPS esposti alla vittima, VPS relay, proxy residenziali, Tor e altri servizi proxy; quando un tunnel veniva omesso o collassava, l'infrastruttura upstream nascosta si connetteva direttamente ai sistemi relay e a quelli esposti alla vittima. La stessa indagine ha inoltre utilizzato un certificato X.509 esposto brevemente sull'infrastruttura upstream come pivot tra tier.<sup>[[14]](#references)</sup>

Mantieni separati il **data plane** (`victim <-> exit`) e il **control plane** (`operator/upstream -> relay administration`). Conserva i log di ingresso e autenticazione a ogni tier gestito, gli storici dei certificati e le connessioni fallite brevi, non solo le sessioni C2 riuscite. Una sorgente che compare solo durante le interruzioni dei relay o che amministra direttamente più nodi esposti alla vittima è un candidato upstream più probabile rispetto a un normale exit, ma il suo ASN/la sua geolocalizzazione resta un'ipotesi, non una prova dell'identità dell'operatore.

Un lab autorizzato dovrebbe fare in modo che il workload fallisca in modalità chiusa. Per un workload isolato in un namespace di rete Linux, la prima route deve utilizzare il tunnel; dopo averlo rimosso, sia la richiesta sia la ricerca della route devono fallire invece di selezionare l'uplink fisico:
```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
--resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```
Ripeti il test per DNS e IPv6 e a ogni confine tra relay. Se una sonda ha successo, registra l'interfaccia/indirizzo sorgente effettivo prima di correggere il policy routing o il firewall; quell'osservazione è l'attribution leak che un investigatore vedrebbe.

## Redirector tiers and traffic shaping

Un **redirector** pubblico accetta il traffico che corrisponde a una grammatica specifica dell'operazione e lo inoltra a un team server protetto. Tutto il resto può essere rifiutato o può ricevere contenuti innocui.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Più livelli limitano l'esposizione: bruciare un dominio pubblico non deve necessariamente esporre il team server. Le CDN aggiungono capacità anycast e un dominio esterno affidabile, ma l'account CDN e i log edge diventano punti di attribuzione. TLS fingerprint, cronologia dei certificati, percorsi distintivi/ordine degli header, dimensioni delle risposte, comportamento dei redirect e allowlist dell'origine possono raggruppare front apparentemente non correlati.

Per il rilevamento, registra i campi del reverse proxy prima della normalizzazione, confronta SNI/Host/authority, analizza combinazioni rare di header, raggruppa i response body e i TLS fingerprint e cerca sovrapposizioni di configurazione nei log di audit cloud/CDN. Per i red team autorizzati, evita di copiare un brand reale o di collocare la raccolta di credenziali dietro una terza parte non correlata.

## Domain fronting and domainless fronting

Con il **domain fronting (T1090.004)** classico, la connessione TLS pubblicizza un dominio front consentito in SNI, mentre l'HTTP `Host` crittografato o l'HTTP/2 `:authority` richiede un dominio back-end diverso. Una CDN collaborante instrada in base al valore interno. Un osservatore di rete privo di decrittazione TLS vede il front; la CDN vede entrambi i valori e l'origine. Nelle varianti domainless, SNI può essere vuoto mentre un altro campo di routing seleziona la destinazione.<sup>[[4]](#references)</sup>

Non si tratta di una magica impersonificazione: funziona solo quando l'intermediario consente intenzionalmente o accidentalmente la discrepanza e sa come instradare il nome interno. I principali provider hanno limitato il fronting tra account. Encrypted ClientHello (ECH) modifica ciò che un osservatore sul percorso può vedere, ma non elimina i record della CDN, dell'endpoint o dell'applicazione.

I punti di rilevamento includono:

- discendenza dei processi dell'endpoint e destinazione non prevista per quell'applicazione;
- discrepanza tra SNI e autorità HTTP, quando l'ispezione TLS è lecita e disponibile;
- log CDN che mostrano un tenant/front che instrada verso un'altra authority/origin;
- sessioni insolitamente longeve o periodiche verso un servizio normalmente interattivo;
- dimensioni e cadenza stabili dei flussi crittografati attraverso domini front variabili.

Il laboratorio sicuro simula la discrepanza di routing su un reverse proxy di proprietà; non abusa di una CDN pubblica.

## Dynamic resolution: DDNS, DGA and fast flux

La risoluzione dinamica separa un servizio logico dall'infrastruttura fissa:

- **DDNS:** un client autenticato aggiorna un nome stabile dopo la modifica del proprio indirizzo.
- **DGA:** endpoint e controller derivano entrambi domini candidati da un seed temporale/chiave; l'operatore registra un piccolo sottoinsieme.
- **Fast flux:** un nome restituisce un insieme in rapida variazione di indirizzi compromessi/proxy, spesso con TTL bassi.
- **Double flux:** ruotano sia gli indirizzi dei servizi sia quelli dei name server autorevoli, nascondendo anche il control layer.

Il fast flux è un pattern di distribuzione del carico usato in modo avversario, non semplicemente “molte risposte DNS”. Evidenze più solide combinano TTL bassi, un numero elevato di indirizzi unici, ampia dispersione di ASN/geografia, breve durata dei nodi, comportamento applicativo ripetuto e cronologia di registrazione sospetta. Le CDN condividono legittimamente diverse di queste proprietà. MITRE raccomanda di correlare il comportamento DNS con il processo e le connessioni successive.<sup>[[5]](#references)</sup>

Una DGA può essere rilevata tramite entropia lessicale, pattern di consonanti/cifre, raffiche di NXDOMAIN, domini sincronizzati visti per la prima volta e contesto del processo. Le DGA basate su wordlist e i modelli generativi eludono le semplici regole sull'entropia, rendendo più importante il clustering temporale a livello di flotta e la lineage degli endpoint.

## Compromised domains and domain shadowing

Un attore può dirottare un account registrar/DNS, prendere il controllo di un sottodominio abbandonato o aggiungere record sotto un dominio altrimenti affidabile. Il **domain shadowing** conserva l'apice legittimo mentre grandi quantità di sottodomini controllati dall'attaccante puntano verso host di delivery o C2 variabili. Sfrutta anzianità e reputazione e può eludere il blocco a livello di dominio.<sup>[[6]](#references)</sup>

I difensori necessitano di log di audit del registrar e del DNS autorevole, MFA, blocchi di registry/registrar, alert per nuove deleghe/token API/name server, monitoraggio della certificate transparency e un inventario delle risorse cloud referenziate dal DNS. Analizza la risoluzione e la cronologia dei certificati di un sottodominio indipendentemente dalla reputazione dell'apice.

## Web services and dead-drop resolvers

Un **dead-drop resolver (T1102.001)** memorizza un puntatore codificato al C2 corrente all'interno di un post, profilo, documento, repository, cloud object o campo blockchain legittimo. Il malware recupera l'oggetto pubblico, decodifica un dominio/IP e contatta lo stage successivo. Le varianti bidirezionali scambiano comandi o file tramite API dei servizi.<sup>[[7]](#references)</sup>

Questo offre resilienza e nasconde il C2 back-end dall'analisi statica del binario. Crea inoltre identificatori stabili di oggetti, tenant, repository, API e pattern di accesso. I difensori dovrebbero correlare:

1. il processo che ha contattato il servizio;
2. il percorso API/object esatto e l'hash della risposta;
3. l'attività di decodifica o di elaborazione delle stringhe;
4. la nuova connessione in uscita poco dopo; e
5. il comportamento identico altrove nella flotta.

Bloccare tutti i GitHub, cloud storage o social media è raramente praticabile. Una policy di egress consapevole del servizio e la correlazione a livello di processo sono più efficaci del blocco basato solo sul dominio.

## Personas, accounts and procurement compartments

L'anonimato dell'infrastruttura fallisce quando una persona, un'email di recupero, un telefono, un pagamento, un browser o un IP amministrativo collega i compartimenti. Le operazioni legate a uno Stato hanno coltivato profili social, identità email e account cloud molto prima dell'utilizzo; ATT&CK lo registra come Establish Accounts (T1585), incluse le sotto-tecniche social, email e cloud.<sup>[[8]](#references)</sup>

Un difensore o investigatore costruisce un grafo a partire da:

- orario di creazione e primo login, impostazioni locali, fuso orario e calendario operativo;
- campi di recupero, dispositivi MFA, documenti d'identità e strumenti di pagamento;
- fingerprint del browser/TLS e cronologia della rete sorgente;
- riutilizzo dell'avatar, provenienza delle immagini, stile di scrittura e crescita del grafo sociale;
- registrante del dominio, name server, certificato, ID analytics o commit del repository condivisi;
- azioni del management plane che aggirano l'architettura pubblica del relay.

Per un red team autorizzato, le personas sintetiche devono essere documentate presso il responsabile dell'esercitazione, usare canali di recupero/pagamento di proprietà dell'organizzazione, evitare di impersonare persone reali non coinvolte e prevedere una dismissione pianificata. Il SOC può rimanere cieco; l'operazione non deve diventare irresponsabile.

## Emerging compound patterns to threat-model

Le seguenti sono **composizioni guidate dal difensore**, non affermazioni secondo cui un attore specifico abbia implementato ciascun design esatto. Combinano primitive già osservate e sono utili come ipotesi di purple team.

### Asymmetric one-way tasking

I comandi arrivano tramite una fonte pubblica, broadcast o append-only, mentre i risultati escono attraverso un canale non correlato dopo un ritardo. Esempi della primitiva includono la comunicazione unidirezionale tramite web service e i dead drop. La separazione impedisce che un singolo flusso appaia bidirezionale e ostacola la semplice correlazione request/response.<sup>[[9]](#references)</sup>

**Rilevamento:** conserva le letture a livello di oggetto, quindi correla i cambiamenti dello stato del processo e i successivi trasferimenti in uscita su una finestra temporale più ampia. Cerca un processo raro che legga lo stesso oggetto pubblico anche quando non segue una risposta immediata.

### Multi-stage channel promotion

Un primo stage silenzioso esegue l'inventario e promuove solo i sistemi selezionati a un canale di secondo stage non correlato. Il secondo endpoint, protocollo e processo possono non condividere alcuna infrastruttura con il primo. Ciò limita l'esposizione dell'infrastruttura capace ed è esplicitamente modellato come ATT&CK T1104.<sup>[[10]](#references)</sup>

**Rilevamento:** collega `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; non chiudere l'incidente dopo aver bloccato il primo dominio.

### Cross-protocol relay translation

Hop diversi traducono HTTPS, QUIC, WebSocket, DNS, SSH o un'API message-queue invece di inoltrare trasparentemente i pacchetti. La traduzione rimuove un singolo fingerprint di protocollo end-to-end, ma crea gateway con timing, buffering e conversione semantica distintivi. Il protocol tunneling (T1572) può essere combinato con proxy e service impersonation.<sup>[[11]](#references)</sup>

**Rilevamento:** cerca host gateway che ricevono un protocollo e ne avviano un altro con comportamento byte/time strettamente correlato; confronta l'intento dell'endpoint con il protocollo effettivamente trasportato.

### Passive activation on edge devices

Invece di effettuare beaconing, un implant monitora il traffico già diretto a un router/VPN e si attiva solo in presenza di un valore magico, di un pattern di source-port o di un token autenticato. Il traffico normale continua verso il servizio reale. ATT&CK lo definisce Traffic Signaling (T1205), con esempi documentati su dispositivi di rete e APT.<sup>[[12]](#references)</sup>

**Rilevamento:** integrità del firmware/file, cattura dei pacchetti raw durante un hunt autorizzato, socket filter inattesi e comportamento differenziale del servizio. L'assenza di un beacon periodico non dimostra che un edge device sia pulito.

### Serverless and ephemeral origin rotation

Un front mantiene un'identità logica stabile mentre funzioni/container di breve durata gestiscono i singoli stage in diverse regioni/account. Ciò riduce la durata su disco e gli IP origin fissi, ma la creazione nel control plane, l'immagine/layer, il ruolo, il secret, il request ID e la telemetria di billing diventano il grafo persistente.

**Rilevamento:** conserva i log di audit e di invocazione cloud al di fuori del workload; raggruppa template di deployment, ruoli, chiavi d'ambiente e relazioni front-to-origin.

### Privacy-layer diversity

Un'operazione può evitare deliberatamente una singola catena omogenea: per esempio, un canale usa un relay in leasing, il tasking usa un oggetto pubblico, l'uscita proviene da un collegamento cellulare di laboratorio di proprietà e l'amministrazione usa una rete separata dell'organizzazione. Ciò riduce il valore della compromissione di un singolo provider, ma aumenta i rischi di correlazione temporale tra i layer e di errori operativi.

**Rilevamento:** costruisci timeline della campagna attraverso sensori di identità, DNS, SaaS, rete e cloud. Cerca transizioni di stato sincronizzate invece di indicatori identici.

### Decentralized or transparency-log dead drops

Un attore può collocare un piccolo puntatore crittografato in qualsiasi sistema pubblico durevole append-only, content-addressed store o feed simile a una transparency log. L'oggetto pubblico è resiliente, ma il suo indice esatto/hash del contenuto e il comportamento di polling del client diventano identificatori stabili.

**Rilevamento:** registra identificatori completi di API/oggetti e hash delle risposte; genera alert per processi non standard che effettuano il polling di oggetti immutabili seguito da decodifica o nuove connessioni.

### Delayed store-and-forward operations

Il C2 interattivo crea una forte correlazione temporale. Un design store-and-forward raggruppa job crittografati e restituisce i risultati dopo minuti od ore tramite una coda diversa o un trasferimento fisico. Sacrifica la reattività per ottenere una correlazione temporale end-to-end più debole.

**Rilevamento:** estendi le finestre di correlazione, modella l'accesso periodico alle code ed esamina lo staging degli endpoint. Il batching sposta il segnale dal timing dei pacchetti al comportamento pianificato di processi/file; non lo elimina.

## Design review: think in observers

Per ogni percorso, compila questa tabella prima del deployment e dopo la raccolta:

| Layer | Vede la sorgente? | Vede la destinazione? | Vede il contenuto? | Identificatori stabili | Responsabile della conservazione/aspetti legali |
|---|---:|---:|---:|---|---|
| rete locale/carrier | | | | | |
| servizio di ingresso/accesso | | | | | |
| operatori di traversal | | | | | |
| uscita/redirector/CDN | | | | | |
| DNS autorevole/registrar | | | | | |
| target | | | | | |
| provider dell'account/pagamento | | | | | |

Se un singolo provider ordinario può compilare ogni colonna, l'architettura offre occultamento rispetto al target, ma non una separazione robusta. Se nessun controller interno può ricondurre l'attività a un engagement, non è adatta al red teaming professionale.

## References

- [1] [MITRE ATT&CK — Acquisizione dell'infrastruttura (T1583), compromissione dell'infrastruttura (T1584) e Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Gli attori di spionaggio legati alla Cina usano reti ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromissione dell'infrastruttura: domini (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: comunicazione unidirezionale (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Interrompere la più grande rete mondiale di proxy residenziali](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Le campagne Shadow: alla scoperta dello spionaggio globale](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
{{#include ../banners/hacktricks-training.md}}
