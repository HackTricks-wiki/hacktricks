# Infrastruttura offensiva ed evasione dell'attribuzione

{{#include ../banners/hacktricks-training.md}}

Un operatore raramente ottiene un anonimato significativo usando un solo proxy. Le campagne reali creano un **grafo di separazione**: l'operatore raggiunge un nodo di accesso, i nodi di transito nascondono quel nodo al nodo di uscita, i redirector proteggono il vero C2 e nomi usa e getta puntano al bordo pubblico.

Consulta il [Catalogo delle tecniche di accesso anonimo a Internet](anonymous-internet-access-techniques.md) per una panoramica uniforme di vantaggi, svantaggi, distribuzione e rilevamento di ogni percorso. Questa pagina approfondisce la composizione di infrastrutture avversarie.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

L'ultimo indirizzo visto dal target è quindi una prova del percorso, non della persona che controllava la tastiera. MITRE mappa i componenti principali su Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) e Web Service (T1102).<sup>[[1]](#references)</sup>

## Classi di infrastruttura

| Classe | Perché un attore la usa | Esposizione persistente | Miglior punto di pivot per i defender |
|---|---|---|---|
| VPS/cloud a noleggio | Rapido, prevedibile, instradabile, facile da ricreare | tenant, fatturazione, console, cronologia degli accessi di origine e delle immagini | eventi dell'account/control plane e fingerprint del server ricorrente |
| VPN commerciale/Tor | Ampio insieme di egress condivisi; nessuna amministrazione del server | visibilità del provider/guard e timing end-to-end | comportamento verso la destinazione, evidenze sugli endpoint e correlazione dei flussi |
| Proxy residenziale/mobile | ASN consumer e plausibilità geografica | registri di broker/clienti; comportamento di proxyware o host infetti | spostamenti impossibili, protocolli proxy e variazione degli indirizzi per sessione |
| Server/router/IoT compromessi | Sfrutta la reputazione e la giurisdizione della vittima | impianto, flusso di gestione e controller upstream ricorrente | telemetria dei dispositivi e topologia ORB, non un singolo IP di uscita |
| CDN/redirector | Separa l'edge pubblico dal C2 back-end | grammatica TLS/HTTP, certificato, routing e artefatti dell'account cloud | correlazione edge-origin e clustering della forma delle richieste |
| Servizio web legittimo | Si confonde con il traffico consentito di GitHub/cloud/social | token API, identificatori di tenant/oggetto e lineage insolito dei processi | processo sull'endpoint e semantica del servizio/API |
| Percorso fisico/cellulare/satellitare | Cambia l'origine fisica apparente | registri RF, dell'operatore, dell'abbonato, del dispositivo e della posizione | evidenze radio/fisiche e di rete combinate |

## Reti operative di nodi relay

Una **rete ORB** è una flotta di proxy gestita e utilizzata come servizio intermedio. Mandiant le suddivide in reti provisioned, composte da server in leasing, reti non-provisioned, composte da router/IoT compromessi, e reti ibride. Una topologia matura ha quattro ruoli logici:<sup>[[2]](#references)</sup>

1. **Server di amministrazione (ACOS):** mantiene inventario, credenziali, stato e policy di routing.
2. **Nodo di accesso/relay:** autentica clienti o operatori; è il punto di ingresso stabile verso una mesh in evoluzione.
3. **Nodi di transito:** uno o più sistemi in leasing o compromessi inoltrano connessioni opache.
4. **Nodo di uscita/staging:** presenta l'indirizzo sorgente finale ai target di ricognizione, exploitation o C2.

La mesh può selezionare le uscite in base a paese, ASN, latenza o disponibilità e sostituire i nodi non funzionanti. Più gruppi di minacce possono noleggiare la stessa rete. Mandiant ha osservato che alcuni indirizzi IPv4 restavano associati a determinate ORB per appena 31 giorni; raccomanda quindi di considerare la **rete come un'entità in evoluzione simile a un attore**, anziché bloccare un elenco obsoleto di IP.<sup>[[2]](#references)</sup>

### Cosa offre e cosa leaks

- Il target vede un'uscita che può trovarsi geograficamente vicino e apparire residenziale.
- L'uscita vede il target e l'hop precedente, ma non necessariamente l'operatore.
- Il servizio di accesso vede il cliente e la richiesta di percorso. Una mesh gestita in modo indipendente può mantenere il cliente separato dalle uscite, ma crea un potente archivio per la controparte.
- Porte ricorrenti, ordine degli handshake, banner dei server, certificati, finestre di uptime e relazioni tra controller possono rivelare la flotta anche quando gli IP ruotano.
- Un router compromesso spesso non dispone di telemetria degli endpoint, ma il suo ISP conserva comunque dati sugli abbonati e sui flussi; un sequestro rivela artefatti dell'impianto/configurazione.

{% hint style="info" %}
Per un'esercitazione autorizzata, riproduci la topologia con VM o router di proprietà dell'organizzazione e conserva la mappa di attribuzione del controller. Non reclutare proxy aperti o dispositivi di terze parti. La [guida al lab](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) crea la stessa struttura di hop visibile ai defender senza vittimizzare un intermediario.
{% endhint %}

## Reti di proxy residenziali e mobili

I servizi di proxy residenziali assegnano le sessioni a indirizzi di connessioni broadband consumer; i proxy mobili escono attraverso pool NAT degli operatori. Le risorse possono provenire da appliance con adesione esplicita, SDK/proxyware inclusi in applicazioni consumer, rivenditori o malware. Queste origini non sono equivalenti: senza consenso informato, un servizio per la privacy diventa infrastruttura compromessa.

Le modalità di rotazione influiscono sul rilevamento:

- la **rotazione per richiesta** produce rapide discontinuità di IP e ASN/area geografica, mentre l'identità ai livelli superiori resta stabile;
- le **sessioni sticky** mantengono un'uscita per minuti o ore, somigliando a un normale abbonato;
- i **gateway backconnect** espongono al cliente un singolo endpoint del broker e scelgono internamente le uscite;
- i **pool mobili** collocano molti abbonati reali dietro un numero ridotto di indirizzi NAT dell'operatore, rendendo costoso bloccare un IP.

I defender dovrebbero correlare l'IP con la sessione autenticata, il fingerprint TLS/client, l'ordine HTTP, il cookie del dispositivo e il comportamento. Un accesso residenziale apparentemente locale, seguito da un accesso da un altro paese mentre tutte le caratteristiche ai livelli superiori restano identiche, è un indicatore più forte della sola reputazione. Al contrario, la condivisione degli indirizzi e il passaggio tra celle mobili causano variazioni legittime: non considerare mai la classificazione residenziale/proxy come una sentenza.

### Control plane di proxyware e sovrapposizione tra rivenditori

Non modellare un pool residenziale come un semplice elenco di uscite. L'analisi dell'ecosistema IPIDEA ha rivelato un **control plane a due livelli** riutilizzabile: un SDK incorporato invia prima i metadati del dispositivo/registrazione a un dominio Tier One e riceve coppie IP:porta per la pianificazione e le operazioni `connect`/`proxy` di Tier Two. Il nodo interroga periodicamente la porta connect di Tier Two per ricevere un task codificato, apre una seconda connessione alla porta proxy associata e inoltra i byte forniti verso la destinazione richiesta. SDK e brand di proxy nominalmente diversi avevano domini di discovery separati, ma convergevanо su infrastrutture Tier Two condivise e pool di uscita sovrapposti tramite proprietà comune e relazioni tra rivenditori.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Questo produce pivot di hunting più duraturi rispetto a un blocco di IP residenziali:<sup>[[13]](#references)</sup>

- un processo inatteso di utility, VPN, gioco o dispositivo embedded invia un ID dispositivo/chiave cliente stabile e riceve un elenco di server variabile;
- l'endpoint interroga un IP diretto su una porta insolita, poi si connette a un'altra porta sullo stesso indirizzo immediatamente prima di aprire un socket verso una nuova destinazione;
- diversi brand apparenti condividono indirizzi Tier Two, grammatica di protocollo, codice SDK o sovrapposizioni tra exit node;
- applicazioni distinte che contattano domini Tier One diversi ricevono indirizzi dallo stesso pool Tier Two.

La sovrapposizione limita anche l'attribuzione: vedere un IP nel pool pubblicizzato di un vendor non dimostra quale reseller, cliente o threat actor lo abbia usato nel momento rilevante. Conservate timestamp dei flussi, lineage dei processi, corpi delle risposte Tier One e identificatori delle task Tier Two.<sup>[[13]](#references)</sup> In un'esercitazione autorizzata, emulate questa gerarchia solo con endpoint di proprietà dell'organizzazione; non arruolate mai dispositivi consumer o proxyware di terze parti.

## Catene di proxy multi-hop

MITRE distingue i proxy esterni dai **proxy multi-hop (T1090.003)**. La proprietà importante non è il numero di hop, ma la separazione di conoscenze e amministrazione.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Se una parte gestisce A e B, i log condivisi o la temporizzazione dei flussi possono consentire di ricostruire il circuito. Aggiungere VPN commerciali in sequenza dallo stesso endpoint/account può aumentare la latenza, lasciando però tracce comuni di identità, pagamento e temporizzazione. Tor riduce questo problema usando relay selezionati in modo indipendente e un design client condiviso, ma una rete interattiva a bassa latenza non può garantire protezione contro un osservatore che misura entrambe le estremità.

Tra i guasti più comuni ci sono bypass DNS o IPv6, applicazioni che aprono socket propri, traffico di gestione diretto ai relay, attività sincronizzate, chiavi SSH riutilizzate e accessi ad account identificativi. La verifica corretta è un test di guasto: arrestare ogni relay a turno e dimostrare che il carico di lavoro non può ripiegare su un percorso in chiaro.

### Collasso del tunnel e leak a monte

Un’architettura a relay è spesso più facile da attribuire quando si guasta. Unit 42 ha documentato un percorso di spionaggio a più livelli che usava VPS esposti alle vittime, VPS relay, proxy residenziali, Tor e altri servizi proxy; quando un tunnel veniva omesso o collassava, l’infrastruttura nascosta a monte si collegava direttamente ai sistemi relay e a quelli esposti alle vittime. La stessa indagine ha anche usato un certificato X.509 esposto brevemente sull’infrastruttura a monte come pivot tra livelli.<sup>[[14]](#references)</sup>

Mantieni separati il **piano dati** (`victim <-> exit`) e il **piano di controllo** (`operator/upstream -> relay administration`). Conserva i log di ingresso e autenticazione in ogni livello sotto il tuo controllo, le cronologie dei certificati e le connessioni brevi non riuscite, non solo le sessioni C2 riuscite. Una sorgente che compare solo durante le interruzioni dei relay o amministra direttamente più nodi esposti alle vittime è una candidata a infrastruttura a monte più probabile di un normale exit, ma il suo ASN/geolocalizzazione resta un’ipotesi, non una prova dell’identità dell’operatore.

In un lab autorizzato, il carico di lavoro dovrebbe fallire in modo chiuso. Per un carico di lavoro isolato in un namespace di rete Linux, la prima route deve usare il tunnel; dopo averlo rimosso, sia la richiesta sia la ricerca della route devono fallire, invece di selezionare l’interfaccia fisica verso l’esterno:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Ripeti il test per DNS e IPv6 e a ogni confine del relay. Se una qualsiasi sonda ha esito positivo, registra l’interfaccia/l’indirizzo sorgente effettivo prima di correggere il policy routing o il firewall: è il leak di attribuzione che un investigatore vedrebbe.

## Livelli dei redirector e modellazione del traffico

Un **redirector** pubblico accetta il traffico conforme a una grammatica specifica per l’operazione e lo inoltra a un team server protetto. Tutto il resto può essere rifiutato o ricevere contenuti innocui.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Più livelli limitano l’esposizione: sacrificare un dominio pubblico non deve necessariamente esporre il team server. Le CDN aggiungono capacità anycast e un dominio esterno affidabile, ma l’account CDN e i log edge diventano punti di attribuzione. Le fingerprint TLS, la cronologia dei certificati, i percorsi distintivi, l’ordine degli header, le dimensioni delle risposte, il comportamento dei redirect e le allowlist dell’origine possono raggruppare front apparentemente non correlati.

Per il rilevamento, registra i campi del reverse proxy prima della normalizzazione, confronta SNI/Host/authority, esamina combinazioni di header rare, raggruppa i corpi delle risposte e le fingerprint TLS e cerca sovrapposizioni di configurazione nei log di audit cloud/CDN. Nei red team autorizzati, evita di copiare un brand reale o di raccogliere credenziali tramite una terza parte non correlata.

## Domain fronting e domainless fronting

Con il **domain fronting (T1090.004)** classico, la connessione TLS indica nel SNI un front domain consentito, mentre l’`Host` HTTP cifrato o `:authority` HTTP/2 richiede un dominio back-end diverso. Una CDN collaborativa instrada il traffico in base al valore interno. Un osservatore di rete privo di decrittazione TLS vede il front; la CDN vede entrambi i valori e l’origine. Nelle varianti domainless, il SNI può essere vuoto mentre un altro campo di routing seleziona la destinazione.<sup>[[4]](#references)</sup>

Non è un’impersonificazione magica: funziona solo se l’intermediario consente intenzionalmente o accidentalmente la discrepanza e sa come instradare il nome interno. I principali provider hanno limitato il fronting tra account diversi. Encrypted ClientHello (ECH) modifica ciò che può vedere un osservatore sul percorso, ma non cancella i record della CDN, dell’endpoint o dell’applicazione.

I punti di rilevamento includono:

- l’ascendenza dei processi sull’endpoint e una destinazione non prevista per quell’applicazione;
- la discrepanza tra SNI e authority HTTP, quando l’ispezione TLS è legale e disponibile;
- i log CDN che mostrano un tenant/front instradare il traffico verso un’altra authority/origine;
- sessioni insolitamente lunghe o periodiche verso un servizio normalmente interattivo;
- dimensioni e cadenza stabili dei flussi cifrati mentre cambiano i front domain.

Il lab sicuro simula la discrepanza di routing su un reverse proxy di proprietà; non abusa di una CDN pubblica.

## Risoluzione dinamica: DDNS, DGA e fast flux

La risoluzione dinamica disaccoppia un servizio logico da un’infrastruttura fissa:

- **DDNS:** un client autenticato aggiorna un nome stabile dopo il cambio del proprio indirizzo.
- **DGA:** endpoint e controller derivano entrambi nomi di dominio candidati da un seed temporale/chiave; l’operatore ne registra un piccolo sottoinsieme.
- **Fast flux:** un nome restituisce un insieme di indirizzi compromessi/proxy che cambia rapidamente, spesso con TTL bassi.
- **Double flux:** ruotano sia gli indirizzi dei servizi sia quelli dei name server autorevoli, nascondendo anche il livello di controllo.

Il fast flux è un modello di distribuzione del carico usato a fini avversari, non semplicemente «molte risposte DNS». Le prove più solide combinano TTL bassi, un elevato numero di indirizzi univoci, ampia dispersione tra ASN e aree geografiche, breve durata dei nodi, comportamento applicativo ripetuto e cronologia di registrazione sospetta. Le CDN presentano legittimamente diverse di queste caratteristiche. MITRE consiglia di correlare il comportamento DNS con il processo e le connessioni successive.<sup>[[5]](#references)</sup>

Una DGA può essere rilevata tramite entropia lessicale, schemi di consonanti/cifre, picchi di NXDOMAIN, domini comparsi per la prima volta in modo sincronizzato e contesto del processo. Le DGA basate su wordlist e i modelli generativi eludono le semplici regole basate sull’entropia, rendendo più importanti il clustering temporale a livello di flotta e la lineage degli endpoint.

## Domini compromessi e domain shadowing

Un attore può dirottare un account registrar/DNS, assumere il controllo di un sottodominio abbandonato o aggiungere record sotto un dominio altrimenti affidabile. Il **domain shadowing** mantiene legittimo il dominio apex, mentre un gran numero di sottodomini controllati dall’attaccante punta a host di delivery o C2 variabili. Sfrutta anzianità e reputazione e può eludere il blocco dell’intero dominio.<sup>[[6]](#references)</sup>

I difensori hanno bisogno dei log di audit del registrar e del DNS autorevole, MFA, blocchi a livello di registry/registrar, avvisi per nuove deleghe/token API/name server, monitoraggio della Certificate Transparency e un inventario delle risorse cloud a cui fa riferimento il DNS. Esamina la risoluzione e la cronologia dei certificati di un sottodominio indipendentemente dalla reputazione del dominio apex.

## Web service e dead-drop resolver

Un **dead-drop resolver (T1102.001)** memorizza un puntatore codificato al C2 corrente in un post, profilo, documento, repository, oggetto cloud o campo blockchain legittimo. Il malware recupera l’oggetto pubblico, decodifica un dominio/IP e contatta lo stage successivo. Le varianti bidirezionali scambiano comandi o file tramite le API dei servizi.<sup>[[7]](#references)</sup>

Una variante di resolver specifica per GitHub usa la Search API di Issues solo quando un canale repository autenticato non è disponibile. Il client cerca issue corrispondenti alla data corrente, al repository e al tipo di issue, segue l’URL dei commenti di ogni issue ed estrae il ciphertext tra i marcatori `<!--` e `-->`. Dopo la decrittazione derivata per host e data, campi come `Owner`, `LicRepo` e `LicToken` sostituiscono rispettivamente il proprietario, il percorso e il token del repository primario. Ciò consente all’operatore di ruotare credenziali ed endpoint senza sostituire il client; il commento dell’issue funge da resolver, mentre i file del repository rimangono il canale di tasking.<sup>[[15]](#references)</sup>

Una variante Android seleziona all’avvio una di due pagine pubbliche di Telegram ed estrae il ciphertext tra due occorrenze di un marcatore incorporato nell’APK. Decodifica il valore con Base64URL e lo decritta con AES-128-CBC: i primi 16 byte di `SHA-256(marker)` costituiscono la chiave e i successivi 16 byte l’IV. Il testo in chiaro è l’URL base C2 effettivo, non l’URL della pagina Telegram. Quando si riproduce la risoluzione, conserva il contenuto della pagina e il marcatore esatto; modificare la pagina pubblica ruota l’endpoint senza dover ricompilare l’APK.<sup>[[16]](#references)</sup>

Questo offre resilienza e nasconde il C2 back-end dall’analisi statica dei binari. Crea anche identificatori stabili per oggetti, tenant, repository, API e schemi di accesso. I difensori dovrebbero correlare:

1. il processo che ha contattato il servizio;
2. il percorso API/oggetto esatto e l’hash della risposta;
3. l’attività di decodifica o elaborazione delle stringhe;
4. la nuova connessione in uscita poco dopo; e
5. lo stesso comportamento altrove nella flotta.

Bloccare GitHub, il cloud storage o i social media nella loro interezza è raramente praticabile. Le policy di egress consapevoli del servizio e la correlazione a livello di processo sono più efficaci del solo blocco dei domini.

## Persona, account e compartimenti di approvvigionamento

L’anonimato dell’infrastruttura viene meno quando una persona, un’e-mail di recupero, un numero di telefono, un pagamento, un browser o un IP amministrativo collega compartimenti diversi. Le operazioni legate a Stati hanno creato profili social, identità e-mail e account cloud molto prima di usarli; ATT&CK registra questa attività come Establish Accounts (T1585), incluse le sottotecniche relative ai social media, all’e-mail e al cloud.<sup>[[8]](#references)</sup>

Un difensore o investigatore costruisce un grafo a partire da:

- orario di creazione e del primo accesso, impostazioni locali, fuso orario e orari di attività;
- dati di recupero, dispositivi MFA, documenti d’identità e strumenti di pagamento;
- fingerprint di browser/TLS e cronologia delle reti di origine;
- riutilizzo dell’avatar, provenienza delle immagini, stile di scrittura e crescita del grafo sociale;
- registrante di dominio, name server, certificato, ID di analytics o commit del repository condivisi;
- azioni del piano di gestione che aggirano l’architettura dei relay pubblici.

Per un red team autorizzato, le persone sintetiche devono essere documentate per il responsabile dell’esercitazione, usare canali di recupero/pagamento di proprietà dell’organizzazione, evitare di impersonare persone reali estranee all’attività e avere una procedura di dismissione pianificata. Il SOC può restare all’oscuro; l’operazione non deve diventare priva di responsabilità.

## Schemi composti emergenti da includere nel threat modeling

Quelli che seguono sono **combinazioni formulate per i difensori**, non affermazioni secondo cui un attore identificato abbia implementato ciascun progetto esatto. Combinano primitive già osservate e sono utili come ipotesi per esercitazioni purple team.

### Tasking unidirezionale asimmetrico

I comandi arrivano tramite una fonte pubblica, broadcast o append-only, mentre i risultati escono tramite un canale non correlato dopo un ritardo. Tra gli esempi delle primitive vi sono la comunicazione unidirezionale tramite web service e i dead drop. La separazione impedisce a un singolo flusso di apparire bidirezionale e ostacola la semplice correlazione richiesta/risposta.<sup>[[9]](#references)</sup>

**Rilevamento:** conserva le letture a livello di oggetto, quindi correla le modifiche di stato del processo e i successivi trasferimenti in uscita su una finestra temporale più ampia. Cerca processi rari che leggono lo stesso oggetto pubblico anche quando non segue alcuna risposta immediata.

### Promozione del canale in più fasi

Un primo stage discreto esegue un inventario e promuove solo i sistemi selezionati a un canale di secondo stage non correlato. Il secondo endpoint, protocollo e processo potrebbero non condividere alcuna infrastruttura con il primo. Ciò limita l’esposizione dell’infrastruttura più capace ed è modellato esplicitamente da ATT&CK come T1104.<sup>[[10]](#references)</sup>

**Rilevamento:** correla `primo processo di rete -> stato scaricato/configurato -> nuovo processo o injection -> destinazione non correlata`; non chiudere l’incidente dopo aver bloccato il primo dominio.

### Traduzione relay cross-protocol

Hop diversi traducono HTTPS, QUIC, WebSocket, DNS, SSH o un’API di message queue, anziché inoltrare i pacchetti in modo trasparente. La traduzione elimina una singola fingerprint end-to-end del protocollo, ma crea gateway con tempistiche, buffering e conversione semantica distintivi. Il protocol tunneling (T1572) può essere combinato con proxy e service impersonation.<sup>[[11]](#references)</sup>

**Rilevamento:** cerca host gateway che ricevono un protocollo e ne avviano un altro con un comportamento di byte/tempo strettamente correlato; confronta l’intento dell’endpoint con il protocollo effettivamente trasportato.

### Attivazione passiva sui dispositivi edge

Invece di inviare beacon, un implant monitora il traffico che raggiunge già un router/VPN e si attiva solo in presenza di un valore magico, uno schema di porte sorgente o un token autenticato. Il traffico normale continua a raggiungere il servizio reale. ATT&CK definisce questa tecnica Traffic Signaling (T1205) e documenta esempi relativi a dispositivi di rete e APT.<sup>[[12]](#references)</sup>

**Rilevamento:** integrità di firmware/file, packet capture grezzo durante un hunt autorizzato, filtri socket inattesi e comportamento differenziale del servizio. L’assenza di un beacon periodico non dimostra che un dispositivo edge sia pulito.

### Rotazione di origini serverless ed effimere

Un front mantiene un’identità logica stabile, mentre funzioni/container di breve durata gestiscono singoli stage in più regioni/account. Ciò riduce la permanenza su disco e il numero di IP di origine fissi, ma i dati telemetrici di creazione nel piano di controllo, immagini/layer, ruoli, secret, request ID e fatturazione diventano il grafo persistente.

**Rilevamento:** conserva i log di audit cloud e di invocazione al di fuori del workload; raggruppa i template di deployment, i ruoli, le chiavi di ambiente e le relazioni front-origine.

### Diversità dei livelli di privacy

Un’operazione può evitare deliberatamente una catena omogenea: per esempio, un canale usa un relay noleggiato, il tasking usa un oggetto pubblico, un’uscita proviene da un collegamento cellulare di lab di proprietà e l’amministrazione usa una rete separata dell’organizzazione. Questo riduce il valore della compromissione di un singolo provider, ma aumenta il rischio di correlazione temporale tra livelli e di errori operativi.

**Rilevamento:** crea timeline della campagna attraverso i sensori di identità, DNS, SaaS, rete e cloud. Cerca transizioni di stato sincronizzate invece di indicatori identici.

### Dead drop decentralizzati o basati su transparency log

Un attore può inserire un piccolo puntatore cifrato in qualsiasi sistema pubblico persistente append-only, store content-addressed o feed simile a un transparency log. L’oggetto pubblico è resiliente, ma il suo indice/hash del contenuto esatto e il comportamento di polling del client diventano identificatori stabili.

**Rilevamento:** registra gli identificatori completi di API/oggetto e gli hash delle risposte; genera avvisi quando processi non standard interrogano oggetti immutabili e poi eseguono decodifica o avviano nuove connessioni.

### Operazioni store-and-forward ritardate

Il C2 interattivo crea una forte correlazione temporale. Un modello store-and-forward raggruppa job cifrati e restituisce i risultati dopo minuti o ore tramite una coda diversa o un trasferimento fisico. Sacrifica la reattività per ridurre la correlazione temporale end-to-end.

**Rilevamento:** estendi le finestre di correlazione, modella gli accessi periodici alle code ed esamina lo staging sugli endpoint. Il batching sposta il segnale dalla temporizzazione dei pacchetti al comportamento pianificato di processi/file; non lo cancella.

## Revisione del design: ragiona in termini di osservatori

Per ogni percorso, compila questa tabella prima del deployment e dopo la raccolta:

| Livello | Vede la sorgente? | Vede la destinazione? | Vede il contenuto? | Identificatori stabili | Conservazione/titolare legale |
|---|---:|---:|---:|---|---|
| rete locale/operatore | | | | | |
| servizio di ingresso/accesso | | | | | |
| operatore/i di transito | | | | | |
| uscita/redirector/CDN | | | | | |
| DNS autorevole/registrar | | | | | |
| target | | | | | |
| provider dell’account/dei pagamenti | | | | | |

Se un singolo provider ordinario può compilare ogni colonna, l’architettura nasconde l’attività al target, ma non offre una separazione solida. Se nessun responsabile interno può ricondurre l’attività a un incarico, l’architettura non è adatta a un red team professionale.

## References

- [1] [MITRE ATT&CK — Acquisizione di infrastruttura (T1583), compromissione di infrastruttura (T1584) e proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Attori di spionaggio legati alla Cina usano reti ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Proxy multi-hop (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromissione dell’infrastruttura: domini (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web service: dead-drop resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Creazione di account (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web service: comunicazione unidirezionale (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Canali multi-stage (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Interruzione della più grande rete proxy residenziale al mondo](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Le campagne Shadow: alla scoperta dello spionaggio globale](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - La campagna Blinder Tunnel prende di mira le infrastrutture irachene](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: l’AI ha creato gli overlay. Le vittime perdono i PIN](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
{{#include ../banners/hacktricks-training.md}}
