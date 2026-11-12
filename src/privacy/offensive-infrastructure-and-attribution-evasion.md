# Infrastruttura offensiva ed evasione dell’attribuzione

{{#include ../banners/hacktricks-training.md}}

Un operatore raramente ottiene un anonimato significativo usando un solo proxy. Le campagne reali costruiscono un **grafo di separazione**: l’operatore raggiunge un nodo di accesso, i nodi di transito nascondono quel nodo all’exit, i redirector proteggono il vero C2 e i nomi usa e getta puntano al perimetro pubblico.

Consulta il [Catalogo delle tecniche di accesso anonimo a Internet](anonymous-internet-access-techniques.md) per una panoramica standardizzata di vantaggi, svantaggi, distribuzione e rilevamento di ogni percorso. Questa pagina approfondisce la composizione dell’infrastruttura avversaria.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

L'ultimo indirizzo visto da un bersaglio è quindi una prova del percorso, non della persona che ha controllato la tastiera. MITRE associa i componenti principali a Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) e Web Service (T1102).<sup>[[1]](#references)</sup>

## Classi di infrastruttura

| Classe | Perché un attore la usa | Esposizione persistente | Migliore pivot per i defender |
|---|---|---|---|
| VPS/cloud a noleggio | Rapido, prevedibile, instradabile, facile da ricreare | tenant, fatturazione, console, cronologia degli accessi e delle immagini | eventi dell'account/control plane e fingerprint del server ripetuti |
| VPN commerciale/Tor | Ampio insieme di egress condivisi; nessuna amministrazione del server | visibilità del provider/guard e temporizzazione end-to-end | comportamento verso la destinazione, prove sull'endpoint e correlazione dei flussi |
| Proxy residenziale/mobile | ASN consumer e plausibilità geografica | registri del broker/cliente; comportamento di proxyware o host infetto | spostamenti impossibili, protocolli proxy e variazioni degli indirizzi per sessione |
| Server/router/IoT compromesso | Sfrutta la reputazione e la giurisdizione della vittima | implant, flussi di gestione e controller upstream ricorrente | telemetria del dispositivo e topologia ORB, non un singolo IP di uscita |
| CDN/redirector | Separa l'edge pubblico dal C2 back-end | grammatica TLS/HTTP, certificato, routing e artefatti dell'account cloud | correlazione tra edge e origin e clustering della forma delle richieste |
| Servizio web legittimo | Si confonde con il traffico consentito verso GitHub/cloud/social | token API, identificatori di tenant/oggetto e lineage anomala dei processi | processo sull'endpoint più semantica del servizio/API |
| Percorso fisico/cellulare/satellitare | Modifica l'origine fisica apparente | registri RF, dell'operatore, dell'abbonato, del dispositivo e della posizione | prove radio/fisiche e di rete combinate |

## Reti di relay box operative

Una **rete ORB** è una flotta di proxy gestita e usata come servizio intermediario. Mandiant le suddivide in reti provisioned di server a noleggio, reti non-provisioned di router/IoT compromessi e reti ibride. Una topologia matura ha quattro ruoli logici:<sup>[[2]](#references)</sup>

1. **Server di amministrazione (ACOS):** gestisce inventario, credenziali, stato e policy di routing.
2. **Nodo di accesso/relay:** autentica i clienti o gli operatori; è l'ingresso stabile verso una mesh in evoluzione.
3. **Nodi di transito:** uno o più sistemi a noleggio o compromessi inoltrano connessioni opache.
4. **Nodo di uscita/staging:** presenta l'indirizzo sorgente finale ai target di ricognizione, exploitation o C2.

La mesh può selezionare le uscite per paese, ASN, latenza o disponibilità e sostituire i nodi non funzionanti. Più gruppi di minaccia possono noleggiare la stessa rete. Mandiant ha osservato che un indirizzo IPv4 è rimasto associato ad alcuni ORB per appena 31 giorni; raccomanda quindi di considerare la **rete come un'entità in evoluzione simile a un attore**, anziché bloccare un elenco obsoleto di IP.<sup>[[2]](#references)</sup>

### Cosa offre e cosa leaks

- Il target vede un'uscita che può essere geograficamente vicina e sembrare residenziale.
- L'uscita vede il target e l'hop precedente, non necessariamente l'operatore.
- Il servizio di accesso vede il cliente e la richiesta di routing. Una mesh gestita in modo indipendente può separare il cliente dalle uscite, ma crea una potente traccia presso la controparte.
- Porte ripetute, ordine degli handshake, banner del server, certificati, finestre di uptime e relazioni con i controller possono rivelare la flotta anche mentre gli IP ruotano.
- Un router compromesso spesso non dispone di telemetria dell'endpoint, ma il suo ISP conserva comunque dati dell'abbonato e dei flussi; il sequestro espone artefatti dell'implant e della configurazione.

{% hint style="info" %}
Per un'esercitazione autorizzata, riproduci la topologia con VM o router di proprietà dell'organizzazione e conserva la mappa di attribuzione del controller. Non reclutare proxy aperti o dispositivi di terze parti. La [guida al laboratorio](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) crea la stessa struttura di hop visibile ai defender senza danneggiare un intermediario.
{% endhint %}

## Reti di proxy residenziali e mobili

I servizi di proxy residenziale assegnano le sessioni a indirizzi di connessioni consumer a banda larga; i proxy mobili effettuano l'egress attraverso pool NAT degli operatori. La fornitura può provenire da dispositivi registrati esplicitamente, SDK/proxyware integrati in applicazioni consumer, rivenditori o malware. Queste origini non sono equivalenti: senza consenso informato, un servizio per la privacy diventa infrastruttura compromessa.

Le modalità di rotazione influiscono sul rilevamento:

- la **rotazione per richiesta** produce rapide discontinuità di IP e ASN/geografia, mentre l'identità ai livelli superiori rimane stabile;
- le **sessioni sticky** mantengono un'uscita per minuti o ore, somigliando a un normale abbonato;
- i **gateway backconnect** mostrano al cliente un singolo endpoint del broker e scelgono internamente le uscite;
- i **pool mobili** collocano molti abbonati reali dietro un numero ridotto di indirizzi NAT degli operatori, rendendo costoso bloccare un IP.

I defender dovrebbero correlare l'IP con la sessione autenticata, il fingerprint TLS/client, l'ordine HTTP, il cookie del dispositivo e il comportamento. Un accesso residenziale apparentemente locale seguito da uno proveniente da un altro paese, mentre tutte le caratteristiche ai livelli superiori restano identiche, è un segnale più forte della sola reputazione. Al contrario, la condivisione degli indirizzi e il passaggio tra celle mobili generano variazioni legittime: non considerare mai la classificazione residenziale/proxy come una sentenza.

### Piani di controllo del proxyware e sovrapposizione tra rivenditori

Non modellare un pool residenziale come un elenco piatto di uscite. L'analisi dell'ecosistema IPIDEA ha rivelato un **piano di controllo a due livelli** riutilizzabile: un SDK integrato invia prima i metadati del dispositivo/registrazione a un dominio Tier One e riceve coppie IP:port `connect`/`proxy` di Tier Two insieme alle istruzioni di pianificazione. Il nodo interroga periodicamente la porta connect di Tier Two per ricevere un task codificato, apre una seconda connessione alla porta proxy associata e inoltra i byte forniti alla destinazione richiesta. SDK e brand di proxy nominalmente distinti avevano domini di discovery separati, ma convergevano su infrastrutture Tier Two condivise e pool di uscita sovrapposti tramite relazioni di proprietà comune e rivendita.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Questo produce pivot di hunting più duraturi rispetto a un blocco di IP residenziali:<sup>[[13]](#references)</sup>

- un processo imprevisto di un servizio di utilità, VPN, gioco o dispositivo embedded invia un ID stabile del dispositivo/una chiave cliente e riceve un elenco di server variabile;
- l'endpoint interroga un IP diretto su una porta insolita, quindi si connette a un'altra porta sullo stesso indirizzo subito prima di aprire un socket verso una nuova destinazione;
- diversi brand apparentemente distinti condividono indirizzi Tier Two, grammatica di protocollo, codice SDK o sovrapposizioni di exit-node;
- applicazioni distinte che contattano domini Tier One diversi ricevono indirizzi dallo stesso pool Tier Two.

Questa sovrapposizione limita anche l'attribuzione: rilevare un IP nel pool pubblicizzato di un vendor non dimostra quale reseller, cliente o threat actor lo abbia usato nel momento rilevante. Conserva i timestamp dei flussi, la lineage dei processi, i corpi delle risposte Tier One e gli identificatori delle attività Tier Two.<sup>[[13]](#references)</sup> In un'esercitazione autorizzata, emula questa gerarchia solo con endpoint di proprietà dell'organizzazione; non iscrivere mai dispositivi consumer né proxyware di terze parti.

## Catene di proxy multi-hop

MITRE distingue i proxy esterni dai **proxy multi-hop (T1090.003)**. La proprietà importante non è il numero di hop, ma la separazione delle informazioni e dell'amministrazione.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Se un'unica parte gestisce A e B, i log condivisi o la temporizzazione del traffico possono ricostruire il circuito. Aggiungere VPN commerciali in sequenza a partire dallo stesso endpoint/account può aumentare la latenza, lasciando però intatte le prove legate a identità, pagamento e tempistiche comuni. Tor riduce questo problema usando relay selezionati in modo indipendente e un design client condiviso, ma una rete interattiva a bassa latenza non può garantire resistenza a un osservatore che misura entrambe le estremità.

Tra i guasti comuni rientrano il bypass tramite DNS o IPv6, le applicazioni che aprono socket propri, il traffico di gestione che raggiunge direttamente i relay, l'attività sincronizzata, il riutilizzo delle chiavi SSH e l'accesso ad account identificativi. La verifica corretta consiste in un test di failure: arrestare ogni relay a turno e dimostrare che il workload non può ripiegare su un percorso in chiaro.

### Collasso del tunnel e leak upstream

Un'architettura a relay è spesso più attribuibile quando si guasta. Unit 42 ha documentato un percorso di spionaggio a più livelli che usava VPS rivolti alle vittime, VPS relay, proxy residenziali, Tor e altri servizi proxy; quando un tunnel veniva omesso o collassava, l'infrastruttura upstream nascosta si connetteva direttamente ai sistemi relay e a quelli rivolti alle vittime. La stessa indagine ha usato anche un certificato X.509 esposto brevemente sull'infrastruttura upstream come pivot tra livelli.<sup>[[14]](#references)</sup>

Mantieni separati il **data plane** (`victim <-> exit`) e il **control plane** (`operator/upstream -> relay administration`). Conserva i log di ingresso e autenticazione in ogni livello controllato, la cronologia dei certificati e le connessioni brevi non riuscite, non solo le sessioni C2 riuscite. Una sorgente che compare solo durante le interruzioni dei relay o amministra direttamente più nodi rivolti alle vittime è un candidato upstream più convincente di un normale exit, ma il suo ASN/geolocalizzazione resta un'ipotesi, non una prova dell'identità dell'operatore.

In un lab autorizzato, il workload dovrebbe fallire in modo chiuso. Per un workload isolato in un namespace di rete Linux, la prima route deve passare attraverso il tunnel; dopo averlo rimosso, sia la richiesta sia la ricerca della route devono fallire, anziché selezionare l'uplink fisico:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Ripeti il test per DNS e IPv6 e a ogni confine tra relay. Se una qualsiasi sonda ha esito positivo, registra l’interfaccia/l’indirizzo sorgente effettivo prima di correggere il policy routing o il firewall: è il leak di attribuzione che un investigatore potrebbe rilevare.

## Livelli di redirector e traffic shaping

Un **redirector** pubblico accetta il traffico conforme a una grammatica specifica dell’operazione e lo inoltra a un team server protetto. Tutto il resto può essere rifiutato o ricevere contenuti innocui.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Più livelli limitano l'esposizione: bruciare un dominio pubblico non deve necessariamente esporre il team server. Le CDN aggiungono capacità anycast e un dominio esterno affidabile, ma l'account CDN e i log edge diventano punti di attribuzione. Impronte TLS, cronologia dei certificati, percorsi distintivi/ordine degli header, dimensioni delle risposte, comportamento dei redirect e allowlist degli origin possono raggruppare front apparentemente non correlati.

Per il rilevamento, registra i campi del reverse proxy prima della normalizzazione, confronta SNI/Host/authority, ispeziona combinazioni rare di header, raggruppa i corpi delle risposte e le impronte TLS e cerca sovrapposizioni di configurazione nei log di audit cloud/CDN. Per i red team autorizzati, evita di copiare un marchio reale o di raccogliere credenziali tramite terze parti non correlate.

## Domain fronting and domainless fronting

Con il **domain fronting classico (T1090.004)**, la connessione TLS annuncia un front domain consentito in SNI, mentre l'`Host` HTTP o `:authority` HTTP/2, cifrato, richiede un diverso dominio back-end. Una CDN collaborativa instrada in base al valore interno. Un osservatore di rete senza decrittazione TLS vede il front; la CDN vede entrambi i valori e l'origin. Nelle varianti domainless, SNI può essere vuoto, mentre un altro campo di instradamento seleziona la destinazione.<sup>[[4]](#references)</sup>

Non è un'impersonificazione magica: funziona solo se l'intermediario consente intenzionalmente o accidentalmente la discrepanza e sa come instradare il nome interno. I principali provider hanno limitato il fronting tra account diversi. Encrypted ClientHello (ECH) cambia ciò che può vedere un osservatore sul percorso, ma non elimina i record della CDN, dell'endpoint o dell'applicazione.

I punti di rilevamento includono:

- la gerarchia dei processi dell'endpoint e una destinazione non prevista per quell'applicazione;
- la discrepanza tra SNI e authority HTTP, laddove l'ispezione TLS sia legittima e disponibile;
- log CDN che mostrano un tenant/front instradato verso un'altra authority/origin;
- sessioni insolitamente lunghe o periodiche verso un servizio normalmente interattivo;
- dimensioni e cadenza stabili dei flussi cifrati, nonostante il cambiamento dei front domain.

Il lab sicuro simula la discrepanza di instradamento su un reverse proxy di proprietà; non abusa di una CDN pubblica.

## Risoluzione dinamica: DDNS, DGA e fast flux

La risoluzione dinamica separa un servizio logico dall'infrastruttura fissa:

- **DDNS:** un client autenticato aggiorna un nome stabile dopo che il suo indirizzo cambia.
- **DGA:** l'endpoint ricava nomi di dominio da un seed, spesso basato sul tempo o su una chiave, ma talvolta su contenuti pubblici modificabili; l'operatore configura il DNS per il nome attivo.<sup>[[17]](#references)</sup>
- **Fast flux:** un nome restituisce un insieme di indirizzi compromessi/proxy che cambia rapidamente, spesso con TTL bassi.
- **Double flux:** ruotano sia gli indirizzi dei servizi sia quelli dei name server autoritativi, nascondendo anche il livello di controllo.

Il fast flux è un pattern di distribuzione del carico usato a scopi avversari, non semplicemente «molte risposte DNS». Le prove più solide combinano TTL basso, alto numero di indirizzi univoci, ampia dispersione per ASN/area geografica, breve durata dei nodi, comportamento applicativo ripetuto e cronologia di registrazione sospetta. Le CDN presentano legittimamente diverse di queste caratteristiche. MITRE raccomanda di correlare il comportamento DNS con il processo e le connessioni successive.<sup>[[5]](#references)</sup>

Una DGA può essere rilevata tramite entropia lessicale, pattern di consonanti/cifre, raffiche di NXDOMAIN, domini sincronizzati al primo rilevamento e contesto del processo. Le DGA basate su wordlist e i modelli generativi eludono le semplici regole basate sull'entropia; diventano quindi più importanti il clustering temporale sull'intera flotta e la genealogia degli endpoint.

### Seed di immagine modificabile per una DGA basata su wordlist

Una DGA non deve necessariamente dipendere dal tempo. Un loader recupera la pagina di un canale pubblico Telegram, legge l'attributo `src` dell'elemento `tgme_page_photo_image`, scarica l'immagine del profilo e ne calcola l'hash sugli **ultimi 50 byte del file**, anziché sui pixel decodificati. Quattro seed hash selezionano un aggettivo, un sostantivo, un verbo e un numero. Cambiare l'immagine modifica il nome DNS derivato senza distribuire un nuovo client. Mantieni esattamente gli stessi byte dell'immagine scaricata e lo stesso ordine delle wordlist su entrambi i lati; ricodificare l'immagine o riordinare una lista produce nomi diversi.<sup>[[17]](#references)</sup>

Con le wordlist recuperate dal client, è possibile riprodurre la fase di selezione del nome. L'hash byte per byte della sorgente usa un accumulatore a 64 bit, il moltiplicatore `0x1000193` e seed separati per ciascun componente:<sup>[[17]](#references)</sup>

<details>
<summary>Riprodurre la selezione del nome da wordlist basata sul seed dell'immagine</summary>

```python
def wordlist_domain(image: bytes, adjectives: list[str], nouns: list[str], verbs: list[str], suffix: str) -> str:
    if len(image) < 50:
        raise ValueError("Image must contain at least 50 bytes")
    tail = image[-50:]
    def hashed(seed: int) -> int:
        value = seed
        for byte in tail:
            value = ((value ^ byte) * 0x1000193) & 0xFFFFFFFFFFFFFFFF
        return value
    a = adjectives[hashed(0x811C9DC5) % len(adjectives)]
    n = nouns[hashed(0xAF0154A5) % len(nouns)]
    v = verbs[hashed(0xFE5439E4) % len(verbs)]
    digit = hashed(0xFFA7471A) % 1000
    return f"{a}-{n}-{v}-{digit}.{suffix}"
```

</details>

A differenza di un [dead-drop resolver](#web-services-and-dead-drop-resolvers) che pubblica direttamente l'endpoint, qui l'oggetto pubblico fornisce solo un seed modificabile; il client ricava localmente l'endpoint.

Il nome generato viene quindi usato per cercare un record DNS TXT tramite `https://dns.google/resolve?name=<domain>&type=TXT`. Il client decodifica in Base64 il campo `data` della risposta JSON, verifica una firma Ed25519 con la chiave pubblica incorporata e solo allora decifra il comando con AES-ECB. Il testo in chiaro osservato inizia con un selettore di metodo e un URL per un payload cifrato. Il controllo della firma impedisce che un semplice record TXT risolvibile fornisca tasking accettato.<sup>[[17]](#references)</sup>

## Domini compromessi e domain shadowing

Un attore può dirottare un account registrar/DNS, assumere il controllo di un sottodominio abbandonato oppure aggiungere record sotto un dominio altrimenti rispettabile. **Il domain shadowing** mantiene intatto il dominio apex legittimo mentre un gran numero di sottodomini controllati dall'attaccante punta a host di delivery o C2 che cambiano nel tempo. Sfrutta anzianità e reputazione e può eludere i blocchi applicati all'intero dominio.<sup>[[6]](#references)</sup>

I difensori hanno bisogno di log di audit del registrar e del DNS autoritativo, MFA, blocchi di registry/registrar, avvisi per nuove deleghe/token API/name server, monitoraggio della Certificate Transparency e un inventario delle risorse cloud a cui fa riferimento il DNS. Esaminate la risoluzione e la cronologia dei certificati di un sottodominio separatamente dalla reputazione del dominio apex.

## Web services e dead-drop resolver

Un **dead-drop resolver (T1102.001)** conserva un puntatore codificato al C2 corrente all'interno di un post, profilo, documento, repository, oggetto cloud o campo blockchain legittimo. Il malware recupera l'oggetto pubblico, decodifica un dominio/IP e contatta lo stage successivo. Le varianti bidirezionali scambiano comandi o file tramite le API del servizio.<sup>[[7]](#references)</sup>

Una variante specifica di GitHub usa l'API Issues Search solo quando un canale autenticato del repository non è disponibile. Il client cerca issue corrispondenti alla data corrente, al repository e al tipo di issue, segue l'URL dei commenti di ciascuna issue ed estrae il ciphertext compreso tra i marcatori `<!--` e `-->`. Dopo la decrittazione specifica per host e basata sulla data, campi come `Owner`, `LicRepo` e `LicToken` sostituiscono rispettivamente il proprietario, il percorso e il token del repository primario. Questo consente all'operatore di ruotare credenziali ed endpoint senza sostituire il client; il commento dell'issue funge da resolver, mentre i file del repository restano il canale di tasking.<sup>[[15]](#references)</sup>

Una variante Android seleziona all'avvio una delle due pagine Telegram pubbliche ed estrae il ciphertext compreso tra due occorrenze di un marcatore incorporato nell'APK. Decodifica il valore in Base64URL e lo decifra con AES-128-CBC: i primi 16 byte di `SHA-256(marker)` costituiscono la chiave e i 16 successivi l'IV. Il testo in chiaro è l'effettivo URL di base del C2, non l'URL della pagina Telegram. Per riprodurre la risoluzione, mantenete invariati il contenuto della pagina e il marcatore esatto; modificare la pagina pubblica consente di ruotare l'endpoint senza ricompilare l'APK.<sup>[[16]](#references)</sup>

Questo offre resilienza e nasconde il C2 back-end dall'analisi statica dei binari. Crea inoltre identificatori stabili di oggetti, tenant, repository, API e pattern di accesso. I difensori dovrebbero correlare:

1. il processo che ha contattato il servizio;
2. il percorso API/oggetto esatto e l'hash della risposta;
3. l'attività di decodifica o elaborazione delle stringhe;
4. la nuova connessione in uscita poco dopo; e
5. lo stesso comportamento nel resto della flotta.

Bloccare tutti i servizi GitHub, cloud storage o social media è raramente praticabile. Le policy di egress consapevoli del servizio e la correlazione a livello di processo sono più efficaci del blocco basato solo sul dominio.

## Persona, account e compartimenti di approvvigionamento

L'anonimato dell'infrastruttura viene meno quando una persona, un'email di recupero, un numero di telefono, un pagamento, un browser o un IP amministrativo collega tra loro i compartimenti. Le operazioni legate a uno Stato hanno creato profili social, identità email e account cloud molto prima del loro utilizzo; ATT&CK registra questa attività come Establish Accounts (T1585), comprese le sottotecniche relative a social media, email e cloud.<sup>[[8]](#references)</sup>

Un difensore o un investigatore costruisce un grafo basato su:

- orario di creazione e primo accesso, lingua, fuso orario e orari di attività;
- dati di recupero, dispositivi MFA, documenti d'identità e strumenti di pagamento;
- fingerprint di browser/TLS e cronologia delle reti di origine;
- riutilizzo degli avatar, provenienza delle immagini, stile di scrittura e crescita del grafo sociale;
- registrante di dominio, name server, certificato, ID analytics o commit del repository condivisi;
- azioni del piano di gestione che aggirano l'architettura del relay pubblico.

Per un red team autorizzato, le persone sintetiche devono essere documentate per il responsabile dell'esercitazione, usare canali di recupero/pagamento di proprietà dell'organizzazione, evitare di impersonare persone reali estranee all'attività e avere un piano di dismissione. Il SOC può restare all'oscuro; l'operazione non deve diventare priva di responsabilità.

## Pattern compositi emergenti da includere nel threat modeling

Quelli che seguono sono **composizioni proposte dai difensori**, non affermazioni secondo cui un attore specifico abbia implementato ciascun design esatto. Combinano primitive già osservate e sono utili come ipotesi per il purple team.

### Tasking asimmetrico a senso unico

I comandi arrivano tramite una fonte pubblica, broadcast o append-only, mentre i risultati escono tramite un canale non correlato dopo un ritardo. Tra le primitive utilizzate figurano la comunicazione unidirezionale tramite web service e i dead drop. La separazione impedisce a un singolo flusso di apparire bidirezionale e ostacola la semplice correlazione richiesta/risposta.<sup>[[9]](#references)</sup>

**Rilevamento:** conservate i dati delle letture a livello di oggetto, quindi correlate le modifiche di stato del processo e i successivi trasferimenti in uscita su una finestra temporale più ampia. Cercate processi rari che leggono lo stesso oggetto pubblico anche quando non segue una risposta immediata.

### Promozione a canale multistadio

Un primo stage silenzioso raccoglie informazioni e promuove solo i sistemi selezionati a un secondo canale non correlato. L'endpoint, il protocollo e il processo del secondo stage potrebbero non condividere alcuna infrastruttura con il primo. Questo limita l'esposizione dell'infrastruttura avanzata ed è esplicitamente modellato come ATT&CK T1104.<sup>[[10]](#references)</sup>

**Rilevamento:** correlate `processo di rete iniziale -> stato scaricato/configurato -> nuovo processo o injection -> destinazione non correlata`; non chiudete l'incidente dopo aver bloccato il primo dominio.

### Traduzione del relay tra protocolli

Hop diversi traducono HTTPS, QUIC, WebSocket, DNS, SSH o un'API di message queue anziché inoltrare i pacchetti in modo trasparente. La traduzione elimina un'impronta di protocollo end-to-end univoca, ma crea gateway con pattern distintivi di timing, buffering e conversione semantica. Il protocol tunneling (T1572) può essere combinato con proxy e impersonificazione di servizi.<sup>[[11]](#references)</sup>

**Rilevamento:** cercate host gateway che ricevono un protocollo e ne avviano un altro con comportamenti di byte/tempo strettamente correlati; confrontate l'intento dell'endpoint con il protocollo effettivamente trasportato.

### Attivazione passiva sui dispositivi edge

Invece di inviare beacon, un implant monitora il traffico che raggiunge già un router/VPN e si attiva solo in presenza di un valore magico, un pattern di porte sorgente o un token autenticato. Il traffico normale continua a raggiungere il servizio reale. ATT&CK chiama questa tecnica Traffic Signaling (T1205), con esempi documentati relativi a dispositivi di rete e APT.<sup>[[12]](#references)</sup>

**Rilevamento:** integrità del firmware/dei file, packet capture grezzo durante un hunt autorizzato, filtri socket inattesi e comportamento differenziale del servizio. L'assenza di un beacon periodico non dimostra che un dispositivo edge sia pulito.

### Rotazione delle origini serverless ed effimere

Un front mantiene un'identità logica stabile, mentre funzioni/container di breve durata gestiscono singoli stage in più regioni/account. Questo riduce la durata dei dati su disco e la presenza di IP di origine fissi, ma la creazione nel piano di controllo, le immagini/layer, i ruoli, i secret, gli ID delle richieste e i dati di billing diventano il grafo persistente.

**Rilevamento:** conservate i log di audit e di invocazione cloud al di fuori del workload; raggruppate i template di deployment, i ruoli, le chiavi d'ambiente e le relazioni tra front e origine.

### Diversificazione dei livelli di privacy

Un'operazione può evitare deliberatamente una catena omogenea: per esempio, un canale usa un relay a noleggio, il tasking usa un oggetto pubblico, l'uscita proviene da un collegamento cellulare di laboratorio di proprietà e l'amministrazione usa una rete distinta dell'organizzazione. Questo riduce il valore della compromissione di un singolo provider, ma aumenta il rischio di correlazione temporale tra livelli e di errori operativi.

**Rilevamento:** create timeline della campagna combinando sensori di identità, DNS, SaaS, rete e cloud. Cercate transizioni di stato sincronizzate anziché indicatori identici.

### Dead drop decentralizzati o basati su transparency log

Un attore può inserire un piccolo puntatore cifrato in qualsiasi sistema pubblico persistente e append-only, archivio content-addressed o feed simile a un transparency log. L'oggetto pubblico è resiliente, ma il suo indice/hash del contenuto esatto e il pattern di polling del client diventano identificatori stabili.

**Rilevamento:** registrate gli identificatori completi di API/oggetto e gli hash delle risposte; generate avvisi quando processi non standard eseguono il polling di oggetti immutabili e poi li decodificano o avviano nuove connessioni.

### Operazioni store-and-forward ritardate

Il C2 interattivo crea forti correlazioni temporali. Un design store-and-forward raggruppa job cifrati e restituisce i risultati minuti o ore dopo tramite una coda diversa o un trasferimento fisico. Sacrifica la reattività per ridurre la correlazione temporale end-to-end.

**Rilevamento:** ampliate le finestre di correlazione, modellate gli accessi periodici alle code ed esaminate lo staging sugli endpoint. Il batching sposta il segnale dal timing dei pacchetti al comportamento pianificato di processi/file; non lo elimina.

## Revisione del design: ragionate in termini di osservatori

Per ogni percorso, compilate questa tabella prima del deployment e dopo la raccolta:

| Livello | Vede la sorgente? | Vede la destinazione? | Vede il contenuto? | Identificatori stabili | Conservazione/responsabile legale |
|---|---:|---:|---:|---|---|
| rete locale/operatore | | | | | |
| servizio di ingresso/accesso | | | | | |
| operatori di transito | | | | | |
| uscita/redirector/CDN | | | | | |
| DNS autoritativo/registrar | | | | | |
| target | | | | | |
| provider di account/pagamento | | | | | |

Se un singolo provider ordinario può compilare tutte le colonne, l'architettura offre occultamento rispetto al target, ma non una separazione solida. Se nessun responsabile interno può ricondurre l'attività a un engagement, l'architettura non è adatta a un red team professionale.

## References

- [1] [MITRE ATT&CK — Acquisire infrastruttura (T1583), Compromettere infrastruttura (T1584) e Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Attori di spionaggio legati alla Cina utilizzano reti ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Proxy multi-hop (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromettere infrastruttura: domini (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Creare account (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: comunicazione unidirezionale (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Canali multistadio (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Interrompere la più grande rete di proxy residenziali al mondo](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Le campagne Shadow: alla scoperta dello spionaggio globale](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - La campagna Blinder Tunnel prende di mira le infrastrutture irachene](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: l'AI ha creato gli overlay. Le vittime perdono i PIN](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
- [17] [Check Point Research — Tecniche del passato distribuite tramite binari firmati di ChatGPT e Claude](https://research.checkpoint.com/2026/tricks-from-the-past-deployed-via-signed-chatgpt-and-claude-binaries/)
{{#include ../banners/hacktricks-training.md}}
