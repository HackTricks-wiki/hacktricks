# Catalogo delle tecniche per l'accesso anonimo a Internet

Questo è l'inventario canonico dei percorsi di accesso. Comprende le **famiglie** di protocolli e procedure operative, non ogni nome di vendor. Nessun percorso Internet garantisce l'anonimato: account, browser, endpoint, tempistiche, pagamenti, control plane cloud e prove fisiche possono vanificare anche un percorso apparentemente perfetto.

Ogni voce utilizza gli stessi campi. “Procedura” indica un deployment lecito o un'emulazione in un laboratorio di proprietà. Quando la tecnica reale dipende dal compromettere un router, rubare accesso o abusare di un intermediario non consenziente, la riproduzione sostituisce tali sistemi con sistemi di proprietà dell'esercitazione.

## Matrice di copertura

| Famiglia | Cosa vede la destinazione | Proprietà più forte | Velocità | Trattamento |
|---|---|---|---|---|
| NAT condiviso/CGNAT | indirizzo pubblico condiviso | ambiguità tra gli abbonati | alta | implementabile |
| VPN, VPS, proxy SOCKS/HTTP/SSH | indirizzo del relay | separazione rapida dell'indirizzo sorgente | alta | implementabile |
| Multi-hop/split relay, MASQUE | proxy finale | separazione della conoscenza o tunnel IP completo | alta/moderata | implementabile con relay affidabili |
| Tor, bridge, onion service | exit o identità onion | percorso multi-party e browser comune | moderata | implementabile |
| I2P, GNUnet, mixnet | peer/gateway dell'overlay | resistenza dell'overlay o alle tempistiche | bassa/variabile | specifica per applicazione |
| OHTTP/ODoH, Private Relay | gateway/egress | partizionamento di sorgente/richiesta | alta | solo applicazioni supportate |
| Wi-Fi pubblico, travel router | indirizzo della venue/tunnel | cambio di posizione/percorso di accesso | alta | richiede autorizzazione |
| Cellulare/eSIM, satellite | indirizzo carrier/provider | uplink fisico indipendente | alta/variabile | l'abbonamento/provider osserva |
| Browser remoto/jump host | workspace remoto | separazione di endpoint ed egress | alta | implementabile |
| Proxy residenziale/mobile | indirizzo consumer/carrier | aspetto di rete consumer | alta | consenso/provenienza fondamentali |
| ORB/relay compromesso | indirizzo di un'altra vittima | occultamento dell'origine e reputazione presa in prestito | alta | riproduzione solo in laboratorio di proprietà |
| CDN/fronting/redirector | indirizzo front del CDN | protezione dell'infrastruttura back-end | alta | richiede approvazione del provider/proprietario |
| Fast flux/DGA/dead drop | nodo/servizio rotante | resistenza alla discovery dell'infrastruttura | variabile | riproduzione solo in laboratorio di proprietà |
| Drop/nearest-neighbor | indirizzo adiacente al target | attraversamento di confini geografici/di rete | alta | solo laboratorio su siti di proprietà |
| Store-and-forward/offline | gateway o ricevitore fisico | riduzione del collegamento temporale interattivo | bassa | specifica per applicazione |
| Pluggable/refraction transport | ingresso Tor o proxy di diversion cooperante | raggiungibilità resistente alla censura | variabile | client supportato o laboratorio di ricerca |
| Gateway IPFS/PIR/remote fetcher | gateway o servizio applicativo | separazione di publisher/query/richiesta | variabile | solo applicazioni limitate |
| Anycast/QUIC/MPTCP | broker stabile o subflow multipli | rendezvous e continuità della sessione | alta | disponibilità, non anonimato |
| CI/CD automation runner | indirizzo del runner hosted | egress temporaneo e tracciabile | alta | solo workflow di proprietà |
| Primo hop locale non-IP | gateway dell'organizzazione | rimozione dello stack Internet dal sensore | bassa | deployment approvato dal proprietario |

## NAT condiviso diretto e carrier-grade NAT

**Meccanismi:** più utenti condividono un indirizzo pubblico; l'access provider mappa indirizzi e porte lato abbonato sulla tupla pubblica.

**Vantaggi:** rapido; nessun client speciale; il solo IP lato destinazione può identificare soltanto un'abitazione, una venue o un pool del carrier.

**Svantaggi:** il provider può conservare le mappature abbonato/porta/ora; account e fingerprint restano; altri utenti possono danneggiare la reputazione dell'indirizzo.

**Procedura:** (1) confermare se l'accesso autorizzato utilizza NAT/CGNAT; (2) registrare l'IP pubblico esatto e la porta sorgente presso un endpoint di proprietà; (3) mantenere separate le identità applicative; (4) non trattare l'indirizzamento condiviso come controllo della privacy; (5) usare un percorso più forte se l'ISP non deve conoscere le destinazioni.

**Rilevamento:** le destinazioni dovrebbero conservare porta sorgente e ora precisa, non soltanto l'IP. I provider correlano i log di allocazione NAT; gli investigatori uniscono prove relative ad account, dispositivo e browser.

## VPN commerciale

**Meccanismi:** una connessione full-tunnel cifrata termina presso la VPN; le destinazioni vedono il suo egress. La VPN può normalmente associare sorgente, tempistiche e destinazioni.

**Vantaggi:** rapida; semplice; protegge dall'osservazione passiva locale; exit stabili o condivisi; adatta all'egress controllato del red team.

**Svantaggi:** fiducia concentrata; telemetria di billing/login; errori di kill-switch/DNS/IPv6; gli exit condivisi sono spesso bloccati per reputazione.

**Procedura:** (1) identificare provider, proprietario, giurisdizione, conservazione dei dati e policy di assessment; (2) installare il client ufficiale firmato; (3) abilitare full tunnel, always-on e comportamento fail-closed; (4) instradare deliberatamente DNS e IPv6; (5) verificare IPv4/IPv6/DNS osservati presso un endpoint di proprietà; (6) arrestare/riconnettere il tunnel e confermare l'assenza di fallback in chiaro.<sup>[[1]](#references)</sup>

**Rilevamento:** le reti locali vedono un flusso cifrato prolungato verso l'infrastruttura VPN; i provider dispongono dei record di autenticazione/connessione; le destinazioni usano ASN/reputazione insieme a correlazione di account, TLS/browser e comportamento.

## Egress VPN self-hosted o VPS noleggiato

**Meccanismi:** l'operatore controlla un gateway WireGuard/OpenVPN o inoltra il traffico attraverso un server noleggiato.

**Vantaggi:** velocità elevata prevedibile; indirizzo fisso inseribile in allowlist; logging/firewall personalizzati; buon controllo degli incidenti.

**Svantaggi:** anonymity set ridotto; tenant cloud, pagamenti, login sorgente, API e cronologia delle immagini collegano l'operatore; un server nuovo e distintivo è facile da raggruppare.

**Procedura:** (1) creare un progetto organizzativo specifico per l'engagement; (2) effettuare il provisioning di un'immagine supportata e di un indirizzo fisso; (3) limitare la gestione ad amministrazione basata su MFA/chiavi; (4) configurare egress full-tunnel e DNS; (5) consentire solo destinazioni limitate ove pratico; (6) testare comportamento in caso di leak/failure; (7) conservare i record di audit del controller; (8) distruggere credenziali e risorse al teardown.

**Rilevamento:** correlare ASN di hosting, indirizzo visto per la prima volta, fingerprint di certificato/servizio e comportamento di scanning; i cloud owner usano log di control plane, console, billing e flusso.

## Forwarding HTTP CONNECT, SOCKS e SSH

**Meccanismi:** un'applicazione chiede a un proxy di aprire un flusso TCP; SOCKS può anche trasmettere risoluzione dei nomi e UDP a seconda della versione; SSH inoltra flussi all'interno di una singola sessione cifrata.

**Vantaggi:** leggero; per-applicazione; rapido; utile per il chaining e per raggiungere reti segmentate.

**Svantaggi:** le applicazioni possono bypassarlo; il DNS può fare leak; il proxy vede gli endpoint adiacenti; lo stato del browser resta; gli open proxy possono essere trappole o sistemi compromessi.

**Procedura:** (1) implementare il proxy su un host di proprietà; (2) richiedere autenticazione e limitare sorgente/destinazione; (3) configurare un profilo applicativo usa-e-getta; (4) garantire la risoluzione DNS remota quando necessaria; (5) verificare con un endpoint DNS/HTTP di proprietà; (6) bloccare l'egress diretto del workload; (7) ispezionare e ruotare le credenziali del proxy.

**Rilevamento:** identificare processi capaci di creare tunnel, negoziazione CONNECT/SOCKS, sessioni SSH prolungate e destinazioni incoerenti con l'applicazione; i log del proxy ricostruiscono i flussi.

## Web proxy con riscrittura degli URL ed estensione proxy del browser

**Meccanismi:** un sito recupera una destinazione e riscrive link/form attraverso la propria origine, oppure un'estensione indirizza le richieste del browser verso un proxy. La destinazione vede il servizio, mentre il servizio può vedere il plaintext dopo la terminazione TLS e iniettare o conservare contenuti.

**Vantaggi:** nessun client system-wide; rapido per la navigazione semplice; funziona dove l'installazione di una VPN è impossibile.

**Svantaggi:** il proxy può leggere credenziali/contenuti, riscrivere download e creare fingerprint degli utenti; script/WebSocket/download possono bypassarlo; l'estensione del browser ha privilegi ampi; anonymity set ridotto e blocchi frequenti.

**Procedura:** (1) utilizzare soltanto un proxy gestito dall'organizzazione per test autorizzati; (2) isolarlo in un browser usa-e-getta senza account personali; (3) vietare l'inserimento di password e i download sensibili; (4) verificare che ogni subresource di una pagina di proprietà venga risolta attraverso il proxy; (5) testare comportamento di WebSocket, download e form; (6) rimuovere estensione/profilo dopo l'uso.

**Rilevamento:** la destinazione registra il proxy; proxy/DNS enterprise e inventario delle estensioni identificano il servizio; subresource content-security/reporting o canary di proprietà rivelano bypass diretti; i log del proxy mappano la sessione dell'utente sui target.

## Proxy multi-hop o VPN multi-hop del provider

**Meccanismi:** un entry vede la sorgente, mentre uno o più relay di transito la separano da un exit che vede la destinazione.

**Vantaggi:** nessun relay ordinario necessita di entrambe le estremità; il failure/sequestro di un nodo rivela meno informazioni; geografia flessibile.

**Svantaggi:** amministrazione e log condivisi vanificano la separazione; latenza; correlazione temporale; più failure e percorsi DNS; lo stesso account/pagamento può collegare ogni hop.

**Procedura:** (1) definire quale osservatore viene rimosso da ogni hop; (2) usare relay indipendentemente amministrati, di proprietà o approvati, quando la separazione è importante; (3) imporre accesso solo-entry dal workload; (4) garantire che ogni relay possa raggiungere soltanto l'hop successivo; (5) verificare i log a ogni livello; (6) arrestare ogni hop e confermare il comportamento fail-closed. Riprodurre con [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain).

**Rilevamento:** correlare tempistiche/volumi NetFlow adiacenti, handshake ripetuti dei proxy e infrastruttura comune del controller; non dedurre la geografia dell'operatore dall'exit.

## Relay applicativo a conoscenza separata e OHTTP

**Meccanismi:** il client cifra un messaggio HTTP stateless verso un gateway e lo invia attraverso un relay. Il relay vede l'IP del client ma non la richiesta; il gateway vede la richiesta ma normalmente soltanto l'IP del relay.

**Vantaggi:** partizionamento della privacy forte e verificabile per le richieste supportate; overhead inferiore rispetto alle reti di anonimato generali.

**Svantaggi:** non consente browsing arbitrario; cookie/autenticazione possono ricollegare l'utente; collusione relay/gateway e traffic analysis restano possibili; l'applicazione deve implementarlo.

**Procedura:** (1) selezionare un'applicazione che supporti esplicitamente RFC 9458; (2) verificare le chiavi del gateway tramite il percorso di configurazione ufficiale; (3) evitare campi stabili per utente; (4) inviare soltanto la richiesta stateless supportata; (5) confrontare i log di relay, gateway e target; (6) testare rotazione delle chiavi/failure senza fallback diretto.<sup>[[2]](#references)</sup>

**Rilevamento:** gli endpoint espongono il processo iniziale e il relay OHTTP; i gateway rilevano traffico malformato/replayed; tempistiche e campi stabili di payload/account possono correlare le richieste.

## MASQUE CONNECT-UDP/CONNECT-IP e proxy HTTP per la privacy

**Meccanismi:** HTTP Extended CONNECT su TLS/QUIC trasporta pacchetti UDP o IP attraverso un proxy. Può implementare un tunnel moderno simile a una VPN e confondere il trasporto con HTTP/3, ma il proxy resta un osservatore.<sup>[[3]](#references)</sup>

**Vantaggi:** multiplexing/roaming efficienti; supporto a UDP o IP completo; deployment attraverso infrastruttura HTTP moderna.

**Svantaggi:** non è una rete di anonimato; proxy/account vedono sorgente e destinazioni; fingerprint QUIC/HTTP e percorsi noti sono visibili a endpoint/provider.

**Procedura:** (1) usare un client/servizio che documenti il supporto a RFC 9298/9484; (2) autenticare certificato/configurazione del proxy; (3) definire i percorsi target consentiti; (4) abilitare DNS cifrato nel percorso; (5) verificare UDP, TCP, IPv6 e failover contro endpoint di proprietà; (6) ispezionare i log di richiesta e flusso del proxy.

**Rilevamento:** gli endpoint vedono il processo client e l'interfaccia virtuale; le reti possono classificare QUIC/TLS prolungato verso un proxy; i log del proxy espongono target/percorso CONNECT e route assegnate.

## Tor Browser

**Meccanismi:** Tor seleziona relay guard, middle ed exit; la cifratura a livelli limita ciò che ogni relay può vedere. Tor Browser aggiunge un browser standardizzato progettato per resistere al fingerprinting.

**Vantaggi:** grande anonymity set pubblico; nessun relay ordinario conosce entrambe le estremità; non richiede la gestione di server.

**Svantaggi:** più lento; focalizzato su TCP; reputazione/blocchi degli exit; login e divulgazioni identificano l'utente; resta possibile la correlazione temporale a bassa latenza.

**Procedura:** (1) scaricare e verificare Tor Browser dal progetto; (2) mantenere le impostazioni predefinite ed evitare estensioni; (3) scegliere un livello di sicurezza appropriato; (4) creare un'identità/sessione separata; (5) evitare account identificativi e documenti esterni attivi; (6) usare HTTPS o onion service autenticati; (7) verificare l'exit soltanto con un endpoint di proprietà.<sup>[[4]](#references)</sup>

**Rilevamento:** le reti locali possono identificare il traffico verso guard noti salvo uso di bridge/transport; le destinazioni vedono gli exit e il comportamento di Tor Browser; osservatori end-to-end correlano tempistiche/volumi.

## Bridge Tor e pluggable transport

**Meccanismi:** un bridge non pubblico sostituisce il guard pubblico; obfs4, Snowflake o WebTunnel modificano il trasporto del primo hop per resistere a blocchi e probing semplici.

**Vantaggi:** aggira la censura e nasconde destinazioni evidenti di relay pubblici; conserva il circuito Tor dopo l'ingresso.

**Svantaggi:** pattern di trasporto e discovery dei bridge restano possibili; prestazioni variabili; non aggiunge protezione contro account o tempistiche globali.

**Procedura:** (1) provare prima Tor diretto; (2) nelle impostazioni Connection di Tor Browser selezionare un transport supportato integrato o richiedere un bridge ufficiale; (3) non usare binari/liste casuali; (4) connettersi ed eseguire un test innocuo; (5) testare riconnessione e clock; (6) mantenere standard tutte le altre impostazioni del browser.<sup>[[5]](#references)</sup>

**Rilevamento:** i censori usano discovery della destinazione, classificazione del protocollo/flusso e probing attivo; i defender devono distinguere l'uso di circumvention dalla compromissione e basarsi su processo/contesto dell'endpoint.

## VPN prima di Tor e Tor prima della VPN

**Meccanismi:** VPN-before-Tor nasconde l'uso diretto di Tor all'ISP di accesso ma espone la sorgente alla VPN. Tor-before-VPN consegna alla VPN il traffico post-Tor e spesso un'identità stabile di cliente/tunnel.

**Vantaggi:** rimuove uno specifico osservatore se progettata correttamente; può raggiungere reti che bloccano un livello.

**Svantaggi:** complessità, fingerprint insolito, leak, anonymity set ridotto e falsa sicurezza; Tor Project considera queste combinazioni avanzate.<sup>[[6]](#references)</sup>

**Procedura:** (1) scrivere quale osservatore viene rimosso e quale nuovo osservatore viene introdotto; (2) usare un ambiente usa-e-getta; (3) stabilire soltanto il percorso esterno previsto; (4) imporre le route del firewall; (5) verificare DNS/IPv4/IPv6 e l'ordine di ogni failure; (6) confrontare la visibilità di entrambi i provider; (7) abbandonare lo stack se non offre un vantaggio misurabile.

**Rilevamento:** osservatori locali/VPN/Tor vedono livelli adiacenti diversi; la tempistica resta end-to-end; fingerprint insoliti di tunnel annidati e account dei provider possono collegare le sessioni.

## Onion service

**Meccanismi:** client e servizio costruiscono entrambi circuiti Tor verso un rendezvous, nascondendo l'IP del servizio ed evitando un exit.

**Vantaggi:** protezione della posizione di sorgente e servizio; autenticazione onion end-to-end; nessuna porta inbound pubblica; autorizzazione opzionale del client.

**Svantaggi:** aggiornamenti/analytics/errori possono causare leak dell'origine; la chiave onion è critica; identità applicativa, tempistiche e compromissione dell'host restano.

**Procedura:** (1) isolare l'applicazione e associarla soltanto a loopback/socket; (2) installare Tor supportato; (3) configurare un onion service v3 seguendo le istruzioni ufficiali; (4) proteggere/creare un backup della chiave solo se serve un'identità stabile; (5) aggiungere autorizzazione client per uso chiuso; (6) rimuovere fetch di terze parti; (7) verificare esternamente che l'origine non sia raggiungibile.<sup>[[7]](#references)</sup>

**Rilevamento:** i defender dell'host/rete individuano processo/configurazione Tor e circuiti outbound; errori applicativi, DNS, certificati o risorse di terze parti possono esporre l'origine.

## Servizi interni I2P

**Meccanismi:** I2P utilizza tunnel inbound/outbound unidirezionali separati per destinazioni interne all'overlay; gli outproxy verso Internet pubblico aggiungono un punto di fiducia.

**Vantaggi:** pubblicazione interna decentralizzata; nessuna dipendenza da un exit ufficiale; percorsi inbound/outbound separati.

**Svantaggi:** non sostituisce il web generale; ecosistema più piccolo; comportamento dei peer di lunga durata; l'outproxy può osservare il browsing pubblico.

**Procedura:** (1) installare dalla fonte ufficiale; (2) usare un contesto dedicato; (3) consentire stabilizzazione di integrazione/banda; (4) accedere a un servizio I2P-native di proprietà; (5) evitare outproxy salvo necessità esplicita; (6) verificare che lo shutdown non produca fallback diretto; (7) ispezionare i log locali di peer e servizio.<sup>[[8]](#references)</sup>

**Rilevamento:** le reti locali vedono traffico peer di lunga durata e comportamento di bootstrap; gli endpoint espongono processi router/applicazione; gli outproxy registrano gli exit.

## Mixnet

**Meccanismi:** pacchetti di dimensione fissa, batching, ritardi, riordino e cover traffic riducono la correlazione temporale; i gateway collegano le applicazioni.

**Vantaggi:** maggiore resistenza alla traffic analysis rispetto ai proxy a bassa latenza; utile per messaggi/transazioni asincroni.

**Svantaggi:** latenza, overhead di banda, deployment più ridotto e limiti applicativi; metadati di gateway/account possono persistere.

**Procedura:** (1) selezionare un client mantenuto e un'applicazione supportata; (2) leggere il threat model effettivo; (3) installare in un compartimento separato; (4) inviare dati innocui a un endpoint di proprietà; (5) misurare latenza/affidabilità e percorso di risposta; (6) testare il failure del gateway; (7) non disabilitare ritardi/cover traffic soltanto per aumentare la velocità.<sup>[[9]](#references)</sup>

**Rilevamento:** gli endpoint identificano il client; le reti di accesso possono classificare gateway/cadenza dei pacchetti; gateway ed exit osservano i ruoli adiacenti, mentre una correlazione più ampia richiede finestre statistiche più lunghe.

## GNUnet anonymous file sharing

**Meccanismi:** GNUnet può instradare richieste di pubblicazione/ricerca/download attraverso peer e aggiungere cover traffic in base a un anonymity level. La documentazione avverte che il livello predefinito 1 non richiede cover traffic e che una traffic analysis potente può identificare l'origine.<sup>[[10]](#references)</sup>

**Vantaggi:** condivisione anonima decentralizzata e nativa per l'applicazione; requisito di cover traffic configurabile.

**Svantaggi:** non è accesso web anonimo ordinario; costi di prestazioni/storage; limiti dei peer e della traffic analysis; la documentazione GNUnet VPN afferma che il suo overlay IP non fornisce un buon anonimato.

**Procedura:** (1) installare una build ufficiale mantenuta; (2) isolare un peer di test; (3) limitare banda/storage; (4) pubblicare un file di test innocuo e univoco con un anonymity level scelto; (5) recuperarlo da un altro peer di proprietà; (6) registrare cover traffic e latenza; (7) non sostenere che il componente IP VPN fornisca un anonimato equivalente.

**Rilevamento:** bootstrap dei peer, traffico overlay, datastore/processo locale e identificatori dei file; un osservatore esteso può analizzare il volume rispetto al cover traffic.

## DNS cifrato, ODoH ed ECH

**Meccanismi:** DoH/DoT/DoQ cifrano verso un resolver; ODoH separa l'indirizzo del client dalla query tra proxy e resolver; ECH cifra il ClientHello TLS interno/nome del server.

**Vantaggi:** rimuove DNS/SNI in chiaro da alcuni osservatori locali; ODoH separa la conoscenza di sorgente/query.

**Svantaggi:** non è un percorso di anonimato IP; resolver/proxy/server conservano i rispettivi ruoli; IP di destinazione, tempistiche/volumi ed endpoint restano; il fallback può causare leak.

**Procedura:** (1) scegliere se il DNS è gestito da OS, applicazione o tunnel; (2) abilitare modalità strict cifrata o ODoH supportato; (3) testare un dominio di proprietà univoco; (4) catturare localmente per confermare l'assenza di query in chiaro; (5) interrompere il resolver e verificare il comportamento previsto; (6) per ECH, confermare dai diagnostici del server l'accettazione del ClientHello interno.<sup>[[11]](#references)</sup>

**Rilevamento:** i log di endpoint/resolver espongono le query; le reti identificano endpoint di resolver cifrati e flussi verso le destinazioni; lo stato ECH è visibile a endpoint/CDN anche quando è nascosto nel percorso.

## Split-provider privacy relay

**Meccanismi:** prodotti come iCloud Private Relay usano un ingresso che conosce il client e un egress gestito indipendentemente che conosce la destinazione, con gestione regionale approssimativa.

**Vantaggi:** separazione della conoscenza con bassa frizione; rapido; protezione DNS/web integrata per il traffico supportato.

**Svantaggi:** scope limitato a prodotto/applicazione; account/platform provider identifica comunque il cliente; non fornisce anonimato arbitrario a livello di sistema; restano rischi di collusione/legali e temporali.

**Procedura:** (1) confermare esattamente applicazioni e tipi di traffico supportati; (2) abilitare la funzione in un contesto di piattaforma dedicato ove appropriato; (3) selezionare il comportamento regionale; (4) testare separatamente Safari/DNS e applicazioni non supportate; (5) ispezionare l'indirizzo visto dalla destinazione; (6) testare cambio/failure della rete.<sup>[[12]](#references)</sup>

**Rilevamento:** l'accesso vede l'ingresso; la destinazione vede l'egress; log di piattaforma/relay e record dell'account coprono il rispettivo livello; le applicazioni non supportate espongono percorsi normali.

## Browser remoto, VDI, RDP o jump host dell'organizzazione

**Meccanismi:** browsing/esecuzione degli strumenti avvengono su un sistema remoto; la destinazione vede il suo egress, mentre il provider del workspace vede la connessione dell'operatore e il control plane.

**Vantaggi:** rapido; isola contenuti rischiosi; egress stabile e controllato; stato temporaneo e audit organizzativo forte.

**Svantaggi:** provider/admin può osservare sessione/account; canali schermo/clipboard/file causano leak; il fingerprint del browser remoto può essere unico; non è anonimo per il proprietario del workspace.

**Procedura:** (1) creare un workspace di proprietà dell'organizzazione per ogni engagement; (2) richiedere MFA e limitare l'amministrazione; (3) disabilitare o limitare clipboard/upload/download; (4) instradare attraverso egress fisso approvato; (5) non usare IdP/sync personali; (6) esportare soltanto evidenze revisionate; (7) distruggere workspace e credenziali secondo pianificazione.

**Rilevamento:** i log di provider e IdP mappano l'utente sulla sessione; le destinazioni raggruppano egress/browser del workspace; i defender enterprise identificano protocolli di controllo remoto e sessioni cloud anomale.

## Wi-Fi pubblico o guest

**Meccanismi:** il traffico esce attraverso il NAT della venue o un tunnel avviato lì.

**Vantaggi:** alta velocità e indirizzo condiviso non domestico; nessuna infrastruttura dedicata.

**Svantaggi:** prove relative a venue/DHCP/portal, telecamere, acquisti e posizione; peer/AP ostili; termini di servizio; rischio fisico.

**Procedura:** (1) ottenere l'accesso offerto agli ospiti e verificare l'SSID con il personale; (2) usare un dispositivo aggiornato e a bassa fiducia; (3) disabilitare condivisione/auto-join e abilitare MAC privato; (4) completare il portal senza identità riutilizzata; (5) avviare un percorso VPN/Tor fail-closed; (6) verificare il traffico tethered; (7) dimenticare la rete.

**Rilevamento:** la venue correla AP, MAC, DHCP, portal e ora; la destinazione vede venue/tunnel; gli investigatori combinano prove fisiche e del dispositivo. Non bypassare mai i controlli di accesso.

## Travel router

**Meccanismi:** un router di proprietà dell'operatore si collega al Wi-Fi/Ethernet della venue e fornisce una rete interna isolata con policy di tunnel imposta.

**Vantaggi:** isola le workstation; kill switch/DNS centralizzati; rete client coerente; protegge gli endpoint privilegiati dai broadcast locali.

**Svantaggi:** il router diventa un fingerprint radio/DHCP stabile; aggiunge superficie d'attacco; captive portal e tethering possono bypassare il tunnel.

**Procedura:** (1) aggiornare il firmware supportato; (2) impostare credenziali di gestione univoche e disabilitare WAN admin/WPS/UPnP; (3) configurare MAC upstream privato ove consentito; (4) creare un SSID interno separato; (5) imporre policy firewall full-tunnel DNS/IPv6; (6) testare portal, riconnessione e failure del tunnel.

**Rilevamento:** la venue vede associazione del router e forma del traffico; il fingerprinting RF/DHCP locale lo identifica; il provider VPN vede la sorgente della venue.

## Cellulare, SIM prepagata ed eSIM

**Meccanismi:** un modem usa l'accesso radio del carrier e normalmente il NAT del carrier; un livello VPN/Tor può modificare l'exit visibile alla destinazione.

**Vantaggi:** indipendente dalla rete cablata/Wi-Fi locale; mobile; alta velocità; utile come backhaul per drop autorizzati.

**Svantaggi:** il carrier conosce abbonato/eSIM, IMSI, IMEI, celle, orari e porte assegnate; le leggi di registrazione variano; la co-locazione con il telefono personale collega i dispositivi.

**Procedura:** (1) ottenere il servizio legalmente con i dati richiesti corretti; (2) usare modem/dispositivo separato di proprietà dell'organizzazione; (3) registrarlo presso il controller dell'esercitazione; (4) disabilitare radio/account non pertinenti; (5) stabilire il tunnel approvato; (6) testare se i client tethered lo seguono realmente; (7) verificare ipotesi su provider e conservazione dei dati prima del viaggio.<sup>[[13]](#references)</sup>

**Rilevamento:** record del carrier e localizzazione RF; inventario enterprise USB/PCI/MDM e rilevamento di rogue hotspot; tempistiche di destinazione/tunnel.

## Internet satellitare e abuso del downlink satellitare

**Meccanismi:** il servizio normale usa un terminale/provider registrato. Il precedente abuso DVB-S unidirezionale consentiva a un ricevitore all'interno di un beam di osservare traffico downlink non cifrato indirizzato a un abbonato legittimo, utilizzando un altro percorso per le richieste outbound.

**Vantaggi:** ampia copertura; ultimo miglio indipendente; l'abuso unidirezionale storico poteva attribuire erroneamente il C2 alla geografia di un abbonato.

**Svantaggi:** record di apparati/RF/provider; latenza e copertura; i sistemi bidirezionali moderni differiscono; il percorso outbound e il routing asimmetrico restano prove.

**Procedura:** per l'accesso lecito, registrare un terminale di proprietà e instradare il traffico attraverso un tunnel secondo necessità. Per emulare il comportamento storico Turla, riprodurre packet capture sintetici unidirezionali in un laboratorio privo di RF e testare se gli analisti rilevano una risposta verso un host che non ha effettuato richieste; non intercettare traffico satellitare live.<sup>[[14]](#references)</sup>

**Rilevamento:** telemetria provider/terminale, radiogoniometria RF, flusso impossibile/asimmetrico, inconsistenza RTT/routing e configurazione malware.

## Proxy residenziale/mobile o proxyware consensuale

**Meccanismi:** un gateway backconnect assegna exit di banda larga mobile/consumer, fissi o rotanti. La fornitura può essere consensuale, inclusa in modo ingannevole o malevola.

**Vantaggi:** alta velocità; scelta geografica; ASN consumer evita alcuni blocchi degli hosting; pool ampi.

**Svantaggi:** rischio di provenienza/consenso e legale; il broker vede il cliente; gli exit infetti danneggiano le vittime; la rotazione crea anomalie; costoso e inaffidabile.

**Procedura:** usare soltanto agenti di proprietà dell'organizzazione, documentati e basati su consenso informato per l'emulazione: (1) registrare endpoint di test; (2) inventariare proprietari/IP; (3) configurare un gateway; (4) ruotare modalità sticky/per-request; (5) inviare soltanto verso un target di proprietà; (6) confrontare log gateway/exit/target; (7) rimuovere ogni agent.

**Rilevamento:** impossible travel, browser/account stabili attraverso rapidi cambi di IP/ASN, protocolli backconnect, artefatti di processo/rete proxyware e relazioni broker/controller.

## ORB, botnet e relay di edge device compromessi

**Meccanismi:** router/IoT/server noleggiati o compromessi formano ruoli di accesso, transito ed exit amministrati come una flotta. Più clienti APT possono condividerla.

**Vantaggi:** reputazione/geografia presa in prestito; exit di breve durata; mesh multi-hop resiliente; debole collegamento diretto tra attore e IP.

**Svantaggi:** vittimizzazione criminale; pattern di implant/controller e della flotta; sequestro dell'intermediario; prestazioni incoerenti; record di operatore/servizio clienti.

**Procedura:** non compromettere mai dispositivi reali. Usare [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain): (1) creare reti isolate di ingresso/transito/target; (2) collegare container relay dual-homed di proprietà; (3) inoltrare una sola porta di test; (4) inviare una richiesta innocua; (5) verificare che il target veda soltanto l'exit; (6) ruotare l'exit; (7) eseguire il teardown di tutti gli asset nominati.<sup>[[15]](#references)</sup>

**Rilevamento:** tracciare topologia, porte/servizi, relazioni del controller, fingerprint degli implant e ciclo di vita dei nodi; centralizzare telemetria di configurazione edge/flusso/integrità; non equiparare l'IP dell'exit all'attore.

## CDN redirector, domain fronting e domainless fronting

**Meccanismi:** un edge pubblico inoltra soltanto il traffico che corrisponde a una grammatica; il fronting utilizza un SNI esterno benigno e una diversa authority HTTP interna, o SNI vuoto, quando l'intermediario lo consente.

**Vantaggi:** nasconde/protegge il back-end; edge globale rapido; confonde la destinazione con un servizio condiviso; cutover rapido.

**Svantaggi:** il CDN vede tutto il routing e il tenant; molti provider vietano il fronting cross-tenant; artefatti SNI/Host/processo/flusso/account; il riutilizzo della configurazione raggruppa le campagne.

**Procedura:** riprodurre soltanto su un reverse proxy di proprietà con [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging): creare certificato/edge locale, instradare un Host non corrispondente verso un target di proprietà, registrare SNI e Host, inviare richieste normali/non corrispondenti, quindi rimuovere i container.<sup>[[16]](#references)</sup>

**Rilevamento:** confrontare SNI/ECH/Host/`:authority` presso endpoint o edge terminante; collegare processo iniziale, tenant/origine, grammatica della richiesta e cadenza del flusso.

## DNS dinamico, DGA, fast flux e double flux

**Meccanismi:** DDNS aggiorna un nome stabile; DGA deriva nomi candidati mutevoli; fast flux ruota gli indirizzi dei servizi con TTL basso; double flux ruota anche i name server.

**Vantaggi:** discovery resiliente; sostituzione rapida dell'infrastruttura; protegge il controller dietro molti nodi.

**Svantaggi:** il DNS crea telemetria centralizzata; entropia/NXDOMAIN/churn; TTL basso e pattern ASN ampi; registrazione e infrastruttura authoritative restano.

**Procedura:** usare [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry): servire una zona di proprietà che restituisca indirizzi RFC 5737 con TTL di cinque secondi, interrogarla ripetutamente, modificare l'epoch sintetico e validare le analytics. Non puntare mai record di test verso terze parti.<sup>[[17]](#references)</sup>

**Rilevamento:** risposte/ASN univoci in finestre scorrevoli, TTL mediano, geografia, churn authoritative, cluster NXDOMAIN/lessicali/temporali DGA e attività successiva del processo; escludere CDN legittimi con il contesto.

## Servizio web legittimo, dead-drop resolver e tasking unidirezionale

**Meccanismi:** un post pubblico, repository, documento, oggetto o feed contiene un endpoint o task corrente codificato. Il client può restituire i risultati attraverso un altro canale.

**Vantaggi:** servizio con reputazione elevata; TLS; rotazione dell'endpoint senza modificare il binario; il tasking asimmetrico ostacola la correlazione semplice dei flussi.

**Svantaggi:** identificatori stabili di oggetto/account/API; record del provider; sequenza decode/follow-on dell'endpoint; il contenuto può essere sequestrato o modificato.

**Procedura:** usare [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence): ospitare un puntatore codificato su un container di proprietà, recuperarlo/decodificarlo da un client di breve durata, contattare un secondo servizio di proprietà, conservare entrambi i log, quindi eseguire il teardown.

**Rilevamento:** correlare processo insolito → lettura di oggetto stabile → decode → nuova destinazione; sottoporre a hash e conservare il contenuto, mantenendo i percorsi completi degli oggetti, non soltanto il dominio.

## Egress serverless, container temporaneo e cloud-NAT

**Meccanismi:** funzioni/job di breve durata vengono eseguiti dietro NAT del provider o un front; il servizio logico resta stabile mentre istanze e indirizzi ruotano.

**Vantaggi:** deployment/distruzione rapidi; egress condiviso su scala provider; poco disco locale; routing regionale elastico.

**Svantaggi:** tenant, ruolo, API, immagine, secret, invocation, billing e log front-to-origin sono duraturi; fingerprint di cold start e piattaforma; policy del provider.

**Procedura:** (1) usare un tenant di esercitazione di proprietà dell'organizzazione; (2) implementare una funzione innocua che richieda soltanto un endpoint di proprietà; (3) registrare progetto/ruolo/immagine/configurazione; (4) invocare attraverso diverse istanze; (5) confrontare IP target con audit/request ID; (6) testare la conservazione dei log; (7) rimuovere funzione, ruoli e secret.

**Rilevamento:** log di audit/invocazione cloud, creazione insolita di ruoli, egress condiviso con grammatica stabile delle richieste, riutilizzo di immagini/layer e secret, correlazione front-origine.

## Drop autorizzato sul posto

**Meccanismi:** un piccolo computer inventariato usa la rete locale cablata/Wi-Fi e rendezvous VPN/cellulare outbound, presentando una sorgente locale.

**Vantaggi:** test realistico da origine interna; alta velocità; consente di testare NAC, inventario fisico e controlli egress.

**Svantaggi:** scoperta/furto fisico; prove seriale/MAC/USB/DHCP/PoE/RF e telecamere; la perdita può esporre credenziali.

**Procedura:** seguire [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md): (1) ottenere autorizzazione scritta precisa al posizionamento; (2) registrare seriale, MAC, foto, posizione e ora di recupero; (3) usare un'immagine minima firmata e credenziali mutual di breve durata; (4) limitare destinazioni/capacità esclusivamente outbound; (5) aggiungere quarantine lato server e limiti di banda; (6) testare visibilità SOC e risposta alla perdita; (7) recuperare, preservare le evidenze necessarie, quindi sanificare secondo la policy concordata. Non nasconderne mai uno in una venue non consenziente.

**Rilevamento:** NAC/802.1X, switchport/PoE/DHCP, inventario USB, survey RF, tunnel ricorrente, ricezione/telecamere e ispezione fisica.

## Pivot wireless nearest-neighbor

**Meccanismi:** un attore controlla un host nella portata radio del target, quindi usa credenziali Wi-Fi del target per attraversare il confine da remoto. APT28 lo ha utilizzato tramite organizzazioni compromesse vicine.<sup>[[18]](#references)</sup>

**Vantaggi:** nessun viaggio dell'operatore; il target vede una sorgente radio locale; aggira controlli applicati soltanto all'ingresso Internet.

**Svantaggi:** richiede un host dual-radio vicino, compromesso o di proprietà, e accesso valido; restano prove RADIUS/NAC/AP e dell'endpoint vicino; anomalie di segnale/dispositivo.

**Procedura:** riprodurre soltanto con il [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot): collegare un pivot di proprietà agli SSID dei laboratori neighbor e target, inoltrare un solo servizio, raccogliere log di entrambi gli AP/pivot, quindi abilitare EAP-TLS/device posture e confermare il fallimento del secondo tentativo.

**Rilevamento:** correlare identità RADIUS, certificato/posture gestito, dispositivo visto per la prima volta, edge/segnale AP, login simultaneo e presenza fisica; cercare endpoint vicini con radio, forwarding e tunnel simultanei.

## Community mesh, delay-tolerant e store-and-forward offline

**Meccanismi:** il traffico attraversa peer locali, gateway asincroni, supporti rimovibili o code pianificate anziché una singola sessione Internet interattiva.

**Vantaggi:** funziona durante interruzioni/censura; la consegna ritardata/batched indebolisce la tempistica semplice; nessun ultimo miglio centrale per la comunicazione locale.

**Svantaggi:** alta latenza; anonymity set ridotto; metadati di custodia/fisici; peer malevoli; i dati raggiungono infine un gateway che li osserva.

**Procedura:** (1) creare una mesh isolata di proprietà a tre nodi o una coda di file; (2) cifrare/autenticare i contenuti end-to-end; (3) rimuovere route Internet dirette dall'origine; (4) inoltrare un file innocuo dopo un ritardo controllato; (5) verificare che soltanto il gateway contatti la destinazione di proprietà; (6) confrontare custodia/timestamp; (7) preservare le evidenze necessarie, quindi sanificare media/code temporanei alla chiusura approvata.

**Rilevamento:** attività di file/processo dell'endpoint, collegamenti radio peer, audit dei supporti rimovibili, periodicità di coda/gateway e identificatori dei contenuti. Finestre di correlazione più lunghe sostituiscono l'analisi dei flussi interattivi.

## Relay TURN e WebRTC forced-relay

**Meccanismi:** Traversal Using Relays around NAT (TURN) assegna un indirizzo relay pubblico e trasporta traffico UDP, TCP o TLS tra client e peer. Una policy ICE può imporre l'uso del relay invece di esporre un candidate diretto. TURN risolve la raggiungibilità, non l'anonimato generale: il server autentica il client e osserva allocazioni, peer, ora e volume.<sup>[[19]](#references)</sup>

**Vantaggi:** ampiamente implementato; gestisce NAT restrittivi; supporta WebRTC mobile; il peer non riceve l'indirizzo di trasporto diretto del client quando la policy relay-only è applicata correttamente.

**Svantaggi:** l'operatore TURN vede entrambi i lati adiacenti; identità applicativa, fingerprint media e signaling restano; relay-only costa banda e latenza; una configurazione errata può comunque raccogliere candidate host o server-reflexive.

**Procedura:** (1) implementare un servizio TURN di proprietà dell'organizzazione con TLS e credenziali di breve durata; (2) limitare realm, peer, porte, quote e scadenza; (3) impostare l'applicazione di test su ICE relay-only; (4) chiamare un peer di proprietà; (5) ispezionare `getStats()` e packet capture per confermare che soltanto i candidate relay trasportino media; (6) interrompere il relay e confermare l'assenza di fallback diretto; (7) conservare i log delle allocazioni per l'engagement.

**Rilevamento:** signaling, processo del browser e allocazioni TURN collegano la sessione al relay; le reti osservano flussi prolungati verso porte TURN o endpoint TLS; il peer vede il relay assegnato. **Nodo catturato:** stato applicativo e credenziali TURN temporanee possono rivelare realm e servizio di rendezvous. Ridurre l'esposizione con credenziali per dispositivo e di breve durata, mantenendo l'autenticazione dell'operatore soltanto presso il controller.

## Rendezvous outbound-only o reverse overlay

**Meccanismi:** un nodo dietro NAT avvia una connessione autenticata verso un broker controllato dall'organizzazione. L'operatore si autentica separatamente al broker, che autorizza un canale di gestione ristretto; non servono port forwarding inbound né una route diretta operatore-nodo.

**Vantaggi:** stabile dietro NAT e ultimi miglia captive; revoca e audit centralizzati; i cambi di indirizzo del field node non richiedono discovery dell'operatore; separa chiaramente l'identità dell'operatore dalla credenziale del nodo.

**Svantaggi:** il broker diventa un punto di correlazione di alto valore; i keepalive periodici sono riconoscibili; un tunnel ampio può diventare un pivot non sicuro; la perdita del broker interrompe la gestione.

**Procedura:** seguire [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous): emettere un'identità dispositivo limitata, consentire soltanto un broker di proprietà e un servizio di gestione approvato, usare keepalive autenticato, imporre il routing fail-closed, testare cambi di indirizzo e recupero dal reboot, quindi revocare l'identità durante il loss drill. WireGuard documenta un persistent keepalive di 25 secondi come intervallo NAT generalmente utile quando effettivamente necessario.<sup>[[20]](#references)</sup>

**Rilevamento:** log di broker e identity provider mappano entrambi i lati; la rete di accesso vede una destinazione/cadenza cifrata ripetuta; l'inventario dell'endpoint mostra l'overlay agent. **Nodo catturato:** presumere esposte chiave del dispositivo, nome del broker, indirizzi del tunnel e task memorizzati. Non deve contenere chiave privata dell'operatore, account personali o token riutilizzabili del controller.

## Mailbox pull, message queue o rendezvous object-store

**Meccanismi:** un workload sul campo interroga una mailbox autenticata per job firmati e pre-approvati e pubblica risultati limitati. L'operatore scrive nella coda attraverso un control plane separato; non esiste un socket interattivo tra i due.

**Vantaggi:** tollera collegamenti intermittenti; disaccoppia tempistiche e indirizzamento; quote e schema possono limitare le capacità; audit e revoca centralizzati semplici.

**Svantaggi:** cadenza del polling e nomi stabili di oggetti/code creano fingerprint del sistema; i log del provider collegano producer e consumer; controllo ritardato; dati accodati catturati possono esporre l'esercitazione.

**Procedura:** (1) creare una coda per engagement e un'identità dispositivo; (2) definire uno schema firmato di job innocui e precisamente limitati; (3) impostare TTL dei messaggi, dimensione massima dei risultati e rate; (4) consentire al nodo di leggere soltanto la propria coda e scrivere soltanto nel proprio prefisso dei risultati; (5) testare accumulo offline, consegna duplicata e revoca; (6) centralizzare log di accesso immutabili; (7) eliminare la coda dopo aver soddisfatto i requisiti di conservazione.

**Rilevamento:** cercare chiamate API periodiche di un processo insolito, percorsi stabili di bucket/object/queue, user-agent o comportamento TLS identici e sequenza fetch-poi-nuova-connessione. **Nodo catturato:** la cache locale può rivelare job pendenti e nomi degli oggetti; mantenere la cache cifrata, limitata e temporanea, preservando i log autorevoli del controller.

## Failover dual-uplink e connection migration

**Meccanismi:** un field node approvato ha due uplink indipendenti, come Ethernet/Wi-Fi della venue e cellulare dell'organizzazione, e mantiene la sessione di controllo attraverso un overlay o message broker mentre cambiano le route. È ingegneria della disponibilità, non anonimato.

**Vantaggi:** sopravvive al failure di un provider, AP o captive portal; supporta manutenzione pianificata; consente il rapido isolamento di un percorso sospetto.

**Svantaggi:** due provider creano due record di posizione/account; l'uso simultaneo facilita la correlazione; leak di route e DNS durante il failover; resta la prova di co-locazione cellulare.

**Procedura:** (1) registrare entrambe le interfacce e i provider di proprietà dell'organizzazione; (2) assegnare priorità di route e health check deterministici verso endpoint di proprietà; (3) vincolare DNS e gestione all'overlay; (4) impedire al percorso secondario di accettare traffico inbound; (5) scollegare ciascun percorso e verificare recupero sessione, policy della sorgente e assenza di accesso diretto alla destinazione; (6) generare alert sui cambi di percorso non pianificati; (7) documentare uso dati e limiti di roaming.

**Rilevamento:** correlare lo stesso certificato dispositivo, grammatica delle richieste e tempistiche tra ASN; l'inventario locale vede entrambe le radio; carrier/venue conservano i propri record. **Nodo catturato:** entrambi gli identificatori SIM/dispositivo e gli SSID conosciuti possono essere visibili; usare asset dell'organizzazione e non associare mai il nodo a dispositivi personali.

## APN privato dell'organizzazione o tunnel cellulare gestito

**Meccanismi:** un APN privato del carrier colloca le SIM registrate in un dominio instradato privato o crea un tunnel verso un gateway enterprise. Separa il dispositivo dall'Internet mobile pubblico, ma non lo nasconde al carrier o all'organizzazione contraente.

**Vantaggi:** indirizzamento privato stabile; enrollment e policy del traffico a livello carrier; evita esposizione inbound pubblica; utile per appliance remote autorizzate.

**Svantaggi:** attribuzione tramite abbonato, IMSI/IMEI, cella e billing; tempi e costi di procurement; failure carrier/gateway; non è anonimo per l'operatore.

**Procedura:** (1) stipulare il contratto APN a nome dell'organizzazione che esegue l'assessment; (2) consentire soltanto SIM registrate e prefissi gateway; (3) aggiungere autenticazione mutual a livello applicativo; (4) limitare la route APN al rendezvous e ai servizi di update; (5) testare rimozione SIM, roaming, breakout verso Internet pubblico e revoca; (6) monitorare record carrier e gateway; (7) annullare o mettere in quarantine ogni SIM alla chiusura.

**Rilevamento:** inventario carrier e telemetria delle celle, flussi del gateway APN, mismatch SIM/IMEI e record degli asset enterprise. **Nodo catturato:** SIM e modem identificano il contratto anche con storage cifrato; la resilienza alla cattura significa quindi sospensione rapida e autorizzazione ristretta, non negabilità.

## Bridge wireless point-to-point a lungo raggio

**Meccanismi:** Wi-Fi direzionale o altra radio point-to-point con licenza o non licenziata collega due siti approvati dai proprietari, con egress Internet presso il sito remoto. Può spostare la posizione IP apparente senza usare un proxy commerciale.

**Vantaggi:** throughput elevato; indipendenza dai carrier cablati intermedi; RF e routing controllabili; utile per testare segmentazione e monitoraggio di siti remoti.

**Svantaggi:** linea di vista, spettro, proprietari e vincoli normativi; emissioni RF e hardware distintivi; entrambi gli endpoint sono prove fisiche; meteo/alimentazione/allineamento influenzano la stabilità.

**Procedura:** (1) ottenere autorizzazione scritta per entrambi i siti e verificare regole su spettro/potenza; (2) esaminare il percorso senza trasmettere fuori dai parametri approvati; (3) usare cifratura autenticata e una management VLAN; (4) limitare il bridge a un rendezvous o subnet di test di proprietà; (5) testare failover, allineamento, recupero dall'alimentazione e contenimento RF; (6) etichettare e inventariare entrambe le radio; (7) rimuoverle e verificare il reset della configurazione dopo l'esercitazione.

**Rilevamento:** survey RF, analisi dello spettro, ispezione rooftop/sito, MAC/OUI del bridge, traffico di gestione e log di egress del sito remoto. **Nodo catturato:** la configurazione rivela il peer e il dominio di gestione; usare credenziali univoche dell'esercitazione, nessun account personale di gestione e revoca rapida della chiave del peer.

## Exit cooperativo o comunitario consensuale

**Meccanismi:** volontari o organizzazioni partner eseguono consapevolmente relay secondo una policy pubblicata. Il traffico esce da un pool comunitario condiviso mentre il livello di coordinamento gestisce abuso e revoca.

**Vantaggi:** reti non-cloud diversificate; il consenso esplicito è più sicuro del proxyware; la governance condivisa può distribuire la fiducia; utile per ricerca e studi sulla resilienza alla censura.

**Svantaggi:** pool ridotti e record di appartenenza diminuiscono l'anonimato; gli operatori degli exit ricevono reclami e osservano metadati del traffico; partecipanti malevoli, uptime variabile e differenze giurisdizionali.

**Procedura:** (1) pubblicare policy di uso accettabile e logging; (2) ottenere opt-in informato da ogni operatore; (3) emettere un'identità relay univoca e limitare destinazioni/rate; (4) fornire gestione degli abusi e revoca con un'azione; (5) inviare soltanto traffico autorizzato verso endpoint di proprietà durante i test; (6) misurare churn ed esposizione alla correlazione; (7) rimuovere correttamente il relay quando termina il consenso.

**Rilevamento:** record di appartenenza/control plane, certificati relay, fingerprint software comune e comportamento dell'exit identificano il pool. **Nodo catturato:** la configurazione del relay può identificare la cooperativa, ma non dovrebbe contenere identità dei client; conservare la responsabilità client-sessione presso il controller autorizzato sotto controllo degli accessi.

## Indirizzi temporanei IPv6 e rotazione dei prefissi

**Meccanismi:** le privacy extension IPv6 creano identificatori temporanei dell'interfaccia affinché un indirizzo stabile non venga riutilizzato per ogni connessione outbound. I cambi di prefisso del provider possono aggiungere rotazione, ma prefisso delegato, record dell'abbonato e fingerprint dei livelli superiori restano.<sup>[[21]](#references)</sup>

**Vantaggi:** riduce il tracking passivo a lungo termine tramite un identificatore stabile dell'interfaccia; integrato nei sistemi operativi comuni; nessun overhead di relay.

**Svantaggi:** non offre anonimato della sorgente; ISP e rete locale conoscono ancora prefisso/dispositivo; DNS, account e stato del browser collegano le sessioni; il churn degli indirizzi complica allowlist e logging.

**Procedura:** (1) ispezionare gli indirizzi stabili e temporanei correnti su un client di proprietà; (2) abilitare il default degli indirizzi privacy supportato dall'OS invece di spoofing di terze parti; (3) richiedere ripetutamente un endpoint IPv6 di proprietà durante i cicli di vita degli indirizzi; (4) confermare che i servizi inbound siano associati soltanto agli indirizzi stabili previsti; (5) conservare log DHCPv6/RA/neighbor ed endpoint precisi; (6) testare comportamento VPN/firewall per ogni indirizzo IPv6.

**Rilevamento:** correlare prefisso delegato, identità layer 2, neighbor discovery, account e telemetria dell'endpoint invece di trattare un indirizzo come un dispositivo. **Nodo catturato:** profili di rete e identificatori delle interfacce restano; l'indirizzamento temporaneo impedisce un identificatore passivo, non l'attribuzione forense.

## Tor pluggable transports: Snowflake, WebTunnel, obfs4 e meek

**Meccanismi:** un pluggable transport modifica l'aspetto della prima connessione Tor o il modo in cui raggiunge un bridge. Snowflake usa proxy WebRTC volontari di breve durata, WebTunnel assomiglia a HTTPS ordinario, obfs4 resiste alla semplice identificazione del protocollo e al probing attivo, mentre meek inoltra attraverso infrastruttura web supportata. Sono transport di circumvention verso Tor, non livelli aggiuntivi di anonimato end-to-end.<sup>[[22]](#references)</sup>

**Vantaggi:** utili quando Tor diretto o relay noti sono bloccati; Snowflake evita un indirizzo pubblico stabile del bridge; integrati nei client Tor mantenuti; la destinazione riceve comunque le proprietà ordinarie di Tor.

**Svantaggi:** prestazioni inferiori o variabili; broker/front/bridge e rete locale osservano metadati diversi; fingerprint di trasporto e blocchi restano possibili; il proxy volontario non sostituisce Tor e non deve essere considerato affidabile per il plaintext applicativo.

**Procedura:** (1) installare e verificare Tor Browser ufficiale o un client Tor supportato; (2) selezionare il transport integrato in Connection/Bridges; (3) connettersi soltanto a una pagina diagnostica di proprietà; (4) confermare che la pagina veda un exit Tor, non il peer Snowflake/WebTunnel; (5) confrontare bootstrap e prestazioni; (6) interrompere il transport e confermare che il client non si connetta direttamente in modo silenzioso; (7) tornare alla configurazione standard supportata dopo il test.

**Rilevamento:** un censor può combinare allowlist delle destinazioni, comportamento TLS/WebRTC, discovery del broker e analisi del flusso; gli endpoint espongono Tor e la configurazione del transport. **OPSEC resiliente alla cattura:** usare il client standard, non copiare mai in esso lo stato del browser personale e presumere recuperabile la cronologia di bridge/broker. **Monitoraggio:** osservare i log di bootstrap Tor, tentativi DNS/connessione diretti inattesi e osservazioni della pagina di proprietà lato controller; il fallimento del transport non prova la discovery.

## Refraction networking o decoy routing

**Meccanismi:** un network operator cooperante rileva un segnale occulto in traffico apparentemente indirizzato a un decoy consentito e devia il flusso verso un proxy di circumvention. Il deployment richiede infrastruttura nel percorso di rete; non è qualcosa che un client possa creare semplicemente selezionando un sito innocente.<sup>[[23]](#references)</sup>

**Vantaggi:** la destinazione apparente può essere difficile da bloccare per un censor senza danni collaterali; non è necessario distribuire un indirizzo pubblico del bridge; utile come modello di ricerca per la circumvention assistita on-path.

**Svantaggi:** partecipazione specializzata di ISP/transit; implementabilità e prestazioni dipendono dal routing; flusso client-decoy e attività lato proxy restano; un osservatore globale o cooperante può correlare le tempistiche.

**Procedura:** non inviare segnali attraverso reti non coinvolte. Riprodurre l'architettura in un laboratorio isolato: (1) creare namespace di proprietà per client, router, decoy e proxy; (2) usare una richiesta di test benignamente marcata; (3) lasciare che il router di proprietà reindirizzi soltanto quel tag al proxy; (4) registrare tuple e request ID pre/post-routing; (5) confrontare flussi normali e segnalati; (6) testare falsi positivi e rimozione; (7) distruggere le route del laboratorio.

**Rilevamento:** i network operator autorizzati possono ispezionare divergenza del routing, comportamento insolito di ClientHello/tag e discrepanze tra flussi decoy e back-end. **OPSEC resiliente alla cattura:** un client di ricerca dovrebbe contenere soltanto chiavi di test e indirizzi documentali. **Monitoraggio:** confrontare decisioni firmate del router di laboratorio con gli arrivi al proxy; non sondare provider transit di produzione per determinare se abbiano rilevato il signaling.

## Gateway content-addressed o recupero da peer in cache

**Meccanismi:** un gateway HTTP recupera un content identifier (CID) IPFS, eventualmente dalla propria cache o da peer, e restituisce il contenuto verificabile al client. Il publisher originale può vedere il gateway o altri peer invece del lettore finale; il gateway vede l'IP del lettore e il CID richiesto. Il recupero peer-to-peer nativo espone il client a peer e partecipanti DHT/routing.<sup>[[24]](#references)</sup>

**Vantaggi:** publisher e lettore possono essere separati dalle cache; il contenuto immutabile è verificabile tramite hash; i dati replicati sopravvivono alla perdita di un host; i client HTTP non richiedono uno stack peer nativo.

**Svantaggi:** CID pubblici e log del gateway rivelano gli interessi; la tempistica del primo recupero può correlare publisher e lettore; contenuti web malevoli e rischi same-origin dei percorsi; i gateway pubblici sono best-effort e vietano gli abusi.

**Procedura:** (1) pubblicare un file di test innocuo su una private IPFS swarm o gateway di proprietà; (2) registrare il CID; (3) recuperarlo attraverso un gateway HTTP distinto usando isolamento tramite subdomain; (4) verificare i byte rispetto al CID; (5) ripetere dopo il caching; (6) confrontare log di publisher, peer e gateway; (7) eseguire unpin e rimuovere il contenuto di test alla scadenza della conservazione.

**Rilevamento:** i gateway registrano sorgente/CID; connessioni DHT e peer rivelano il recupero; cronologia dell'endpoint e hash dei file identificano il contenuto. **OPSEC resiliente alla cattura:** non conservare chiavi private di publishing su un field client read-only e cifrare i contenuti sensibili prima del content addressing. **Monitoraggio:** generare alert su pinning inatteso, cambi del peer set, richieste CID fuori allowlist o notifiche dell'account gateway.

## Servizio di private information retrieval

**Meccanismi:** Private Information Retrieval (PIR) consente a un client di recuperare un record da un database nascondendo crittograficamente al server l'indice selezionato, secondo un threat model single-server o multi-server dichiarato. Protegge la selezione della query per un dataset limitato; non è accesso web generale né anonimato IP.<sup>[[25]](#references)</sup>

**Vantaggi:** forte privacy della query specifica per applicazione; modello di leakage misurabile; utile per directory di chiavi, blocklist o piccoli database pubblici; può ridurre la necessità di rivelare i termini esatti della ricerca.

**Svantaggi:** overhead computazionale/di banda; il server conosce ora/IP della connessione salvo combinazione con un relay; versione del dataset, dimensione della risposta e stato applicativo possono partizionare gli utenti; maturità dell'implementazione variabile.

**Procedura:** (1) implementare una soluzione PIR verificata contro un database sintetico di proprietà; (2) pubblicare versione e parametri del dataset; (3) recuperare diversi indici tramite richieste di dimensione identica; (4) verificare localmente la correttezza; (5) confrontare i log del server e confermare l'assenza dell'indice; (6) testare risposte malevole/troncate e mismatch di versione; (7) documentare l'ipotesi precisa sulla privacy invece di definirla browsing anonimo.

**Rilevamento:** le reti vedono uso e volume del servizio; la telemetria dell'endpoint espone il client e l'uso del record finale; un server compromesso può manipolare dataset o tempistiche. **OPSEC resiliente alla cattura:** conservare sul client soltanto parametri pubblici del database e una cache limitata. **Monitoraggio:** validare root firmate del dataset, forme fisse delle richieste, cambi del tasso di errore e rotazioni delle chiavi server.

## Fetcher, preview o rendering service lato server limitato

**Meccanismi:** un servizio remoto recupera o renderizza un URL e restituisce screenshot, metadati o contenuto sanificato. La destinazione vede l'indirizzo del fetcher; il servizio vede requester, URL e risultato. Abusare di bot di link-preview, security scanner o URL fetcher di terze parti non costituisce uso autorizzato di un proxy.

**Vantaggi:** isola i contenuti attivi dalla workstation; la destinazione riceve un fingerprint controllato del fetcher; consente limiti su tipo file, dimensione, destinazione e rendering; ambiente di esecuzione temporaneo.

**Svantaggi:** il servizio conosce completamente la richiesta; record di account/API/billing; rischio SSRF ed esfiltrazione dati; script, autenticazione e siti interattivi possono non funzionare; URL univoci correlano requester e fetch.

**Procedura:** (1) implementare un fetcher di proprietà dell'organizzazione con allowlist rigida di domini di test di proprietà; (2) bloccare indirizzi privati, link-local, metadata e redirect verso indirizzi non approvati; (3) limitare metodi, redirect, byte e tempo di rendering; (4) rimuovere credenziali/cookie; (5) inviare un URL di proprietà; (6) confrontare log requester/fetcher/target; (7) distruggere l'istanza di rendering e conservare l'audit centrale secondo policy.

**Rilevamento:** il target vede ASN/fingerprint del servizio; log di provider e controller mappano requester e URL; processo endpoint/chiamate API mostrano l'invio. **OPSEC resiliente alla cattura:** usare un solo token di progetto di breve durata senza autorità su destinazioni arbitrarie. **Monitoraggio:** alert su rifiuti dell'allowlist, violazioni dei redirect, fetch senza controller job ID e notifiche di abuso del provider.

## Anycast rendezvous pool

**Meccanismi:** più nodi controllati dall'organizzazione pubblicizzano o presentano un unico indirizzo di servizio stabile, e il routing seleziona un'istanza vicina. Anycast migliora la disponibilità e nasconde al client un singolo back-end, ma l'operatore controlla tutte le istanze e l'indirizzo del servizio resta stabile.<sup>[[26]](#references)</sup>

**Vantaggi:** ingresso regionale resiliente; nessuna riconfigurazione del field node quando un'istanza fallisce; distribuzione DDoS/carico; la policy centrale può spostare le sessioni tra nodi noti.

**Svantaggi:** record BGP/CDN e provider identificano l'organizzazione; i cambi di percorso possono interrompere sessioni stateful; il monitoraggio varia in base alla posizione del client; un singolo indirizzo stabile è facile da bloccare o raggruppare per reputazione.

**Procedura:** usare un progetto dell'organizzazione supportato dal provider o un laboratorio di routing isolato: (1) implementare due health endpoint autenticati identici; (2) esporre un indirizzo di servizio documentato; (3) mantenere lo stato della sessione presso il broker e non presso l'edge; (4) ritirare un nodo e verificare la riconnessione; (5) testare coerenza di certificati, policy e log; (6) generare alert su origine/regione non autorizzata; (7) rimuovere advertisement e credenziali alla chiusura.

**Rilevamento:** BGP/RPKI/history, tenancy del provider, certificati e comportamento identico del servizio identificano il pool. **OPSEC resiliente alla cattura:** un edge conserva soltanto l'identità regionale del servizio e nessuna chiave dell'operatore o di enrollment della flotta. **Monitoraggio:** sondare ogni regione da monitor autorizzati, confrontare origine della route e digest della configurazione, e trattare un'origine inattesa come incidente.

## Migrazione QUIC e continuità Multipath TCP

**Meccanismi:** i connection ID QUIC possono mantenere viva una sessione client durante rebinding NAT o cambi di indirizzo; Multipath TCP può trasportare un singolo byte stream affidabile su più subflow. Migliorano la continuità durante passaggi Wi-Fi/cellulare, ma espongono i percorsi vecchi e nuovi allo stesso peer e possono facilitare la correlazione cross-path.<sup>[[27]](#references)</sup>

**Vantaggi:** recupero più rapido durante cambi di uplink; la sessione applicativa non deve ripartire; MPTCP può combinare resilienza e throughput; prezioso per field node approvati.

**Svantaggi:** non è anonimato; il peer vede migrazione/subflow; connection ID e traffico simultaneo collegano i percorsi; supporto middlebox/carrier variabile; record duplicati dei provider aumentano l'esposizione.

**Procedura:** (1) abilitare il transport supportato soltanto tra un field client di proprietà e il rendezvous; (2) autenticare l'applicazione indipendentemente dall'IP; (3) avviare un trasferimento limitato su Wi-Fi approvato; (4) passare alla rete cellulare dell'organizzazione; (5) confermare validazione del percorso, integrità dei dati e assenza di fallback in chiaro/diretto; (6) testare idle timeout e ritorno; (7) conservare presso il broker i record di ogni transizione del percorso.

**Rilevamento:** il peer osserva direttamente migrazione dell'indirizzo o subflow MPTCP; gli access provider vedono la propria parte; connection ID, identità TLS e tempistiche collegano entrambi. **OPSEC resiliente alla cattura:** conservare soltanto materiale di sessione limitato al dispositivo e far scadere rapidamente lo stato resumable. **Monitoraggio:** alert su cambi di percorso impossibili, reti non approvate simultanee, migration storm e resume dopo quarantine.

## Egress di managed CI/CD o ephemeral automation runner

**Meccanismi:** un workflow di proprietà dell'organizzazione esegue un controllo di rete limitato su un runner hosted. La destinazione vede un indirizzo cloud del runner, mentre la piattaforma conserva attribuzione a repository, attore, workflow, token, log e billing. È esecuzione remota con egress tracciabile, non anonimato dal provider.<sup>[[28]](#references)</sup>

**Vantaggi:** ambiente pulito temporaneo; definizione del job riproducibile; nessuna connessione inbound; utile per controlli di disponibilità distribuiti geograficamente; audit forte del controller.

**Svantaggi:** piattaforma e organizzazione identificano l'iniziatore; token ampi del workflow e pull request non affidabili sono pericolosi; reputazione IP condivisa; log/artifact possono conservare secret o dati del target.

**Procedura:** (1) creare repository e ambiente privati dell'organizzazione per l'assessment; (2) consentire soltanto job benigni, fissi e approvati manualmente contro endpoint di proprietà; (3) usare permessi workflow minimi read-only e nessun secret di produzione; (4) eseguire il controllo; (5) confrontare record di workflow, provider e target; (6) verificare che gli artifact non contengano credenziali; (7) eliminare il token dell'ambiente e conservare l'audit necessario.

**Rilevamento:** audit del provider e log del workflow forniscono attribuzione diretta; i target identificano ASN/range dei runner e grammatica stabile delle richieste. **OPSEC resiliente alla cattura:** non inserire mai secret di field device, signing, wallet o cloud administrator nelle variabili del runner. **Monitoraggio:** richiedere approvazione di branch/ambiente e generare alert su modifiche del workflow, esecuzione da fork, accesso ai secret e destinazioni inattese.

## Primo hop locale non-IP verso un gateway di proprietà

**Meccanismi:** Bluetooth mesh, Wi-Fi Aware/Direct, radio low-power o collegamento seriale/ottico trasportano messaggi limitati da un sensore vicino a un gateway Internet approvato dal proprietario. Il field device non ha alcuna route Internet; il gateway è l'unico egress. Portata radio e limiti del protocollo rendono questo un design di telemetria/store-and-forward, non Internet interattivo anonimo.

**Vantaggi:** rimuove stack Internet e credenziali dal più piccolo dispositivo sul campo; basso consumo; il gateway centralizza la policy; può attraversare zone temporaneamente isolate.

**Svantaggi:** discovery RF/fisica, pairing e identificatori del dispositivo; banda e portata ridotte; il gateway collega tutti i messaggi; restrizioni su spettro e cifratura variabili; la cattura può esporre dati accodati.

**Procedura:** (1) ottenere approvazione del sito e dello spettro; (2) associare un sensore di proprietà a un gateway di proprietà usando chiavi univoche; (3) definire tipi di messaggio firmati, di dimensione fissa, con TTL e rate; (4) non assegnare al sensore alcuna route IP predefinita; (5) consentire al gateway di inoltrare soltanto verso un collector di proprietà; (6) testare replay, perdita di portata e outage del gateway; (7) inventariare e recuperare entrambi i dispositivi.

**Rilevamento:** survey RF, database di pairing, ispezione fisica e log di processo/flusso del gateway rivelano il percorso. **OPSEC resiliente alla cattura:** il sensore contiene soltanto la chiave pairwise e una coda cifrata limitata, mai credenziali dell'operatore, Wi-Fi, cellulare o controller. **Monitoraggio:** alert su nuovi peer, rollback della sequenza, failure della chiave, rate RF insolito e messaggi arrivati attraverso un gateway non registrato.

## Matrice di esposizione a cattura/compromissione

Questa tabella applica un controllo di resilienza alla cattura a ogni famiglia precedente. “Ridurre al minimo” significa ridurre secret e blast radius sugli asset autorizzati; non significa mai cancellare prove o nascondersi da un'indagine.

| Famiglia di tecniche | Cosa può rivelare un endpoint/relay catturato | Controllo autorizzato minimo |
|---|---|---|
| NAT/CGNAT, Wi-Fi pubblico, travel router | reti note, cronologia DHCP/portal, MAC, peer del tunnel | dispositivo separato dell'organizzazione; MAC privato ove supportato; nessun account personale; inventario del controller |
| VPN, VPS, HTTP/SOCKS/SSH, multi-hop | provider/hostname, chiavi, route, log e hop adiacenti | un'identità per engagement; TTL breve; route ristrette; revoca lato broker; nessuna master key |
| OHTTP/ODoH, MASQUE, split-provider relay | configurazione relay/gateway, identificatori applicativi e richieste in cache | ridurre gli identificatori del payload; bloccare la config approvata; cache limitata; nessun fallback diretto |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | software installato, materiale bridge/onion, stato locale e cronologia dei peer | client standard; chiavi di servizio separate; stato minimo cifrato; ruotare l'identità del servizio compromessa |
| Browser remoto/VDI/jump host | token workspace, clipboard/file e tenant remoto | MFA resistente al phishing presso il gateway; canali di trasferimento disabilitati; revoca rapida della sessione |
| Cellulare, satellite, APN privato | SIM/eSIM, identità IMEI/terminale, provider e posizione approssimativa | contratto dell'organizzazione; nessuna co-locazione personale; policy APN/overlay ristretta; runbook di sospensione provider |
| Proxy residenziale/cooperativo, ORB lab | identità dell'agent, controller/next hop, traffico in cache | soltanto nodi consensuali/di proprietà; agent firmato; credenziale per nodo; mapping dei partecipanti presso il controller |
| CDN/fronting, fast flux, serverless | tenant/origine/configurazione, token API, riferimenti deployment/billing | progetto dedicato; ruolo least-privilege; deploy token breve; audit provider conservato centralmente |
| Dead drop, pull mailbox, store-and-forward | nomi oggetti, coda, job/risultati in cache e dati di custodia | job firmati e limitati; TTL; cache cifrata; identità producer separata; log server immutabili |
| Drop, nearest-neighbor, bridge long-range | seriale/radio/SSID/peer, chiave dispositivo, artefatti fisici di posizionamento | posizionamento scritto; identità dispositivo univoca; nessun secret operatore; telemetria tamper/stato; revoca e recupero |
| TURN, reverse overlay, dual-uplink | realm/broker, credenziale dispositivo, peer/route e profili uplink | servizio ristretto outbound-only; credenziale breve del dispositivo; login operatore indipendente; percorsi fail-closed |
| Indirizzamento temporaneo IPv6 | profili, cronologia del prefisso e stato endpoint/applicazione | trattarlo soltanto come anti-tracking; conservare log di rete; abbinarlo a compartimentazione dell'endpoint |
| Pluggable transport/refraction lab | impostazioni bridge/broker/decoy, stato Tor e chiavi di ricerca | client standard o laboratorio isolato; nessuno stato browser personale; nessun signaling di produzione |
| IPFS/PIR/fetcher | CID/query richiesto dal client, contenuti in cache, token gateway/servizio | cache cifrata e limitata; soli parametri pubblici; token di servizio breve e allowlisted |
| Anycast/QUIC/MPTCP | nodi servizio, connection ID, stato resumable e ogni percorso noto | identità soltanto regionale; breve durata del resume; revoca centrale di route/sessione |
| Managed CI/CD runner | repository, workflow, token provider, log e artifact | workflow least-privilege; nessun secret di produzione/field/wallet; approvazione dell'ambiente |
| Hop locale non-IP | peer radio, chiave pairwise, messaggi in coda e identità gateway | chiave pairwise univoca; schema messaggi fisso; nessuna credenziale Wi-Fi/cellulare/operatore |

## Monitoraggio della possibile discovery per ogni famiglia di accesso

Nessun test lato client prova che un investigatore o defender stia osservando. Monitorare i cambiamenti nei sistemi controllati dall'engagement, corroborarli con controller/client e fermarsi invece di sondare gli osservatori. Le righe seguenti coprono ogni tecnica precedente; combinarle con gli [stati di alert del field node e il runbook di risposta](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise).

| Tecniche coperte | Segnali sicuri lato controller | Condizione di quarantine/stop |
|---|---|---|
| NAT/CGNAT, Wi-Fi pubblico/guest, travel router, cellulare/eSIM, satellite, APN privato | sessione lease/portal/carrier, tupla pubblica, cambio BSSID/cella/percorso, notifica provider | rete/SIM/dispositivo non approvato, spostamento inspiegato o escalation provider/SOC |
| VPN/VPS, HTTP/SOCKS/SSH, multi-hop, proxy residenziale/cooperativo | autenticazione peer, stato tunnel, leak route/DNS, nuovo evento admin/API, reclamo | credenziale duplicata/rubata, amministratore sconosciuto, fallback diretto o egress fuori scope |
| OHTTP/ODoH/ECH, MASQUE, split-provider relay, TURN | allocazione relay/gateway, versione chiave/config, connessione diretta non supportata, tasso errori/replay | mismatch chiave, fallback diretto, realm/peer sconosciuto o notifica di abuso del provider |
| Tor Browser, bridge, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, onion service | stato bootstrap, failure circuito, descriptor onion/stato del servizio e pagina canary di proprietà | crossover con account personale, connessione non-Tor inattesa o chiave servizio compromessa |
| I2P, mixnet, GNUnet, mesh/store-forward, hop locale non-IP | peer set, età/sequence della coda, arrivo gateway, associazione radio e hash contenuto | peer/gateway sconosciuto, rollback della sequenza, contenuto non autorizzato o record di custodia mancante |
| Browser remoto/VDI/jump host, CI/CD runner, serverless | sessione IdP, cambio workflow/immagine/config, nuovo uso token, artifact/export e audit cloud | login/modifica workflow sconosciuti, accesso a secret, destinazione inattesa o escalation di ruolo/progetto |
| ORB lab, fast flux/DGA, CDN/fronting, dead drop/pull mailbox | inventario nodi di proprietà, accesso DNS/edge/oggetto, grafo controller, firma job e TTL | nodo/origine/oggetto writer sconosciuto, job non firmato/replayed, topology escape dal laboratorio |
| Drop/nearest-neighbor/bridge long-range/outbound overlay/dual uplink | heartbeat firmato, hash boot/config, stato enclosure, contesto AP/switch, identità duplicata | nodo spostato/aperto, boot/hash/percorso inatteso, uso sentinel o report del sito |
| Indirizzi temporanei IPv6, migrazione QUIC, MPTCP | prefisso delegato, connection ID/subflow, validazione percorso e sessione broker | migrazione impossibile, percorsi simultanei non approvati o resume sessione dopo revoca |
| IPFS/cache, PIR, fetcher limitato | CID/forma query/versione root, cambio peer/gateway, rifiuto redirect/allowlist | pin/query/destinazione inattesa, root dataset non firmata o notifica abuso provider |
| Refraction/decoy-routing lab, rendezvous anycast | decisione diversion di proprietà, arrivo proxy, origine BGP/RPKI, digest config regionale | segnale sul percorso di produzione, origine route sconosciuta, incoerenza regionale/configurativa |

## Scelta e test di un percorso

1. Nominare l'osservatore da rimuovere e i dati da nascondere.
2. Selezionare la famiglia meno complessa che lo rimuove.
3. Disegnare osservatori di sorgente, ingresso, transito, uscita, DNS, account e pagamento.
4. Usare un'identità separata per endpoint/applicazione.
5. Verificare bypass IPv4, IPv6, DNS, WebRTC/applicazione e vista della destinazione.
6. Interrompere ogni hop e confermare che il failure sia chiuso.
7. Confrontare i log di ogni componente controllato.
8. Registrare i collegamenti residui temporali, provider, endpoint e fisici.

## References

- [1] [EFF — La VPN giusta per te](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [RFC 9458 — HTTP Oblivious](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [RFC 9298 — Proxying UDP in HTTP](https://www.rfc-editor.org/rfc/rfc9298.html) and [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [4] [Tor Project — Protezioni di Tor](https://support.torproject.org/about-tor/introduction/protections/) and [Tor specification introduction](https://spec.torproject.org/intro/)
- [5] [Tor Project — Sbloccare Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [6] [Tor Project — Usare Tor Browser con una VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [7] [Tor Project — Panoramica degli onion service](https://community.torproject.org/onion-services/overview/)
- [8] [I2P — Threat model](https://www.i2p.net/en/docs/overview/threat-model/)
- [9] [Katzenpost — Threat model](https://katzenpost.network/docs/threat_model/)
- [10] [GNUnet — Condivisione anonima di file](https://docs.gnunet.org/master/users/fs.html) and [GNUnet VPN limitations](https://docs.gnunet.org/latest/users/vpn.html)
- [11] [RFC 9230 — Oblivious DoH](https://www.rfc-editor.org/rfc/rfc9230.html) and [RFC 9849 — Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [12] [Apple Platform Security — Sicurezza di iCloud Private Relay](https://support.apple.com/guide/security/secad8ce3233/web)
- [13] [GSMA — Registrazione obbligatoria delle SIM](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [15] [Google Cloud/Mandiant — Attori di spionaggio China-nexus usano reti ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [16] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [17] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [18] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [19] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [20] [WireGuard — Quick Start: persistenza NAT e firewall traversal](https://www.wireguard.com/quickstart/)
- [21] [RFC 8981 — Estensioni degli indirizzi temporanei per la Stateless Address Autoconfiguration in IPv6](https://www.rfc-editor.org/rfc/rfc8981.html)
- [22] [Tor Project — Pluggable transport e bridge](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/) and [Using Snowflake](https://support.torproject.org/anti-censorship/how-can-i-use-snowflake/)
- [23] [Refraction Networking — Ricerca sul progetto e sul deployment](https://refraction.network/) and [Running Refraction Networking for Real](https://refraction.network/papers/deployment-pets20.pdf)
- [24] [IPFS — Concetti dei gateway HTTP e ciclo di vita delle richieste](https://docs.ipfs.tech/concepts/ipfs-gateway/)
- [25] [IETF PEARG — Panoramica del Private Information Retrieval](https://datatracker.ietf.org/meeting/121/materials/slides-121-pearg-call-me-by-my-name-simple-practical-private-information-retrieval-for-keyword-queries-00)
- [26] [RFC 4786 — Funzionamento dei servizi Anycast](https://www.rfc-editor.org/rfc/rfc4786.html)
- [27] [RFC 9000 — Migrazione delle connessioni QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) and [RFC 8684 — Multipath TCP](https://www.rfc-editor.org/rfc/rfc8684.html)
- [28] [GitHub — Riferimento ai runner hosted da GitHub](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
