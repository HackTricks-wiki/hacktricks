# Catalogo delle tecniche per l'accesso anonimo a Internet

{{#include ../banners/hacktricks-training.md}}

Questo è l'inventario canonico dei percorsi di accesso. Copre le **famiglie** di protocolli e operative, non ogni nome di vendor. Nessun percorso Internet garantisce l'anonimato: account, browser, endpoint, tempistiche, pagamenti, control plane cloud e prove fisiche possono compromettere anche un percorso apparentemente perfetto.

Ogni voce usa gli stessi campi. “Procedura” indica un'implementazione lecita o un'emulazione in un lab di proprietà. Quando la tecnica reale dipende dal compromettere un router, rubare l'accesso o abusare di un intermediario non consenziente, la riproduzione sostituisce tali sistemi con sistemi di proprietà dell'esercitazione.

## Matrice di copertura

| Famiglia | Cosa vede la destinazione | Proprietà più forte | Velocità | Trattamento |
|---|---|---|---|---|
| Shared NAT/CGNAT | indirizzo pubblico condiviso | ambiguità tra abbonati | alta | implementabile |
| VPN, VPS, proxy SOCKS/HTTP/SSH | indirizzo del relay | rapida separazione dell'indirizzo sorgente | alta | implementabile |
| Multi-hop/split relay, MASQUE | proxy finale | separazione della conoscenza o tunnel IP completo | alta/moderata | implementabile con relay affidabili |
| Tor, bridge, onion service | exit o identità onion | percorso multiparte e browser comune | moderata | implementabile |
| I2P, GNUnet, mixnet | peer/gateway overlay | overlay o resistenza all'analisi temporale | bassa/variabile | specifico per applicazione |
| OHTTP/ODoH, Private Relay | gateway/egress | partizionamento sorgente/richiesta | alta | solo applicazioni supportate |
| Wi-Fi pubblico, travel router | indirizzo della sede/tunnel | cambio di posizione/percorso di accesso | alta | richiede autorizzazione |
| Cellulare/eSIM, satellite | indirizzo carrier/provider | uplink fisico indipendente | alta/variabile | osservato dall'abbonamento/provider |
| Browser remoto/jump host | workspace remoto | separazione di endpoint ed egress | alta | implementabile |
| Proxy residenziale/mobile | indirizzo consumer/carrier | aspetto di rete consumer | alta | consenso/provenienza critici |
| ORB/relay compromesso | indirizzo di un'altra vittima | occultamento dell'origine e reputazione presa in prestito | alta | solo riproduzione in lab di proprietà |
| CDN/fronting/redirector | indirizzo front della CDN | protezione dell'infrastruttura back-end | alta | richiede approvazione di provider/proprietario |
| Fast flux/DGA/dead drop | nodo/servizio rotante | resistenza alla scoperta dell'infrastruttura | variabile | solo riproduzione in lab di proprietà |
| Drop/nearest-neighbor | indirizzo adiacente al target | attraversamento di un confine geografico/di rete | alta | solo lab su siti di proprietà |
| Store-and-forward/offline | gateway o ricevitore fisico | riduzione del collegamento temporale interattivo | bassa | specifico per applicazione |
| Pluggable/refraction transport | ingresso Tor o proxy diversion cooperante | raggiungibilità resistente alla censura | variabile | client supportato o lab di ricerca |
| Gateway IPFS/PIR/remote fetcher | gateway o servizio applicativo | separazione publisher/query/richiesta | variabile | solo applicazioni circoscritte |
| Anycast/QUIC/MPTCP | broker stabile o più subflow | rendezvous e continuità della sessione | alta | disponibilità, non anonimato |
| Runner di automazione CI/CD | indirizzo del runner hosted | egress effimero e attribuibile | alta | solo workflow di proprietà |
| Primo hop locale non-IP | gateway dell'organizzazione | rimozione dello stack Internet dal sensore | bassa | implementazione approvata dal proprietario |

## NAT condiviso diretto e NAT carrier-grade

**Meccanica:** più utenti condividono un indirizzo pubblico; l'access provider associa indirizzi e porte lato abbonato alla tupla pubblica.

**Vantaggi:** rapido; nessun client speciale; il solo IP lato destinazione può identificare soltanto una casa, una sede o un pool del carrier.

**Svantaggi:** il provider può conservare le associazioni abbonato/porta/ora; account e fingerprint restano; altri utenti possono danneggiare la reputazione dell'indirizzo.

**Procedura:** (1) confermare se l'accesso autorizzato usa NAT/CGNAT; (2) registrare IP pubblico esatto e porta sorgente presso un endpoint di proprietà; (3) mantenere separata l'identità delle applicazioni; (4) non trattare l'indirizzamento condiviso come controllo di privacy; (5) usare un percorso più forte se l'ISP non deve conoscere le destinazioni.

**Rilevamento:** le destinazioni dovrebbero conservare porta sorgente e ora precisa, non solo l'IP. I provider correlano i log di allocazione NAT; gli investigatori uniscono prove relative ad account, dispositivo e browser.

## VPN commerciale

**Meccanica:** una connessione full-tunnel cifrata termina presso la VPN; le destinazioni vedono il suo egress. La VPN può normalmente associare sorgente, tempistiche e destinazioni.

**Vantaggi:** rapida; semplice; protegge dall'osservazione passiva locale; exit stabili o condivisi; utile per l'egress controllato dei red team.

**Svantaggi:** fiducia concentrata; telemetria di fatturazione/login; errori di kill-switch/DNS/IPv6; gli exit condivisi sono spesso bloccati per reputazione.

**Procedura:** (1) identificare provider, proprietario, giurisdizione, conservazione dei dati e policy di assessment; (2) installare il client ufficiale firmato; (3) abilitare full tunnel, always-on e comportamento fail-closed; (4) instradare deliberatamente DNS e IPv6; (5) verificare IPv4/IPv6/DNS osservati presso un endpoint di proprietà; (6) arrestare/riconnettere il tunnel e confermare l'assenza di fallback in chiaro.<sup>[[1]](#references)</sup>

**Rilevamento:** le reti locali vedono un flusso cifrato prolungato verso l'infrastruttura VPN; i provider dispongono dei record di autenticazione/connessione; le destinazioni usano ASN/reputazione insieme a correlazioni di account, TLS/browser e comportamento.

## Egress VPN self-hosted o VPS noleggiato

**Meccanica:** l'operatore controlla un gateway WireGuard/OpenVPN o inoltra il traffico tramite un server noleggiato.

**Vantaggi:** velocità elevata prevedibile; indirizzo fisso inseribile in allowlist; logging/firewall personalizzati; buon controllo degli incidenti.

**Svantaggi:** anonymity set ridotto; tenant cloud, pagamenti, login sorgente, API e cronologia delle immagini collegano l'operatore; un server nuovo e distintivo è facile da raggruppare.

**Procedura:** (1) creare un project dell'organizzazione dedicato all'engagement; (2) fornire un'immagine supportata e un indirizzo fisso; (3) limitare la gestione ad amministrazione basata su MFA/chiavi; (4) configurare egress full-tunnel e DNS; (5) consentire solo destinazioni circoscritte quando pratico; (6) testare comportamento di leak/failure; (7) conservare i record di audit del controller; (8) distruggere credenziali e risorse al teardown.

**Rilevamento:** correlare ASN di hosting, indirizzo visto per la prima volta, fingerprint di certificato/servizio e comportamento di scanning; i proprietari cloud usano log del control plane, console, fatturazione e flussi.

## Forwarding HTTP CONNECT, SOCKS e SSH

**Meccanica:** un'applicazione chiede a un proxy di aprire un flusso TCP; SOCKS può anche trasportare risoluzione dei nomi e UDP a seconda della versione; SSH inoltra flussi dentro una sessione cifrata.

**Vantaggi:** leggero; per singola applicazione; rapido; utile per il chaining e per raggiungere reti segmentate.

**Svantaggi:** le applicazioni possono aggirarlo; il DNS può fuoriuscire; il proxy vede gli endpoint adiacenti; lo stato del browser resta; gli open proxy possono essere trappole o sistemi compromessi.

**Procedura:** (1) implementare il proxy su un host di proprietà; (2) richiedere autenticazione e limitare sorgente/destinazione; (3) configurare un profilo applicativo usa-e-getta; (4) garantire la risoluzione DNS remota quando richiesta; (5) verificare con un endpoint DNS/HTTP di proprietà; (6) bloccare l'egress diretto del workload; (7) ispezionare e ruotare le credenziali del proxy.

**Rilevamento:** identificare processi capaci di creare tunnel, negoziazioni CONNECT/SOCKS, sessioni SSH lunghe e destinazioni incoerenti con l'applicazione; i log del proxy ricostruiscono i flussi.

## Web proxy con riscrittura degli URL ed estensione proxy del browser

**Meccanica:** un sito recupera una destinazione e riscrive link/form attraverso la propria origine, oppure un'estensione dirige le richieste del browser verso un proxy. La destinazione vede il servizio, mentre il servizio può vedere il testo in chiaro dopo la terminazione TLS e iniettare o conservare contenuti.

**Vantaggi:** nessun client a livello di sistema; rapido per la navigazione semplice; funziona dove è impossibile installare una VPN.

**Svantaggi:** il proxy può leggere credenziali/contenuti, riscrivere download e creare fingerprint degli utenti; script/WebSocket/download possono aggirarlo; l'estensione del browser ha privilegi ampi; anonymity set ridotto e blocchi frequenti.

**Procedura:** (1) usare esclusivamente un proxy gestito dall'organizzazione per test autorizzati; (2) isolarlo in un browser usa-e-getta senza account personali; (3) vietare l'inserimento di password e i download sensibili; (4) verificare che ogni subresource di una pagina di proprietà venga risolta tramite il proxy; (5) testare comportamento di WebSocket, download e form; (6) rimuovere estensione e profilo dopo l'uso.

**Rilevamento:** la destinazione registra il proxy; proxy/DNS aziendali e inventario delle estensioni identificano il servizio; subresource canary con content-security/reporting o di proprietà rivelano bypass diretti; i log del proxy associano la sessione utente ai target.

## Multi-hop proxy o VPN multi-hop del provider

**Meccanica:** un entry vede la sorgente, mentre uno o più relay di transito la separano da un exit che vede la destinazione.

**Vantaggi:** nessun relay ordinario deve conoscere entrambe le estremità; il guasto/sequestro di un nodo rivela meno informazioni; geografia flessibile.

**Svantaggi:** amministrazione e log condivisi annullano la separazione; latenza; correlazione temporale; più failure e percorsi DNS; stesso account/pagamento può collegare tutti gli hop.

**Procedura:** (1) definire quale osservatore viene rimosso da ogni hop; (2) usare relay di proprietà/approvati e amministrati indipendentemente quando la separazione è importante; (3) imporre accesso solo-entry dal workload; (4) garantire che ogni relay possa raggiungere solo l'hop successivo; (5) verificare i log a ogni livello; (6) arrestare ogni hop e confermare il comportamento fail-closed. Riprodurre con [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain).

**Rilevamento:** correlare tempistiche/volumi NetFlow adiacenti, handshake proxy ripetuti e infrastruttura comune del controller; non dedurre la geografia dell'operatore dall'exit.

## Relay applicativo a conoscenza divisa e OHTTP

**Meccanica:** il client cifra un messaggio HTTP stateless verso un gateway e lo invia tramite un relay. Il relay vede l'IP del client ma non la richiesta; il gateway vede la richiesta ma normalmente solo l'IP del relay.

**Vantaggi:** separazione della privacy forte e verificabile per richieste supportate; overhead inferiore rispetto alle reti di anonimato generiche.

**Svantaggi:** non consente browsing arbitrario; cookie/autenticazione possono ricollegare; collusione relay/gateway e analisi del traffico restano possibili; l'applicazione deve implementarlo.

**Procedura:** (1) selezionare un'applicazione che supporti esplicitamente RFC 9458; (2) verificare le chiavi del gateway tramite il percorso di configurazione ufficiale; (3) evitare campi stabili per utente; (4) inviare soltanto la richiesta stateless supportata; (5) confrontare i log di relay, gateway e target; (6) testare rotazione delle chiavi/failure senza fallback diretto.<sup>[[2]](#references)</sup>

**Rilevamento:** gli endpoint espongono il processo iniziale e il relay OHTTP; i gateway rilevano traffico malformato/riprodotto; tempistiche e campi payload/account stabili possono correlare le richieste.

## MASQUE CONNECT-UDP/CONNECT-IP e proxy HTTP per la privacy

**Meccanica:** HTTP Extended CONNECT su TLS/QUIC trasporta pacchetti UDP o IP attraverso un proxy. Può implementare un tunnel moderno simile a una VPN e confondere il trasporto con HTTP/3, ma il proxy resta un osservatore.<sup>[[3]](#references)</sup>

**Vantaggi:** multiplexing/roaming efficienti; supporto UDP o IP completo; implementazione tramite infrastruttura HTTP moderna.

**Svantaggi:** non è una rete di anonimato; proxy/account vedono sorgente e destinazioni; fingerprint QUIC/HTTP e percorsi noti sono visibili a endpoint/provider.

**Procedura:** (1) usare un client/servizio che documenti il supporto a RFC 9298/9484; (2) autenticare certificato/configurazione del proxy; (3) definire i percorsi target consentiti; (4) abilitare DNS cifrato nel percorso; (5) verificare UDP, TCP, IPv6 e failover contro endpoint di proprietà; (6) ispezionare log di richieste e flussi del proxy.

**Rilevamento:** gli endpoint vedono il processo client e l'interfaccia virtuale; le reti possono classificare QUIC/TLS prolungato verso un proxy; i log del proxy espongono target/percorso CONNECT e route assegnate.

## Tor Browser

**Meccanica:** Tor seleziona relay guard, middle ed exit; la cifratura a strati limita ciò che ogni relay può vedere. Tor Browser aggiunge un browser standardizzato pensato per resistere al fingerprinting.

**Vantaggi:** ampio anonymity set pubblico; nessun relay ordinario conosce entrambe le estremità; unlinkability verso la destinazione senza gestire server.

**Svantaggi:** più lento; principalmente TCP; reputazione/blocchi degli exit; login e divulgazioni identificano l'utente; resta possibile la correlazione temporale a bassa latenza.

**Procedura:** (1) scaricare e verificare Tor Browser dal progetto; (2) mantenere le impostazioni predefinite ed evitare estensioni; (3) scegliere un livello di sicurezza appropriato; (4) creare identità/sessione separata; (5) evitare account identificativi e documenti attivi esterni; (6) usare HTTPS o onion service autenticati; (7) verificare l'exit solo con un endpoint di proprietà.<sup>[[4]](#references)</sup>

**Rilevamento:** le reti locali possono identificare il traffico verso guard noti se non si usa un bridge/transport; le destinazioni vedono gli exit e il comportamento di Tor Browser; gli osservatori end-to-end correlano tempistiche/volumi.

## Tor bridge e pluggable transport

**Meccanica:** un bridge non pubblico sostituisce il guard pubblico; obfs4, Snowflake o WebTunnel modificano il trasporto del primo hop per resistere a blocchi/probing semplici.

**Vantaggi:** aggira la censura e nasconde destinazioni verso relay pubblici evidenti; conserva il circuito Tor dopo l'ingresso.

**Svantaggi:** pattern di trasporto/scoperta del bridge restano possibili; prestazioni variabili; non protegge da account o timing globale.

**Procedura:** (1) provare prima Tor diretto; (2) nelle impostazioni Connection di Tor Browser selezionare un transport supportato integrato o richiedere un bridge ufficiale; (3) non usare binari/liste casuali; (4) connettersi ed eseguire un test innocuo; (5) testare riconnessione e orologio; (6) mantenere standard tutte le altre impostazioni del browser.<sup>[[5]](#references)</sup>

**Rilevamento:** i censori usano scoperta della destinazione, classificazione di protocollo/flusso e probing attivo; i defender devono distinguere l'uso di circumvention dal compromesso e basarsi su processo/contesto dell'endpoint.

## VPN prima di Tor e Tor prima della VPN

**Meccanica:** VPN-before-Tor nasconde l'uso diretto di Tor all'ISP di accesso ma espone la sorgente alla VPN. Tor-before-VPN fornisce alla VPN traffico post-Tor e spesso un'identità stabile di cliente/tunnel.

**Vantaggi:** rimuove uno specifico osservatore se progettato correttamente; può raggiungere reti che bloccano uno dei livelli.

**Svantaggi:** complessità, fingerprint insolito, leak, anonymity set ridotto e falsa sicurezza; Tor Project considera queste combinazioni avanzate.<sup>[[6]](#references)</sup>

**Procedura:** (1) scrivere quale osservatore viene rimosso e quale nuovo osservatore viene introdotto; (2) usare un ambiente usa-e-getta; (3) stabilire soltanto il percorso esterno previsto; (4) imporre route tramite firewall; (5) verificare DNS/IPv4/IPv6 e l'ordine di ogni failure; (6) confrontare la visibilità dei due provider; (7) abbandonare lo stack se non offre un vantaggio misurabile.

**Rilevamento:** osservatori locali/VPN/Tor vedono livelli adiacenti differenti; il timing resta end-to-end; fingerprint di tunnel annidati e account provider possono collegare le sessioni.

## Onion service

**Meccanica:** client e servizio costruiscono entrambi circuiti Tor verso un rendezvous, nascondendo l'IP del servizio ed evitando un exit.

**Vantaggi:** protezione di origine e posizione del servizio; autenticazione onion end-to-end; nessuna porta inbound pubblica; autorizzazione client opzionale.

**Svantaggi:** leak dell'origine tramite update/analytics/errori; la chiave onion è critica; identità applicativa, timing e compromissione dell'host restano.

**Procedura:** (1) isolare l'applicazione e associarla solo a loopback/socket; (2) installare Tor supportato; (3) configurare un onion service v3 seguendo le istruzioni ufficiali; (4) proteggere/backup della chiave solo se serve un'identità stabile; (5) aggiungere autorizzazione client per uso chiuso; (6) rimuovere fetch di terze parti; (7) verificare esternamente che l'origine non sia raggiungibile.<sup>[[7]](#references)</sup>

**Rilevamento:** i defender dell'host/rete trovano processo/configurazione Tor e circuiti outbound; errori applicativi, DNS, certificati o risorse di terze parti possono esporre l'origine.

## Servizi interni I2P

**Meccanica:** I2P usa tunnel inbound/outbound unidirezionali separati per destinazioni interne all'overlay; gli outproxy verso Internet pubblico aggiungono un punto di fiducia.

**Vantaggi:** publishing interno decentralizzato; nessuna dipendenza da un exit ufficiale; percorsi inbound/outbound separati.

**Svantaggi:** non sostituisce il web generale; ecosistema più piccolo; comportamento dei peer di lunga durata; l'outproxy può osservare il browsing pubblico.

**Procedura:** (1) installare dalla fonte ufficiale; (2) usare un contesto dedicato; (3) consentire stabilizzazione dell'integrazione/banda; (4) accedere a un servizio nativo I2P di proprietà; (5) evitare outproxy salvo necessità esplicita; (6) verificare che lo shutdown non produca fallback diretto; (7) ispezionare log locali di peer e servizio.<sup>[[8]](#references)</sup>

**Rilevamento:** le reti locali vedono traffico peer di lunga durata e bootstrap; gli endpoint espongono processi router/applicazione; gli outproxy registrano gli exit.

## Mixnet

**Meccanica:** pacchetti di dimensione fissa, batching, ritardi, riordinamento e cover traffic riducono la correlazione temporale; i gateway collegano le applicazioni.

**Vantaggi:** maggiore resistenza all'analisi temporale rispetto ai proxy a bassa latenza; utile per messaggi/transazioni asincroni.

**Svantaggi:** latenza, overhead di banda, deployment più limitato e vincoli applicativi; metadata di gateway/account possono persistere.

**Procedura:** (1) selezionare un client mantenuto e un'applicazione supportata; (2) leggere il threat model effettivo; (3) installare in un compartimento separato; (4) inviare dati innocui a un endpoint di proprietà; (5) misurare latenza/affidabilità e percorso di risposta; (6) testare il failure del gateway; (7) non disabilitare mai ritardi/cover traffic solo per aumentare la velocità.<sup>[[9]](#references)</sup>

**Rilevamento:** gli endpoint identificano il client; le reti di accesso possono classificare gateway/cadenza dei pacchetti; gateway ed exit osservano i ruoli adiacenti, mentre una correlazione più ampia richiede finestre statistiche più lunghe.

## File sharing anonimo GNUnet

**Meccanica:** GNUnet può instradare richieste di pubblicazione/ricerca/download attraverso peer e aggiungere cover traffic in base al livello di anonimato. La documentazione avverte che il livello predefinito 1 non richiede cover traffic e che una forte analisi del traffico può identificare l'origine.<sup>[[10]](#references)</sup>

**Vantaggi:** condivisione decentralizzata, anonima e nativa dell'applicazione; requisito di cover traffic configurabile.

**Svantaggi:** non è normale accesso web anonimo; costi di prestazioni/storage; limiti dei peer e dell'analisi del traffico; la documentazione GNUnet VPN afferma che il suo overlay IP non fornisce buon anonimato.

**Procedura:** (1) installare una build ufficiale mantenuta; (2) isolare un peer di test; (3) limitare banda/storage; (4) pubblicare un file di test innocuo e unico con un livello di anonimato scelto; (5) recuperarlo da un altro peer di proprietà; (6) registrare cover traffic e latenza; (7) evitare di affermare che il componente IP VPN fornisca anonimato equivalente.

**Rilevamento:** bootstrap dei peer, traffico overlay, datastore/processo locale e identificatori dei file; un osservatore ampio può analizzare il volume rispetto al cover traffic.

## DNS cifrato, ODoH ed ECH

**Meccanica:** DoH/DoT/DoQ cifrano verso un resolver; ODoH separa l'indirizzo client dalla query tra proxy e resolver; ECH cifra il ClientHello TLS interno/nome server.

**Vantaggi:** rimuove DNS/SNI in chiaro da alcuni osservatori locali; ODoH separa la conoscenza di sorgente/query.

**Svantaggi:** non è un percorso di anonimato IP; resolver/proxy conservano i propri ruoli; IP destinazione, timing, volume ed endpoint restano; il fallback può creare leak.

**Procedura:** (1) scegliere se il DNS è gestito da OS, applicazione o tunnel; (2) abilitare modalità cifrata strict o ODoH supportato; (3) testare un dominio di proprietà unico; (4) catturare localmente per confermare l'assenza di query in chiaro; (5) interrompere il resolver e verificare il comportamento previsto; (6) per ECH, confermare dai diagnostici del server l'accettazione del ClientHello interno.<sup>[[11]](#references)</sup>

**Rilevamento:** i log di endpoint/resolver espongono le query; le reti identificano endpoint di resolver cifrati e flussi di destinazione; lo stato ECH è visibile a endpoint/CDN anche quando è nascosto nel percorso.

## Relay di privacy con provider separati

**Meccanica:** prodotti come iCloud Private Relay usano un ingresso che conosce il client e un egress gestito indipendentemente che conosce la destinazione, con gestione per regione approssimativa.

**Vantaggi:** separazione della conoscenza con bassa frizione; rapidità; protezione DNS/web integrata per il traffico supportato.

**Svantaggi:** scope limitato a prodotto/applicazione; il provider account/platform identifica comunque il cliente; non fornisce anonimato arbitrario a livello di sistema; restano rischi di collusione/legali e temporali.

**Procedura:** (1) confermare applicazioni e tipi di traffico esattamente supportati; (2) abilitare la funzione in un contesto platform dedicato quando appropriato; (3) selezionare il comportamento regionale; (4) testare separatamente Safari/DNS e applicazioni non supportate; (5) ispezionare l'indirizzo visto dalla destinazione; (6) testare cambio rete/failure.<sup>[[12]](#references)</sup>

**Rilevamento:** l'accesso vede l'ingresso; la destinazione vede l'egress; log di platform/relay e record account coprono i rispettivi livelli; le applicazioni non supportate espongono percorsi normali.

## Browser remoto, VDI, RDP o jump host dell'organizzazione

**Meccanica:** browsing/esecuzione degli strumenti avvengono su un sistema remoto; la destinazione vede il suo egress mentre il provider del workspace vede connessione dell'operatore e control plane.

**Vantaggi:** rapido; isola contenuti rischiosi; egress stabile e controllato; stato usa-e-getta e audit organizzativo forte.

**Svantaggi:** provider/admin può osservare sessione/account; canali schermo/clipboard/file creano leak; il fingerprint del browser remoto può essere unico; non è anonimo verso il proprietario del workspace.

**Procedura:** (1) creare un workspace di proprietà dell'organizzazione per ogni engagement; (2) richiedere MFA e limitare l'amministrazione; (3) disabilitare o limitare clipboard/upload/download; (4) instradare tramite egress fisso approvato; (5) non usare IdP/sync personali; (6) esportare solo evidenze revisionate; (7) distruggere workspace e credenziali secondo pianificazione.

**Rilevamento:** log provider e IdP associano l'utente alla sessione; le destinazioni raggruppano egress/fingerprint del workspace; i defender aziendali identificano protocolli di controllo remoto e sessioni cloud anomale.

## Wi-Fi pubblico o guest

**Meccanica:** il traffico esce tramite il NAT della sede o un tunnel avviato in quella sede.

**Vantaggi:** alta velocità e indirizzo condiviso non domestico; nessuna infrastruttura dedicata.

**Svantaggi:** associazione alla sede/DHCP/portal, telecamere, acquisti e prove di posizione; peer/AP ostili; termini di servizio; rischio fisico.

**Procedura:** (1) ottenere l'accesso offerto agli ospiti e verificare l'SSID con il personale; (2) usare un dispositivo aggiornato e a bassa fiducia; (3) disabilitare condivisione/auto-join e abilitare MAC privato; (4) completare il portal senza identità riutilizzata; (5) avviare un percorso VPN/Tor fail-closed; (6) verificare il traffico tethered; (7) dimenticare la rete.

**Rilevamento:** la sede correla AP, MAC, DHCP, portal e ora; la destinazione vede sede/tunnel; gli investigatori combinano prove fisiche e del dispositivo. Non aggirare mai i controlli di accesso.

## Travel router

**Meccanica:** un router di proprietà dell'operatore si collega al Wi-Fi/Ethernet della sede e fornisce una rete interna isolata con policy del tunnel applicata.

**Vantaggi:** isola le workstation; kill switch/DNS centralizzati; rete client coerente; protegge gli endpoint privilegiati dai broadcast locali.

**Svantaggi:** il router diventa un fingerprint radio/DHCP stabile; aggiunge superficie d'attacco; portal captive e tethering possono aggirare il tunnel.

**Procedura:** (1) aggiornare il firmware supportato; (2) impostare credenziali di gestione uniche e disabilitare WAN admin/WPS/UPnP; (3) configurare MAC upstream privato dove consentito; (4) creare un SSID interno separato; (5) imporre policy firewall full-tunnel DNS/IPv6; (6) testare portal, riconnessione e failure del tunnel.

**Rilevamento:** la sede vede associazione del router e forma del traffico; il fingerprinting RF/DHCP locale lo identifica; il provider VPN vede la sorgente della sede.

## Cellulare, SIM prepagata ed eSIM

**Meccanica:** un modem usa l'accesso radio del carrier e normalmente il NAT del carrier; un livello VPN/Tor può modificare l'exit visibile alla destinazione.

**Vantaggi:** indipendente dalla rete locale cablata/Wi-Fi; mobile; alta velocità; utile come backhaul per drop autorizzati.

**Svantaggi:** il carrier conosce abbonato/eSIM, IMSI, IMEI, celle, ora e porte assegnate; le leggi di registrazione variano; la co-localizzazione con il telefono personale collega i dispositivi.

**Procedura:** (1) ottenere legalmente il servizio con i dati richiesti corretti; (2) usare modem/dispositivo separato di proprietà dell'organizzazione; (3) registrarlo presso il controller dell'esercitazione; (4) disabilitare radio/account non pertinenti; (5) stabilire il tunnel approvato; (6) verificare che i client tethered lo seguano effettivamente; (7) verificare ipotesi di provider e conservazione prima del viaggio.<sup>[[13]](#references)</sup>

**Rilevamento:** record del carrier e posizione RF; inventario enterprise USB/PCI/MDM e survey degli hotspot non autorizzati; timing di destinazione/tunnel.

## Internet satellitare e abuso del downlink satellitare

**Meccanica:** il servizio normale usa un terminale/provider registrato. Il vecchio abuso DVB-S unidirezionale consentiva a un ricevitore dentro un beam di osservare traffico downlink non cifrato indirizzato a un abbonato legittimo, usando un altro percorso per le richieste outbound.

**Vantaggi:** ampia copertura; last mile indipendente; l'abuso storico unidirezionale poteva attribuire erroneamente il C2 alla geografia dell'abbonato.

**Svantaggi:** apparecchiature/RF/record del provider; latenza e copertura; i sistemi bidirezionali moderni sono diversi; percorso outbound e routing asimmetrico restano prove.

**Procedura:** per l'accesso lecito, registrare un terminale di proprietà e instradare il traffico tramite tunnel quando necessario. Per emulare il comportamento storico di Turla, riprodurre packet capture sintetici unidirezionali in un lab privo di RF e verificare se gli analisti rilevano una risposta a un host che non ha effettuato richieste; non intercettare traffico satellitare live.<sup>[[14]](#references)</sup>

**Rilevamento:** telemetria provider/terminale, radiogoniometria RF, flussi impossibili/asimmetrici, incoerenza RTT/routing e configurazione malware.

## Proxy residenziale/mobile o proxyware consensuale

**Meccanica:** un gateway backconnect assegna exit broadband/mobile consumer, fissi o rotanti. La fornitura può essere consensuale, ottenuta tramite bundle ingannevoli o malevola.

**Vantaggi:** alta velocità; scelta geografica; ASN consumer evita alcuni blocchi di hosting; pool ampi.

**Svantaggi:** rischio di provenienza/consenso e legale; il broker vede il cliente; exit infetti danneggiano vittime; la rotazione crea anomalie; costoso e inaffidabile.

**Procedura:** usare solo agenti documentati e con consenso informato, di proprietà dell'organizzazione, per l'emulazione: (1) registrare endpoint di test; (2) inventariare proprietari/IP; (3) configurare un gateway; (4) ruotare modalità sticky/per-request; (5) inviare solo verso un target di proprietà; (6) confrontare log gateway/exit/target; (7) rimuovere ogni agente.

**Rilevamento:** viaggi impossibili, stesso browser/account attraverso cambi rapidi di IP/ASN, protocolli backconnect, artefatti di processo/rete proxyware e relazioni broker/controller.

## ORB, botnet e relay di edge device compromessi

**Meccanica:** router/IoT/server noleggiati o compromessi formano ruoli di accesso, transito ed exit amministrati come una flotta. Più clienti APT possono condividerla.

**Vantaggi:** reputazione/geografia prese in prestito; exit di breve durata; mesh multi-hop resiliente; debole collegamento diretto attore-IP.

**Svantaggi:** vittimizzazione criminale; pattern di implant/controller e flotta; sequestro dell'intermediario; prestazioni incoerenti; record di operatore/servizio clienti.

**Procedura:** non compromettere mai dispositivi reali. Usare [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain): (1) creare reti isolate di ingresso/transito/target; (2) collegare container relay dual-homed di proprietà; (3) inoltrare una sola porta di test; (4) inviare una richiesta innocua; (5) verificare che il target veda solo l'exit; (6) ruotare l'exit; (7) smantellare tutti gli asset nominati.<sup>[[15]](#references)</sup>

**Rilevamento:** tracciare topologia, porte/servizi, relazioni del controller, fingerprint degli implant e ciclo di vita dei nodi; centralizzare telemetria edge di configurazione/flussi/integrità; non equiparare l'IP dell'exit all'attore.

## CDN redirector, domain fronting e domainless fronting

**Meccanica:** un edge pubblico inoltra soltanto traffico conforme a una grammatica; il fronting usa uno SNI esterno benigno e una diversa authority HTTP interna, o SNI vuoto, quando l'intermediario lo consente.

**Vantaggi:** nasconde/protegge il back-end; edge globale rapido; confonde la destinazione con un servizio condiviso; cutover rapido.

**Svantaggi:** la CDN vede tutto il routing e il tenant; molti provider vietano il fronting cross-tenant; artefatti SNI/Host/processo/flusso/account; il riuso della configurazione raggruppa le campagne.

**Procedura:** riprodurre solo su un reverse proxy di proprietà con [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging): creare certificato/edge locale, instradare un Host non corrispondente verso un target di proprietà, registrare SNI e Host, inviare richieste normali/non corrispondenti, poi rimuovere i container.<sup>[[16]](#references)</sup>

**Rilevamento:** confrontare SNI/ECH/Host/`:authority` all'endpoint o sull'edge terminante; correlare processo iniziale, tenant/origine, grammatica delle richieste e cadenza dei flussi.

## Dynamic DNS, DGA, fast flux e double flux

**Meccanica:** DDNS aggiorna un nome stabile; DGA deriva nomi candidati mutevoli; fast flux ruota gli indirizzi del servizio con TTL bassi; double flux ruota anche i name server.

**Vantaggi:** discovery resiliente; sostituzione rapida dell'infrastruttura; controller nascosto dietro molti nodi.

**Svantaggi:** il DNS crea telemetria centralizzata; entropia/NXDOMAIN/churn; TTL bassi e pattern ASN ampi; registrazione e infrastruttura authoritative restano.

**Procedura:** usare [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry): servire una zona di proprietà che restituisca indirizzi RFC 5737 con TTL di cinque secondi, interrogarla ripetutamente, cambiare l'epoca sintetica e validare gli analytics. Non puntare mai record di test verso terze parti.<sup>[[17]](#references)</sup>

**Rilevamento:** risposte/ASN unici su finestra mobile, TTL mediano, geografia, churn authoritative, cluster DGA di NXDOMAIN/lessicali/temporali e follow-on del processo; escludere CDN legittime con il contesto.

## Servizio web legittimo, dead-drop resolver e tasking unidirezionale

**Meccanica:** un post pubblico, repository, documento, object o feed contiene un endpoint corrente o task codificato. Il client può restituire i risultati tramite un altro canale.

**Vantaggi:** servizio consentito ad alta reputazione; TLS; rotazione dell'endpoint senza modificare il binario; tasking asimmetrico che ostacola la semplice correlazione dei flussi.

**Svantaggi:** identificatori stabili di object/account/API; record del provider; sequenza decode/follow-on dell'endpoint; il contenuto può essere sequestrato o modificato.

**Procedura:** usare [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence): ospitare un puntatore codificato su un container di proprietà, recuperarlo/decodificarlo da un client di breve durata, contattare un secondo servizio di proprietà, conservare entrambi i log, poi smantellare.

**Rilevamento:** correlare processo insolito → lettura di object stabile → decode → nuova destinazione; fare hash e conservare il contenuto, mantenendo i percorsi completi degli object, non solo il dominio.

## Egress serverless, container effimero e cloud-NAT

**Meccanica:** funzioni/job di breve durata eseguono dietro NAT provider o front; il servizio logico resta stabile mentre istanze e indirizzi ruotano.

**Vantaggi:** deployment/distruzione rapidi; egress condiviso su scala provider; poco disco locale; routing regionale elastico.

**Svantaggi:** tenant, ruolo, API, immagine, secret, invocazione, fatturazione e log front-to-origin sono duraturi; fingerprint di cold start e platform; policy del provider.

**Procedura:** (1) usare un tenant di esercitazione di proprietà dell'organizzazione; (2) distribuire una funzione innocua che richieda solo un endpoint di proprietà; (3) registrare project/ruolo/immagine/configurazione; (4) invocare su più istanze; (5) confrontare IP target con audit/request ID; (6) testare la conservazione dei log; (7) rimuovere funzione, ruoli e secret.

**Rilevamento:** log cloud di audit/invocazione, creazione insolita di ruoli, egress condiviso con grammatica stabile delle richieste, riuso di immagini/layer e secret, correlazione front-origin.

## Drop autorizzato sul posto

**Meccanica:** un piccolo computer inventariato usa rete locale cablata/Wi-Fi e rendezvous VPN/cellulare outbound, presentando una sorgente locale.

**Vantaggi:** test realistico dell'origine interna; alta velocità; consente di testare NAC, inventario fisico e controlli di egress.

**Svantaggi:** scoperta/furto fisico; prove serial/MAC/USB/DHCP/PoE/RF e telecamere; la perdita può esporre credenziali.

**Procedura:** seguire [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md): (1) ottenere autorizzazione scritta precisa al posizionamento; (2) registrare seriale, MAC, foto, posizione e ora di recupero; (3) usare un'immagine minima firmata e credenziali mutual di breve durata; (4) limitare destinazioni/capacità outbound-only; (5) aggiungere quarantena server-side e limiti di banda; (6) testare visibilità del SOC e risposta alla perdita; (7) recuperare, preservare le evidenze necessarie, poi sanificare secondo la policy del ciclo di vita concordata. Non nasconderne mai uno in una sede non consenziente.

**Rilevamento:** NAC/802.1X, switchport/PoE/DHCP, inventario USB, survey RF, tunnel ricorrente, ricezione/telecamere e ispezione fisica.

## Pivot wireless nearest-neighbor

**Meccanica:** un attore controlla un host nel raggio radio del target e usa quindi le credenziali Wi-Fi del target per attraversare il confine da remoto. APT28 ha usato in questo modo organizzazioni compromesse vicine.<sup>[[18]](#references)</sup>

**Vantaggi:** nessun viaggio dell'operatore; il target vede una sorgente radio locale; aggira controlli applicati solo all'ingresso Internet.

**Svantaggi:** richiede un host dual-radio vicino, compromesso o di proprietà, e accesso valido; restano prove RADIUS/NAC/AP ed endpoint vicino; anomalie di segnale/dispositivo.

**Procedura:** riprodurre solo con il [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot): collegare un pivot di proprietà agli SSID lab del vicino e del target, inoltrare un solo servizio, raccogliere log di entrambi gli AP/pivot, poi abilitare EAP-TLS/device posture e confermare il fallimento del secondo tentativo.

**Rilevamento:** correlare identità RADIUS, certificato/posture gestiti, dispositivo visto per la prima volta, bordo/segnale AP, login concomitante e presenza fisica; cercare endpoint vicini con radio simultanee, forwarding e tunnel.

## Mesh comunitaria, delay-tolerant e store-and-forward offline

**Meccanica:** il traffico attraversa peer locali, gateway asincroni, supporti rimovibili o code pianificate invece di una singola sessione Internet interattiva.

**Vantaggi:** funziona durante interruzioni/censura; delivery ritardato/batch indebolisce il semplice timing; nessun last mile centrale per le comunicazioni locali.

**Svantaggi:** latenza elevata; anonymity set ridotto; metadati di custodia/fisici; peer malevoli; i dati raggiungono infine un gateway che li osserva.

**Procedura:** (1) costruire una mesh o coda file isolata a tre nodi di proprietà; (2) cifrare/autenticare i contenuti end-to-end; (3) rimuovere route Internet dirette dall'origine; (4) inoltrare un file innocuo dopo un ritardo controllato; (5) verificare che solo il gateway contatti la destinazione di proprietà; (6) confrontare custodia/timestamp; (7) preservare le evidenze necessarie, poi sanificare media/code temporanei alla chiusura approvata.

**Rilevamento:** attività file/processo dell'endpoint, collegamenti radio peer, audit dei supporti rimovibili, periodicità di coda/gateway e identificatori del contenuto. Finestre di correlazione più lunghe sostituiscono l'analisi dei flussi interattivi.

## Relay TURN e WebRTC con relay obbligatorio

**Meccanica:** Traversal Using Relays around NAT (TURN) alloca un indirizzo relay pubblico e trasporta traffico UDP, TCP o TLS tra client e peer. Una policy ICE può imporre l'uso del relay invece di esporre un candidato diretto. TURN risolve la raggiungibilità, non l'anonimato generale: il server autentica il client e osserva allocazioni, peer, ora e volume.<sup>[[19]](#references)</sup>

**Vantaggi:** ampiamente implementato; gestisce NAT restrittivi; supporta WebRTC mobile; il peer non riceve l'indirizzo di trasporto diretto del client quando la policy relay-only è applicata correttamente.

**Svantaggi:** l'operatore TURN vede entrambi i lati adiacenti; identità applicativa, fingerprint media e signaling restano; relay-only costa banda e latenza; una configurazione errata può comunque raccogliere candidati host o server-reflexive.

**Procedura:** (1) distribuire un servizio TURN di proprietà dell'organizzazione con TLS e credenziali di breve durata; (2) limitare realm, peer, porte, quote e scadenza; (3) impostare l'applicazione di test su ICE relay-only; (4) chiamare un peer di proprietà; (5) ispezionare `getStats()` e packet capture per confermare che solo i candidati relay trasportino i media; (6) interrompere il relay e confermare l'assenza di fallback diretto; (7) conservare i log delle allocazioni per l'engagement.

**Rilevamento:** signaling, processo browser e allocazioni TURN collegano la sessione al relay; le reti osservano flussi prolungati verso porte TURN o endpoint TLS; il peer vede il relay allocato. **Nodo catturato:** stato applicativo e credenziali TURN effimere possono rivelare realm e servizio rendezvous. Ridurre l'esposizione con credenziali per dispositivo e di breve durata, mantenendo l'autenticazione dell'operatore solo presso il controller.

## Rendezvous outbound-only o reverse overlay

**Meccanica:** un nodo dietro NAT avvia una connessione autenticata verso un broker controllato dall'organizzazione. L'operatore si autentica separatamente al broker, che autorizza un canale di gestione ristretto; non servono port forwarding inbound né un percorso diretto operatore-nodo.

**Vantaggi:** stabile dietro NAT e last mile captive; revoca e audit centralizzati; il cambio di indirizzo del field node non richiede discovery dell'operatore; separa nettamente identità dell'operatore e credenziale del nodo.

**Svantaggi:** il broker diventa un punto di correlazione di alto valore; i keepalive periodici sono riconoscibili; un tunnel ampio può diventare un pivot non sicuro; la perdita del broker interrompe la gestione.

**Procedura:** seguire [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous): rilasciare un'identità dispositivo circoscritta, consentire solo broker di proprietà e servizio di gestione approvato, usare keepalive autenticato, imporre routing fail-closed, testare cambio indirizzo e ripristino dopo reboot, e revocare l'identità durante l'esercitazione di perdita. WireGuard documenta un persistent keepalive di 25 secondi come intervallo NAT generalmente utile quando effettivamente necessario.<sup>[[20]](#references)</sup>

**Rilevamento:** log broker e identity provider associano entrambi i lati; la rete di accesso vede una destinazione/cadenza cifrata ripetuta; l'inventario dell'endpoint mostra l'agent overlay. **Nodo catturato:** presumere esposte chiave dispositivo, nome broker, indirizzi tunnel e task memorizzati. Non deve contenere chiave privata dell'operatore, account personale o token riutilizzabile del controller.

## Mailbox pull, message queue o rendezvous object-store

**Meccanica:** un workload sul campo interroga una mailbox autenticata per job firmati e pre-approvati e pubblica risultati limitati. L'operatore scrive nella coda tramite un control plane separato; non esiste un socket interattivo tra loro.

**Vantaggi:** tollera link intermittenti; disaccoppia tempistiche e indirizzamento; quote e schema limitano la capacità; audit e revoca centralizzati semplici.

**Svantaggi:** cadenza di polling e nomi stabili di object/coda creano fingerprint; i log del provider uniscono producer e consumer; controllo ritardato; dati accodati catturati possono esporre l'esercitazione.

**Procedura:** (1) creare una coda per engagement e un'identità dispositivo; (2) definire uno schema firmato di job innocui e circoscritti; (3) impostare TTL dei messaggi, dimensione massima dei risultati e rate; (4) consentire al nodo di leggere solo la propria coda e scrivere solo il proprio prefisso risultati; (5) testare accumulo offline, consegna duplicata e revoca; (6) centralizzare log di accesso immutabili; (7) eliminare la coda dopo il periodo di conservazione richiesto.

**Rilevamento:** cercare chiamate API periodiche da un processo insolito, percorsi stabili bucket/object/queue, stesso user-agent o comportamento TLS e sequenza fetch→nuova connessione. **Nodo catturato:** la cache locale può rivelare job pendenti e nomi object; mantenere la cache cifrata, limitata e usa-e-getta, conservando i log autorevoli del controller.

## Failover dual-uplink e migrazione della connessione

**Meccanica:** un field node approvato ha due uplink indipendenti, come Ethernet/Wi-Fi della sede e cellulare dell'organizzazione, e mantiene la sessione di controllo tramite overlay o message broker mentre cambiano le route. È ingegneria della disponibilità, non anonimato.

**Vantaggi:** sopravvive al failure di un provider, AP o captive portal; supporta manutenzione pianificata; consente isolamento rapido di un percorso sospetto.

**Svantaggi:** due provider creano due record di posizione/account; l'uso simultaneo facilita la correlazione; leak di route e DNS durante il failover; resta la prova di co-localizzazione cellulare.

**Procedura:** (1) registrare entrambe le interfacce e i provider di proprietà dell'organizzazione; (2) assegnare priorità route e health check deterministici verso endpoint di proprietà; (3) associare DNS e management all'overlay; (4) impedire al percorso secondario di accettare traffico inbound; (5) scollegare ogni percorso e verificare ripristino sessione, policy sorgente e assenza di accesso diretto alla destinazione; (6) generare alert sui cambi percorso non pianificati; (7) documentare uso dati e limiti di roaming.

**Rilevamento:** correlare stesso certificato dispositivo, grammatica delle richieste e timing tra ASN; l'inventario locale vede entrambe le radio; carrier/sedi conservano i propri record. **Nodo catturato:** possono essere visibili entrambi gli identificatori SIM/dispositivo e gli SSID noti; usare asset dell'organizzazione e non associare mai il nodo a dispositivi personali.

## APN privato dell'organizzazione o tunnel cellulare gestito

**Meccanica:** un APN privato del carrier colloca SIM registrate in un dominio instradato privato o inoltra il traffico verso un gateway enterprise. Separa il dispositivo dall'Internet mobile pubblico ma non lo nasconde al carrier o all'organizzazione contraente.

**Vantaggi:** indirizzamento privato stabile; enrollment e policy del traffico a livello carrier; evita esposizione inbound pubblica; utile per appliance remote autorizzate.

**Svantaggi:** attribuzione forte di abbonato, IMSI/IMEI, cella e fatturazione; tempi e costi di procurement; failure carrier/gateway; non è anonimo verso l'operatore.

**Procedura:** (1) stipulare il contratto APN a nome dell'organizzazione di assessment; (2) consentire solo SIM registrate e prefissi gateway; (3) aggiungere autenticazione mutual a livello applicativo; (4) limitare la route APN a rendezvous e servizi di update; (5) testare rimozione SIM, roaming, uscita Internet pubblica e revoca; (6) monitorare record carrier e gateway; (7) cancellare o mettere in quarantena ogni SIM alla chiusura.

**Rilevamento:** inventario carrier e telemetria cella, flussi gateway APN, mismatch SIM/IMEI e record asset enterprise. **Nodo catturato:** SIM e modem identificano il contratto anche con storage cifrato; la resilienza alla cattura significa quindi sospensione rapida e autorizzazione ristretta, non negabilità.

## Bridge wireless point-to-point a lunga distanza

**Meccanica:** Wi-Fi direzionale o altra radio point-to-point autorizzata collega due siti approvati dal proprietario, con egress Internet presso il sito remoto. Può spostare la posizione IP apparente senza usare un proxy commerciale.

**Vantaggi:** throughput elevato; indipendenza dai carrier cablati intermedi; RF e routing controllabili; utile per testare segmentazione e monitoraggio del sito remoto.

**Svantaggi:** linea di vista, spettro, proprietari e vincoli normativi; emissioni RF e hardware distintivi; entrambi gli endpoint sono prove fisiche; meteo/alimentazione/allineamento influenzano la stabilità.

**Procedura:** (1) ottenere autorizzazione scritta per entrambi i siti e verificare regole su spettro/potenza; (2) esaminare il percorso senza trasmettere fuori dai parametri approvati; (3) usare cifratura autenticata e VLAN di gestione; (4) limitare il bridge a rendezvous o subnet di test di proprietà; (5) testare failover, allineamento, recupero alimentazione e contenimento RF; (6) etichettare/inventariare entrambe le radio; (7) rimuoverle e verificare il reset della configurazione dopo l'esercitazione.

**Rilevamento:** survey RF, analisi dello spettro, ispezione di tetto/sito, MAC/OUI del bridge, traffico di gestione e log di egress del sito remoto. **Nodo catturato:** la configurazione rivela peer e dominio di gestione; usare credenziali uniche per l'esercitazione, nessun account personale di gestione e revoca rapida della chiave peer.

## Exit cooperativo o comunitario consensuale

**Meccanica:** volontari o organizzazioni partner eseguono relay consapevolmente secondo una policy pubblicata. Il traffico esce da un pool comunitario condiviso mentre il livello di coordinamento gestisce abuso e revoca.

**Vantaggi:** reti non-cloud diversificate; il consenso esplicito è più sicuro del proxyware; la governance condivisa può distribuire la fiducia; utile per ricerca e studi di resilienza alla censura.

**Svantaggi:** pool piccoli e record dei membri riducono l'anonimato; gli operatori exit ricevono reclami e osservano metadata del traffico; partecipanti malevoli, uptime variabile e differenze di giurisdizione.

**Procedura:** (1) pubblicare policy di uso accettabile e logging; (2) ottenere opt-in informato da ogni operatore; (3) emettere un'identità relay unica e limitare destinazioni/rate; (4) fornire gestione degli abusi e revoca con un'azione; (5) inviare durante i test solo traffico autorizzato verso endpoint di proprietà; (6) misurare churn ed esposizione alla correlazione; (7) rimuovere correttamente il relay quando termina il consenso.

**Rilevamento:** record di membership/control plane, certificati relay, fingerprint software comune e comportamento dell'exit identificano il pool. **Nodo catturato:** la configurazione relay può identificare il cooperante ma non dovrebbe contenere identità dei client; conservare l'accountability client-session presso il controller autorizzato con controllo degli accessi.

## Indirizzi temporanei IPv6 e rotazione dei prefissi

**Meccanica:** le privacy extension IPv6 creano identificatori temporanei dell'interfaccia, così un indirizzo stabile non viene riutilizzato per ogni connessione outbound. I cambi di prefisso del provider possono aggiungere rotazione, ma prefisso delegato, record dell'abbonato e fingerprint dei livelli superiori restano.<sup>[[21]](#references)</sup>

**Vantaggi:** riduce il tracking passivo a lungo termine tramite un identificatore stabile dell'interfaccia; integrato nei sistemi operativi comuni; nessun overhead di relay.

**Svantaggi:** non è anonimato della sorgente; ISP e rete locale conoscono ancora prefisso/dispositivo; DNS, account e stato browser collegano le sessioni; il churn degli indirizzi complica allowlist e logging.

**Procedura:** (1) ispezionare indirizzi stabili e temporanei correnti su un client di proprietà; (2) abilitare il default degli indirizzi privacy supportato dall'OS invece di spoofing di terze parti; (3) richiedere ripetutamente un endpoint IPv6 di proprietà durante i cicli di vita degli indirizzi; (4) confermare che i servizi inbound si associno solo agli indirizzi stabili previsti; (5) conservare log DHCPv6/RA/neighbor ed endpoint precisi; (6) testare comportamento VPN/firewall per ogni indirizzo IPv6.

**Rilevamento:** correlare prefisso delegato, identità layer 2, neighbor discovery, account e telemetria dell'endpoint invece di trattare un indirizzo come un dispositivo. **Nodo catturato:** profili di rete e identificatori di interfaccia restano; l'indirizzamento temporaneo impedisce un identificatore passivo, non l'attribuzione forense.

## Tor pluggable transport: Snowflake, WebTunnel, obfs4 e meek

**Meccanica:** un pluggable transport modifica l'aspetto della prima connessione Tor o il modo in cui raggiunge un bridge. Snowflake usa proxy WebRTC volontari di breve durata, WebTunnel assomiglia a HTTPS ordinario, obfs4 resiste alla semplice identificazione del protocollo e al probing attivo, mentre meek inoltra tramite infrastruttura web supportata. Sono transport di circumvention verso Tor, non ulteriori livelli di anonimato end-to-end.<sup>[[22]](#references)</sup>

**Vantaggi:** utile quando Tor diretto o relay noti sono bloccati; Snowflake evita un indirizzo bridge pubblico stabile; integrato nei client Tor mantenuti; la destinazione riceve comunque le normali proprietà Tor.

**Svantaggi:** prestazioni inferiori o variabili; broker/front/bridge e rete locale osservano metadata diversi; fingerprint e blocchi del transport restano possibili; il proxy volontario non sostituisce Tor e non deve essere considerato affidabile per il plaintext applicativo.

**Procedura:** (1) installare e verificare Tor Browser ufficiale o un client Tor supportato; (2) selezionare il transport integrato in Connection/Bridges; (3) connettersi solo a una pagina diagnostica di proprietà; (4) confermare che la pagina veda un exit Tor, non il peer Snowflake/WebTunnel; (5) confrontare bootstrap e prestazioni; (6) interrompere il transport e confermare che il client non si connetta silenziosamente in modo diretto; (7) tornare alla configurazione standard supportata dopo il test.

**Rilevamento:** un censore può combinare allowlist delle destinazioni, comportamento TLS/WebRTC, discovery del broker e analisi dei flussi; gli endpoint espongono Tor e la configurazione del transport. **OPSEC resiliente alla cattura:** usare il client standard, non copiare mai stato browser personale e presumere recuperabile la cronologia di bridge/broker. **Monitoraggio:** osservare log di bootstrap Tor, tentativi DNS/connessione diretti inattesi e osservazioni delle pagine di proprietà lato controller; il failure del transport non prova la scoperta.

## Refraction networking o decoy routing

**Meccanica:** un operatore di rete cooperante rileva un segnale covert in traffico apparentemente indirizzato a un decoy consentito e devia il flusso verso un proxy di circumvention. Il deployment richiede infrastruttura nel percorso di rete; non è qualcosa che un client possa creare selezionando semplicemente un sito innocente.<sup>[[23]](#references)</sup>

**Vantaggi:** la destinazione apparente può essere difficile da bloccare per un censore senza danni collaterali; non è necessario distribuire un indirizzo bridge pubblico; utile come modello di ricerca per circumvention assistita on-path.

**Svantaggi:** partecipazione ISP/transit specializzata; implementabilità e prestazioni dipendono dal routing; flusso client-decoy e attività lato proxy restano; un osservatore globale o cooperante può correlare il timing.

**Procedura:** non segnalare attraverso reti non coinvolte. Riprodurre l'architettura in un lab isolato: (1) creare namespace client, router, decoy e proxy di proprietà; (2) usare una richiesta di test benignamente marcata; (3) fare in modo che il router di proprietà reindirizzi solo quel tag al proxy; (4) registrare tuple e request ID pre/post-routing; (5) confrontare flussi ordinari e segnalati; (6) testare falsi positivi e rimozione; (7) distruggere le route del lab.

**Rilevamento:** gli operatori autorizzati possono ispezionare divergenza del routing, comportamento insolito di client hello/tag e discrepanze tra flussi decoy e back-end. **OPSEC resiliente alla cattura:** un client di ricerca dovrebbe contenere solo chiavi di test e indirizzi documentali. **Monitoraggio:** confrontare decisioni firmate del router lab con gli arrivi al proxy; non sondare provider transit di produzione per determinare se hanno rilevato la segnalazione.

## Gateway content-addressed o recupero da peer in cache

**Meccanica:** un gateway HTTP recupera un content identifier (CID) IPFS, eventualmente dalla cache o da peer, e restituisce al client il contenuto verificabile. Il publisher originale può vedere il gateway o altri peer invece del lettore finale; il gateway vede l'IP del lettore e il CID richiesto. Il recupero peer-to-peer nativo espone il client ai peer e ai partecipanti DHT/routing.<sup>[[24]](#references)</sup>

**Vantaggi:** publisher e lettore possono essere separati dalle cache; il contenuto immutabile è verificabile tramite hash; i dati replicati sopravvivono alla perdita di un host; i client HTTP non richiedono uno stack peer nativo.

**Svantaggi:** CID pubblici e log del gateway rivelano gli interessi; il timing del primo recupero può correlare publisher e lettore; contenuti web malevoli e rischi same-origin dei percorsi; i gateway pubblici sono best-effort e vietano gli abusi.

**Procedura:** (1) pubblicare un file di test innocuo su una swarm IPFS privata di proprietà o gateway di proprietà; (2) registrarne il CID; (3) recuperarlo tramite un gateway HTTP separato di proprietà usando isolamento tramite subdomain; (4) verificare i byte rispetto al CID; (5) ripetere dopo il caching; (6) confrontare log publisher, peer e gateway; (7) unpin e rimuovere i contenuti di test al termine della conservazione.

**Rilevamento:** i gateway registrano sorgente/CID; connessioni DHT e peer rivelano il recupero; cronologia dell'endpoint e hash dei file identificano il contenuto. **OPSEC resiliente alla cattura:** non conservare chiavi private di publishing su un field client read-only e cifrare i contenuti sensibili prima del content addressing. **Monitoraggio:** alert su pinning inatteso, cambiamento del set di peer, richieste CID fuori allowlist o notifiche dell'account gateway.

## Servizio Private Information Retrieval

**Meccanica:** Private Information Retrieval (PIR) permette a un client di recuperare un record da un database nascondendo crittograficamente al server l'indice selezionato secondo un threat model single- o multi-server dichiarato. Protegge la selezione della query per un dataset circoscritto; non è accesso web generale né anonimato IP.<sup>[[25]](#references)</sup>

**Vantaggi:** forte privacy della query specifica per applicazione; modello di leakage misurabile; utile per directory di chiavi, blocklist o piccoli database pubblici; può ridurre la necessità di rivelare termini di ricerca esatti.

**Svantaggi:** overhead computazionale/di banda; il server conosce tempo/IP della connessione salvo combinazione con un relay; versione del dataset, dimensione della risposta e stato dell'applicazione possono partizionare gli utenti; maturità dell'implementazione variabile.

**Procedura:** (1) distribuire un'implementazione PIR verificata su un database sintetico di proprietà; (2) pubblicare versione e parametri del dataset; (3) recuperare più indici usando richieste di dimensione identica; (4) verificare localmente la correttezza; (5) confrontare i log server e confermare l'assenza dell'indice; (6) testare risposte malevole/troncate e mismatch di versione; (7) documentare l'assunzione esatta sulla privacy invece di definirlo browsing anonimo.

**Rilevamento:** le reti vedono uso e volume del servizio; la telemetria endpoint espone client e uso del record finale; un server compromesso può manipolare dataset o timing. **OPSEC resiliente alla cattura:** conservare sul client solo parametri pubblici del database e una cache limitata. **Monitoraggio:** validare root firmate del dataset, forme fisse delle richieste, variazioni dell'error rate e rotazioni delle chiavi server.

## Fetcher server-side limitato, servizio preview o rendering

**Meccanica:** un servizio remoto recupera o renderizza un URL e restituisce screenshot, metadata o contenuti sanificati. La destinazione vede l'indirizzo del fetcher; il servizio vede requester, URL e risultato. Abusare di bot di link-preview, security scanner o fetcher URL di terze parti non è uso autorizzato di un proxy.

**Vantaggi:** isola i contenuti attivi dalla workstation; la destinazione riceve un fingerprint controllato del fetcher; può imporre limiti su tipo file, dimensione, destinazione e rendering; ambiente di esecuzione usa-e-getta.

**Svantaggi:** il servizio conosce l'intera richiesta; record account/API/fatturazione; rischi SSRF ed esfiltrazione dati; script, autenticazione e siti interattivi possono non funzionare; URL unici correlano requester e fetch.

**Procedura:** (1) distribuire un fetcher di proprietà dell'organizzazione con allowlist rigida di domini di test di proprietà; (2) bloccare indirizzi privati, link-local, metadata e redirect verso indirizzi non approvati; (3) limitare metodi, redirect, byte e tempo di rendering; (4) rimuovere credenziali/cookie; (5) inviare un URL di proprietà; (6) confrontare log requester/fetcher/target; (7) distruggere l'istanza di rendering e conservare l'audit centrale secondo policy.

**Rilevamento:** il target vede ASN/fingerprint del servizio; log provider e controller associano requester e URL; processo endpoint/chiamate API mostrano l'invio. **OPSEC resiliente alla cattura:** usare un token di progetto di breve durata senza autorità su destinazioni arbitrarie. **Monitoraggio:** alert su rifiuti allowlist, violazioni dei redirect, fetch senza controller job ID e notifiche di abuso del provider.

## Pool di rendezvous Anycast

**Meccanica:** più nodi controllati dall'organizzazione annunciano o frontano un unico indirizzo stabile del servizio, e il routing seleziona un'istanza vicina. Anycast migliora la disponibilità e nasconde al client un singolo back-end, ma l'operatore controlla tutte le istanze e l'indirizzo del servizio è stabile.<sup>[[26]](#references)</sup>

**Vantaggi:** ingresso regionale resiliente; nessuna riconfigurazione del field node quando un'istanza fallisce; distribuzione DDoS/carico; policy centrale per spostare sessioni tra nodi noti.

**Svantaggi:** record BGP/CDN e provider identificano l'organizzazione; cambi di percorso possono interrompere sessioni stateful; il monitoraggio varia con la posizione del client; un singolo indirizzo stabile è facile da bloccare o raggruppare per reputazione.

**Procedura:** usare un project dell'organizzazione supportato dal provider o un lab di routing isolato: (1) distribuire due endpoint health autenticati identici; (2) esporre un unico indirizzo di servizio documentato; (3) mantenere lo stato della sessione nel broker invece che nell'edge; (4) ritirare un nodo e verificare la riconnessione; (5) testare coerenza di certificato, policy e log; (6) generare alert su origine/regione non autorizzata; (7) rimuovere annunci e credenziali alla chiusura.

**Rilevamento:** BGP/RPKI/storia, tenancy del provider, certificati e comportamento identico del servizio identificano il pool. **OPSEC resiliente alla cattura:** un edge conserva solo l'identità del servizio regionale e nessuna chiave dell'operatore o di enrollment della flotta. **Monitoraggio:** sondare ogni regione da monitor autorizzati, confrontare origine della route e digest della configurazione, e trattare un'origine inattesa come incidente.

## Migrazione QUIC e continuità Multipath TCP

**Meccanica:** i connection ID QUIC possono mantenere viva una sessione client attraverso rebinding NAT o cambio di indirizzo; Multipath TCP può trasportare un singolo byte stream affidabile su più subflow. Migliorano la continuità tra transizioni Wi-Fi/cellulare ma espongono entrambi i percorsi al peer comune e possono facilitare la correlazione cross-path.<sup>[[27]](#references)</sup>

**Vantaggi:** recupero più rapido durante cambi uplink; la sessione applicativa non deve ripartire; MPTCP può combinare resilienza e throughput; utile per field node approvati.

**Svantaggi:** non è anonimato; il peer vede migrazione/subflow; connection ID e traffico simultaneo collegano i percorsi; supporto middlebox/carrier variabile; record duplicati del provider aumentano l'esposizione.

**Procedura:** (1) abilitare il transport supportato solo tra field client e rendezvous di proprietà; (2) autenticare l'applicazione indipendentemente dall'IP; (3) iniziare un trasferimento limitato su Wi-Fi approvato; (4) passare al cellulare dell'organizzazione; (5) confermare path validation, integrità dei dati e assenza di fallback diretto/in chiaro; (6) testare idle timeout e ritorno; (7) conservare nel broker i record di ogni transizione del percorso.

**Rilevamento:** il peer osserva direttamente migrazione dell'indirizzo o subflow MPTCP; gli access provider vedono la propria parte; connection ID, identità TLS e timing uniscono entrambi i percorsi. **OPSEC resiliente alla cattura:** conservare solo materiale di sessione circoscritto al dispositivo e far scadere rapidamente lo stato resumable. **Monitoraggio:** alert su cambi impossibili del percorso, reti simultanee non approvate, migration storm e ripresa dopo quarantena.

## Egress di runner CI/CD gestito o automazione effimera

**Meccanica:** un workflow di proprietà dell'organizzazione esegue un controllo di rete limitato su un runner hosted. La destinazione vede un indirizzo cloud del runner, mentre la platform conserva attribuzione di repository, attore, workflow, token, log e fatturazione. È esecuzione remota con egress attribuibile, non anonimato verso il provider.<sup>[[28]](#references)</sup>

**Vantaggi:** ambiente pulito usa-e-getta; job riproducibile; nessuna connessione inbound; utile per controlli di disponibilità distribuiti geograficamente; audit forte del controller.

**Svantaggi:** platform e organizzazione identificano l'iniziatore; token workflow ampi e pull request non affidabili sono pericolosi; reputazione IP condivisa; log/artifact possono conservare secret o dati del target.

**Procedura:** (1) creare repository e environment privati dell'organizzazione per l'assessment; (2) consentire solo job benigni fissi e approvati manualmente verso endpoint di proprietà; (3) usare permessi workflow minimi read-only e nessun secret di produzione; (4) eseguire il controllo; (5) confrontare record workflow/provider/target; (6) verificare che gli artifact non contengano credenziali; (7) eliminare il token dell'environment e conservare l'audit richiesto.

**Rilevamento:** audit provider e log workflow forniscono attribuzione diretta; i target identificano ASN/range dei runner e grammatica stabile delle richieste. **OPSEC resiliente alla cattura:** non inserire mai secret di field device, signing, wallet o cloud administrator nelle variabili del runner. **Monitoraggio:** richiedere approvazione branch/environment e generare alert su modifiche workflow, esecuzione da fork, letture di secret e destinazioni inattese.

## Primo hop locale non-IP verso un gateway di proprietà

**Meccanica:** Bluetooth mesh, Wi-Fi Aware/Direct, radio a basso consumo o collegamento seriale/ottico trasporta messaggi limitati da un sensore vicino a un gateway Internet approvato dal proprietario. Il dispositivo sul campo non ha route Internet; il gateway è l'unico egress. Portata radio e limiti del protocollo lo rendono un design telemetry/store-and-forward, non Internet anonimo interattivo.

**Vantaggi:** rimuove stack Internet e credenziali dal dispositivo più piccolo; basso consumo; il gateway centralizza la policy; può attraversare zone morte temporanee.

**Svantaggi:** scoperta RF/fisica, pairing e identificatori dispositivo; banda e portata ridotte; il gateway collega tutti i messaggi; vincoli su spettro e cifratura variabili; la cattura può esporre dati accodati.

**Procedura:** (1) ottenere approvazione del sito e dello spettro; (2) associare un sensore di proprietà a un gateway di proprietà usando chiavi uniche; (3) definire tipi di messaggio firmati e di dimensione fissa, TTL e rate; (4) dare al sensore nessuna route IP predefinita; (5) consentire al gateway l'inoltro solo verso un collector di proprietà; (6) testare replay, perdita della portata e failure del gateway; (7) inventariare e recuperare entrambi i dispositivi.

**Rilevamento:** survey RF, database di pairing, ispezione fisica e log di processo/flusso del gateway rivelano il percorso. **OPSEC resiliente alla cattura:** il sensore conserva solo chiave pairwise e coda cifrata limitata, mai credenziali operatore, Wi-Fi, cellulare o controller. **Monitoraggio:** alert su nuovi peer, rollback della sequenza, failure della chiave, rate RF insolito e messaggi ricevuti tramite gateway non registrato.

## Matrice di esposizione a cattura/compromissione

Questa tabella applica un controllo di resilienza alla cattura a ogni famiglia sopra. “Minimizzare” significa ridurre secret e blast radius sugli asset autorizzati; non significa mai cancellare evidenze o nascondersi da un'indagine.

| Famiglia di tecniche | Cosa può rivelare un endpoint/relay catturato | Controllo autorizzato minimo |
|---|---|---|
| NAT/CGNAT, Wi-Fi pubblico, travel router | reti note, cronologia DHCP/portal, MAC, peer del tunnel | dispositivo organizzativo separato; MAC privato dove supportato; nessun account personale; inventario controller |
| VPN, VPS, HTTP/SOCKS/SSH, multi-hop | provider/hostname, chiavi, route, log e hop adiacente | un'identità per engagement; TTL breve; route ristrette; revoca lato broker; nessuna master key |
| OHTTP/ODoH, MASQUE, relay split-provider | configurazione relay/gateway, identificatori applicativi e richieste in cache | minimizzare identificatori payload; pin della configurazione approvata; cache limitata; nessun fallback diretto |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | software installato, materiale bridge/onion, stato locale e cronologia peer | client standard; chiavi servizio separate; stato minimo cifrato; ruotare l'identità del servizio compromessa |
| Browser remoto/VDI/jump host | token workspace, clipboard/file e tenant remoto | MFA resistente al phishing sul gateway; canali di trasferimento disabilitati; revoca rapida della sessione |
| Cellulare, satellite, APN privato | SIM/eSIM, identità IMEI/terminale, provider e posizione approssimativa | contratto organizzativo; nessuna co-localizzazione personale; policy APN/overlay ristretta; runbook di sospensione provider |
| Proxy residenziale/cooperativo, ORB lab | identità agente, controller/next hop, traffico in cache | solo nodi consensuali/di proprietà; agent firmato; credenziale per nodo; mapping partecipanti conservato dal controller |
| CDN/fronting, fast flux, serverless | tenant/origine/configurazione, token API, riferimenti deployment/fatturazione | project dedicato; ruolo least-privilege; token deploy breve; audit provider conservato centralmente |
| Dead drop, pull mailbox, store-and-forward | nomi object, coda, job/risultati in cache e dati di custodia | job firmati e limitati; TTL; cache cifrata; identità producer separata; log server immutabili |
| Drop, nearest-neighbor, bridge lunga distanza | seriale/radio/SSID/peer, chiave dispositivo, artefatti di posizionamento | posizionamento scritto; identità dispositivo unica; nessun secret operatore; telemetria tamper/stato; revoca e recupero |
| TURN, reverse overlay, dual-uplink | realm/broker, credenziale dispositivo, peer/route e profili uplink | servizio outbound-only ristretto; credenziale breve; login operatore indipendente; percorsi fail-closed |
| Indirizzamento temporaneo IPv6 | profili, cronologia prefissi e stato endpoint/applicazione | trattarlo solo come anti-tracking; conservare log di rete; abbinarlo a compartmentation dell'endpoint |
| Pluggable transport/refraction lab | impostazioni bridge/broker/decoy, stato Tor e chiavi di ricerca | client standard o lab isolato; nessuno stato browser personale; nessuna segnalazione di produzione |
| IPFS/PIR/fetcher | CID/query richiesti dal client, contenuto in cache, token gateway/servizio | cache cifrata e limitata; soli parametri pubblici; token servizio breve e in allowlist |
| Anycast/QUIC/MPTCP | nodi servizio, connection ID, stato resumable e ogni percorso noto | solo identità regionale; breve durata del resume; revoca centrale di route/sessione |
| Runner CI/CD gestito | repository, workflow, token provider, log e artifact | workflow least-privilege; nessun secret produzione/campo/wallet; approvazione environment |
| Hop locale non-IP | peer radio, chiave pairwise, messaggi accodati e identità gateway | chiave pairwise unica; schema messaggi fisso; nessuna credenziale Wi-Fi/cellulare/operatore |

## Monitoraggio della possibile scoperta per ogni famiglia di accesso

Nessun test lato client dimostra che un investigatore o defender stia osservando. Monitorare i cambiamenti nei sistemi di proprietà dell'engagement, corroborarli con controller/client e fermarsi invece di sondare gli osservatori. Le righe seguenti coprono ogni tecnica sopra; combinarle con gli [stati di alert e il runbook di risposta dei field node](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise).

| Tecniche coperte | Segnali sicuri lato controller | Condizione di quarantena/stop |
|---|---|---|
| NAT/CGNAT, Wi-Fi pubblico/guest, travel router, cellulare/eSIM, satellite, APN privato | sessione lease/portal/carrier, tupla pubblica, cambio BSSID/cella/percorso, avviso provider | rete/SIM/dispositivo non approvato, spostamento inspiegato o escalation provider/SOC |
| VPN/VPS, HTTP/SOCKS/SSH, multi-hop, proxy residenziale/cooperativo | autenticazione peer, stato tunnel, leak route/DNS, nuovo evento admin/API, reclamo | credenziale duplicata/rubata, amministratore sconosciuto, fallback diretto o egress fuori scope |
| OHTTP/ODoH/ECH, MASQUE, relay split-provider, TURN | allocazione relay/gateway, versione chiave/config, connessione diretta non supportata, rate errore/replay | mismatch chiave, fallback diretto, realm/peer sconosciuto o avviso abuso provider |
| Tor Browser, bridge, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, onion service | stato bootstrap, failure circuito, descriptor onion/health servizio e pagina canary di proprietà | crossover ad account personale, connessione non-Tor inattesa o chiave servizio compromessa |
| I2P, mixnet, GNUnet, mesh/store-forward, hop locale non-IP | set peer, età/sequence coda, arrivo gateway, associazione radio e hash contenuto | peer/gateway sconosciuto, rollback sequence, contenuto non autorizzato o record di custodia mancante |
| Browser remoto/VDI/jump host, runner CI/CD, serverless | sessione IdP, modifica workflow/immagine/config, nuovo uso token, artifact/export e audit cloud | login/modifica workflow sconosciuto, lettura secret, destinazione inattesa o escalation project-role |
| ORB lab, fast flux/DGA, CDN/fronting, dead drop/pull mailbox | inventario nodi di proprietà, accesso DNS/edge/object, grafo controller, firma job e TTL | nodo/origine/object writer sconosciuto, job non firmato/riprodotto, topologia fuori dal lab |
| Drop/nearest-neighbor/bridge lunga distanza/overlay outbound/dual uplink | heartbeat firmato, hash boot/config, stato enclosure, contesto AP/switch, identità duplicata | nodo spostato/aperto, boot/hash/percorso inatteso, uso sentinel o report della sede |
| Indirizzi temporanei IPv6, migrazione QUIC, MPTCP | prefisso delegato, connection ID/subflow, path validation e sessione broker | migrazione impossibile, percorsi simultanei non approvati o resume sessione dopo revoca |
| IPFS/cache, PIR, fetcher limitato | forma CID/query/root version, cambio peer/gateway, rifiuto redirect/allowlist | pin/query/destinazione inattesa, root dataset non firmata o avviso abuso provider |
| Lab refraction/decoy-routing, rendezvous anycast | decisione diversion di proprietà, arrivo proxy, origine BGP/RPKI, digest configurazione regionale | segnale su percorso di produzione, origine route sconosciuta, incoerenza regione/configurazione |

## Scelta e test di un percorso

1. Nominare l'osservatore da rimuovere e i dati da nascondere.
2. Selezionare la famiglia meno complessa che lo rimuove.
3. Disegnare gli osservatori di sorgente, ingresso, transito, uscita, DNS, account e pagamento.
4. Usare un'identità separata per endpoint/applicazione.
5. Verificare bypass IPv4, IPv6, DNS, WebRTC/applicazione e vista della destinazione.
6. Interrompere ogni hop e confermare che il failure sia chiuso.
7. Confrontare i log di ogni componente sotto il proprio controllo.
8. Registrare i collegamenti residui temporali, provider, endpoint e fisici.

## References

- [1] [EFF — Choosing the VPN that is right for you](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [RFC 9298 — Proxying UDP in HTTP](https://www.rfc-editor.org/rfc/rfc9298.html) and [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [4] [Tor Project — Tor protections](https://support.torproject.org/about-tor/introduction/protections/) and [Tor specification introduction](https://spec.torproject.org/intro/)
- [5] [Tor Project — Unblocking Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [6] [Tor Project — Using Tor Browser with a VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [7] [Tor Project — Onion services overview](https://community.torproject.org/onion-services/overview/)
- [8] [I2P — Threat model](https://www.i2p.net/en/docs/overview/threat-model/)
- [9] [Katzenpost — Threat model](https://katzenpost.network/docs/threat_model/)
- [10] [GNUnet — Anonymous file sharing](https://docs.gnunet.org/master/users/fs.html) and [GNUnet VPN limitations](https://docs.gnunet.org/latest/users/vpn.html)
- [11] [RFC 9230 — Oblivious DoH](https://www.rfc-editor.org/rfc/rfc9230.html) and [RFC 9849 — Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [12] [Apple Platform Security — iCloud Private Relay security](https://support.apple.com/guide/security/secad8ce3233/web)
- [13] [GSMA — Mandatory SIM registration](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [15] [Google Cloud/Mandiant — China-nexus espionage actors use ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [16] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [17] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [18] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [19] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [20] [WireGuard — Quick Start: NAT and Firewall Traversal Persistence](https://www.wireguard.com/quickstart/)
- [21] [RFC 8981 — Temporary Address Extensions for Stateless Address Autoconfiguration in IPv6](https://www.rfc-editor.org/rfc/rfc8981.html)
- [22] [Tor Project — Pluggable transports and bridges](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/) and [Using Snowflake](https://support.torproject.org/anti-censorship/how-can-i-use-snowflake/)
- [23] [Refraction Networking — project and deployment research](https://refraction.network/) and [Running Refraction Networking for Real](https://refraction.network/papers/deployment-pets20.pdf)
- [24] [IPFS — HTTP Gateway concepts and request lifecycle](https://docs.ipfs.tech/concepts/ipfs-gateway/)
- [25] [IETF PEARG — Private Information Retrieval overview](https://datatracker.ietf.org/meeting/121/materials/slides-121-pearg-call-me-by-my-name-simple-practical-private-information-retrieval-for-keyword-queries-00)
- [26] [RFC 4786 — Operation of Anycast Services](https://www.rfc-editor.org/rfc/rfc4786.html)
- [27] [RFC 9000 — QUIC connection migration](https://www.rfc-editor.org/rfc/rfc9000.html) and [RFC 8684 — Multipath TCP](https://www.rfc-editor.org/rfc/rfc8684.html)
- [28] [GitHub — GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
{{#include ../banners/hacktricks-training.md}}
