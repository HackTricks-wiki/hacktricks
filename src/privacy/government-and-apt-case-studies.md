# Case study di governi e APT

{{#include ../banners/hacktricks-training.md}}

Questi casi pubblici mostrano come tecniche di privacy separate vengano combinate nelle operazioni reali. Le attribuzioni sono quelle utilizzate dagli investigatori o dai governi citati; un indirizzo IP, una sovrapposizione degli strumenti o una corrispondenza geopolitica, presi singolarmente, non costituiscono un'attribuzione conclusiva.

## APT28: accesso Wi-Fi remote nearest-neighbor

**Risultato pubblico.** Volexity ha attribuito un'intrusione del 2022 a GruesomeLarch/APT28. Dopo che l'accesso a Internet con una credenziale convalidata è stato bloccato dalla MFA, l'attore ha compromesso organizzazioni vicine al target e ha raggiunto la rete Wi-Fi aziendale del target da un host dual-homed nelle vicinanze. Il percorso Wi-Fi accettava la credenziale senza la MFA richiesta dall'esterno.<sup>[[1]](#references)</sup>

**Effetto sulla privacy.** L'accesso finale proveniva dal raggio fisico della radio e le organizzazioni intermedie erano vittime. L'operazione ha evitato gli spostamenti e ha fatto sì che la geolocalizzazione IP convenzionale puntasse a un vicino.

**Cosa lo ha smascherato.** L'alert del target, l'indagine su host/rete, l'attività delle credenziali, la topologia delle interfacce e la prossimità fisica dovevano essere analizzati come un'unica catena. Il fatto anomalo non era semplicemente un nuovo IP; era un'identità legittima che arrivava attraverso un contesto Wi-Fi/dispositivo insolito mentre i sistemi vicini erano compromessi.

**Lezione difensiva.** Applicare accessi basati su certificati/dispositivi al Wi-Fi, correlare RADIUS con NAC/MDM e il contesto fisico, e analizzare l'infrastruttura vicina invece di presumere che l'ultimo hop sia l'operatore.

## APT28: infrastruttura criminale Moobot riutilizzata dal GRU

**Risultato pubblico.** Nel febbraio 2024, il Dipartimento di Giustizia degli Stati Uniti ha descritto una botnet composta da centinaia di router Ubiquiti EdgeOS. Attori criminali avevano installato Moobot su router che conservavano credenziali amministrative predefinite note; l'Unità 26165 del GRU ha quindi aggiunto script e file, trasformando una botnet criminale esistente in una piattaforma di spionaggio utilizzata per spearphishing e furto di credenziali.<sup>[[2]](#references)</sup>

**Effetto sulla privacy.** Il GRU non ha costruito autonomamente tutta l'infrastruttura. Prendere in prestito una flotta già compromessa ha posto indirizzi di abitazioni e piccoli uffici non correlati tra l'attore e i target, ha mescolato l'attività statale con quella criminale e ha ridotto gli artefatti di registrazione specifici dell'attore.

**Cosa lo ha smascherato.** I file dei router, il comportamento di controllo del malware e le informazioni di routing non relative al contenuto hanno supportato l'indagine. L'interruzione ha modificato temporaneamente le regole del firewall e rimosso i file dannosi, mentre il DOJ ha avvertito che credenziali predefinite non modificate potevano consentire una reinfezione.

**Lezione difensiva.** Sostituire i router non più supportati, rimuovere l'amministrazione esposta a Internet, modificare le impostazioni predefinite, applicare le patch, raccogliere dati di configurazione/di flusso dei dispositivi edge e cercare comportamenti della flotta. Un “Residential US IP” non è una prova che l'operatore sia statunitense.

## Volt Typhoon: KV Botnet più living off the land

**Risultato pubblico.** Il DOJ e un advisory congiunto della CISA hanno descritto Volt Typhoon, sponsorizzato dallo Stato della RPC, mentre utilizzava la KV Botnet, composta principalmente da router SOHO Cisco e NETGEAR compromessi e a fine vita, per nascondere l'origine cinese dell'attività mirata alle infrastrutture critiche. All'interno delle vittime, l'attore privilegiava account validi e strumenti di amministrazione integrati; le agenzie hanno segnalato che in alcuni ambienti l'accesso è durato almeno cinque anni.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
```text
PRC operator -> encrypted KV path -> compromised SOHO exit -> edge service
|
valid accounts + native tools
```
**Effetto sulla privacy.** Il percorso simile a ORB ha nascosto l'origine, mentre il living-off-the-land ha ridotto i binari nuovi e le opportunità basate sulle signature dopo l'accesso. Il concealment della rete e degli endpoint si è rafforzato reciprocamente.

**Cosa lo ha esposto.** La struttura router/controller, la raccolta tecnica autorizzata dal tribunale, l'attività ricorrente e l'analisi tra le vittime hanno avuto più rilevanza di un singolo IOC. Il riavvio di un router ha rimosso il malware KV volatile nei casi descritti, ma non ha corretto l'esposizione sottostante del dispositivo a fine vita.

**Lezione difensiva.** Sostituire gli edge device EOL, centralizzare i log di autenticazione e dei dispositivi di rete, stabilire una baseline del comportamento degli amministratori, limitare la connettività in uscita e cercare sequenze comportamentali tra i livelli identity, endpoint e network.

## China-nexus ORB networks: infrastructure as a service

**Risultato pubblico.** Mandiant ha descritto un ecosistema di ORB networks utilizzate da diversi attori di espionage China-nexus. Le reti provisioned utilizzavano nodi VPS in leasing; le reti non-provisioned utilizzavano IoT e router compromessi; le reti ibride combinavano entrambi. ORB3/SPACEHOP supportava attività associate ad APT5/APT15. ORB2/FLORAHOX combinava un administration server, server in leasing, un layer Tor personalizzato e dispositivi Cisco, ASUS e DrayTek compromessi. Mandiant ha valutato che alcune reti fossero amministrate indipendentemente e affittate a più attori APT.<sup>[[5]](#references)</sup>

**Effetto sulla privacy.** L'infrastruttura è diventata un confine di servizio. Un operatore poteva ottenere exit geografiche/residenziali senza gestire la flotta delle vittime, mentre la condivisione tra molti clienti indeboliva il semplice mapping actor-to-IP. Il rapido turnover della flotta accelerava l'“IOC extinction”.

**Cosa lo ha esposto.** La topologia della rete, le immagini server clonate, porte/servizi, relazioni con i controller, impianti nei router e pattern del ciclo di vita restavano raggruppabili. Mandiant ha riferito che alcuni IP dei nodi sono rimasti in un ORB per appena 31 giorni.

**Lezione difensiva.** Tracciare un ORB come un'entità mutevole: ruoli dei nodi, service fingerprint, relazioni upstream, comportamento di scanning e ritmo di rotazione. La scadenza di un indicatore IP dovrebbe aggiornare il cluster, non cancellare il caso.

## PRC global espionage system: routers, trusted links and traffic mirroring

**Risultato pubblico.** Un advisory multinazionale del 2025 ha descritto attività sovrapposte a nomi usati nei report commerciali, tra cui Salt Typhoon, OPERATOR PANDA, RedMike, UNC5807 e GhostEmperor. Le agenzie hanno riferito l'uso di VPS in leasing e router intermedi compromessi per raggiungere provider di telecomunicazioni e di rete. Gli attori si spostavano attraverso link trusted tra provider e clienti, modificavano le route, creavano tunnel GRE/IPsec, utilizzavano container sui dispositivi e abilitavano SPAN/RSPAN/ERSPAN o la packet capture nativa per raccogliere autenticazioni e traffico dei clienti.<sup>[[13]](#references)</sup>

**Effetto sulla privacy.** Un router compromesso è contemporaneamente relay, punto di osservazione e partecipante trusted alla rete. Le interconnessioni private possono aggirare i controlli progettati intorno a Internet pubblico, mentre il traffic mirroring raccoglie credenziali senza distribuire un endpoint agent.

**Cosa lo espone.** Configuration diff, amministrazione SNMP/SSH/web inattesa, nuove route statiche/tunnel, mirror session, container Guest Shell, file PCAP, modifiche alle destinazioni TACACS+/RADIUS e logging disabilitato. L'advisory sottolinea che alcuni router intermedi non facevano parte di una botnet pubblica precedentemente nominata; pertanto, l'assenza di indicatori ORB noti non era una prova di innocenza.

**Lezione difensiva.** Utilizzare amministrazione out-of-band, log centralizzati di configurazione/autenticazione, controlli di integrità dell'immagine firmata e del runtime, restrizioni sull'egress delle management interface e alert per modifiche a route/mirror/tunnel/AAA. Estendere l'ambito di una compromissione sospetta ai peer trusted prima dell'eviction.

## UNC3886 RedPenguin: passive backdoors on ISP routers

**Risultato pubblico.** Mandiant ha attribuito a UNC3886 backdoor personalizzate derivate da TINYSHELL su router Juniper MX a fine vita. Il set includeva implant attivi e passivi, nomi che imitavano daemon legittimi, comportamento di disabilitazione dei log, process injection in un processo trusted, capacità di SOCKS proxy e infrastruttura valutata come nodi di staging ORB. Le varianti passive ispezionavano i pacchetti tramite `libpcap` e si attivavano solo dopo un magic pattern; una poteva passare a un active callback fornito nel trigger.<sup>[[14]](#references)</sup>

**Effetto sulla privacy.** Un passive implant non emette beacon periodici da individuare. Condivide porte/traffico con un appliance di rete reale, si attiva brevemente e può effettuare relay attraverso un ORB invece di connettersi direttamente a un controller finale.

**Cosa lo espone.** Analisi della memoria, differenze tra codice su disco e codice in esecuzione, filtri di packet capture/comportamento dei socket inattesi, nomi di processi/file che approssimano soltanto daemon legittimi, amministrazione tramite terminal server, log mancanti e la relazione in due fasi tra nodi di staging e backend controller.

**Lezione difensiva.** Acquisire la memoria oltre alle prove relative a filesystem/configurazione, confrontare processi/moduli con un'immagine known-good, monitorare l'uso di packet capture/socket filter, proteggere i management terminal server e sostituire l'hardware di rete EOL. Un hunt pulito per outbound beacon non equivale a un certificato di integrità.

## APT29: Tor domain fronting

**Risultato pubblico.** MITRE documenta l'uso da parte di APT29 del pluggable transport Tor `meek` per effettuare domain fronting del traffico C2. Il nome TLS esterno appariva come un dominio consentito ospitato su una CDN, mentre l'host HTTP interno selezionava il percorso effettivo.<sup>[[6]](#references)</sup>

**Effetto sulla privacy.** Un osservatore che applicava il filtering poteva vedere un front/CDN comune invece della destinazione interna, e bloccarlo rischiava danni collaterali.

**Cosa lo espone.** La CDN può osservare il routing mismatch, mentre un defender con visibilità endpoint o TLS lawful può correlare processo, authority, durata della connessione, byte pattern e attività successive. Modifiche alle policy del provider possono disabilitare la tecnica.

**Lezione difensiva.** Non fare affidamento soltanto sull'allowlisting SNI. Applicare un egress application-aware, confrontare le identità TLS e HTTP quando visibili e collegare l'evento di rete al processo che lo ha avviato.

## APT41 and other dead-drop resolvers

**Risultato pubblico.** MITRE documenta l'uso da parte di APT41 di siti legittimi, tra cui GitHub, Pastebin, Microsoft TechNet, Cloudflare e forum community, per pubblicare o recuperare informazioni C2. Altri tool collegati a gruppi statali hanno utilizzato post, documenti e social media in modo analogo.<sup>[[7]](#references)</sup>

**Effetto sulla privacy.** Un binario contiene un servizio/oggetto legittimo invece di un indirizzo C2 stabile. L'oggetto può essere modificato per ruotare l'infrastruttura, e la richiesta iniziale si confonde con il traffico TLS comune.

**Cosa lo espone.** L'oggetto o l'identificatore dell'account è stabile; processi rari lo scaricano ripetutamente; il contenuto viene decodificato; segue una seconda connessione in uscita. I record dell'account del provider e delle API possono collegare la pubblicazione all'operatore.

**Lezione difensiva.** Conservare i path completi del proxy/object ID e la process lineage dell'endpoint. Un evento a livello di dominio come “connected to GitHub” è troppo generico.

## Turla: satellite-address C2

**Risultato pubblico.** Kaspersky ha riferito che Turla abusava di broadcast downstream non cifrati provenienti da vecchi servizi Internet DVB-S one-way. Un operatore nella copertura satellitare poteva selezionare l'indirizzo di un subscriber legittimo e ricevere le risposte trasmesse a tale indirizzo, facendo apparire il C2 come ospitato dietro un provider satellitare in una regione diversa.<sup>[[8]](#references)</sup>

**Effetto sulla privacy.** L'indirizzo del server apparente non identificava il ricevitore, e i processi convenzionali di seizure/WHOIS dell'hosting erano meno utili.

**Cosa lo espone.** L'attore aveva comunque bisogno di un percorso per le richieste in uscita, il routing era asimmetrico, il subscriber legittimo non avviava lo scambio C2 e un'indagine RF/provider poteva restringere l'area di ricezione.

**Lezione difensiva.** Considerare la geolocalizzazione come una sola ipotesi. Validare la simmetria del percorso, RTT, proprietà del routing e se l'endpoint presunto potesse realmente produrre il servizio osservato.

## Cyclops Blink and VPNFilter: edge devices as durable cover

**Risultato pubblico.** Un advisory NCSC/CISA/FBI/NSA del 2022 ha descritto il malware modulare Cyclops Blink di Sandworm sui dispositivi WatchGuard, distribuito in modo persistente come firmware update e capace di aggiungere moduli. Il DOJ ha descritto separatamente la precedente botnet VPNFilter di APT28, composta da router e dispositivi NAS, come capace di intelligence collection, attività distruttive e misattribution.<sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>

**Effetto sulla privacy.** Gli edge appliance sono costantemente online, trusted come infrastruttura e scarsamente coperti dall'EDR. La persistenza nel firmware può sopravvivere a un normale riavvio e trasformare un dispositivo vittima in un relay o control point.

**Cosa lo espone.** Integrità del firmware, protocollo dell'implant specifico del vendor, esposizione inattesa della gestione, modifiche alla configurazione e outbound beaconing. Gli edge device devono essere soggetti forensi, non plumbing trasparente.

## DPRK: identity, network and financial layering

**Risultato pubblico.** I casi del DOJ descrivono lavoratori DPRK che ottenevano impieghi da remoto utilizzando materiale d'identità falso o rubato e VPN, ricevevano cryptocurrency, suddividevano i trasferimenti, scambiavano asset/chain, utilizzavano NFT e mescolavano i proventi. Altri casi descrivono trader OTC e società di copertura che convertivano cryptocurrency rubata in acquisti. Il Treasury e l'FBI hanno collegato pubblicamente i proventi Lazarus/TraderTraitor a mixer e identificato indirizzi derivanti da furti rilevanti.<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup>

**Effetto sulla privacy.** Non si tratta di “una privacy coin”. È una catena multi-dominio: la persona e l'accesso remoto nascondono la posizione del lavoratore; la crypto trasferisce valore; il layering interrompe le semplici ricostruzioni delle transazioni; trader OTC e società di copertura collegano beni e fiat.

**Cosa lo espone.** Anomalie di employer/device, facilitatori riutilizzati, continuità di tempi/valori sulla blockchain, record di exchange/bridge, indirizzi sanzionati, identità dell'account e record di spedizioni/società ricostruiscono la catena.

**Lezione difensiva.** I team di hiring, IAM, endpoint, payroll, blockchain e sanzioni hanno bisogno di un modello di caso condiviso. Ulteriori dettagli sono disponibili in [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md).

## Cross-case patterns

| Pattern | Esempi APT | Adattamento del defender |
|---|---|---|
| L'uscita è un'altra vittima | APT28/Moobot, Volt Typhoon/KV, ORBs | indagare e correggere l'exit; non assimilarla alla posizione dell'attore |
| I controlli differiscono in base al confine | APT28 nearest neighbor | assegnare all'accesso interno/wireless la stessa garanzia d'identità dell'accesso Internet |
| Il servizio legittimo è un routing layer | APT29, APT41 | conservare il contesto di oggetto/path/processo, non solo il dominio di destinazione |
| Gli edge device non hanno telemetria | KV, Moobot, Cyclops Blink, ORBs | centralizzare i log di config/auth/flow e verificare firmware/inventario |
| L'infrastruttura è condivisa e di breve durata | China-nexus ORBs | raggruppare comportamento/topologia e tracciare nel tempo i cambiamenti di ruolo |
| Diverse separazioni deboli si compongono | DPRK personas + VPN + crypto + OTC | correlare evidenze di identità, dispositivo, rete, pagamento e presenza fisica |

## References

- [1] [Volexity — L'attacco Nearest Neighbor](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [US DOJ — Interruzione della botnet router Moobot controllata dal GRU](https://www.justice.gov/archives/opa/pr/justice-department-conducts-court-authorized-disruption-botnet-controlled-russian)
- [3] [US DOJ — Interruzione della botnet KV della PRC](https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical)
- [4] [CISA AA24-038A — Gli attori della PRC compromettono e mantengono l'accesso persistente alle infrastrutture critiche statunitensi](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [5] [Google Cloud/Mandiant — Gli attori di espionage China-nexus utilizzano ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [6] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [7] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [Kaspersky Securelist — Turla satellitare](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [9] [CISA/NCSC/FBI/NSA — Advisory Cyclops Blink AA22-054A](https://www.cisa.gov/sites/default/files/publications/AA22-054A%20New%20Sandworm%20Malware%20Cyclops%20Blink%20Replaces%20VPN%20Filter.pdf)
- [10] [US DOJ — Interruzione di APT28 VPNFilter](https://www.justice.gov/archives/opa/pr/justice-department-announces-actions-disrupt-advanced-persistent-threat-28-botnet-infected)
- [11] [US DOJ — Rappresentante della Foreign Trade Bank della DPRK incriminato per cospirazioni di crypto-laundering](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [12] [US Treasury — Sanzioni Blender.io e fondi Lazarus](https://home.treasury.gov/news/press-releases/jy0768)
- [13] [CISA AA25-239A — Contrastare la compromissione delle reti globali da parte di attori sponsorizzati dallo Stato cinese](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [14] [Google Cloud/Mandiant — Ghost in the Router: UNC3886 prende di mira i router Juniper](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers)
{{#include ../banners/hacktricks-training.md}}
