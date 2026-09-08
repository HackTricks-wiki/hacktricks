# Casi di studio governativi e APT

Questi casi pubblici mostrano come diverse tecniche di privacy vengano combinate in operazioni reali. Le etichette di attribuzione sono quelle utilizzate dagli investigatori o dai governi citati; un indirizzo IP, una sovrapposizione di tool o una corrispondenza geopolitica, presi singolarmente, non costituiscono un'attribuzione conclusiva.

## APT28: accesso Wi-Fi tramite nearest-neighbor remoto

**Risultato pubblico.** Volexity ha attribuito un'intrusione del 2022 a GruesomeLarch/APT28. Dopo che l'accesso a Internet con una credential validata è stato bloccato dall'MFA, l'attore ha compromesso organizzazioni vicine al target e ha raggiunto il Wi-Fi aziendale del target da un host dual-homed nelle vicinanze. Il percorso Wi-Fi accettava la credential senza l'MFA richiesto esternamente.<sup>[[1]](#references)</sup>

**Effetto sulla privacy.** L'accesso finale proveniva dal raggio fisico della radio e le organizzazioni intermedie erano vittime. L'operazione ha evitato gli spostamenti e ha fatto sì che la geolocalizzazione IP convenzionale indicasse un vicino.

**Cosa lo ha esposto.** L'alert del target, l'indagine su host/rete, l'attività delle credential, la topologia delle interfacce e la prossimità fisica dovevano essere analizzati come un'unica catena. Il fatto anomalo non era semplicemente un nuovo IP; era un'identità legittima che arrivava attraverso un contesto Wi-Fi/device insolito mentre i sistemi vicini erano compromessi.

**Lezione difensiva.** Applicare l'accesso al Wi-Fi basato su certificati/device, correlare RADIUS con NAC/MDM e il contesto fisico, e investigare l'infrastruttura vicina invece di presumere che l'ultimo hop sia l'operatore.

## APT28: infrastruttura criminale Moobot riutilizzata dal GRU

**Risultato pubblico.** Nel febbraio 2024, il Dipartimento di Giustizia degli Stati Uniti ha descritto una botnet composta da centinaia di router Ubiquiti EdgeOS. Attori criminali avevano installato Moobot su router che conservavano credential administrator predefinite note; l'Unità 26165 del GRU ha quindi aggiunto script e file, trasformando una botnet criminale esistente in una piattaforma di spionaggio utilizzata per spearphishing e credential theft.<sup>[[2]](#references)</sup>

**Effetto sulla privacy.** Il GRU non ha costruito autonomamente tutta l'infrastruttura. Prendere in prestito una flotta già compromessa ha collocato indirizzi di abitazioni e piccoli uffici non correlati tra l'attore e i target, ha mescolato l'attività statale con quella criminale e ha ridotto gli artefatti di registrazione specifici dell'attore.

**Cosa lo ha esposto.** I file dei router, il comportamento di controllo del malware e le informazioni di routing non relative ai contenuti hanno supportato l'indagine. L'interruzione ha modificato temporaneamente le regole del firewall e rimosso i file malevoli, mentre il DOJ ha avvertito che credential predefinite non modificate potevano consentire una reinfezione.

**Lezione difensiva.** Sostituire i router non supportati, rimuovere l'amministrazione esposta a Internet, modificare i valori predefiniti, applicare le patch, raccogliere dati di configurazione/flow degli edge device e cercare comportamenti a livello di flotta. Un “Residential US IP” non è una prova che l'operatore sia statunitense.

## Volt Typhoon: KV Botnet e living off the land

**Risultato pubblico.** Il DOJ e un advisory congiunto di CISA hanno descritto Volt Typhoon, sponsorizzato dallo Stato della RPC, mentre utilizzava la KV Botnet, composta principalmente da router SOHO Cisco e NETGEAR compromessi e ormai a fine vita, per nascondere l'origine cinese dell'attività rivolta alle infrastrutture critiche. All'interno delle vittime, l'attore privilegiava account validi e tool di amministrazione integrati; le agenzie hanno riferito che in alcuni ambienti l'accesso è durato almeno cinque anni.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
```text
PRC operator -> encrypted KV path -> compromised SOHO exit -> edge service
|
valid accounts + native tools
```
**Effetto sulla privacy.** Il percorso simile a ORB ha nascosto l'origine, mentre il living-off-the-land ha ridotto i binary nuovi e le opportunità basate sulle signature dopo l'accesso. Il mascheramento a livello di network ed endpoint si è rafforzato reciprocamente.

**Cosa lo ha esposto.** La struttura router/controller, la raccolta tecnica autorizzata dal tribunale, l'attività ricorrente e l'analisi tra vittime sono state più importanti di un singolo IOC. Il riavvio di un router ha rimosso il malware KV volatile nei casi descritti, ma non ha corretto l'esposizione sottostante del dispositivo ormai end-of-life.

**Lezione difensiva.** Sostituire gli edge device EOL, centralizzare i log di autenticazione e dei network device, definire una baseline del comportamento degli amministratori, limitare la connettività in uscita e cercare sequenze comportamentali tra i layer di identità, endpoint e network.

## China-nexus ORB networks: infrastruttura come servizio

**Risultato pubblico.** Mandiant ha descritto un ecosistema di ORB networks utilizzate da più attori di spionaggio China-nexus. Le reti provisioned utilizzavano nodi VPS in leasing; le reti non-provisioned utilizzavano IoT e router compromessi; le reti ibride combinavano entrambi. ORB3/SPACEHOP supportava attività associate ad APT5/APT15. ORB2/FLORAHOX combinava un administration server, server in leasing, un layer Tor personalizzato e dispositivi Cisco, ASUS e DrayTek compromessi. Mandiant ha valutato che alcune reti fossero amministrate autonomamente e affittate a più attori APT.<sup>[[5]](#references)</sup>

**Effetto sulla privacy.** L'infrastruttura è diventata un confine di servizio. Un operatore poteva ottenere exit geografici/residenziali senza mantenere la fleet delle vittime, mentre la condivisione tra molti clienti indeboliva la semplice associazione tra attore e IP. Il rapido ricambio della fleet accelerava l'“estinzione degli IOC”.

**Cosa lo ha esposto.** Topologia di rete, immagini server clonate, porte/servizi, relazioni con i controller, impianti sui router e pattern del ciclo di vita rimanevano raggruppabili. Mandiant ha riferito che alcuni IP dei nodi sono rimasti in un ORB per appena 31 giorni.

**Lezione difensiva.** Tracciare un ORB come un'entità mutevole: ruoli dei nodi, service fingerprint, relazioni upstream, comportamento di scanning e ritmo di rotazione. La scadenza di un indicatore IP dovrebbe aggiornare il cluster, non cancellare il caso.

## PRC global espionage system: router, link trusted e traffic mirroring

**Risultato pubblico.** Un advisory multinazionale del 2025 ha descritto attività sovrapposte a nomi usati nei report commerciali, tra cui Salt Typhoon, OPERATOR PANDA, RedMike, UNC5807 e GhostEmperor. Le agenzie hanno riportato l'uso di VPS in leasing e router intermedi compromessi per raggiungere provider di telecomunicazioni e network. Gli attori hanno eseguito pivot attraverso link trusted tra provider e clienti, modificato le route, creato tunnel GRE/IPsec, utilizzato container sui dispositivi e abilitato SPAN/RSPAN/ERSPAN o il packet capture nativo per raccogliere autenticazione e traffico dei clienti.<sup>[[13]](#references)</sup>

**Effetto sulla privacy.** Un router compromesso è contemporaneamente un relay, un punto di osservazione e un partecipante trusted al network. Le interconnessioni private possono bypassare i controlli progettati attorno a Internet pubblico, mentre il traffic mirroring raccoglie credenziali senza distribuire un agent sull'endpoint.

**Cosa lo espone.** Differenze di configurazione, amministrazione SNMP/SSH/web inattesa, nuove route statiche/tunnel, sessioni di mirroring, container Guest Shell, file PCAP, modifiche alle destinazioni TACACS+/RADIUS e logging disabilitato. L'advisory sottolinea che alcuni router intermedi non facevano parte di una botnet pubblica precedentemente nominata; pertanto, l'assenza di indicatori ORB noti non era scagionante.

**Lezione difensiva.** Utilizzare l'amministrazione out-of-band, log centralizzati di configurazione/autenticazione, controlli di integrità dell'immagine firmata e del runtime, restrizioni sull'egress delle interfacce di management e alert per modifiche a route/mirror/tunnel/AAA. Estendere l'analisi di una compromissione sospetta ai peer trusted prima dell'eviction.

## UNC3886 RedPenguin: passive backdoor sui router degli ISP

**Risultato pubblico.** Mandiant ha attribuito a UNC3886 backdoor personalizzate derivate da TINYSHELL su router Juniper MX end-of-life. Il set includeva impianti attivi e passivi, nomi simili a daemon legittimi, comportamento di disabilitazione dei log, process injection in un processo trusted, funzionalità SOCKS proxy e infrastruttura valutata come nodi di staging ORB. Le varianti passive ispezionavano i pacchetti tramite `libpcap` e si attivavano solo dopo un magic pattern; una poteva passare a un active callback fornito nel trigger.<sup>[[14]](#references)</sup>

**Effetto sulla privacy.** Un impianto passivo non dispone di un beacon periodico da rilevare. Condivide porte/traffico con un vero network appliance, si attiva brevemente e può effettuare relay tramite un ORB invece di connettersi direttamente al controller finale.

**Cosa lo espone.** Analisi della memoria, differenze tra codice su disco e codice in esecuzione, filtri di packet capture o comportamento dei socket inattesi, nomi di processi/file che imitano solo approssimativamente daemon legittimi, amministrazione tramite terminal server, log mancanti e relazione a due stadi tra i nodi di staging e un backend controller.

**Lezione difensiva.** Acquisire la memoria oltre alle evidenze di filesystem/configurazione, confrontare processi/moduli con un'immagine nota come good, monitorare l'uso di packet capture/socket filter, proteggere i terminal server di management e sostituire l'hardware di rete EOL. Un hunt pulito per outbound beacon non garantisce l'assenza di compromissione.

## APT29: domain fronting Tor

**Risultato pubblico.** MITRE registra l'uso da parte di APT29 del pluggable transport Tor `meek` per eseguire domain fronting del traffico C2. Il nome TLS esterno appariva come un dominio ospitato su un CDN consentito, mentre l'host HTTP interno selezionava il percorso effettivo.<sup>[[6]](#references)</sup>

**Effetto sulla privacy.** Un osservatore che applicava filtri poteva vedere un front/CDN comune anziché la destinazione interna, e bloccarlo rischiava danni collaterali.

**Cosa lo espone.** Il CDN può osservare la discrepanza di routing, mentre un defender con visibilità sull'endpoint o sul TLS ottenuta legalmente può correlare processo, authority, durata della connessione, pattern dei byte e attività successive. I cambiamenti nelle policy del provider possono disabilitare la tecnica.

**Lezione difensiva.** Non affidarsi esclusivamente all'allowlisting SNI. Applicare un egress consapevole dell'applicazione, confrontare le identità TLS e HTTP quando visibili e associare l'evento di rete al processo che lo ha avviato.

## APT41 e altri dead-drop resolver

**Risultato pubblico.** MITRE documenta l'uso da parte di APT41 di siti legittimi, tra cui GitHub, Pastebin, Microsoft TechNet, Cloudflare e forum di community, per pubblicare o recuperare informazioni C2. Altri tool collegati ad attività statali hanno utilizzato in modo simile post, documenti e social media.<sup>[[7]](#references)</sup>

**Effetto sulla privacy.** Un binary contiene un servizio/oggetto legittimo anziché un indirizzo C2 stabile. L'oggetto può essere modificato per ruotare l'infrastruttura e la richiesta iniziale si confonde con il traffico TLS comune.

**Cosa lo espone.** L'oggetto o l'identificatore dell'account è stabile; processi rari lo recuperano ripetutamente; il contenuto viene decodificato; segue una seconda connessione in uscita. I record dell'account del provider e delle API possono collegare la pubblicazione all'operatore.

**Lezione difensiva.** Conservare i percorsi completi del proxy/gli object ID e la process lineage dell'endpoint. Un evento a livello di dominio come “connesso a GitHub” è troppo generico.

## Turla: C2 tramite indirizzi satellitari

**Risultato pubblico.** Kaspersky ha riportato che Turla abusava di broadcast downstream non cifrati provenienti da vecchi servizi Internet DVB-S unidirezionali. Un operatore nella copertura satellitare poteva selezionare l'indirizzo di un abbonato legittimo e ricevere le risposte trasmesse a tale indirizzo, facendo apparire il C2 come ospitato dietro un provider satellitare in un'altra regione.<sup>[[8]](#references)</sup>

**Effetto sulla privacy.** L'indirizzo del server apparente non identificava il ricevitore e i processi convenzionali di sequestro dell'hosting/WHOIS erano meno utili.

**Cosa lo espone.** L'attore aveva comunque bisogno di un percorso per le richieste in uscita, il routing era asimmetrico, l'abbonato legittimo non avviava lo scambio C2 e un'indagine RF/provider poteva restringere l'area di ricezione.

**Lezione difensiva.** Considerare la geolocalizzazione come una sola ipotesi. Validare simmetria del percorso, RTT, titolarità del routing e possibilità che l'endpoint dichiarato produca effettivamente il servizio osservato.

## Cyclops Blink e VPNFilter: edge device come copertura persistente

**Risultato pubblico.** Un advisory NCSC/CISA/FBI/NSA del 2022 ha descritto il malware modulare Cyclops Blink di Sandworm sui dispositivi WatchGuard, distribuito in modo persistente come firmware update e capace di aggiungere moduli. Il DOJ ha descritto separatamente la precedente botnet APT28 VPNFilter di router e dispositivi NAS come capace di intelligence collection, attività distruttive e misattribution.<sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>

**Effetto sulla privacy.** Gli edge appliance sono sempre online, trusted come infrastruttura e coperti in modo insufficiente dall'EDR. La persistenza nel firmware può sopravvivere a un normale riavvio e trasformare un dispositivo della vittima in un relay o control point.

**Cosa lo espone.** Integrità del firmware, protocollo dell'impianto specifico del vendor, esposizione inattesa del management, modifiche alla configurazione e outbound beaconing. Gli edge device devono essere soggetti forensi, non plumbing trasparente.

## DPRK: identity, network e financial layering

**Risultato pubblico.** I casi del DOJ descrivono lavoratori DPRK che ottenevano impieghi remote utilizzando materiale d'identità falso o rubato e VPN, ricevevano cryptocurrency, suddividevano i trasferimenti, scambiavano asset/chain, utilizzavano NFT e mescolavano i proventi. Altri casi descrivono trader OTC e front company che convertivano crypto rubate in acquisti. Il Tesoro e l'FBI hanno collegato pubblicamente i proventi di Lazarus/TraderTraitor a mixer e identificato indirizzi provenienti da grandi furti.<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup>

**Effetto sulla privacy.** Non si tratta di “una private coin”. È una catena multidominio: persona e accesso remote nascondono la posizione del lavoratore; la crypto trasferisce valore; il layering interrompe le semplici narrazioni delle transazioni; trader OTC e front company collegano beni e fiat.

**Cosa lo espone.** Anomalie di employer/device, facilitatori riutilizzati, continuità di tempi/valori sulla blockchain, record di exchange/bridge, indirizzi sanzionati, identità dell'account e record di spedizione/azienda ricongiungono la catena.

**Lezione difensiva.** I team hiring, IAM, endpoint, payroll, blockchain e sanzioni hanno bisogno di un modello di caso condiviso. Ulteriori dettagli sono disponibili in [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md).

## Pattern trasversali

| Pattern | Esempi APT | Adattamento del defender |
|---|---|---|
| L'uscita è un'altra vittima | APT28/Moobot, Volt Typhoon/KV, ORB | investigare e correggere l'uscita; non assimilarla alla posizione dell'attore |
| I controlli differiscono in base al confine | APT28 nearest neighbor | fornire all'accesso interno/wireless la stessa identity assurance dell'accesso Internet |
| Un servizio legittimo è un layer di routing | APT29, APT41 | conservare il contesto di oggetto/percorso/processo, non solo il dominio di destinazione |
| Gli edge device mancano di telemetria | KV, Moobot, Cyclops Blink, ORB | centralizzare i log di config/auth/flow e verificare firmware/inventory |
| L'infrastruttura è condivisa e di breve durata | China-nexus ORB | raggruppare comportamento/topologia e tracciare nel tempo i cambiamenti di ruolo |
| Diverse separazioni deboli si compongono | persona DPRK + VPN + crypto + OTC | unire evidenze di identità, device, network, pagamenti e fisiche |

## References

- [1] [Volexity — L'attacco Nearest Neighbor](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [US DOJ — Interruzione della botnet di router Moobot controllata dal GRU](https://www.justice.gov/archives/opa/pr/justice-department-conducts-court-authorized-disruption-botnet-controlled-russian)
- [3] [US DOJ — Interruzione della botnet PRC KV](https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical)
- [4] [CISA AA24-038A — Gli attori PRC compromettono e mantengono l'accesso persistente alle infrastrutture critiche statunitensi](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [5] [Google Cloud/Mandiant — Gli attori di spionaggio China-nexus utilizzano ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [6] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [7] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [Kaspersky Securelist — Turla satellitare](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [9] [CISA/NCSC/FBI/NSA — Advisory Cyclops Blink AA22-054A](https://www.cisa.gov/sites/default/files/publications/AA22-054A%20New%20Sandworm%20Malware%20Cyclops%20Blink%20Replaces%20VPN%20Filter.pdf)
- [10] [US DOJ — Interruzione di APT28 VPNFilter](https://www.justice.gov/archives/opa/pr/justice-department-announces-actions-disrupt-advanced-persistent-threat-28-botnet-infected)
- [11] [US DOJ — Rappresentante della Foreign Trade Bank DPRK incriminato per cospirazioni di riciclaggio crypto](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [12] [US Treasury — Sanzioni a Blender.io e fondi Lazarus](https://home.treasury.gov/news/press-releases/jy0768)
- [13] [CISA AA25-239A — Contrastare la compromissione globale dei network da parte di attori sponsorizzati dallo Stato cinese](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [14] [Google Cloud/Mandiant — Ghost in the Router: UNC3886 prende di mira i router Juniper](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers)
