# Privacy di rete e connettività anonima

{{#include ../banners/hacktricks-training.md}}

La privacy di rete è una decisione di routing, non un'identità completa. Seleziona un percorso chiedendoti chi non dovrebbe riuscire a collegare **fonte**, **destinazione**, **contenuto** e **tempistica**.

Per l'inventario normalizzato—`Pros`, `Cons`, `Procedure` passo per passo e `Detection` per ogni famiglia di percorsi di accesso—inizia dal [Catalogo delle tecniche di accesso anonimo a Internet](anonymous-internet-access-techniques.md). Questa pagina amplia le opzioni comuni implementabili.

## Cosa può solitamente vedere ogni osservatore

| Percorso | Rete locale / ISP | Intermediario | Destinazione | Limitazione principale | Velocità relativa |
|---|---|---|---|---|---|
| HTTPS diretto | Metadati della fonte e della destinazione, tempistica/volume | L'hosting/CDN vede la connessione | IP della fonte, dati del browser/app | Nessuna privacy dell'IP sorgente | Massima |
| VPN commerciale | Fonte connessa alla VPN; non i consueti metadati della destinazione | La VPN vede la fonte e i metadati della destinazione | IP di egress della VPN | Un provider diventa un punto di correlazione | Solitamente elevata |
| VPN/VPS self-hosted | Fonte connessa al VPS | Log dell'host/account/control-plane/pagamento | IP di egress del VPS | Facile da attribuire al server/account noleggiato | Solitamente elevata |
| Tor Browser | Fonte connessa a Tor/bridge; tempistica/volume | Ogni relay vede una porzione limitata | Exit Tor, dati del browser | Più lento; rischi relativi ad account/endpoint/correlazione | Media/lenta |
| Tails/Whonix | Percorso Tor simile, con confini di routing più forti | Le stesse limitazioni di Tor | Exit Tor/dati dell'applicazione | Errori operativi e host/hardware rimangono | Media/lenta |
| Wi-Fi guest pubblico + HTTPS | La sede vede il dispositivo locale/la tempistica e le destinazioni | L'ISP della sede vede i metadati | IP pubblico guest | Correlazione fisica/captive portal/dispositivo | Elevata/variabile |
| Hotspot cellulare | Il carrier vede abbonato/dispositivo/posizione e destinazioni | VPN/Tor, se utilizzati | IP di egress del carrier, della VPN o di Tor | L'abbonamento mobile e la posizione sono identificatori persistenti | Elevata/variabile |
| Mixnet | L'accesso vede l'utilizzo della mixnet; tempistica/volume | Più nodi di mixing | Gateway/egress | Ecosistema emergente; costi di latenza e banda | Più lenta |

HTTPS protegge il contenuto durante il transito, ma non tutti i metadati. EFF osserva che dominio, orario e dimensione del traffico possono rimanere visibili agli intermediari anche quando i percorsi delle pagine, le credenziali e i messaggi sono cifrati.<sup>[[1]](#references)</sup>

## VPN: privacy veloce con fiducia concentrata

Una VPN è utile per nascondere i metadati della destinazione all'ISP di accesso, proteggere il primo hop su una rete non affidabile, presentare un indirizzo di egress stabile per un engagement o raggiungere una rete privata. **Non** rende anonimo l'utente. La VPN vede la connessione sorgente e può osservare i metadati della destinazione; account, cookie, GPS, fingerprint e informazioni di pagamento rimangono.<sup>[[1]](#references)</sup>

### Checklist per valutare un provider

1. **Proprietà e giurisdizione:** identifica l'entità legale, la società madre, i Paesi operativi, i subappaltatori dell'infrastruttura e le procedure legali applicabili.
2. **Dati raccolti:** distingui tra dati di account/fatturazione, IP sorgente, timestamp delle connessioni, banda, telemetria dei crash, query DNS e log delle destinazioni. “Nessun log di navigazione” non significa “nessun dato”.
3. **Conservazione ed eliminazione:** individua durate precise e verifica se backup, sistemi antifrode e processor seguono lo stesso calendario.
4. **Evidenze:** preferisci audit pubblici con ambito, data, risultati e remediation; client riproducibili/open; transparency report; e incidenti documentati.
5. **Protocollo e client:** WireGuard, OpenVPN o un altro protocollo revisionato e mantenuto; aggiornamenti automatici; gestione di DNS e IPv6; kill switch; e test di leak per piattaforma.
6. **Modello di business:** comprendi come viene finanziato un servizio gratuito o sovvenzionato. La sola presenza nell'app store non è una prova di funzionamento affidabile.
7. **Compatibilità dei pagamenti:** un pagamento alternativo può ridurre la divulgazione dei dati di fatturazione alla VPN, ma non elimina l'IP sorgente osservato a ogni connessione.

### Configurare e verificare una VPN

1. Installa il client firmato del provider/organizzazione dalla sua fonte ufficiale.
2. Seleziona il **tunnel completo**, salvo che un percorso documentato debba escluderlo. Lo split tunneling crea percorsi di correlazione e leak.
3. Abilita il comportamento fail-closed/always-on e blocca il traffico durante la riconnessione.
4. Invia il DNS attraverso il tunnel e verifica sia IPv4 sia IPv6. Disabilita un protocollo solo se non può essere incanalato in sicurezza e si accetta la perdita di funzionalità.
5. Verifica sospensione/riattivazione, cambio di rete, accesso al captive portal, crash del tunnel e tethering tramite hotspot. NCSC avverte che, su alcune piattaforme, i client con tethering possono bypassare la VPN del telefono.<sup>[[2]](#references)</sup>
6. Utilizza un endpoint di test controllato dall'organizzazione per registrare IPv4, IPv6, resolver DNS e tempistica della connessione osservati. Non esporre un engagement sensibile a siti casuali di “leak test”.
7. Ripeti il test dopo modifiche al client, al sistema operativo, alla rete o alle policy.

### Bypass del routing su LAN ostili

Una VPN può rimanere visibilmente “connessa” mentre pacchetti selezionati la bypassano, perché il sistema operativo sceglie un percorso **prima** che la VPN cifri il pacchetto. TunnelCrack ha dimostrato due modi per abusare delle comuni eccezioni di routing: **LocalNet** fa apparire una destinazione Internet come appartenente alla subnet direttamente connessa, mentre **ServerIP** falsifica la risoluzione del gateway VPN, così un indirizzo target eredita l'eccezione della rete in chiaro necessaria al trasporto VPN. Si tratta di errori del client/routing, non di vulnerabilità in WireGuard, OpenVPN, IPsec o TLS; i payload HTTPS rimangono cifrati end-to-end, ma l'osservatore locale può recuperare i metadati di destinazione/tempistica e qualsiasi dato di protocollo in chiaro.<sup>[[18]](#references)</sup>

TunnelVision applica lo stesso primitivo pre-cifratura tramite l'opzione DHCP 121. Un server DHCP malevolo o compromesso può installare un percorso classless più specifico del percorso catch-all della VPN, selezionando l'interfaccia fisica per un host o un intervallo arbitrario. Il control channel della VPN può rimanere attivo, quindi un kill switch attivato solo dalla disconnessione del tunnel potrebbe non entrare in funzione e un singolo controllo pubblico dell'“IP leak” potrebbe non rilevare bypass selettivi.<sup>[[19]](#references)</sup>

Un kill switch basato sul packet filter che consenta sull'interfaccia fisica solo DHCP e il trasporto VPN autenticato dovrebbe trasformare questo scenario in un comportamento fail-closed, ma l'iniezione mirata di percorsi può comunque creare un side channel di denial selettivo. Per workload Linux ad alto impatto, preferisci il [pattern di network namespace con routing enforcement](advanced-network-privacy-architectures.md#enforce-the-route-per-workload) più robusto, in cui il namespace dell'applicazione non dispone di un'interfaccia fisica né di un percorso predefinito verso la rete in chiaro.<sup>[[19]](#references)</sup>

#### Verifica in un lab controllato

Testa il client/OS/versione esatti su un AP, un server DHCP, un endpoint VPN e una destinazione di proprietà; le affermazioni generali sui prodotti diventano rapidamente obsolete perché le implementazioni di routing e packet filter sono specifiche della piattaforma. Esegui la cattura anche sull'endpoint stesso, oltre che sul test server: un sito che mostra l'IP di egress da solo non dimostra che ogni destinazione segua il tunnel.<sup>[[18]](#references)[[19]](#references)</sup>

1. Connettiti alla VPN, registra l'indirizzo del server VPN e salva ogni tabella di routing IPv4/IPv6 e ogni regola di policy routing. Su Windows usa `route print`; su macOS usa `netstat -rn`; su Linux usa i comandi seguenti.
2. Interroga il percorso selezionato per diversi IP di destinazione di tua proprietà. Il next hop/l'interfaccia deve essere il tunnel, ad eccezione dell'endpoint di trasporto VPN documentato.
3. Per TunnelVision, rinnova il lease sulla rete DHCP controllata e installa un percorso con opzione 121 **solo per una destinazione di test di tua proprietà**. Un passaggio significa che il traffico è ancora incanalato nel tunnel o bloccato, mai emesso come traffico verso la destinazione sull'interfaccia fisica.
4. Per LocalNet, assegna al client una subnet pubblica riservata esclusivamente alla documentazione, come `203.0.113.0/24`, e colloca al suo interno la destinazione di test di tua proprietà. Verifica che l'abilitazione dell'accesso LAN non faccia bypassare il tunnel alle destinazioni di classe Internet.
5. Per ServerIP, prima della connessione VPN fai in modo che il DNS controllato risolva l'hostname VPN di tua proprietà nella destinazione di test di tua proprietà, mentre il gateway del lab inoltra il trasporto VPN al vero endpoint VPN di tua proprietà. Il client non deve esentare traffico applicativo non correlato verso l'indirizzo falsificato.
6. Ripeti con “accesso alla rete locale” abilitato e disabilitato, dopo riconnessione, sospensione/riattivazione, cambio di rete e crash del processo VPN. Testa IPv4, IPv6 e DNS separatamente.
7. Esamina la cattura sull'interfaccia fisica. Dovrebbe contenere DHCP e pacchetti cifrati verso il server VPN, non pacchetti indirizzati direttamente alla destinazione di test di tua proprietà. Verifica inoltre che un bypass rifiutato non possa ricadere silenziosamente dopo i prompt dell'utente o il ripristino della connettività.
```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```
## Tor Browser: maggiore unlinkability sul web

Tor costruisce un circuito attraverso più relay, così normalmente nessun singolo relay conosce sia la sorgente sia la destinazione. La destinazione vede un'uscita Tor invece dell'IP dell'utente; la rete locale normalmente vede una connessione Tor.<sup>[[3]](#references)</sup> Tor è progettato per applicazioni TCP a bassa latenza, quindi è più lento e non può garantire protezione contro un avversario in grado di correlare entrambe le estremità.<sup>[[4]](#references)</sup>

### Workflow sicuro con Tor Browser

1. Scarica Tor Browser solo dal Tor Project o da un mirror ufficiale e verifica la firma quando possibile.
2. Usa **Tor Browser**, non un browser normale indirizzato a una porta SOCKS di Tor. I browser comuni possono causare leak DNS/WebRTC e rivelare informazioni identificative.<sup>[[5]](#references)</sup>
3. Mantieni dimensioni, font, estensioni e impostazioni di privacy predefiniti. Componenti aggiuntivi extra possono rendere il browser più univoco.<sup>[[6]](#references)</sup>
4. Scegli il livello di sicurezza **Safer** o **Safest** quando la maggiore incompatibilità è accettabile.
5. Usa un bridge quando Tor diretto è bloccato o quando gli IP dei relay ordinari creerebbero una visibilità locale inaccettabile. I bridge riducono il riconoscimento immediato, ma non eliminano l'analisi del traffico.<sup>[[7]](#references)</sup>
6. Non accedere a un account identificativo, non fornire informazioni identificative e non aprire documenti attivi scaricati in un'applicazione esterna con accesso alla rete.
7. Usa una sessione/un contesto separato per ogni identità. “New circuit” non equivale a cancellare l'identità del browser/dell'applicazione; usa **New Identity** o riavvia l'ambiente isolato secondo necessità.
8. Preferisci HTTPS autenticato o un onion service autenticato. Un'uscita Tor può osservare il traffico HTTP non cifrato.

### Tor più VPN

Combinarli non è automaticamente più sicuro. Una VPN prima di Tor può nascondere a un ISP le connessioni dirette ai relay Tor, mentre la VPN vede la sorgente; Tor prima di una VPN offre alla VPN una visione stabile dell'attività successiva a Tor e può ridurre l'insieme di anonimato. Una configurazione errata può introdurre leak. Tor Project raccomanda queste combinazioni solo per threat model avanzati ed espliciti.<sup>[[8]](#references)</sup>

## Wi-Fi pubblico e guest

L'HTTPS moderno fa sì che i vicini passivi normalmente non possano leggere contenuti web correttamente cifrati, ma il Wi-Fi guest non garantisce l'anonimato. Il gestore del luogo può registrare orari di associazione, identificatori del dispositivo, dati del captive portal, destinazioni e dettagli DHCP; telecamere, acquisti, trasporti e osservazione fisica possono identificare l'utente. Un hotspot falso con un nome simile può inoltre catturare credenziali del portal o manipolare il traffico non cifrato.<sup>[[9]](#references)</sup>

### Workflow legittimo per reti guest

1. Usa solo una rete offerta agli ospiti o una per cui il proprietario abbia concesso un'autorizzazione esplicita. Chiedi al personale l'SSID esatto e la procedura del portal.
2. Aggiorna l'endpoint e il travel router prima dell'arrivo. Disabilita la condivisione di file/stampanti, il rilevamento inbound, l'auto-join e la ricerca di reti memorizzate.
3. Abilita l'indirizzo Wi-Fi privato/randomizzato del sistema operativo. I sistemi Apple attuali possono usare indirizzi rotanti sulle reti aperte/deboli; la randomizzazione moderna di Android è comunemente persistente per SSID. Questo riduce un solo identificatore locale.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Preferisci un travel router controllato dall'organizzazione o un bridge device a basso livello di fiducia tra una workstation privilegiata e la rete guest. Questo centralizza le policy firewall/VPN, ma non nasconde il router al gestore del luogo.<sup>[[12]](#references)</sup>
5. Completa un captive portal solo tramite il device/browser designato a basso livello di fiducia. Non inserire mai credenziali personali o riutilizzate per un contesto presumibilmente anonimo. Chiudi il browser del portal dopo aver stabilito la connettività.
6. Avvia una VPN full-tunnel o Tor prima delle attività sensibili e conferma il comportamento fail-closed.
7. Dimentica la rete dopo l'uso e verifica la policy dell'account del portal e della conservazione dei dati.

{% hint style="danger" %}
Craccare il Wi-Fi di un vicino, aggirare un portal, usare credenziali guest ottenute tramite leak, clonare l'accesso di un altro ospite o nascondere un Raspberry Pi in un bar sono attività non autorizzate, non tecniche di privacy. Le alternative sicure sono una rete guest legittima, un sito approvato dal cliente oppure un drop node documentato, installato e recuperato con il consenso scritto del proprietario.
{% endhint %}

## Travel router

Un travel router può isolare una workstation dai broadcast locali ostili, applicare un firewall, fornire un SSID interno coerente e riconnettere automaticamente una VPN. **Non** è anonimo: l'upstream vede la sua identità radio e i tempi del traffico, mentre il provider VPN vede la sorgente del tunnel.

- Usa firmware OpenWrt/vendor supportato e rimuovi i servizi inutilizzati.
- Amministralo tramite Ethernet o un SSID di gestione dedicato con una password univoca.
- Disabilita l'amministrazione dal lato WAN, UPnP, WPS, condivisione di file e traffico inbound non richiesto.
- Usa un MAC WAN randomizzato/privato solo quando supportato e consentito.
- Applica la policy VPN sul router, inclusi DNS e IPv6, e blocca l'egress quando il tunnel non è attivo.
- Non presumere che un hotspot del telefono instradi i device tethered attraverso la VPN del telefono; verificalo.

## Reti cellulari, SIM ed eSIM

La rete cellulare è comoda ma non anonima. Gli operatori mantengono identificatori dell'abbonato/del dispositivo e la posizione derivata dall'aggancio alla rete; un'eSIM è comunque un abbonamento mobile. Il prepagato non significa necessariamente non registrato: i requisiti variano per paese e cambiano nel tempo.<sup>[[13]](#references)</sup>

A livello operativo:

- Usa un device separato e supportato per ridurre l'esposizione dei dati personali, non per creare un abbonato fittizio.
- Non portare continuamente un device “separato” accanto a un telefono personale se la co-localizzazione rientra nel threat model.
- Disabilita rete cellulare, Wi-Fi, Bluetooth e accesso alla posizione inutilizzati; lo spegnimento offre un confine radio più forte rispetto ai toggle dell'interfaccia.
- Inserisci il traffico sensibile nel percorso VPN/Tor approvato, riconoscendo che l'operatore conosce comunque l'abbonamento, la posizione del device e l'endpoint del tunnel.
- Verifica le regole attuali di registrazione e conservazione con l'autorità nazionale di regolamentazione o un consulente locale; non fare affidamento su elenchi online di “paesi con SIM anonime”.

## Metadati DNS e TLS

- **DoH/DoT/DoQ** cifrano il DNS tra client e resolver, impedendo la semplice lettura o modifica locale, ma il resolver vede comunque le query e gli identificatori di trasporto. Spostano la fiducia, ma non forniscono anonimato.<sup>[[14]](#references)</sup>
- **ODoH** aggiunge un proxy affinché il resolver non debba conoscere l'IP del client, assumendo che proxy e destinazione non colludano. L'analisi del traffico è esplicitamente fuori ambito.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** può proteggere il nome del server interno in un handshake TLS quando client, DNS e server lo supportano. IP della destinazione, tempi, volume ed endpoint restano visibili.<sup>[[16]](#references)</sup>
- In un ambiente VPN o Tor configurato correttamente, il DNS dovrebbe seguire il percorso supportato da quell'ambiente. Aggiungere un resolver separato può creare un nuovo osservatore o una nuova fingerprint.

### Workflow di verifica di DNS cifrato/ECH

1. Decidi se il DNS è controllato dall'ambiente VPN/Tor, dal sistema operativo o dall'applicazione. Configuralo in **un solo** livello previsto, invece di sovrapporre resolver non correlati.
2. Seleziona un resolver in base alla sua policy pubblicata su privacy/conservazione e abilita la modalità cifrata strict quando la piattaforma la supporta. Il fallback opportunistico può tornare silenziosamente al plaintext.
3. Interroga un sottodominio univoco sotto una test zone authoritative che controlli; conferma che il log authoritative veda il recursive resolver previsto.
4. Cattura, con autorizzazione, solo il traffico del device di test. Conferma che la rete di accesso non possa leggere il DNS in plaintext, riconoscendo che può vedere l'endpoint del resolver/tunnel cifrato.
5. Testa un resolver cifrato bloccato/non raggiungibile. La condizione di successo è il comportamento fail-closed scelto o il fallback documentato, non una query clear accidentale.
6. Per ECH, usa un host controllato con ECH abilitato e analizza la diagnostica client/server per confermare che il **ClientHello** interno sia stato accettato. La semplice disponibilità di un record HTTPS non dimostra che ECH abbia avuto successo.
7. Ripeti dopo cambi di rete, captive portal, aggiornamenti del browser e riconnessioni VPN. Registra quale componente gestisce DNS/ECH, affinché gli amministratori successivi non creino un bypass.

## Mixnet

Le mixnet come Nym o Katzenpost aggiungono pacchetti di dimensione fissa, ritardi, riordinamento e cover traffic per resistere alla correlazione temporale. Queste proprietà comportano costi in latenza e banda, mentre le evidenze indipendenti su scala di deployment sono limitate. Considera le mixnet consumer attuali come **opzioni emergenti/ad alta latenza**, non come sostituti più veloci o garantiti di Tor/VPN.<sup>[[17]](#references)</sup>

### Workflow di valutazione

1. Identifica un client mantenuto e l'applicazione esatta supportata; non forzare traffico arbitrario del browser/sistema attraverso un proxy non documentato.
2. Leggi il threat model attuale per entry, mix node, gateway, destinazione e ipotesi di collusione.
3. Installa dalla sorgente ufficiale firmata in un compartimento di test separato e usa solo un endpoint di tua proprietà e benigno.
4. Misura latenza di consegna, limiti di dimensione dei messaggi, affidabilità, ritrasmissioni e comportamento quando il gateway non è disponibile.
5. Analizza il traffico locale e l'endpoint controllato per confermare il percorso e la sorgente previsti. Verifica se le risposte usano lo stesso modello di privacy.
6. Testa arresto/errore: l'applicazione non deve ricadere silenziosamente nell'accesso diretto a Internet.
7. Non disabilitare il cover traffic, ridurre i ritardi o scegliere percorsi fissi insoliti solo per aumentare la velocità; tali modifiche possono invalidare il modello di anonimato dichiarato.
8. Mantienila sperimentale finché deployment specifico, analisi indipendente e affidabilità operativa non siano adeguati al livello delle conseguenze.

## Checklist preliminare di rete

- [ ] L'autorizzazione copre la rete di accesso, la destinazione, le date e l'infrastruttura sorgente.
- [ ] L'endpoint non contiene identità non correlate o sessioni di sincronizzazione attive.
- [ ] IPv4, IPv6, DNS e comportamento di riconnessione corrispondono al piano.
- [ ] L'iniezione controllata di route DHCP/subnet locale non può spostare il traffico di test sull'interfaccia fisica.
- [ ] La destinazione vede solo l'egress previsto.
- [ ] Il comportamento del captive portal e dell'hotspot è stato testato senza traffico sensibile.
- [ ] La condivisione/individuazione locale e l'accesso automatico alle reti sono disabilitati.
- [ ] La tabella degli osservatori e il rischio residuo di correlazione del traffico sono accettati.
- [ ] La policy del provider, la conservazione dei dati e il contatto di emergenza sono aggiornati.

Per relay a conoscenza separata, workload con routing applicato, pluggable transport, onion service, I2P e browser remoti disposable, continua con [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).



## References

- [1] [EFF — Scegliere la VPN giusta per te](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Linee guida sulla sicurezza dei dispositivi: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Le protezioni di privacy e anonimato offerte da Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Una breve introduzione a Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Usare Tor con altri browser](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugin e add-on in Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Sbloccare Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Usare Tor Browser con una VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Le reti Wi-Fi pubbliche sono sicure?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Privacy Wi-Fi con i dispositivi Apple](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Implementare la randomizzazione MAC](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Principi per workstation sicure con accesso privilegiato](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Registrazione obbligatoria delle SIM: prospettive politiche e normative](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Raccomandazioni per gli operatori di servizi DNS Privacy](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — Bypassing Tunnels: perdita del traffico client VPN tramite abuso delle tabelle di routing](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: come gli attaccanti possono rendere visibili le VPN basate sul routing causando un leak totale della VPN](https://www.leviathansecurity.com/blog/tunnelvision)
{{#include ../banners/hacktricks-training.md}}
