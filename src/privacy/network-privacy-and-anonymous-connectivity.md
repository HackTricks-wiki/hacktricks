# Privacy di rete e connettività anonima

{{#include ../banners/hacktricks-training.md}}

La privacy di rete è una decisione di routing, non un’identità completa. Scegli un percorso chiedendoti chi non dovrebbe poter collegare **sorgente**, **destinazione**, **contenuto** e **tempistiche**.

Per l’inventario normalizzato — `Pro`, `Contro`, `Procedura` passo passo e `Rilevamento` per ogni famiglia di percorsi di accesso — inizia dal [Catalogo delle tecniche per l’accesso anonimo a Internet](anonymous-internet-access-techniques.md). Questa pagina approfondisce le opzioni comuni che possono essere implementate.

## Cosa può vedere di solito ciascun osservatore

| Percorso | Rete locale / ISP | Intermediario | Destinazione | Limite principale | Velocità relativa |
|---|---|---|---|---|---|
| HTTPS diretto | Sorgente, metadati della destinazione, tempistiche/volume | L’hosting/CDN vede la connessione | IP sorgente, dati del browser/app | Nessuna privacy dell’IP sorgente | La più veloce |
| VPN commerciale | Sorgente connessa alla VPN; non i consueti metadati della destinazione | La VPN vede sorgente e metadati della destinazione | IP di uscita della VPN | Un provider diventa un punto di correlazione | Di solito veloce |
| VPN/VPS self-hosted | Sorgente connessa al VPS | Log dell’host/account/pagamento/piano di controllo | IP di uscita del VPS | È facile ricondurre l’attività al server/account noleggiato | Di solito veloce |
| Tor Browser | Sorgente connessa a Tor/bridge; tempistiche/volume | Ogni relay vede una porzione limitata | Exit node Tor, dati del browser | Più lento; rischi legati ad account/endpoint/correlazione | Media/lenta |
| Tails/Whonix | Percorso Tor simile, con confini di routing più rigorosi | Stessi limiti di Tor | Exit node Tor/dati delle applicazioni | Restano possibili errori operativi e rischi legati a host/hardware | Media/lenta |
| Wi-Fi pubblico per ospiti + HTTPS | Il locale vede dispositivo locale/tempistiche e destinazioni | L’ISP del locale vede i metadati | IP pubblico del Wi-Fi per ospiti | Correlazione tramite presenza fisica/portale captive/dispositivo | Veloce/variabile |
| Hotspot cellulare | L’operatore vede abbonato/dispositivo/posizione e destinazioni | VPN/Tor, se usati | IP di uscita dell’operatore, della VPN o di Tor | L’abbonamento mobile e la posizione sono identificatori persistenti | Veloce/variabile |
| Mixnet | La rete di accesso rileva l’uso della mixnet; tempistiche/volume | Più nodi di mixing | Gateway/uscita | Ecosistema emergente; costi in termini di latenza e larghezza di banda | La più lenta |

HTTPS protegge il contenuto durante il transito, ma non tutti i metadati. EFF osserva che dominio, orario e dimensioni del traffico possono restare visibili agli intermediari anche quando percorsi delle pagine, credenziali e messaggi sono cifrati.<sup>[[1]](#references)</sup>

Un overlay cifrato non è automaticamente una rete anonima: i peer diretti di Yggdrasil possono vedere gli indirizzi IP degli altri peer.<sup>[[20]](#references)</sup> Il suo [forwarding in userspace e trasporto SOCKS](../generic-hacking/tunneling-and-port-forwarding.md#yggdrasil-userspace-overlay-with-yggstack) è un’opzione di tunneling, non un livello di anonimato della sorgente.<sup>[[20]](#references)[[21]](#references)</sup>

## VPN: privacy veloce con fiducia concentrata

Una VPN è utile per nascondere i metadati della destinazione all’ISP di accesso, proteggere il primo hop su una rete non attendibile, presentare un indirizzo di uscita stabile per un engagement o raggiungere una rete privata. **Non** rende anonimo l’utente. La VPN vede la connessione sorgente e può osservare i metadati della destinazione; account, cookie, GPS, fingerprint e dati di pagamento restano identificabili.<sup>[[1]](#references)</sup>

### Checklist per valutare un provider

1. **Proprietà e giurisdizione:** identifica l’entità legale, la società madre, i paesi in cui opera, i subappaltatori dell’infrastruttura e le procedure legali applicabili.
2. **Dati raccolti:** distingui tra dati dell’account/fatturazione, IP sorgente, timestamp delle connessioni, larghezza di banda, telemetria degli arresti anomali, query DNS e log delle destinazioni. “Nessun log di navigazione” non significa “nessun dato”.
3. **Conservazione e cancellazione:** verifica le durate precise e se backup, sistemi antifrode e responsabili del trattamento seguono le stesse tempistiche.
4. **Prove:** preferisci audit pubblici che specifichino ambito, data, risultati e correzioni; client open source e riproducibili; report sulla trasparenza; e incidenti documentati.
5. **Protocollo e client:** WireGuard, OpenVPN o un altro protocollo verificato e mantenuto; aggiornamenti automatici; gestione di DNS e IPv6; kill switch; e test di leak per ogni piattaforma.
6. **Modello di business:** cerca di capire come viene finanziato un servizio gratuito o sovvenzionato. La sola presenza in un app store non prova che il servizio sia affidabile.
7. **Modalità di pagamento:** un metodo di pagamento alternativo può ridurre le informazioni di fatturazione fornite alla VPN, ma non cancella l’IP sorgente osservato a ogni connessione.

### Configurare e verificare una VPN

1. Installa il client firmato del provider/organizzazione dalla fonte ufficiale.
2. Seleziona **full tunnel**, a meno che un percorso documentato non debba escluderlo. Lo split tunneling crea percorsi di correlazione e leak.
3. Abilita il comportamento fail-closed/always-on e blocca il traffico durante la riconnessione.
4. Instrada il DNS attraverso il tunnel e verifica sia IPv4 sia IPv6. Disabilita un protocollo solo se non può essere instradato in sicurezza e accetti la perdita di funzionalità.
5. Verifica sospensione/riattivazione, cambio di rete, accesso al portale captive, arresto anomalo del tunnel e tethering dell’hotspot. NCSC avverte che, su alcune piattaforme, i client connessi tramite tethering potrebbero aggirare la VPN del telefono.<sup>[[2]](#references)</sup>
6. Usa un endpoint di test controllato dall’organizzazione per registrare IPv4, IPv6, resolver DNS e tempistiche della connessione osservati. Non esporre un engagement sensibile a siti casuali per il “test dei leak”.
7. Ripeti i test dopo modifiche al client, al sistema operativo, alla rete o alle policy.

### Bypass del routing su LAN ostili

Una VPN può apparire “connessa” mentre alcuni pacchetti la aggirano, perché il sistema operativo sceglie una route **prima** che la VPN cifri il pacchetto. TunnelCrack ha dimostrato due modi per abusare delle eccezioni di routing comuni: **LocalNet** fa apparire una destinazione Internet come parte della subnet connessa direttamente, mentre **ServerIP** falsifica la risoluzione del gateway VPN, facendo sì che un indirizzo di destinazione erediti l’eccezione per la rete in chiaro richiesta dal trasporto VPN. Si tratta di errori del client/routing, non di vulnerabilità di WireGuard, OpenVPN, IPsec o TLS; il payload HTTPS resta cifrato end-to-end, ma l’osservatore locale può recuperare i metadati della destinazione/tempistiche e qualsiasi dato trasmesso in chiaro.<sup>[[18]](#references)</sup>

TunnelVision applica lo stesso primitivo pre-cifratura tramite l’opzione DHCP 121. Un server DHCP malevolo o compromesso può installare una route classless più specifica della route predefinita della VPN, selezionando l’interfaccia fisica per un host o un intervallo arbitrario. Il canale di controllo della VPN può rimanere attivo, quindi un kill switch che si attiva solo in caso di disconnessione del tunnel potrebbe non intervenire e un singolo controllo dell’“IP leak” pubblico potrebbe non rilevare i bypass selettivi.<sup>[[19]](#references)</sup>

Un kill switch basato su packet filter, che consente sull’interfaccia fisica solo DHCP e il trasporto VPN autenticato, dovrebbe trasformare il problema in un comportamento fail-closed; tuttavia, l’iniezione mirata di route può comunque creare un canale laterale di denial selettivo. Per carichi di lavoro Linux ad alto impatto, preferisci il più robusto [pattern di network namespace con route applicata](advanced-network-privacy-architectures.md#enforce-the-route-per-workload), in cui il namespace dell’applicazione non ha un’interfaccia fisica né una route predefinita verso la rete in chiaro.<sup>[[19]](#references)</sup>

#### Verifica in un lab controllato

Testa la combinazione esatta di client/sistema operativo/versione usando un AP, un server DHCP, un endpoint VPN e una destinazione di tua proprietà; le affermazioni generali sui prodotti diventano rapidamente obsolete perché le implementazioni di routing e packet filter variano da piattaforma a piattaforma. Cattura il traffico sull’endpoint stesso oltre che sul server di test: un sito che mostra l’IP di uscita non dimostra che tutto il traffico verso ogni destinazione segua il tunnel.<sup>[[18]](#references)[[19]](#references)</sup>

1. Connettiti alla VPN, annota l’indirizzo del server VPN e salva tutte le tabelle di routing IPv4/IPv6 e le regole di policy routing. Su Windows usa `route print`; su macOS usa `netstat -rn`; su Linux usa i comandi qui sotto.
2. Verifica la route selezionata per diversi IP di destinazione di tua proprietà. Il next hop/interfaccia deve essere il tunnel, fatta eccezione per l’endpoint di trasporto VPN documentato.
3. Per TunnelVision, rinnova il lease sulla rete DHCP controllata e installa una route con opzione 121 **solo per una destinazione di test di tua proprietà**. Il test è superato se il traffico continua a passare nel tunnel o viene bloccato, e non viene mai inviato come traffico diretto alla destinazione sull’interfaccia fisica.
4. Per LocalNet, assegna al client una subnet pubblica di documentazione, solo per il lab, come `203.0.113.0/24`, e inserisci al suo interno la destinazione di test di tua proprietà. Verifica che abilitare l’accesso alla LAN non faccia aggirare il tunnel alle destinazioni di tipo Internet.
5. Per ServerIP, prima di connettere la VPN, configura il DNS controllato in modo che risolva il nome host VPN di tua proprietà nell’indirizzo della destinazione di test; nel frattempo, il gateway del lab deve inoltrare il trasporto VPN all’endpoint VPN reale di tua proprietà. Il client non deve escludere dal tunnel il traffico di applicazioni non correlate diretto all’indirizzo falsificato.
6. Ripeti con l’opzione “accesso alla rete locale” sia abilitata sia disabilitata, dopo riconnessione, sospensione/riattivazione, cambio di rete e arresto anomalo del processo VPN. Verifica separatamente IPv4, IPv6 e DNS.
7. Esamina la cattura sull’interfaccia fisica. Deve contenere DHCP e pacchetti cifrati diretti al server VPN, non pacchetti indirizzati direttamente alla destinazione di test di tua proprietà. Verifica inoltre che un bypass bloccato non possa passare silenziosamente a un percorso alternativo dopo richieste dell’utente o il ripristino della connettività.

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

Tor crea un circuito attraverso più relay, in modo che normalmente nessun singolo relay conosca sia la sorgente sia la destinazione. La destinazione vede un exit node di Tor anziché l'IP dell'utente; la rete locale normalmente vede una connessione a Tor.<sup>[[3]](#references)</sup> Tor è progettato per applicazioni TCP a bassa latenza, quindi è più lento e non può garantire protezione contro un avversario in grado di correlare entrambe le estremità.<sup>[[4]](#references)</sup>

### Procedura sicura con Tor Browser

1. Scarica Tor Browser solo dal Tor Project o da un mirror ufficiale e, quando possibile, verifica la firma.
2. Usa **Tor Browser**, non un browser normale configurato per usare una porta SOCKS di Tor. I browser normali possono causare leak di DNS/WebRTC e dello stato identificativo.<sup>[[5]](#references)</sup>
3. Mantieni le dimensioni, i font, le estensioni e le impostazioni di privacy predefinite. Gli add-on aggiuntivi possono rendere il browser più riconoscibile.<sup>[[6]](#references)</sup>
4. Scegli il livello di sicurezza **Safer** o **Safest** se puoi accettare i problemi di compatibilità che ne derivano.
5. Usa un bridge quando Tor diretto è bloccato o quando la visibilità locale dei normali IP dei relay sarebbe inaccettabile. I bridge rendono più difficile il riconoscimento immediato, ma non eliminano l'analisi del traffico.<sup>[[7]](#references)</sup>
6. Non accedere a un account identificativo, non fornire informazioni identificative e non aprire documenti attivi scaricati in un'applicazione esterna connessa alla rete.
7. Usa una sessione/un contesto separato per ogni identità. «New circuit» non equivale a cancellare l'identità del browser/dell'applicazione: usa **New Identity** o riavvia l'ambiente isolato, secondo necessità.
8. Preferisci HTTPS autenticato o un onion service autenticato. Un exit node di Tor può osservare il traffico HTTP non cifrato.

### Tor e VPN

La loro combinazione non è automaticamente più sicura. Una VPN prima di Tor può nascondere all'ISP le connessioni dirette ai relay Tor, ma la VPN vede la sorgente; Tor seguito da una VPN offre alla VPN una visione stabile dell'attività post-Tor e può ridurre l'insieme di anonimato. Una configurazione errata può introdurre leak. Il Tor Project raccomanda queste combinazioni solo per threat model espliciti e avanzati.<sup>[[8]](#references)</sup>

## Wi-Fi pubbliche e per gli ospiti

Con HTTPS moderno, i vicini passivi di solito non possono leggere i contenuti web cifrati correttamente, ma una Wi-Fi per gli ospiti non offre anonimato. Il gestore del locale può registrare gli orari di connessione, gli identificatori dei dispositivi, i dati del captive portal, le destinazioni e i dettagli DHCP; telecamere, acquisti, trasporti e osservazione fisica possono identificare l'utente. Un hotspot falso con un nome simile può anche acquisire le credenziali del captive portal o manipolare il traffico non cifrato.<sup>[[9]](#references)</sup>

### Procedura legittima per le reti per gli ospiti

1. Usa solo una rete offerta agli ospiti o una rete per cui il proprietario ti ha concesso un'autorizzazione esplicita. Chiedi al personale l'SSID esatto e la procedura per il captive portal.
2. Aggiorna l'endpoint e il travel router prima dell'arrivo. Disabilita la condivisione di file/stampanti, l'individuazione in ingresso, la connessione automatica e la ricerca delle reti memorizzate.
3. Attiva l'indirizzo Wi-Fi privato/randomizzato del sistema operativo. I sistemi Apple attuali possono usare indirizzi a rotazione sulle reti aperte/deboli; la randomizzazione sui moderni dispositivi Android è comunemente persistente per SSID. Questo riduce un solo identificatore locale.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Preferisci un travel router controllato dall'organizzazione o un dispositivo bridge a basso livello di fiducia tra una workstation privilegiata e la rete per gli ospiti. Centralizza le policy firewall/VPN, ma non nasconde il router al gestore del locale.<sup>[[12]](#references)</sup>
5. Completa il captive portal solo tramite il dispositivo/browser designato a basso livello di fiducia. Non inserire mai credenziali personali o riutilizzate in un contesto che dovrebbe essere anonimo. Chiudi il browser del portal dopo aver stabilito la connessione.
6. Avvia una VPN full-tunnel o Tor prima delle attività sensibili e verifica il comportamento fail-closed.
7. Dimentica la rete dopo l'uso e consulta la policy del portal relativa agli account e alla conservazione dei dati.

{% hint style="danger" %}
Craccare la Wi-Fi di un vicino, aggirare un portal, usare credenziali per gli ospiti ottenute tramite leak, clonare l'accesso di un altro ospite o nascondere un Raspberry Pi in un bar sono attività non autorizzate, non tecniche di privacy. Le alternative sicure sono una rete per gli ospiti legittima, un sito approvato dal cliente o un drop node documentato, installato e recuperato con il consenso scritto del proprietario.
{% endhint %}

## Travel router

Un travel router può isolare una workstation dalle broadcast locali ostili, applicare un firewall, fornire un SSID interno stabile e riconnettere automaticamente una VPN. **Non** offre anonimato: la rete a monte vede la sua identità radio e gli orari del traffico, mentre il provider VPN vede la sorgente del tunnel.

- Usa firmware OpenWrt/del vendor supportato e rimuovi i servizi inutilizzati.
- Amministralo tramite Ethernet o un SSID di gestione dedicato con una password univoca.
- Disabilita l'amministrazione dal lato WAN, UPnP, WPS, la condivisione di file e il traffico in ingresso non richiesto.
- Usa un MAC WAN randomizzato/privato solo se supportato e consentito.
- Applica le policy VPN sul router, includendo DNS e IPv6, e blocca il traffico in uscita quando il tunnel non funziona.
- Non dare per scontato che un hotspot del telefono instradi i dispositivi connessi via tethering attraverso la VPN del telefono: verificalo.

## Reti cellulari, SIM ed eSIM

La rete cellulare è comoda, ma non anonima. Gli operatori conservano identificatori degli abbonati/dei dispositivi e dati sulla posizione ricavati dalla connessione alla rete; un'eSIM è comunque un abbonamento mobile. Il prepagato non significa necessariamente non registrato: i requisiti variano da paese a paese e cambiano.<sup>[[13]](#references)</sup>

Dal punto di vista operativo:

- Usa un dispositivo separato e supportato per ridurre l'esposizione dei dati personali, non per creare un abbonato fittizio.
- Se la co-localizzazione rientra nel threat model, non portare continuamente con te un dispositivo «separato» insieme a un telefono personale.
- Disabilita le funzioni cellulari, Wi-Fi, Bluetooth e di accesso alla posizione che non usi; spegnere il dispositivo crea una barriera radio più efficace rispetto agli interruttori dell'interfaccia.
- Instrada il traffico sensibile attraverso il percorso VPN/Tor approvato, tenendo presente che l'operatore conosce comunque la posizione dell'abbonamento/del dispositivo e l'endpoint del tunnel.
- Verifica le regole vigenti su registrazione e conservazione dei dati presso l'autorità nazionale di regolamentazione o un legale locale; non basarti su elenchi online di «paesi con SIM anonime».

## Metadati DNS e TLS

- **DoH/DoT/DoQ** cifrano il DNS tra client e resolver, impedendone la semplice lettura o modifica locale, ma il resolver continua a vedere le query e gli identificatori di trasporto. Spostano la fiducia, ma non offrono anonimato.<sup>[[14]](#references)</sup>
- **ODoH** aggiunge un proxy, in modo che il resolver non debba conoscere l'IP del client, assumendo che proxy e target non colludano. L'analisi del traffico è esplicitamente esclusa dall'ambito.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** può proteggere il nome del server interno nell'handshake TLS quando client, DNS e server lo supportano. L'IP di destinazione, gli orari, il volume e l'endpoint restano visibili.<sup>[[16]](#references)</sup>
- In un ambiente VPN o Tor configurato correttamente, il DNS dovrebbe seguire il percorso supportato da quell'ambiente. Aggiungere un resolver separato può introdurre un nuovo osservatore o rendere più riconoscibile il dispositivo.

### Procedura di verifica di DNS cifrato/ECH

1. Decidi se il DNS è gestito dall'ambiente VPN/Tor, dal sistema operativo o dall'applicazione. Configuralo in **un solo** livello previsto, invece di sovrapporre resolver non correlati.
2. Scegli un resolver in base alla sua policy pubblicata su privacy/conservazione dei dati e attiva la modalità cifrata rigorosa se supportata dalla piattaforma. Il fallback opportunistico può tornare silenziosamente al testo in chiaro.
3. Esegui una query per un sottodominio univoco sotto una zona di test autoritativa che controlli; verifica che il log autoritativo mostri il resolver ricorsivo previsto.
4. Cattura solo il traffico del dispositivo di test e solo se autorizzato. Verifica che la rete di accesso non possa leggere il DNS in testo in chiaro, tenendo presente che può vedere l'endpoint del resolver/tunnel cifrato.
5. Prova un resolver cifrato bloccato/non raggiungibile. La condizione di superamento è il comportamento fail-closed scelto o il fallback documentato, non una query in chiaro involontaria.
6. Per ECH, usa un host controllato con ECH attivo ed esamina la diagnostica di client/server per confermare che il **ClientHello** interno sia stato accettato. La semplice presenza di un record HTTPS non dimostra che ECH abbia funzionato.
7. Ripeti dopo cambi di rete, captive portal, aggiornamenti del browser e riconnessioni VPN. Registra quale componente gestisce DNS/ECH, affinché gli amministratori successivi non creino un bypass.

## Mixnet

Le mixnet come Nym o Katzenpost aggiungono pacchetti a dimensione fissa, ritardi, riordino e traffico di copertura per contrastare la correlazione temporale. Queste caratteristiche comportano costi in termini di latenza e larghezza di banda, e le prove indipendenti su scala di deployment sono limitate. Considera le mixnet consumer attuali **opzioni emergenti/ad alta latenza**, non sostituti più veloci o garantiti di Tor/VPN.<sup>[[17]](#references)</sup>

### Procedura di valutazione

1. Individua un client mantenuto e l'applicazione esattamente supportata; non forzare traffico arbitrario del browser/sistema attraverso un proxy non documentato.
2. Leggi il threat model aggiornato per le ipotesi su entry, mix node, gateway, destinazione e collusione.
3. Installa il software dalla fonte ufficiale firmata in un compartimento di test separato e usa solo un endpoint innocuo di tua proprietà.
4. Misura la latenza di consegna, i limiti di dimensione dei messaggi, l'affidabilità, le ritrasmissioni e il comportamento in caso di indisponibilità del gateway.
5. Esamina il traffico locale e l'endpoint di tua proprietà per confermare il percorso previsto e la sorgente. Verifica se le risposte seguono lo stesso modello di privacy.
6. Testa l'arresto/il guasto: l'applicazione non deve passare silenziosamente all'accesso diretto a Internet.
7. Non disabilitare il traffico di copertura, ridurre i ritardi o scegliere percorsi fissi insoliti solo per aumentare la velocità: queste modifiche possono invalidare il modello di anonimato dichiarato.
8. Mantieni la soluzione in fase sperimentale finché il deployment specifico, l'analisi indipendente e l'affidabilità operativa non sono adeguati al livello di conseguenze.

## Checklist preflight di rete

- [ ] L'autorizzazione copre la rete di accesso, il target, le date e l'infrastruttura sorgente.
- [ ] L'endpoint non contiene identità non correlate o sessioni di sincronizzazione attive.
- [ ] IPv4, IPv6, DNS e comportamento alla riconnessione corrispondono al piano.
- [ ] L'iniezione controllata di route DHCP/sottorete locale non può spostare il traffico di test sull'interfaccia fisica.
- [ ] La destinazione vede solo l'egress previsto.
- [ ] Il comportamento del captive portal e dell'hotspot è stato testato senza traffico sensibile.
- [ ] La condivisione/individuazione locale e la connessione automatica alle reti sono disabilitate.
- [ ] La tabella degli osservatori e il rischio residuo di correlazione del traffico sono stati accettati.
- [ ] Le policy del provider, la conservazione dei dati e il contatto di emergenza sono aggiornati.

Per relay con conoscenza suddivisa, workload con routing imposto, transport pluggable, onion service, I2P e browser remoti usa e getta, continua con [Architetture avanzate per la privacy di rete](advanced-network-privacy-architectures.md).



## References

- [1] [EFF — Scegliere la VPN giusta per te](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Indicazioni sulla sicurezza dei dispositivi: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Le protezioni di privacy e anonimato offerte da Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Breve introduzione a Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Usare Tor con altri browser](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugin e add-on in Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Sbloccare Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Usare Tor Browser con una VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Le reti Wi-Fi pubbliche sono sicure?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Privacy Wi-Fi con i dispositivi Apple](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Implementare la randomizzazione MAC](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Principi per workstation sicure con accesso privilegiato](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Registrazione SIM obbligatoria: prospettive normative e di policy](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Raccomandazioni per gli operatori di servizi DNS Privacy](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — DNS over HTTPS Oblivious](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — Aggirare i tunnel: leak del traffico dei client VPN tramite l'abuso delle tabelle di routing](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: come gli aggressori possono smascherare le VPN basate sul routing causando un leak totale della VPN](https://www.leviathansecurity.com/blog/tunnelvision)
- [20] [Yggdrasil FAQ: Yggdrasil è anonimo?](https://yggdrasil-network.github.io/faq.html#is-yggdrasil-anonymous)
- [21] [Yggstack README](https://github.com/yggdrasil-network/yggstack)
{{#include ../banners/hacktricks-training.md}}
