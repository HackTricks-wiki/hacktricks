# Privacy di rete e connettività anonima

{{#include ../banners/hacktricks-training.md}}

La privacy di rete è una decisione di routing, non un'identità completa. Seleziona un percorso chiedendoti chi non dovrebbe essere in grado di collegare **source**, **destination**, **content** e **timing**.

Per l'inventario normalizzato — `Pros`, `Cons`, `Procedure` e `Detection` per ogni famiglia di percorsi di accesso — inizia dal [Catalogo delle tecniche di accesso anonimo a Internet](anonymous-internet-access-techniques.md). Questa pagina amplia le opzioni comuni implementabili.

## Cosa può solitamente vedere ciascun osservatore

| Percorso | Rete locale / ISP | Intermediario | Destinazione | Limitazione principale | Velocità relativa |
|---|---|---|---|---|---|
| HTTPS diretto | Metadati di source, destination, timing/volume | L'hosting/CDN vede la connessione | IP di source, dati del browser/app | Nessuna privacy dell'IP di source | Più veloce |
| VPN commerciale | Source connesso alla VPN; non i consueti metadati di destination | La VPN vede i metadati di source e destination | IP di egress della VPN | Un provider diventa un punto di correlazione | Di solito veloce |
| VPN/VPS self-hosted | Source connesso al VPS | Log dell'host/account/payment/control-plane | IP di egress del VPS | Facile da attribuire al server/account noleggiato | Di solito veloce |
| Tor Browser | Source connesso a Tor/bridge; timing/volume | Ogni relay vede una porzione limitata | Exit Tor, dati del browser | Più lento; rischi relativi ad account/endpoint/correlazione | Moderata/lenta |
| Tails/Whonix | Percorso Tor simile, con confini di routing più forti | Stesse limitazioni di Tor | Exit Tor/dati dell'applicazione | Gli errori operativi e l'host/l'hardware restano rilevanti | Moderata/lenta |
| Wi-Fi pubblico per ospiti + HTTPS | Il locale vede dispositivo locale/timing e destinazioni | L'ISP del locale vede i metadati | IP pubblico dell'ospite | Correlazione fisica/captive portal/dispositivo | Veloce/variabile |
| Hotspot cellulare | L'operatore vede abbonato/dispositivo/posizione e destinazioni | VPN/Tor, se utilizzati | IP di egress dell'operatore, della VPN o di Tor | L'abbonamento mobile e la posizione sono identificatori persistenti | Veloce/variabile |
| Mixnet | L'accesso vede l'uso della mixnet; timing/volume | Più nodi di mixing | Gateway/egress | Ecosistema emergente; costi di latenza e banda | Più lenta |

HTTPS protegge il contenuto in transito, ma non tutti i metadati. EFF osserva che dominio, orario e dimensione del traffico possono restare visibili agli intermediari anche quando percorsi delle pagine, credenziali e messaggi sono cifrati.<sup>[[1]](#references)</sup>

## VPN: privacy veloce con fiducia concentrata

Una VPN è utile per nascondere i metadati della destinazione all'ISP di accesso, proteggere un primo hop su una rete non attendibile, presentare un indirizzo di egress stabile per un engagement o raggiungere una rete privata. **Non** rende l'utente anonimo. La VPN vede la connessione di source e può osservare i metadati della destination; account, cookie, GPS, fingerprint e informazioni di payment restano visibili.<sup>[[1]](#references)</sup>

### Checklist per valutare un provider

1. **Proprietà e giurisdizione:** identifica l'entità legale, la società madre, i Paesi operativi, i subappaltatori dell'infrastruttura e le procedure legali applicabili.
2. **Dati raccolti:** distingui account/billing, IP di source, timestamp delle connessioni, banda, telemetria dei crash, query DNS e log delle destinazioni. “Nessun browsing log” non significa “nessun dato”.
3. **Conservazione e cancellazione:** individua durate precise e verifica se backup, sistemi antifrode e processor seguono la stessa pianificazione.
4. **Evidenze:** preferisci audit pubblici con ambito, data, risultati e remediation; client riproducibili/open; transparency report; e incidenti documentati.
5. **Protocollo e client:** WireGuard, OpenVPN o altro protocollo esaminato e mantenuto; aggiornamenti automatici; gestione di DNS e IPv6; kill switch; e leak test per ogni piattaforma.
6. **Modello di business:** comprendi come viene finanziato un servizio gratuito o sovvenzionato. La sola presenza nell'app store non dimostra un'operatività affidabile.
7. **Adeguatezza del pagamento:** un payment alternativo può ridurre la divulgazione dei dati di billing alla VPN, ma non cancella l'IP di source osservato a ogni connessione.

### Configurare e verificare una VPN

1. Installa il client firmato del provider/organizzazione dalla sua source ufficiale.
2. Seleziona **full tunnel**, salvo che un percorso documentato debba bypassarlo. Lo split tunneling crea percorsi di correlazione e leak.
3. Abilita il comportamento fail-closed/always-on e blocca il traffico durante la riconnessione.
4. Invia il DNS attraverso il tunnel e verifica IPv4 e IPv6. Disabilita un protocollo solo se non può essere instradato in sicurezza e accetti la perdita di funzionalità.
5. Verifica sospensione/riattivazione, cambio di rete, captive portal login, crash del tunnel e tethering tramite hotspot. NCSC avverte che i client tethered possono bypassare la VPN del telefono su alcune piattaforme.<sup>[[2]](#references)</sup>
6. Usa un endpoint di test controllato dall'organizzazione per registrare IPv4, IPv6, resolver DNS e timing della connessione osservati. Non esporre un engagement sensibile a siti casuali di “leak test”.
7. Ripeti i test dopo modifiche al client, al sistema operativo, alla rete o alle policy.

## Tor Browser: maggiore unlinkability sul web

Tor costruisce un circuito attraverso più relay, affinché normalmente nessun singolo relay conosca sia la source sia la destination. La destinazione vede un exit Tor invece dell'IP dell'utente; la rete locale vede normalmente una connessione Tor.<sup>[[3]](#references)</sup> Tor è progettato per applicazioni TCP a bassa latenza, quindi è più lento e non può garantire protezione contro un avversario in grado di correlare entrambe le estremità.<sup>[[4]](#references)</sup>

### Workflow sicuro per Tor Browser

1. Scarica Tor Browser solo dal Tor Project o da un mirror ufficiale e verifica la firma quando possibile.
2. Usa **Tor Browser**, non un browser normale indirizzato a una porta SOCKS di Tor. I browser ordinari possono causare leak di DNS/WebRTC e dello stato identificativo.<sup>[[5]](#references)</sup>
3. Mantieni dimensioni, font, estensioni e impostazioni di privacy predefiniti. Add-on aggiuntivi possono rendere il browser più unico.<sup>[[6]](#references)</sup>
4. Scegli il livello di sicurezza **Safer** o **Safest** quando l'aumento dei malfunzionamenti è accettabile.
5. Usa un bridge quando Tor diretto è bloccato o quando gli IP dei relay ordinari creerebbero una visibilità locale inaccettabile. I bridge riducono il riconoscimento immediato, ma non eliminano l'analisi del traffico.<sup>[[7]](#references)</sup>
6. Non accedere a un account identificativo, non fornire informazioni identificative e non aprire documenti attivi scaricati in un'applicazione esterna connessa alla rete.
7. Usa una sessione/un contesto separato per ogni identità. “New circuit” non equivale a cancellare l'identità del browser/applicazione; usa **New Identity** o riavvia l'ambiente isolato quando appropriato.
8. Preferisci HTTPS autenticato o un onion service autenticato. Un exit Tor può osservare il traffico HTTP non cifrato.

### Tor più VPN

Combinarli non è automaticamente più sicuro. Una VPN prima di Tor può nascondere a un ISP le connessioni dirette ai relay Tor, mentre la VPN vede la source; Tor prima di una VPN offre alla VPN una visione stabile dell'attività successiva a Tor e può ridurre l'anonymity set. Una configurazione errata può introdurre leak. Il Tor Project raccomanda queste combinazioni solo per threat model avanzati ed espliciti.<sup>[[8]](#references)</sup>

## Wi-Fi pubblici e per ospiti

L'HTTPS moderno significa che i vicini passivi normalmente non possono leggere contenuti web correttamente cifrati, ma il Wi-Fi per ospiti non è anonimato. Il locale può registrare orari di associazione, identificatori del dispositivo, dati del captive portal, destinazioni e dettagli DHCP; telecamere, acquisti, trasporti e osservazione fisica possono identificare l'utente. Un hotspot falso con un nome simile può inoltre catturare credenziali del portal o manipolare traffico non cifrato.<sup>[[9]](#references)</sup>

### Workflow legittimo per una rete ospiti

1. Usa solo una rete offerta agli ospiti o una per la quale il proprietario abbia concesso un permesso esplicito. Chiedi al personale l'SSID esatto e la procedura del portal.
2. Aggiorna endpoint e travel router prima dell'arrivo. Disabilita condivisione di file/stampanti, rilevamento inbound, auto-join e probing delle reti memorizzate.
3. Abilita l'indirizzo Wi-Fi privato/randomizzato del sistema operativo. Gli attuali sistemi Apple possono usare indirizzi rotanti su reti aperte/deboli; la randomizzazione moderna di Android è comunemente persistente per SSID. Questo riduce un solo identificatore locale.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Preferisci un travel router controllato dall'organizzazione o un bridge device a bassa fiducia tra una workstation privilegiata e la rete ospiti. Questo centralizza firewall e policy VPN, ma non nasconde il router al locale.<sup>[[12]](#references)</sup>
5. Completa un captive portal solo attraverso il device/browser designato a bassa fiducia. Non inserire mai credenziali personali o riutilizzate in un contesto che dovrebbe essere anonimo. Chiudi il browser del portal dopo aver stabilito la connettività.
6. Avvia una VPN full-tunnel o Tor prima delle attività sensibili e conferma il comportamento fail-closed.
7. Dimentica la rete dopo l'uso e verifica la policy dell'account del portal e della conservazione dei dati.

{% hint style="danger" %}
Craccare il Wi-Fi di un vicino, bypassare un portal, usare credenziali guest ottenute tramite leak, clonare l'accesso di un altro ospite o nascondere un Raspberry Pi in un bar sono attività non autorizzate, non tecniche di privacy. Le alternative sicure sono una rete ospiti legittima, un sito approvato dal cliente o un drop node documentato, installato e recuperato con il consenso scritto del proprietario.
{% endhint %}

## Travel router

Un travel router può isolare una workstation dai broadcast locali ostili, applicare un firewall, fornire un SSID interno coerente e riconnettere automaticamente una VPN. **Non** è anonimo: l'upstream vede la sua identità radio e il timing del traffico, mentre il provider VPN vede la source del tunnel.

- Usa firmware OpenWrt/vendor supportato e rimuovi i servizi inutilizzati.
- Amministralo tramite Ethernet o un SSID di gestione dedicato con una password univoca.
- Disabilita l'amministrazione dal lato WAN, UPnP, WPS, condivisione file e traffico inbound non richiesto.
- Usa un MAC WAN randomizzato/privato solo quando supportato e consentito.
- Applica la policy VPN sul router, inclusi DNS e IPv6, e blocca l'egress quando il tunnel fallisce.
- Non presumere che un hotspot del telefono instradi i device tethered attraverso la VPN del telefono; verifica il comportamento.

## Cellular, SIM ed eSIM

La connettività cellulare è pratica, ma non anonima. Gli operatori conservano identificatori di abbonato/dispositivo e la posizione derivata dall'aggancio alla rete; un'eSIM è comunque un abbonamento mobile. Il prepaid non significa necessariamente non registrato: i requisiti variano per Paese e cambiano nel tempo.<sup>[[13]](#references)</sup>

Operativamente:

- Usa un device separato e supportato per ridurre l'esposizione dei dati personali, non per creare un abbonato fittizio.
- Non trasportare continuamente un device “separato” insieme a un telefono personale se la co-localizzazione rientra nel threat model.
- Disabilita connettività cellulare, Wi-Fi, Bluetooth e accesso alla posizione non utilizzati; spegnere il dispositivo costituisce un confine radio più forte rispetto ai semplici toggle dell'interfaccia.
- Inserisci il traffico sensibile nel percorso VPN/Tor approvato, riconoscendo che l'operatore conosce comunque la posizione dell'abbonamento/dispositivo e l'endpoint del tunnel.
- Verifica le regole attuali di registrazione e conservazione con il regolatore nazionale o un consulente locale; non affidarti a elenchi online di “Paesi con SIM anonime”.

## Metadati DNS e TLS

- **DoH/DoT/DoQ** cifrano il DNS tra client e resolver, impedendo la semplice lettura o modifica locale, ma il resolver vede comunque le query e gli identificatori di trasporto. Spostano la fiducia, non forniscono anonimato.<sup>[[14]](#references)</sup>
- **ODoH** aggiunge un proxy affinché il resolver non debba conoscere l'IP del client, assumendo che proxy e target non colludano. L'analisi del traffico è esplicitamente fuori ambito.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** può proteggere il nome interno del server in un handshake TLS quando client, DNS e server lo supportano. IP di destinazione, timing, volume ed endpoint restano visibili.<sup>[[16]](#references)</sup>
- In un ambiente VPN o Tor configurato correttamente, il DNS dovrebbe seguire il percorso supportato da quell'ambiente. Aggiungere un resolver separato può creare un nuovo osservatore o fingerprint.

### Workflow di verifica di DNS cifrato/ECH

1. Decidi se il DNS è controllato dall'ambiente VPN/Tor, dal sistema operativo o dall'applicazione. Configuralo in **un solo** livello previsto, invece di sovrapporre resolver non correlati.
2. Seleziona un resolver in base alla sua policy pubblicata di privacy/conservazione e abilita la modalità cifrata strict quando la piattaforma la supporta. Il fallback opportunistico può tornare silenziosamente al plaintext.
3. Interroga un sottodominio univoco sotto una test zone authoritative che controlli; conferma che il log authoritative veda il resolver ricorsivo previsto.
4. Cattura solo il traffico del device di test con autorizzazione. Conferma che la rete di accesso non possa leggere il DNS in plaintext, riconoscendo che può vedere l'endpoint del resolver/tunnel cifrato.
5. Testa un resolver cifrato bloccato/non raggiungibile. La condizione di successo è il comportamento fail-closed scelto o il fallback documentato, non una query clear accidentale.
6. Per ECH, usa un host controllato con ECH abilitato e ispeziona la diagnostica client/server per confermare che il **ClientHello** interno sia stato accettato. La semplice pubblicazione di un record HTTPS non dimostra che ECH abbia avuto successo.
7. Ripeti il test dopo modifiche alla rete, captive portal, aggiornamenti del browser e riconnessioni VPN. Registra quale componente gestisce DNS/ECH, affinché gli amministratori successivi non creino un bypass.

## Mixnet

Mixnet come Nym o Katzenpost aggiungono pacchetti di dimensione fissa, ritardi, riordinamento e cover traffic per contrastare la correlazione temporale. Queste proprietà hanno costi in termini di latenza e banda, mentre le evidenze indipendenti su scala di deployment sono limitate. Considera le mixnet consumer attuali come **opzioni emergenti/ad alta latenza**, non come sostituti più veloci o garantiti di Tor/VPN.<sup>[[17]](#references)</sup>

### Workflow di valutazione

1. Identifica un client mantenuto e l'applicazione esatta supportata; non forzare traffico arbitrario del browser/sistema attraverso un proxy non documentato.
2. Leggi il threat model corrente per le ipotesi su entry, mix node, gateway, destination e collusione.
3. Installa dalla source ufficiale firmata in un compartimento di test separato e usa solo un endpoint benigno che possiedi.
4. Misura latenza di consegna, limiti di dimensione dei messaggi, affidabilità, ritrasmissioni e comportamento quando il gateway non è disponibile.
5. Ispeziona il traffico locale e l'endpoint di tua proprietà per confermare il percorso e la source previsti. Verifica se le risposte usano lo stesso modello di privacy.
6. Testa arresto/fallimento: l'applicazione non deve ricadere silenziosamente sull'accesso diretto a Internet.
7. Non disabilitare il cover traffic, ridurre i ritardi o scegliere percorsi fissi insoliti solo per aumentare la velocità; tali modifiche possono invalidare il modello di anonimato dichiarato.
8. Mantieni la soluzione in fase sperimentale finché deployment specifico, analisi indipendente e affidabilità operativa non siano adeguati al livello di conseguenza.

## Checklist preflight di rete

- [ ] L'autorizzazione copre rete di accesso, target, date e infrastruttura di source.
- [ ] L'endpoint non contiene identità estranee o sessioni di sincronizzazione attive.
- [ ] IPv4, IPv6, DNS e comportamento di riconnessione corrispondono al piano.
- [ ] La destinazione vede solo l'egress previsto.
- [ ] Il comportamento del captive portal e dell'hotspot è stato testato senza traffico sensibile.
- [ ] Condivisione/rilevamento locali e accesso automatico alle reti sono disabilitati.
- [ ] La tabella degli osservatori e il rischio residuo di correlazione del traffico sono accettati.
- [ ] Policy del provider, conservazione e contatto di emergenza sono aggiornati.

Per relay a conoscenza separata, workload con routing vincolato, pluggable transport, onion service, I2P e browser remoti usa-e-getta, continua con [Architetture avanzate per la privacy di rete](advanced-network-privacy-architectures.md).

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
- [12] [UK NCSC — Principi per workstation privilegiate ad accesso sicuro](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Registrazione obbligatoria delle SIM: prospettive normative e di policy](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Raccomandazioni per gli operatori di servizi DNS Privacy](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
{{#include ../banners/hacktricks-training.md}}
