# Attribution, Detection and Countermeasures

L'infrastruttura di elusione dell'attribuzione è progettata per rendere sostituibili i singoli indicatori. I difensori dovrebbero preservare le evidenze grezze, modellare le relazioni e cercare comportamenti che persistono anche dopo un cambio di IP, dominio o persona.

## Gerarchia delle evidenze

| Evidenza | Utile per | Principale cautela |
|---|---|---|
| IP/ASN/geolocalizzazione di origine | localizzare l'uscita visibile e il provider | l'uscita può essere un relay, un NAT o una vittima; la geolocalizzazione è approssimativa |
| DNS passivo/registrazione | cronologia dell'infrastruttura e co-hosting | privacy/redaction e shared hosting creano lacune |
| Fingerprint di certificato/TLS/HTTP | raggruppare deployment ripetuti | software comuni e mimetizzazione creano falsi positivi |
| Temporizzazione del flusso e forma dei byte | collegare gli stadi del relay e i beacon ricorrenti | CDN/NAT e visibilità limitata riducono la certezza |
| Processo/identità dell'endpoint | spiegare perché è stata effettuata una connessione | non presenti su edge/IoT; l'attaccante può usare strumenti nativi |
| Audit di Cloud/CDN/API | identificare il tenant e il controllo dell'infrastruttura | la conservazione e l'accesso del provider o legale variano |
| Pagamento/account/dispositivo | collegare l'approvvigionamento a una persona/entità | occorre considerare prestanome, compromissioni e dispositivi condivisi |
| Implant/configurazione sequestrati | rivelare chiavi, peer, controller e collegamenti di build | l'integrità della raccolta e il momento del sequestro sono importanti |
| Evidenze umane/fisiche | collegare l'evento digitale al luogo/all'operatore | intrusive, dipendenti dalla giurisdizione e richiedono una gestione rigorosa |

Nessuna singola riga dovrebbe sostenere un'attribuzione a uno stato con elevata confidenza. Usate ipotesi concorrenti e indicate quale osservazione falsificherebbe ciascuna di esse.

## Telemetria minima

1. **DNS:** client, query, tipo, risposte, TTL, codice di risposta, resolver e timestamp.
2. **Network flow:** origine/destinazione/porta, inizio/fine, pacchetti/byte, flag TCP e posizione del sensore.
3. **TLS/HTTP:** SNI quando visibile, certificato, protocollo negoziato, fingerprint client/server, metodo, categoria di authority/path, stato e conteggio dei byte. Proteggete gli URL completi sensibili.
4. **Identità:** risultato dell'autenticazione, fattore/certificato/dispositivo, origine, applicazione, ID della sessione e decisione sul rischio.
5. **Endpoint:** processo che avvia la connessione, processo padre, utente, firma/hash del binary e destinazione.
6. **Edge/network device:** differenze di configurazione, login dell'amministratore, integrità di processo/file/firmware, log delle interfacce e dei flussi.
7. **Cloud/SaaS/CDN:** actor, tenant/project, azione API, origine, oggetto/risorsa, token e risultato.
8. **Wireless/NAC:** station, flag randomized-MAC, AP, segnale, identità/certificato EAP, VLAN/IP assegnati e postura.

Sincronizzate gli orologi, mantenete i fusi orari originali, documentate i confini NAT/proxy e conservate una cronologia sufficiente a superare la durata di un nodo ORB di 31 giorni.

## Costruire un grafo di attribuzione

Rappresentate le osservazioni come nodi ed edge tipizzati:
```text
[persona]--created-->[cloud account]--deployed-->[VPS]
|                       |                     |
recovery               login-from             TLS fingerprint
|                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```
I nodi utili includono IP, prefisso, ASN, dominio, account DNS, certificato/chiave, fingerprint simile a JA3/JA4, grammatica HTTP, hash di file/configurazione, tenant cloud, token API, email, persona, strumento di pagamento e dispositivo fisico. Ogni edge deve includere `first_seen`, `last_seen`, sensore/fonte, livello di confidenza e indicare se è osservato o dedotto.

La sola densità del grafo è fuorviante: una CDN o una certificate authority collega molti attori non correlati. Attribuisci un peso maggiore alle relazioni rare controllate dall'operatore—stesso account API, chiave SSH, origin allowlist, response body univoco o protocollo di controllo—rispetto all'hosting comune.

## Hunting di ORB e router compromessi

### Da un exit osservato

1. Determina se l'indirizzo appartiene a hosting, rete residenziale, mobile, educativa o aziendale; non scartare le fonti residenziali.
2. Recupera DNS storico, servizi/certificati, porte aperte e comportamento di scanning/exploitation osservato per un periodo delimitato.
3. Cerca peer che condividono fingerprint di servizio rari, destinazioni dei controller, materiale dei certificati o tempistiche di rotazione.
4. Classifica i probabili ruoli: accesso, transito, exit/staging o amministrazione.
5. Verifica se più cluster di intrusioni non correlati hanno usato lo stesso pool; la multi-tenancy indebolisce l'attribuzione diretta all'attore, ma rafforza un'ipotesi ORB.
6. Monitora i nuovi nodi che corrispondono al profilo del ruolo dopo la scomparsa dei vecchi IP.

### Presso il proprietario della rete

- Genera alert per la nuova esposizione su Internet di sistemi di gestione e per l'autenticazione predefinita/legacy.
- Invia fuori dal dispositivo le modifiche alla configurazione di router/firewall/VPN e le autenticazioni degli amministratori.
- Crea una baseline delle connessioni in uscita dall'infrastruttura che normalmente avvia poche sessioni.
- Rileva nuovi processi proxy/listener, tunnel, attività pianificate, modifiche al firmware e DNS inatteso.
- Sostituisci i dispositivi end-of-life; un reboot che rimuove il malware volatile non risolve l'esposizione.
- Limita la gestione a un piano di amministrazione autenticato e a fonti note.

Mandiant raccomanda di monitorare l'infrastruttura ORB come un'entità in evoluzione, poiché il blocco degli IP di breve durata non cattura la topologia e il ciclo di vita.<sup>[[1]](#references)</sup>

## Analytics Fast-flux e dynamic-DNS

Aggrega per dominio registrato e finestra temporale scorrevole. Un punteggio pratico può combinare:
```text
score =
2 * low_median_ttl
+ 2 * unique_answer_count
+ 2 * unique_asn_count
+ geographic_dispersion
+ nxdomain_or_answer_churn
+ first_seen_recently
+ suspicious_process_or_follow_on
```
Analizza i domini usando diverse caratteristiche indipendenti, non una sola soglia. Confrontali con un modello di autorizzazione CDN/anti-DDoS e verifica la rotazione dei name server autorevoli per distinguere il flux singolo dal double flux. Per le DGA, aggiungi i picchi di NXDOMAIN per client, la distribuzione di lunghezza/caratteri, le query sincronizzate tra gli host e il processo che le genera. Anche le linee guida attuali di MITRE sottolineano i cambiamenti ad alta frequenza, il TTL basso e la correlazione tra processo e rete.<sup>[[2]](#references)</sup>

## Rilevamento del domain-fronting

Quando l'endpoint aziendale o un punto di ispezione autorizzato dispone di entrambe le identità, confronta:
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
Aumentare il livello di confidenza quando SNI e authority appartengono a tenant non correlati, il processo non è un client approvato, la sessione è periodica/di lunga durata e l’origine interna è rara. Un SNI vuoto è un elemento da registrare, non è automaticamente malevolo. ECH può nascondere SNI sul wire, quindi endpoint, DNS e log del provider/CDN diventano più importanti. MITRE documenta sia le varianti con mismatch sia quelle con SNI vuoto.<sup>[[3]](#references)</sup>

## Rilevamento della sequenza del resolver dead-drop

Il comportamento ad alto segnale è una sequenza, non un dominio bloccato:
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
Cerca in tutta la flotta percorsi di oggetti, hash delle risposte, identificatori API e destinazioni successive identici. Conserva il contenuto recuperato, perché l'attore può modificarlo o eliminarlo. Limita le service API non necessarie e richiedi alle applicazioni approvate di usare proxy aziendali, tenendo però conto degli strumenti per sviluppatori e dell'automazione. MITRE elenca GitHub, forum, documenti e servizi social/web nelle procedure reali.<sup>[[4]](#references)</sup>

## Clustering di redirector e deployment riutilizzabili

Anche quando domini e indirizzi cambiano, gli operatori spesso eseguono nuovamente la stessa automazione. Raggruppa sulla base di combinazioni di:

- campi dei certificati/riutilizzo delle chiavi e tempistiche di emissione;
- versione TLS/ordine di cipher ed estensioni e comportamento del server;
- status HTTP, ordine degli header, comportamento della cache, icona/corpo e pagina di errore identici;
- coppie di porte insolite e catene di redirect;
- pattern del provider DNS/name server e pianificazione del TTL;
- momento del deployment, uptime e finestra di manutenzione;
- esposizione dell'origine back-end o allowlist identiche.

Una singola pagina generica Nginx è un'evidenza debole. Diverse corrispondenze rare e indipendenti, unite alla continuità temporale, possono giustificare un'ipotesi di cluster dell'infrastruttura.

## Rilevamento di proxy residenziali e sessioni impossibili

Mantieni l'identità della sessione al di sopra del livello IP. Segnala combinazioni come:

- il fingerprint di una sessione/device cambia paese/ASN più velocemente di quanto consenta un viaggio;
- un IP consumer cambia a ogni richiesta mentre cookie e identità TLS/browser rimangono fissi;
- il device locale dichiarato presenta latenza/fuso orario/lingua incoerenti con l'uscita;
- un indirizzo alterna popolazioni di account non correlate o mostra un comportamento da backconnect proxy;
- una sessione privilegiata appare da un accesso residenziale senza il certificato del device dell'organizzazione.

Carrier NAT, strumenti di accessibilità, VPN aziendali e viaggi producono anomalie legittime. Richiedi autenticazione step-up o un'indagine invece di bloccare irreversibilmente basandoti soltanto sulle etichette “proxy residenziale”.

## Rilevamento di dispositivi wireless e covert

Collega RADIUS/NAC al contesto degli AP e a quello fisico:

1. trova le combinazioni account–device–AP osservate per la prima volta;
2. identifica le credenziali usate senza un certificato/postura EAP gestito;
3. confronta le sessioni simultanee con la presenza nel badge/edificio;
4. analizza segnali insolitamente deboli/al limite e gli spostamenti tra AP;
5. cerca negli endpoint gestiti vicini attività di wireless scanning, un'interfaccia bridge/NAT appena abilitata, virtual adapter o tunnel;
6. inventaria nuove attività su switchport, DHCP, rete USB e PoE;
7. esegui una scansione RF/fisica autorizzata quando le evidenze lo supportano.

Questo rileva sia un percorso APT28-style verso il vicino più prossimo sia un drop di un'esercitazione. La randomizzazione MAC non deve essere trattata come identità o prova di colpevolezza.

## Rilevamento dell'attribuzione finanziaria

- Conserva gli identificativi esatti della catena, del token, dell'indirizzo, della transazione e del blocco.
- Segui il valore attraverso change, peel chain, fan-out/in, mixer, bridge e depositi presso servizi, etichettando le euristiche.
- Correla tempo, importo al netto delle commissioni, evento del contratto, liquidità e prelievo sulla catena di destinazione.
- Ottieni o conserva legalmente i record di exchange, bridge, merchant, account, device e consegna.
- Controlla le entità/gli indirizzi attualmente sanzionati e i derivati secondo il programma applicabile; non fare affidamento su una vecchia lista statica.
- Tratta l'uso di privacy protocol come un elemento del contesto di rischio, non come prova di illecito.

I red flag del FATF sono esplicitamente contestuali: pattern insolito, importo/frequenza, geografia, origine dei fondi e servizi che aumentano l'anonimato diventano significativi insieme.<sup>[[5]](#references)</sup>

## Deception e canary

I defender possono creare segnali ad alta affidabilità senza tentare di de-anonimizzare gli utenti comuni:

- credenziali o documenti univoci che non dovrebbero mai uscire da un sistema;
- endpoint amministrativi fittizi e share-esca;
- nomi DNS strumentati incorporati esclusivamente in artefatti controllati;
- cloud key canary senza uso legittimo;
- un'identità Wi-Fi esca che nessun device gestito possiede.

Definisci e governa attentamente l'ambito della deception. Un canary dovrebbe identificare l'uso improprio di una risorsa del defender, non raccogliere traffico non correlato di terze parti.

## Priorità delle contromisure

1. Rimuovi router, VPN e appliance esposti su Internet e non supportati.
2. Richiedi MFA resistente al phishing e certificati associati al device, incluso l'accesso interno/wireless.
3. Centralizza log sufficientemente immutabili di identità, endpoint, DNS, flow, proxy, cloud e dispositivi di rete.
4. Limita la gestione e l'egress; inventaria ogni servizio raggiungibile dall'esterno.
5. Monitora DNS, certificate transparency e configurazione cloud alla ricerca di risorse non autorizzate.
6. Conserva visibilità SaaS a livello di processo-rete e di oggetto.
7. Esegui esercitazioni di indagine cross-layer e coordinamento con provider adiacenti.
8. Tieni traccia dei cluster e dei comportamenti dell'infrastruttura, non solo delle IP blocklist.

## Disciplina analitica

Usa un linguaggio che esprima il livello di confidenza:

- **Osservato:** il record del sensore/provider mostra direttamente la relazione.
- **Fortemente supportato:** diverse osservazioni indipendenti lo favoriscono rispetto alle alternative.
- **Valutato:** inferenza basata su assunzioni ed evidenze dichiarate.
- **Sconosciuto:** la visibilità mancante impedisce una conclusione.

Mantieni sempre almeno due ipotesi: infrastruttura gestita dall'attore rispetto a intermediario compromesso/condiviso; un singolo attore rispetto a un servizio multi-tenant; elusione deliberata rispetto a comportamento legittimo di privacy/CDN. La capacità di spiegare l'incertezza fa parte di un rilevamento corretto.

## References

- [1] [Google Cloud/Mandiant — Gli attori di spionaggio con legami con la Cina usano reti ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Indicatori di red flag degli asset virtuali](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — Gli attori della RPC compromettono e mantengono l'accesso persistente](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — Indicazioni su visibilità avanzata e hardening per l'infrastruttura delle comunicazioni](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
