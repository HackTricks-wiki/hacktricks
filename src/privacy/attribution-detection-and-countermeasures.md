# Attribuzione, rilevamento e contromisure

{{#include ../banners/hacktricks-training.md}}

L'infrastruttura per l'elusione dell'attribuzione è progettata per rendere sostituibili i singoli indicatori. I difensori dovrebbero preservare le evidenze grezze, modellare le relazioni e cercare comportamenti che persistono anche dopo il cambio di IP, dominio o persona.

## Gerarchia delle evidenze

| Evidenza | Utile per | Principale limitazione |
|---|---|---|
| IP/ASN/geolocalizzazione di origine | individuare l'uscita visibile e il provider | l'uscita può essere un relay, un NAT o una vittima; la geolocalizzazione è approssimativa |
| DNS passivo/registrazione | cronologia dell'infrastruttura e co-hosting | privacy/redaction e shared hosting creano lacune |
| Fingerprint di certificato/TLS/HTTP | raggruppare deployment ripetuti | software comuni e mimicry creano falsi positivi |
| Temporizzazione del traffico e forma dei byte | collegare gli stadi dei relay e i beacon ricorrenti | CDN/NAT e visibilità limitata riducono la certezza |
| Processo/identità dell'endpoint | spiegare perché è avvenuta una connessione | non presente su edge/IoT; l'attaccante può usare strumenti nativi |
| Audit Cloud/CDN/API | identificare il tenant e il controllo sull'infrastruttura | la retention e l'accesso del provider o legale variano |
| Pagamento/account/dispositivo | collegare l'approvvigionamento a una persona/entità | è necessario considerare nominee, compromissioni e dispositivi condivisi |
| Implant/configurazione sequestrati | rivelare chiavi, peer, controller e collegamenti di build | l'integrità della raccolta e il momento del sequestro sono importanti |
| Evidenze umane/fisiche | collegare l'evento digitale al luogo/operatore | intrusive, dipendenti dalla giurisdizione e richiedono una gestione rigorosa |

Nessuna singola riga dovrebbe determinare da sola un'attribuzione statale ad alta confidenza. Utilizzate ipotesi concorrenti e indicate quale osservazione falsificherebbe ciascuna di esse.

## Telemetria minima

1. **DNS:** client, query, tipo, risposte, TTL, codice di risposta, resolver e timestamp.
2. **Network flow:** origine/destinazione/porta, inizio/fine, pacchetti/byte, flag TCP e posizione del sensore.
3. **TLS/HTTP:** SNI quando visibile, certificato, protocollo negoziato, fingerprint del client/server, metodo, categoria di authority/path, stato e conteggio dei byte. Proteggere gli URL completi sensibili.
4. **Identità:** risultato dell'autenticazione, fattore/certificato/dispositivo, origine, applicazione, ID di sessione e decisione sul rischio.
5. **Endpoint:** processo iniziale, parent, utente, firma/hash del binary e destinazione.
6. **Dispositivo edge/network:** differenze di configurazione, login admin, integrità di processo/file/firmware, log delle interfacce e dei flow.
7. **Cloud/SaaS/CDN:** actor, tenant/progetto, azione API, origine, oggetto/risorsa, token e risultato.
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

La sola densità del grafo è fuorviante: un CDN o una certificate authority collega molti attori non correlati. Attribuisci un peso maggiore alle relazioni rare controllate dall’operatore—stesso account API, chiave SSH, origin allowlist, body di risposta univoco o protocollo di controllo—rispetto all’hosting comune.

## Caccia a ORB e router compromessi

### Da un exit osservato

1. Determina se l’indirizzo appartiene a hosting, rete residenziale, mobile, educativa o aziendale; non scartare le fonti residenziali.
2. Recupera DNS storico, servizi/certificati, porte aperte e comportamento di scansione/exploitation osservato per un periodo delimitato.
3. Cerca peer che condividano fingerprint rari dei servizi, destinazioni dei controller, materiale dei certificati o tempistiche di rotazione.
4. Classifica i probabili ruoli: accesso, traversata, exit/staging o amministrazione.
5. Verifica se più cluster di intrusioni non correlati hanno utilizzato lo stesso pool; la multi-tenancy indebolisce l’attribuzione diretta all’attore, ma rafforza l’ipotesi ORB.
6. Tieni traccia dei nuovi nodi che corrispondono al profilo del ruolo dopo la scomparsa dei vecchi IP.

### Presso il proprietario della rete

- Genera alert per nuovi sistemi di gestione esposti su Internet e per autenticazione predefinita/legacy.
- Invia le modifiche alla configurazione di router/firewall/VPN e le autenticazioni degli amministratori fuori dal dispositivo.
- Crea una baseline delle connessioni in uscita dall’infrastruttura che normalmente avvia poche sessioni.
- Rileva nuovi processi proxy/listener, tunnel, attività pianificate, modifiche al firmware e DNS inatteso.
- Sostituisci i dispositivi a fine vita; un riavvio che rimuove malware volatile non risolve l’esposizione.
- Limita la gestione a un administration plane autenticato e a fonti note.

Mandiant raccomanda di monitorare l’infrastruttura ORB come un’entità in evoluzione, perché il blocco temporaneo degli IP non riflette topologia e ciclo di vita.<sup>[[1]](#references)</sup>

## Analisi di Fast-flux e dynamic-DNS

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
Investiga i domini utilizzando diverse caratteristiche indipendenti, non una sola soglia. Confrontali con un modello di autorizzazione CDN/anti-DDoS e verifica la rotazione dei name server autorevoli per distinguere il single flux dal double flux. Per le DGA, aggiungi i burst di NXDOMAIN per client, la distribuzione di lunghezza/caratteri, le query sincronizzate tra gli host e il processo che le genera. Anche le linee guida attuali di MITRE sottolineano i cambiamenti ad alta frequenza, il TTL basso e la correlazione tra processo e rete.<sup>[[2]](#references)</sup>

## Rilevamento del Domain-fronting

Quando l'endpoint aziendale o un punto di ispezione autorizzato dispone di entrambe le identità, confronta:
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
Aumenta il livello di confidenza quando SNI e authority appartengono a tenant non correlati, il processo non è un client approvato, la sessione è periodica/di lunga durata e l’origine interna è rara. Uno SNI vuoto è un elemento da registrare, non automaticamente un’attività malevola. ECH può nascondere lo SNI sulla rete, quindi endpoint, DNS e log del provider/CDN diventano più importanti. MITRE documenta sia le varianti con SNI non corrispondente sia quelle con SNI vuoto.<sup>[[3]](#references)</sup>

## Rilevamento della sequenza del resolver dead-drop

Il comportamento ad alto segnale è una sequenza, non un dominio bloccato:
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
Cerca in tutta la flotta percorsi di oggetti, hash delle risposte, identificatori API e destinazioni successive identici. Conserva il contenuto recuperato, perché l'attore può modificarlo o eliminarlo. Limita le API dei servizi non necessarie e richiedi alle applicazioni approvate di usare proxy aziendali, tenendo però conto degli strumenti per sviluppatori e dell'automazione. MITRE elenca GitHub, forum, documenti e servizi social/web in procedure reali.<sup>[[4]](#references)</sup>

## Clustering di Redirector e deployment riutilizzabili

Anche quando domini e indirizzi cambiano, gli operatori spesso eseguono nuovamente la stessa automazione. Crea cluster basati su combinazioni di:

- campi dei certificati/riutilizzo delle chiavi e tempistiche di emissione;
- versione TLS/ordine di cipher ed estensioni e comportamento del server;
- codice di stato HTTP, ordine degli header, comportamento della cache, icona/corpo e pagina di errore identici;
- coppie di porte insolite e catene di redirect;
- pattern del provider DNS/name server e pianificazione dei TTL;
- tempo di deployment, uptime e finestra di manutenzione;
- esposizione dell'origine back-end o allowlist identiche.

Una singola pagina Nginx generica è una prova debole. Diverse corrispondenze rare e indipendenti, unite alla continuità temporale, possono giustificare un'ipotesi di cluster dell'infrastruttura.

## Rilevamento di proxy residenziali e sessioni impossibili

Mantieni l'identità della sessione al di sopra del livello IP. Segnala combinazioni come:

- un'unica sessione/fingerprint del dispositivo cambia paese/ASN più rapidamente di quanto il viaggio renda possibile;
- un IP consumer cambia a ogni richiesta mentre cookie e identità TLS/browser rimangono fissi;
- il dispositivo locale dichiarato presenta latenza/fuso orario/lingua incoerenti con l'uscita;
- un indirizzo alterna popolazioni di account non correlate o mostra un comportamento da backconnect proxy;
- una sessione privilegiata appare da un accesso residenziale senza il certificato del dispositivo dell'organizzazione.

Carrier NAT, strumenti di accessibilità, VPN aziendali e viaggi producono anomalie legittime. Richiedi un'autenticazione step-up o un'indagine invece di bloccare irreversibilmente basandoti soltanto sulle etichette “proxy residenziale”.

## Rilevamento di dispositivi wireless e covert

Correla RADIUS/NAC con il contesto dell'AP e quello fisico:

1. trova le prime combinazioni account–dispositivo–AP osservate;
2. identifica le credenziali usate senza un certificato/postura EAP gestito;
3. confronta le sessioni concorrenti e la presenza registrata all'ingresso/nell'edificio;
4. analizza segnali insolitamente deboli/al limite e gli spostamenti tra AP;
5. cerca sugli endpoint gestiti vicini attività di wireless scanning, un'interfaccia bridge/NAT appena abilitata, virtual adapter o tunnel;
6. inventaria nuove attività su switchport, DHCP, rete USB e PoE;
7. esegui una scansione RF/fisica autorizzata quando le prove la giustificano.

Questo rileva sia un percorso APT28-style verso il vicino più prossimo sia un drop di esercitazione. La randomizzazione MAC non deve essere trattata come identità o prova di colpevolezza.

## Rilevamento dell'attribuzione finanziaria

- Conserva la catena, il token, l'indirizzo, la transazione e gli identificatori del blocco esatti.
- Segui il valore attraverso change, peel chain, fan-out/in, mixer, bridge e depositi presso servizi, etichettando le euristiche.
- Correla orario, importo meno le commissioni, evento del contratto, liquidità e prelievo sulla catena di destinazione.
- Ottieni o conserva legalmente i record di exchange, bridge, merchant, account, dispositivo e consegna.
- Controlla le entità/gli indirizzi attualmente sanzionati e i derivati previsti dal programma applicabile; non basarti su una vecchia lista statica.
- Tratta l'uso di privacy protocol come input del contesto di rischio, non come prova di illeciti.

I red flag della FATF sono esplicitamente contestuali: pattern insoliti, importo/frequenza, area geografica, origine dei fondi e servizi che aumentano l'anonimato diventano significativi nel loro insieme.<sup>[[5]](#references)</sup>

## Deception e canary

I difensori possono creare segnali ad alta affidabilità senza tentare di deanonymize gli utenti comuni:

- credenziali o documenti univoci che non dovrebbero mai uscire da un sistema;
- endpoint amministrativi falsi e condivisioni esca;
- nomi DNS strumentati incorporati esclusivamente in artifact controllati;
- chiavi cloud canary senza alcun uso legittimo;
- un'identità Wi-Fi esca che nessun dispositivo gestito possiede.

Definisci e governa attentamente l'ambito della deception. Un canary dovrebbe identificare l'uso improprio di una risorsa del difensore, non raccogliere traffico non correlato di terze parti.

## Priorità delle contromisure

1. Rimuovi router, VPN e appliance esposti a Internet non supportati.
2. Richiedi MFA resistente al phishing e certificati vincolati al dispositivo, incluso l'accesso interno/wireless.
3. Centralizza log sufficientemente immutabili di identità, endpoint, DNS, flow, proxy, cloud e dispositivi di rete.
4. Limita la gestione e l'egress; inventaria ogni servizio raggiungibile dall'esterno.
5. Monitora DNS, certificate transparency e configurazioni cloud per individuare asset non autorizzati.
6. Mantieni visibilità SaaS a livello di processo-rete e di oggetto.
7. Esegui esercitazioni di indagine cross-layer e coordinamento con i provider adiacenti.
8. Tieni traccia dei cluster e dei comportamenti dell'infrastruttura, non solo delle blocklist IP.

## Disciplina analitica

Usa un linguaggio che esprima il livello di confidenza:

- **Osservato:** il record del sensore/provider mostra direttamente la relazione.
- **Fortemente supportato:** diverse osservazioni indipendenti lo favoriscono rispetto alle alternative.
- **Valutato:** inferenza basata su assunzioni dichiarate e prove.
- **Sconosciuto:** la visibilità mancante impedisce una conclusione.

Mantieni sempre almeno due ipotesi: infrastruttura gestita dall'attore contro intermediario compromesso/condiviso; un singolo attore contro un servizio multi-tenant; evasione deliberata contro comportamento legittimo di privacy/CDN. La capacità di spiegare l'incertezza fa parte di un rilevamento corretto.

## References

- [1] [Google Cloud/Mandiant — Gli attori dello spionaggio con legami con la Cina usano reti ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Indicatori di rischio per gli asset virtuali](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — Gli attori della RPC compromettono e mantengono l'accesso persistente](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — Indicazioni per una maggiore visibilità e il rafforzamento dell'infrastruttura delle comunicazioni](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
{{#include ../banners/hacktricks-training.md}}
