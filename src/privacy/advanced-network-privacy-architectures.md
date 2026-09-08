# Architetture avanzate per la privacy di rete

{{#include ../banners/hacktricks-training.md}}

La complessità è utile solo quando rimuove un osservatore specifico o una modalità di errore specifica. Uno stack di tunnel unico, una forma dei pacchetti personalizzata, uno user agent raro o un'infrastruttura che ruota frequentemente possono diventare un fingerprint più forte di una configurazione standard usata da migliaia di persone.

L'[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) fornisce lo schema comune `Pros`/`Cons`/`Procedure`/`Detection`. Questa pagina approfondisce le architetture più complesse e i confini di trust.

L'obiettivo avanzato è quindi la **separazione delle conoscenze**: nessun componente ordinario dovrebbe possedere simultaneamente l'identità dell'utente, la destinazione, il plaintext e la cronologia delle attività a lungo termine. Questa non è invisibilità: la collusione, un procedimento legale, la compromissione dell'endpoint o la correlazione end-to-end del traffico possono comunque ricostruire il percorso.

## Selezione dell'architettura

| Pattern | Proprietà acquisita | Nuovo trust/errore | Uso adatto |
|---|---|---|---|
| Standard Tor Browser | Fingerprint del browser condiviso e percorso attraverso più relay | La bassa latenza consente la correlazione del traffico | Navigazione web anonima generica |
| Tor bridge + pluggable transport | Rende più difficile il blocco/la classificazione diretta di Tor | Il bridge/transport può comunque essere rilevato; il bridge apprende la sorgente | Reti sottoposte a censura |
| Onion service | Nasconde l'IP del servizio; evita l'exit; autentica l'identità onion | La chiave onion e l'endpoint del server diventano asset critici | Pubblicazione privata, raccolta o amministrazione |
| Relay di ingresso + uscita indipendenti | Normalmente nessun singolo relay vede sorgente e destinazione | Gli operatori possono colludere; il timing attraversa entrambi | Applicazioni supportate ad alte prestazioni |
| Oblivious HTTP | Separa l'IP sorgente dalla richiesta HTTP stateless cifrata | Richiede il supporto dell'applicazione, del relay e del gateway | Telemetria, query e invii senza stato di sessione |
| Namespace del workload solo VPN | Assenza di una route verso la rete in chiaro applicata dal kernel | La VPN vede comunque entrambe le estremità; host/root rimane trusted | Strumenti per incarichi autorizzati e uscita fissa |
| Browser remoto disposable | La destinazione è isolata dal browser/endpoint locale | Il provider del workspace vede l'attività e l'identità di login | Siti/file non trusted e ricerca controllata |
| Servizio interno I2P | Tunnel overlay separati in ingresso/uscita; nessun exit ufficiale | Ecosistema più piccolo/diverso; comportamento dei peer a lungo termine | Servizi nativi di I2P, non sostituzione del web ordinario |
| Mixnet/consegna asincrona | Ritardi, batching e cover traffic resistono all'analisi temporale | Alta latenza, applicazioni e maturità limitate | Messaggi/task che non richiedono interazione |

## Relay a conoscenza separata

Un pattern relay a due operatori può superare una singola VPN per un'applicazione circoscritta:
```text
client identity/IP
|
ingress relay -- sees client, not clear request/destination detail
|
encrypted request
|
egress gateway -- sees request/destination, not client IP
|
target service
```
Apple Private Relay è un esempio implementato: Apple gestisce l'ingresso mentre un diverso content provider gestisce l'uscita, quindi normalmente nessuno dei due vede sia l'IP del client sia la destinazione della navigazione.<sup>[[1]](#references)</sup> Si tratta di un servizio di privacy specifico del prodotto, per Safari/DNS, non di una rete di anonimato per tutti i dispositivi, e preserva deliberatamente una regione approssimativa.

Oblivious HTTP (OHTTP) standardizza un pattern applicativo più limitato. Il relay vede il client e il traffico cifrato verso il gateway; il gateway decritta il messaggio HTTP, ma vede il relay e non il client. RFC 9458 avverte che richiede il supporto volontario di relay/gateway, è più adatto a richieste senza cookie/autenticazione/stato di sessione ed esclude l'analisi del traffico dalle proprie garanzie.<sup>[[2]](#references)</sup>

### Checklist di progettazione

1. Definisci gli esatti messaggi applicativi da proteggere; non fare silenziosamente da proxy per sessioni web autenticate arbitrarie.
2. Usa organizzazioni di ingresso e uscita gestite indipendentemente, con amministrazione, credenziali, logging e controllo legale separati, ove possibile.
3. Cifra la richiesta applicativa verso il gateway affinché l'ingresso non possa leggerla.
4. Rimuovi gli header di forwarding derivati dal client, gli identificatori TLS e i token stabili per utente al livello appropriato.
5. Evita chiavi univoche, cookie o campi del payload che consentano al gateway di ricollegare le richieste nonostante la separazione del trasporto.
6. Aggrega, minimizza e fai scadere i log su entrambi i lati; documenta il rischio di collusione e di divulgazione obbligata.
7. Applica padding o batching solo in base a un protocollo revisionato. Un traffic shaping fatto in casa può creare una firma univoca senza impedire la correlazione.
8. Esegui test con richieste canary controllate e confronta ciò che registrano rispettivamente il client, l'ingresso, il gateway e il target.

Per la normale navigazione interattiva, usa Tor Browser invece di inventare un proxy OHTTP privato. OHTTP protegge una transazione applicativa supportata, non un'identità completa del browser.

## Applica il percorso per workload

Un kill switch basato soltanto su route dell'host modificabili può fallire durante il rinnovo DHCP, la sospensione/riattivazione, i cambiamenti IPv6 o il crash di un tunnel. Un pattern Linux più robusto assegna a un container o a un network namespace solo un'interfaccia loopback e un'interfaccia tunnel. WireGuard documenta che un'interfaccia può essere creata in un namespace fisico, spostata in un namespace del workload e mantenere il proprio socket UDP cifrato nel namespace originale.<sup>[[3]](#references)</sup>

### Pattern di deployment

1. Costruisci prima il sistema su un host usa-e-getta/con console locale; gli errori nei namespace possono rimuovere l'accesso remoto.
2. Inserisci l'interfaccia Ethernet/Wi-Fi fisica e DHCP/supplicant in un namespace **fisico**.
3. Crea lì l'interfaccia WireGuard affinché il suo socket di trasporto cifrato abbia accesso alla rete fisica.
4. Sposta solo l'interfaccia WireGuard nel namespace del **workload** e rendila l'unica route predefinita.
5. Assegna al workload un resolver specifico del namespace, raggiungibile solo attraverso il tunnel. Considera esplicitamente IPv6.
6. Esegui il container del browser/tool in quel namespace senza host networking, capability privilegiata, directory condivisa del browser o personal credential agent.
7. Arresta il tunnel e verifica che il workload non possa risolvere o connettersi a un endpoint IPv4 o IPv6 controllato.
8. Testa il roaming dell'endpoint, il rinnovo DHCP, la sospensione/riattivazione e la gestione dei captive portal al di fuori del namespace del workload.
9. Registra l'hash della configurazione namespace/tunnel e l'indirizzo di egress approvato per la responsabilità dell'engagement.

Questo fornisce **route enforcement**, non anonimato rispetto alla VPN o al bastion dell'engagement. Un host/root compromesso può ispezionare o modificare i namespace.

## Tor bridges e pluggable transports

I bridge sono relay di ingresso Tor non pubblici. I pluggable transports modificano il traffico del primo hop, rendendo più difficile il semplice blocco o la classificazione del protocollo. Non aggiungono livelli di relay anonimi dopo l'ingresso e non sconfiggono un osservatore capace di una correlazione temporale più ampia.

| Transport | Approccio del primo hop | Compromesso pratico |
|---|---|---|
| **obfs4** | Fa apparire il traffico casuale e resiste all'attivo probing | Un indirizzo bridge noto può comunque essere bloccato |
| **Snowflake** | Usa proxy WebRTC volontari di breve durata per raggiungere un bridge | Le prestazioni variano; esistono pattern broker/STUN/WebRTC |
| **WebTunnel** | Trasporta il traffico del bridge in un tunnel WebSocket simile a HTTPS | Dipende da un web front raggiungibile e può comunque essere classificato |

Il Tor Project descrive Snowflake e WebTunnel come transport per l'elusione della censura, non come strumenti di indistinguibilità perfetta.<sup>[[4]](#references)</sup>

### Workflow sicuro

1. Inizia con la connessione diretta di Tor Browser. Aggiungi un bridge solo quando il blocco o la visibilità nel modello dell'osservatore locale lo giustificano.
2. Usa transport integrati o bridge line ottenuti tramite i canali del Tor Project. Non scaricare binary di transport casuali o liste pubbliche di bridge dai forum.
3. Prova l'opzione supportata meno complessa che si connette in modo affidabile; registra il motivo della scelta.
4. Mantieni Tor Browser altrimenti standard. Un bridge non rende sicure le estensioni personalizzate, gli account login o le impostazioni insolite del browser.
5. Testa la riconnessione e la correttezza dell'orologio. Non alternare ripetutamente i transport in modo da inviare una sequenza distintiva allo stesso osservatore locale.
6. Rivaluta la situazione se cambiano il censor o la policy di rete; in alcune località l'utilizzo può essere sensibile o soggetto a restrizioni.

## Onion services come rendezvous privato

Un onion service crea circuiti Tor in uscita verso introduction point e relay di rendezvous, quindi non necessita di una porta pubblica in ingresso e non espone l'IP del server attraverso il protocollo onion. Il traffico client-to-service rimane all'interno di Tor e l'indirizzo onion autentica la chiave del service.<sup>[[5]](#references)</sup>

Per un portale di raccolta legittimo, un repository privato, un'interfaccia amministrativa o un evidence drop dell'engagement:

1. Esegui l'applicazione su un host/VM dedicato e fai il bind a loopback o a un Unix socket isolato.
2. Installa Tor dal suo repository ufficiale e segui la configurazione ufficiale v3 onion-service; non usare mai istruzioni obsolete v2.
3. Proteggi la chiave privata dell'onion service come una chiave TLS/signing. Esegui il backup solo se è necessaria un'identità stabile.
4. Aggiungi la client authorization dell'onion service per un gruppo chiuso e distribuisci le credenziali tramite un canale autenticato indipendentemente.<sup>[[6]](#references)</sup>
5. Impedisci all'origine di recuperare font, analytics, aggiornamenti o webhook di terze parti che rivelino il suo IP pubblico o l'account dell'operatore.
6. Implementa autenticazione e autorizzazione anche nell'applicazione; il possesso dell'indirizzo onion non costituisce controllo degli accessi.
7. Applica patch, rate-limit e monitora il service senza incorporare telemetry di terze parti.
8. Da un contesto di test separato, verifica che DNS, email, pagine di errore, metadati dei file e header delle risposte non divulghino l'origine.
9. Per l'uso red-team, indica service, proprietario, finalità e orario di shutdown nel ROE. Non usarlo per nascondere C2 fuori scope.

## Browser remoto e workspace usa-e-getta

Un browser remoto sposta il rendering e i contenuti rischiosi lontano dall'endpoint locale e può presentare un egress cloud specifico per l'engagement. Protegge il dispositivo locale da alcuni contenuti e dalla persistenza; non rende anonimo l'operatore rispetto al provider del workspace. AWS, ad esempio, documenta la raccolta di dati del portale, dell'identità, delle policy, delle preferenze e dei log di sessione, anche se l'istanza del browser usa-e-getta viene eliminata al termine della sessione.<sup>[[7]](#references)</sup>

Usa un workspace controllato dall'organizzazione per ogni engagement, limita download/upload/clipboard, disabilita i personal identity provider, invia il suo egress fisso attraverso il bastion approvato ed elimina il workspace dopo l'esportazione delle evidenze. Considera la console del provider, l'IdP e l'amministratore come osservatori.

## I2P e overlay interni

I2P crea tunnel inbound e outbound unidirezionali separati e non dispone di exit ufficiali a livello di rete; è principalmente destinato ai service all'interno di I2P.<sup>[[8]](#references)</sup> Non è un modo più veloce drop-in per navigare nell'Internet pubblico. Gli outproxy introducono un punto di trust e il threat model ufficiale richiede ulteriori ricerche e non rivendica un anonimato perfetto.

Usa I2P solo quando entrambe le estremità lo supportano intenzionalmente, isola il suo router di lunga durata dalle applicazioni personali e comprendi che peer/reti locali possono osservare la partecipazione a I2P. Non aumentare il numero di hop o modificare la selezione dei peer senza evidenze: impostazioni insolite possono ridurre le prestazioni e l'anonymity set.

## Operazioni resistenti alla correlazione

- Preferisci una configurazione client comune e supportata rispetto a una build univoca.
- Separa le identità sull'endpoint; nessuna topologia di routing ripara il riutilizzo di account, pagamenti, recupero o contenuti.
- Per le attività non interattive, preferisci un protocollo asincrono/mixnet revisionato rispetto all'aggiunta manuale di sleep o traffico fittizio.
- Evita di gestire identità apparentemente separate secondo un pattern sincronizzato dallo stesso contesto fisico.
- Usa un one-way export gate: i contenuti non attendibili entrano in un renderer usa-e-getta; ne esce solo un risultato revisionato e sanificato.
- Mantieni gli orologi corretti per la sicurezza del protocollo, ma rimuovi gli timestamp precisi non necessari dagli artefatti pubblicati.
- Riduci al minimo la durata delle sessioni e l'infrastruttura obsoleta senza una rotazione rapida di tipo “fast-flux”, che è evidente e danneggia la responsabilità.

## Tecniche che non possono usare terze parti non coinvolte

Queste sono tecniche reali dell'avversario, non tecniche immaginarie o irrilevanti. I loro meccanismi e il rilevamento sono trattati in [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md), [Covert Physical and Wireless Access](covert-physical-wireless-access.md) e negli [APT case studies](government-and-apt-case-studies.md). Durante un esercizio autorizzato, riproducine il comportamento osservabile usando sostituti di proprietà:

- simula il churn degli exit residenziali/mobili con pool di relay controllati, mai con mercati dal consenso poco chiaro;
- simula open proxy, router compromessi e botnet con VM/router di proprietà;
- simula account cloud rubati con un tenant di esercizio designato e un'identità vittima sintetica;
- simula domain fronting su un reverse proxy di proprietà anziché su una CDN non consenziente;
- simula il Wi-Fi di terze parti con due AP isolati di proprietà del laboratorio;
- tratta la crittografia personalizzata, le catene multi-VPN e la rotazione degli identificatori come ipotesi di test i cui flow, account e artefatti degli endpoint restano rilevabili.

Per un red team autorizzato, qualsiasi tentativo di rendere il traffico meno riconoscibile deve essere un obiettivo di rilevamento esplicito nel ROE, avere una mappa di attribuzione conservata dal controller e includere un meccanismo di arresto/deconfliction.

## Matrice di verifica

| Test | Risultato atteso | Significato del fallimento |
|---|---|---|
| Tunnel/bridge arrestato | Il workload non ha alcun percorso diretto IPv4/IPv6/DNS | La route enforcement è incompleta |
| Log del target ispezionato | Appare solo l'egress/l'identità applicativa previsti | leak di header, route o account |
| Log dell'ingresso ispezionato | La sorgente è presente; target/richiesta in chiaro assenti | La trust split è fallita all'ingresso |
| Log dell'uscita ispezionato | Relay/richiesta presenti; identità della sorgente assente | La trust split è fallita all'uscita |
| Origine onion sottoposta a scan esterno | Nessun service di origine pubblico è raggiungibile/collegato | L'origine è trapelata o ha doppia connettività |
| Sessione usa-e-getta terminata | Lo stato dell'istanza è scomparso; le evidenze approvate sono conservate separatamente | Il confine di persistenza è fallito |
| Lookup del controller eseguito | L'attività viene associata rapidamente all'engagement/operatore | La responsabilità del red team è fallita |

## References

- [1] [Apple Platform Security — sicurezza di iCloud Private Relay](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Routing e Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake e pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — Come funzionano gli Onion Services](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — Impostazioni avanzate degli Onion Service e client authorization](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Crittografia dei dati in Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Threat Model](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
{{#include ../banners/hacktricks-training.md}}
