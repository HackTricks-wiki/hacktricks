# Architetture avanzate per la privacy di rete

La complessità è utile solo quando elimina uno specifico osservatore o una modalità di guasto. Una combinazione unica di tunnel, un formato dei pacchetti personalizzato, uno user agent raro o un'infrastruttura che cambia frequentemente possono diventare un fingerprint più forte di una configurazione standard utilizzata da migliaia di persone.

L'[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) fornisce lo schema comune `Pros`/`Cons`/`Procedure`/`Detection`. Questa pagina approfondisce le architetture più complesse e i confini di trust.

L'obiettivo avanzato è quindi la **separazione delle informazioni**: nessun componente ordinario dovrebbe possedere contemporaneamente l'identità dell'utente, la destinazione, il plaintext e la cronologia delle attività a lungo termine. Questo non garantisce l'invisibilità e la collusione, le procedure legali, la compromissione dell'endpoint o la correlazione del traffico end-to-end possono comunque ricostruire il percorso.

## Selezione dell'architettura

| Pattern | Proprietà acquisita | Nuovo trust/failure | Uso adatto |
|---|---|---|---|
| Standard Tor Browser | Fingerprint del browser condiviso e percorso attraverso più relay | La bassa latenza consente la correlazione del traffico | Navigazione web anonima generale |
| Tor bridge + pluggable transport | Rende più difficile il blocco e la classificazione diretta di Tor | Il bridge/transport può comunque essere rilevato; il bridge apprende la sorgente | Reti sottoposte a censura |
| Onion service | Nasconde l'IP del servizio; evita l'exit; autentica l'identità onion | La chiave onion e l'endpoint del server diventano asset critici | Pubblicazione privata, raccolta di dati o amministrazione |
| Independent ingress + egress relays | Normalmente nessun singolo relay vede sorgente e destinazione | Gli operatori possono colludere; il timing attraversa entrambi | Applicazioni supportate ad alte prestazioni |
| Oblivious HTTP | Separa l'indirizzo IP sorgente dalla richiesta HTTP stateless cifrata | Richiede il supporto dell'applicazione, del relay e del gateway | Telemetria, query e invii senza stato di sessione |
| VPN-only workload namespace | Assenza di una route verso una rete non cifrata, applicata dal kernel | La VPN vede comunque entrambe le estremità; host/root rimane affidabile | Tool per attività autorizzate e egress fisso |
| Disposable remote browser | La destinazione è isolata dal browser/endpoint locale | Il provider del workspace vede l'attività e l'identità di login | Siti/file non attendibili e ricerca controllata |
| I2P internal service | Tunnel overlay separati in ingresso/uscita; nessun exit ufficiale | Ecosistema più piccolo/differente; comportamento dei peer a lunga durata | Servizi nativi di I2P, non sostituzione del web ordinario |
| Mixnet/asynchronous delivery | Ritardo, batching e cover traffic resistono all'analisi temporale | Latenza elevata, applicazioni e maturità limitate | Messaggi/task che non richiedono interazione |

## Relay con separazione delle informazioni

Un pattern di relay gestito da due operatori può essere superiore a una singola VPN per un'applicazione specifica:
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
Apple Private Relay è un esempio implementato: Apple gestisce l'ingress, mentre un diverso content provider gestisce l'egress, quindi normalmente nessuno dei due vede sia l'IP del client sia la destinazione della navigazione.<sup>[[1]](#references)</sup> È un servizio di privacy specifico del prodotto per Safari/DNS, non una rete di anonimato per tutti i dispositivi, e preserva deliberatamente una regione approssimativa.

Oblivious HTTP (OHTTP) standardizza un pattern applicativo più circoscritto. Il relay vede il client e il traffico cifrato verso il gateway; il gateway decritta il messaggio HTTP ma vede il relay, non il client. RFC 9458 avverte che richiede il supporto volontario di relay/gateway, è più adatto a richieste senza cookie/autenticazione/stato di sessione ed esclude l'analisi del traffico dalle proprie garanzie.<sup>[[2]](#references)</sup>

### Checklist di progettazione

1. Definire gli esatti messaggi applicativi da proteggere; non fare silenziosamente da proxy a sessioni web autenticate arbitrarie.
2. Usare organizzazioni ingress ed egress gestite separatamente, con amministrazione, credenziali, logging e controllo legale distinti ove possibile.
3. Cifrare la richiesta applicativa verso il gateway, in modo che l'ingress non possa leggerla.
4. Rimuovere gli header di forwarding derivati dal client, gli identificatori TLS e i token stabili per utente al livello appropriato.
5. Evitare chiavi, cookie o campi del payload univoci che consentano al gateway di ricollegare le richieste nonostante la separazione del trasporto.
6. Aggregare, minimizzare e far scadere i log su entrambi i lati; documentare il rischio di collusione e di divulgazione obbligata.
7. Eseguire padding o batching solo in base a un protocollo verificato. Il traffic shaping fatto in casa può creare una firma univoca senza impedire la correlazione.
8. Testare con richieste canary controllate e confrontare ciò che registrano rispettivamente il client, l'ingress, il gateway e il target.

Per la normale navigazione interattiva, usare Tor Browser invece di inventare un proxy OHTTP privato. OHTTP protegge una transazione applicativa supportata, non un'identità completa del browser.

## Applicare il percorso per workload

Un kill switch basato solo su route host modificabili può fallire durante il rinnovo DHCP, la sospensione/riattivazione, i cambiamenti IPv6 o il crash di un tunnel. Un pattern Linux più robusto assegna a un container o a un network namespace solo un'interfaccia loopback e un'interfaccia tunnel. WireGuard documenta che un'interfaccia può essere creata in un namespace fisico, spostata in un namespace del workload e mantenere il proprio socket UDP cifrato nel namespace originale.<sup>[[3]](#references)</sup>

### Pattern di deployment

1. Costruire inizialmente tutto su un host usa-e-getta/console locale; gli errori nei namespace possono rimuovere l'accesso remoto.
2. Inserire l'interfaccia Ethernet/Wi-Fi fisica e DHCP/supplicant in un namespace **fisico**.
3. Creare lì l'interfaccia WireGuard, così il suo socket di trasporto cifrato dispone dell'accesso alla rete fisica.
4. Spostare solo l'interfaccia WireGuard nel namespace **workload** e renderla l'unica route predefinita.
5. Assegnare al workload un resolver specifico del namespace, raggiungibile solo attraverso il tunnel. Gestire esplicitamente IPv6.
6. Eseguire il container del browser/tool in quel namespace senza host networking, capability privilegiata, directory browser condivisa o personal credential agent.
7. Arrestare il tunnel e verificare che il workload non possa risolvere o connettersi a un endpoint IPv4 o IPv6 controllato.
8. Testare endpoint roaming, rinnovo DHCP, sospensione/ripresa e gestione dei captive portal al di fuori del namespace del workload.
9. Registrare l'hash della configurazione namespace/tunnel e l'indirizzo egress approvato per la responsabilità dell'engagement.

Questo fornisce **route enforcement**, non anonimato rispetto alla VPN o al bastion dell'engagement. Un host/root compromesso può ispezionare o modificare i namespace.

## Tor bridges e pluggable transports

I bridges sono relay di ingresso Tor non pubblici. I pluggable transports modificano il traffico del primo hop, rendendo più difficile il semplice blocking o la classificazione del protocollo. Non aggiungono livelli di relay anonimi dopo l'ingresso e non eludono un osservatore capace di una correlazione temporale più ampia.

| Transport | Approccio al primo hop | Compromesso pratico |
|---|---|---|
| **obfs4** | Fa apparire il traffico casuale e resiste all'attivo probing | Un indirizzo bridge noto può comunque essere bloccato |
| **Snowflake** | Usa proxy WebRTC di volontari a breve durata per raggiungere un bridge | Le prestazioni variano; esistono pattern broker/STUN/WebRTC |
| **WebTunnel** | Trasporta il traffico del bridge in un tunnel WebSocket simile a HTTPS | Dipende da un web front raggiungibile e può comunque essere classificato |

Il Tor Project descrive Snowflake e WebTunnel come transport di elusione della censura, non come strumenti di indistinguibilità perfetta.<sup>[[4]](#references)</sup>

### Workflow sicuro

1. Iniziare con la connessione diretta di Tor Browser. Aggiungere un bridge solo quando il blocking o la visibilità nel modello dell'osservatore locale lo giustificano.
2. Usare transport integrati o bridge line ottenuti tramite i canali del Tor Project. Non scaricare binari di transport casuali o liste pubbliche di bridge dai forum.
3. Provare l'opzione supportata meno complessa che si connette in modo affidabile; registrare il motivo della scelta.
4. Mantenere per il resto Tor Browser standard. Un bridge non rende sicure le estensioni personalizzate, gli accessi agli account o le impostazioni insolite del browser.
5. Testare la riconnessione e la correttezza dell'orologio. Non cambiare ripetutamente transport in modo da inviare una sequenza distintiva allo stesso osservatore locale.
6. Rivalutare la situazione se cambiano il censor o la policy di rete; in alcuni luoghi l'uso può essere sensibile o soggetto a restrizioni.

## Onion services come rendezvous privato

Un onion service crea circuiti Tor in uscita verso introduction point e relay rendezvous, quindi non necessita di una porta pubblica in ingresso e non espone l'IP del server tramite il protocollo onion. Il traffico client-service resta all'interno di Tor e l'indirizzo onion autentica la chiave del service.<sup>[[5]](#references)</sup>

Per un portale di ricezione legittimo, un repository privato, un'interfaccia amministrativa o un evidence drop dell'engagement:

1. Eseguire l'applicazione su un host/VM dedicato e associarla al loopback o a un Unix socket isolato.
2. Installare Tor dal repository ufficiale e seguire la configurazione ufficiale v3 dell'onion service; non usare mai istruzioni obsolete v2.
3. Proteggere la chiave privata dell'onion service come una chiave TLS/signing. Eseguirne il backup solo se è necessaria un'identità stabile.
4. Aggiungere la client authorization dell'onion service per un gruppo chiuso e consegnare le credenziali tramite un canale autenticato indipendentemente.<sup>[[6]](#references)</sup>
5. Impedire all'origine di recuperare font, analytics, aggiornamenti o webhook di terze parti che rivelino il suo IP pubblico o l'account dell'operatore.
6. Implementare autenticazione e autorizzazione anche nell'applicazione; il possesso dell'indirizzo onion non costituisce controllo degli accessi.
7. Applicare patch, rate-limit e monitorare il service senza incorporare telemetria di terze parti.
8. Da un contesto di test separato, verificare che DNS, email, pagine di errore, metadati dei file e header delle risposte non divulghino l'origine.
9. Per l'uso in red team, elencare service, proprietario, finalità e orario di spegnimento nel ROE. Non usarlo per nascondere C2 fuori scope.

## Browser remoto e workspace usa-e-getta

Un browser remoto sposta il rendering e i contenuti rischiosi lontano dall'endpoint locale e può presentare un egress cloud specifico dell'engagement. Protegge il dispositivo locale da alcuni contenuti e dalla persistenza; non rende l'operatore anonimo rispetto al provider del workspace. AWS, ad esempio, documenta la raccolta di dati relativi a portale, identità, policy, preferenze e log di sessione anche se l'istanza browser usa-e-getta viene eliminata al termine della sessione.<sup>[[7]](#references)</sup>

Usare un workspace controllato dall'organizzazione per ogni engagement, limitare download/upload/clipboard, disabilitare gli identity provider personali, inviare il suo egress fisso attraverso il bastion approvato ed eliminare il workspace dopo l'esportazione delle evidenze. Considerare la console del provider, l'IdP e l'amministratore come osservatori.

## I2P e overlay interni

I2P crea tunnel inbound e outbound unidirezionali separati e non dispone di exit ufficiali a livello di rete; è principalmente destinato ai service all'interno di I2P.<sup>[[8]](#references)</sup> Non è un modo più veloce, pronto all'uso, per navigare nell'Internet pubblico. Gli outproxy introducono un punto di fiducia e il threat model ufficiale richiede ulteriori ricerche e non rivendica un anonimato perfetto.

Usare I2P solo quando entrambe le estremità lo supportano intenzionalmente, isolare il suo router a lunga durata dalle applicazioni personali e comprendere che i peer/le reti locali possono osservare la partecipazione a I2P. Non aumentare il numero di hop o modificare la selezione dei peer senza evidenze: impostazioni insolite possono ridurre le prestazioni e l'insieme di anonimato.

## Operazioni resistenti alla correlazione

- Preferire una configurazione client comune e supportata anziché una build univoca.
- Separare le identità sull'endpoint; nessuna topologia di routing ripara il riutilizzo di account, pagamenti, recupero o contenuti.
- Per le attività non interattive, preferire un protocollo asincrono/mixnet verificato invece di aggiungere manualmente ritardi o traffico fittizio.
- Evitare di gestire identità apparentemente separate secondo uno schema sincronizzato dallo stesso contesto fisico.
- Usare un gate di esportazione a senso unico: il contenuto non attendibile entra in un renderer usa-e-getta; esce solo un risultato verificato e sanificato.
- Mantenere gli orologi corretti per la sicurezza del protocollo, ma rimuovere dagli artefatti pubblicati i timestamp precisi non necessari.
- Minimizzare la durata delle sessioni e l'infrastruttura obsoleta senza una rotazione rapida “fast-flux”, che è evidente e danneggia la responsabilità.

## Tecniche che non possono usare terze parti non coinvolte

Queste sono tecniche avversarie reali, non immaginarie o irrilevanti. I loro meccanismi e il rilevamento sono trattati in [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md), [Covert Physical and Wireless Access](covert-physical-wireless-access.md) e negli [APT case studies](government-and-apt-case-studies.md). Durante un'esercitazione autorizzata, riprodurne il comportamento osservabile con sostituti di proprietà:

- modellare il churn degli exit residenziali/mobili con pool di relay controllati, mai con mercati dal consenso non chiaro;
- modellare open proxy, router compromessi e botnet con VM/router di proprietà;
- modellare account cloud sottratti con un tenant di esercitazione designato e un'identità vittima sintetica;
- modellare il domain fronting su un reverse proxy di proprietà anziché su una CDN non consenziente;
- modellare il Wi-Fi di terze parti con due AP isolati di proprietà del laboratorio;
- trattare la cifratura personalizzata, le catene multi-VPN e la rotazione degli identificatori come ipotesi di test i cui artefatti di flusso, account ed endpoint restano rilevabili.

Per un red team autorizzato, ogni tentativo di rendere il traffico meno riconoscibile deve essere un obiettivo di rilevamento esplicito nel ROE, avere una mappa di attribuzione custodita dal controller e includere un meccanismo di arresto/deconfliction.

## Matrice di verifica

| Test | Risultato atteso | Il fallimento significa |
|---|---|---|
| Tunnel/bridge arrestato | Il workload non dispone di alcun percorso diretto IPv4/IPv6/DNS | La route enforcement è incompleta |
| Log del target ispezionato | Appare solo l'egress/l'identità applicativa pianificata | Header, route o account leak |
| Log dell'ingress ispezionato | La sorgente è presente; target/richiesta in chiaro assenti | La separazione della fiducia è fallita all'ingress |
| Log dell'egress ispezionato | Relay/richiesta presenti; identità della sorgente assente | La separazione della fiducia è fallita all'egress |
| Origine onion analizzata esternamente | Nessun service origin pubblico è raggiungibile/collegato | L'origine è trapelata o ha doppia connessione |
| Sessione usa-e-getta terminata | Lo stato dell'istanza è scomparso; le evidenze approvate sono conservate separatamente | Il confine di persistenza è fallito |
| Lookup del controller eseguito | L'attività viene associata rapidamente all'engagement/operatore | La responsabilità del red team è fallita |

## References

- [1] [Sicurezza delle piattaforme Apple — sicurezza di iCloud Private Relay](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Routing e network namespace](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake e pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — Come funzionano gli Onion Services](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — Impostazioni avanzate degli Onion Service e client authorization](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Cifratura dei dati in Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Threat Model](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
