# Nodi di campo autorizzati resilienti alla cattura

{{#include ../banners/hacktricks-training.md}}

Un Raspberry Pi, mini-PC, travel router o dispositivo cellulare installato in loco può offrire a un red team autorizzato un punto di osservazione duraturo. È anche un probabile punto di scoperta, furto e attribuzione. L'obiettivo progettuale corretto è quindi **un accesso stabile e controllato con poca autorità sul nodo di campo**, non un implant non tracciabile.

Questa guida si applica esclusivamente alle apparecchiature installate con l'autorizzazione scritta del proprietario del sito. Un bar, un vicino, un hotel o un edificio condiviso non rientrano nell'ambito solo perché la loro rete è raggiungibile. Non nascondere hardware in un luogo il cui proprietario non abbia prestato il consenso, non aggirare un captive portal, non usare le credenziali di un'altra persona, non interferire con il monitoraggio e non tentare di cancellare le prove dopo la scoperta.

{% hint style="warning" %}
Non esiste un'impostazione affidabile per “non lasciare tracce”. I record di associazione radio, DHCP/NAT, operatore, telecamere, acquisto, dispositivo, provider, controller e destinazione possono sopravvivere al dispositivo. Un red team responsabile rimuove invece dal nodo **i secret personali e non pertinenti**, conserva l'attribuzione protetta sul controller e rende la cattura semplice da contenere.
{% endhint %}

## Vantaggi e svantaggi

**Vantaggi:** sorgente interna o adiacente al target realistica; testing stabile e ad alta velocità; convalida NAC, egress, inventario fisico e copertura del SOC; può continuare anche in caso di cambiamenti dell'indirizzo dell'operatore; l'accesso limitato può essere revocato centralmente.

**Svantaggi:** l'installazione fisica crea prove evidenti; la perdita può esporre credenziali del dispositivo, profili di rete e dati raccolti; il traffico di controllo ripetuto è rilevabile; alimentazione, portal e cambiamenti radio compromettono l'affidabilità; un tunnel ampio può diventare un pivot non controllato.

## Modello di minaccia e invarianti progettuali

Supponi che chi trova il dispositivo possa rimuovere lo storage, ispezionare il firmware, copiare ogni secret conservato dal software, osservare il comportamento di rete successivo e consegnare il dispositivo al cliente o alle forze dell'ordine. La crittografia dell'intero disco protegge un dispositivo spento solo nel rispetto del proprio modello di minaccia; un nodo acceso e sbloccato e le chiavi rilasciate in memoria sono casi diversi.

| Invariante | Conseguenza pratica |
|---|---|
| Nessuna identità diretta tra operatore e nodo | L'operatore effettua il login al gateway dell'organizzazione; il nodo ha un'identità del dispositivo diversa |
| Nessun materiale della workstation personale | Nessuna chiave SSH personale, profilo del browser, email, password manager, associazione con il telefono o cache della CLI cloud |
| Nessun secret master del controller | Un nodo non può effettuare l'enrollment di un altro nodo, modificare la policy o decrittografare altri engagement |
| Solo connessioni in uscita e ristrette | La rete di campo non accetta alcun management listener; il nodo raggiunge solo i servizi di rendezvous, aggiornamento e sincronizzazione dell'ora denominati |
| Autorità limitata e di breve durata | Ogni credenziale è associata a un solo dispositivo, audience, servizio, scadenza e percorso di revoca immediata |
| Dati locali minimi | I risultati vengono inviati al controller; le cache sono cifrate, con dimensioni e TTL limitati e non autorevoli |
| La responsabilità del controller sopravvive alla cattura | La mappatura asset-engagement, le approvazioni, gli accessi degli operatori e i comandi vengono archiviati centralmente e sottoposti a controllo degli accessi |
| La perdita interrompe il lavoro | Una scoperta o un cambiamento di stato non spiegato attiva arresto, revoca, notifica e conservazione delle prove, non la distruzione remota |

La baseline IoT di NIST raggruppa l'identificazione del dispositivo, la configurazione, la protezione dei dati, l'accesso logico, l'aggiornamento sicuro del software e la consapevolezza dello stato di cybersecurity come funzionalità fondamentali. Considera nello specifico la consapevolezza dello stato e i record degli eventi archiviati fuori dal dispositivo come supporto alle indagini sui compromessi.<sup>[[1]](#references)</sup>

## Architettura di riferimento
```text
operator workstation
|  phishing-resistant MFA; named user; no field-device key
v
organization access gateway ----> immutable audit / alerting
|  per-engagement authorization          ^
v                                        |
rendezvous/broker <==== outbound mTLS or WireGuard ==== field node
|                                                     |-- approved site Wi-Fi/Ethernet
+---- allowlisted owned test services                 +-- organization cellular fallback
```
Il gateway deve sapere quale operatore nominativo ha raggiunto quale dispositivo nominativo. Il field node necessita solo di una device credential per il rendezvous. Non apprende mai l'indirizzo sorgente o il secret di autenticazione dell'operatore, e l'operatore non vi copia mai una private management key. Questo riduce il collegamento personale recuperabile **dallo storage del field node** senza distruggere la accountability dell'esercitazione.

Per una flotta più grande, un sistema di workload identity può emettere identità X.509 a breve durata e ruotare automaticamente le chiavi. SPIFFE raccomanda gli X.509 SVID quando possibile e descrive durate brevi e rotazione frequente come misure per limitare l'esposizione derivante dalla compromissione delle chiavi.<sup>[[2]](#references)</sup> Un piccolo team può applicare le stesse proprietà con una CA privata e certificati automatizzati per dispositivo; installare SPIRE non è necessario semplicemente per soddisfare il pattern.

## Step 1: autorizzare e registrare il posizionamento

1. Registrare il proprietario, il sito, la zona di posizionamento esatta consentita, le reti consentite, la finestra di assessment, le destinazioni/azioni consentite e i contatti di emergenza.
2. Registrare modello, seriale, seriale dello storage, MAC cablate/wireless, IMEI/eSIM del modem o ICCID della SIM, alimentatore e una fotografia aggiornata.
3. Assegnare al dispositivo un engagement identifier non personale, ad esempio `E2026-014-DROP03`. Non codificare il nome del cliente negli hostname o negli SSID trasmessi.
4. Comunicare al controller dell'esercitazione e al gruppo minimo necessario di physical security/SOC incaricato del deconfliction che cosa significano “perso”, “spostato” e “scoperto” per questo test.
5. Concordare in anticipo chi può recuperarlo e come un eventuale ritrovatore può segnalarlo. Un'etichetta di sicurezza può omettere i dettagli sensibili del cliente fornendo comunque un callback controllato.
6. Impostare una scadenza automatica dell'autorizzazione. La connettività che continua dopo la fine dello scope non deve estendere il permesso.

## Step 2: creare un'immagine minima recuperabile

Usare un'immagine OS supportata, verificarne la firma/checksum tramite il canale documentato dal vendor, installare gli aggiornamenti di sicurezza e mantenere un manifest di build riproducibile. Preferire una base read-only o immutabile con una piccola partizione dati writable, quando il software lo consente.

1. Rimuovere gli account predefiniti, i servizi demo, i compilatori e i package non necessari al workload autorizzato.
2. Disabilitare la GUI locale, Bluetooth, i protocolli di discovery, il file sharing, il Wi-Fi P2P e l'amministrazione inbound, salvo che l'esercitazione ne richieda esplicitamente uno.
3. Abilitare secure boot e measured boot/release delle chiavi basato su TPM, se l'hardware li supporta realmente; non dichiarare che una configurazione Raspberry Pi disponga di measured boot di classe PC senza aver convalidato il modello esatto.
4. Crittografare lo stato locale writable e configurare una dimensione massima e un tempo di retention rigorosi. La crittografia è un controllo di ritardo/contenimento, non una prova che un node in esecuzione non riveli nulla.
5. Inviare i log importanti off-device. Limitare i journal locali per evitare l'esaurimento dello storage, ma non configurare la cancellazione dei log o la deletion anti-forensics.
6. Conservare il manifest dell'immagine, le versioni dei package, l'hash della configurazione e le istruzioni di recovery presso il controller.
7. Reimaging di uno spare a partire dal manifest ed eseguire lo stesso health test. Un design che solo il suo builder sa recuperare non è field-ready.

## Step 3: emettere identità con trust unidirezionale

Creare tre identità diverse:

- una **device identity**, accettata solo dal rendezvous per questo dispositivo;
- una **operator identity**, accettata dal gateway dell'organizzazione e protetta con MFA resistente al phishing; e
- una **controller/deployment identity**, utilizzata per firmare job o configurazioni approvati, conservata al di fuori sia dell'operatore sia del field node.

Il node deve avere la public key necessaria a verificare i job firmati, mai la signing key. Una device credential catturata non deve autenticare a cloud console, source repository, payment account, altri node o alla produzione del cliente.

Usare certificate lifetime brevi quando il rinnovo automatico è affidabile. Quando una chiave WireGuard a lunga durata è necessaria dal punto di vista operativo, trattare la sua public key come revocation handle e limitarla con un tunnel address specifico per peer, una firewall policy e un'autorizzazione del broker. Mantenere un'azione del controller testata che rimuova immediatamente quel peer.

## Step 4: rendezvous outbound stabile

Il seguente pattern di laboratorio di proprietà dell'organizzazione fornisce una gestione stabile attraverso NAT senza esporre un servizio inbound. È normale networking WireGuard, non una covert reverse shell. Usare indirizzi di documentazione e sostituirli solo con endpoint di proprietà dell'organizzazione.

Presso il rendezvous dell'organizzazione, assegnare `10.77.0.1/32`; assegnare al field node `10.77.0.20/32`. La peer entry del gateway deve accettare solo il singolo indirizzo del node:
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
Il nodo effettua una connessione in uscita verso il rendezvous e mantiene il mapping NAT solo quando necessario:
```ini
# field node: /etc/wireguard/wg-field.conf
[Interface]
Address = 10.77.0.20/32
PrivateKey = <DROP03_PRIVATE_KEY>

[Peer]
PublicKey = <RENDEZVOUS_PUBLIC_KEY>
Endpoint = vpn.redteam.example:51820
AllowedIPs = 10.77.0.1/32
PersistentKeepalive = 25
```
WireGuard documenta 25 secondi come intervallo di keepalive sensato in molte implementazioni NAT/firewall quando è necessaria la persistenza; lasciarlo disabilitato è preferibile quando non serve.<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` rende deliberatamente questo un percorso di gestione, non un pivot verso la default route.

Quindi applicare i controlli al di fuori di WireGuard:

1. Risolvere `vpn.redteam.example` tramite il percorso DNS di bootstrap approvato e fissare l'endpoint dell'organizzazione previsto nei record di deployment.
2. Sul nodo, consentire DHCP/RA in uscita, il DNS/NTP richiesto, l'endpoint di rendezvous e il percorso minimo di aggiornamento approvato. Negare il traffico in ingresso non sollecitato su ogni uplink.
3. Sul rendezvous, consentire a `10.77.0.20` di raggiungere solo il broker/health service richiesto dall'esercitazione. Non inoltrarlo genericamente in una rete client.
4. Collocare l'accesso interattivo degli operatori dietro il gateway dell'organizzazione. Evitare di esporre SSH dal nodo attraverso il tunnel se un'interfaccia signed pull-job è sufficiente per l'assessment.
5. Configurare il service manager per avviare il tunnel dopo la disponibilità della rete, riavviarlo dopo un errore con un backoff limitato e generare un alert dopo errori ripetuti. Un restart loop non deve sovraccaricare la sede né nascondere il problema sottostante.
6. Verificare l'ultimo handshake del peer, ma non usare “handshake presente” come prova che il dispositivo non sia compromesso.

TURN può fornire raggiungibilità relay-only per un control plane WebRTC appositamente progettato, mentre una message queue può tollerare un servizio intermittente. TURN assegna esplicitamente a un client un indirizzo relay pubblico dietro NAT; il suo server rimane un osservatore.<sup>[[4]](#references)</sup> Scegliere un'architettura di controllo invece di sovrapporre tunnel senza dichiarare un vantaggio in termini di osservabilità o affidabilità.

## Step 5: stabilità dell'uplink senza link personali

Per un nodo di sede autorizzato, preferire questo ordine:

1. VLAN cablata o VLAN di test dedicata fornita dal client;
2. profilo Wi-Fi enterprise/guest approvato dal proprietario;
3. fallback cellulare/private APN sotto contratto con l'organizzazione.

Non preconfigurarlo mai con un hotspot personale del telefono, un SSID domestico, una eSIM personale, un account Apple/Google personale o un profilo Wi-Fi esportato da un laptop quotidiano. Questi sono esattamente gli artefatti a cui si collegherà una cattura.

Per ogni uplink approvato:

- registrare SSID/BSSID oppure switch/VLAN e il comportamento previsto del captive portal;
- impostare una priorità deterministica e un health check verso un endpoint di proprietà;
- fare in modo che il failover modifichi solo l'underlay; le identità del dispositivo e dell'operatore restano presso il broker;
- assicurarsi che DNS, IPv6 e traffico applicativo non aggirino il rendezvous durante la transizione;
- generare un alert per SSID/BSSID sconosciuti, cambio di SIM, nuovo default gateway, cambio di IP pubblico/ASN o uplink simultanei;
- testare perdita di alimentazione, rinnovo DHCP, riavvio dell'AP, cambio di IP pubblico, 24 ore di inattività, perdita del tunnel e ripristino primary-to-secondary-to-primary prima del deployment.

L'indirizzamento MAC privato può ridurre il tracking casuale tra reti, ma per un NAC autorizzato è spesso necessario un MAC stabile per rete. Registrare il comportamento effettivo del sistema operativo scelto e non ruotare il MAC intorno al controllo degli accessi del proprietario.

## Step 6: limitare attività e dati

Un field node sicuro non dovrebbe accettare testo shell arbitrario da una mailbox. Definire tipi di job firmati come `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` o un'altra azione nominata esplicitamente nelle rules of engagement. Convalidare nuovamente sul nodo destinazione, durata, rate, dimensione dell'output e scope.

1. Assegnare a ogni job un ID univoco, il dispositivo destinatario, l'orario di emissione, la scadenza, un riferimento allo scope e l'output massimo.
2. Firmarlo con l'identità del controller/deployment.
3. Rifiutare campi sconosciuti, job scaduti o riprodotti e job destinati a un altro dispositivo.
4. Inviare i risultati in streaming a un collector di proprietà; cifrare e applicare un TTL a qualsiasi spool locale inevitabile.
5. Registrare nel controller l'ID del job accettato/rifiutato e l'hash del risultato. Non inserire parametri di comando sensibili in un canale pubblico di monitoring.
6. Interrompere l'elaborazione quando l'autorizzazione scade, la rotazione dell'identità fallisce o il controller mette il dispositivo in quarantena.

## Monitoring per discovery, perdita o compromissione

Il monitoring può comunicare al controller che lo stato osservato è cambiato. Non può dimostrare in modo affidabile che “gli investigatori hanno trovato il dispositivo” e tentare di sorvegliare i responder o sondare i loro sistemi supererebbe i limiti di un assessment autorizzato.

### Raccogliere lo stato off-device

Inviare al controller un health record firmato e a basso volume a un intervallo operativo casualizzato ma limitato. Includere solo ciò di cui il controller ha bisogno:

- device ID, boot ID/counter e uptime monotono;
- hash della configurazione/immagine e versione del software;
- seriale del certificato del dispositivo e stato del rinnovo;
- classe dell'uplink, interfaccia, BSSID o contesto switch come autorizzato, hash del default gateway e IP pubblico/ASN osservati da un servizio di proprietà;
- età dell'handshake del tunnel, packet counter e queue depth;
- stato dell'enclosure switch o dell'hardware-tamper se il proprietario ha approvato il sensore;
- pressione sul disco, temperatura, stima dell'offset dell'orologio e ID dell'ultimo job completato con successo;
- un numero di sequenza e una firma per evidenziare replay o lacune.

Archiviare centralmente l'autenticazione del gateway, le decisioni delle policy, l'accesso degli operatori, l'invio dei job, gli hash dei risultati, gli eventi di audit del provider e gli alert. CISA raccomanda di centralizzare i log, proteggerli dalla cancellazione, definire una baseline dell'attività normale e designare i contatti per l'incident response.<sup>[[5]](#references)</sup>

### Indicatori di discovery/compromissione

| Segnale | Possibili spiegazioni | Azione del controller |
|---|---|---|
| Heartbeat assente | errore di alimentazione/rete, cambio del portale, danno, blocco deliberato o rimozione | corroborare lo stato del provider/sito; non riconnettersi da un percorso non approvato |
| Boot counter cambiato in modo imprevisto | interruzione di alimentazione, crash, rimozione o manutenzione | mettere i job in quarantena; confrontare orario ed eventi del sito |
| Hash della configurazione/immagine cambiato | errore di aggiornamento, guasto dello storage o tampering | interrompere l'attività; revocare se non si tratta di una release approvata dal controller |
| Nuovo uplink/BSSID/gateway/ASN | sostituzione dell'AP, roaming, spostamento del dispositivo o intercettazione | confrontare l'inventario approvato; mettere in quarantena una transizione inspiegata |
| Job/firma rifiutati ripetutamente | corruzione, replay o controller non autorizzato | interrompere l'elaborazione e analizzare i log del gateway/controller |
| Credenziale del dispositivo usata due volte o da percorsi incompatibili | chiave clonata, riutilizzo di snapshot o transizione di rete | revocare immediatamente; conservare entrambi i record di sessione |
| Login locale, interfaccia, processo o evento di privilegio inatteso | manutenzione o compromissione | isolare tramite la policy del broker; preservare le evidenze |
| Transizione dello stato dell'enclosure switch | assistenza, spostamento o discovery | notificare il contatto del sito indicato; non attivare azioni distruttive |
| Notifica di abuso del provider/query sull'account o alert del SOC | rilevamento, configurazione errata o traffico fuori scope | interrompere l'attività e attivare il processo di deconfliction/incident |
| Sentinel credential utilizzata | qualcuno ha letto un secret decoy senza privilegi, unico per questo nodo | revocare l'identità reale del dispositivo e preservare la traccia dell'alert |

Una sentinel credential non deve concedere **alcun accesso**, deve chiamare solo un alert service di proprietà dell'organizzazione e deve essere indicata nelle rules of engagement. È un tripwire per la lettura non autorizzata, non un beacon per tracciare chiunque abbia trovato l'apparecchiatura.

### Soglie degli alert

Usare regole stateful, non un unico allarme drammatico di “cattura”:

- **warning:** un intervallo mancato, un normale cambio di indirizzo o crescita della coda;
- **degraded:** tre intervalli consecutivi mancati, ritardo nel rinnovo, perdita dell'uplink primary o riavvii ripetuti;
- **quarantine:** cambio non approvato di hash/boot/uplink, credenziale duplicata, uso del sentinel o evento privilegiato inatteso;
- **confirmed discovery/loss:** report del sito/controller, discrepanza nell'inventario fisico, recupero del dispositivo da parte di una persona non prevista o escalation validata del provider/SOC.

Testare la consegna degli alert tramite un canale indipendente dal field node. Evitare di inviare dettagli sensibili sul client/dispositivo a sistemi di messaggistica personali o account push consumer.

## Runbook per sospetta discovery o cattura

1. **Stop:** sospendere i nuovi job e le sessioni degli operatori. Non inviare una probe per “verificare se si è sotto sorveglianza”.
2. **Quarantine:** fare in modo che il broker neghi l'identità del dispositivo e le relative route, conservando al contempo i log esistenti.
3. **Revoke:** revocare il certificato/chiave del dispositivo, il token della coda, la credenziale di aggiornamento e qualsiasi service token single-purpose. Sospendere la SIM dell'organizzazione quando è plausibile una perdita fisica.
4. **Preserve:** acquisire snapshot dei record del controller, gateway, provider e degli alert; registrare l'orario attendibile, chi ha agito e l'ultima configurazione nota. Non cancellare né eseguire il remote wipe del nodo.
5. **Notify:** contattare il controller dell'esercitazione, il contatto del client per gli incident e i contatti legali/privacy definiti nell'autorizzazione. Se lo ha trovato una terza parte, usare il processo di recupero concordato in precedenza.
6. **Assess:** presumere che ogni secret e risultato in cache sul nodo siano esposti. Enumerare esattamente a cosa poteva accedere ogni secret e se è stato usato dopo l'evento sospetto.
7. **Contain downstream:** ruotare le credenziali dei servizi interessati, invalidare i job in attesa e analizzare i log dei target/provider di proprietà per individuare comportamenti inattesi.
8. **Recover safely:** recuperare il dispositivo solo tramite una persona autorizzata; fotografarlo/imballarlo, registrare la custodia e acquisire le evidenze forensi secondo le indicazioni del client.
9. **Resume with a new identity:** non riabilitare mai silenziosamente la credenziale catturata. Ricostruire dal manifest noto, correggere il problema di controllo e ottenere un'approvazione esplicita.

Le indicazioni attuali del NIST sull'incident response integrano preparazione, rilevamento, risposta e recovery nella gestione del rischio di cybersecurity a livello organizzativo; preservare prima, così il client può determinare cosa è successo e scegliere la risposta appropriata.<sup>[[6]](#references)</sup>

## Capture drill prima del deployment

Consegnare un'unità di test sbloccata o una copia del suo storage a un reviewer indipendente e chiedergli di enumerare:

1. identificativi del dispositivo/sito/engagement;
2. nomi degli operatori, account personali, reti domestiche/workstation e contatti di recovery;
3. destinazioni e credenziali del controller/broker;
4. profili delle reti client e risultati in cache;
5. altri dispositivi/progetti raggiungibili con ogni secret;
6. credenziali di valore o di pagamento;
7. cosa può revocare il controller e con quale rapidità;
8. quale attività resta attribuibile dai log centralizzati.

Criteri di superamento: zero account personali/chiavi di workstation; zero autorità cross-engagement o di enrollment; nessuna credenziale di pagamento; cache cifrata e limitata; un'azione documentata di revoca del dispositivo; accountability completa lato controller. Trattare qualsiasi link personale inatteso o capacità laterale come un blocco al rilascio.

## Chiusura

1. Interrompere i job e disabilitare la route del broker alla fine dello scope.
2. Recuperare e riconciliare l'inventario esatto; segnalare qualsiasi elemento mancante.
3. Preservare log/risultati e, se richiesto, un'immagine forense secondo il piano di conservazione dell'engagement.
4. Revocare le identità del dispositivo, della SIM, della coda, dell'aggiornamento e dei servizi anche quando l'hardware è stato recuperato.
5. Solo dopo la preservazione/accettazione, sanificare o distruggere i media tramite il processo di smaltimento dati approvato dal proprietario e registrare il completamento. Questa è gestione del ciclo di vita, non occultamento.
6. Rimuovere le prenotazioni NAC/DHCP della sede, le route del broker, il DNS, i ruoli cloud, le regole degli alert e i contatti temporanei.
7. Documentare il rilevamento osservato, la telemetria mancante, il tempo necessario per la quarantena e ogni artefatto esposto dalla cattura.

## References

- [1] [NIST — IoT Device Cybersecurity Capability Catalog](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Concepts and short-lived workload identities](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Use Logging on Business Systems](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
{{#include ../banners/hacktricks-training.md}}
