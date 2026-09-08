# Nodi di campo autorizzati e resilienti alla cattura

Un Raspberry Pi, mini-PC, travel router o dispositivo cellulare installato sul posto può fornire a un red team autorizzato un punto di osservazione duraturo. È anche un probabile punto di scoperta, furto e attribuzione. L'obiettivo progettuale corretto è quindi **un accesso stabile e controllato con poca autorità sul nodo di campo**, non un implant non tracciabile.

Questa guida si applica solo alle apparecchiature installate con l'autorizzazione scritta del proprietario del sito. Un bar, un vicino, un hotel o un edificio condiviso non rientrano nell'ambito solo perché la loro rete è raggiungibile. Non nascondere hardware in un luogo in cui non è stato dato il consenso, non aggirare un captive portal, non usare le credenziali di un'altra persona, non interferire con il monitoraggio e non tentare di cancellare le prove dopo la scoperta.

{% hint style="warning" %}
Non esiste un'impostazione affidabile per “non lasciare tracce”. I record di associazione radio, DHCP/NAT, carrier, telecamere, acquisto, dispositivo, provider, controller e destinazione possono sopravvivere al dispositivo. Un red team responsabile rimuove invece dal nodo **i segreti personali e non correlati**, conserva l'attribuzione protetta sul controller e rende la cattura facile da contenere.
{% endhint %}

## Pro e contro

**Pro:** sorgente interna o adiacente al target realistica; testing stabile ad alta velocità; convalida NAC, egress, inventario fisico e copertura del SOC; può continuare anche in caso di cambiamento dell'indirizzo dell'operatore; l'accesso limitato può essere revocato centralmente.

**Contro:** il posizionamento fisico crea prove concrete; la perdita può esporre credenziali del dispositivo, profili di rete e dati raccolti; il traffico di controllo ripetuto è rilevabile; alimentazione, portal e cambiamenti radio compromettono l'affidabilità; un tunnel ampio può diventare un pivot non controllato.

## Modello di minaccia e invarianti progettuali

Supponi che chi trova il dispositivo possa rimuovere lo storage, ispezionare il firmware, copiare ogni segreto conservato dal software, osservare il comportamento di rete successivo e consegnare il dispositivo al cliente o alle forze dell'ordine. La full-disk encryption protegge un dispositivo spento solo secondo il proprio modello di minaccia dichiarato; un nodo in esecuzione e sbloccato e le chiavi rilasciate in memoria sono casi diversi.

| Invariante | Conseguenza pratica |
|---|---|
| Nessuna identità diretta tra operatore e nodo | L'operatore accede al gateway dell'organizzazione; il nodo ha un'identità del dispositivo diversa |
| Nessun materiale della workstation personale | Nessuna chiave SSH personale, profilo del browser, email, password manager, pairing del telefono o cache della cloud CLI |
| Nessun segreto master del controller | Un nodo non può registrarne un altro, modificare la policy o decrittografare altri engagement |
| Solo traffico in uscita e ristretto | La rete di campo non accetta alcun listener di gestione; il nodo raggiunge solo i servizi di rendezvous/update/time indicati |
| Autorità con durata breve e ambito limitato | Ogni credenziale ha un solo dispositivo, audience, servizio, scadenza e percorso di revoca immediata |
| Dati locali minimi | I risultati vengono trasmessi al controller; le cache sono cifrate, con dimensioni/TTL limitati e non autorevoli |
| La responsabilità del controller sopravvive alla cattura | La mappatura asset-engagement, le approvazioni, gli accessi degli operatori e i comandi vengono archiviati centralmente e sottoposti a controllo degli accessi |
| La perdita interrompe il lavoro | Una scoperta o un cambiamento di stato non spiegato attiva l'arresto, la revoca, la notifica e la conservazione delle prove, non la distruzione remota |

Il baseline IoT di NIST raggruppa l'identificazione del dispositivo, la configurazione, la protezione dei dati, l'accesso logico, l'aggiornamento sicuro del software e la consapevolezza dello stato di cybersecurity come funzionalità fondamentali. Considera specificamente la consapevolezza dello stato e i record degli eventi off-device come supporto alle indagini sui compromessi.<sup>[[1]](#references)</sup>

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
Il gateway deve sapere quale operatore identificato ha raggiunto quale dispositivo identificato. Il field node necessita solo di una device credential per il rendezvous. Non viene mai a conoscenza dell'indirizzo sorgente o del secret di autenticazione dell'operatore, e l'operatore non vi copia mai una private management key. Questo riduce il collegamento personale recuperabile **dal field storage** senza compromettere la responsabilità dell'esercitazione.

Per una flotta più ampia, un sistema di workload identity può emettere identità X.509 a breve durata e ruotare automaticamente le key. SPIFFE raccomanda gli X.509 SVID quando possibile e descrive le durate brevi e la rotazione frequente come misure per limitare l'esposizione dovuta alla compromissione delle key.<sup>[[2]](#references)</sup> Un piccolo team può applicare le stesse proprietà con una CA privata e certificati per dispositivo automatizzati; installare SPIRE non è necessario semplicemente per soddisfare questo pattern.

## Step 1: autorizzare e registrare il posizionamento

1. Registrare il proprietario, il sito, la zona esatta di posizionamento consentita, le reti consentite, la finestra temporale dell'assessment, le destinazioni/azioni consentite e i contatti di emergenza.
2. Registrare modello, numero di serie, numero di serie dello storage, MAC cablati/wireless, IMEI/eSIM del modem o ICCID della SIM, alimentatore e una fotografia aggiornata.
3. Assegnare al dispositivo un engagement identifier non personale, ad esempio `E2026-014-DROP03`. Non inserire il nome del cliente negli hostname o negli SSID trasmessi.
4. Informare il controller dell'esercitazione e il gruppo minimo necessario di physical-security/SOC incaricato della deconfliction su cosa significhino “perso”, “spostato” e “scoperto” per questo test.
5. Concordare in anticipo chi può recuperarlo e come un eventuale ritrovatore può segnalarlo. Un'etichetta di sicurezza può omettere i dettagli sensibili del cliente fornendo al contempo un callback controllato.
6. Impostare una scadenza automatica dell'autorizzazione. La connettività che continua dopo la fine dello scope non deve estendere il permesso.

## Step 2: creare un'immagine minima recuperabile

Utilizzare un'immagine OS supportata, verificarne la firma/checksum attraverso il canale documentato dal vendor, installare gli aggiornamenti di sicurezza e mantenere un manifest di build riproducibile. Preferire una base read-only o immutable con una piccola partizione dati writable, quando il software lo consente.

1. Rimuovere gli account predefiniti, i servizi demo, i compilatori e i pacchetti non necessari al workload autorizzato.
2. Disabilitare la GUI locale, Bluetooth, i protocolli di discovery, il file sharing, Wi-Fi P2P e l'amministrazione inbound, salvo che l'esercitazione ne richieda esplicitamente uno.
3. Abilitare secure boot e measured boot/rilascio delle key basato su TPM se l'hardware li supporta realmente; non affermare che una configurazione Raspberry Pi disponga di measured boot di livello PC senza aver validato il modello esatto.
4. Cifrare lo stato writable locale e configurare una dimensione massima e un tempo di retention rigorosi. La cifratura è un controllo di ritardo/contenimento, non la prova che un nodo in esecuzione non riveli nulla.
5. Inviare i log importanti off-device. Limitare i journal locali per impedire l'esaurimento dello storage, ma non configurare il wiping dei log o la cancellazione anti-forensics.
6. Conservare il manifest dell'immagine, le versioni dei pacchetti, l'hash della configurazione e le istruzioni di recovery presso il controller.
7. Reimaging di uno spare a partire dal manifest ed esecuzione dello stesso health test. Un design che solo il suo builder è in grado di recuperare non è pronto per il field.

## Step 3: emettere identità con trust unidirezionale

Creare tre identità differenti:

- una **device identity**, accettata solo dal rendezvous per questo dispositivo;
- una **operator identity**, accettata dal gateway dell'organizzazione e protetta con MFA phishing-resistant; e
- una **controller/deployment identity**, utilizzata per firmare job o configurazioni approvati, conservata al di fuori sia dell'operatore sia del field node.

Il nodo deve avere la public key necessaria a verificare i job firmati, mai la signing key. Una device credential catturata non deve autenticarsi alle cloud console, ai source repository, agli account di pagamento, ad altri nodi o alla produzione del cliente.

Utilizzare durate brevi dei certificati quando il rinnovo automatico è affidabile. Quando una key WireGuard a lunga durata è necessaria per motivi operativi, trattare la sua public key come revocation handle e limitarla con un tunnel address specifico per peer, una firewall policy e l'autorizzazione del broker. Mantenere un'azione del controller testata che rimuova immediatamente quel peer.

## Step 4: rendezvous outbound stabile

Il seguente pattern in un lab di proprietà fornisce una gestione stabile attraverso NAT senza esporre un servizio inbound. È normale networking WireGuard, non una covert reverse shell. Utilizzare indirizzi di documentazione e sostituirli solo con endpoint di proprietà dell'organizzazione.

Presso il rendezvous dell'organizzazione, assegnare `10.77.0.1/32`; assegnare al field node `10.77.0.20/32`. La peer entry del gateway deve accettare solo il singolo indirizzo del nodo:
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
Il nodo effettua connessioni in uscita verso il rendezvous e mantiene il mapping NAT solo quando necessario:
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
WireGuard documenta 25 secondi come un intervallo di keepalive appropriato per molte implementazioni NAT/firewall quando è necessaria la persistenza; lasciarlo disabilitato è preferibile quando non serve.<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` rende deliberatamente questo un percorso di gestione, non un pivot con default route.

Applicare quindi i controlli al di fuori di WireGuard:

1. Risolvere `vpn.redteam.example` tramite il percorso DNS di bootstrap approvato e fissare l'endpoint dell'organizzazione previsto nei record di deployment.
2. Sul nodo, consentire DHCP/RA in uscita, il DNS/NTP richiesto, l'endpoint di rendezvous e il percorso minimo di aggiornamento approvato. Negare il traffico in ingresso non sollecitato su ogni uplink.
3. Sul rendezvous, consentire a `10.77.0.20` di raggiungere solo il servizio broker/health richiesto dall'esercitazione. Non inoltrarlo genericamente verso una rete client.
4. Porre l'accesso interattivo degli operatori dietro il gateway dell'organizzazione. Evitare di esporre SSH dal nodo attraverso il tunnel se un'interfaccia signed pull-job soddisfa l'assessment.
5. Configurare il service manager per avviare il tunnel dopo la rete, riavviarlo dopo un errore con un backoff limitato e generare un alert dopo errori ripetuti. Un ciclo di riavvio non deve sovraccaricare la sede né nascondere il problema sottostante.
6. Verificare l'ultimo handshake del peer, ma non usare “handshake presente” come prova che il dispositivo non sia compromesso.

TURN può fornire reachability solo tramite relay per un control plane WebRTC realizzato ad hoc, mentre una message queue può tollerare un servizio intermittente. TURN assegna esplicitamente a un client un indirizzo pubblico di relay dietro NAT; il suo server rimane un osservatore.<sup>[[4]](#references)</sup> Scegliere un'unica architettura di controllo invece di sovrapporre tunnel senza un osservatore o un vantaggio di affidabilità dichiarato.

## Step 5: stabilità dell'uplink senza link personali

Per un nodo di sede autorizzato, preferire questo ordine:

1. VLAN cablata o VLAN di test dedicata fornita dal client;
2. profilo Wi-Fi enterprise/guest approvato dal proprietario;
3. fallback cellulare/private APN contrattualizzato dall'organizzazione.

Non configurarlo mai con un hotspot personale del telefono, un SSID domestico, una eSIM personale, un account Apple/Google personale o un profilo Wi-Fi esportato da un laptop usato quotidianamente. Questi sono esattamente gli artifact a cui si collegherà una capture.

Per ogni uplink approvato:

- registrare SSID/BSSID oppure switch/VLAN e il comportamento previsto del captive portal;
- impostare una priorità deterministica e un health check verso un endpoint di proprietà;
- fare in modo che il failover modifichi solo l'underlay; le identità del dispositivo e dell'operatore rimangono presso il broker;
- assicurarsi che DNS, IPv6 e traffico applicativo non bypassino il rendezvous durante la transizione;
- generare un alert per SSID/BSSID sconosciuti, cambio di SIM, nuovo default gateway, cambio di public IP/ASN o uplink simultanei;
- testare perdita di alimentazione, rinnovo DHCP, riavvio dell'AP, cambio di public IP, 24 ore di inattività, perdita del tunnel e recupero primary-to-secondary-to-primary prima del deployment.

L'indirizzamento MAC privato può ridurre il tracking casuale tra reti, ma per un NAC autorizzato è spesso necessario un MAC stabile per rete. Registrare ciò che fa effettivamente l'OS scelto e non ruotare il MAC intorno al controllo degli accessi del proprietario.

## Step 6: limitare attività e dati

Un field node sicuro non dovrebbe accettare testo shell arbitrario da una mailbox. Definire tipi di job firmati come `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` o un'altra azione nominata esplicitamente nelle rules of engagement. Validare nuovamente sul nodo destinazione, durata, rate, dimensione dell'output e scope.

1. Assegnare a ogni job un ID univoco, l'audience del dispositivo, l'ora di emissione, la scadenza, un riferimento allo scope e l'output massimo.
2. Firmarlo con l'identità del controller/deployment.
3. Rifiutare campi sconosciuti, job scaduti o riprodotti e job destinati a un altro dispositivo.
4. Inviare i risultati in streaming a un collector di proprietà; cifrare e applicare un TTL a ogni spool locale inevitabile.
5. Registrare presso il controller l'ID del job accettato/rifiutato e l'hash del risultato. Non inserire parametri sensibili dei comandi in un canale pubblico di monitoring.
6. Interrompere l'elaborazione quando l'autorizzazione scade, la rotazione dell'identità fallisce o il controller mette il dispositivo in quarantena.

## Monitoring per discovery, perdita o compromissione

Il monitoring può comunicare al controller che lo stato osservato è cambiato. Non può dimostrare in modo affidabile che gli “investigatori abbiano trovato il dispositivo”, e tentare di sorvegliare i responder o sondare i loro sistemi supererebbe i limiti di un assessment autorizzato.

### Raccogliere lo stato off-device

Inviare al controller un health record firmato e a basso volume a un intervallo operativo casualizzato ma limitato. Includere solo ciò che serve al controller:

- ID del dispositivo, boot ID/counter e uptime monotono;
- hash della configurazione/immagine e versione del software;
- seriale del certificato del dispositivo e stato del rinnovo;
- classe dell'uplink, interfaccia, BSSID o contesto switch come autorizzato, hash del default gateway e public IP/ASN osservati da un servizio di proprietà;
- età dell'handshake del tunnel, packet counter e profondità della coda;
- stato dell'enclosure switch o dell'hardware-tamper se il proprietario ha approvato il sensore;
- pressione del disco, temperatura, stima del clock offset e ID dell'ultimo job completato con successo;
- un numero di sequenza e una firma per evidenziare replay o lacune.

Archiviare centralmente l'autenticazione del gateway, le decisioni delle policy, l'accesso degli operatori, l'invio dei job, gli hash dei risultati, gli eventi di audit del provider e gli alert. CISA raccomanda di centralizzare i log, proteggerli dalla cancellazione, creare una baseline dell'attività normale e designare i contatti per l'incident response.<sup>[[5]](#references)</sup>

### Indicatori di discovery/compromissione

| Segnale | Possibili spiegazioni | Azione del controller |
|---|---|---|
| Heartbeat assente | errore di alimentazione/rete, cambio del portal, danno, blocco deliberato o rimozione | verificare lo stato del provider/sito; non riconnettersi da un percorso non approvato |
| Boot counter cambiato in modo inatteso | interruzione dell'alimentazione, crash, rimozione o manutenzione | mettere i job in quarantena; confrontare orari ed eventi del sito |
| Hash della configurazione/immagine cambiato | errore di aggiornamento, guasto dello storage o tampering | interrompere il lavoro; revocare se non si tratta di una release approvata dal controller |
| Nuovo uplink/BSSID/gateway/ASN | sostituzione dell'AP, roaming, spostamento del dispositivo o intercettazione | confrontare l'inventario approvato; mettere in quarantena una transizione non spiegata |
| Job/firma rifiutati ripetutamente | corruzione, replay o controller non autorizzato | interrompere l'elaborazione e analizzare i log del gateway/controller |
| Credential del dispositivo utilizzata due volte o da percorsi incompatibili | chiave clonata, riutilizzo di snapshot o transizione di rete | revocare immediatamente; conservare entrambi i record di sessione |
| Login, interfaccia, processo o evento di privilegio locale inatteso | manutenzione o compromissione | isolare tramite la policy del broker; preservare le evidenze |
| Transizione dello stato dell'enclosure switch | assistenza, spostamento o discovery | notificare il contatto del sito indicato; non attivare azioni distruttive |
| Avviso di abuso del provider/query sull'account o alert del SOC | rilevamento, configurazione errata o traffico fuori scope | interrompere l'attività e avviare il processo di deconfliction/incident |
| Sentinel credential utilizzata | qualcuno ha letto un secret decoy senza privilegi, univoco per questo nodo | revocare l'identità reale del dispositivo e preservare la traccia dell'alert |

Una sentinel credential non deve concedere **alcun accesso**, deve chiamare solo un alert service di proprietà dell'organizzazione e deve essere indicata nelle rules of engagement. È un tripwire per la lettura non autorizzata, non un beacon per tracciare chiunque abbia trovato l'apparecchiatura.

### Soglie degli alert

Usare regole stateful, non un unico allarme drammatico di “cattura”:

- **warning:** un intervallo mancato, un normale cambio di indirizzo o crescita della coda;
- **degraded:** tre intervalli consecutivi mancati, ritardo nel rinnovo, perdita dell'uplink primario o riavvio ripetuto;
- **quarantine:** cambio non approvato di hash/boot/uplink, credential duplicata, uso del sentinel o evento privilegiato inatteso;
- **confirmed discovery/loss:** report del sito/controller, mismatch dell'inventario fisico, recupero del dispositivo da parte di una persona non prevista o escalation validata del provider/SOC.

Testare la consegna degli alert tramite un canale indipendente dal field node. Evitare di inviare dettagli sensibili sul client/dispositivo a servizi di messaggistica personali o account consumer per le notifiche push.

## Runbook per suspected discovery o capture

1. **Stop:** sospendere i nuovi job e le sessioni degli operatori. Non inviare una probe per “verificare se si è sotto sorveglianza”.
2. **Quarantine:** configurare il broker affinché neghi l'identità del dispositivo e le relative route, conservando al contempo i log esistenti.
3. **Revoke:** revocare il certificato/chiave del dispositivo, il queue token, la credential di aggiornamento e ogni service token monouso. Sospendere la SIM dell'organizzazione quando la perdita fisica è plausibile.
4. **Preserve:** acquisire snapshot dei record del controller, gateway, provider e alert; registrare l'ora attendibile, chi ha agito e l'ultima configurazione nota. Non cancellare né eseguire un wipe remoto del nodo.
5. **Notify:** contattare il controller dell'esercitazione, il contatto incident del client e i contatti legal/privacy definiti nell'autorizzazione. Se lo ha trovato una terza parte, utilizzare il processo di recupero concordato in precedenza.
6. **Assess:** presumere che ogni secret e risultato in cache sul nodo sia esposto. Elencare esattamente a cosa avrebbe potuto accedere ogni secret e verificare se sia stato utilizzato dopo l'evento sospetto.
7. **Contain downstream:** ruotare le credential dei servizi interessati, invalidare i job in attesa e analizzare i log dei target/provider di proprietà per individuare comportamenti inattesi.
8. **Recover safely:** recuperare il dispositivo solo tramite una persona autorizzata; fotografarlo/confezionarlo, registrare la custody e acquisire le evidenze forensi secondo le indicazioni del client.
9. **Resume with a new identity:** non riabilitare mai silenziosamente la credential catturata. Ricostruire dal manifest noto, correggere il problema di controllo e ottenere un'approvazione esplicita.

Le attuali linee guida NIST sull'incident response integrano preparazione, detection, response e recovery nella gestione del rischio di cybersecurity a livello organizzativo; preservare prima, affinché il client possa determinare cosa sia successo e scegliere la risposta appropriata.<sup>[[6]](#references)</sup>

## Capture drill prima del deployment

Consegnare un'unità di test sbloccata o una copia del suo storage a un reviewer indipendente e chiedergli di elencare:

1. identificativi del dispositivo/sito/engagement;
2. nomi degli operatori, account personali, reti domestiche/workstation e contatti di recovery;
3. destinazioni e credential del controller/broker;
4. profili di rete del client e risultati in cache;
5. altri dispositivi/progetti raggiungibili con ciascun secret;
6. credential di valore o di pagamento;
7. cosa può revocare il controller e con quale rapidità;
8. quale attività rimane attribuibile dai log centrali.

Criteri di superamento: zero account personali/chiavi di workstation; zero autorità cross-engagement o di enrollment; nessuna credential di pagamento; cache cifrata e limitata; un'azione documentata di revoca del dispositivo; accountability completa lato controller. Considerare ogni link personale inatteso o capacità laterale come un blocco al rilascio.

## Chiusura

1. Interrompere i job e disabilitare la route del broker alla fine dello scope.
2. Recuperare e riconciliare l'inventario esatto; segnalare qualsiasi elemento mancante.
3. Preservare log/risultati e, se richiesto, un'immagine forense secondo il retention plan dell'engagement.
4. Revocare le identità del dispositivo, della SIM, della queue, dell'update e dei servizi anche quando l'hardware è stato recuperato.
5. Solo dopo la preservazione/accettazione, sanificare o distruggere i media tramite il processo di data disposal approvato dal proprietario e registrare il completamento. Questa è gestione del ciclo di vita, non concealment.
6. Rimuovere le prenotazioni NAC/DHCP della sede, le route del broker, il DNS, i ruoli cloud, le regole degli alert e i contatti temporanei.
7. Documentare il rilevamento osservato, la telemetry mancante, il tempo necessario per la quarantena e ogni artifact esposto dalla capture.

## References

- [1] [NIST — Catalogo delle capacità di cybersecurity dei dispositivi IoT](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Concetti e workload identity di breve durata](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Guida rapida: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Utilizzare il logging sui sistemi aziendali](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Raccomandazioni e considerazioni sull'Incident Response](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
