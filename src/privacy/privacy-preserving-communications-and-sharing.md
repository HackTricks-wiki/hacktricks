# Comunicazioni e condivisione con tutela della privacy

La crittografia end-to-end protegge il contenuto. Non nasconde automaticamente l'account, il numero di telefono, la rete dei contatti, l'indirizzo IP, il push token, l'anteprima delle notifiche, la tempistica, i metadati dei file o il comportamento del destinatario. Seleziona uno strumento in base ai metadati che rimuove e agli osservatori che introduce.

## Confronta i modelli di comunicazione

| Strumento/modello | Proprietà utile | Osservatori e limiti rimanenti |
|---|---|---|
| Signal | E2EE matura; gli username possono avviare un contatto senza condividere il numero; sealed sender riduce i metadati del servizio | Il numero di telefono è necessario per la registrazione; il servizio, il push provider, i contatti e gli endpoint conservano alcune osservazioni |
| SimpleX | Nessun identificatore utente globale; code per contatto; trasporto Tor opzionale | Tempistiche/trasporto del relay, servizio push, inviti ed endpoint; ecosistema più nuovo e ridotto |
| Briar | Sincronizzazione diretta; Tor online; Bluetooth/Wi-Fi offline; nessun message store centrale | Contatti ed endpoint; osservatori delle radio locali; incentrato su Android; entrambi i lati devono essere disponibili o usare Mailbox |
| OnionShare | File/receive/chat/site diretti tramite un servizio onion temporaneo; nessun provider di storage | Il computer del mittente è il servizio; chi possiede il link apprende l'accesso; tempistiche ed endpoint rimangono |
| File cifrato con `age` | Crittografia semplice con la chiave del destinatario, indipendente dal trasporto | Il trasporto vede mittente/destinatario/tempistiche/dimensioni; nomi dei file/metadati degli archivi ed endpoint rimangono |
| Email ordinaria + TLS | Crittografia del canale server-to-server | Entrambi i mail provider possono normalmente leggere il contenuto e conservare i metadati di routing/account |

## Signal: contatto privato senza divulgare il numero

Gli username di Signal possono avviare una chat senza rivelare il numero di telefono dell'utente al nuovo contatto, ma per la registrazione è comunque necessario un numero di telefono.<sup>[[1]](#references)</sup> Sealed sender è una protezione incrementale dei metadati, non una protezione contro ogni correlazione di IP/tempistiche.<sup>[[2]](#references)</sup>

### Workflow

1. Installa Signal dall'app store/progetto ufficiale e aggiorna prima il sistema operativo.
2. Registrati con un numero che sei legalmente autorizzato a utilizzare. Non usare attivazioni SMS a noleggio, il numero di un'altra persona o un account di un provider ottenuto con un'identità falsa.
3. In **Impostazioni → Privacy → Numero di telefono**, imposta chi può vedere il numero e chi può trovare l'account tramite il numero in base al threat model.
4. Crea uno username per trovare nuovi contatti. Condividi il suo link/QR esatto tramite un canale già autenticato; gli username possono cambiare e non sono il nome del profilo.
5. Disabilita il caricamento dei contatti/permessi se la comodità non vale il collegamento e aggiungi manualmente i contatti dove la piattaforma lo consente.
6. Apri i dettagli del contatto e confronta il safety number/QR tramite un secondo canale o di persona prima di inviare contenuti sensibili.
7. Esamina i dispositivi collegati, il registration lock/PIN, le anteprime delle notifiche, la sicurezza dello schermo, il call relaying, le impostazioni predefinite dei messaggi a scomparsa e il comportamento dei backup.
8. Invia un messaggio di test non sensibile ed effettua una chiamata. Controlla le tracce nella schermata di blocco, sul desktop, sui dispositivi wearable e nelle notifiche cloud su entrambi i lati.
9. Considera un safety number cambiato o un dispositivo collegato imprevisto come un evento da esaminare, non come un avviso da ignorare automaticamente.

Non associare una foto profilo pseudonima, una bio, l'appartenenza a gruppi o gli orari abituali a un contesto Signal identificativo.

## SimpleX: connessioni per contatto senza un identificatore globale

SimpleX instrada i messaggi tramite code unidirezionali e non assegna un identificatore utente valido sull'intera rete. La sua policy documenta comunque le sessioni di trasporto, i dati temporanei dei server, i compromessi delle push notification e la responsabilità dell'endpoint.<sup>[[3]](#references)</sup>

### Workflow

1. Scarica un client mantenuto dal progetto/store ufficiale e verifica il publisher. Usa un profilo OS/app dedicato quando le identità non devono essere mescolate.
2. Crea un profilo **locale** con un nome visualizzato e un'immagine specifici per il contesto. Eliminare l'app senza un backup può causare la perdita del profilo e delle connessioni.
3. Al primo avvio, scegli deliberatamente la modalità delle notifiche. Le push mobile istantanee possono esporre metadati aggiuntivi all'infrastruttura Apple/Google.
4. Crea un link di invito monouso per un contatto. Trasferiscilo tramite un canale autenticato; chiunque ottenga un invito attivo può tentare di usarlo.
5. Dopo la connessione, apri i dettagli del contatto e confronta il security code di persona o tramite un canale indipendente verificato.<sup>[[4]](#references)</sup>
6. Usa un profilo incognito per gruppo, se supportato, invece di riutilizzare lo stesso profilo in gruppi non correlati.
7. Configura il trasporto Tor supportato dal client se la rete/server locale non deve vedere l'IP diretto. Conferma la connessione dopo la modifica; non forzare un system proxy non supportato.
8. Esamina le ricevute di consegna, le anteprime dei link, le chiamate, i download automatici e l'esportazione/il backup del database. Ognuno modifica l'esposizione dei metadati o dell'endpoint.
9. Prova il recupero su un dispositivo secondario isolato senza eseguire uno stato duplicato del profilo live; il progetto avverte che copie simultanee possono interrompere le conversazioni.

L'assenza di un identificatore globale non impedisce a un contatto di identificare l'utente tramite il contenuto, il riutilizzo del profilo, la consegna dell'invito, le tempistiche o la rete sociale.

## Briar: messaggistica diretta e resistente alle interruzioni

Briar sincronizza direttamente tra i dispositivi, tramite Tor quando è online e tramite Bluetooth/Wi-Fi durante le interruzioni locali. Il threat model ufficiale presuppone solo un monitoraggio avversario limitato delle radio a corto raggio, quindi le comunicazioni wireless locali non sono invisibili.<sup>[[5]](#references)</sup>

### Workflow

1. Installa dalla distribuzione ufficiale di Briar e verifica la fonte del pacchetto. Usa un dispositivo Android supportato con aggiornamenti di sicurezza correnti.
2. Crea un account locale con un nickname specifico per il contesto e una password robusta. Non esiste una procedura di reimpostazione della password; verifica che il segreto di sblocco possa essere recuperato.
3. Aggiungi i contatti di persona scansionando, quando possibile, i rispettivi codici QR. Questa procedura autentica il contatto ed evita di inviare un link tramite un canale correlabile.
4. Nelle impostazioni di connettività, abilita solo i trasporti necessari: Tor/Internet, Wi-Fi e/o Bluetooth. Disabilita le radio locali quando non sono necessarie.
5. Per la consegna asincrona, valuta Briar Mailbox su un dispositivo dedicato e alimentato; inventarialo e proteggilo fisicamente come un message server.
6. Invia un test non sensibile mentre Internet è disponibile, quindi prova il percorso previsto durante un'interruzione con Internet disabilitato in un luogo autorizzato dal proprietario.
7. Esamina i backup Android, le anteprime delle notifiche, gli screenshot e i contenuti esportati. Lo storage locale cifrato è esposto quando l'endpoint viene sbloccato o compromesso.
8. Rimuovi i contatti/dispositivi persi e dismetti l'intero contesto se la custodia fisica o la password dell'account sono compromesse.

## OnionShare: trasferimento diretto temporaneo

OnionShare esegue un servizio onion sul computer del mittente/destinatario; i file non vengono caricati su un provider di storage e il traffico è cifrato end-to-end all'interno di Tor.<sup>[[6]](#references)</sup> L'URL onion completo è una bearer capability e deve essere protetto.

### Workflow GUI per la condivisione di file

1. Installa OnionShare dalla sua distribuzione ufficiale firmata e Tor Browser sul lato del destinatario.
2. Inserisci **copie sanificate** dei file in una directory di staging dedicata. Non indicare a OnionShare una directory home personale.
3. Apri **Share Files**, aggiungi solo i file preparati, lascia abilitata la protezione con chiave privata/accesso e mantieni abilitato **Stop sharing after files have been sent** per un destinatario.
4. Avvia la condivisione e invia l'URL onion completo tramite un canale E2EE già autenticato. Non incollarlo in email, issue tracker o chat pubbliche.
5. Il destinatario apre l'URL in Tor Browser, verifica con il mittente i nomi/dimensioni previsti dei file ed effettua il download.
6. Entrambi i lati confrontano un digest SHA-256 concordato in precedenza o consegnato separatamente per verificare l'integrità quando il file stesso costituisce il confine di sicurezza.
7. Conferma che OnionShare si sia arrestato dopo il download; altrimenti arrestalo manualmente e chiudi l'applicazione.
8. Elimina la copia nella directory di staging secondo la retention policy ed esamina le impostazioni della cronologia/dei log di OnionShare per individuare eventuali divulgazioni involontarie dei nomi dei file.

### Workflow CLI

La CLI ufficiale accetta i file come argomenti posizionali e si arresta dopo la singola condivisione completata predefinita. Su un host con la CLI ufficiale/Tor installati:
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
Fornisci l'URL completo risultante in modo sicuro. Non aggiungere `--public`, `--no-autostop-sharing`, il logging dettagliato dei nomi dei file o la persistenza, a meno che il threat model non richieda esplicitamente l'esposizione risultante.<sup>[[7]](#references)</sup>

Considera i documenti ricevuti come ostili. Aprili in una VM usa-e-getta/con un renderer in stile Dangerzone, anziché sull'host associato all'identità.

## Cifrare un file in modo indipendente con `age`

La cifratura indipendente dal trasporto è utile quando un provider di storage/email può vedere l'oggetto. Non nasconde il mittente, il destinatario, la dimensione, la tempistica o il nome del file, a meno che questi aspetti non vengano gestiti separatamente.

### Configurazione del destinatario
```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```
Autentica la stringa del destinatario pubblico tramite un secondo canale. Il mittente esegue quindi:
```bash
age -R recipient-public.txt -o package.tar.age package.tar
```
Il destinatario decritta in un nuovo percorso:
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
La CLI ufficiale avvisa che `-o` sovrascrive un output esistente, quindi usa una nuova directory e verifica il digest/contenuto prima di spostarlo.<sup>[[8]](#references)</sup> Non inviare mai il file di identità insieme al ciphertext.

## Pipeline riproducibile di sanitizzazione dei file

La rimozione dei metadati dipende dal formato. Conserva un originale crittografato quando l'autenticità, la forensics o la catena di custodia sono importanti; opera su una copia.

### Esempio JPEG
```bash
mkdir -p ./clean

# Inventory embedded metadata
exiftool -a -u -g1 ./original/photo.jpg

# Write a new JPEG while retaining color-profile/color-space information
exiftool -all= --icc_profile:all -tagsfromfile @ -colorspacetags \
-o ./clean/photo.jpg ./original/photo.jpg

# Re-inspect the output
exiftool -a -u -g1 ./clean/photo.jpg
```
Questa procedura segue le indicazioni più sicure di ExifTool per i JPEG: rimuovere ciecamente ogni tag può eliminare anche le informazioni sul colore.<sup>[[9]](#references)</sup> Esamina quindi visivamente i pixel alla ricerca di volti, riflessi, schermi, punti di riferimento e pattern univoci di danni/rumore.

### Flusso di lavoro Office/PDF

1. Mantieni l'originale modificabile crittografato e offline rispetto al contesto di pubblicazione.
2. Rimuovi commenti, modifiche rilevate, diapositive/fogli nascosti, file incorporati, modelli personali e proprietà del documento nell'applicazione di authoring.
3. Esporta un nuovo PDF da un profilo pulito dedicato; non “stampare” su una cloud printer.
4. Esamina il file con strumenti consapevoli del formato e con un renderizzatore visivo usa-e-getta:
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. Cerca nell'output renderizzato nomi, percorsi, indirizzi email e testo delle revisioni. La rasterizzazione può rimuovere le strutture attive, ma compromette accessibilità/ricerca e non rimuove il contenuto visibile né lo stile di scrittura.
6. Calcola l'hash dell'artefatto finale e trasferisci **solo** quella copia attraverso il compartimento di pubblicazione.

## Privacy Pass: autorizzazione anonima per i service designer

Privacy Pass separa l'**emissione** dei token dal loro **riscatto**. Un origin può sapere che un client possiede un token approvato dall'issuer senza conoscere l'interazione specifica del client durante l'emissione. Il riutilizzo di un token, i metadati univoci, il timing o la collusione possono reintrodurre la linkability.<sup>[[10]](#references)</sup>

Pattern di deployment sicuro:

1. Definisci l'affermazione dimostrata dal token (per esempio, l'idoneità al rate limit), non un'identità globale nascosta.
2. Usa l'architettura e i protocolli di emissione standardizzati; non implementare la crittografia blind-signature da zero.
3. Separa l'amministrazione dell'issuer/attester da quella dell'origin quando la proprietà desiderata lo richiede.
4. Riduci al minimo i metadati pubblici/privati dei token e assicurati che gli anonymity set siano sufficientemente grandi.
5. Emetti batch prima dell'uso quando supportato, in modo che il tempo di emissione non corrisponda banalmente al tempo di riscatto.
6. Riscatta ogni token una sola volta, valida la challenge associata all'origin ed elimina lo stato dei token scaduti.
7. Impedisci che cookie, logging degli IP e account applicativi neutralizzino silenziosamente la proprietà di privacy del token.
8. Verifica se i log dell'issuer e dell'origin possono correlare un evento controllato di emissione e riscatto usando timing, metadati o errori univoci.

Privacy Pass è una funzionalità dell'applicazione, non qualcosa che un utente può aggiungere a un account arbitrario.

## Checklist per la verifica delle comunicazioni

- [ ] Il contatto/invito/chiave è stato autenticato in modo indipendente.
- [ ] L'esposizione del numero di telefono, username, profilo, gruppo e caricamento dei contatti è stata compresa.
- [ ] Sono elencati gli osservatori diretti dell'IP, dei relay, di Tor, del push provider e delle comunicazioni radio locali.
- [ ] Sono state testate le anteprime delle notifiche, i dispositivi indossabili, i desktop collegati e i backup.
- [ ] I file sono stati sanificati, cifrati se necessario e aperti in un contesto disposable.
- [ ] Il recupero funziona senza collegare identità non correlate.
- [ ] Log, cronologia e servizi temporanei di condivisione hanno una regola di arresto/conservazione.

## References

- [1] [Signal — Privacy del numero di telefono e username](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Informativa sulla privacy e condizioni d'uso](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Guida alla privacy e alla sicurezza](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — Come funziona](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Progettazione della sicurezza](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Uso avanzato e CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — CLI e utilizzo ufficiali](https://github.com/FiloSottile/age)
- [9] [FAQ di ExifTool — Rimozione sicura dei metadati](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Architettura di Privacy Pass](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
