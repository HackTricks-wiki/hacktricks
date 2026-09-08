# Comunicazioni e condivisione che preservano la privacy

{{#include ../banners/hacktricks-training.md}}

La crittografia end-to-end protegge il contenuto. Non nasconde automaticamente l'account, il numero di telefono, il grafo dei contatti, l'indirizzo IP, il push token, l'anteprima delle notifiche, la tempistica, i metadati dei file o il comportamento del destinatario. Seleziona uno strumento in base ai metadati che rimuove e agli osservatori che introduce.

## Confronta i modelli di comunicazione

| Strumento/modello | Proprietà utile | Osservatori e limiti rimanenti |
|---|---|---|
| Signal | E2EE matura; gli username possono avviare un contatto senza condividere il numero; sealed sender riduce i metadati del servizio | Il numero di telefono è richiesto per la registrazione; il servizio, il provider push, i contatti e gli endpoint conservano alcune osservazioni |
| SimpleX | Nessun identificatore utente globale; code per contatto; trasporto Tor opzionale | Tempistiche/trasporto del relay, servizio push, inviti ed endpoint; ecosistema più nuovo e ridotto |
| Briar | Sincronizzazione diretta; Tor online; Bluetooth/Wi-Fi offline; nessun archivio centrale dei messaggi | Contatti ed endpoint; osservatori delle radio locali; orientato ad Android; entrambe le parti devono essere disponibili o usare Mailbox |
| OnionShare | File/ricezione/chat/sito diretto tramite un servizio onion temporaneo; nessun provider di storage | Il computer del mittente è il servizio; chi possiede il link apprende l'accesso; tempistiche ed endpoint rimangono |
| File crittografato con `age` | Crittografia semplice con la chiave del destinatario, indipendente dal trasporto | Il trasporto vede mittente/destinatario/tempistiche/dimensione; nomi dei file/metadati dell'archivio ed endpoint rimangono |
| Email ordinaria + TLS | Crittografia del canale server-to-server | Entrambi i provider email possono normalmente leggere il contenuto e conservare i metadati di routing/account |

## Signal: contatto privato senza divulgare il numero

Gli username di Signal possono avviare una chat senza rivelare il numero di telefono dell'utente al nuovo contatto, ma per la registrazione è comunque necessario un numero di telefono.<sup>[[1]](#references)</sup> Sealed sender è una protezione incrementale dei metadati, non una resistenza a ogni correlazione di IP/tempistiche.<sup>[[2]](#references)</sup>

### Workflow

1. Installa Signal dall'app store/progetto ufficiale e aggiorna prima il sistema operativo.
2. Registrati con un numero che sei legalmente autorizzato a usare. Non utilizzare attivazioni SMS a noleggio, il numero di un'altra persona o un account del provider ottenuto con un'identità falsa.
3. In **Impostazioni → Privacy → Numero di telefono**, imposta chi può vedere il numero e chi può trovare l'account tramite il numero in base al threat model.
4. Crea uno username per la ricerca di nuovi contatti. Condividi il suo link/QR esatto tramite un canale già autenticato; gli username possono cambiare e non corrispondono al nome del profilo.
5. Disabilita il caricamento dei contatti/le autorizzazioni se la comodità non vale il collegamento, e aggiungi manualmente i contatti dove la piattaforma lo supporta.
6. Apri i dettagli del contatto e confronta il safety number/QR tramite un secondo canale o di persona prima di inviare contenuti sensibili.
7. Esamina i dispositivi collegati, il registration lock/PIN, le anteprime delle notifiche, la sicurezza dello schermo, il call relaying, i valori predefiniti dei messaggi a scomparsa e il comportamento dei backup.
8. Invia un messaggio di test non sensibile ed effettua una chiamata. Controlla le tracce sulla schermata di blocco, sul desktop, sui dispositivi wearable e nelle notifiche cloud da entrambe le parti.
9. Considera un safety number modificato o un dispositivo collegato inatteso come un evento da investigare, non come un avviso da ignorare automaticamente.

Non associare una foto profilo pseudonima, una bio, l'appartenenza a gruppi o una pianificazione a un contesto Signal identificativo.

## SimpleX: connessioni per contatto senza un identificatore globale

SimpleX instrada i messaggi tramite code unidirezionali e non assegna un identificatore utente valido sull'intera rete. La sua policy documenta comunque le sessioni di trasporto, i dati temporanei del server, i compromessi delle notifiche push e la responsabilità dell'endpoint.<sup>[[3]](#references)</sup>

### Workflow

1. Scarica un client mantenuto dal progetto/store ufficiale e verifica l'editore. Usa un profilo OS/app dedicato quando le identità non devono essere mescolate.
2. Crea un profilo **locale** con un nome visualizzato e un'immagine specifici per il contesto. Eliminare l'app senza un backup può far perdere il profilo e le connessioni.
3. Al primo avvio, scegli deliberatamente la modalità delle notifiche. Le notifiche push mobili istantanee possono esporre ulteriori metadati all'infrastruttura Apple/Google.
4. Crea un link di invito monouso per un contatto. Trasferiscilo tramite un canale autenticato; chiunque ottenga un invito attivo potrebbe tentare di utilizzarlo.
5. Dopo la connessione, apri i dettagli del contatto e confronta il codice di sicurezza di persona o tramite un canale indipendente verificato.<sup>[[4]](#references)</sup>
6. Usa un profilo incognito per gruppo, se supportato, invece di riutilizzare lo stesso profilo in gruppi non correlati.
7. Configura il trasporto Tor supportato dal client se la rete/server locale non deve vedere l'IP diretto. Conferma la connessione dopo la modifica; non forzare un proxy di sistema non supportato.
8. Esamina ricevute di consegna, anteprime dei link, chiamate, download automatici ed esportazione/backup del database. Ognuno modifica i metadati o l'esposizione dell'endpoint.
9. Testa il ripristino su un dispositivo isolato di riserva senza eseguire uno stato duplicato del profilo attivo; il progetto avverte che copie concorrenti possono interrompere le conversazioni.

L'assenza di un identificatore globale non impedisce a un contatto di identificare l'utente tramite il contenuto, il riutilizzo del profilo, la consegna dell'invito, le tempistiche o il grafo sociale.

## Briar: messaggistica diretta e resistente alle interruzioni

Briar sincronizza direttamente tra i dispositivi, tramite Tor quando è online e tramite Bluetooth/Wi-Fi durante le interruzioni locali. Il threat model ufficiale presuppone solo un monitoraggio avversario limitato delle radio a corto raggio, quindi le reti wireless locali non sono invisibili.<sup>[[5]](#references)</sup>

### Workflow

1. Installa dalla distribuzione ufficiale di Briar e verifica la fonte del pacchetto. Usa un dispositivo Android supportato con aggiornamenti di sicurezza recenti.
2. Crea un account locale con un nickname contestuale univoco e una password robusta. Non esiste una procedura di reimpostazione della password; verifica di poter recuperare il segreto di sblocco.
3. Aggiungi i contatti di persona scansionando i rispettivi codici QR, quando possibile. Questo autentica il contatto ed evita di inviare un link tramite un canale correlabile.
4. Nelle impostazioni di connettività, abilita solo i trasporti necessari: Tor/Internet, Wi-Fi e/o Bluetooth. Disabilita le radio locali quando non sono necessarie.
5. Per la consegna asincrona, valuta Briar Mailbox su un dispositivo dedicato e alimentato; censiscilo e proteggilo fisicamente come un message server.
6. Invia un test benigno mentre Internet è disponibile, quindi testa il percorso previsto durante un'interruzione con Internet disabilitato in un luogo autorizzato dal proprietario.
7. Controlla i backup Android, le anteprime delle notifiche, gli screenshot e i contenuti esportati. Lo storage locale crittografato è esposto quando l'endpoint è sbloccato/compromesso.
8. Rimuovi i contatti/dispositivi persi e dismetti l'intero contesto se la custodia fisica o la password dell'account sono compromesse.

## OnionShare: trasferimento diretto temporaneo

OnionShare esegue un servizio onion sul computer del mittente/ricevente; i file non vengono caricati su un provider di storage e il traffico è crittografato end-to-end all'interno di Tor.<sup>[[6]](#references)</sup> L'URL onion completo è una bearer capability e deve essere protetto.

### Workflow di condivisione file tramite GUI

1. Installa OnionShare dalla sua distribuzione ufficiale firmata e Tor Browser sul lato del destinatario.
2. Inserisci **copie sanificate** dei file in una directory di staging dedicata. Non indicare a OnionShare una directory home personale.
3. Apri **Condividi file**, aggiungi solo i file preparati, lascia abilitata la protezione con chiave privata/accesso e mantieni abilitata l'opzione **Interrompi la condivisione dopo l'invio dei file** per un singolo destinatario.
4. Avvia la condivisione e invia l'URL onion completo tramite un canale E2EE già autenticato. Non incollarlo in email, issue tracker o chat pubbliche.
5. Il destinatario apre l'URL in Tor Browser, verifica con il mittente i nomi/dimensioni dei file previsti e scarica.
6. Entrambe le parti confrontano un digest SHA-256 concordato in precedenza o consegnato separatamente per verificare l'integrità quando il file stesso costituisce il confine di sicurezza.
7. Conferma che OnionShare si sia arrestato dopo il download; altrimenti arrestalo manualmente e chiudi l'applicazione.
8. Elimina la copia di staging secondo la policy di conservazione e controlla le impostazioni della cronologia/dei log di OnionShare per individuare eventuali divulgazioni indesiderate dei nomi dei file.

### Workflow CLI

La CLI ufficiale accetta i file come argomenti posizionali e si arresta dopo la singola condivisione completata predefinita. Su un host con la CLI ufficiale/Tor installati:
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
Fornisci l'URL completo risultante in modo sicuro. Non aggiungere `--public`, `--no-autostop-sharing`, il logging dettagliato dei nomi dei file o la persistenza, a meno che il modello di minaccia non richieda esplicitamente l'esposizione risultante.<sup>[[7]](#references)</sup>

Tratta i documenti ricevuti come ostili. Aprili in una VM usa-e-getta/con un renderer in stile Dangerzone anziché sull'host associato all'identità.

## Crittografa un file indipendentemente con `age`

La crittografia indipendente dal trasporto è utile quando un provider di storage/email potrebbe vedere l'oggetto. Non nasconde il mittente, il destinatario, la dimensione, la tempistica o il nome del file, a meno che questi aspetti non vengano gestiti separatamente.

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
Il destinatario esegue la decifratura in un nuovo percorso:
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
La CLI ufficiale avvisa che `-o` sovrascrive un output esistente, quindi usa una nuova directory e verifica il digest/contenuto prima di spostarlo.<sup>[[8]](#references)</sup> Non inviare mai il file di identità insieme al ciphertext.

## Pipeline riproducibile di sanitizzazione dei file

La rimozione dei metadati è specifica per formato. Conserva un originale cifrato quando l'autenticità, la computer forensics o la catena di custodia sono importanti; opera su una copia.

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
Questa procedura segue le indicazioni più sicure di ExifTool per i JPEG: rimuovere ciecamente ogni tag può eliminare anche le informazioni sul colore.<sup>[[9]](#references)</sup> Esamina quindi visivamente i pixel alla ricerca di volti, riflessi, schermi, punti di riferimento e pattern unici di danni/rumore.

### Flusso di lavoro Office/PDF

1. Mantieni l'originale modificabile crittografato e offline rispetto al contesto di pubblicazione.
2. Rimuovi commenti, modifiche rilevate, diapositive/fogli nascosti, file incorporati, modelli personali e proprietà del documento nell'applicazione di authoring.
3. Esporta un nuovo PDF da un profilo pulito dedicato; non “stampare” su una stampante cloud.
4. Esamina il documento con strumenti consapevoli del formato e con un renderer visivo usa-e-getta:
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. Cerca nell'output renderizzato nomi, percorsi, indirizzi email e testo delle revisioni. La rasterizzazione può rimuovere le strutture attive, ma compromette accessibilità/ricerca e non rimuove i contenuti visibili né lo stile di scrittura.
6. Calcola l'hash dell'artefatto finale e trasferisci **solo** quella copia attraverso il compartimento di pubblicazione.

## Privacy Pass: autorizzazione anonima per i progettisti di servizi

Privacy Pass separa l'**emissione** dei token dal loro **riscatto**. Un'origine può sapere che un client possiede un token approvato dall'issuer senza conoscere la specifica interazione di emissione del client. Il riutilizzo di un token, i metadati univoci, il timing o la collusione possono reintrodurre la linkability.<sup>[[10]](#references)</sup>

Pattern di deployment sicuro:

1. Definisci l'affermazione dimostrata dal token (per esempio, l'idoneità al rate-limit), non un'identità globale nascosta.
2. Usa l'architettura e i protocolli di emissione standardizzati; non implementare la crittografia delle blind signature da zero.
3. Separa l'amministrazione di issuer/attester e origine quando la proprietà desiderata lo richiede.
4. Riduci al minimo i metadati pubblici/privati dei token e assicurati che gli anonymity set siano sufficientemente grandi.
5. Emetti batch prima dell'uso, quando supportato, così il momento dell'emissione non corrisponde banalmente a quello del riscatto.
6. Riscatta ogni token una sola volta, valida la challenge associata all'origine ed elimina lo stato dei token scaduti.
7. Impedisci che cookie, logging degli IP e account applicativi compromettano silenziosamente la proprietà di privacy del token.
8. Verifica se i log dell'issuer e dell'origine possono correlare un evento controllato di emissione e riscatto usando timing, metadati o errori univoci.

Privacy Pass è una funzionalità dell'applicazione, non qualcosa che un utente può aggiungere a un account arbitrario.

## Checklist per la verifica delle comunicazioni

- [ ] Il contatto/invito/chiave è stato autenticato in modo indipendente.
- [ ] L'esposizione di numero di telefono, username, profilo, gruppo e caricamento dei contatti è stata compresa.
- [ ] Sono elencati gli osservatori diretti dell'IP, relay, Tor, push provider e radio locali.
- [ ] Sono state testate le anteprime delle notifiche, i wearable, i desktop collegati e i backup.
- [ ] I file sono stati sanitizzati, cifrati se necessario e aperti in un contesto disposable.
- [ ] Il recupero funziona senza collegare identità non correlate.
- [ ] Log, cronologia e servizi temporanei di condivisione hanno una regola di arresto/conservazione.

## References

- [1] [Signal — Privacy dei numeri di telefono e username](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Informativa sulla privacy e condizioni d'uso](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Guida a privacy e sicurezza](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — Come funziona](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Progettazione della sicurezza](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Uso avanzato e CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — CLI e utilizzo ufficiali](https://github.com/FiloSottile/age)
- [9] [FAQ di ExifTool — Rimozione sicura dei metadati](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Architettura di Privacy Pass](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
{{#include ../banners/hacktricks-training.md}}
