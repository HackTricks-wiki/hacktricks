# Forensics dei backup iOS (triage incentrato sulla messaggistica)

Questa pagina descrive procedure pratiche per ricostruire e analizzare i backup iOS alla ricerca di segnali di distribuzione di 0-click exploit tramite allegati di app di messaggistica. Si concentra sulla conversione del layout con hash dei backup Apple in percorsi leggibili, quindi sull'enumerazione e la scansione degli allegati nelle app più comuni.

Obiettivi:
- Ricostruire percorsi leggibili da Manifest.db
- Enumerare i database delle app di messaggistica (iMessage, WhatsApp, Signal, Telegram, Viber)
- Risolvere i percorsi degli allegati, estrarre gli oggetti incorporati dove supportato (PDF/Immagini/Font) e passarli agli structural detector


## Ricostruzione di un backup iOS

I backup archiviati in MobileSync utilizzano nomi di file con hash che non sono leggibili. Il database SQLite Manifest.db associa ogni oggetto archiviato al relativo percorso logico.<sup>[[1]](#references)[[2]](#references)</sup>

Procedura generale:
1) Aprire Manifest.db e leggere i record dei file (domain, relativePath, flags, fileID/hash)
2) Ricreare la gerarchia delle cartelle originale sulla base di domain + relativePath
3) Copiare o creare un hardlink per ogni oggetto archiviato nel percorso ricostruito

Esempio di workflow con uno strumento che implementa il processo end-to-end (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Note:
- Decrittografare i backup cifrati prima di passarli a uno strumento di ricostruzione; ElegantBouncer si aspetta un backup decrittografato.<sup>[[2]](#references)[[3]](#references)</sup>
- Quando possibile, preservare i timestamp/ACL originali per il loro valore probatorio

### Acquisizione e decrittografia del backup (USB / Finder / libimobiledevice)

- In Finder/Apple Devices/iTunes, abilitare "Encrypt local backup" e creare un nuovo backup; i backup cifrati possono includere password salvate e dati Health che i backup non cifrati omettono.<sup>[[8]](#references)</sup>
- Cross-platform: libimobiledevice 1.4.0 include correzioni per `idevicebackup2`.<sup>[[4]](#references)</sup> Abilitare interattivamente la cifratura, quindi forzare un backup completo usando l'ordine dei comandi documentato, con la directory di destinazione per ultima.<sup>[[6]](#references)</sup>
```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```
### Triage guidato dagli IOC con MVT

Il Mobile Verification Toolkit di Amnesty può estrarre una chiave da e decrittografare i backup iTunes/Finder crittografati, quindi analizzare il backup decrittografato con un file IOC STIX2.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```
Con `-o`, i risultati JSON vengono scritti in `/tmp/mvt-results/`; le corrispondenze IOC usano il suffisso `_detected` e possono essere correlate con i percorsi degli allegati recuperati di seguito.<sup>[[3]](#references)</sup>

### Analisi generale degli artefatti (iLEAPP)

Per informazioni temporali/metadati oltre alla messaggistica, esegui iLEAPP sulla cartella del backup grezzo; il suo tipo di input `itunes` accetta backup di iTunes/Finder e le versioni attuali supportano iOS/iPadOS dalla versione 11 fino alle versioni attuali.<sup>[[7]](#references)</sup>
```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```
## Enumerazione degli allegati delle app di messaggistica

Dopo la ricostruzione, enumera gli allegati delle app più diffuse. Lo schema esatto varia in base all'app/versione, ma l'approccio è simile: esegui una query sul database di messaggistica, collega i messaggi agli allegati e risolvi i percorsi sul disco.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Tabelle principali: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ).<sup>[[2]](#references)</sup>

Esempi di query:
```sql
-- List attachments with basic message linkage
SELECT
m.ROWID            AS message_rowid,
a.ROWID            AS attachment_rowid,
a.filename         AS attachment_path,
m.handle_id,
m.date,
m.is_from_me
FROM message m
JOIN message_attachment_join maj ON maj.message_id = m.ROWID
JOIN attachment a ON a.ROWID = maj.attachment_id
ORDER BY m.date DESC;

-- Include chat names via chat_message_join
SELECT
c.display_name,
a.filename AS attachment_path,
m.date
FROM chat c
JOIN chat_message_join cmj ON cmj.chat_id = c.ROWID
JOIN message m ON m.ROWID = cmj.message_id
JOIN message_attachment_join maj ON maj.message_id = m.ROWID
JOIN attachment a ON a.ROWID = maj.attachment_id
ORDER BY m.date DESC;
```
I percorsi degli allegati possono essere assoluti o relativi all'albero ricostruito in Library/SMS/Attachments.<sup>[[2]](#references)</sup>

### WhatsApp (ChatStorage.sqlite)
Collegamento comune: tabella dei messaggi ↔ tabella dei media/allegati (la denominazione varia in base alla versione). Eseguire una query sulle righe dei media per ottenere i percorsi su disco. Belkasoft identifica `ZMEDIALOCALPATH` in `ZWAMEDIAITEM` come posizione del file multimediale; l'implementazione attuale di ElegantBouncer collega `ZWAMEDIAITEM.ZMESSAGE` a `ZWAMESSAGE.Z_PK` e antepone `Message/` durante la risoluzione di un percorso che inizia con `Media/`.<sup>[[9]](#references)[[10]](#references)</sup>
```sql
SELECT
m.Z_PK                 AS message_pk,
mi.ZMEDIALOCALPATH     AS media_path,
datetime(m.ZMESSAGEDATE + 978307200, 'unixepoch') AS message_date,
CASE m.ZISFROMME WHEN 1 THEN 'outgoing' ELSE 'incoming' END AS direction
FROM ZWAMEDIAITEM mi
JOIN ZWAMESSAGE m ON mi.ZMESSAGE = m.Z_PK
WHERE mi.ZMEDIALOCALPATH IS NOT NULL
ORDER BY m.ZMESSAGEDATE DESC;
```
Per quel percorso di ricostruzione di ElegantBouncer, un percorso media che inizia con `Media/` viene risolto sotto `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/`; la guida di Belkasoft documenta invece un percorso `Messages/Media/`, quindi ispeziona il backup prima di dare per scontata una delle due grafie.<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal: il message DB è encrypted; tuttavia, gli allegati memorizzati nella cache su disco (e le thumbnail) sono generalmente scansionabili.<sup>[[2]](#references)</sup>
- Telegram: ispeziona le directory media/cache dell'app; Telegram ha documentato un bug di pulizia della cache nell'app iOS 11.2 su iOS 18.0.1, indicato come risolto nella 11.3, quindi verifica la presenza di file residui.<sup>[[2]](#references)[[5]](#references)</sup>
- Viber: Viber.sqlite contiene tabelle di messaggi/allegati con riferimenti su disco.<sup>[[2]](#references)</sup>

Suggerimento: anche quando i metadata sono encrypted, la scansione delle directory media/cache può comunque far emergere oggetti malicious.<sup>[[2]](#references)</sup>


## Scansione degli allegati alla ricerca di exploit strutturali

Una volta ottenuti i percorsi degli allegati, passali a structural detectors che convalidano gli invarianti del file format anziché le signatures. Esempio con ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Rilevamenti coperti dalle regole strutturali includono:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): stati impossibili dei dizionari JBIG2
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): costruzioni di tabelle Huffman sovradimensionate
- TrueType TRIANGULATION (CVE‑2023‑41990): opcode bytecode non documentati
- DNG/TIFF CVE‑2025‑43300: discrepanze tra metadati e componenti dello stream


## Validazione, avvertenze e falsi positivi

- Conversioni temporali: iMessage memorizza le date utilizzando epoche/unità Apple in alcune versioni; convertirle correttamente durante la reportistica.<sup>[[2]](#references)</sup>
- Deriva dello schema: gli schemi SQLite delle app cambiano nel tempo; verificare i nomi delle tabelle/colonne per ogni build del dispositivo
- Estrazione ricorsiva: i PDF possono incorporare stream JBIG2 e font; utilizzare un parser in grado di estrarre e analizzare gli oggetti interni
- Falsi positivi: le euristiche strutturali sono conservative, ma possono segnalare contenuti multimediali rari, malformati ma innocui.<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER: Quando non puoi ottenere i sample, ma devi comunque rilevare la minaccia](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [Progetto ElegantBouncer (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [Workflow di MVT per i backup iOS](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [Note di rilascio di libimobiledevice 1.4.0](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [L'aggiornamento 11.2 ha interrotto la pulizia della cache su iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)
- [6] [Manuale di idevicebackup2](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [Progetto iLEAPP (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [Informazioni sui backup crittografati su iPhone, iPad o iPod touch (Apple Support)](https://support.apple.com/en-ie/108353)
- [9] [Analisi forense di WhatsApp su iOS con Belkasoft X](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [Scanner WhatsApp e risolutore di percorsi di ElegantBouncer](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)
{{#include ../../banners/hacktricks-training.md}}
