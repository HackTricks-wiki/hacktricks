# iOS Backup Forensics (triage incentrato sulla messaggistica)

{{#include ../../banners/hacktricks-training.md}}

Questa pagina descrive passaggi pratici per ricostruire e analizzare backup iOS alla ricerca di segni di 0‑click exploit distribuiti tramite allegati di app di messaggistica. Si concentra sul trasformare il layout hashed dei backup Apple in percorsi leggibili dall'uomo, per poi enumerare e scansionare gli allegati nelle app più comuni.

Obiettivi:
- Ricostruire percorsi leggibili da Manifest.db
- Enumerare i database di messaggistica (iMessage, WhatsApp, Signal, Telegram, Viber)
- Risolvere i percorsi degli allegati, estrarre oggetti incorporati (PDF/Immagini/Fonts) e inviarli ai rivelatori strutturali


## Ricostruzione di un backup iOS

I backup memorizzati sotto MobileSync usano nomi di file hash che non sono leggibili dall'uomo. Il database SQLite Manifest.db mappa ogni oggetto memorizzato al suo percorso logico.

Procedura ad alto livello:
1) Aprire Manifest.db e leggere i record dei file (domain, relativePath, flags, fileID/hash)
2) Ricreare la gerarchia di cartelle originale basata su domain + relativePath
3) Copiare o creare hardlink di ogni oggetto memorizzato nel percorso ricostruito

Esempio di workflow con uno strumento che implementa questo end‑to‑end (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Note:
- Gestire i backup crittografati fornendo la password del backup al tuo estrattore
- Conservare i timestamp/ACLs originali quando possibile per il valore probatorio

### Acquisizione e decrittazione del backup (USB / Finder / libimobiledevice)

- Su macOS/Finder impostare "Encrypt local backup" e creare un backup crittografato *fresco* in modo che gli elementi del keychain siano presenti.
- Multipiattaforma: `idevicebackup2` (libimobiledevice ≥1.4.0) supporta le modifiche del protocollo di backup di iOS 17/18 e corregge errori di handshake di restore/backup precedenti.
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### Triage guidato dagli IOC con MVT

Amnesty’s Mobile Verification Toolkit (mvt-ios) ora funziona direttamente su backup iTunes/Finder criptati, automatizzando la decrittazione e la corrispondenza degli IOC per casi di mercenary spyware.
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Gli output vengono salvati in `mvt-results/` (es. analytics_detected.json, safari_history_detected.json) e possono essere correlati con i percorsi degli allegati recuperati di seguito.

### Parsing generale degli artefatti (iLEAPP)

Per la timeline e i metadati oltre la messaggistica, esegui iLEAPP direttamente sulla cartella del backup (supporta schemi iOS 11‑17):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Enumerazione degli allegati delle app di messaggistica

Dopo la ricostruzione, enumerare gli allegati per le app più diffuse. Lo schema esatto varia in base all'app/versione, ma l'approccio è simile: interrogare il database dei messaggi, unire i messaggi agli allegati e risolvere i percorsi sul disco.

### iMessage (sms.db)
Tabelle chiave: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

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
I percorsi degli allegati possono essere assoluti o relativi all'albero ricostruito sotto Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Collegamento comune: tabella message ↔ tabella media/attachment (la denominazione varia a seconda della versione). Interroga le righe media per ottenere i percorsi su disco. Le build iOS recenti espongono ancora `ZMEDIALOCALPATH` in `ZWAMEDIAITEM`.
```sql
SELECT
m.Z_PK                 AS message_pk,
mi.ZMEDIALOCALPATH     AS media_path,
datetime(m.ZMESSAGEDATE + 978307200, 'unixepoch') AS message_date,
CASE m.ZISFROMME WHEN 1 THEN 'outgoing' ELSE 'incoming' END AS direction
FROM ZWAMESSAGE m
LEFT JOIN ZWAMEDIAITEM mi ON mi.Z_PK = m.ZMEDIAITEM
WHERE mi.ZMEDIALOCALPATH IS NOT NULL
ORDER BY m.ZMESSAGEDATE DESC;
```
I percorsi solitamente coincidono con `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` all'interno del backup ricostruito.

### Signal / Telegram / Viber
- Signal: the message DB is encrypted; however, attachments cached on disk (and thumbnails) are usually scan‑able
- Telegram: cache remains under `Library/Caches/` inside the sandbox; iOS 18 builds exhibit cache‑clearing bugs, so large residual media caches are common evidence sources
- Viber: Viber.sqlite contains message/attachment tables with on‑disk references

Suggerimento: anche quando i metadati sono criptati, la scansione delle directory media/cache fa emergere comunque oggetti malevoli.


## Scansione degli allegati per exploit strutturali

Una volta ottenuti i percorsi degli allegati, passali a rilevatori strutturali che validano le invarianti del formato file invece che le firme. Esempio con ElegantBouncer:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Detections covered by structural rules include:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): stati del dizionario JBIG2 impossibili
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): costruzioni di tabelle Huffman sovradimensionate
- TrueType TRIANGULATION (CVE‑2023‑41990): opcodes di bytecode non documentati
- DNG/TIFF CVE‑2025‑43300: incongruenze tra metadata e componenti di stream


## Validazione, avvertenze e falsi positivi

- Conversioni temporali: iMessage memorizza date in epoche/unità Apple in alcune versioni; convertire appropriatamente durante il reporting
- Deriva dello schema: gli schemi SQLite delle app cambiano nel tempo; confermare i nomi di tabelle/colonne per build del dispositivo
- Estrazione ricorsiva: i PDF possono incorporare stream JBIG2 e font; estrarre e scansionare gli oggetti interni
- Falsi positivi: le euristiche strutturali sono conservative ma possono segnalare media rari, malformati ma benigni


## Riferimenti

- [ELEGANTBOUNCER: Quando non puoi ottenere i campioni ma devi comunque catturare la minaccia](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [Progetto ElegantBouncer (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [Flusso di lavoro di backup iOS MVT](https://docs.mvt.re/en/latest/ios/backup/check/)
- [Note di rilascio libimobiledevice 1.4.0](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)

{{#include ../../banners/hacktricks-training.md}}
