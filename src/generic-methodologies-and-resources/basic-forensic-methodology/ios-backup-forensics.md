# Forensics dei backup iOS (triage incentrato sulla messaggistica)

{{#include ../../banners/hacktricks-training.md}}

Questa pagina descrive passaggi pratici per ricostruire e analizzare i backup iOS alla ricerca di tracce di delivery di exploit 0-click tramite allegati delle app di messaggistica. Si concentra sulla trasformazione del layout hashed dei backup Apple in percorsi leggibili, quindi sull'enumerazione e la scansione degli allegati nelle app più comuni.

Obiettivi:
- Ricostruire percorsi leggibili da Manifest.db
- Enumerare i database di messaggistica (iMessage, WhatsApp, Signal, Telegram, Viber)
- Risolvere i percorsi degli allegati, estrarre gli oggetti incorporati (PDF/immagini/font) e passarli a structural detector


## Ricostruzione di un backup iOS

I backup archiviati in MobileSync utilizzano filename hashed non leggibili. Il database SQLite Manifest.db associa ogni oggetto archiviato al relativo percorso logico.

Procedura di alto livello:
1) Aprire Manifest.db e leggere i record dei file (domain, relativePath, flags, fileID/hash)
2) Ricreare la gerarchia delle cartelle originale sulla base di domain + relativePath
3) Copiare o creare un hardlink per ogni oggetto archiviato nel relativo percorso ricostruito

Esempio di workflow con uno strumento che implementa il processo end-to-end (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Note:
- Gestisci i backup crittografati fornendo la password del backup al tuo extractor
- Preserva, quando possibile, i timestamp e gli ACL originali per il loro valore probatorio

### Acquisizione e decrittografia del backup (USB / Finder / libimobiledevice)

- Su macOS/Finder, imposta "Encrypt local backup" e crea un backup crittografato *fresh* in modo che gli elementi del keychain siano presenti.
- Cross-platform: `idevicebackup2` (libimobiledevice ≥1.4.0) supporta le modifiche al protocollo dei backup di iOS 17/18 e risolve gli errori precedenti durante l'handshake di restore/backup.<sup>[[4]](#references)</sup>
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### Triage guidato dagli IOC con MVT

Il Mobile Verification Toolkit di Amnesty (mvt-ios) ora funziona direttamente sui backup iTunes/Finder crittografati, automatizzando la decrittografia e la corrispondenza con gli IOC nei casi di spyware mercenario.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Gli output vengono salvati in `mvt-results/` (ad esempio, analytics_detected.json, safari_history_detected.json) e possono essere correlati con i percorsi degli allegati recuperati di seguito.

### Analisi generale degli artifact (iLEAPP)

Per timeline/metadati oltre alla messaggistica, esegui iLEAPP direttamente sulla cartella del backup (supporta gli schemi iOS 11‑17):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Enumerazione degli allegati delle app di messaggistica

Dopo la ricostruzione, enumera gli allegati delle app più diffuse. Lo schema esatto varia in base all'app/versione, ma l'approccio è simile: interrogare il database di messaggistica, collegare i messaggi agli allegati e risolvere i percorsi sul disco.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Tabelle principali: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

Query di esempio:
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
I percorsi degli allegati possono essere assoluti oppure relativi all’albero ricostruito sotto Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Collegamento comune: tabella dei messaggi ↔ tabella dei media/allegati (la denominazione varia in base alla versione). Interroga le righe dei media per ottenere i percorsi su disco. Le versioni recenti di iOS espongono ancora `ZMEDIALOCALPATH` in `ZWAMEDIAITEM`.
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
I percorsi di solito vengono risolti sotto `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` all'interno del backup ricostruito.

### Signal / Telegram / Viber
- Signal: il DB dei messaggi è crittografato; tuttavia, gli allegati memorizzati nella cache su disco (e le miniature) sono solitamente scansionabili
- Telegram: la cache rimane sotto `Library/Caches/` all'interno della sandbox; le build di iOS 18 presentano bug nella cancellazione della cache, quindi cache residue di grandi dimensioni contenenti media sono fonti comuni di evidenze<sup>[[5]](#references)</sup>
- Viber: Viber.sqlite contiene tabelle di messaggi/allegati con riferimenti su disco

Suggerimento: anche quando i metadati sono crittografati, la scansione delle directory dei media/cache può comunque far emergere oggetti malevoli.


## Scansione degli allegati alla ricerca di exploit strutturali

Una volta ottenuti i percorsi degli allegati, passali a detector strutturali che convalidano gli invarianti del formato dei file invece delle signature. Esempio con ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Rilevamenti coperti dalle regole strutturali includono:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): stati impossibili dei dizionari JBIG2
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): costruzioni sovradimensionate delle tabelle Huffman
- TrueType TRIANGULATION (CVE‑2023‑41990): opcode bytecode non documentati
- DNG/TIFF CVE‑2025‑43300: discrepanze tra i metadati e i componenti dello stream


## Validazione, limitazioni e falsi positivi

- Conversioni temporali: iMessage memorizza le date usando epoch/unità Apple in alcune versioni; convertile adeguatamente durante la reportistica
- Evoluzione dello schema: gli schemi SQLite dell'app cambiano nel tempo; conferma i nomi delle tabelle/colonne in base al build del dispositivo
- Estrazione ricorsiva: i PDF possono incorporare stream JBIG2 e font; estrai ed esegui la scansione degli oggetti interni
- Falsi positivi: le euristiche strutturali sono conservative, ma possono segnalare media rari, malformati ma benigni<sup>[[1]](#references)[[2]](#references)</sup>


## Riferimenti

- [1] [ELEGANTBOUNCER: quando non puoi ottenere i sample, ma devi comunque rilevare la minaccia](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [Progetto ElegantBouncer (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [Workflow di MVT iOS per i backup](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [Note di rilascio di libimobiledevice 1.4.0](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [L'aggiornamento 11.2 ha interrotto la pulizia della cache su iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)

{{#include ../../banners/hacktricks-training.md}}
