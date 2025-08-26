# Analisi forense di backup iOS (triage incentrato sui messaggi)

{{#include ../../banners/hacktricks-training.md}}

Questa pagina descrive passaggi pratici per ricostruire e analizzare backup iOS alla ricerca di segni di delivery di exploit 0‑click tramite allegati di app di messaggistica. Si concentra sul trasformare il layout hashed dei backup Apple in percorsi leggibili dall'uomo, quindi sull'enumerazione e scansione degli allegati nelle app più comuni.

Obiettivi:
- Ricostruire percorsi leggibili da Manifest.db
- Enumerare i database di messaggistica (iMessage, WhatsApp, Signal, Telegram, Viber)
- Risolvere i percorsi degli allegati, estrarre oggetti embedded (PDF/Images/Fonts) e inviarli a rilevatori strutturali


## Ricostruzione di un backup iOS

I backup memorizzati sotto MobileSync usano nomi di file hashed che non sono leggibili. Il database SQLite Manifest.db mappa ogni oggetto memorizzato al suo percorso logico.

Procedura di alto livello:
1) Aprire Manifest.db e leggere i record dei file (domain, relativePath, flags, fileID/hash)
2) Ricreare la gerarchia di cartelle originale basata su domain + relativePath
3) Copiare o creare hardlink di ogni oggetto memorizzato nel suo percorso ricostruito

Esempio di workflow con uno strumento che implementa questo end‑to‑end (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Note:
- Gestire i backup cifrati fornendo la password del backup al tuo extractor
- Conservare i timestamp/ACL originali quando possibile per valore probatorio


## Enumerazione degli allegati delle app di messaggistica

Dopo la ricostruzione, enumerare gli allegati per le app più diffuse. Lo schema esatto varia a seconda dell'app/versione, ma l'approccio è simile: interrogare il database dei messaggi, unire i messaggi agli allegati e risolvere i percorsi su disco.

### iMessage (sms.db)
Key tables: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

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
I percorsi degli allegati possono essere assoluti o relativi all'albero ricostruito sotto Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Collegamento comune: tabella message ↔ tabella media/attachment (i nomi variano a seconda della versione). Interroga le righe media per ottenere i percorsi sul disco.

Esempio (generico):
```sql
SELECT
m.Z_PK          AS message_pk,
mi.ZMEDIALOCALPATH AS media_path,
m.ZMESSAGEDATE  AS message_date
FROM ZWAMESSAGE m
LEFT JOIN ZWAMEDIAITEM mi ON mi.ZMESSAGE = m.Z_PK
WHERE mi.ZMEDIALOCALPATH IS NOT NULL
ORDER BY m.ZMESSAGEDATE DESC;
```
Adatta i nomi di tabelle/colonne alla versione della tua app (ZWAMESSAGE/ZWAMEDIAITEM sono comuni nelle build iOS).

### Signal / Telegram / Viber
- Signal: il DB dei messaggi è cifrato; tuttavia gli allegati memorizzati nella cache su disco (e le miniature) sono di solito scansionabili
- Telegram: ispeziona le directory della cache (cache di foto/video/documenti) e associale alle chat quando possibile
- Viber: Viber.sqlite contiene tabelle di messaggi/allegati con riferimenti su disco

Suggerimento: anche quando i metadati sono cifrati, la scansione delle directory media/cache fa emergere comunque oggetti dannosi.


## Scansione degli allegati per exploit strutturali

Una volta ottenuti i percorsi degli allegati, forniscili a rilevatori strutturali che validano le invarianti del formato file invece delle firme. Esempio con ElegantBouncer:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Le rilevazioni coperte dalle regole strutturali includono:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): stati del dizionario JBIG2 impossibili
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): costruzioni di tabelle Huffman sovradimensionate
- TrueType TRIANGULATION (CVE‑2023‑41990): opcode di bytecode non documentati
- DNG/TIFF CVE‑2025‑43300: incongruenze tra metadati e componenti del flusso


## Validazione, avvertenze e falsi positivi

- Conversioni temporali: iMessage memorizza le date in epoch/unità Apple in alcune versioni; convertirle adeguatamente durante la redazione del report
- Deriva dello schema: gli schemi SQLite delle app cambiano nel tempo; confermare nomi di tabelle/colonne per la build del dispositivo
- Estrazione ricorsiva: i PDF possono incorporare stream JBIG2 e font; estrarre e scansionare gli oggetti interni
- Falsi positivi: le euristiche strutturali sono conservative ma possono segnalare media rari, malformati ma benigni


## References

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)

{{#include ../../banners/hacktricks-training.md}}
