# iOS Backup Forensics (Messaging‑centric triage)

{{#include ../../banners/hacktricks-training.md}}

This page describes practical steps to reconstruct and analyze iOS backups for signs of 0‑click exploit delivery via messaging app attachments. It focuses on turning Apple’s hashed backup layout into human‑readable paths, then enumerating and scanning attachments across common apps.

Goals:
- Rebuild readable paths from Manifest.db
- Enumerate messaging databases (iMessage, WhatsApp, Signal, Telegram, Viber)
- Resolve attachment paths, extract embedded objects (PDF/Images/Fonts), and feed them to structural detectors


## Reconstructing an iOS backup

Backups stored under MobileSync use hashed filenames that are not human‑readable. The Manifest.db SQLite database maps each stored object to its logical path.

High‑level procedure:
1) Open Manifest.db and read the file records (domain, relativePath, flags, fileID/hash)
2) Recreate the original folder hierarchy based on domain + relativePath
3) Copy or hardlink each stored object to its reconstructed path

Example workflow with a tool that implements this end‑to‑end (ElegantBouncer):

```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```

Notes:
- Handle encrypted backups by supplying the backup password to your extractor
- Preserve original timestamps/ACLs when possible for evidentiary value

### Acquiring & decrypting the backup (USB / Finder / libimobiledevice)

- On macOS/Finder set "Encrypt local backup" and create a *fresh* encrypted backup so keychain items are present.
- Cross‑platform: `idevicebackup2` (libimobiledevice ≥1.4.0) understands iOS 17/18 backup protocol changes and fixes earlier restore/backup handshake errors.

```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```

### IOC‑driven triage with MVT

Amnesty’s Mobile Verification Toolkit (mvt-ios) now works directly on encrypted iTunes/Finder backups, automating decryption and IOC matching for mercenary spyware cases.

```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```

Outputs land under `mvt-results/` (e.g., analytics_detected.json, safari_history_detected.json) and can be correlated with the attachment paths recovered below.

### General artifact parsing (iLEAPP)

For timeline/metadata beyond messaging, run iLEAPP directly on the backup folder (supports iOS 11‑17 schemas):

```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```


## Messaging app attachment enumeration

After reconstruction, enumerate attachments for popular apps. The exact schema varies by app/version, but the approach is similar: query the messaging database, join messages to attachments, and resolve paths on disk.

### iMessage (sms.db)
Key tables: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

Example queries:

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

Attachment paths may be absolute or relative to the reconstructed tree under Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Common linkage: message table ↔ media/attachment table (naming varies by version). Query media rows to obtain on‑disk paths. Recent iOS builds still expose `ZMEDIALOCALPATH` in `ZWAMEDIAITEM`.

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

Paths usually resolve under `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` inside the reconstructed backup.

### Signal / Telegram / Viber
- Signal: the message DB is encrypted; however, attachments cached on disk (and thumbnails) are usually scan‑able
- Telegram: cache remains under `Library/Caches/` inside the sandbox; iOS 18 builds exhibit cache‑clearing bugs, so large residual media caches are common evidence sources
- Viber: Viber.sqlite contains message/attachment tables with on‑disk references

Tip: even when metadata is encrypted, scanning the media/cache directories still surfaces malicious objects.


## Scanning attachments for structural exploits

Once you have attachment paths, feed them into structural detectors that validate file‑format invariants instead of signatures. Example with ElegantBouncer:

```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```

Detections covered by structural rules include:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): impossible JBIG2 dictionary states
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): oversized Huffman table constructions
- TrueType TRIANGULATION (CVE‑2023‑41990): undocumented bytecode opcodes
- DNG/TIFF CVE‑2025‑43300: metadata vs. stream component mismatches


## Validation, caveats, and false positives

- Time conversions: iMessage stores dates in Apple epochs/units on some versions; convert appropriately during reporting
- Schema drift: app SQLite schemas change over time; confirm table/column names per device build
- Recursive extraction: PDFs may embed JBIG2 streams and fonts; extract and scan inner objects
- False positives: structural heuristics are conservative but can flag rare malformed yet benign media


## References

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)

{{#include ../../banners/hacktricks-training.md}}
