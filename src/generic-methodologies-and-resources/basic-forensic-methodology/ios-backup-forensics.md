# iOS Backup Forensics (Messaging‑centric triage)

{{#include ../../banners/hacktricks-training.md}}

This page describes practical steps to reconstruct and analyze iOS backups for signs of 0‑click exploit delivery via messaging app attachments. It focuses on turning Apple’s hashed backup layout into human‑readable paths, then enumerating and scanning attachments across common apps.

Goals:
- Rebuild readable paths from Manifest.db
- Enumerate messaging databases (iMessage, WhatsApp, Signal, Telegram, Viber)
- Resolve attachment paths, extract embedded objects where supported (PDF/Images/Fonts), and feed them to structural detectors


## Reconstructing an iOS backup

Backups stored under MobileSync use hashed filenames that are not human‑readable. The Manifest.db SQLite database maps each stored object to its logical path.<sup>[[1]](#references)[[2]](#references)</sup>

High‑level procedure:
1) Open Manifest.db and read the file records (domain, relativePath, flags, fileID/hash)
2) Recreate the original folder hierarchy based on domain + relativePath
3) Copy or hardlink each stored object to its reconstructed path

Example workflow with a tool that implements this end‑to‑end (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>

```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```

Notes:
- Decrypt encrypted backups before passing them to a reconstruction tool; ElegantBouncer expects a decrypted backup.<sup>[[2]](#references)[[3]](#references)</sup>
- Preserve original timestamps/ACLs when possible for evidentiary value

### Acquiring & decrypting the backup (USB / Finder / libimobiledevice)

- In Finder/Apple Devices/iTunes, enable "Encrypt local backup" and create a new backup; encrypted backups can include saved passwords and Health data that unencrypted backups omit.<sup>[[8]](#references)</sup>
- Cross‑platform: libimobiledevice 1.4.0 includes fixes for `idevicebackup2`.<sup>[[4]](#references)</sup> Enable encryption interactively, then force a full backup using the documented command ordering, with the target directory last.<sup>[[6]](#references)</sup>

```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```

### IOC‑driven triage with MVT

Amnesty’s Mobile Verification Toolkit can extract a key from and decrypt encrypted iTunes/Finder backups, then scan the decrypted backup with a STIX2 IOC file.<sup>[[3]](#references)</sup>

```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```

With `-o`, JSON results are written under `/tmp/mvt-results/`; IOC matches use a `_detected` suffix and can be correlated with the attachment paths recovered below.<sup>[[3]](#references)</sup>

### General artifact parsing (iLEAPP)

For timeline/metadata beyond messaging, run iLEAPP against the raw backup folder; its `itunes` input type accepts iTunes/Finder backups and current releases support iOS/iPadOS 11 through current versions.<sup>[[7]](#references)</sup>

```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```


## Messaging app attachment enumeration

After reconstruction, enumerate attachments for popular apps. The exact schema varies by app/version, but the approach is similar: query the messaging database, join messages to attachments, and resolve paths on disk.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Key tables: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ).<sup>[[2]](#references)</sup>

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

Attachment paths may be absolute or relative to the reconstructed tree under Library/SMS/Attachments.<sup>[[2]](#references)</sup>

### WhatsApp (ChatStorage.sqlite)
Common linkage: message table ↔ media/attachment table (naming varies by version). Query media rows to obtain on‑disk paths. Belkasoft identifies `ZMEDIALOCALPATH` in `ZWAMEDIAITEM` as the media-file location; ElegantBouncer’s current implementation joins `ZWAMEDIAITEM.ZMESSAGE` to `ZWAMESSAGE.Z_PK` and prepends `Message/` when resolving a path that begins with `Media/`.<sup>[[9]](#references)[[10]](#references)</sup>

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

For that ElegantBouncer reconstruction path, a media path beginning with `Media/` resolves under `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/`; Belkasoft’s guide instead documents a `Messages/Media/` path, so inspect the backup before assuming either spelling.<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal: the message DB is encrypted; however, attachments cached on disk (and thumbnails) are usually scan‑able.<sup>[[2]](#references)</sup>
- Telegram: inspect the app's media/cache directories; Telegram documented a cache-cleanup bug in iOS app 11.2 on iOS 18.0.1, marked fixed in 11.3, so check for residual files.<sup>[[2]](#references)[[5]](#references)</sup>
- Viber: Viber.sqlite contains message/attachment tables with on‑disk references.<sup>[[2]](#references)</sup>

Tip: even when metadata is encrypted, scanning the media/cache directories still surfaces malicious objects.<sup>[[2]](#references)</sup>


## Scanning attachments for structural exploits

Once you have attachment paths, feed them into structural detectors that validate file‑format invariants instead of signatures. Example with ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```

Detections covered by structural rules include:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): impossible JBIG2 dictionary states
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): oversized Huffman table constructions
- TrueType TRIANGULATION (CVE‑2023‑41990): undocumented bytecode opcodes
- DNG/TIFF CVE‑2025‑43300: metadata vs. stream component mismatches


## Validation, caveats, and false positives

- Time conversions: iMessage stores dates in Apple epochs/units on some versions; convert appropriately during reporting.<sup>[[2]](#references)</sup>
- Schema drift: app SQLite schemas change over time; confirm table/column names per device build
- Recursive extraction: PDFs may embed JBIG2 streams and fonts; use a parser that can extract and scan inner objects
- False positives: structural heuristics are conservative but can flag rare malformed yet benign media.<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Update 11.2 has broken cache cleanup on iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)
- [6] [idevicebackup2 manual](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [iLEAPP project (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [About encrypted backups on your iPhone, iPad or iPod touch (Apple Support)](https://support.apple.com/en-ie/108353)
- [9] [iOS WhatsApp Forensics with Belkasoft X](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [ElegantBouncer WhatsApp scanner and path resolver](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)

{{#include ../../banners/hacktricks-training.md}}
