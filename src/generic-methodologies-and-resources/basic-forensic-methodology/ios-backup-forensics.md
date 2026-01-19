# Analiza kopii zapasowych iOS (triage skoncentrowany na komunikatorach)

{{#include ../../banners/hacktricks-training.md}}

Ta strona opisuje praktyczne kroki pozwalające odtworzyć i analizować kopie zapasowe iOS w celu wykrycia dostarczenia exploitów 0‑click przez załączniki w aplikacjach komunikacyjnych. Skupia się na przekształceniu hashowanego układu kopii Apple w czytelne ścieżki, a następnie na enumeracji i skanowaniu załączników w popularnych aplikacjach.

Cele:
- Odtworzyć czytelne ścieżki z Manifest.db
- Wyenumerować bazy danych komunikatorów (iMessage, WhatsApp, Signal, Telegram, Viber)
- Rozwiązać ścieżki załączników, wyodrębnić osadzone obiekty (PDF/Images/Fonts) i przekazać je do detektorów strukturalnych


## Odtwarzanie kopii zapasowej iOS

Kopie zapasowe przechowywane w MobileSync używają hashowanych nazw plików, które nie są czytelne dla człowieka. Baza SQLite Manifest.db mapuje każdy przechowywany obiekt na jego logiczną ścieżkę.

Procedura wysokiego poziomu:
1) Otwórz Manifest.db i odczytaj rekordy plików (domain, relativePath, flags, fileID/hash)
2) Odtwórz oryginalną hierarchię folderów na podstawie domain + relativePath
3) Skopiuj lub utwórz twarde linki do każdego przechowywanego obiektu w jego odtworzonej ścieżce

Przykładowy przebieg pracy z narzędziem implementującym ten proces end‑to‑end (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Notes:
- Obsługuj zaszyfrowane kopie zapasowe, podając hasło kopii zapasowej do używanego narzędzia ekstrakcji
- Zachowaj oryginalne znaczniki czasowe/ACLs, jeśli to możliwe, ze względu na wartość dowodową

### Pozyskiwanie & odszyfrowywanie kopii zapasowej (USB / Finder / libimobiledevice)

- Na macOS/Finder ustaw "Encrypt local backup" i utwórz *świeżą* zaszyfrowaną kopię zapasową, aby elementy keychain były obecne.
- Wieloplatformowo: `idevicebackup2` (libimobiledevice ≥1.4.0) obsługuje zmiany protokołu kopii zapasowych w iOS 17/18 i naprawia wcześniejsze błędy handshake podczas operacji przywracania i tworzenia kopii zapasowych.
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### Triage oparty na IOC z MVT

Amnesty’s Mobile Verification Toolkit (mvt-ios) teraz działa bezpośrednio na zaszyfrowanych kopiach zapasowych iTunes/Finder, automatyzując odszyfrowywanie i dopasowywanie IOC w sprawach dotyczących mercenary spyware.
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Wyniki trafiają do `mvt-results/` (np. analytics_detected.json, safari_history_detected.json) i mogą być skorelowane ze ścieżkami załączników odzyskanymi poniżej.

### Parsowanie ogólnych artefaktów (iLEAPP)

Aby uzyskać oś czasu/metadane wykraczające poza wiadomości, uruchom iLEAPP bezpośrednio na folderze kopii zapasowej (obsługuje schematy iOS 11‑17):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Enumeracja załączników aplikacji do wiadomości

Po rekonstrukcji wylicz załączniki dla popularnych aplikacji. Dokładny schemat różni się w zależności od aplikacji/wersji, ale podejście jest podobne: zapytaj bazę danych wiadomości, powiąż wiadomości z załącznikami i rozwiąż ścieżki na dysku.

### iMessage (sms.db)
Kluczowe tabele: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

Przykładowe zapytania:
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
Ścieżki załączników mogą być bezwzględne lub względne względem odtworzonej struktury katalogów pod Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Typowe powiązanie: message table ↔ media/attachment table (nazewnictwo różni się w zależności od wersji). Wykonaj zapytanie na wierszach media, aby uzyskać ścieżki na dysku. Nowsze wersje iOS nadal ujawniają `ZMEDIALOCALPATH` w `ZWAMEDIAITEM`.
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
Ścieżki zwykle rozwiązują się pod `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` w odtworzonym backupie.

### Signal / Telegram / Viber
- Signal: the message DB is encrypted; however, attachments cached on disk (and thumbnails) are usually scan‑able
- Telegram: cache remains under `Library/Caches/` inside the sandbox; iOS 18 builds exhibit cache‑clearing bugs, so large residual media caches are common evidence sources
- Viber: Viber.sqlite contains message/attachment tables with on‑disk references

Tip: even when metadata is encrypted, scanning the media/cache directories still surfaces malicious objects.


## Skanowanie załączników w poszukiwaniu structural exploits

Once you have attachment paths, feed them into structural detectors that validate file‑format invariants instead of signatures. Example with ElegantBouncer:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Wykrycia objęte regułami strukturalnymi obejmują:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): niemożliwe stany słownika JBIG2
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): nadmiernie rozbudowane konstrukcje tabel Huffmana
- TrueType TRIANGULATION (CVE‑2023‑41990): nieudokumentowane bytecode opcodes
- DNG/TIFF CVE‑2025‑43300: niezgodności między metadanymi a komponentami strumienia


## Weryfikacja, zastrzeżenia i fałszywe alarmy

- Konwersje czasu: iMessage przechowuje daty w Apple epochs/units w niektórych wersjach; odpowiednio je konwertuj podczas raportowania
- Dryf schematu: schematy SQLite aplikacji zmieniają się z czasem; potwierdź nazwy tabel i kolumn zgodnie z buildem urządzenia
- Rekurencyjna ekstrakcja: pliki PDF mogą osadzać strumienie JBIG2 i fonty; wyodrębnij i zeskanuj obiekty wewnętrzne
- Fałszywe alarmy: heurystyki strukturalne są zachowawcze, ale mogą oznaczyć rzadko występujące, źle sformatowane, lecz nieszkodliwe media


## Referencje

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)

{{#include ../../banners/hacktricks-training.md}}
