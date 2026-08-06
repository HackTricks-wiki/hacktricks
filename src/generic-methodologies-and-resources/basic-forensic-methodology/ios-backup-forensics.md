# Forensics kopii zapasowych iOS (triage skoncentrowany na messaging)

{{#include ../../banners/hacktricks-training.md}}

Ta strona opisuje praktyczne kroki umożliwiające odtworzenie i analizę kopii zapasowych iOS pod kątem oznak dostarczenia exploitów 0-click za pośrednictwem załączników w aplikacjach messaging. Skupia się na przekształceniu zahashowanego układu kopii zapasowej Apple w czytelne dla człowieka ścieżki, a następnie na wyliczeniu i skanowaniu załączników w popularnych aplikacjach.

Cele:
- Odtworzenie czytelnych ścieżek na podstawie Manifest.db
- Wyliczenie baz danych aplikacji messaging (iMessage, WhatsApp, Signal, Telegram, Viber)
- Rozwiązanie ścieżek załączników, wyodrębnienie osadzonych obiektów (PDF/Images/Fonts) i przekazanie ich do detectorów strukturalnych


## Odtwarzanie kopii zapasowej iOS

Kopie zapasowe przechowywane w MobileSync używają zahashowanych nazw plików, które nie są czytelne dla człowieka. Baza danych SQLite Manifest.db mapuje każdy zapisany obiekt na jego ścieżkę logiczną.

Procedura wysokiego poziomu:
1) Otwórz Manifest.db i odczytaj rekordy plików (domain, relativePath, flags, fileID/hash)
2) Odtwórz pierwotną hierarchię folderów na podstawie domain + relativePath
3) Skopiuj lub utwórz hardlink do każdego zapisanego obiektu w jego odtworzonej ścieżce

Przykładowy workflow z użyciem narzędzia, które implementuje ten proces end-to-end (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Uwagi:
- Obsługuj zaszyfrowane backupy, podając hasło backupu do extractor
- W miarę możliwości zachowuj oryginalne znaczniki czasu/ACL, aby zachować wartość dowodową

### Pozyskiwanie i odszyfrowywanie backupu (USB / Finder / libimobiledevice)

- W macOS/Finder zaznacz opcję "Encrypt local backup" i utwórz *świeży* zaszyfrowany backup, aby elementy keychain były obecne.
- Wieloplatformowo: `idevicebackup2` (libimobiledevice ≥1.4.0) obsługuje zmiany w protokole backupu iOS 17/18 oraz naprawia wcześniejsze błędy uzgadniania podczas przywracania/tworzenia backupu.<sup>[[4]](#references)</sup>
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### Triaging oparty na IOC z użyciem MVT

Mobile Verification Toolkit Amnesty International (mvt-ios) działa teraz bezpośrednio z zaszyfrowanymi kopiami zapasowymi iTunes/Finder, automatyzując ich odszyfrowywanie i dopasowywanie IOC w przypadkach dotyczących mercenary spyware.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Wyniki są zapisywane w katalogu `mvt-results/` (np. analytics_detected.json, safari_history_detected.json) i można je skorelować ze ścieżkami załączników odzyskanymi poniżej.

### Ogólne analizowanie artefaktów (iLEAPP)

Aby uzyskać dane osi czasu/metadane wykraczające poza wiadomości, uruchom iLEAPP bezpośrednio na folderze kopii zapasowej (obsługuje schematy iOS 11–17):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Enumeracja załączników w aplikacjach do przesyłania wiadomości

Po rekonstrukcji wylicz załączniki dla popularnych aplikacji. Dokładny schemat różni się w zależności od aplikacji i wersji, ale podejście jest podobne: wykonaj zapytanie do messaging database, połącz wiadomości z załącznikami i ustal ścieżki na dysku.<sup>[[1]](#references)[[2]](#references)</sup>

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
Ścieżki załączników mogą być absolutne lub względne względem odtworzonego drzewa w `Library/SMS/Attachments/`.

### WhatsApp (ChatStorage.sqlite)
Typowe powiązanie: tabela wiadomości ↔ tabela multimediów/załączników (nazewnictwo różni się w zależności od wersji). Wykonaj zapytanie dotyczące wierszy multimediów, aby uzyskać ścieżki na dysku. Nowsze wersje iOS nadal udostępniają `ZMEDIALOCALPATH` w `ZWAMEDIAITEM`.
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
Ścieżki zwykle znajdują się w `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` w obrębie odtworzonej kopii zapasowej.

### Signal / Telegram / Viber
- Signal: baza wiadomości jest zaszyfrowana; jednak załączniki buforowane na dysku (oraz miniatury) zwykle można skanować
- Telegram: cache pozostaje w `Library/Caches/` wewnątrz sandboxa; kompilacje iOS 18 wykazują błędy czyszczenia cache, dlatego duże pozostałości cache z multimediami są częstym źródłem dowodów<sup>[[5]](#references)</sup>
- Viber: Viber.sqlite zawiera tabele wiadomości/załączników z odniesieniami do plików na dysku

Wskazówka: nawet gdy metadane są zaszyfrowane, skanowanie katalogów multimediów/cache nadal ujawnia złośliwe obiekty.


## Skanowanie załączników pod kątem exploitów strukturalnych

Po uzyskaniu ścieżek załączników przekaż je do detektorów strukturalnych, które sprawdzają niezmienniki formatu pliku zamiast sygnatur. Przykład z ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Detekcje objęte regułami strukturalnymi obejmują:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): niemożliwe stany słownika JBIG2
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): konstrukcje tablic Huffmana o zbyt dużym rozmiarze
- TrueType TRIANGULATION (CVE‑2023‑41990): nieudokumentowane kody operacji bytecode
- DNG/TIFF CVE‑2025‑43300: niezgodności między metadanymi a komponentami strumienia


## Walidacja, zastrzeżenia i fałszywe alarmy

- Konwersja czasu: iMessage przechowuje daty w epokach/jednostkach Apple w niektórych wersjach; podczas raportowania należy je odpowiednio konwertować
- Zmiany schematu: schematy SQLite aplikacji zmieniają się z czasem; należy potwierdzić nazwy tabel/kolumn dla danej wersji systemu na urządzeniu
- Rekurencyjna ekstrakcja: pliki PDF mogą zawierać osadzone strumienie JBIG2 i czcionki; należy wyodrębnić i skanować obiekty wewnętrzne
- Fałszywe alarmy: heurystyki strukturalne są zachowawcze, ale mogą wykrywać rzadkie, zniekształcone, lecz nieszkodliwe multimedia<sup>[[1]](#references)[[2]](#references)</sup>


## Odniesienia

- [1] [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Update 11.2 has broken cache cleanup on iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)

{{#include ../../banners/hacktricks-training.md}}
