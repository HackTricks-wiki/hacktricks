# Forensics kopii zapasowej iOS (triage koncentrujący się na messaging)

{{#include ../../banners/hacktricks-training.md}}

Ta strona opisuje praktyczne kroki pozwalające odtworzyć i przeanalizować kopie zapasowe iOS pod kątem oznak dostarczenia exploita 0-click za pośrednictwem załączników w aplikacjach messaging. Skupia się na przekształceniu zahashowanego układu kopii zapasowej Apple w czytelne dla człowieka ścieżki, a następnie na wyliczeniu i skanowaniu załączników w popularnych aplikacjach.

Cele:
- Odtworzenie czytelnych ścieżek na podstawie Manifest.db
- Wyliczenie baz danych aplikacji messaging (iMessage, WhatsApp, Signal, Telegram, Viber)
- Rozwiązanie ścieżek załączników, wyodrębnienie osadzonych obiektów tam, gdzie jest to obsługiwane (PDF/Images/Fonts), oraz przekazanie ich do detectorów strukturalnych


## Odtwarzanie kopii zapasowej iOS

Kopie zapasowe przechowywane w MobileSync używają nazw plików opartych na hashach, które nie są czytelne dla człowieka. Baza danych SQLite Manifest.db mapuje każdy przechowywany obiekt na jego ścieżkę logiczną.<sup>[[1]](#references)[[2]](#references)</sup>

Procedura wysokiego poziomu:
1) Otwórz Manifest.db i odczytaj rekordy plików (domain, relativePath, flags, fileID/hash)
2) Odtwórz pierwotną hierarchię folderów na podstawie domain + relativePath
3) Skopiuj lub utwórz hardlink do każdego przechowywanego obiektu w jego odtworzonej ścieżce

Przykładowy workflow z użyciem narzędzia, które realizuje cały proces end-to-end (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
- Odszyfruj zaszyfrowane kopie zapasowe przed przekazaniem ich do narzędzia rekonstrukcyjnego; ElegantBouncer wymaga odszyfrowanej kopii zapasowej.<sup>[[2]](#references)[[3]](#references)</sup>
- W miarę możliwości zachowaj oryginalne znaczniki czasu/ACL, aby zachować wartość dowodową

### Pozyskiwanie i odszyfrowywanie kopii zapasowej (USB / Finder / libimobiledevice)

- W Finderze/Apple Devices/iTunes włącz opcję „Szyfruj lokalną kopię zapasową” i utwórz nową kopię; zaszyfrowane kopie zapasowe mogą zawierać zapisane hasła i dane Health, których nie zawierają niezaszyfrowane kopie zapasowe.<sup>[[8]](#references)</sup>
- Wieloplatformowo: libimobiledevice 1.4.0 zawiera poprawki dla `idevicebackup2`.<sup>[[4]](#references)</sup> Włącz szyfrowanie interaktywnie, a następnie wymuś pełną kopię zapasową, stosując udokumentowaną kolejność poleceń, z katalogiem docelowym na końcu.<sup>[[6]](#references)</sup>
```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```
### Triage oparte na IOC z użyciem MVT

Mobile Verification Toolkit firmy Amnesty może wyodrębnić klucz z zaszyfrowanych backupów iTunes/Finder i je odszyfrować, a następnie przeskanować odszyfrowany backup za pomocą pliku IOC STIX2.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```
With `-o`, wyniki w formacie JSON są zapisywane w `/tmp/mvt-results/`; dopasowania IOC używają sufiksu `_detected` i można je skorelować ze ścieżkami załączników odzyskanymi poniżej.<sup>[[3]](#references)</sup>

### Ogólna analiza artefaktów (iLEAPP)

Aby uzyskać dane osi czasu/metadane wykraczające poza messaging, uruchom iLEAPP na folderze surowej kopii zapasowej; jego typ wejścia `itunes` obsługuje kopie zapasowe iTunes/Finder, a bieżące wydania obsługują iOS/iPadOS 11 oraz nowsze wersje.<sup>[[7]](#references)</sup>
```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```
## Wyliczanie załączników w aplikacjach do przesyłania wiadomości

Po rekonstrukcji zinwentaryzuj załączniki w popularnych aplikacjach. Dokładny schemat różni się w zależności od aplikacji i wersji, ale podejście jest podobne: odpytaj bazę danych komunikatora, połącz wiadomości z załącznikami i ustal ścieżki na dysku.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Kluczowe tabele: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ).<sup>[[2]](#references)</sup>

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
Ścieżki załączników mogą być absolutne lub względne względem zrekonstruowanego drzewa w `Library/SMS/Attachments`.<sup>[[2]](#references)</sup>

### WhatsApp (ChatStorage.sqlite)
Typowe powiązanie: tabela wiadomości ↔ tabela multimediów/załączników (nazewnictwo różni się w zależności od wersji). Wykonaj zapytanie dotyczące wierszy multimediów, aby uzyskać ścieżki na dysku. Belkasoft identyfikuje `ZMEDIALOCALPATH` w `ZWAMEDIAITEM` jako lokalizację pliku multimedialnego; bieżąca implementacja ElegantBouncer łączy `ZWAMEDIAITEM.ZMESSAGE` z `ZWAMESSAGE.Z_PK` i dodaje prefiks `Message/` podczas rozwiązywania ścieżki rozpoczynającej się od `Media/`.<sup>[[9]](#references)[[10]](#references)</sup>
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
W przypadku ścieżki rekonstrukcji ElegantBouncer ścieżka multimediów zaczynająca się od `Media/` jest rozwiązywana w ramach `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/`; przewodnik Belkasoft dokumentuje natomiast ścieżkę `Messages/Media/`, dlatego przed przyjęciem którejkolwiek z tych pisowni sprawdź backup.<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal: baza danych wiadomości jest zaszyfrowana; jednak załączniki buforowane na dysku (oraz miniatury) zwykle można skanować.<sup>[[2]](#references)</sup>
- Telegram: sprawdź katalogi multimediów/cache aplikacji; Telegram udokumentował błąd czyszczenia cache w aplikacji iOS 11.2 na iOS 18.0.1, oznaczony jako naprawiony w wersji 11.3, dlatego sprawdź pozostałe pliki.<sup>[[2]](#references)[[5]](#references)</sup>
- Viber: Viber.sqlite zawiera tabele wiadomości/załączników z odwołaniami do plików na dysku.<sup>[[2]](#references)</sup>

Wskazówka: nawet gdy metadane są zaszyfrowane, skanowanie katalogów multimediów/cache nadal pozwala wykryć złośliwe obiekty.<sup>[[2]](#references)</sup>


## Skanowanie załączników pod kątem exploitów strukturalnych

Po uzyskaniu ścieżek załączników przekaż je do detektorów strukturalnych, które sprawdzają niezmienniki formatów plików zamiast sygnatur. Przykład z ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Detekcje objęte regułami strukturalnymi obejmują:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): niemożliwe stany słownika JBIG2
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): konstrukcje tabel Huffmana o nadmiernym rozmiarze
- TrueType TRIANGULATION (CVE‑2023‑41990): nieudokumentowane kody operacji bytecode
- DNG/TIFF CVE‑2025‑43300: niezgodności między metadanymi a komponentami strumienia


## Walidacja, zastrzeżenia i false positives

- Konwersja czasu: iMessage przechowuje daty w epokach/jednostkach Apple w niektórych wersjach; podczas raportowania należy przeprowadzić odpowiednią konwersję.<sup>[[2]](#references)</sup>
- Drift schematu: schematy SQLite aplikacji zmieniają się z czasem; należy potwierdzić nazwy tabel/kolumn dla danej wersji systemu urządzenia
- Rekurencyjna ekstrakcja: pliki PDF mogą zawierać strumienie JBIG2 i fonty; należy używać parsera, który potrafi wyodrębniać i skanować obiekty wewnętrzne
- False positives: heurystyki strukturalne są zachowawcze, ale mogą wykrywać rzadkie, uszkodzone, lecz nieszkodliwe multimedia.<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER: Gdy nie możesz uzyskać próbek, ale nadal musisz wykryć zagrożenie](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [Projekt ElegantBouncer (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [Workflow kopii zapasowej iOS w MVT](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [Informacje o wydaniu libimobiledevice 1.4.0](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Aktualizacja 11.2 powoduje uszkodzenie czyszczenia cache w iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)
- [6] [Podręcznik idevicebackup2](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [Projekt iLEAPP (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [Informacje o szyfrowanych kopiach zapasowych na iPhonie, iPadzie lub iPodzie touch (Apple Support)](https://support.apple.com/en-ie/108353)
- [9] [Analiza śledcza WhatsApp na iOS za pomocą Belkasoft X](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [Skaner WhatsApp ElegantBouncer i resolver ścieżek](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)
{{#include ../../banners/hacktricks-training.md}}
