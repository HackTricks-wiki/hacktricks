# Analiza kopii zapasowych iOS (triage ukierunkowany na komunikatory)

{{#include ../../banners/hacktricks-training.md}}

Ta strona opisuje praktyczne kroki umożliwiające odtworzenie i analizę kopii zapasowych iOS pod kątem śladów dostarczenia exploitów 0‑click za pomocą załączników w aplikacjach komunikacyjnych. Koncentruje się na przekształceniu haszowanego układu kopii zapasowej Apple w czytelne ścieżki, a następnie na enumeracji i skanowaniu załączników w popularnych aplikacjach.

Cele:
- Odtworzyć czytelne ścieżki z Manifest.db
- Wyenumerować bazy danych komunikatorów (iMessage, WhatsApp, Signal, Telegram, Viber)
- Rozwiązać ścieżki załączników, wyodrębnić osadzone obiekty (PDF/obrazy/czcionki) i przekazać je do detektorów strukturalnych


## Odtwarzanie kopii zapasowej iOS

Kopie zapasowe przechowywane w MobileSync używają haszowanych nazw plików, które nie są czytelne dla człowieka. Baza danych SQLite Manifest.db mapuje każdy przechowywany obiekt na jego logiczną ścieżkę.

Procedura ogólna:
1) Otwórz Manifest.db i odczytaj rekordy plików (domain, relativePath, flags, fileID/hash)
2) Odtwórz oryginalną hierarchię folderów w oparciu o domain + relativePath
3) Skopiuj lub utwórz hardlink dla każdego przechowywanego obiektu do jego odtworzonej ścieżki

Przykładowy przebieg za pomocą narzędzia, które realizuje to end‑to‑end (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Notatki:
- Obsłuż zaszyfrowane kopie zapasowe, podając extractorowi hasło do backupu
- Zachowaj oryginalne znaczniki czasowe/ACL, gdy to możliwe ze względu na wartość dowodową


## Enumeracja załączników aplikacji wiadomości

Po rekonstrukcji wyodrębnij listę załączników dla popularnych aplikacji. Dokładna struktura schematu różni się w zależności od aplikacji/wersji, ale podejście jest podobne: zapytaj bazę danych wiadomości, połącz wiadomości z załącznikami i rozwiąż ścieżki na dysku.

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
Attachment paths may be absolute or relative to the reconstructed tree under Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Typowe powiązanie: tabela message ↔ tabela media/attachment (nazewnictwo różni się w zależności od wersji). Zapytaj wiersze tabeli media, aby uzyskać ścieżki na dysku.

Example (generic):
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
Dostosuj nazwy tabel/kolumn do wersji aplikacji (ZWAMESSAGE/ZWAMEDIAITEM są powszechne w buildach iOS).

### Signal / Telegram / Viber
- Signal: message DB jest zaszyfrowana; jednak załączniki buforowane na dysku (i miniatury) zwykle dają się przeskanować
- Telegram: sprawdź katalogi cache (photo/video/document caches) i powiąż z czatami, gdy to możliwe
- Viber: Viber.sqlite zawiera tabele wiadomości/załączników z odniesieniami na dysku

Wskazówka: nawet gdy metadane są zaszyfrowane, skanowanie katalogów media/cache nadal ujawnia złośliwe obiekty.


## Skanowanie załączników pod kątem structural exploits

Gdy masz ścieżki do załączników, przekaż je do structural detectors, które walidują file‑format invariants zamiast signatures. Example with ElegantBouncer:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Detections covered by structural rules include:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): niemożliwe stany słownika JBIG2
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): nadmiernie rozbudowane konstrukcje tabel Huffmana
- TrueType TRIANGULATION (CVE‑2023‑41990): niedokumentowane bytecode opcodes
- DNG/TIFF CVE‑2025‑43300: niezgodności między metadanymi a komponentami strumienia


## Walidacja, zastrzeżenia i fałszywe pozytywy

- Konwersje czasu: iMessage przechowuje daty w epokach/jednostkach Apple w niektórych wersjach; przelicz odpowiednio podczas raportowania
- Schema drift: schematy SQLite aplikacji zmieniają się w czasie; potwierdź nazwy tabel/kolumn dla wersji urządzenia
- Recursive extraction: PDF-y mogą osadzać strumienie JBIG2 i fonty; wydobądź i przeskanuj wewnętrzne obiekty
- False positives: heurystyki strukturalne są konserwatywne, ale mogą zgłaszać rzadkie, niepoprawne, lecz nieszkodliwe media


## References

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)

{{#include ../../banners/hacktricks-training.md}}
