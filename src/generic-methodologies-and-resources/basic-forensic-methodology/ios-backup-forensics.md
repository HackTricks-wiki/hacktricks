# iOS Backup Forensics (Messaging‑centric triage)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica opisuje praktične korake za rekonstrukciju i analizu iOS backup‑ova radi traganja za isporukom 0‑click exploit‑a putem priloga u messaging aplikacijama. Fokus je na pretvaranju Apple‑ovog haširanog layout‑a backup‑a u čitljive putanje, zatim na enumeraciju i skeniranje priloga u uobičajenim aplikacijama.

Ciljevi:
- Rekonstruisati čitljive putanje iz Manifest.db
- Enumerisati messaging baze podataka (iMessage, WhatsApp, Signal, Telegram, Viber)
- Rešavati putanje priloga, izdvajati ugrađene objekte (PDF/Images/Fonts) i prosleđivati ih detektorima strukture


## Rekonstrukcija iOS backup‑a

Backup‑ovi smešteni pod MobileSync koriste haširana imena fajlova koja nisu čitljiva čoveku. Manifest.db SQLite baza podataka preslikava svaki sačuvan objekat na njegovu logičku putanju.

Opšti postupak:
1) Otvoriti Manifest.db i pročitati zapise o fajlovima (domain, relativePath, flags, fileID/hash)
2) Ponovo kreirati originalnu hijerarhiju foldera na osnovu domain + relativePath
3) Kopirati ili napraviti hardlink za svaki sačuvan objekat na rekonstruisanu putanju

Primer radnog toka sa alatom koji ovo implementira od početka do kraja (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Beleške:
- Rukujte šifrovanim rezervnim kopijama tako što ćete svom alatu za ekstrakciju proslediti lozinku za backup
- Sačuvajte originalne vremenske oznake i ACL-ove kad je moguće radi dokazne vrednosti


## Enumeracija priloga u aplikacijama za razmenu poruka

Nakon rekonstrukcije, popišite priloge za popularne aplikacije. Tačan šematski raspored varira po aplikaciji/verziji, ali pristup je sličan: upitovanje baze podataka poruka, spajanje poruka sa prilozima i rešavanje putanja na disku.

### iMessage (sms.db)
Ključne tabele: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

Primer upita:
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
Putanje priloga mogu biti apsolutne ili relativne u odnosu na rekonstruisano stablo pod Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Uobičajena veza: message table ↔ media/attachment table (nazivi se razlikuju po verziji). Izvršite upit nad redovima u media tabeli da biste dobili putanje na disku.

Primer (generički):
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
Prilagodite nazive tabela/kolona vašoj verziji aplikacije (ZWAMESSAGE/ZWAMEDIAITEM are common in iOS builds).

### Signal / Telegram / Viber
- Signal: message DB je šifrovana; međutim, prilozi keširani na disku (i sličice) se obično mogu skenirati
- Telegram: pregledajte keš direktorijume (keševi fotografija/video/dokumenata) i mapirajte ih na razgovore kad je moguće
- Viber: Viber.sqlite sadrži tabele poruka/priloga sa referencama na disku

Tip: čak i kada su metapodaci šifrovani, skeniranje direktorijuma medija/keša i dalje otkriva maliciozne objekte.


## Scanning attachments for structural exploits

Kada imate putanje priloga, prosledite ih u strukturne detektore koji proveravaju invariantnost formata fajla umesto potpisa. Primer sa ElegantBouncer:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Detekcije obuhvaćene strukturnim pravilima uključuju:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): impossible JBIG2 dictionary states
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): oversized Huffman table constructions
- TrueType TRIANGULATION (CVE‑2023‑41990): undocumented bytecode opcodes
- DNG/TIFF CVE‑2025‑43300: metadata vs. stream component mismatches


## Validacija, ograničenja i lažno pozitivni

- Konverzije vremena: iMessage čuva datume u Apple epochs/units na nekim verzijama; konvertujte odgovarajuće pri izveštavanju
- Schema drift: app SQLite šeme se menjaju tokom vremena; potvrdite imena tabela/kolona po build-u uređaja
- Rekurzivno izdvajanje: PDF-ovi mogu ugrađivati JBIG2 streamove i fontove; izdvojite i skenirajte unutrašnje objekte
- Lažno pozitivni: strukturne heuristike su konzervativne, ali mogu označiti retke, malformisane, ipak benignе medije


## References

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)

{{#include ../../banners/hacktricks-training.md}}
