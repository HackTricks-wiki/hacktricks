# Forensiki za Backup za iOS (Triage inayojikita kwenye Ujumbe)

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unaelezea hatua za vitendo za kujenga upya na kuchambua backups za iOS kwa dalili za utoaji wa exploit wa 0‑click kupitia viambatisho vya apps za ujumbe. Inalenga kubadilisha muundo wa backup uliopo wa Apple ulioshughulikiwa kwa hashed kuwa njia zinazosomeka na binadamu, kisha kuorodhesha na kuchunguza viambatisho katika apps zinazotumika sana.

Malengo:
- Jenga tena njia zinazosomeka kutoka Manifest.db
- Orodhesha databases za ujumbe (iMessage, WhatsApp, Signal, Telegram, Viber)
- Tatua njia za viambatisho, chunguza vitu vilivyowekwa ndani (PDF/Images/Fonts), na ziingize kwa structural detectors


## Kujenga upya backup ya iOS

Backups zilizohifadhiwa chini ya MobileSync zinatumia majina ya faili yaliyohashishwa ambayo hayawezi kusomwa na binadamu. Manifest.db SQLite database inaunganisha kila kitu kilichohifadhiwa na njia yake ya kifikishi.

Utaratibu wa juu:
1) Fungua Manifest.db na usome rekodi za faili (domain, relativePath, flags, fileID/hash)
2) Jenga upya muundo wa saraka wa awali kulingana na domain + relativePath
3) Nakili au tengeneza hardlink kwa kila kitu kilichohifadhiwa hadi njia yake iliyojengwa tena

Mfano wa mtiririko wa kazi na zana inayotekeleza hii kutoka mwanzo hadi mwisho (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Vidokezo:
- Shughulikia encrypted backups kwa kutoa backup password kwa extractor yako
- Hifadhi timestamps/ACLs za asili inapowezekana kwa thamani ya ushahidi


## Orodhesha viambatanisho vya app za ujumbe

Baada ya ujenzi upya, orodhesha viambatanisho kwa apps maarufu. Muundo halisi (schema) unatofautiana kwa app/toleo, lakini mbinu ni sawa: fanya query kwenye database ya ujumbe, unganya jumbe na viambatanisho, na tatua paths kwenye diski.

### iMessage (sms.db)
Jedwali muhimu: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

Mifano ya query:
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
Njia za attachment zinaweza kuwa absolute au relative kwa mti uliorejeshwa chini ya Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Unganisho la kawaida: message table ↔ media/attachment table (majina yanatofautiana kulingana na toleo). Query media rows ili kupata on-disk paths.

Mfano (ya jumla):
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
Badilisha majina ya jedwali/safu kulingana na toleo la app yako (ZWAMESSAGE/ZWAMEDIAITEM are common in iOS builds).

### Signal / Telegram / Viber
- Signal: DB ya ujumbe imefungwa; hata hivyo, viambatanisho vilivyohifadhiwa kwenye diski (na thumbnails) kawaida vinaweza kuchunguzwa
- Telegram: chunguza saraka za cache (photo/video/document caches) na ziunganishe na mazungumzo pale inapowezekana
- Viber: Viber.sqlite ina meza za ujumbe/viambatanisho zenye marejeleo kwenye diski

Tip: hata pale metadata imefungwa, kuchunguza saraka za media/cache bado huibua vitu hatarishi.


## Kuchunguza viambatanisho kwa structural exploits

Mara tu unapokuwa na njia za viambatanisho, ziingize kwenye structural detectors ambazo zinathibitisha file‑format invariants badala ya signatures. Mfano kwa ElegantBouncer:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Detections covered by structural rules include:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): hali za kamusi za JBIG2 zisizowezekana
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): miundo ya meza za Huffman zilizopitiliza ukubwa
- TrueType TRIANGULATION (CVE‑2023‑41990): opcodes za bytecode zisizoandikwa
- DNG/TIFF CVE‑2025‑43300: migongano kati ya metadata na vipengele vya stream


## Uthibitisho, tahadhari, na matokeo ya uwongo

- Ubadilishaji wa muda: iMessage huhifadhi tarehe katika Apple epochs/vitengo kwa baadhi ya matoleo; badilisha ipasavyo wakati wa kuripoti
- Schema drift: schema za SQLite za app hubadilika kwa muda; thibitisha majina ya jedwali/safina kwa kila build ya kifaa
- Uchimbaji wa rekursive: PDF zinaweza kujumuisha streams za JBIG2 na fonti; chimba na skani vitu vilivyomo
- Matokeo ya uongo: heuristics za muundo ni za tahadhari lakini zinaweza kuonyesha vyombo vya habari vilivyopangwa vibaya lakini visivyo hatari


## References

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)

{{#include ../../banners/hacktricks-training.md}}
