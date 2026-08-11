# Forensics ya iOS Backup (triage inayolenga Messaging)

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unaeleza hatua za kiutendaji za kurekebisha na kuchanganua iOS backups ili kutafuta dalili za uwasilishaji wa 0-click exploit kupitia attachments za messaging apps. Unalenga kubadilisha mpangilio wa backup wenye majina yaliyohashiwa wa Apple kuwa paths zinazosomika na binadamu, kisha kuorodhesha na kuchanganua attachments kwenye apps zinazotumika kwa kawaida.

Malengo:
- Kujenga upya paths zinazosomika kutoka Manifest.db
- Kuorodhesha databases za messaging (iMessage, WhatsApp, Signal, Telegram, Viber)
- Kutatua paths za attachments, kutoa objects zilizopachikwa inapowezekana (PDF/Images/Fonts), na kuzipeleka kwa structural detectors


## Kujenga upya iOS backup

Backups zilizohifadhiwa chini ya MobileSync hutumia filenames zilizohashiwa ambazo hazisomeki kwa binadamu. SQLite database ya Manifest.db huunganisha kila object iliyohifadhiwa na logical path yake.<sup>[[1]](#references)[[2]](#references)</sup>

Utaratibu wa jumla:
1) Fungua Manifest.db na usome rekodi za files (domain, relativePath, flags, fileID/hash)
2) Jenga upya hierarchy ya folders ya awali kulingana na domain + relativePath
3) Nakili au tengeneza hardlink ya kila object iliyohifadhiwa kwenda kwenye path yake iliyojengwa upya

Mfano wa workflow kwa kutumia tool inayotekeleza mchakato huu kutoka mwanzo hadi mwisho (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Notes:
- Decrypt backups zilizosimbwa kwa encryption kabla ya kuzipitisha kwenye reconstruction tool; ElegantBouncer inatarajia backup iliyodecrypt.<sup>[[2]](#references)[[3]](#references)</sup>
- Hifadhi timestamps/ACLs za awali inapowezekana kwa thamani ya ushahidi

### Kupata na ku-decrypt backup (USB / Finder / libimobiledevice)

- Katika Finder/Apple Devices/iTunes, wezesha "Encrypt local backup" na uunde backup mpya; backups zilizosimbwa kwa encryption zinaweza kujumuisha passwords zilizohifadhiwa na data za Health ambazo backups zisizosimbwa kwa encryption huacha.<sup>[[8]](#references)</sup>
- Cross‑platform: libimobiledevice 1.4.0 inajumuisha marekebisho ya `idevicebackup2`.<sup>[[4]](#references)</sup> Wezesha encryption interactively, kisha lazimisha backup kamili kwa kutumia mpangilio wa commands ulioandikwa, ukiweka target directory mwisho.<sup>[[6]](#references)</sup>
```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```
### Triage inayoendeshwa na IOC kwa kutumia MVT

Amnesty’s Mobile Verification Toolkit inaweza kutoa key kwenye iTunes/Finder backups zilizosimbwa, kisha kusimbua backups hizo na kuchanganua backup iliyosimbuliwa kwa kutumia faili ya STIX2 IOC.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```
Kwa kutumia `-o`, matokeo ya JSON huandikwa chini ya `/tmp/mvt-results/`; IOC matches hutumia suffix ya `_detected` na yanaweza kuhusishwa na attachment paths zilizorejeshwa hapa chini.<sup>[[3]](#references)</sup>

### Uchambuzi wa jumla wa artifacts (iLEAPP)

Kwa timeline/metadata zaidi ya messaging, endesha iLEAPP dhidi ya folda ghafi ya backup; aina yake ya input ya `itunes` hukubali iTunes/Finder backups, na matoleo ya sasa yanaunga mkono iOS/iPadOS 11 hadi matoleo ya sasa.<sup>[[7]](#references)</sup>
```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```
## Kuhesabu viambatisho vya messaging app

Baada ya reconstruction, hesabu viambatisho vya apps maarufu. Schema halisi hutofautiana kulingana na app/version, lakini mbinu ni sawa: uliza messaging database, unganisha messages na attachments, na utambue paths kwenye diski.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Majedwali muhimu: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ).<sup>[[2]](#references)</sup>

Mfano wa queries:
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
Njia za attachments zinaweza kuwa absolute au relative kwa tree iliyorejeshwa chini ya Library/SMS/Attachments.<sup>[[2]](#references)</sup>

### WhatsApp (ChatStorage.sqlite)
Muunganisho wa kawaida: jedwali la message ↔ jedwali la media/attachment (majina hutofautiana kulingana na version). Query rows za media ili kupata paths zilizo kwenye disk. Belkasoft hutambua `ZMEDIALOCALPATH` katika `ZWAMEDIAITEM` kama eneo la media-file; implementation ya sasa ya ElegantBouncer huunganisha `ZWAMEDIAITEM.ZMESSAGE` na `ZWAMESSAGE.Z_PK` na huongeza `Message/` mwanzoni wakati wa kutatua path inayoanza na `Media/`.<sup>[[9]](#references)[[10]](#references)</sup>
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
Kwa hiyo ElegantBouncer reconstruction path, media path inayoanza na `Media/` hutatuliwa chini ya `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/`; mwongozo wa Belkasoft badala yake unaandika path ya `Messages/Media/`, kwa hiyo kagua backup kabla ya kudhani spelling mojawapo ni sahihi.<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal: message DB ime-encryptiwa; hata hivyo, attachments zilizocache kwenye disk (pamoja na thumbnails) kwa kawaida zinaweza kuchanganuliwa.<sup>[[2]](#references)</sup>
- Telegram: kagua media/cache directories za app; Telegram iliandika kuhusu bug ya cache-cleanup katika iOS app 11.2 kwenye iOS 18.0.1, iliyoonyeshwa kuwa imerekebishwa katika 11.3, kwa hiyo kagua files zilizobaki.<sup>[[2]](#references)[[5]](#references)</sup>
- Viber: Viber.sqlite ina message/attachment tables zenye marejeleo ya files zilizo kwenye disk.<sup>[[2]](#references)</sup>

Tip: hata metadata ikiwa ime-encryptiwa, kuchanganua media/cache directories bado hufichua malicious objects.<sup>[[2]](#references)</sup>


## Kuchanganua attachments kwa structural exploits

Baada ya kupata attachment paths, zipitishe kwenye structural detectors zinazothibitisha file-format invariants badala ya signatures. Mfano wa ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Mifumo ya ugunduzi inayoshughulikiwa na structural rules inajumuisha:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): hali za kamusi za JBIG2 zisizowezekana
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): uundaji wa jedwali za Huffman zilizozidi ukubwa
- TrueType TRIANGULATION (CVE‑2023‑41990): bytecode opcodes zisizoandikwa kwenye nyaraka
- DNG/TIFF CVE‑2025‑43300: kutolingana kati ya metadata na vipengele vya stream


## Uthibitishaji, tahadhari, na false positives

- Ubadilishaji wa muda: iMessage huhifadhi tarehe kwa kutumia Apple epochs/units kwenye baadhi ya matoleo; zifanyie ubadilishaji ipasavyo wakati wa kuripoti.<sup>[[2]](#references)</sup>
- Schema drift: app SQLite schemas hubadilika baada ya muda; thibitisha majina ya table/column kulingana na device build
- Utoaji wa vitu vilivyopachikwa kwa kujirudia: PDFs zinaweza kuwa na JBIG2 streams na fonts; tumia parser inayoweza kutoa na kuchanganua objects za ndani
- False positives: structural heuristics ni za tahadhari, lakini zinaweza kuripoti media adimu zilizoharibika bila kuwa na madhara.<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER: Wakati Huwezi Kupata Samples Lakini Bado Unahitaji Kubaini Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [Mradi wa ElegantBouncer (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [Mtiririko wa kazi wa MVT iOS backup](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [Maelezo ya toleo la libimobiledevice 1.4.0](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Update 11.2 imeharibu cache cleanup kwenye iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)
- [6] [Mwongozo wa idevicebackup2](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [Mradi wa iLEAPP (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [Kuhusu backups zilizosimbwa kwa njia fiche kwenye iPhone, iPad au iPod touch yako (Apple Support)](https://support.apple.com/en-ie/108353)
- [9] [Uchunguzi wa iOS WhatsApp kwa Belkasoft X](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [ElegantBouncer WhatsApp scanner na path resolver](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)
{{#include ../../banners/hacktricks-training.md}}
