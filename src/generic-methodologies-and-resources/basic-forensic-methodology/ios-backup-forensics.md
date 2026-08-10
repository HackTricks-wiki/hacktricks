# iOS Backup Forensics (Messaging‑centric triage)

Bu sayfa, messaging app ekleri üzerinden 0‑click exploit teslimatına dair belirtileri yeniden oluşturmak ve analiz etmek için iOS backup'larını pratik olarak inceleme adımlarını açıklar. Apple'ın hash'lenmiş backup düzenini okunabilir yollara dönüştürmeye, ardından yaygın uygulamalardaki ekleri listeleyip taramaya odaklanır.

Hedefler:
- Manifest.db'den okunabilir yolları yeniden oluşturmak
- Messaging database'lerini listelemek (iMessage, WhatsApp, Signal, Telegram, Viber)
- Ek yollarını çözümlemek, desteklenen yerlerde gömülü nesneleri (PDF/Images/Fonts) çıkarmak ve bunları structural detector'lara aktarmak


## Bir iOS backup'ını yeniden oluşturma

MobileSync altında depolanan backup'lar, insanlar tarafından okunabilir olmayan hash'lenmiş dosya adlarını kullanır. Manifest.db SQLite database'i, depolanan her nesneyi mantıksal yoluyla eşleştirir.<sup>[[1]](#references)[[2]](#references)</sup>

Üst düzey prosedür:
1) Manifest.db'yi açın ve dosya kayıtlarını okuyun (domain, relativePath, flags, fileID/hash)
2) domain + relativePath temelinde özgün klasör hiyerarşisini yeniden oluşturun
3) Her depolanan nesneyi yeniden oluşturulan yoluna kopyalayın veya hardlink oluşturun

Bunu uçtan uca uygulayan bir tool ile örnek workflow (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
- Şifrelenmiş yedekleri bir reconstruction tool'a aktarmadan önce decrypt edin; ElegantBouncer decrypt edilmiş bir yedek bekler.<sup>[[2]](#references)[[3]](#references)</sup>
- Delil değeri açısından mümkün olduğunda orijinal zaman damgalarını/ACL'leri koruyun

### Yedeği edinme ve decrypt etme (USB / Finder / libimobiledevice)

- Finder/Apple Devices/iTunes'ta "Encrypt local backup" seçeneğini etkinleştirin ve yeni bir yedek oluşturun; şifrelenmiş yedekler, şifrelenmemiş yedeklerin içermediği kayıtlı parolaları ve Sağlık verilerini içerebilir.<sup>[[8]](#references)</sup>
- Cross-platform: libimobiledevice 1.4.0, `idevicebackup2` için düzeltmeler içerir.<sup>[[4]](#references)</sup> Şifrelemeyi etkileşimli olarak etkinleştirin, ardından belgelenmiş komut sıralamasını kullanarak tam bir yedeği zorlayın; hedef dizin en sonda olmalıdır.<sup>[[6]](#references)</sup>
```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```
### MVT ile IOC odaklı triage

Amnesty’s Mobile Verification Toolkit, şifrelenmiş iTunes/Finder backup’larından bir anahtar çıkarıp bunların şifresini çözebilir, ardından şifresi çözülmüş backup’ı bir STIX2 IOC dosyasıyla tarayabilir.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```
`-o` ile JSON sonuçları `/tmp/mvt-results/` altında yazılır; IOC eşleşmeleri `_detected` son ekini kullanır ve aşağıda kurtarılan ek yollarıyla ilişkilendirilebilir.<sup>[[3]](#references)</sup>

### Genel artefakt ayrıştırma (iLEAPP)

Mesajlaşmanın ötesindeki zaman çizelgesi/metadata için iLEAPP'ı ham backup klasöründe çalıştırın; `itunes` giriş türü iTunes/Finder backup'larını kabul eder ve güncel sürümler iOS/iPadOS 11'den mevcut sürümlere kadar olan sürümleri destekler.<sup>[[7]](#references)</sup>
```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```
## Mesajlaşma uygulamalarında ekleri listeleme

Reconstruction işleminden sonra popüler uygulamalardaki ekleri listeleyin. Kesin schema uygulamaya/sürüme göre değişir, ancak yaklaşım benzerdir: messaging database'i sorgulayın, mesajları eklerle birleştirin ve disk üzerindeki path'leri çözümleyin.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Temel tablolar: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ).<sup>[[2]](#references)</sup>

Örnek sorgular:
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
Ek dosya yolları, mutlak olabilir veya Library/SMS/Attachments altındaki yeniden oluşturulmuş ağaca göreli olabilir.<sup>[[2]](#references)</sup>

### WhatsApp (ChatStorage.sqlite)
Yaygın ilişkilendirme: message table ↔ media/attachment table (adlandırma sürüme göre değişir). Disk üzerindeki yolları elde etmek için media satırlarını sorgulayın. Belkasoft, `ZWAMEDIAITEM` içindeki `ZMEDIALOCALPATH` alanını media-file konumu olarak tanımlar; ElegantBouncer’ın mevcut implementation’ı, `ZWAMEDIAITEM.ZMESSAGE` ile `ZWAMESSAGE.Z_PK` alanlarını birleştirir ve `Media/` ile başlayan bir path’i çözümlerken başına `Message/` ekler.<sup>[[9]](#references)[[10]](#references)</sup>
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
For that ElegantBouncer reconstruction path, `Media/` ile başlayan bir media path, `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` altında çözümlenir; ancak Belkasoft’un guide’ı bunun yerine `Messages/Media/` path’ini belgeler, bu nedenle spelling’lerden herhangi birini varsaymadan önce backup’ı inceleyin.<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal: message DB encrypted durumdadır; ancak disk üzerinde cache’lenen attachment’lar (ve thumbnail’ler) genellikle taranabilir.<sup>[[2]](#references)</sup>
- Telegram: app’in media/cache directory’lerini inceleyin; Telegram, iOS 18.0.1 üzerindeki iOS app 11.2’de bir cache-cleanup bug’ı belgeledi ve bunun 11.3’te düzeltildiğini belirtti; bu nedenle residual file’ları kontrol edin.<sup>[[2]](#references)[[5]](#references)</sup>
- Viber: Viber.sqlite, disk üzerindeki reference’larla birlikte message/attachment table’larını içerir.<sup>[[2]](#references)</sup>

İpucu: metadata encrypted olsa bile media/cache directory’lerini taramak malicious object’leri yine de ortaya çıkarır.<sup>[[2]](#references)</sup>


## Structural exploit’ler için attachment’ları tarama

Attachment path’lerine sahip olduğunuzda, bunları signature’lar yerine file-format invariant’larını doğrulayan structural detector’lara verin. ElegantBouncer ile örnek:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Yapısal kuralların kapsadığı tespitler şunlardır:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): imkânsız JBIG2 dictionary durumları
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): aşırı büyük Huffman table oluşturma işlemleri
- TrueType TRIANGULATION (CVE‑2023‑41990): belgelenmemiş bytecode opcode'ları
- DNG/TIFF CVE‑2025‑43300: metadata ve stream component uyuşmazlıkları


## Validation, caveats, and false positives

- Zaman dönüşümleri: iMessage bazı sürümlerde tarihleri Apple epoch/unit formatlarında saklar; reporting sırasında uygun dönüşümü gerçekleştirin.<sup>[[2]](#references)</sup>
- Schema drift: app SQLite schema'ları zaman içinde değişir; table/column adlarını her device build için doğrulayın
- Recursive extraction: PDF'ler JBIG2 stream'leri ve font'lar gömebilir; inner object'leri çıkarıp tarayabilen bir parser kullanın
- False positives: yapısal heuristic'ler temkinlidir, ancak nadir görülen bozuk fakat zararsız media'ları işaretleyebilir.<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER: Örnekleri Alamıyor Olsanız Bile Tehdidi Yakalamanız Gerektiğinde](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer projesi (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT iOS backup workflow'u](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [libimobiledevice 1.4.0 sürüm notları](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Update 11.2, iOS 18.0.1 üzerinde cache cleanup'ı bozdu (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)
- [6] [idevicebackup2 manual'i](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [iLEAPP projesi (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [iPhone, iPad veya iPod touch cihazınızdaki encrypted backup'lar hakkında (Apple Support)](https://support.apple.com/en-ie/108353)
- [9] [Belkasoft X ile iOS WhatsApp Forensics](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [ElegantBouncer WhatsApp scanner'ı ve path resolver'ı](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)
{{#include ../../banners/hacktricks-training.md}}
