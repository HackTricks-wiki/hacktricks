# iOS Backup Forensics (Messaging-centric triage)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, messaging app ekleri üzerinden 0-click exploit delivery belirtilerini yeniden oluşturmak ve analiz etmek için iOS backup'larını pratik olarak inceleme adımlarını açıklar. Apple'ın hash'lenmiş backup düzenini human-readable path'lere dönüştürmeye, ardından yaygın uygulamalardaki ekleri listeleyip taramaya odaklanır.

Hedefler:
- Manifest.db'den okunabilir path'leri yeniden oluşturmak
- Messaging database'lerini (iMessage, WhatsApp, Signal, Telegram, Viber) listelemek
- Attachment path'lerini çözümlemek, desteklenen yerlerde gömülü nesneleri (PDF/Images/Fonts) çıkarmak ve bunları structural detector'lara aktarmak


## Bir iOS backup'ını yeniden oluşturma

MobileSync altında depolanan backup'lar, human-readable olmayan hash'lenmiş dosya adlarını kullanır. Manifest.db SQLite database'i, depolanan her nesneyi logical path'ine eşler.<sup>[[1]](#references)[[2]](#references)</sup>

Üst düzey prosedür:
1) Manifest.db'yi açın ve file record'larını okuyun (domain, relativePath, flags, fileID/hash)
2) domain + relativePath temelinde orijinal folder hierarchy'yi yeniden oluşturun
3) Her depolanan nesneyi yeniden oluşturulan path'ine kopyalayın veya hardlink oluşturun

Bu işlemi uçtan uca uygulayan bir tool ile örnek workflow (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Notlar:
- Şifrelenmiş yedekleri bir reconstruction tool'a aktarmadan önce decrypt edin; ElegantBouncer decrypt edilmiş bir yedek bekler.<sup>[[2]](#references)[[3]](#references)</sup>
- Delil değeri için mümkün olduğunda özgün timestamp'leri/ACL'leri koruyun

### Yedeği edinme ve decrypt etme (USB / Finder / libimobiledevice)

- Finder/Apple Devices/iTunes'ta "Encrypt local backup" seçeneğini etkinleştirin ve yeni bir yedek oluşturun; şifrelenmiş yedekler, şifrelenmemiş yedeklerin içermediği kayıtlı parolaları ve Health verilerini içerebilir.<sup>[[8]](#references)</sup>
- Cross-platform: libimobiledevice 1.4.0, `idevicebackup2` için düzeltmeler içerir.<sup>[[4]](#references)</sup> Şifrelemeyi etkileşimli olarak etkinleştirin, ardından belgelenen komut sıralamasını kullanarak tam bir yedeği zorlayın; hedef dizin en sonda olmalıdır.<sup>[[6]](#references)</sup>
```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```
### MVT ile IOC odaklı triage

Amnesty’nin Mobile Verification Toolkit’i, şifrelenmiş iTunes/Finder backup’larından bir key çıkarıp bunların şifresini çözebilir ve ardından şifresi çözülmüş backup’ı bir STIX2 IOC dosyasıyla tarayabilir.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```
`-o` ile JSON sonuçları `/tmp/mvt-results/` altına yazılır; IOC eşleşmeleri `_detected` son ekini kullanır ve aşağıda kurtarılan ek yollarıyla ilişkilendirilebilir.<sup>[[3]](#references)</sup>

### Genel artifact ayrıştırma (iLEAPP)

Mesajlaşmanın ötesindeki zaman çizelgesi/metadata için iLEAPP'i raw backup klasöründe çalıştırın; `itunes` input type, iTunes/Finder backup'larını kabul eder ve mevcut sürümler iOS/iPadOS 11'den güncel sürümlere kadar destek sunar.<sup>[[7]](#references)</sup>
```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```
## Messaging app attachment enumeration

Kurtarma işleminden sonra popüler uygulamalardaki ekleri listeleyin. Kesin şema uygulamaya/sürüme göre değişir, ancak yaklaşım benzerdir: mesajlaşma veritabanını sorgulayın, mesajları eklerle birleştirin ve disk üzerindeki yolları çözümleyin.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Ana tablolar: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ).<sup>[[2]](#references)</sup>

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
Yaygın ilişkilendirme: message table ↔ media/attachment table (adlandırma sürüme göre değişir). Disk üzerindeki yolları elde etmek için media satırlarını sorgulayın. Belkasoft, `ZWAMEDIAITEM` içindeki `ZMEDIALOCALPATH` alanını medya dosyasının konumu olarak tanımlar; ElegantBouncer’ın mevcut uygulaması, `ZWAMEDIAITEM.ZMESSAGE` ile `ZWAMESSAGE.Z_PK` alanlarını birleştirir ve `Media/` ile başlayan bir yolu çözümlerken başına `Message/` ekler.<sup>[[9]](#references)[[10]](#references)</sup>
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
For that ElegantBouncer reconstruction path, `Media/` ile başlayan bir media path'i `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` altında çözümlenir; Belkasoft’un guide'ı ise bunun yerine `Messages/Media/` path'ini belgeler, bu nedenle iki yazımdan birini varsaymadan önce backup'ı inceleyin.<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal: message DB şifrelenmiştir; ancak diskte cache'lenen attachment'lar (ve thumbnail'lar) genellikle taranabilir.<sup>[[2]](#references)</sup>
- Telegram: app'in media/cache directory'lerini inceleyin; Telegram, iOS 18.0.1 üzerindeki iOS app 11.2'de bir cache-cleanup bug'ını belgeledi ve bunun 11.3'te düzeltildiğini belirtti; bu nedenle artık dosyaları kontrol edin.<sup>[[2]](#references)[[5]](#references)</sup>
- Viber: Viber.sqlite, diskteki referansları içeren message/attachment tablolarını barındırır.<sup>[[2]](#references)</sup>

İpucu: metadata şifrelenmiş olsa bile media/cache directory'lerini taramak malicious object'leri yine de ortaya çıkarır.<sup>[[2]](#references)</sup>


## Structural exploit'ler için attachment'ları tarama

Attachment path'lerini elde ettikten sonra bunları signature'lar yerine file-format invariant'larını doğrulayan structural detector'lara aktarın. ElegantBouncer ile örnek:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Yapısal kuralların kapsadığı tespitler şunlardır:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): imkânsız JBIG2 sözlük durumları
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): aşırı büyük Huffman tablosu oluşturma işlemleri
- TrueType TRIANGULATION (CVE‑2023‑41990): belgelenmemiş bytecode opcode'ları
- DNG/TIFF CVE‑2025‑43300: metadata ve stream bileşeni uyuşmazlıkları


## Doğrulama, dikkat edilmesi gerekenler ve false positive'ler

- Zaman dönüşümleri: iMessage bazı sürümlerde tarihleri Apple epoch/birimleri kullanarak depolar; raporlama sırasında uygun dönüşümü yapın.<sup>[[2]](#references)</sup>
- Schema drift: uygulamaların SQLite şemaları zaman içinde değişir; tablo ve sütun adlarını her device build için doğrulayın
- Recursive extraction: PDF'ler JBIG2 stream'leri ve font'lar gömebilir; iç nesneleri çıkarıp tarayabilen bir parser kullanın
- False positive'ler: yapısal sezgisel yöntemler ihtiyatlıdır, ancak nadir görülen bozuk fakat zararsız media dosyalarını işaretleyebilir.<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [Örnekleri Alamadığınızda Ancak Tehdidi Yine de Tespit Etmeniz Gerektiğinde: ELEGANTBOUNCER](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer projesi (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT iOS backup iş akışı](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [libimobiledevice 1.4.0 sürüm notları](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [11.2 güncellemesi iOS 18.0.1'de cache temizleme işlemini bozdu (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)
- [6] [idevicebackup2 kılavuzu](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [iLEAPP projesi (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [iPhone, iPad veya iPod touch cihazınızdaki encrypted backup'lar hakkında (Apple Support)](https://support.apple.com/en-ie/108353)
- [9] [Belkasoft X ile iOS WhatsApp Forensics](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [ElegantBouncer WhatsApp scanner ve path resolver](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)
{{#include ../../banners/hacktricks-training.md}}
