# iOS Backup Forensics (Messaging‑centric triage)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, messaging app ekleri üzerinden 0‑click exploit iletimi belirtilerini tespit etmek amacıyla iOS backup'larını yeniden oluşturup analiz etmeye yönelik pratik adımları açıklar. Apple'ın hash'lenmiş backup düzenini okunabilir yollara dönüştürmeye, ardından yaygın uygulamalardaki ekleri listeleyip taramaya odaklanır.

Hedefler:
- Manifest.db üzerinden okunabilir yolları yeniden oluşturmak
- Messaging database'lerini listelemek (iMessage, WhatsApp, Signal, Telegram, Viber)
- Ek yollarını çözümlemek, gömülü nesneleri (PDF/Images/Fonts) çıkarmak ve bunları structural detector'lara aktarmak


## iOS backup'ını yeniden oluşturma

MobileSync altında depolanan backup'lar, insanlar tarafından okunabilir olmayan hash'lenmiş dosya adlarını kullanır. Manifest.db SQLite database'i, depolanan her nesneyi mantıksal yoluyla eşleştirir.

Üst düzey prosedür:
1) Manifest.db'yi açın ve dosya kayıtlarını okuyun (domain, relativePath, flags, fileID/hash)
2) domain + relativePath temelinde özgün klasör hiyerarşisini yeniden oluşturun
3) Depolanan her nesneyi yeniden oluşturulan yoluna kopyalayın veya hardlink oluşturun

Bu işlemi uçtan uca uygulayan bir tool ile örnek workflow (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Notlar:
- Şifreli yedekleri, extractor’a yedek parolasını sağlayarak işleyin
- Delil değerini korumak için mümkün olduğunda orijinal zaman damgalarını/ACL’leri koruyun

### Yedeği edinme ve şifresini çözme (USB / Finder / libimobiledevice)

- macOS/Finder’da "Encrypt local backup" seçeneğini etkinleştirin ve Keychain öğelerinin mevcut olması için *yeni* bir şifreli yedek oluşturun.
- Cross-platform: `idevicebackup2` (libimobiledevice ≥1.4.0), iOS 17/18 yedekleme protokolü değişikliklerini anlar ve önceki restore/backup handshake hatalarını düzeltir.<sup>[[4]](#references)</sup>
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### IOC odaklı triage with MVT

Amnesty’nin Mobile Verification Toolkit’i (mvt-ios) artık şifrelenmiş iTunes/Finder yedekleri üzerinde doğrudan çalışarak şifre çözme ve IOC eşleştirme işlemlerini paralı casus yazılım vakaları için otomatikleştiriyor.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Çıktılar `mvt-results/` altında oluşturulur (ör. `analytics_detected.json`, `safari_history_detected.json`) ve aşağıda kurtarılan attachment path'leriyle ilişkilendirilebilir.

### Genel artifact parsing (iLEAPP)

Mesajlaşmanın ötesindeki timeline/metadata için iLEAPP'i doğrudan backup folder üzerinde çalıştırın (iOS 11‑17 şemalarını destekler):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Mesajlaşma uygulaması eklerini listeleme

Yeniden oluşturma işleminden sonra popüler uygulamalardaki ekleri listeleyin. Kesin şema uygulamaya/sürüme göre değişir, ancak yaklaşım benzerdir: messaging database'i sorgulayın, mesajları eklere join edin ve disk üzerindeki yolları çözümleyin.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Temel tablolar: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

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
Ek dosya yolları mutlak olabilir veya Library/SMS/Attachments/ altındaki yeniden oluşturulan ağaca göreli olabilir.

### WhatsApp (ChatStorage.sqlite)
Yaygın ilişkilendirme: message tablosu ↔ media/attachment tablosu (adlandırma sürüme göre değişir). Disk üzerindeki yolları elde etmek için media satırlarını sorgulayın. Güncel iOS derlemeleri hâlâ `ZWAMEDIAITEM` içinde `ZMEDIALOCALPATH` değerini sunar.
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
Yollar genellikle yeniden oluşturulan yedek içinde `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` altında çözülür.

### Signal / Telegram / Viber
- Signal: mesaj DB'si şifrelenmiştir; ancak diskte önbelleğe alınan ekler (ve küçük resimler) genellikle taranabilir durumdadır
- Telegram: önbellek sandbox içinde `Library/Caches/` altında kalır; iOS 18 sürümlerinde önbellek temizleme hataları görülür, bu nedenle büyük kalıntı medya önbellekleri yaygın kanıt kaynaklarıdır<sup>[[5]](#references)</sup>
- Viber: Viber.sqlite, disk üzerindeki referansları içeren mesaj/ek tablolarına sahiptir

İpucu: metadata şifrelenmiş olsa bile medya/önbellek dizinlerini taramak kötü amaçlı nesneleri yine de ortaya çıkarır.


## Ekleri yapısal exploit'ler açısından tarama

Ek yollarına sahip olduktan sonra bunları imzalar yerine dosya biçimi değişmezlerini doğrulayan yapısal algılayıcılara iletin. ElegantBouncer ile örnek:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Yapısal kuralların kapsadığı tespitler şunlardır:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): imkânsız JBIG2 dictionary durumları
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): aşırı büyük Huffman table yapıları
- TrueType TRIANGULATION (CVE‑2023‑41990): belgelenmemiş bytecode opcode'ları
- DNG/TIFF CVE‑2025‑43300: metadata ve stream component uyumsuzlukları


## Validation, caveats, and false positives

- Time conversions: iMessage bazı sürümlerde tarihleri Apple epoch'ları/birimleriyle depolar; reporting sırasında uygun şekilde dönüştürün
- Schema drift: app SQLite şemaları zaman içinde değişir; table/column adlarını her device build'i için doğrulayın
- Recursive extraction: PDF'ler JBIG2 stream'leri ve font'lar gömebilir; iç nesneleri çıkarıp tarayın
- False positives: structural heuristic'ler conservative olsa da nadir görülen bozuk ancak zararsız media'yı işaretleyebilir<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Update 11.2 has broken cache cleanup on iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)

{{#include ../../banners/hacktricks-training.md}}
