# iOS Yedek Adli Bilişim (Messaging‑centric triage)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, mesajlaşma uygulaması ekleri aracılığıyla 0‑click exploit teslimatına işaret eden kanıtlar için iOS yedeklerini yeniden oluşturmak ve analiz etmek üzere pratik adımları açıklar. Odak, Apple’ın hashed yedek düzenini insan tarafından okunabilir yollara dönüştürmek ve ardından yaygın uygulamalar genelinde ekleri listeleyip taramaktır.

Goals:
- Manifest.db'den okunabilir yolları yeniden oluşturmak
- Mesajlaşma veritabanlarını listelemek (iMessage, WhatsApp, Signal, Telegram, Viber)
- Ek yollarını çözümlemek, gömülü nesneleri çıkarmak (PDF/Images/Fonts) ve bunları yapısal detektörlere vermek


## iOS yedeğinin yeniden oluşturulması

MobileSync altında saklanan yedekler, insanlar tarafından okunamayan hashed dosya adları kullanır. Manifest.db SQLite veritabanı, depolanan her nesneyi mantıksal yoluna eşler.

Yüksek seviyeli prosedür:
1) Manifest.db'yi açın ve dosya kayıtlarını okuyun (domain, relativePath, flags, fileID/hash)
2) domain + relativePath'e dayanarak orijinal klasör hiyerarşisini yeniden oluşturun
3) Her depolanan nesneyi yeniden oluşturulan yoluna kopyalayın veya hardlink oluşturun

Bu uçtan uca işlemi uygulayan bir araç ile örnek iş akışı (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Notlar:
- Şifreli yedekleri, extractor'ınıza yedek parolasını vererek işleyin
- Delil değeri için mümkün olduğunda orijinal zaman damgalarını/ACL'leri koruyun

### Yedeğin edinilmesi & şifre çözümü (USB / Finder / libimobiledevice)

- On macOS/Finder set "Encrypt local backup" and create a *taze* şifreli yedekleme so keychain items are present.
- Çapraz platform: `idevicebackup2` (libimobiledevice ≥1.4.0) iOS 17/18 yedek protokolü değişikliklerini anlar ve önceki restore/backup el sıkışma hatalarını düzeltir.
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### IOC‑driven triage ile MVT

Amnesty’s Mobile Verification Toolkit (mvt-ios) artık şifrelenmiş iTunes/Finder backups üzerinde doğrudan çalışıyor, paralı spyware vakaları için şifre çözmeyi ve IOC eşleştirmesini otomatikleştiriyor.
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Çıktılar `mvt-results/` altında yer alır (ör. analytics_detected.json, safari_history_detected.json) ve aşağıda kurtarılan ek dosya yolları ile ilişkilendirilebilir.

### Genel artefakt ayrıştırma (iLEAPP)

Mesajlaşmanın ötesindeki zaman çizelgesi ve meta veriler için, yedek klasörü üzerinde doğrudan iLEAPP'i çalıştırın (iOS 11‑17 şemalarını destekler):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Mesajlaşma uygulaması eklerinin listelenmesi

Yeniden yapılandırmadan sonra, popüler uygulamalar için ekleri listeleyin. Tam şema uygulama/sürüme göre değişir, ancak yaklaşım benzerdir: mesajlaşma veritabanını sorgulayın, mesajları eklerle birleştirin ve disk üzerindeki yolları çözümleyin.

### iMessage (sms.db)
Ana tablolar: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

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
Eklenti yolları Library/SMS/Attachments/ altında yeniden oluşturulmuş ağaca göre mutlak veya göreli olabilir.

### WhatsApp (ChatStorage.sqlite)
Yaygın bağlantı: mesaj tablosu ↔ medya/ek tablosu (adlandırma sürüme göre değişir). Diskteki yolları elde etmek için medya satırlarını sorgulayın. Güncel iOS build'ları hâlâ `ZMEDIALOCALPATH`'i `ZWAMEDIAITEM` içinde ortaya çıkarıyor.
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
- Signal: mesaj DB şifreli; ancak diskte cache'lenen ekler (ve thumbnails) genellikle taranabilir
- Telegram: cache sandbox içinde `Library/Caches/` altında kalır; iOS 18 build'larında cache temizleme hataları görülüyor, bu yüzden büyük artakalan medya cache'leri yaygın delil kaynaklarıdır
- Viber: Viber.sqlite, diskte referanslar içeren message/attachment tabloları içerir

İpucu: metadata şifreli olsa bile, media/cache dizinlerini taramak hâlâ zararlı nesneleri ortaya çıkarır.


## Ekleri structural exploits için tarama

Ek yollarını elde ettikten sonra, bunları signature'lar yerine file‑format invariants doğrulayan structural detectors'a verin. ElegantBouncer örneği:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Yapısal kurallarla kapsanan tespitler şunlardır:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): imkansız JBIG2 sözlük durumları
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): aşırı büyük Huffman tablo yapıları
- TrueType TRIANGULATION (CVE‑2023‑41990): belgelendirilmemiş bytecode opcode'ları
- DNG/TIFF CVE‑2025‑43300: metadata ile stream bileşeni uyumsuzlukları


## Doğrulama, uyarılar ve yanlış pozitifler

- Zaman dönüşümleri: iMessage bazı sürümlerde tarihleri Apple epoklarında/birimlerinde saklar; raporlama sırasında uygun şekilde dönüştürün
- Şema kayması: uygulama SQLite şemaları zamanla değişir; cihaz build'ine göre tablo/sütun adlarını doğrulayın
- Özyinelemeli çıkarma: PDFs JBIG2 akışları ve fontlar içerebilir; iç nesneleri çıkarın ve tarayın
- Yanlış pozitifler: yapısal sezgiler muhafazakardır ancak nadir hatalı fakat zararsız medya örneklerini işaretleyebilir


## Referanslar

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)

{{#include ../../banners/hacktricks-training.md}}
