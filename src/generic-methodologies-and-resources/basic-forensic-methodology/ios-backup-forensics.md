# iOS Yedekleme Adli Bilişim (Messaging‑centric triage)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, iOS yedeklerini mesajlaşma uygulaması ekleri aracılığıyla 0‑click exploit dağıtımına dair izler açısından yeniden oluşturmak ve analiz etmek için pratik adımları açıklar. Odak, Apple’ın hashed backup düzenini insan‑okunur yollara dönüştürmek ve ardından ortak uygulamalarda ekleri listeleyip taramaktır.

Amaçlar:
- Manifest.db'den okunabilir yolları yeniden oluşturmak
- Mesajlaşma veritabanlarını listelemek (iMessage, WhatsApp, Signal, Telegram, Viber)
- Ek yollarını çözümlemek, gömülü nesneleri çıkarmak (PDF/Görseller/Yazı tipleri) ve bunları yapısal dedektörlere vermek


## iOS yedeğinin yeniden oluşturulması

MobileSync altında saklanan yedekler, insan‑tarafından okunamayan hashed dosya adları kullanır. Manifest.db SQLite veritabanı, saklanan her nesneyi mantıksal yoluna eşler.

Genel prosedür:
1) Manifest.db'yi açın ve dosya kayıtlarını okuyun (domain, relativePath, flags, fileID/hash)  
2) domain + relativePath temel alınarak orijinal klasör hiyerarşisini yeniden oluşturun  
3) Her saklanan nesneyi yeniden oluşturulan yoluna kopyalayın veya hardlink yapın

Bunu uçtan uca uygulayan bir araçla örnek iş akışı (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Notes:
- Şifreli yedeklemeleri, yedekleme parolasını extractor'ınıza sağlayarak işleyin
- Orijinal zaman damgalarını/ACL'leri mümkünse delil değeri için koruyun


## Mesajlaşma uygulaması eklerinin listelenmesi

Yeniden oluşturma sonrası, popüler uygulamalar için ekleri listeleyin. Kesin şema uygulama/sürüme göre değişir, ancak yaklaşım benzerdir: mesajlaşma veritabanını sorgulayın, mesajları eklerle ilişkilendirin ve diskteki yolları çözün.

### iMessage (sms.db)
Key tables: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

Example queries:
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
Eklenti yolları Library/SMS/Attachments/ altında yeniden oluşturulan ağaca göre mutlak veya göreli olabilir.

### WhatsApp (ChatStorage.sqlite)
Yaygın bağlantı: message table ↔ media/attachment table (isimlendirme sürüme göre değişir). On‑disk yolları elde etmek için media satırlarını sorgulayın.

Örnek (genel):
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
Adjust table/column names to your app version (ZWAMESSAGE/ZWAMEDIAITEM are common in iOS builds).

### Signal / Telegram / Viber
- Signal: message DB şifrelenmiştir; ancak diske cached attachments (ve thumbnails) genellikle taranabilir
- Telegram: cache directories (photo/video/document caches) inceleyin ve mümkünse sohbetlere eşleyin
- Viber: Viber.sqlite, diskteki referanslarla birlikte message/attachment tabloları içerir

Tip: metadata şifreli olsa bile, media/cache dizinlerini taramak hâlâ kötü amaçlı öğeleri ortaya çıkarır.


## Scanning attachments for structural exploits

Once you have attachment paths, feed them into structural detectors that validate file‑format invariants instead of signatures. Example with ElegantBouncer:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Yapısal kurallar tarafından kapsanan tespitler şunlardır:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): mümkün olmayan JBIG2 sözlük durumları
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): aşırı büyük Huffman tablo yapıları
- TrueType TRIANGULATION (CVE‑2023‑41990): belgelendirilmeyen bytecode opcode'ları
- DNG/TIFF CVE‑2025‑43300: metadata ile stream bileşen uyumsuzlukları


## Doğrulama, çekinceler ve yanlış pozitifler

- Zaman dönüşümleri: iMessage bazı sürümlerde tarihleri Apple epoch/birimlerinde saklar; raporlama sırasında uygun şekilde dönüştürün
- Şema kayması: uygulamanın SQLite şemaları zamanla değişir; cihaz build'ine göre tablo/sütun adlarını doğrulayın
- Özyinelemeli çıkarım: PDF'ler JBIG2 stream'leri ve font'ları gömebilir; iç nesneleri çıkarın ve tarayın
- Yanlış pozitifler: yapısal heuristikler temkinlidir ancak nadir hatalı ama zararsız medya dosyalarını işaretleyebilir


## Referanslar

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)

{{#include ../../banners/hacktricks-training.md}}
