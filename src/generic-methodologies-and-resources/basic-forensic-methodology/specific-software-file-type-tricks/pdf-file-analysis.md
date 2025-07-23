# PDF Dosya analizi

{{#include ../../../banners/hacktricks-training.md}}

**Daha fazla detay için kontrol edin:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

PDF formatı, karmaşıklığı ve verileri gizleme potansiyeli ile bilinir, bu da onu CTF adli bilişim zorlukları için bir odak noktası haline getirir. Düz metin unsurlarını, sıkıştırılmış veya şifrelenmiş olabilecek ikili nesnelerle birleştirir ve JavaScript veya Flash gibi dillerdeki betikleri içerebilir. PDF yapısını anlamak için Didier Stevens'ın [giriş materyaline](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) başvurulabilir veya bir metin düzenleyici ya da Origami gibi PDF'ye özel bir düzenleyici kullanılabilir.

PDF'lerin derinlemesine keşfi veya manipülasyonu için [qpdf](https://github.com/qpdf/qpdf) ve [Origami](https://github.com/mobmewireless/origami-pdf) gibi araçlar mevcuttur. PDF'lerde gizli veriler şunlarda gizlenebilir:

- Görünmez katmanlar
- Adobe tarafından sağlanan XMP meta veri formatı
- Artan nesil
- Arka planla aynı renkteki metin
- Resimlerin arkasındaki metin veya üst üste binen resimler
- Gösterilmeyen yorumlar

Özel PDF analizi için, [PeepDF](https://github.com/jesparza/peepdf) gibi Python kütüphaneleri, özel ayrıştırma betikleri oluşturmak için kullanılabilir. Ayrıca, PDF'nin gizli veri depolama potansiyeli o kadar geniştir ki, orijinal konumunda artık barındırılmayan NSA'nın PDF riskleri ve karşı önlemlerine dair kılavuzu bile değerli bilgiler sunmaktadır. [Kılavuzun bir kopyası](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) ve Ange Albertini'nin [PDF formatı hileleri](https://github.com/corkami/docs/blob/master/PDF/PDF.md) koleksiyonu, konu hakkında daha fazla okuma sağlayabilir.

## Yaygın Kötü Amaçlı Yapılar

Saldırganlar, belgenin açılması veya etkileşimde bulunulması durumunda otomatik olarak yürütülen belirli PDF nesnelerini ve eylemlerini sıklıkla kötüye kullanır. Aranması gereken anahtar kelimeler:

* **/OpenAction, /AA** – açıldığında veya belirli olaylarda yürütülen otomatik eylemler.
* **/JS, /JavaScript** – gömülü JavaScript (genellikle obfuscate edilmiş veya nesneler arasında bölünmüş).
* **/Launch, /SubmitForm, /URI, /GoToE** – harici işlem / URL başlatıcıları.
* **/RichMedia, /Flash, /3D** – yükleri gizleyebilen multimedya nesneleri.
* **/EmbeddedFile /Filespec** – dosya ekleri (EXE, DLL, OLE, vb.).
* **/ObjStm, /XFA, /AcroForm** – genellikle shell-code gizlemek için kötüye kullanılan nesne akışları veya formlar.
* **Artan güncellemeler** – birden fazla %%EOF işareti veya çok büyük bir **/Prev** ofseti, imzadan sonra eklenen verileri gösterebilir.

Önceki tokenlerden herhangi biri şüpheli dizelerle (powershell, cmd.exe, calc.exe, base64, vb.) birlikte ortaya çıktığında, PDF daha derin bir analiz gerektirir.

---

## Statik analiz ipucu kılavuzu
```bash
# Fast triage – keyword statistics
pdfid.py suspicious.pdf

# Deep dive – decompress/inspect the object tree
pdf-parser.py -f suspicious.pdf                # interactive
pdf-parser.py -a suspicious.pdf                # automatic report

# Search for JavaScript and pretty-print it
pdf-parser.py -search "/JS" -raw suspicious.pdf | js-beautify -

# Dump embedded files
peepdf "open suspicious.pdf" "objects embeddedfile" "extract 15 16 17" -o dumps/

# Remove passwords / encryptions before processing with other tools
qpdf --password='secret' --decrypt suspicious.pdf clean.pdf

# Lint the file with a Go verifier (checks structure violations)
pdfcpu validate -mode strict clean.pdf
```
Ekstra yararlı projeler (aktif olarak bakımda 2023-2025):
* **pdfcpu** – PDF'leri *lint*, *şifre çözme*, *çıkarma*, *sıkıştırma* ve *temizleme* yeteneğine sahip Go kütüphanesi/CLI.
* **pdf-inspector** – nesne grafiğini ve akışları render eden tarayıcı tabanlı görselleştirici.
* **PyMuPDF (fitz)** – gömülü JS'yi sertleştirilmiş bir kum havuzunda patlatmak için sayfaları güvenli bir şekilde görüntüleyebilen scriptlenebilir Python motoru.

---

## Son saldırı teknikleri (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC, tehdit aktörlerinin son **%%EOF**'dan sonra VBA makroları içeren MHT tabanlı bir Word belgesini eklediğini gözlemledi ve hem geçerli bir PDF hem de geçerli bir DOC olan bir dosya üretti. Sadece PDF katmanını ayrıştıran AV motorları makroyu atlar. Statik PDF anahtar kelimeleri temizdir, ancak `file` yine de `%PDF` yazdırır. `<w:WordDocument>` dizesini de içeren herhangi bir PDF'yi son derece şüpheli olarak değerlendirin.
* **Shadow-incremental updates (2024)** – düşmanlar, masum ilk revizyonu imzalı tutarken kötü niyetli `/OpenAction` ile ikinci bir **/Catalog** eklemek için artımlı güncelleme özelliğini kötüye kullanır. Sadece ilk xref tablosunu inceleyen araçlar atlatılır.
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – gömülü CIDType2 fontlardan erişilebilen savunmasız bir **CoolType.dll** fonksiyonu, hazırlanmış bir belge açıldığında kullanıcının ayrıcalıklarıyla uzaktan kod yürütmeye izin verir. Mayıs 2024'te APSB24-29'da yamanmıştır.

---

## YARA hızlı kural şablonu
```yara
rule Suspicious_PDF_AutoExec {
meta:
description = "Generic detection of PDFs with auto-exec actions and JS"
author      = "HackTricks"
last_update = "2025-07-20"
strings:
$pdf_magic = { 25 50 44 46 }          // %PDF
$aa        = "/AA" ascii nocase
$openact   = "/OpenAction" ascii nocase
$js        = "/JS" ascii nocase
condition:
$pdf_magic at 0 and ( all of ($aa, $openact) or ($openact and $js) )
}
```
---

## Savunma ipuçları

1. **Hızla yamanın** – Acrobat/Reader'ı en son Sürekli sürümde tutun; sahada gözlemlenen çoğu RCE zinciri, aylar önce düzeltmiş n-gün güvenlik açıklarını kullanıyor.
2. **Aktif içeriği geçitte kaldırın** – JavaScript, gömülü dosyaları ve gelen PDF'lerden başlatma eylemlerini kaldırmak için `pdfcpu sanitize` veya `qpdf --qdf --remove-unreferenced` kullanın.
3. **İçerik Silme ve Yeniden Yapılandırma (CDR)** – Aktif nesneleri atarken görsel sadakati korumak için PDF'leri bir kum havuzu ana bilgisayarında görüntülere (veya PDF/A'ya) dönüştürün.
4. **Nadir kullanılan özellikleri engelleyin** – Reader'daki kurumsal “Gelişmiş Güvenlik” ayarları, JavaScript, multimedya ve 3D renderlamayı devre dışı bırakmaya izin verir.
5. **Kullanıcı eğitimi** – sosyal mühendislik (fatura ve özgeçmiş tuzakları) başlangıç vektörü olmaya devam ediyor; çalışanlara şüpheli ekleri IR'ye iletmeyi öğretin.

## Referanslar

* JPCERT/CC – “PDF'de MalDoc – Kötü niyetli bir Word dosyasını PDF dosyasına gömerek tespit atlatma” (Ağu 2023)
* Adobe – Acrobat ve Reader için güvenlik güncellemesi (APSB24-29, Mayıs 2024)

{{#include ../../../banners/hacktricks-training.md}}
