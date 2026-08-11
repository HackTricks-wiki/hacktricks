# PDF File analysis

{{#include ../../../banners/hacktricks-training.md}}

**Daha fazla ayrıntı için şuraya bakın:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

PDF formatı, karmaşıklığı ve verileri gizleme potansiyeliyle bilinir ve bu da onu CTF forensics görevlerinin odak noktalarından biri yapar. Sıkıştırılmış veya şifrelenmiş olabilen düz metin öğelerini binary nesnelerle birleştirir ve JavaScript veya Flash gibi dillerde script'ler içerebilir. PDF yapısını anlamak için Didier Stevens'ın [giriş materyaline](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) başvurulabilir veya bir text editor ya da Origami gibi PDF'ye özgü bir editor kullanılabilir.

PDF'leri derinlemesine incelemek veya değiştirmek için [qpdf](https://github.com/qpdf/qpdf) ve [Origami](https://github.com/mobmewireless/origami-pdf) gibi araçlar kullanılabilir. PDF'lerdeki gizli veriler şuralarda saklanabilir:

- Görünmez katmanlar
- Adobe'nin XMP metadata formatı
- Incremental generation'lar
- Arka planla aynı renkteki text
- Görsellerin arkasındaki veya üst üste binen görsellerin içindeki text
- Görüntülenmeyen comment'ler

Özel PDF analizi için, [PeepDF](https://github.com/jesparza/peepdf) gibi Python kütüphaneleri özel parsing script'leri oluşturmak amacıyla kullanılabilir. Ayrıca PDF'nin gizli veri depolama potansiyeli o kadar geniştir ki, artık orijinal konumunda barındırılmayan PDF riskleri ve karşı önlemleri hakkındaki NSA guide gibi kaynaklar hâlâ değerli bilgiler sunar. Bir [guide kopyası](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) ve Ange Albertini tarafından hazırlanan bir [PDF format tricks koleksiyonu](https://github.com/corkami/docs/blob/master/PDF/PDF.md) konu hakkında daha fazla okuma sağlayabilir.<sup>[[4]](#references)[[5]](#references)</sup>

## Common Malicious Constructs

Saldırganlar, document açıldığında veya document ile etkileşime geçildiğinde otomatik olarak çalışan belirli PDF nesnelerini ve action'ları sıklıkla kötüye kullanır. Aranması gereken keyword'ler:

* **/OpenAction, /AA** – açılışta veya belirli event'lerde yürütülen automatic action'lar.
* **/JS, /JavaScript** – gömülü JavaScript (çoğunlukla obfuscate edilmiş veya nesneler arasında bölünmüş).
* **/Launch, /SubmitForm, /URI, /GoToE** – external process / URL launcher'ları.
* **/RichMedia, /Flash, /3D** – payload'ları gizleyebilen multimedia nesneleri.
* **/EmbeddedFile /Filespec** – file attachment'ları (EXE, DLL, OLE vb.).
* **/ObjStm, /XFA, /AcroForm** – shell-code gizlemek için sıklıkla kötüye kullanılan object stream'leri veya form'lar.
* **Incremental updates** – birden fazla %%EOF marker'ı veya çok büyük bir **/Prev** offset'i, AV'yi atlatmak amacıyla signing işleminden sonra data eklendiğini gösterebilir.

Önceki token'lardan herhangi biri şüpheli string'lerle (powershell, cmd.exe, calc.exe, base64 vb.) birlikte göründüğünde PDF daha derinlemesine analiz edilmelidir.

---

## Static analysis cheat-sheet

Aşağıdaki örneklerde belgelenmiş `pdf-parser.py`, qpdf ve pdfcpu command-line interface'leri kullanılır.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
# Fast triage – keyword statistics
pdfid.py suspicious.pdf

# Deep dive – pass supported streams through their declared filters
pdf-parser.py -f suspicious.pdf
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
Ek kullanışlı projeler (2023-2025 döneminde aktif olarak bakımı yapılan):
* **pdfcpu** – PDF'leri doğrulayabilen, şifrelerini çözebilen, ayıklayabilen, optimize edebilen ve değiştirebilen Go library/CLI.<sup>[[9]](#references)</sup>
* **pdf-inspector** – object graph'ı ve stream'leri oluşturan browser-based visualizer.
* **PyMuPDF** – PDF'leri incelemek ve sayfaları raster image'lara dönüştürmek için scriptable Python bindings. Parser/renderer'ı güvenilmeyen dosya attack surface'ı olarak değerlendirin ve uygun şekilde izole edilmiş bir analysis environment içinde çalıştırın.<sup>[[8]](#references)</sup>

---

## Recent attack techniques (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC, Word-created bir MHT file'ını VBA macros ile bir PDF'ye ekleyen ve hem PDF magic'i korurken hem de Word'de açılmasını sağlayan bir technique bildirdi. PDF-only analysis tools, sandboxes veya antivirus macro'yu gözden kaçırabilir; çünkü malicious behavior Word olarak açıldığında gerçekleşir. Diğer MHT indicators ile birlikte `<w:WordDocument>` marker'ını arayın.<sup>[[2]](#references)</sup>
* **Shadow attacks on signed PDFs** – attackers, bir PDF imzalanmadan önce içine hidden content yerleştirebilir, ardından catalog veya object references'ı değiştiren bir incremental update ekleyebilir; böylece viewers, original signature geçerli kalırken hidden content'i görüntüler. Bu technique, bu tür updates'leri harmless olarak sınıflandıran viewers'ları atlatabilir.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe, bu critical vulnerability'yi arbitrary code execution'a yol açabilen bir use-after-free olarak derecelendiriyor; APSB24-29, 14 Mayıs 2024'te yayımlandı.<sup>[[3]](#references)</sup>

---

## YARA quick rule template
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

1. **Hızlı patch uygulayın** – Acrobat/Reader'ı en güncel Continuous track üzerinde tutun; gerçek dünyada gözlemlenen RCE zincirlerinin çoğu, aylar önce düzeltilmiş n-day güvenlik açıklarından yararlanır.
2. **Gateway'de active content'i kaldırın** – JavaScript, embedded files, launch actions, forms ve multimedia öğelerini açıkça kaldıran, amaca yönelik ve policy-controlled bir sanitizer veya CDR ürünü kullanın. `qpdf --qdf`, PDF nesnelerinin incelenmesini kolaylaştırırken pdfcpu doğrulama ve değiştirme özellikleri sunar; ancak bu komutların hiçbiri tek başına active content'in kaldırıldığının kanıtı değildir.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – Görsel doğruluğu korurken active objects öğelerini atmak için PDF'leri bir sandbox host üzerinde image'lara (veya PDF/A'ya) dönüştürün.
4. **Nadiren kullanılan özellikleri engelleyin** – Reader'daki kurumsal “Enhanced Security” ayarları JavaScript, multimedia ve 3D rendering özelliklerinin devre dışı bırakılmasına olanak tanır.
5. **Kullanıcı eğitimi** – Social engineering (invoice ve resume tuzakları) başlangıç vektörü olmaya devam ediyor; çalışanlara şüpheli attachment'ları IR ekibine iletmeyi öğretin.

## References

- [1] [Forensics CTF Saha Rehberi](https://trailofbits.github.io/ctf/forensics/)
- [2] [PDF içindeki MalDoc – Kötü amaçlı bir Word dosyasını PDF dosyasına gömerek Detection bypass](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Adobe Acrobat ve Reader için Security update mevcut (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - rehberin kopyası](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - PDF format hileleri](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: İmzalı PDF'lerde İçeriği Gizleme ve Değiştirme](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [PyMuPDF Tutorial](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [qpdf command-line seçenekleri](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
