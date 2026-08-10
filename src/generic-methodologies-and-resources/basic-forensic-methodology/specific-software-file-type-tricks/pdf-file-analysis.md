# PDF dosya analizi

**Daha fazla ayrıntı için:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

PDF formatı, karmaşıklığı ve verileri gizleme potansiyeliyle bilinir; bu da onu CTF forensics görevlerinin odak noktalarından biri hâline getirir. Düz metin öğelerini, sıkıştırılmış veya şifrelenmiş olabilen binary nesnelerle birleştirir ve JavaScript veya Flash gibi dillerde scriptler içerebilir. PDF yapısını anlamak için Didier Stevens'ın [giriş materyaline](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) başvurulabilir veya bir text editor ya da Origami gibi PDF'ye özel bir editor kullanılabilir.

PDF'leri derinlemesine incelemek veya değiştirmek için [qpdf](https://github.com/qpdf/qpdf) ve [Origami](https://github.com/mobmewireless/origami-pdf) gibi araçlar kullanılabilir. PDF'lerdeki gizli veriler şu konumlarda saklanabilir:

- Görünmez katmanlar
- Adobe'nin XMP metadata formatı
- Incremental generations
- Arka planla aynı renkteki metinler
- Görsellerin arkasındaki veya üst üste binen görseller
- Görüntülenmeyen yorumlar

Özel PDF analizi için [PeepDF](https://github.com/jesparza/peepdf) gibi Python kütüphaneleri, amaca özel parsing scriptleri oluşturmak için kullanılabilir. Ayrıca PDF'nin gizli veri depolama potansiyeli o kadar geniştir ki, artık orijinal konumunda barındırılmıyor olsa da PDF riskleri ve karşı önlemleri hakkındaki NSA rehberi hâlâ değerli bilgiler sunar. Bir [rehber kopyası](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) ve Ange Albertini tarafından hazırlanan [PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) derlemesi, konu hakkında daha fazla okuma sağlayabilir.<sup>[[4]](#references)[[5]](#references)</sup>

## Yaygın Malicious Constructs

Saldırganlar, belge açıldığında veya belgeyle etkileşim kurulduğunda otomatik olarak çalıştırılan belirli PDF nesnelerini ve action'ları sıklıkla abuse eder. Aranması gereken keyword'ler:

* **/OpenAction, /AA** – açılışta veya belirli event'lerde çalıştırılan otomatik action'lar.
* **/JS, /JavaScript** – gömülü JavaScript (genellikle obfuscate edilmiş veya nesneler arasında bölünmüş).
* **/Launch, /SubmitForm, /URI, /GoToE** – harici process / URL launch mekanizmaları.
* **/RichMedia, /Flash, /3D** – payload'ları gizleyebilen multimedia nesneleri.
* **/EmbeddedFile /Filespec** – file attachment'ları (EXE, DLL, OLE vb.).
* **/ObjStm, /XFA, /AcroForm** – shell-code gizlemek için sıklıkla abuse edilen object stream'leri veya formlar.
* **Incremental updates** – birden fazla %%EOF marker'ı veya çok büyük bir **/Prev** offset'i, AV'yi bypass etmek amacıyla imzalama işleminden sonra veri eklendiğini gösterebilir.

Önceki token'lardan herhangi biri suspicious string'lerle (powershell, cmd.exe, calc.exe, base64 vb.) birlikte göründüğünde PDF daha derin bir analizi hak eder.

---

## Static analysis cheat-sheet

Aşağıdaki örneklerde belgelenmiş `pdf-parser.py`, qpdf ve pdfcpu command-line interface'leri kullanılmaktadır.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>
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
Ek yararlı projeler (2023-2025 döneminde aktif olarak sürdürülen):
* **pdfcpu** – PDF'leri doğrulayabilen, şifrelerini çözebilen, çıkarabilen, optimize edebilen ve değiştirebilen Go kütüphanesi/CLI aracı.<sup>[[9]](#references)</sup>
* **pdf-inspector** – nesne grafiğini ve stream'leri oluşturan, tarayıcı tabanlı görselleştirici.
* **PyMuPDF** – PDF'leri incelemek ve sayfaları raster görüntülere dönüştürmek için script yazılabilir Python bindings. Parser/renderer'ı güvenilmeyen dosya saldırı yüzeyi olarak değerlendirin ve uygun şekilde izole edilmiş bir analiz ortamı içinde çalıştırın.<sup>[[8]](#references)</sup>

---

## Güncel saldırı teknikleri (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC, Word ile oluşturulmuş ve VBA macro'ları içeren bir MHT dosyasını PDF'ye ekleyen; PDF magic'ini korurken dosyanın Word'de de açılmasını sağlayan bir teknik bildirdi. Yalnızca PDF analizi yapan araçlar, sandbox'lar veya antivirus yazılımları macro'yu gözden kaçırabilir; çünkü kötü amaçlı davranış dosya Word olarak açıldığında gerçekleşir. Diğer MHT göstergeleriyle birlikte `<w:WordDocument>` marker'ını arayın.<sup>[[2]](#references)</sup>
* **İmzalı PDF'lere yönelik Shadow attacks** – saldırganlar, PDF imzalanmadan önce içine gizli içerik yerleştirebilir, ardından catalog veya object referanslarını değiştiren bir incremental update ekleyebilir. Böylece görüntüleyiciler gizli içeriği gösterirken özgün imza geçerliliğini korur. Bu teknik, bu tür güncellemeleri zararsız olarak sınıflandıran görüntüleyicilerden kaçabilir.<sup>[[6]](#references)</sup>
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

1. **Hızlıca patch uygulayın** – Acrobat/Reader'ı en güncel Continuous track üzerinde tutun; wild ortamında gözlemlenen çoğu RCE zinciri, aylar önce düzeltilmiş n-day güvenlik açıklarından yararlanır.
2. **Active content'ı gateway'de temizleyin** – JavaScript, embedded files, launch actions, forms ve multimedia'yı açıkça kaldıran, amaca özel ve policy-controlled bir sanitizer veya CDR ürünü kullanın. `qpdf --qdf`, PDF nesnelerinin incelenmesini kolaylaştırırken pdfcpu doğrulama ve değiştirme özellikleri sağlar; ancak bu komutların hiçbiri tek başına active content'ın kaldırıldığını kanıtlamaz.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – Görsel doğruluğu korurken active objects'leri kaldırmak için PDF'leri bir sandbox host üzerinde images'e (veya PDF/A'ya) dönüştürün.
4. **Nadiren kullanılan özellikleri engelleyin** – Reader'daki kurumsal “Enhanced Security” ayarları JavaScript, multimedia ve 3D rendering'in devre dışı bırakılmasına olanak tanır.
5. **Kullanıcı eğitimi** – Social engineering (invoice ve resume lure'ları) başlangıç vektörü olmaya devam ediyor; çalışanlara şüpheli attachment'ları IR ekibine iletmeyi öğretin.

## References

- [1] [Forensics CTF Saha Rehberi](https://trailofbits.github.io/ctf/forensics/)
- [2] [PDF içinde MalDoc – Kötü amaçlı bir Word dosyasının PDF dosyasına gömülmesiyle detection bypass](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Adobe Acrobat ve Reader için security update mevcut (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - rehberin kopyası](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - PDF format hileleri](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: İmzalı PDF'lerde içeriği gizleme ve değiştirme](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [PyMuPDF Tutorial](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [qpdf command-line options](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
