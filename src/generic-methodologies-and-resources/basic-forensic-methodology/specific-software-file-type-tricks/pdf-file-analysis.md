# PDF Dosyası analizi

{{#include ../../../banners/hacktricks-training.md}}

**Daha fazla ayrıntı için şuraya bakın:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

PDF formatı, karmaşıklığı ve verileri gizleme potansiyeliyle bilinir ve bu da onu CTF forensics challenge'larında önemli bir odak noktası hâline getirir. Düz metin öğelerini, sıkıştırılmış veya şifrelenmiş olabilecek binary nesnelerle birleştirir ve JavaScript veya Flash gibi dillerde yazılmış script'leri içerebilir. PDF yapısını anlamak için Didier Stevens'ın [giriş materyaline](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) başvurulabilir veya bir text editor ya da Origami gibi PDF'ye özel bir editor kullanılabilir.

PDF'leri derinlemesine incelemek veya değiştirmek için [qpdf](https://github.com/qpdf/qpdf) ve [Origami](https://github.com/mobmewireless/origami-pdf) gibi araçlar kullanılabilir. PDF'lerin içindeki gizli veriler şu şekillerde saklanabilir:

- Görünmez katmanlar
- Adobe tarafından kullanılan XMP metadata formatı
- Incremental generation'lar
- Arka planla aynı renkteki text
- Görsellerin arkasındaki veya üst üste binen görsellerin içindeki text
- Görüntülenmeyen yorumlar

Özel PDF analizi için, [PeepDF](https://github.com/jesparza/peepdf) gibi Python kütüphaneleri özel parsing script'leri oluşturmak amacıyla kullanılabilir. Ayrıca PDF'lerin gizli veri depolama potansiyeli o kadar geniştir ki, artık orijinal konumunda barındırılmayan PDF riskleri ve karşı önlemleri hakkındaki NSA guide'ı bile hâlâ değerli bilgiler sunar. [Guide'ın bir kopyası](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) ve Ange Albertini tarafından hazırlanan [PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) koleksiyonu konu hakkında daha fazla okuma sağlayabilir.<sup>[[4]](#references)[[5]](#references)</sup>

## Yaygın Kötü Amaçlı Yapılar

Saldırganlar, document açıldığında veya document ile etkileşime girildiğinde otomatik olarak yürütülen belirli PDF nesnelerini ve action'ları sıklıkla kötüye kullanır. Aranması gereken önemli keyword'ler:

* **/OpenAction, /AA** – açılışta veya belirli event'lerde yürütülen otomatik action'lar.
* **/JS, /JavaScript** – gömülü JavaScript (genellikle obfuscate edilmiş veya nesneler arasında bölünmüş).
* **/Launch, /SubmitForm, /URI, /GoToE** – harici process / URL launcher'ları.
* **/RichMedia, /Flash, /3D** – payload'ları gizleyebilen multimedia nesneleri.
* **/EmbeddedFile /Filespec** – file attachment'ları (EXE, DLL, OLE vb.).
* **/ObjStm, /XFA, /AcroForm** – shell-code gizlemek için sıklıkla kötüye kullanılan object stream'leri veya form'lar.
* **Incremental update'ler** – birden fazla %%EOF marker'ı veya çok büyük bir **/Prev** offset'i, AV'yi atlatmak amacıyla signing işleminden sonra data eklendiğini gösterebilir.

Önceki token'lardan herhangi biri şüpheli string'lerle (powershell, cmd.exe, calc.exe, base64 vb.) birlikte göründüğünde PDF daha derinlemesine analiz edilmelidir.

---

## Statik analiz hızlı başvuru rehberi
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
Ek yararlı projeler (aktif olarak 2023-2025 döneminde maintained):
* **pdfcpu** – PDF'leri *lint*, *decrypt*, *extract*, *compress* ve *sanitize* edebilen Go library/CLI.
* **pdf-inspector** – object graph ve streams'i oluşturan browser-based visualizer.
* **PyMuPDF (fitz)** – embedded JS'i hardened sandbox içinde çalıştırmak için sayfaları güvenli bir şekilde image'lara dönüştürebilen scriptable Python engine.

---

## Recent attack techniques (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC, threat actor'ların son **%%EOF** sonrasına VBA macro'ları içeren MHT-based bir Word document ekleyerek hem geçerli bir PDF hem de geçerli bir DOC olan bir file oluşturduğunu gözlemledi. Yalnızca PDF layer'ını parse eden AV engine'leri macro'yu kaçırır. Static PDF keywords temizdir, ancak `file` yine de `%PDF` yazdırır. Ayrıca `<w:WordDocument>` string'ini içeren herhangi bir PDF'yi highly suspicious olarak değerlendirin.<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – adversary'ler, benign first revision'ı signed olarak korurken malicious `/OpenAction` içeren ikinci bir **/Catalog** eklemek için incremental update özelliğini abuse eder. Yalnızca ilk xref table'ı inspect eden tools bypass edilir.
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – vulnerable bir **CoolType.dll** function'a embedded CIDType2 fonts üzerinden ulaşılabilir; bu da crafted bir document açıldığında user'ın privileges'larıyla remote code execution sağlar. APSB24-29 kapsamında Mayıs 2024'te patched edilmiştir.<sup>[[3]](#references)</sup>

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

1. **Hızlıca patch uygulayın** – Acrobat/Reader'ı en güncel Continuous track üzerinde tutun; gerçek dünyada gözlemlenen RCE zincirlerinin çoğu, aylar önce düzeltilmiş n-day güvenlik açıklarından yararlanır.
2. **Gateway'de active content'i kaldırın** – Gelen PDF'lerden JavaScript'i, gömülü dosyaları ve launch action'larını kaldırmak için `pdfcpu sanitize` veya `qpdf --qdf --remove-unreferenced` kullanın.
3. **Content Disarm & Reconstruction (CDR)** – Görsel bütünlüğü korurken active object'leri atmak için PDF'leri bir sandbox host üzerinde görüntülere (veya PDF/A'ya) dönüştürün.
4. **Nadiren kullanılan özellikleri engelleyin** – Reader'daki kurumsal “Enhanced Security” ayarları, JavaScript'in, multimedyanın ve 3D rendering'in devre dışı bırakılmasına olanak tanır.
5. **Kullanıcı eğitimi** – Social engineering (fatura ve özgeçmiş tuzakları) ilk vektör olmaya devam ediyor; çalışanlara şüpheli ekleri IR ekibine iletmeyi öğretin.

## Referanslar

- [1] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Kötü amaçlı bir Word dosyasını PDF dosyasına gömerek detection bypass](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Adobe Acrobat ve Reader için güvenlik güncellemesi mevcut (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - kılavuzun kopyası](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - PDF format hileleri](https://github.com/corkami/docs/blob/master/PDF/PDF.md)

{{#include ../../../banners/hacktricks-training.md}}
