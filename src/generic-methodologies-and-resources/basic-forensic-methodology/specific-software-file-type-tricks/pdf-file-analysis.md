# PDF Dosyası analizi

{{#include ../../../banners/hacktricks-training.md}}

**Daha fazla ayrıntı için şuraya bakın:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

PDF formatı, karmaşıklığı ve verileri gizleme potansiyeliyle bilinir; bu da onu CTF forensics challenge'ları için önemli bir odak noktası hâline getirir. Düz metin öğelerini, sıkıştırılmış veya şifrelenmiş olabilecek binary nesnelerle birleştirir ve JavaScript veya Flash gibi dillerde script'ler içerebilir. PDF yapısını anlamak için Didier Stevens'ın [giriş materyaline](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) başvurulabilir veya bir text editor ya da Origami gibi PDF'ye özgü bir editor kullanılabilir.

PDF'leri derinlemesine incelemek veya değiştirmek için [qpdf](https://github.com/qpdf/qpdf) ve [Origami](https://github.com/mobmewireless/origami-pdf) gibi araçlar kullanılabilir. PDF'lerdeki gizli veriler şu şekillerde saklanabilir:

- Görünmez katmanlar
- Adobe'nin XMP metadata formatı
- Incremental generation'lar
- Arka planla aynı renkteki metinler
- Görsellerin arkasındaki metinler veya üst üste binen görseller
- Görüntülenmeyen yorumlar

Özel PDF analizi için, [PeepDF](https://github.com/jesparza/peepdf) gibi Python kütüphaneleri özel parsing script'leri oluşturmak amacıyla kullanılabilir. Ayrıca PDF'nin gizli veri depolama potansiyeli o kadar geniştir ki, artık orijinal konumunda barındırılmayan PDF riskleri ve karşı önlemleri hakkındaki NSA rehberi gibi kaynaklar hâlâ değerli bilgiler sunar. Ange Albertini tarafından hazırlanan [rehberin bir kopyası](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) ve bir [PDF format tricks koleksiyonu](https://github.com/corkami/docs/blob/master/PDF/PDF.md) konu hakkında daha fazla okuma sağlayabilir.

## Yaygın Malicious Construct'lar

Attackers, document açıldığında veya document ile etkileşime girildiğinde otomatik olarak çalışan belirli PDF nesnelerini ve action'ları sıklıkla abuse eder. Aranması gereken keyword'ler:

* **/OpenAction, /AA** – açılışta veya belirli event'lerde çalıştırılan automatic action'lar.
* **/JS, /JavaScript** – gömülü JavaScript (genellikle obfuscated veya nesneler arasında bölünmüş).
* **/Launch, /SubmitForm, /URI, /GoToE** – external process / URL launcher'ları.
* **/RichMedia, /Flash, /3D** – payload'ları gizleyebilen multimedia nesneleri.
* **/EmbeddedFile /Filespec** – file attachment'ları (EXE, DLL, OLE vb.).
* **/ObjStm, /XFA, /AcroForm** – shell-code gizlemek için sıklıkla abuse edilen object stream'leri veya form'lar.
* **Incremental updates** – birden fazla %%EOF marker'ı veya çok büyük bir **/Prev** offset'i, AV'yi bypass etmek amacıyla signing sonrasında eklenmiş verilere işaret edebilir.

Önceki token'lardan herhangi biri suspicious string'lerle (powershell, cmd.exe, calc.exe, base64 vb.) birlikte göründüğünde PDF daha derinlemesine analiz edilmelidir.

---

## Static analysis cheat-sheet
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
Ek yararlı projects (aktif olarak 2023-2025 arasında sürdürülen):
* **pdfcpu** – PDF'leri *lint* edebilen, *decrypt* edebilen, *extract* edebilen, *compress* edebilen ve *sanitize* edebilen Go library/CLI.
* **pdf-inspector** – object graph ve streams'leri oluşturan browser-based visualizer.
* **PyMuPDF (fitz)** – gömülü JS'yi hardened sandbox içinde güvenli şekilde detonate etmek üzere sayfaları görsellere render edebilen scriptable Python engine.

---

## Recent attack techniques (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC, threat actors'ın son **%%EOF** sonrasına VBA macros içeren MHT-based Word document eklediğini gözlemledi; böylece hem geçerli bir PDF hem de geçerli bir DOC olan bir file üretiliyor. Yalnızca PDF layer'ını parse eden AV engines macro'yu kaçırıyor. Static PDF keywords temiz görünse de `file` hâlâ `%PDF` çıktısını veriyor. `<w:WordDocument>` string'ini de içeren tüm PDF'leri highly suspicious kabul edin.<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – adversaries, benign first revision signed durumunu korurken malicious `/OpenAction` içeren ikinci bir **/Catalog** eklemek için incremental update özelliğini abuse ediyor. Yalnızca ilk xref table'ını inspect eden tools bypass ediliyor.
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – vulnerable bir **CoolType.dll** function'ına embedded CIDType2 fonts üzerinden ulaşılabilir; crafted bir document açıldığında user privileges ile remote code execution elde edilebilir. APSB24-29 kapsamında Mayıs 2024'te patch'lendi.<sup>[[3]](#references)</sup>

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

1. **Hızlı patch uygulayın** – Acrobat/Reader'ı en güncel Continuous track üzerinde tutun; doğada gözlemlenen çoğu RCE zinciri, aylar önce düzeltilmiş n-day güvenlik açıklarından yararlanır.
2. **Gateway'de active content'i kaldırın** – gelen PDF'lerden JavaScript, embedded files ve launch actions öğelerini kaldırmak için `pdfcpu sanitize` veya `qpdf --qdf --remove-unreferenced` kullanın.
3. **Content Disarm & Reconstruction (CDR)** – görsel doğruluğu korurken active objects öğelerini atmak için PDF'leri bir sandbox host üzerinde görüntülere (veya PDF/A'ya) dönüştürün.
4. **Nadiren kullanılan özellikleri engelleyin** – Reader'daki kurumsal “Enhanced Security” ayarları JavaScript, multimedia ve 3D rendering özelliklerinin devre dışı bırakılmasına izin verir.
5. **Kullanıcı eğitimi** – social engineering (invoice ve resume lure'ları) ilk vector olmaya devam ediyor; çalışanlara şüpheli ekleri IR ekibine iletmelerini öğretin.

## Referanslar

- [1] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Detection bypass by embedding a malicious Word file into a PDF file](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Security update available for Adobe Acrobat and Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)

{{#include ../../../banners/hacktricks-training.md}}
