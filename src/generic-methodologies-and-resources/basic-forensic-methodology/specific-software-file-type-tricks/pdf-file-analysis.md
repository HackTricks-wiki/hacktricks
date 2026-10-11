# PDF dosyası analizi

{{#include ../../../banners/hacktricks-training.md}}

**Daha fazla ayrıntı için şu kaynağa bakın:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

PDF formatı, karmaşıklığı ve verileri gizleme potansiyeliyle bilinir; bu nedenle CTF adli bilişim görevlerinde sıkça karşımıza çıkar. Sıkıştırılmış veya şifrelenmiş olabilen düz metin öğelerini ikili nesnelerle birleştirir ve JavaScript veya Flash gibi dillerde komut dosyaları içerebilir. PDF yapısını anlamak için Didier Stevens'ın [giriş materyaline](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) başvurabilir veya bir metin düzenleyici ya da Origami gibi PDF'ye özel bir düzenleyici kullanabilirsiniz.

PDF'leri ayrıntılı incelemek veya değiştirmek için [qpdf](https://github.com/qpdf/qpdf) ve [Origami](https://github.com/mobmewireless/origami-pdf) gibi araçlar kullanılabilir. PDF'lerdeki gizli veriler şuralarda saklanabilir:

- Görünmez katmanlar
- Adobe'nin XMP metadata formatı
- Artımlı nesil sürümleri
- Arka planla aynı renkteki metinler
- Görsellerin arkasındaki veya üst üste bindirilmiş görsellerdeki metinler
- Görüntülenmeyen yorumlar

Özel PDF analizi için [PeepDF](https://github.com/jesparza/peepdf) gibi Python kütüphaneleriyle amaca özel ayrıştırma betikleri yazılabilir. Ayrıca PDF'lerin gizli veri depolama potansiyeli o kadar geniştir ki, artık ilk konumunda barındırılmasa da NSA'nın PDF riskleri ve karşı önlemleri hakkındaki kılavuzu hâlâ değerli bilgiler sunar. Konuyla ilgili daha fazla bilgi için [kılavuzun bir kopyası](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) ve Ange Albertini'nin derlediği [PDF formatı hileleri](https://github.com/corkami/docs/blob/master/PDF/PDF.md) incelenebilir.<sup>[[4]](#references)[[5]](#references)</sup>

## Yaygın Kötü Amaçlı Yapılar

Saldırganlar, belge açıldığında veya belgeyle etkileşim kurulduğunda otomatik olarak çalışan belirli PDF nesnelerini ve eylemlerini sıklıkla kötüye kullanır. Aranması gereken anahtar sözcükler:

* **/OpenAction, /AA** – belge açıldığında veya belirli olaylarda yürütülen otomatik eylemler.
* **/JS, /JavaScript** – gömülü JavaScript (genellikle karmaşıklaştırılmış veya nesneler arasında bölünmüş).
* **/Launch, /SubmitForm, /URI, /GoToE** – harici süreç / URL başlatıcıları.
* **/RichMedia, /Flash, /3D** – payload'ları gizleyebilen multimedya nesneleri.
* **/EmbeddedFile /Filespec** – dosya ekleri (EXE, DLL, OLE vb.).
* **/ObjStm, /XFA, /AcroForm** – shell-code gizlemek için sıklıkla kötüye kullanılan nesne akışları veya formlar.
* **Artımlı güncellemeler** – birden fazla %%EOF işaretçisi veya çok büyük bir **/Prev** offset'i, AV'yi atlatmak için imzalama sonrasında veri eklenmiş olabileceğine işaret edebilir.

Önceki belirteçlerden herhangi biri şüpheli dizelerle (powershell, cmd.exe, calc.exe, base64 vb.) birlikte görülürse PDF daha ayrıntılı incelenmelidir.

---

## Statik analiz kısa başvuru kılavuzu

Aşağıdaki örneklerde belgelenmiş `pdf-parser.py`, qpdf ve pdfcpu komut satırı arayüzleri kullanılır.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>

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

PDF içindeki bir görüntüyü pikselleştirmek, alttaki pikselleri kaldırmaz. Okunabilir bir belge bu şekilde bir kimlik bilgisini gizliyor gibi görünüyorsa, yetkili çevrimdışı inceleme için gömülü görüntüyü çıkarın; sonuç görüntüye ve uygun bir referansa bağlıdır, görsel kurtarma garanti edilmez. Kurtarılan bir parolanın, ayrı olarak ve ilgili ayrıcalıklara sahip hesap üzerinde doğrulanması gerekir. Rutin bir host-enumeration taramasına PDF çıkarma veya görüntü kurtarma adımı eklemeyin.

Ek yararlı projeler (2023-2025 arasında aktif olarak bakımı yapılıyor):
* **pdfcpu** – PDF'leri doğrulayabilen, şifrelerini çözebilen, çıkarabilen, optimize edebilen ve değiştirebilen Go kütüphanesi/CLI.<sup>[[9]](#references)</sup>
* **pdf-inspector** – nesne grafiğini ve akışları oluşturan, tarayıcı tabanlı görselleştirici.
* **PyMuPDF** – PDF'leri incelemek ve sayfaları raster görüntülere dönüştürmek için betiklenebilir Python bağlamaları. Ayrıştırıcıyı/oluşturucuyu güvenilmeyen dosya saldırı yüzeyi olarak ele alın ve uygun şekilde yalıtılmış bir analiz ortamında çalıştırın.<sup>[[8]](#references)</sup>

---

## Yeni saldırı teknikleri (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC, VBA makroları içeren ve Word ile oluşturulmuş bir MHT dosyasının PDF'ye eklenmesiyle PDF magic değerinin korunduğu, ancak dosyanın Word'de de açıldığı bir teknik bildirdi. Kötü amaçlı davranış dosya Word olarak açıldığında gerçekleştiğinden, yalnızca PDF'leri analiz eden araçlar, sandbox'lar veya antivirüs makroyu gözden kaçırabilir; diğer MHT göstergelerinin yanı sıra `<w:WordDocument>` işaretçisini de arayın.<sup>[[2]](#references)</sup>
* **İmzalı PDF'lere yönelik Shadow saldırıları** – saldırganlar, PDF imzalanmadan önce içine gizli içerik yerleştirip ardından katalog veya nesne referanslarını değiştiren artımlı bir güncelleme ekleyebilir. Böylece görüntüleyiciler gizli içeriği gösterirken özgün imza geçerliliğini korur. Bu teknik, bu tür güncellemeleri zararsız olarak sınıflandıran görüntüleyicileri atlatabilir.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe, bu kritik güvenlik açığını arbitrary code execution'a yol açabilen bir use-after-free olarak sınıflandırıyor; APSB24-29, 14 Mayıs 2024'te yayımlandı.<sup>[[3]](#references)</sup>

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

1. **Hızlıca yama uygulayın** – Acrobat/Reader'ı en güncel Continuous kanalında tutun; gerçek saldırılarda gözlemlenen RCE zincirlerinin çoğu, aylar önce düzeltilmiş n-day güvenlik açıklarından yararlanır.
2. **Etkin içeriği ağ geçidinde kaldırın** – JavaScript'i, gömülü dosyaları, launch eylemlerini, formları ve multimedya içeriğini açıkça kaldıran, amaca özel ve politikalarla denetlenen bir sanitizer veya CDR ürünü kullanın. `qpdf --qdf` PDF nesnelerinin incelenmesini kolaylaştırırken pdfcpu doğrulama ve düzenleme özellikleri sunar; ancak bu komutların hiçbiri tek başına etkin içeriğin kaldırıldığını kanıtlamaz.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – Görsel aslına uygunluğu korurken etkin nesneleri kaldırmak için PDF'leri bir sandbox ana bilgisayarında görüntülere (veya PDF/A'ya) dönüştürün.
4. **Nadiren kullanılan özellikleri engelleyin** – Reader'daki kurumsal “Enhanced Security” ayarları JavaScript'i, multimedya içeriğini ve 3D işlemeyi devre dışı bırakmaya olanak tanır.
5. **Kullanıcıları eğitin** – Sosyal mühendislik (fatura ve özgeçmiş tuzakları) hâlâ ilk saldırı vektörüdür; çalışanlara şüpheli ekleri IR ekibine iletmeyi öğretin.

## References

- [1] [Forensics CTF Saha Rehberi](https://trailofbits.github.io/ctf/forensics/)
- [2] [PDF İçinde MalDoc – Kötü amaçlı bir Word dosyası PDF dosyasına gömülerek algılamanın atlatılması](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Güvenlik Bülteni – Adobe Acrobat ve Reader için güvenlik güncellemesi kullanıma sunuldu (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - kılavuzun kopyası](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - PDF biçimi hileleri](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Gölge Saldırıları: İmzalı PDF'lerde İçeriği Gizleme ve Değiştirme](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [PyMuPDF Öğreticisi](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [qpdf komut satırı seçenekleri](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
