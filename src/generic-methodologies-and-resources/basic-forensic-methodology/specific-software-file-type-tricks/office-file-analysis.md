# Office dosya analizi

{{#include ../../../banners/hacktricks-training.md}}

Daha fazla bilgi için [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/) adresine bakın. Bu yalnızca bir özettir:<sup>[[4]](#references)</sup>

Microsoft Office belgeleri genellikle RTF ve OLE/CFBF tabanlı DOC, XLS ve PPT gibi eski formatlarda veya DOCX, XLSX ve PPTX gibi daha yeni **Office Open XML (OOXML)** formatlarında görülür. Office belgeleri makrolar gibi etkin içerikler barındırabilir; bu da onları yaygın phishing ve malware taşıyıcıları hâline getirir. OOXML dosyaları, dosya hiyerarşisi ve XML içerikleri açılarak incelenebilen ZIP container'larıdır.<sup>[[3]](#references)[[4]](#references)</sup>

OOXML dosya yapılarını incelemek için bir belgeyi açma komutu ve çıktı yapısı verilmiştir. Bu dosyalarda veri gizleme teknikleri belgelenmiştir; bu durum, CTF challenge'larında veri gizleme alanındaki sürekli yenilikleri göstermektedir.<sup>[[4]](#references)</sup>

Analiz için **oletools** ve **OfficeDissector**, hem OLE hem de OOXML belgelerini incelemeye yönelik kapsamlı toolset'ler sunar. Bu araçlar, genellikle malware dağıtımı için vektör görevi gören ve çoğunlukla ek malicious payload'ları indirip çalıştıran gömülü makroların tespit edilmesine ve analiz edilmesine yardımcı olur. VBA makrolarının analizi, Microsoft Office kullanılmadan Libre Office aracılığıyla gerçekleştirilebilir; Libre Office breakpoint'ler ve watch variable'lar ile debugging yapılmasına olanak tanır.<sup>[[4]](#references)</sup>

**oletools** kurulumu ve kullanımı oldukça basittir; pip ile kurulum ve belgelerden makroların çıkarılması için komutlar sağlanmıştır. Word'de otomatik makrolar arasında `AutoExec` ve `AutoOpen` bulunurken, `Document_Open` bir open-event procedure'dür.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
Parola ile şifrelenmiş Office belgeleri için [grammar-driven offline recovery workflow](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example) bölümüne bakın.

---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA modelleri, bir [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (diğer adıyla CFBF) olarak depolanır. Serileştirilmiş model şu storage/stream altında bulunur:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

`Global\Latest` için temel düzen (Revit 2025'te gözlemlenmiştir):

- Header
- GZIP-compressed payload (gerçek serileştirilmiş object graph)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit, ECC trailer'ı kullanarak stream üzerindeki küçük değişiklikleri otomatik olarak onarır ve ECC ile eşleşmeyen stream'leri reddeder. Bu nedenle, compressed bytes üzerinde doğrudan düzenleme yapmak kalıcı olmaz: değişiklikleriniz ya geri alınır ya da dosya reddedilir. Deserializer'ın gördüğü içerik üzerinde byte-accurate control sağlamak için şunları yapmanız gerekir:<sup>[[1]](#references)</sup>

- Revit-compatible bir gzip implementation ile yeniden compress edin (böylece Revit'in ürettiği/kabul ettiği compressed bytes, beklediği değerlerle eşleşir).
- Revit'in değiştirilmiş stream'i auto-repair uygulamadan kabul etmesi için padded stream üzerindeki ECC trailer'ı yeniden hesaplayın.

RFA içeriklerini patch/fuzz etmek için pratik workflow:<sup>[[1]](#references)</sup>

1) OLE compound document'ı genişletin.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Global\Latest'i gzip/ECC ilkelerine uygun şekilde düzenleyin

- `Global/Latest`'ı ayrıştırın: başlığı koruyun, payload'u gunzip ile açın, byte'ları değiştirin, ardından Revit uyumlu deflate parametrelerini kullanarak tekrar gzip'leyin.
- Sıfır dolguyu koruyun ve yeni byte'ların Revit tarafından kabul edilmesi için ECC trailer'ını yeniden hesaplayın.
- Byte-byte deterministik yeniden üretime ihtiyacınız varsa, araştırmada gösterildiği gibi gzip/gunzip yollarını ve ECC hesaplamasını çağırmak için Revit DLL'leri etrafında minimal bir wrapper oluşturun veya bu semantiği taklit eden mevcut bir helper'ı yeniden kullanın.

3) OLE compound document'ı yeniden oluşturun.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notlar:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool, NTFS adlarında geçersiz olan karakterler için escaping kullanarak storage/stream'leri dosya sistemine yazar; istediğiniz stream yolu çıktı ağacında tam olarak `Global/Latest` şeklindedir.
- RFA'ları cloud storage'dan alan ecosystem plugin'leri üzerinden mass attacks gerçekleştirirken, network injection girişiminden önce patched RFA'nın yerel olarak Revit'in integrity checks kontrollerinden geçtiğinden (gzip/ECC doğru) emin olun.

Exploitation insight (gzip payload içine yerleştirilecek byte'ları yönlendirmek için):<sup>[[1]](#references)</sup>

- Revit deserializer, 16-bit class index'i okur ve bir object oluşturur. Bazı type'lar non-polymorphic'tir ve vtable içermez; destructor handling'in abuse edilmesi, engine'in attacker-controlled pointer üzerinden indirect call gerçekleştirdiği bir type confusion oluşturur.
- `AString` (`class index` `0x1F`) seçildiğinde, object offset 0'a attacker-controlled bir heap pointer yerleştirilir. Destructor loop sırasında Revit fiilen şunu çalıştırır:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Serileştirilmiş grafiğe bu tür birden çok nesne yerleştirin; böylece destructor döngüsünün her yinelemesi bir gadget (“weird machine”) çalıştırır ve geleneksel bir x64 ROP chain içine stack pivot düzenleyin.

Windows x64 pivot/gadget oluşturma ayrıntılarına buradan ulaşabilirsiniz:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

genel ROP rehberine ise buradan ulaşabilirsiniz:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Araçlar:<sup>[[1]](#references)</sup>

- OLE compound files dosyalarını genişletmek/yeniden oluşturmak için CompoundFileTool (OSS): https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- Tersine mühendislik/taint analizi için IDA Pro + WinDBG TTD; trace'leri kompakt tutmak için TTD ile page heap'i devre dışı bırakın.
- Yerel bir proxy (ör. Fiddler), test amacıyla plugin trafiğindeki RFA'ları değiştirerek supply-chain teslimatını simüle edebilir.

## References

- [1] [Bir Autodesk Revit RFA Dosyası Ayrıştırma Crash'inden Tam Bir Exploit RCE Oluşturma (ZDI blogu)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) belgeleri](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Saha Rehberi](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba belgeleri (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open event (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
