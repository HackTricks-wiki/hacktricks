# Office dosyası analizi

{{#include ../../../banners/hacktricks-training.md}}

Daha fazla bilgi için [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/) adresine bakın. Bu yalnızca bir özettir:<sup>[[4]](#references)</sup>

Microsoft Office belgeleri genellikle RTF ve OLE/CFBF tabanlı DOC, XLS ve PPT gibi eski formatlarda veya DOCX, XLSX ve PPTX gibi daha yeni **Office Open XML (OOXML)** formatlarında görülür. Office belgeleri makrolar gibi aktif içerikler barındırabilir; bu da onları yaygın phishing ve malware taşıyıcıları hâline getirir. OOXML dosyaları, unzip edilerek dosya hiyerarşileri ve XML içerikleri incelenebilen ZIP container'larıdır.<sup>[[3]](#references)[[4]](#references)</sup>

OOXML dosya yapılarını keşfetmek için bir belgeyi unzip etme komutu ve çıktı yapısı verilmiştir. Bu dosyalarda data gizleme teknikleri belgelenmiştir; bu durum, CTF challenge'larında data concealment alanındaki sürekli yeniliğe işaret eder.<sup>[[4]](#references)</sup>

**oletools** ve **OfficeDissector**, hem OLE hem de OOXML belgelerini incelemek için kapsamlı toolset'ler sunar. Bu tool'lar, genellikle malware delivery için vector olarak kullanılan ve çoğunlukla ek malicious payload'ları indirip execute eden gömülü makroların tespit edilmesine ve analiz edilmesine yardımcı olur. VBA makrolarının analizi, Microsoft Office kullanılmadan Libre Office aracılığıyla gerçekleştirilebilir; Libre Office breakpoint'ler ve watch variable'lar ile debugging yapılmasına olanak tanır.<sup>[[4]](#references)</sup>

**oletools** kurulumu ve kullanımı oldukça basittir; pip aracılığıyla kurulum ve belgelerden makro çıkarma komutları sağlanmıştır. Word'de otomatik makrolar arasında `AutoExec` ve `AutoOpen` bulunurken `Document_Open`, bir open-event procedure'dür.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA modelleri bir [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (diğer adıyla CFBF) olarak depolanır. Serileştirilmiş model storage/stream altında bulunur:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

`Global\Latest` için temel düzen (Revit 2025 üzerinde gözlemlenmiştir):

- Header
- GZIP-compressed payload (gerçek serileştirilmiş object graph)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit, ECC trailer kullanarak stream üzerindeki küçük değişiklikleri otomatik olarak onarır ve ECC ile eşleşmeyen stream'leri reddeder. Bu nedenle, compressed bytes'ları doğrudan düzenlemek kalıcı olmaz: değişiklikleriniz ya geri alınır ya da dosya reddedilir. Deserializer'ın gördüğü veriler üzerinde byte-accurate control sağlamak için şunları yapmanız gerekir:<sup>[[1]](#references)</sup>

- Revit-compatible bir gzip implementation ile yeniden sıkıştırma yapın (böylece Revit'in ürettiği/kabul ettiği compressed bytes beklediği değerlerle eşleşir).
- Revit'in modified stream'i auto-repair uygulamadan kabul etmesi için padded stream üzerindeki ECC trailer'ı yeniden hesaplayın.

RFA içeriklerini patch/fuzz etmek için pratik workflow:<sup>[[1]](#references)</sup>

1) OLE compound document'i genişletin.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Global\Latest’i gzip/ECC kurallarına uygun şekilde düzenleyin

- `Global/Latest` öğesini ayrıştırın: header’ı koruyun, payload’u gunzip ile açın, byte’ları değiştirin, ardından Revit uyumlu deflate parametrelerini kullanarak tekrar gzip uygulayın.
- Zero-padding’i koruyun ve yeni byte’ların Revit tarafından kabul edilmesi için ECC trailer’ını yeniden hesaplayın.
- Byte-byte deterministik yeniden üretime ihtiyacınız varsa, gzip/gunzip yollarını ve ECC hesaplamasını çağırmak üzere Revit DLL’leri etrafında minimal bir wrapper oluşturun (araştırmada gösterildiği gibi) veya bu semantiği taklit eden mevcut bir helper’ı yeniden kullanın.

3) OLE compound document’ı yeniden oluşturun.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notlar:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool, NTFS adlarında geçersiz karakterleri escape ederek storage/stream'leri filesystem'e yazar; istediğiniz stream path'i çıktı ağacında tam olarak `Global/Latest` şeklindedir.
- Cloud storage'dan RFA alan ecosystem plugin'leri aracılığıyla mass attacks gerçekleştirirken, network injection denemeden önce patched RFA'nın yerel olarak Revit'in integrity checks'inden geçtiğinden (gzip/ECC doğru) emin olun.

Exploitation içgörüsü (gzip payload'ına yerleştirilecek byte'ları yönlendirmek için):<sup>[[1]](#references)</sup>

- Revit deserializer, 16-bit class index'i okur ve bir object oluşturur. Bazı type'lar non-polymorphic'tir ve vtable içermez; destructor handling'in abuse edilmesi, engine'in attacker-controlled pointer üzerinden indirect call gerçekleştirdiği bir type confusion oluşturur.
- `AString`'i (class index `0x1F`) seçmek, attacker-controlled bir heap pointer'ı object offset 0'a yerleştirir. Destructor loop sırasında Revit fiilen şunu çalıştırır:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Serileştirilmiş grafiğe bu türden birden fazla nesne yerleştirin; böylece destructor loop'un her iterasyonu bir gadget (“weird machine”) çalıştırır ve conventional x64 ROP chain içine bir stack pivot düzenleyin.

Windows x64 pivot/gadget oluşturma ayrıntılarına buradan ulaşabilirsiniz:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

genel ROP yönergeleri için:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Araçlar:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS), OLE compound file'larını genişletmek/yeniden oluşturmak için: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- Reverse/taint işlemleri için IDA Pro + WinDBG TTD; trace'leri kompakt tutmak için TTD ile page heap'i devre dışı bırakın.
- Yerel bir proxy (ör. Fiddler), test amacıyla plugin trafiğindeki RFA'ları değiştirerek supply-chain delivery'yi simüle edebilir.

## References

- [1] [Autodesk Revit RFA File Parsing'deki Bir Crash'ten Tam Bir Exploit RCE Oluşturma (ZDI blogu)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) belgeleri](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba documentation (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open event (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
