# Office file analysis

{{#include ../../../banners/hacktricks-training.md}}


Daha fazla bilgi için [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/) adresine bakın. Bu yalnızca bir özet niteliğindedir:<sup>[[4]](#references)</sup>

Microsoft, iki ana türü **OLE formats** (RTF, DOC, XLS, PPT gibi) ve **Office Open XML (OOXML) formats** (DOCX, XLSX, PPTX gibi) olan birçok office document formatı oluşturmuştur. Bu formatlar, phishing ve malware için hedef hâline gelmelerine neden olan macro'ları içerebilir. OOXML files, zip container olarak yapılandırılmıştır; bu sayede dosya ve klasör hiyerarşisi ile XML file içerikleri ortaya çıkarılarak unzipping yoluyla incelenebilir.

OOXML file yapılarını keşfetmek için bir document'i unzip etme komutu ve çıktı yapısı verilmiştir. Bu file'larda data gizleme teknikleri belgelenmiştir; bu da CTF challenge'larında data concealment alanında sürekli yenilik yapıldığını göstermektedir.

Analysis için **oletools** ve **OfficeDissector**, hem OLE hem de OOXML document'lerini incelemek üzere kapsamlı toolset'ler sunar. Bu tool'lar, genellikle malware delivery için vector görevi gören ve çoğunlukla ek malicious payload'ları download edip execute eden embedded macro'ların belirlenmesine ve analysis edilmesine yardımcı olur. VBA macro'larının analysis'i, Microsoft Office kullanılmadan Libre Office aracılığıyla gerçekleştirilebilir; bu da breakpoint'ler ve watch variable'lar ile debugging yapılmasına olanak tanır.

**oletools** kurulumu ve kullanımı basittir; pip aracılığıyla kurulum ve document'lerden macro çıkarma komutları sağlanmıştır. Macro'ların automatic execution işlemi `AutoOpen`, `AutoExec` veya `Document_Open` gibi function'lar tarafından tetiklenir.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File istismarı: Autodesk Revit RFA – ECC yeniden hesaplama ve kontrollü gzip

Revit RFA modelleri, [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (diğer adıyla CFBF) olarak depolanır. Serileştirilmiş model, aşağıdaki storage/stream altında bulunur:<sup>[[1]](#references)</sup>

- Depolama: `Global`
- Akış: `Latest` → `Global\Latest`

`Global\Latest` için temel düzen (Revit 2025'te gözlemlenmiştir):

- Başlık
- GZIP ile sıkıştırılmış payload (gerçek serileştirilmiş nesne grafiği)
- Sıfır padding
- Hata Düzeltme Kodu (ECC) trailer'ı

Revit, ECC trailer'ını kullanarak stream üzerindeki küçük değişiklikleri otomatik olarak onarır ve ECC ile eşleşmeyen stream'leri reddeder. Bu nedenle, sıkıştırılmış byte'ları doğrudan düzenlemek kalıcı olmaz: değişiklikleriniz geri alınır veya dosya reddedilir. Deserializer'ın gördüğü içerik üzerinde byte düzeyinde kontrol sağlamak için şunları yapmanız gerekir:

- Revit ile uyumlu bir gzip implementation ile yeniden sıkıştırma yapmak (böylece Revit'in ürettiği/kabul ettiği sıkıştırılmış byte'lar beklediği değerlerle eşleşir).
- Revit'in değiştirilmiş stream'i otomatik olarak onarmadan kabul etmesi için padded stream üzerindeki ECC trailer'ını yeniden hesaplamak.

RFA içeriklerini patch/fuzzing amacıyla değiştirmek için pratik workflow:<sup>[[1]](#references)</sup>

1) OLE compound document'ı genişletin
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) gzip/ECC kurallarına uygun olarak `Global\Latest`'i düzenle

- `Global/Latest`'ı ayrıştır: header'ı koru, payload'ı gunzip ile aç, byte'ları değiştir, ardından Revit uyumlu deflate parametrelerini kullanarak tekrar gzip'le.
- Zero-padding'i koru ve yeni byte'ların Revit tarafından kabul edilmesi için ECC trailer'ını yeniden hesapla.
- Deterministik, byte-byte aynı yeniden üretime ihtiyacın varsa, araştırmada gösterildiği gibi gzip/gunzip yollarını ve ECC hesaplamasını çağırmak için Revit'in DLL'leri etrafında minimal bir wrapper oluştur veya bu semantiği taklit eden mevcut bir helper'ı yeniden kullan.

3) OLE compound document'ı yeniden oluştur
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)</sup>

- CompoundFileTool, NTFS adlarında geçersiz olan karakterler için escaping kullanarak storages/streams'leri filesystem'e yazar; istediğiniz stream path, output tree içinde tam olarak `Global/Latest` şeklindedir.
- Cloud storage'dan RFA'ları alan ecosystem plugins aracılığıyla mass attacks gerçekleştirirken, network injection denemeden önce patched RFA'nın yerel olarak Revit’in integrity checks'lerini geçtiğinden (gzip/ECC doğru) emin olun.

Exploitation insight (gzip payload içine hangi byte'ların yerleştirileceğine rehberlik etmesi için):<sup>[[1]](#references)</sup>

- Revit deserializer, 16-bit class index'i okur ve bir object oluşturur. Bazı type'lar non-polymorphic'tir ve vtable içermez; destructor handling'in kötüye kullanılması, engine'in attacker-controlled pointer üzerinden indirect call gerçekleştirdiği bir type confusion oluşturur.
- `AString`'i (class index `0x1F`) seçmek, object offset 0'a attacker-controlled bir heap pointer yerleştirir. Destructor loop sırasında Revit etkin olarak şunu çalıştırır:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Serialized graph içine bu tür nesnelerden birden fazla yerleştirin; böylece destructor loop'unun her iterasyonu bir gadget ("weird machine") çalıştırır ve conventional x64 ROP chain'e bir stack pivot düzenleyin.

Windows x64 pivot/gadget oluşturma ayrıntılarına buradan ulaşabilirsiniz:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

genel ROP yönergelerine ise buradan ulaşabilirsiniz:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Araçlar:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS), OLE compound file'larını genişletmek/yeniden oluşturmak için: https://github.com/thezdi/CompoundFileTool
- Reverse/taint işlemleri için IDA Pro + WinDBG TTD; trace'leri kompakt tutmak için TTD ile page heap'i devre dışı bırakın.
- Yerel bir proxy (ör. Fiddler), test amacıyla plugin trafiğindeki RFA'ları değiştirerek supply-chain delivery'yi simüle edebilir.

## Referanslar

- [1] [Autodesk Revit RFA File Parsing'deki Bir Crash'ten Full Exploit RCE Oluşturma (ZDI blogu)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) belgeleri](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
