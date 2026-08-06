# Office dosyası analizi

{{#include ../../../banners/hacktricks-training.md}}


Daha fazla bilgi için [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/) adresini inceleyin. Bu yalnızca bir özettir:<sup>[[4]](#references)</sup>

Microsoft, başlıca iki türü olan birçok Office belge formatı oluşturmuştur: **OLE formatları** (RTF, DOC, XLS, PPT gibi) ve **Office Open XML (OOXML) formatları** (DOCX, XLSX, PPTX gibi). Bu formatlar makrolar içerebilir ve bu nedenle phishing ile malware saldırılarında hedef haline gelebilir. OOXML dosyaları zip container olarak yapılandırılmıştır. Bu sayede dosyalar unzip edilerek dosya ve klasör hiyerarşisi ile XML dosyalarının içeriği incelenebilir.

OOXML dosya yapılarını keşfetmek için bir belgeyi unzip etmeye yarayan komut ve ortaya çıkan yapı verilmiştir. Bu dosyalarda verileri gizlemeye yönelik teknikler belgelenmiştir; bu da CTF challenge'larında veri gizleme yöntemlerinde sürekli yenilik yapıldığını göstermektedir.

Analiz için **oletools** ve **OfficeDissector**, hem OLE hem de OOXML belgelerini incelemeye yönelik kapsamlı toolset'ler sunar. Bu araçlar, genellikle malware delivery için vector olarak kullanılan ve çoğunlukla ek malicious payload'ları indirip çalıştıran gömülü makroların belirlenmesine ve analiz edilmesine yardımcı olur. VBA makrolarının analizi, Microsoft Office kullanılmadan LibreOffice ile gerçekleştirilebilir; LibreOffice, breakpoint'ler ve watch variable'lar kullanılarak debugging yapılmasına olanak tanır.

**oletools** kurulumu ve kullanımı oldukça kolaydır. Belgelerden makro çıkarmak ve pip aracılığıyla kurulum yapmak için gerekli komutlar verilmiştir. Makroların otomatik çalıştırılması `AutoOpen`, `AutoExec` veya `Document_Open` gibi function'lar tarafından tetiklenir.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation ve kontrollü gzip

Revit RFA modelleri, [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (diğer adıyla CFBF) olarak depolanır. Serileştirilmiş model şu storage/stream altında bulunur:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

`Global\Latest` için temel yerleşim (Revit 2025'te gözlemlenmiştir):

- Header
- GZIP-compressed payload (gerçek serileştirilmiş object graph)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit, ECC trailer'ı kullanarak stream üzerindeki küçük değişiklikleri otomatik olarak onarır ve ECC ile eşleşmeyen stream'leri reddeder. Bu nedenle, compressed bytes'ları naif şekilde düzenlemek kalıcı olmaz: değişiklikleriniz ya geri alınır ya da dosya reddedilir. Deserializer'ın gördüğü içerik üzerinde byte-accurate kontrol sağlamak için şunları yapmanız gerekir:

- Revit-compatible bir gzip implementation ile yeniden compress edin (böylece Revit'in ürettiği/kabul ettiği compressed bytes beklenen değerlerle eşleşir).
- Revit'in değiştirilmiş stream'i auto-repair uygulamadan kabul etmesi için padded stream üzerindeki ECC trailer'ı yeniden hesaplayın.

RFA içeriklerini patching/fuzzing için pratik workflow:<sup>[[1]](#references)</sup>

1) OLE compound document'ı genişletin
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Global\Latest'i gzip/ECC disiplinine uygun şekilde düzenleme

- `Global/Latest` dosyasını ayrıştırın: header'ı koruyun, payload'u gunzip ile açın, byte'ları değiştirin, ardından Revit uyumlu deflate parametrelerini kullanarak tekrar gzip'leyin.
- Zero-padding'i koruyun ve yeni byte'ların Revit tarafından kabul edilmesi için ECC trailer'ını yeniden hesaplayın.
- Byte-byte deterministik yeniden üretim gerekiyorsa, araştırmada gösterildiği gibi gzip/gunzip yollarını ve ECC hesaplamasını çağırmak için Revit DLL'leri etrafında minimal bir wrapper oluşturun veya bu semantiği taklit eden mevcut bir helper'ı yeniden kullanın.

3) OLE compound document'ı yeniden oluşturma
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)</sup>

- CompoundFileTool, NTFS adlarında geçersiz olan karakterler için escaping kullanarak storages/streams öğelerini filesystem'e yazar; çıktı ağacında istediğiniz stream path tam olarak `Global/Latest` şeklindedir.
- Cloud storage'dan RFA alan ecosystem plugins üzerinden mass attacks gerçekleştirirken, network injection denemeden önce patched RFA'nın yerel olarak Revit’in integrity checks kontrollerinden geçtiğinden (gzip/ECC doğru) emin olun.

Exploitation insight (gzip payload içine yerleştirilecek byte'ları yönlendirmek için):<sup>[[1]](#references)</sup>

- Revit deserializer, 16-bit class index'i okur ve bir object oluşturur. Belirli types non-polymorphic'tir ve vtable içermez; destructor handling'in abuse edilmesi, engine'in attacker-controlled pointer üzerinden indirect call gerçekleştirdiği bir type confusion oluşturur.
- `AString` (class index `0x1F`) seçildiğinde, attacker-controlled bir heap pointer'ı object offset 0'a yerleştirilir. Destructor loop sırasında Revit fiilen şunu çalıştırır:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Serialized graph içine bu tür birden fazla nesne yerleştirin; böylece destructor loop'un her iterasyonu bir gadget ("weird machine") çalıştırır ve conventional x64 ROP chain içine bir stack pivot düzenleyin.

Windows x64 pivot/gadget oluşturma ayrıntılarına buradan ulaşabilirsiniz:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

genel ROP yönlendirmesi için:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Araçlar:<sup>[[1]](#references)</sup>

- OLE compound file'larını genişletmek/yeniden oluşturmak için CompoundFileTool (OSS): https://github.com/thezdi/CompoundFileTool<sup>[[2]](#references)</sup>
- Reverse/taint işlemleri için IDA Pro + WinDBG TTD; trace'leri kompakt tutmak için TTD ile page heap'i devre dışı bırakın.
- Yerel bir proxy (ör. Fiddler), test amacıyla plugin trafiğindeki RFA'ları değiştirerek supply-chain delivery'yi simüle edebilir.

## Referanslar

- [1] [Autodesk Revit RFA File Parsing'deki Bir Crash'ten Full Exploit RCE Oluşturma (ZDI blogu)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) belgeleri](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
