# Office dosya analizi

{{#include ../../../banners/hacktricks-training.md}}


Daha fazla bilgi için [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Bu sadece bir özet:

Microsoft birçok Office belge formatı oluşturdu; iki ana tür **OLE formats** (ör. RTF, DOC, XLS, PPT) ve **Office Open XML (OOXML) formats** (ör. DOCX, XLSX, PPTX). Bu formatlar makrolar içerebilir, bu da onları phishing ve malware için hedef haline getirir. OOXML dosyaları zip konteynerleri olarak yapılandırılmıştır; unzip ile açılarak dosya ve klasör hiyerarşisi ile XML dosya içerikleri incelenebilir.

OOXML dosya yapılarını keşfetmek için bir belgeyi unzip etme komutu ve çıktı yapısı verilmiştir. Bu dosyalarda veri gizleme teknikleri belgelenmiştir; bu, CTF meydan okumalarında veri gizleme konusunda süregelen yeniliği gösterir.

Analiz için **oletools** ve **OfficeDissector** hem OLE hem de OOXML belgelerini incelemek için kapsamlı araç setleri sunar. Bu araçlar gömülü makroları tespit edip analiz etmeye yardımcı olur; bu makrolar genellikle malware teslimatı için vektör görevi görür ve tipik olarak ek kötü amaçlı payload'ları indirip çalıştırırlar. VBA makrolarının analizi Microsoft Office olmadan Libre Office kullanılarak yapılabilir; Libre Office breakpoint'lerle ve watch variable'larla debugging yapmaya izin verir.

**oletools**'un kurulumu ve kullanımı basittir; pip ile kurma ve belgelerden makro çıkarma komutları sağlanmıştır. Makroların otomatik çalıştırılması `AutoOpen`, `AutoExec` veya `Document_Open` gibi fonksiyonlar tarafından tetiklenir.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA modelleri bir [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF) olarak saklanır. Serileştirilmiş model storage/stream altında yer alır:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

`Global\Latest`'in temel düzeni (Revit 2025'te gözlemlendi):

- Başlık
- GZIP ile sıkıştırılmış payload (gerçek serileştirilmiş obje grafiği)
- Sıfır dolgu
- Error-Correcting Code (ECC) trailer

Revit, ECC trailer'ı kullanarak akımdaki küçük bozulmaları otomatik onarır ve ECC ile eşleşmeyen akımları reddeder. Bu nedenle, sıkıştırılmış baytları safça düzenlemek kalıcı olmaz: değişiklikleriniz ya geri alınır ya da dosya reddedilir. Serileştiricinin gördüğü veriler üzerinde bayt-doğru kontrol sağlamak için şunları yapmalısınız:

- Revit ile uyumlu bir gzip implementasyonu ile yeniden sıkıştırın (böylece Revit'in ürettiği/kabul ettiği sıkıştırılmış baytlar beklentisiyle eşleşir).
- Dolgu uygulanmış akım üzerinde ECC trailer'ını yeniden hesaplayın, böylece Revit değiştirilen akımı otomatik onarmadan kabul eder.

Practical workflow for patching/fuzzing RFA contents:

1) OLE compound document'ı genişletin
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) gzip/ECC disiplini ile Global\Latest'i düzenleyin

- `Global/Latest`'i parçalarına ayırın: başlığı koruyun, payload'ı gunzip ile açın, byte'ları değiştirin, sonra Revit-uyumlu deflate parametreleri kullanarak tekrar gzip yapın.
- Zero-padding'i koruyun ve yeni byte'ların Revit tarafından kabul edilmesi için ECC trailer'ını yeniden hesaplayın.
- Deterministik byte-for-byte yeniden üretim gerekiyorsa, Revit’in DLL'leri etrafında gzip/gunzip yollarını ve ECC hesaplamasını çağıracak minimal bir wrapper oluşturun (araştırmada gösterildiği gibi) veya bu semantiği tekrarlayan mevcut herhangi bir yardımcıyı yeniden kullanın.

3) OLE compound document'ı yeniden oluşturun
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:

- CompoundFileTool, depolama/stream'leri NTFS adlarında geçersiz olan karakterler için escape uygulayarak dosya sistemine yazar; çıktı ağacında ihtiyacınız olan stream yolu tam olarak `Global/Latest`'tir.
- Bulut depolamadan RFA çeken ekosistem eklentileri aracılığıyla toplu saldırılar gerçekleştirirken, ağ enjeksiyonuna kalkışmadan önce yamanmış RFA'nızın yerelde Revit’in bütünlük kontrollerinden geçtiğinden emin olun (gzip/ECC doğru).

Exploitation insight (gzip payload'a hangi baytları yerleştireceğinizi yönlendirmek için):

- Revit deserializer 16-bit'lik bir class index okur ve bir obje oluşturur. Bazı tipler non‑polymorphic olup vtables'a sahip değildir; destructor işleyişini kötüye kullanmak, motorun saldırgan tarafından kontrol edilen bir işaretçi üzerinden dolaylı çağrı gerçekleştirdiği bir type confusion ortaya çıkarır.
- `AString`'i (class index `0x1F`) seçmek, object offset 0'da saldırgan tarafından kontrol edilen bir heap pointer yerleştirir. Destructor döngüsü sırasında, Revit etkili olarak şunu çalıştırır:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Bunlardan birden fazlasını serialized grafikte yerleştirin; böylece destructor döngüsünün her yinelemesi bir gadget (“weird machine”) yürütür ve stack pivot'u geleneksel bir x64 ROP zincirine yönlendirin.

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Tooling:

- CompoundFileTool (OSS) to expand/rebuild OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD for reverse/taint; disable page heap with TTD to keep traces compact.
- A local proxy (e.g., Fiddler) can simulate supply-chain delivery by swapping RFAs in plugin traffic for testing.

## References

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
