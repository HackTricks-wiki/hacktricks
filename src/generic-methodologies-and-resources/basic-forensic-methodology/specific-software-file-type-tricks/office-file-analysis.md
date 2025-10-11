# Office dosya analizi

{{#include ../../../banners/hacktricks-training.md}}


Daha fazla bilgi için şu adresi inceleyin [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Bu sadece bir özet:

Microsoft birçok Office belge formatı oluşturdu; iki ana tür **OLE formats** (RTF, DOC, XLS, PPT gibi) ve **Office Open XML (OOXML) formats** (DOCX, XLSX, PPTX gibi) şeklindedir. Bu formatlar makrolar içerebilir, bu da onları phishing ve malware hedefi haline getirir. OOXML dosyaları zip konteynerleri olarak yapılandırılmıştır; unzip ederek dosya ve klasör hiyerarşisini ve XML dosya içeriklerini görebilirsiniz.

OOXML dosya yapılarını keşfetmek için bir belgeyi unzip etme komutu ve çıktı yapısı verilmiştir. Bu dosyalarda veri gizleme teknikleri belgelenmiştir; bu, CTF challenge'larında veri gizlemede sürekli yenilik olduğunu göstermektedir.

Analiz için **oletools** ve **OfficeDissector**, hem OLE hem de OOXML belgelerini incelemek için kapsamlı araç setleri sunar. Bu araçlar, gömülü makroları tespit edip analiz etmeye yardımcı olur; bu makrolar genellikle malware dağıtımı için vektör görevi görür, tipik olarak ek kötü amaçlı payload'ları indirip çalıştırırlar. VBA makrolarının analizi Microsoft Office olmadan Libre Office kullanılarak yapılabilir; Libre Office breakpoint'lerle ve watch değişkenleriyle debug yapmaya olanak tanır.

**oletools**'un kurulumu ve kullanımı basittir; pip ile kurma ve belgelerden makro çıkarma komutları verilmiştir. Makroların otomatik yürütülmesi `AutoOpen`, `AutoExec` veya `Document_Open` gibi fonksiyonlar tarafından tetiklenir.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA modelleri bir [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (diğer adıyla CFBF) olarak saklanır. Serileştirilmiş model storage/stream altında bulunur:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

`Global\Latest`'in ana düzeni (Revit 2025'te gözlemlendi):

- Header
- GZIP-compressed payload (gerçek serileştirilmiş obje grafı)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit, ECC sonekini kullanarak stream üzerindeki küçük bozulmaları otomatik olarak onarır ve ECC ile eşleşmeyen stream'leri reddeder. Bu nedenle, sıkıştırılmış baytları naifçe düzenlemek kalıcı olmaz: değişiklikleriniz ya geri alınır ya da dosya reddedilir. Ayrıştırıcının gördüğü veriler üzerinde bayt-hassas kontrol sağlamak için şunları yapmalısınız:

- Revit ile uyumlu bir gzip uygulaması ile yeniden sıkıştırın (böylece Revit'in ürettiği/kabul ettiği sıkıştırılmış baytlar beklediğiyle eşleşir).
- ECC trailer'ını doldurulmuş (padded) stream üzerinde yeniden hesaplayın, böylece Revit değiştirilen stream'i otomatik onarmadan kabul eder.

RFA içeriklerini patching/fuzzing için pratik iş akışı:

1) OLE compound document'u genişlet
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) gzip/ECC disipliniyle Global\Latest üzerinde düzenleme

- Ayrıştır `Global/Latest`: header'ı koru, payload'ı gunzip et, baytları değiştir, sonra Revit-compatible deflate parameters kullanarak tekrar gziple.
- Sıfır-dolguyu koru ve ECC trailer'ını yeniden hesapla ki yeni baytlar Revit tarafından kabul edilsin.
- Eğer deterministik bayt-bayt yeniden üretim gerekiyorsa, Revit’s DLLs etrafında minimal bir wrapper inşa ederek onun gzip/gunzip yollarını ve ECC hesaplamasını çağır (araştırmada gösterildiği gibi), veya bu semantikleri çoğaltan mevcut herhangi bir yardımcıyı yeniden kullan.

3) OLE compound document yeniden oluştur
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:

- CompoundFileTool writes storages/streams to the filesystem with escaping for characters invalid in NTFS names; the stream path you want is exactly `Global/Latest` in the output tree.
- When delivering mass attacks via ecosystem plugins that fetch RFAs from cloud storage, ensure your patched RFA passes Revit’s integrity checks locally first (gzip/ECC correct) before attempting network injection.

Exploitation insight (gzip payload içine hangi byte'ları koyacağınızı yönlendirmek için):

- Revit deserializer 16-bit bir class index okur ve bir object oluşturur. Certain types non‑polymorphic olup vtables'a sahip değildir; destructor handling'in kötüye kullanılması, engine'in attacker-controlled pointer üzerinden bir indirect call gerçekleştirdiği bir type confusion'a yol açar.
- `AString`'i seçmek (class index `0x1F`) saldırgan-kontrollü bir heap pointer'ını object offset 0'a yerleştirir. Destructor loop sırasında Revit pratikte şunu çalıştırır:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Bu tür nesneleri serialized graph içine birden fazla yerleştirin; böylece destructor loop'un her yinelemesi bir gadget (“weird machine”) çalıştırır ve bir stack pivot'u geleneksel bir x64 ROP chain'e yönlendirin.

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Araçlar:

- CompoundFileTool (OSS) to expand/rebuild OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD for reverse/taint; disable page heap with TTD to keep traces compact.
- Bir yerel proxy (ör. Fiddler), test için plugin trafiğindeki RFAs'ları değiştirerek supply-chain teslimatını simüle edebilir.

## Referanslar

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
