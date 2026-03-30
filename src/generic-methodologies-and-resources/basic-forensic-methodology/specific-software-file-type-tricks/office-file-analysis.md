# Office file analysis

{{#include ../../../banners/hacktricks-training.md}}


Daha fazla bilgi için şu adresi inceleyin: [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Bu sadece bir özet:

Microsoft, birçok office belge formatı oluşturdu; iki ana tür **OLE formats** (RTF, DOC, XLS, PPT gibi) ve **Office Open XML (OOXML) formats** (DOCX, XLSX, PPTX gibi) dir. Bu formatlar makrolar içerebilir ve phishing ile malware için hedef oluşturur. OOXML dosyaları zip konteynerleri olarak yapılandırılmıştır; unzip edilerek dosya ve klasör hiyerarşisi ile XML dosya içerikleri incelenebilir.

OOXML dosya yapılarını keşfetmek için bir belgeyi unzip etme komutu ve çıktı yapısı verilmiştir. Bu dosyalarda veri gizleme tekniklerinin belgelenmiş olduğu ve CTF zorluklarında veri gizlemede sürekli yenilik yapıldığını gösteren çalışmalar vardır.

Analiz için **oletools** ve **OfficeDissector** hem OLE hem de OOXML belgelerini incelemeye yönelik kapsamlı araç setleri sunar. Bu araçlar, genellikle ek zararlı payload'lar indirip çalıştıran gömülü makroları tespit edip analiz etmeye yardımcı olur. VBA makrolarının analizi, Microsoft Office olmadan Libre Office kullanılarak yapılabilir; Libre Office ile breakpoint ve watch değişkenleri kullanarak debug yapmak mümkündür.

**oletools**'un kurulumu ve kullanımı basittir; pip ile kurma ve belgelerden makroları çıkarmaya yönelik komutlar sağlanmıştır. Makroların otomatik çalışması `AutoOpen`, `AutoExec` veya `Document_Open` gibi fonksiyonlarla tetiklenir.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA modelleri bir [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF) olarak saklanır. Serileştirilmiş model storage/stream altında yer alır:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

`Global\Latest`'in ana düzeni (Revit 2025'te gözlemlenmiştir):

- Header
- GZIP-compressed payload (the actual serialized object graph)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit, küçük bozulmaları ECC trailer'ını kullanarak otomatik onarır ve ECC ile eşleşmeyen stream'leri reddeder. Bu nedenle, sıkıştırılmış byte'ları naifçe düzenlemek kalıcı olmaz: değişiklikleriniz ya geri alınır ya da dosya reddedilir. Deserializer'ın gördükleri üzerinde byte-hassasiyetli kontrol sağlamak için şu adımları izlemelisiniz:

- Recompress with a Revit-compatible gzip implementation (so the compressed bytes Revit produces/accepts match what it expects).
- Recompute the ECC trailer over the padded stream so Revit will accept the modified stream without auto-repairing it.

RFA içeriklerini patching/fuzzing için pratik iş akışı:

1) Expand the OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) gzip/ECC disipliniyle Global\Latest'i düzenle

- `Global/Latest`'i parçalara ayır: başlığı koru, payload'u gunzip et, bytes'ları değiştir, sonra Revit-uyumlu deflate parametreleri kullanarak tekrar gzip yap.
- Zero-padding'i koru ve ECC trailer'ını yeniden hesapla, böylece yeni bytes'lar Revit tarafından kabul edilir.
- Deterministik bayt-bayt yeniden üretime ihtiyacın varsa, Revit’in DLLs etrafında gzip/gunzip yollarını ve ECC hesaplamasını çağıracak minimal bir wrapper oluştur (araştırmada gösterildiği gibi) veya bu semantikleri çoğaltan mevcut bir yardımcıyı yeniden kullan.

3) OLE bileşik dokümanını yeniden oluştur
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notlar:

- CompoundFileTool, NTFS adlarında geçersiz olan karakterler için kaçış uygulayarak storages/streams'i dosya sistemine yazar; çıktı ağacında ihtiyacınız olan stream yolu tam olarak `Global/Latest`'dir.
- Ecosystem plugins aracılığıyla cloud storage'dan RFAs çeken kitlesel saldırılar dağıtırken, ağ enjeksiyonunu denemeden önce patch'lenmiş RFA'nızın önce yerel olarak Revit’in bütünlük kontrollerinden geçtiğinden emin olun (gzip/ECC doğru).

Sömürme içgörüsü (gzip yükünde hangi byte'ları yerleştireceğinizi yönlendirmek için):

- Revit'in deserializer'ı 16-bit'lik bir sınıf indeksi okur ve bir nesne oluşturur. Bazı türler polimorfik değildir ve vtable'ları yoktur; destructor işleyişinin kötüye kullanılması, motorun saldırgan tarafından kontrol edilen bir işaretçi üzerinden dolaylı bir çağrı gerçekleştirdiği bir type confusion'a yol açar.
- `AString`'i seçmek (class index `0x1F`) saldırgan-kontrollü bir heap işaretçisini nesne offset 0'a yerleştirir. Destructor döngüsü sırasında Revit pratikte şunu çalıştırır:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Bu türden birden fazla objeyi serileştirilmiş grafiğe yerleştirin, böylece destructor loop'un her yinelemesi bir gadget (“weird machine”) çalıştırır ve bir stack pivot'u geleneksel bir x64 ROP chain'e yönlendirin.

Windows x64 pivot/gadget oluşturma ayrıntıları için bakınız:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

ve genel ROP rehberi için:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Araçlar:

- CompoundFileTool (OSS) — OLE compound dosyalarını genişletmek/yeniden oluşturmak için: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD for reverse/taint; izleri kompakt tutmak için TTD ile page heap'i devre dışı bırakın.
- Yerel bir proxy (örn. Fiddler), test için plugin traffic'teki RFAs'i değiştirerek supply-chain teslimatını simüle edebilir.

## Kaynaklar

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
