# Office dosyası analizi

{{#include ../../../banners/hacktricks-training.md}}

Daha fazla bilgi için [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/) adresine bakın. Bu yalnızca bir özettir:<sup>[[4]](#references)</sup>

Microsoft Office belgeleri genellikle RTF ve OLE/CFBF tabanlı DOC, XLS ve PPT gibi eski biçimlerde ya da DOCX, XLSX ve PPTX gibi daha yeni **Office Open XML (OOXML)** biçimlerinde bulunur. Office belgeleri makrolar gibi etkin içerikler barındırabilir; bu da onları yaygın oltalama ve malware taşıyıcıları hâline getirir. OOXML dosyaları, dosyanın açılarak hiyerarşisi ve XML içeriği incelenebilen ZIP kapsayıcılarıdır.<sup>[[3]](#references)[[4]](#references)</sup>

OOXML dosya yapılarını incelemek için belgeyi açma komutu ve elde edilen çıktı yapısı verilmiştir. Bu dosyalarda verileri gizleme teknikleri belgelenmiştir; bu da CTF görevlerinde veri gizleme yöntemlerinin sürekli geliştirildiğini gösterir.<sup>[[4]](#references)</sup>

Analiz için **oletools** ve **OfficeDissector**, hem OLE hem de OOXML belgelerini incelemeye yönelik kapsamlı araç kümeleri sunar. Bu araçlar, genellikle malware dağıtım vektörü olarak kullanılan ve ek zararlı payload'ları indirip çalıştıran gömülü makroları belirlemeye ve analiz etmeye yardımcı olur. VBA makroları, breakpoint ve watch variable desteğiyle hata ayıklamaya olanak tanıyan LibreOffice kullanılarak Microsoft Office olmadan da analiz edilebilir.<sup>[[4]](#references)</sup>

**oletools**'un kurulumu ve kullanımı kolaydır; pip ile kurulum ve belgelerden makro çıkarma komutları verilmiştir. Word'de otomatik makrolar arasında `AutoExec` ve `AutoOpen` bulunurken, `Document_Open` bir açılış olayı yordamıdır.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

Parola şifreli Office belgeleri için [grammar-driven offline recovery workflow](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example) bölümüne bakın.

---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC yeniden hesaplama ve kontrollü gzip

Revit RFA modelleri bir [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (diğer adıyla CFBF) olarak depolanır. Serileştirilmiş model şu depolama/akış altında bulunur:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

`Global\Latest` temel düzeni (Revit 2025'te gözlemlendi):

- Header
- GZIP ile sıkıştırılmış payload (serileştirilmiş gerçek nesne grafiği)
- Sıfır dolgusu
- Hata düzeltme kodu (ECC) son eki

Revit, ECC son ekini kullanarak akıştaki küçük değişiklikleri otomatik olarak onarır ve ECC ile eşleşmeyen akışları reddeder. Bu nedenle, sıkıştırılmış baytları gelişigüzel düzenlemek değişikliklerin kalıcı olmasını sağlamaz: değişiklikleriniz ya geri alınır ya da dosya reddedilir. Serileştiricinin gördükleri üzerinde bayt düzeyinde kesin denetim sağlamak için şunları yapmanız gerekir:<sup>[[1]](#references)</sup>

- Revit'in ürettiği/kabul ettiği sıkıştırılmış baytların beklenenlerle eşleşmesi için Revit uyumlu bir gzip uygulamasıyla yeniden sıkıştırın.
- Revit'in değiştirilmiş akışı otomatik olarak onarmadan kabul etmesi için dolgulu akış üzerindeki ECC son ekini yeniden hesaplayın.

RFA içeriğini patch'lemek/fuzzing için pratik iş akışı:<sup>[[1]](#references)</sup>

1) OLE compound document'i genişletin.<sup>[[2]](#references)</sup>

```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```

2) Global\Latest’i gzip/ECC disiplinine uygun şekilde düzenleyin

- `Global/Latest` öğesini ayrıştırın: başlığı koruyun, payload’ı gunzip ile açın, baytları değiştirin ve Revit uyumlu deflate parametreleriyle yeniden gzip’leyin.
- Sıfır dolguyu koruyun ve yeni baytların Revit tarafından kabul edilmesi için ECC son ekini yeniden hesaplayın.
- Bayt düzeyinde birebir ve deterministik yeniden üretim gerekiyorsa, araştırmada gösterildiği gibi Revit’in DLL’leri etrafında gzip/gunzip yollarını ve ECC hesaplamasını çağıran minimal bir wrapper oluşturun veya bu semantiği taklit eden mevcut bir yardımcı aracı kullanın.

3) OLE bileşik belgesini yeniden oluşturun.<sup>[[2]](#references)</sup>

```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```

Notes:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool, NTFS adlarında geçersiz karakterleri escape ederek storages/streams öğelerini dosya sistemine yazar; istediğiniz stream yolu, çıktı ağacında tam olarak `Global/Latest` şeklindedir.
- Cloud storage’dan RFA dosyaları getiren ecosystem plugins aracılığıyla toplu saldırılar gerçekleştirirken, ağ enjeksiyonunu denemeden önce yamalanmış RFA dosyanızın Revit’in bütünlük kontrollerini yerel olarak geçtiğinden emin olun (gzip/ECC doğru olmalı).

Exploitation insight (gzip payload’ına hangi byte’ların yerleştirileceğine rehberlik etmek için):<sup>[[1]](#references)</sup>

- Revit deserializer, 16 bitlik bir class index okur ve bir nesne oluşturur. Bazı türler polymorphic değildir ve vtable’ları yoktur; destructor işleme mekanizmasının kötüye kullanılması, engine’in saldırgan denetimindeki bir pointer üzerinden dolaylı çağrı yürüttüğü bir type confusion’a yol açar.
- `AString` (class index `0x1F`) seçildiğinde, saldırgan denetimindeki bir heap pointer’ı nesnenin 0 offset’ine yerleştirilir. Destructor döngüsü sırasında Revit etkili olarak şunu yürütür:

```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```

- Serileştirilmiş grafiğe bu nesnelerden birden fazlasını yerleştirerek destructor döngüsünün her yinelemesinde bir gadget (“weird machine”) çalıştırılmasını sağlayın ve geleneksel bir x64 ROP chain’e stack pivot yapın.

Windows x64 pivot/gadget oluşturma ayrıntıları için buraya bakın:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

genel ROP rehberi içinse buraya bakın:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Araçlar:<sup>[[1]](#references)</sup>

- OLE compound dosyalarını genişletmek/yeniden oluşturmak için CompoundFileTool (OSS): https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- Tersine mühendislik/taint analizi için IDA Pro + WinDBG TTD; izleri daha küçük tutmak için TTD ile page heap’i devre dışı bırakın.
- Yerel bir proxy (ör. Fiddler), test amacıyla eklenti trafiğindeki RFA dosyalarını değiştirerek tedarik zinciri teslimatını simüle edebilir.

## References

- [1] [Autodesk Revit RFA Dosyası Ayrıştırmasındaki Bir Çökmeden Tam Bir RCE Exploit’i Oluşturma (ZDI blogu)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) belgeleri](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Saha Rehberi](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba belgeleri (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Makrolar (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open olayı (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
