# Office dosyası analizi

{{#include ../../../banners/hacktricks-training.md}}

Daha fazla bilgi için [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/) adresine bakın. Bu yalnızca bir özettir:<sup>[[2]](#references)</sup>

Microsoft Office belgeleri genellikle RTF ve OLE/CFBF tabanlı DOC, XLS ve PPT gibi eski biçimlerde veya DOCX, XLSX ve PPTX gibi daha yeni **Office Open XML (OOXML)** biçimlerinde bulunur. Office belgeleri makro gibi etkin içerikler barındırabilir; bu nedenle kimlik avı ve malware taşıyıcısı olarak sıkça kullanılır. OOXML dosyaları, dosya hiyerarşisi ve XML içerikleri açılarak incelenebilen ZIP kapsayıcılarıdır.<sup>[[1]](#references)[[2]](#references)</sup>

OOXML dosya yapılarını incelemek için bir belgeyi açma komutu ve elde edilen çıktı yapısı verilmiştir. Bu dosyalarda verileri gizleme teknikleri belgelenmiştir; bu da CTF yarışmalarında veri gizleme yöntemlerinin sürekli geliştirildiğini göstermektedir.<sup>[[2]](#references)</sup>

Analiz için **oletools** ve **OfficeDissector**, hem OLE hem de OOXML belgelerini incelemeye yönelik kapsamlı araç setleri sunar. Bu araçlar, genellikle malware dağıtım vektörü olarak kullanılan ve ek zararlı payload'ları indirip çalıştıran gömülü makroları belirlemeye ve analiz etmeye yardımcı olur. VBA makroları, Microsoft Office kullanmadan Libre Office ile analiz edilebilir; Libre Office, breakpoint ve watch variable kullanarak hata ayıklamaya olanak tanır.<sup>[[2]](#references)</sup>

**oletools** kurulumu ve kullanımı kolaydır; pip ile kurulum ve belgelerden makro çıkarma komutları verilmiştir. Word'de otomatik makrolar arasında `AutoExec` ve `AutoOpen` bulunurken, `Document_Open` bir açılış olayı prosedürüdür.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

## VBA makro analizi: gereksiz kod ve UserForms

## Gereksiz Kod

Makrolar, analizi yavaşlatmak amacıyla **erişilemeyen veya ilgisiz kod** içerebilir. Bir dalı tersine mühendisliğe tabi tutmaya zaman ayırmadan önce sabit koşulları belirleyin ve erişilebilir davranışı izleyin. Aşağıdaki örnekte, hiçbir zaman doğru olamayacak bir `If` koşulu gereksiz kodu gizlemek için kullanılıyor.

![Erişilemeyen koşullu dal ve gereksiz kod içeren bir Word makrosu](<../../../images/image (369).png>)

## Makro Formları

VBA UserForms, metin kutuları gibi denetimlerde veri saklayabilir. Formlar, çerçeveler ve sayfaların her biri bir `Controls` koleksiyonu sunabildiğinden, analistler yalnızca formda görünenlere güvenmek yerine denetim hiyerarşisinin tamamını listelemelidir. Aşağıdaki örnekte gizlenmiş veriler, üst üste binen metin kutularında saklanıyor.<sup>[[6]](#references)</sup>

Dinamik analiz sırasında VBA'nın `GetObject` işlevi, bir dosyadan Automation nesnesi alabilir veya hâlihazırda çalışan bir Automation sunucusuna bağlanabilir. Makrolar, görünür belgede açıkça fark edilmeyen verilere erişmek için bu nesne erişimini kullanabilir; döndürülen nesneyi ve UserForm denetim ağacını inceleyin.<sup>[[7]](#references)</sup>

![Üst üste binen metin kutularında gizlenmiş veriler içeren bir makro UserForm'u](<../../../images/image (344).png>)

Parola ile şifrelenmiş Office belgeleri için [gramer odaklı çevrimdışı kurtarma iş akışına](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example) bakın.

---

OLE/CFBF kullanan Revit RFA dosyaları için [ECC yeniden hesaplama, kontrollü gzip ve deserializer istismarına](../../../binary-exploitation/revit-rfa-ole-compound-file-exploitation.md) bakın; bu parser istismarı iş akışı, Office belgelerinin ön incelemesinden ayrıdır.

## References

- [1] [OLE Bileşik Dosya (CFBF) belgeleri](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [2] [Adli Bilişim CTF Saha Rehberi](https://trailofbits.github.io/ctf/forensics/)
- [3] [olevba belgeleri (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [4] [Otomatik Makrolar (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [5] [Document.Open olayı (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
- [6] [Microsoft Learn - Koleksiyonlar, denetimler ve nesneler (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [7] [Microsoft Learn - `GetObject` işlevi](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../../../banners/hacktricks-training.md}}
