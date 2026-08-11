# Word Makroları

{{#include ../banners/hacktricks-training.md}}

## Junk Code

Makrolar, analizi yavaşlatmak amacıyla **ulaşılamayan veya ilgisiz kod** içerebilir. Bir dalı reverse etmeye zaman harcamadan önce sabit koşulları belirleyin ve erişilebilir davranışı izleyin. Aşağıdaki örnekte, Junk Code'u gizlemek için asla true olamayacak bir `If` koşulu kullanılmıştır.

![Junk Code içeren, ulaşılamayan koşullu bir dala sahip Word makrosu](<../images/image (369).png>)

## Macro Formları

VBA UserForms, verileri metin kutuları gibi kontrollerde depolayabilir. Formlar, çerçeveler ve sayfaların her biri bir `Controls` collection sunabildiğinden, analistler yalnızca formun görüntülediği içeriklere güvenmek yerine tüm kontrol hiyerarşisini enumerate etmelidir. Aşağıdaki örnekte gizlenmiş veriler üst üste binen metin kutularında depolanmıştır.<sup>[[1]](#references)</sup>

![Üst üste binen metin kutularında gizlenmiş veriler içeren bir macro UserForm'u](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Collections, kontroller ve nesneler (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
{{#include ../banners/hacktricks-training.md}}
