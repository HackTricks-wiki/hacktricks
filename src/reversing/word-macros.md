# Word Macros

{{#include ../banners/hacktricks-training.md}}

## Junk Code

Macros, analizi yavaşlatmak amacıyla **erişilemeyen veya ilgisiz kod** içerebilir. Bir dalı reverse etmeden önce sabit koşulları belirleyin ve erişilebilir davranışı izleyin. Aşağıdaki örnek, junk code'u gizlemek için asla true olamayacak bir `If` koşulu kullanır.

![Erişilemeyen bir koşullu dal ve junk code içeren Word macro'su](<../images/image (369).png>)

## Macro Forms

VBA UserForms, text box'lar gibi control'lerde veri depolayabilir. Form'lar, frame'ler ve page'ler ayrı ayrı bir `Controls` collection sunabildiğinden, analistler yalnızca formun görüntülediği içeriğe güvenmek yerine tüm control hiyerarşisini enumerate etmelidir. Aşağıdaki örnek, üst üste bindirilmiş text box'larda gizlenmiş veri depolar.<sup>[[1]](#references)</sup>

Dynamic analysis sırasında VBA'nın `GetObject` function'ı, bir file'dan Automation object'i alabilir veya halihazırda çalışan bir Automation server'a bağlanabilir. Macros, görünür document'ta belirgin olmayan verilere ulaşmak için bu object erişimini kullanabilir; hem döndürülen object'i hem de UserForm control tree'sini inceleyin.<sup>[[2]](#references)</sup>

![Üst üste bindirilmiş text box'larda gizlenmiş veri içeren bir macro UserForm'u](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Collections, controls, and objects (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [2] [Microsoft Learn - `GetObject` function](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../banners/hacktricks-training.md}}
