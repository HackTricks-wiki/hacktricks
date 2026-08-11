# Word マクロ

{{#include ../banners/hacktricks-training.md}}

## ジャンクコード

Macros may contain **解析を遅らせる目的の、到達不能または無関係なコード**。定数条件を特定し、branch の reverse に時間をかける前に、到達可能な挙動を追跡する。以下の例では、決して true にならない `If` condition を使用して、ジャンクコードを隠している。

![到達不能な conditional branch とジャンクコードを含む Word マクロ](<../images/image (369).png>)

## Macro Forms

VBA UserForms は、text box などの control に data を保存できる。form、frame、page はそれぞれ `Controls` collection を公開できるため、analyst は form に表示される内容だけに依存せず、control hierarchy 全体を列挙する必要がある。以下の例では、重なった text box に concealed data を保存している。<sup>[[1]](#references)</sup>

![重なった text box に data を隠した macro UserForm](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Collections、controls、objects（Microsoft Forms）](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
{{#include ../banners/hacktricks-training.md}}
