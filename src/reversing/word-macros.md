# Word Macros

{{#include ../banners/hacktricks-training.md}}

## ジャンクコード

Macros には、解析を遅延させる目的で **到達不能なコードや無関係なコード** が含まれている場合があります。分岐の reverse に時間をかける前に、常に成立しない条件を特定し、到達可能な挙動を追跡してください。以下の例では、決して true にならない `If` 条件を使用してジャンクコードを隠しています。

![到達不能な条件分岐とジャンクコードを含む Word macro](<../images/image (369).png>)

## Macro Forms

VBA UserForms は、テキストボックスなどのコントロールにデータを保存できます。フォーム、フレーム、ページはそれぞれ `Controls` コレクションを公開できるため、表示されているフォームの内容だけに頼らず、コントロール階層全体を列挙する必要があります。以下の例では、重なったテキストボックスに隠されたデータを保存しています。<sup>[[1]](#references)</sup>

動的解析では、VBA の `GetObject` 関数を使用して、ファイルから Automation オブジェクトを取得したり、すでに実行中の Automation server に接続したりできます。Macros はこのオブジェクトアクセスを使用して、表示されているドキュメントからは明らかでないデータに到達する場合があります。返されたオブジェクトと UserForm のコントロールツリーの両方を調査してください。<sup>[[2]](#references)</sup>

![重なったテキストボックスにデータを隠した macro UserForm](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - コレクション、コントロール、オブジェクト (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [2] [Microsoft Learn - `GetObject` 関数](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../banners/hacktricks-training.md}}
