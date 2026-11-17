# Officeファイルの分析

{{#include ../../../banners/hacktricks-training.md}}

詳しくは[https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)を参照してください。ここでは概要のみ説明します:<sup>[[2]](#references)</sup>

Microsoft Officeドキュメントには、RTFやOLE/CFBFベースのDOC、XLS、PPTなどのレガシー形式や、DOCX、XLSX、PPTXなどの新しい**Office Open XML (OOXML)**形式がよく使われます。Officeドキュメントにはマクロなどのアクティブコンテンツが含まれることがあり、フィッシングやマルウェアの配布によく利用されます。OOXMLファイルはZIPコンテナであり、解凍すればファイル階層やXMLの内容を調べられます。<sup>[[1]](#references)[[2]](#references)</sup>

OOXMLファイルの構造を調べるため、ドキュメントを解凍するコマンドと、出力される構造が示されています。これらのファイルにデータを隠す手法も文書化されており、CTFチャレンジにおけるデータ隠蔽の手法が今も進化していることが分かります。<sup>[[2]](#references)</sup>

分析には、**oletools**と**OfficeDissector**を使うと、OLEドキュメントとOOXMLドキュメントの両方を包括的に調査できます。これらのツールを使えば、マルウェア配布の経路となることが多い埋め込みマクロを特定して分析できます。マクロは通常、追加の悪意あるペイロードをダウンロードして実行します。VBAマクロは、Microsoft Officeを使わずにLibreOfficeで分析できます。LibreOfficeでは、ブレークポイントやウォッチ変数を使ったデバッグが可能です。<sup>[[2]](#references)</sup>

**oletools**のインストールと使用は簡単です。pipによるインストールや、ドキュメントからマクロを抽出するコマンドが紹介されています。Wordの自動実行マクロには`AutoExec`や`AutoOpen`があり、`Document_Open`はドキュメントを開いたときに実行されるイベントプロシージャです。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

## VBA macro の分析: ジャンクコードと UserForms

## ジャンクコード

マクロには、分析を遅らせることを目的とした**到達不能または無関係なコード**が含まれている場合があります。分岐のリバースに時間を費やす前に、定数条件を特定し、到達可能な動作を追跡してください。以下の例では、決して真にならない `If` 条件を使ってジャンクコードを隠しています。

![到達不能な条件分岐にジャンクコードが含まれる Word マクロ](<../../../images/image (369).png>)

## マクロフォーム

VBA UserForms は、テキストボックスなどのコントロールにデータを保存できます。フォーム、フレーム、ページはそれぞれ `Controls` コレクションを公開する場合があるため、フォーム上に表示されるものだけに頼らず、コントロール階層全体を列挙してください。以下の例では、重なり合うテキストボックスに隠しデータを保存しています。<sup>[[6]](#references)</sup>

動的解析では、VBA の `GetObject` 関数を使って、ファイルから Automation オブジェクトを取得したり、すでに実行中の Automation サーバーに接続したりできます。マクロはこのオブジェクトアクセスを利用して、表示中のドキュメントからは分かりにくいデータにアクセスする場合があります。返されたオブジェクトと UserForm のコントロールツリーの両方を調べてください。<sup>[[7]](#references)</sup>

![重なり合うテキストボックスにデータを隠したマクロ UserForm](<../../../images/image (344).png>)

パスワードで暗号化された Office ドキュメントについては、[文法駆動型のオフライン復元ワークフロー](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example)を参照してください。

---

OLE/CFBF を使用する Revit RFA ファイルについては、[ECC の再計算、制御された gzip、デシリアライザーの悪用](../../../binary-exploitation/revit-rfa-ole-compound-file-exploitation.md)を参照してください。このパーサー悪用ワークフローは、Office ドキュメントのトリアージとは別のものです。

## References

- [1] [OLE Compound File (CFBF) ドキュメント](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [2] [フォレンジック CTF フィールドガイド](https://trailofbits.github.io/ctf/forensics/)
- [3] [olevba ドキュメント (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [4] [自動マクロ (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [5] [Document.Open イベント (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
- [6] [Microsoft Learn - コレクション、コントロール、オブジェクト (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [7] [Microsoft Learn - `GetObject` 関数](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../../../banners/hacktricks-training.md}}
