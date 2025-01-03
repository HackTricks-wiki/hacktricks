{{#include ../banners/hacktricks-training.md}}

# 攻撃の概要

サーバーが**データ**に**秘密**を追加して**署名**し、そのデータをハッシュ化していると想像してください。もしあなたが以下を知っているなら：

- **秘密の長さ**（これは与えられた長さの範囲からブルートフォースで求めることもできます）
- **平文データ**
- **アルゴリズム（そしてそれがこの攻撃に対して脆弱であること）**
- **パディングが知られている**
- 通常はデフォルトのものが使用されるため、他の3つの要件が満たされていれば、これもそうです
- パディングは秘密+データの長さに応じて異なるため、秘密の長さが必要です

その場合、**攻撃者**は**データ**を**追加**し、**以前のデータ + 追加されたデータ**の有効な**署名**を**生成**することが可能です。

## どうやって？

基本的に、脆弱なアルゴリズムは最初に**データのブロックをハッシュ化**し、その後、**以前に**作成された**ハッシュ**（状態）から**次のデータのブロックを追加**して**ハッシュ化**します。

例えば、秘密が「secret」でデータが「data」の場合、「secretdata」のMD5は6036708eba0d11f6ef52ad44e8b74d5bです。\
攻撃者が「append」という文字列を追加したい場合、彼は以下のことができます：

- 64個の「A」のMD5を生成する
- 以前に初期化されたハッシュの状態を6036708eba0d11f6ef52ad44e8b74d5bに変更する
- 文字列「append」を追加する
- ハッシュを完了させ、その結果のハッシュは「secret」 + 「data」 + 「padding」 + 「append」の**有効なもの**になります

## **ツール**

{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}

## 参考文献

この攻撃については、[https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)でよく説明されています。

{{#include ../banners/hacktricks-training.md}}
