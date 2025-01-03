{{#include ./banners/hacktricks-training.md}}

# 基本ペイロード

- **シンプルリスト:** 各行にエントリが含まれるリスト
- **ランタイムファイル:** ランタイムで読み込まれるリスト（メモリにロードされない）。大きなリストをサポートするため。
- **ケース変更:** 文字列のリストにいくつかの変更を適用する（変更なし、小文字、大文字、適切な名前 - 最初の文字を大文字にし、残りを小文字にする、適切な名前 - 最初の文字を大文字にし、残りはそのままにする）。
- **数字:** XからYまでの数字をZステップで生成するか、ランダムに生成する。
- **ブルートフォース:** 文字セット、最小および最大長。

[https://github.com/0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator) : コマンドを実行し、burpcollabへのDNSリクエストを介して出力を取得するためのペイロード。

{% embed url="https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e" %}

[https://github.com/h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)

{{#include ./banners/hacktricks-training.md}}
