# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Basic Payloads

- **Simple List:** 各行に1つのエントリを含む単純なリスト
- **Runtime File:** runtimeで読み込むリスト（メモリにはロードされない）。大規模なリストをサポートするために使用。
- **Case Modification:** 文字列のリストに変更を適用（変更なし、小文字、UPPERCASE、Proper name - 先頭を大文字にして残りを小文字にする-、Proper Name - 先頭を大文字にして残りはそのままにする-）。
- **Numbers:** XからYまでの数値を、Zのステップまたはランダムで生成。
- **Brute Forcer:** 文字セット、最小および最大の長さ。

[https://github.com/0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator) : burpcollabへのDNS requestsを介してcommandsを実行し、outputを取得するPayload。

{{#ref}}
https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e
{{#endref}}

[https://github.com/h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)

{{#include ../banners/hacktricks-training.md}}
