# Webからの機密情報漏洩の盗難

{{#include ../banners/hacktricks-training.md}}

もしあなたが**セッションに基づいて機密情報を表示するウェブページ**を見つけた場合：クッキーを反映しているか、CCの詳細やその他の機密情報を印刷しているかもしれません、それを盗むことを試みることができます。\
ここでは、それを達成するために試すことができる主な方法を紹介します：

- [**CORSバイパス**](../pentesting-web/cors-bypass.md)：CORSヘッダーをバイパスできれば、悪意のあるページに対してAjaxリクエストを行うことで情報を盗むことができます。
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html)：ページにXSSの脆弱性がある場合、それを悪用して情報を盗むことができるかもしれません。
- [**ダンギングマークアップ**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html)：XSSタグを注入できない場合でも、他の通常のHTMLタグを使用して情報を盗むことができるかもしれません。
- [**クリックジャッキング**](../pentesting-web/clickjacking.md)：この攻撃に対する保護がない場合、ユーザーを騙して機密データを送信させることができるかもしれません（例は[こちら](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)）。

{{#include ../banners/hacktricks-training.md}}
