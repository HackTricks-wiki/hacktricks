# ウェブからの機密情報漏洩の盗難

{{#include ./banners/hacktricks-training.md}}

もしあなたが**セッションに基づいて機密情報を表示するウェブページ**を見つけた場合：クッキーを反映しているか、印刷またはクレジットカードの詳細やその他の機密情報を表示しているかもしれません。あなたはそれを盗むことを試みるかもしれません。\
ここでは、それを達成するために試すことができる主な方法を紹介します：

- [**CORSバイパス**](pentesting-web/cors-bypass.md)：CORSヘッダーをバイパスできれば、悪意のあるページに対してAjaxリクエストを行うことで情報を盗むことができます。
- [**XSS**](pentesting-web/xss-cross-site-scripting/): ページにXSS脆弱性が見つかれば、それを悪用して情報を盗むことができるかもしれません。
- [**ダンギングマークアップ**](pentesting-web/dangling-markup-html-scriptless-injection/): XSSタグを注入できない場合でも、他の通常のHTMLタグを使用して情報を盗むことができるかもしれません。
- [**クリックジャッキング**](pentesting-web/clickjacking.md)：この攻撃に対する保護がない場合、ユーザーを騙して機密データを送信させることができるかもしれません（例は[こちら](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)）。

{{#include ./banners/hacktricks-training.md}}
