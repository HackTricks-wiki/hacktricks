# Web からの機密情報の開示の窃取

{{#include ../banners/hacktricks-training.md}}

ある時点で、**セッションに基づいて機密情報を表示する Web ページ**を見つけた場合: Cookie を反映したり、カード情報やその他の機密情報を出力したりするページなどです。これを盗み出せる可能性があります。\
ここでは、それを実現するために試せる主な方法を紹介します:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): CORS ヘッダーを bypass できれば、悪意のあるページから Ajax リクエストを実行して情報を盗み出せます。
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): ページに XSS の脆弱性が見つかった場合、それを悪用して情報を盗み出せる可能性があります。
- [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): XSS タグをインジェクトできない場合でも、他の通常の HTML タグを使って情報を盗み出せる可能性があります。
- [**Clickjaking**](../pentesting-web/clickjacking.md): この攻撃への保護がない場合、ユーザーをだまして機密データを送信させられる可能性があります（例は[こちら](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)）。<sup>[[1]](#references)</sup>

## References

- [1] [Apache example servlet leads to Information Disclosure](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)

{{#include ../banners/hacktricks-training.md}}
