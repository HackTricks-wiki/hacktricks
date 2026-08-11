# Web Page からの Sensitive Information の窃取

{{#include ../banners/hacktricks-training.md}}

**web page が current session に基づいて sensitive information**（cookies、account data、credit card details など）を表示する場合、attacker はそれを exfiltrate しようとする可能性があります。主な techniques には次のものがあります。

- [**CORS bypass**](../pentesting-web/cors-bypass.md): CORS の misconfiguration により、malicious origin が cross-origin requests を通じて sensitive responses を読み取れる可能性があります。
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): target origin の XSS vulnerability により、injected JavaScript が information を読み取り、exfiltrate できる可能性があります。
- [**Dangling markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): script injection が利用できない場合でも、injected HTML elements によって sensitive content を capture できる可能性があります。
- [**Clickjacking**](../pentesting-web/clickjacking.md): framing protections が存在しない場合、attacker は user を誘導して sensitive page と interaction させる可能性があります。リンク先の case study では、この technique を実証しています。<sup>[[1]](#references)</sup>

## References

- [1] [Apache example servlet が Information Disclosure を引き起こす](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)
{{#include ../banners/hacktricks-training.md}}
