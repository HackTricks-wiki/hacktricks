# Stealing Sensitive Information from a Web Page

{{#include ../banners/hacktricks-training.md}}

If a **web page displays sensitive information based on the current session**—such as cookies, account data, or credit card details—an attacker may try to exfiltrate it. The main techniques include:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): A CORS misconfiguration may allow a malicious origin to read sensitive responses through cross-origin requests.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): An XSS vulnerability in the target origin may allow injected JavaScript to read and exfiltrate the information.
- [**Dangling markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): When script injection is unavailable, injected HTML elements may still capture sensitive content.
- [**Clickjacking**](../pentesting-web/clickjacking.md): If framing protections are absent, an attacker may trick a user into interacting with the sensitive page. The linked case study demonstrates this technique.<sup>[[1]](#references)</sup>

## References

- [1] [Apache example servlet leads to Information Disclosure](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)

{{#include ../banners/hacktricks-training.md}}
