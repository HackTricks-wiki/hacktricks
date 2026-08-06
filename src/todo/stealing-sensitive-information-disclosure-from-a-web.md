# Web에서 민감한 정보 Disclosure 탈취

{{#include ../banners/hacktricks-training.md}}

어떤 시점에 **세션을 기반으로 민감한 정보를 표시하는 web page**를 발견했다면: 쿠키를 반영하거나, 신용카드 또는 기타 민감한 정보를 출력하는 경우, 이를 탈취할 수 있습니다.\
여기에서는 이를 수행하기 위해 시도할 수 있는 주요 방법을 소개합니다:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): CORS headers를 우회할 수 있다면 malicious page에서 Ajax request를 수행하여 정보를 탈취할 수 있습니다.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): page에서 XSS vulnerability를 찾았다면 이를 악용하여 정보를 탈취할 수 있습니다.
- [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): XSS tags를 주입할 수 없더라도 다른 일반적인 HTML tags를 사용하여 정보를 탈취할 수 있습니다.
- [**Clickjaking**](../pentesting-web/clickjacking.md): 이 attack에 대한 protection이 없다면 사용자를 속여 민감한 데이터를 전송하게 만들 수 있습니다 ([여기](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)에 예시가 있습니다).<sup>[[1]](#references)</sup>

## References

- [1] [Apache example servlet leads to Information Disclosure](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)

{{#include ../banners/hacktricks-training.md}}
