# 웹 페이지에서 민감한 정보 탈취

{{#include ../banners/hacktricks-training.md}}

**웹 페이지가 현재 세션을 기반으로 민감한 정보를 표시하는 경우**—예: cookies, 계정 데이터 또는 credit card details—공격자는 이를 exfiltrate하려고 시도할 수 있습니다. 주요 기법은 다음과 같습니다:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): CORS misconfiguration으로 인해 악성 origin이 cross-origin requests를 통해 민감한 responses를 읽을 수 있습니다.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): 대상 origin의 XSS vulnerability를 통해 삽입된 JavaScript가 해당 정보를 읽고 exfiltrate할 수 있습니다.
- [**Dangling markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): script injection을 사용할 수 없는 경우에도 삽입된 HTML elements가 민감한 content를 capture할 수 있습니다.
- [**Clickjacking**](../pentesting-web/clickjacking.md): framing protections이 없으면 공격자가 사용자를 속여 민감한 페이지와 상호 작용하도록 만들 수 있습니다. 링크된 case study에서 이 기법을 설명합니다.<sup>[[1]](#references)</sup>

## References

- [1] [Apache example servlet이 Information Disclosure로 이어짐](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)
{{#include ../banners/hacktricks-training.md}}
