# 웹에서 민감한 정보 유출 도용

{{#include ../banners/hacktricks-training.md}}

어떤 시점에 **세션에 따라 민감한 정보를 제공하는 웹 페이지를 발견하면**: 쿠키를 반영하거나, 카드 세부정보를 인쇄하거나, 기타 민감한 정보를 표시할 수 있습니다. 이 정보를 도용하려고 시도할 수 있습니다.\
여기서 이를 달성하기 위해 시도할 수 있는 주요 방법을 소개합니다:

- [**CORS 우회**](../pentesting-web/cors-bypass.md): CORS 헤더를 우회할 수 있다면 악성 페이지에 대한 Ajax 요청을 수행하여 정보를 도용할 수 있습니다.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/): 페이지에서 XSS 취약점을 발견하면 이를 악용하여 정보를 도용할 수 있습니다.
- [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/): XSS 태그를 주입할 수 없다면 여전히 다른 일반 HTML 태그를 사용하여 정보를 도용할 수 있습니다.
- [**Clickjaking**](../pentesting-web/clickjacking.md): 이 공격에 대한 보호가 없다면 사용자를 속여 민감한 데이터를 보내도록 할 수 있습니다 (예시 [여기](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

{{#include ../banners/hacktricks-training.md}}
