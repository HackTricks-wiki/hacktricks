# वेब पेज से संवेदनशील जानकारी चुराना

{{#include ../banners/hacktricks-training.md}}

यदि कोई **वेब पेज वर्तमान session के आधार पर संवेदनशील जानकारी प्रदर्शित करता है**—जैसे cookies, account data या credit card details—तो attacker उसे exfiltrate करने का प्रयास कर सकता है। मुख्य techniques में शामिल हैं:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): CORS misconfiguration malicious origin को cross-origin requests के माध्यम से sensitive responses पढ़ने की अनुमति दे सकती है।
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): target origin में XSS vulnerability injected JavaScript को जानकारी पढ़ने और exfiltrate करने की अनुमति दे सकती है।
- [**Dangling markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): जब script injection उपलब्ध न हो, तब भी injected HTML elements sensitive content capture कर सकते हैं।
- [**Clickjacking**](../pentesting-web/clickjacking.md): यदि framing protections अनुपस्थित हों, तो attacker user को sensitive page के साथ interact करने के लिए धोखा दे सकता है। Linked case study इस technique को प्रदर्शित करती है।<sup>[[1]](#references)</sup>

## References

- [1] [Apache example servlet से Information Disclosure होता है](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)
{{#include ../banners/hacktricks-training.md}}
