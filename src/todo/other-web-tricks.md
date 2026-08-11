# Other Web Tricks

{{#include ../banners/hacktricks-training.md}}

## Host header

Back ends कभी-कभी absolute links बनाते समय HTTP `Host` field पर भरोसा करते हैं। यदि password-reset email में attacker-supplied host का उपयोग होता है, तो किसी victim के लिए reset का अनुरोध करने पर token-bearing link attacker-controlled domain के माध्यम से भेजा जा सकता है। प्रत्येक proxy hop पर forwarded-host fields, duplicate Host handling और absolute-form request targets का भी परीक्षण करें।<sup>[[1]](#references)</sup>

> [!WARNING]
> User का click आवश्यक नहीं हो सकता: **mail security scanners, preview services या अन्य intermediaries attacker-controlled link का अनुरोध स्वचालित रूप से कर सकते हैं**, जिससे reset token उजागर हो सकता है।

## Session booleans

कुछ applications completed verification को session में boolean के रूप में record करती हैं और फिर किसी अलग endpoint को उस flag पर निर्भर करने देती हैं। किसी resource की check को वैध रूप से pass करने के बाद जाँचें कि क्या वही flag गलती से किसी अलग user, object या workflow को authorize करता है। यह केवल IDOR नहीं, बल्कि second-order authorization/state-reuse flaw है।<sup>[[2]](#references)</sup>

## Registration functionality

किसी पहले से मौजूद user के रूप में register करने का प्रयास करें। Equivalent characters का उपयोग करके भी प्रयास करें (dots, बहुत सारे spaces और Unicode)।

## Email-change state confusion

किसी email address को register करें और confirmation से पहले उसे बदलें। जाँचें कि क्या नए address का confirmation पुराने address पर भेजा जाता है, या पुराने token की पुष्टि करने से नया address activate हो जाता है। Confirmation tokens को exact account, pending address, purpose और current state से bound होना चाहिए।

## Exposed Atlassian service desks


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

## TRACE method

HTTP `TRACE` method diagnostics के लिए प्राप्त request का loop-back अनुरोध करता है। RFC 9110 के अनुसार recipients को reflected content से credentials और cookies जैसे sensitive fields को हटाना आवश्यक है, लेकिन unsafe implementations या intermediary-added headers फिर भी internal request transformations उजागर कर सकते हैं। Browsers script-generated TRACE requests को रोकते हैं, इसलिए historical cross-site tracing attack protected fields inject करने के किसी अलग तरीके पर भी निर्भर करता है।<sup>[[3]](#references)</sup>![TRACE response दिखाती हुई image](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![post के लिए image](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [मैं Host Header Injection के माध्यम से किसी भी user का account takeover करने में सक्षम हुआ](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [एक कम ज्ञात attack vector: Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)
- [3] [RFC 9110, section 9.3.8 — TRACE](https://www.rfc-editor.org/rfc/rfc9110.html#name-trace)
{{#include ../banners/hacktricks-training.md}}
