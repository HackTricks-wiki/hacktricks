# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Intruder payload के प्रकार

Burp Intruder में निम्नलिखित built-in payload generators और transformations शामिल हैं:<sup>[[1]](#references)</sup>

- **Simple list:** Strings की configured list को payloads के रूप में इस्तेमाल करें।
- **Runtime file:** Runtime पर हर पंक्ति से एक payload पढ़ें। यह बड़ी lists के लिए उपयोगी है, क्योंकि Burp पूरी file को memory में load नहीं करता।
- **Case modification:** मूल value, lowercase और uppercase रूप, `Propername` (पहला अक्षर uppercase और बाकी lowercase), या `ProperName` (पहला अक्षर uppercase और बाकी अक्षर अपरिवर्तित) generate करें। Burp duplicate results को हटा देता है।
- **Numbers:** Configured range में sequential या random numbers generate करें।
- **Brute forcer:** चुने गए character set और minimum/maximum length के लिए हर permutation generate करें।

## Extensions और companion tools

- **Collabfiltrator** ऐसे payloads generate करता है जो commands execute करते हैं और उनके output को DNS queries के ज़रिए Burp Collaborator तक exfiltrate करते हैं।<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** Burp findings को दूसरे reporting workflows में उपयोग के लिए export करता है।<sup>[[3]](#references)</sup>
- **HTTP Script Generator** HTTP requests को कई languages में scripts में बदलता है।<sup>[[4]](#references)</sup>

## Session Switcher के साथ multi-session authorization testing

[Session Switcher](https://github.com/doyensec/burp-session-switcher), Burp Suite `2025.5+` के लिए Java extension है, जो cookies और uncommon headers को named credential profiles के रूप में store करता है। Editable request editor—जिसमें Repeater या intercepted Proxy request शामिल हैं—में profile चुनने पर request का authentication material बदल जाता है। यह replay में मदद करने वाला tool है, **authorization bypass नहीं**: इसका इस्तेमाल अलग-अलग accounts के रूप में वही request भेजने के लिए करें, ताकि [web testing methodology](../pentesting-web/web-vulnerabilities-methodology.md) के हिस्से के तौर पर horizontal access, vertical role boundaries, tenant isolation और [IDOR/BOLA](../pentesting-web/idor.md) जाँचे जा सकें।<sup>[[5]](#references)[[8]](#references)</sup>

### दोहराने योग्य identity-differential workflow

यह workflow resource/action और acting identity को अलग-अलग test variables रखता है, जिससे पुराने tokens या गलत browser session के कारण मिलने वाले false results कम होते हैं।<sup>[[5]](#references)[[8]](#references)</sup>

1. हर संबंधित user, role और tenant को दर्शाने वाले test accounts को अलग-अलग browser profiles या containers में authenticate करें।
2. किसी identity की cookies और headers वाली request खोलें, **Sessions > New** चुनें और profile को स्पष्ट नाम दें, जैसे `tenant-a-user` या `tenant-b-admin`। हर test identity के लिए यह दोहराएँ।
3. Candidate request को Repeater में भेजें और method, endpoint, parameters या object identifier बदले बिना replay करें; केवल selected session बदलें। सिर्फ status codes ही नहीं, response data और दिखाई देने वाले state changes की भी तुलना करें।
4. Object-level checks के लिए, account A के किसी ज्ञात object की request को account B का profile चुनकर replay करें। Function-level checks के लिए, वही privileged action कम privileges वाले profiles के साथ replay करें।
5. दोबारा authentication या token rotation के बाद, तुलना दोहराने से पहले किसी मौजूदा browser request पर **Update** करें या Auto Update rule configure करें।

### Capture और injection के semantics

Testing से पहले update/injection modes की समीक्षा करें, क्योंकि दो identities के credentials वाली hybrid request तुलना को अमान्य कर सकती है। मौजूदा defaults profile में request की सभी cookies को mirror करते हैं, केवल पहले से stored uncommon headers को update करते हैं, selected profile की cookies को destination request में mirror करते हैं (उसकी मौजूदा cookies हटाकर), और profile के headers जोड़ते हैं। Selector को किसी exact subdomain, top-level application domain (default), या सभी saved profiles तक सीमित किया जा सकता है।<sup>[[7]](#references)</sup>

- **Mirror** तब उपयोगी है जब पूरा cookie set identity तय करता हो और destination की पुरानी cookies हटानी हों।
- **Update existing** browser traffic से असंबंधित cookies या headers सीखे बिना rotating values को अपडेट करता है।
- **Add all** profile या request में पहले से मौजूद अतिरिक्त values बनाए रखता है; जाँच लें कि इससे पिछले session का identity-bearing data बाकी न रह जाए।
- **Do nothing** उन credential classes की cookies या headers को profile updates से बाहर रखता है जो अप्रासंगिक हों।

### Proxy-आधारित session synchronization

Auto Update rules Proxy traffic को saved profile से जोड़ते हैं और उसकी cookies/headers refresh करते हैं। किसी स्थिर discriminator को प्राथमिकता दें, जैसे dedicated request header, profile-specific `User-Agent` marker, identifying cookie, `X-PwnFox-Color`, या JWT claim; इसे scope/domain/path conditions के साथ मिलाएँ, ताकि असंबंधित applications profile को update न कर सकें। एक rule में सभी conditions क्रम से logical `AND` के रूप में जाँची जाती हैं, इसलिए restrictive checks पहले रखें; `OR` लागू करने के लिए उसी profile को target करने वाले कई rules बनाएँ। Negative matching भी supported है।<sup>[[6]](#references)</sup>

हर matching rule के लिए cookies और headers पर स्वतंत्र रूप से **Mirror request**, **Add all**, **Update existing**, या **Do nothing** चुनें। Request-only rules Proxy के request मिलने पर चलते हैं; response-status, response-header या response-body condition जोड़ने पर evaluation response आने तक टल जाता है। Highlight color से matching traffic को mark किया जा सकता है, जिससे यह जाँचना आसान होता है कि हर browser identity केवल अपना intended profile ही update करे।<sup>[[6]](#references)</sup>

Saved profiles Burp project में रहते हैं, और JSON project-data exports में sessions तथा उनकी cookies और headers शामिल होते हैं। इन दोनों files को live credential material मानें, उन तक पहुँच सीमित रखें और engagement के बाद stored extension data मिटा दें।<sup>[[7]](#references)[[8]](#references)</sup>

## References

- [1] [PortSwigger documentation - Burp Intruder payload के प्रकार](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
- [5] [Doyensec - Session Switcher के source और usage का documentation](https://github.com/doyensec/burp-session-switcher)
- [6] [Doyensec - Session Switcher Auto Update Rules](https://github.com/doyensec/burp-session-switcher/blob/main/docs/auto_update_rules.md)
- [7] [Doyensec - Session Switcher की settings](https://github.com/doyensec/burp-session-switcher/blob/main/docs/settings.md)
- [8] [Doyensec - Session Switcher: Burp Suite में Multi-Session Authorization Testing को आसान बनाना](https://blog.doyensec.com/2026/06/17/session-switcher.html)
{{#include ../banners/hacktricks-training.md}}
