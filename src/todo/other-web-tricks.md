# अन्य Web Tricks

{{#include ../banners/hacktricks-training.md}}

### Host header

कई बार back-end कुछ actions करने के लिए **Host header** पर trust करता है। उदाहरण के लिए, यह इसके value का उपयोग **password reset भेजने के domain** के रूप में कर सकता है। इसलिए जब आपको अपना password reset करने के लिए link वाला email मिलता है, तो इस्तेमाल किया जा रहा domain वही होता है जिसे आपने Host header में डाला था। फिर, आप अन्य users के password reset का request कर सकते हैं और domain को अपने control वाले domain में बदलकर उनके password reset codes चुरा सकते हैं। [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> ध्यान दें कि token प्राप्त करने के लिए आपको user के reset password link पर click करने की प्रतीक्षा करने की भी आवश्यकता नहीं हो सकती, क्योंकि संभव है कि **spam filters या अन्य intermediary devices/bots इसे analyze करने के लिए click कर दें**।

### Session booleans

कभी-कभी जब आप कोई verification सही तरीके से पूरा करते हैं, तो back-end आपकी session के security attribute में **value "True" वाला केवल एक boolean जोड़ देता है**। फिर, एक अलग endpoint यह जान लेता है कि आपने वह check सफलतापूर्वक pass किया है।\
हालांकि, यदि आप **check pass करते हैं** और आपकी session को security attribute में वह "True" value मिल जाती है, तो आप **अन्य resources access करने का प्रयास** कर सकते हैं जो **उसी attribute पर निर्भर हैं**, लेकिन जिन्हें access करने की **आपके पास permissions नहीं होनी चाहिए**। [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Register functionality

पहले से मौजूद user के रूप में register करने का प्रयास करें। Equivalent characters (dots, बहुत सारे spaces और Unicode) का उपयोग करके भी प्रयास करें।

### Takeover emails

एक email register करें, confirmation से पहले email बदल दें, फिर यदि नया confirmation email पहले registered email पर भेजा जाता है, तो आप किसी भी email को takeover कर सकते हैं। या यदि पहले email की पुष्टि करके आप दूसरे email को enable कर सकते हैं, तो आप किसी भी account को भी takeover कर सकते हैं।

### atlassian का उपयोग करके कंपनियों के Internal servicedesk को access करना


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

Developers production environment में विभिन्न debugging options को disable करना भूल सकते हैं। उदाहरण के लिए, HTTP `TRACE` method diagnostic purposes के लिए design किया गया है। यदि यह enabled हो, तो web server `TRACE` method का उपयोग करने वाले requests का response में वही exact request echo करके जवाब देगा जो प्राप्त हुई थी। यह behaviour अक्सर harmless होता है, लेकिन कभी-कभी information disclosure का कारण बनता है, जैसे internal authentication headers के नाम, जिन्हें reverse proxies requests में append कर सकते हैं।![Post के लिए image](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Post के लिए image](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [How I was able to take over any user's account with Host Header injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
