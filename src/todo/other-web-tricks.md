# अन्य Web Tricks

{{#include ../banners/hacktricks-training.md}}

### Host header

कई बार back-end कुछ actions करने के लिए **Host header** पर trust करता है। उदाहरण के लिए, यह इसके value का उपयोग **password reset भेजने के domain** के रूप में कर सकता है। इसलिए जब आपको अपना password reset करने के लिए link वाला ईमेल मिलता है, तो उपयोग किया जा रहा domain वही होता है जिसे आपने Host header में डाला था। फिर, आप अन्य users का password reset request कर सकते हैं और domain को अपने control वाले domain में बदलकर उनके password reset codes चुरा सकते हैं। [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> ध्यान दें कि token प्राप्त करने के लिए आपको user के reset password link पर click करने का इंतजार भी नहीं करना पड़ सकता, क्योंकि संभव है कि **spam filters या अन्य intermediary devices/bots इसका analysis करने के लिए इस पर click कर दें**।

### Session booleans

कभी-कभी जब आप कोई verification सही तरीके से पूरा करते हैं, तो back-end **आपके session के किसी security attribute में केवल "True" value वाला boolean जोड़ देता है**। इसके बाद, कोई अलग endpoint यह जान लेगा कि आपने वह check successfully pass किया है।\
हालांकि, यदि आप **check pass कर लेते हैं** और आपके session को security attribute में वह "True" value मिल जाती है, तो आप **अन्य resources को access करने** का प्रयास कर सकते हैं जो **उसी attribute पर depend करते हैं**, लेकिन जिन्हें access करने की **आपके पास permissions नहीं होनी चाहिए**। [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Register functionality

किसी पहले से existent user के रूप में register करने का प्रयास करें। Equivalent characters (dots, बहुत सारे spaces और Unicode) का उपयोग करके भी प्रयास करें।

### Takeover emails

एक email register करें, उसे confirm करने से पहले email बदल दें। फिर, यदि नया confirmation email पहले registered email पर भेजा जाता है, तो आप किसी भी email का takeover कर सकते हैं। या यदि आप पहले email को confirm करके second email enable कर सकते हैं, तो आप किसी भी account का भी takeover कर सकते हैं।

### atlassian का उपयोग करने वाली companies के Internal servicedesk को access करना


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

Developers production environment में विभिन्न debugging options disable करना भूल सकते हैं। उदाहरण के लिए, HTTP `TRACE` method diagnostic purposes के लिए designed है। यदि यह enabled हो, तो web server `TRACE` method का उपयोग करने वाले requests का response देते समय received exact request को echo करेगा। यह behaviour अक्सर harmless होता है, लेकिन कभी-कभी information disclosure का कारण बनता है, जैसे internal authentication headers के नाम, जिन्हें reverse proxies द्वारा requests में append किया जा सकता है।![पोस्ट के लिए चित्र](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![पोस्ट के लिए चित्र](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [How I was able to take over any user's account with Host Header Injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
