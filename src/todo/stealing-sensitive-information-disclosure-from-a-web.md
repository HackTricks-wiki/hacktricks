# Web से Sensitive Information Disclosure चुराना

{{#include ../banners/hacktricks-training.md}}

यदि किसी समय आपको कोई **web page मिलता है जो आपके session के आधार पर sensitive information प्रस्तुत करता है**: हो सकता है कि वह cookies को reflect कर रहा हो, या CC details अथवा कोई अन्य sensitive information प्रदर्शित कर रहा हो, तो आप उसे चुराने का प्रयास कर सकते हैं।\
यहाँ वे मुख्य तरीके दिए गए हैं जिनसे आप इसे प्राप्त करने का प्रयास कर सकते हैं:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): यदि आप CORS headers को bypass कर सकते हैं, तो आप malicious page के लिए Ajax request करके information चुरा पाएंगे।
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): यदि आपको page पर XSS vulnerability मिलती है, तो आप information चुराने के लिए उसका दुरुपयोग कर सकते हैं।
- [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): यदि आप XSS tags inject नहीं कर सकते, तब भी आप अन्य regular HTML tags का उपयोग करके info चुरा सकते हैं।
- [**Clickjaking**](../pentesting-web/clickjacking.md): यदि इस attack से कोई protection नहीं है, तो आप user को sensitive data आपको भेजने के लिए trick कर सकते हैं (एक उदाहरण [यहाँ](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20) है)।<sup>[[1]](#references)</sup>

## References

- [1] [Apache example servlet leads to Information Disclosure](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)

{{#include ../banners/hacktricks-training.md}}
