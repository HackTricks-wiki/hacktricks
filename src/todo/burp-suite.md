# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Intruder payload types

Burp Intruder में निम्नलिखित built-in payload generators और transformations शामिल हैं:<sup>[[1]](#references)</sup>

- **Simple list:** payloads के रूप में configured strings की सूची का उपयोग करें।
- **Runtime file:** runtime पर प्रति पंक्ति एक payload पढ़ें। यह बड़ी सूचियों के लिए उपयोगी है क्योंकि Burp पूरी file को memory में load नहीं करता।
- **Case modification:** unmodified value, lowercase और uppercase forms, `Propername` (पहला अक्षर uppercase और बाकी lowercase), या `ProperName` (पहला अक्षर uppercase और शेष characters अपरिवर्तित) generate करें। Burp duplicate results को discards कर देता है।
- **Numbers:** configured range के भीतर sequential या random numbers generate करें।
- **Brute forcer:** चुने गए character set और minimum/maximum length के लिए हर permutation generate करें।

## Extensions and companion tools

- **Collabfiltrator** ऐसे payloads generate करता है जो commands execute करते हैं और उनके output को Burp Collaborator के DNS queries के माध्यम से exfiltrate करते हैं।<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** अन्य reporting workflows में उपयोग के लिए Burp findings export करता है।<sup>[[3]](#references)</sup>
- **HTTP Script Generator** HTTP requests को कई languages में scripts में convert करता है।<sup>[[4]](#references)</sup>

## References

- [1] [PortSwigger documentation - Burp Intruder payload types](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
