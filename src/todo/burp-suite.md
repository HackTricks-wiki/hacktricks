# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Basic Payloads

- **Simple List:** हर पंक्ति में एक entry वाली list
- **Runtime File:** Runtime में पढ़ी जाने वाली list (memory में load नहीं होती)। बड़ी lists को support करने के लिए।
- **Case Modification:** strings की list पर कुछ changes लागू करें (No change, to lower, to UPPER, to Proper name - First capitalized and the rest to lower-, to Proper Name -First capitalized an the rest remains the same-.
- **Numbers:** Z step या randomly का उपयोग करके X से Y तक numbers generate करें।
- **Brute Forcer:** Character set, min & max length।

[https://github.com/0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator) : commands execute करने और output को burpcollab पर DNS requests के माध्यम से grab करने के लिए Payload।

{{#ref}}
https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e
{{#endref}}

[https://github.com/h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)

{{#include ../banners/hacktricks-training.md}}
