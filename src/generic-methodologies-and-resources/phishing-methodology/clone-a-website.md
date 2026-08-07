# Website को Clone करना

{{#include ../../banners/hacktricks-training.md}}


फ़िशिंग assessment के लिए कभी-कभी किसी **website को पूरी तरह clone/dump करना** उपयोगी हो सकता है।

ध्यान दें कि आप cloned website में कुछ payloads भी जोड़ सकते हैं, जैसे BeEF hook, ताकि user के tab को "control" किया जा सके।

इस उद्देश्य के लिए आप अलग-अलग tools का उपयोग कर सकते हैं:

## wget
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Social Engineering Toolit
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
