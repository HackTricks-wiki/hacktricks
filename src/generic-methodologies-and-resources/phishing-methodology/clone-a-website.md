# Website को Clone करना

{{#include ../../banners/hacktricks-training.md}}

Phishing assessment के लिए कभी-कभी किसी **website को पूरी तरह clone/dump करना** उपयोगी हो सकता है।

ध्यान दें कि आप cloned website में कुछ payloads भी जोड़ सकते हैं, जैसे उपयोगकर्ता के tab को "control" करने के लिए BeEF hook।

इस उद्देश्य के लिए आप अलग-अलग tools का उपयोग कर सकते हैं:

## wget

निम्न command Wget के mirroring, page-requisite, link-conversion और extension-adjustment modes का उपयोग करती है, फिर Python के `http.server` module के साथ वर्तमान directory से downloaded files को port 8000 पर serve करती है।<sup>[[1]](#references)[[2]](#references)</sup>
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone

goclone repository इस utility को relative link structure को बनाए रखते हुए किसी website को local directory में download करने के रूप में वर्णित करता है और `goclone <url>` invocation को document करता है।<sup>[[3]](#references)</sup>
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Social Engineering Toolit

Social-Engineer Toolkit (SET) repository SET को अधिकृत social-engineering assessments के लिए open-source penetration-testing framework के रूप में पहचानता है।<sup>[[4]](#references)</sup>
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
## References

- [1] [GNU Wget Manual](https://www.gnu.org/software/wget/manual/wget.html)
- [2] [Python `http.server` documentation](https://docs.python.org/3/library/http.server.html)
- [3] [goclone repository](https://github.com/imthaghost/goclone)
- [4] [Social-Engineer Toolkit repository](https://github.com/trustedsec/social-engineer-toolkit)
{{#include ../../banners/hacktricks-training.md}}
