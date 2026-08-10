# किसी Website को Clone करना

Phishing assessment के लिए कभी-कभी किसी **website को पूरी तरह clone/dump** करना उपयोगी हो सकता है।

ध्यान दें कि आप cloned website में कुछ payloads भी जोड़ सकते हैं, जैसे किसी user के tab को "control" करने के लिए BeEF hook।

इस उद्देश्य के लिए आप अलग-अलग tools का उपयोग कर सकते हैं:

## wget

निम्न command Wget के mirroring, page-requisite, link-conversion और extension-adjustment modes का उपयोग करती है, फिर downloaded files को current directory से Python के `http.server` module द्वारा port 8000 पर serve करती है।<sup>[[1]](#references)[[2]](#references)</sup>
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone

goclone repository इस utility को किसी website को उसकी relative link structure को सुरक्षित रखते हुए local directory में download करने के रूप में वर्णित करता है और `goclone <url>` invocation को document करता है।<sup>[[3]](#references)</sup>
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Social Engineering Toolit

Social-Engineer Toolkit (SET) repository में SET को authorized social-engineering assessments के लिए एक open-source penetration-testing framework के रूप में पहचाना गया है।<sup>[[4]](#references)</sup>
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
## References

- [1] [GNU Wget मैनुअल](https://www.gnu.org/software/wget/manual/wget.html)
- [2] [Python `http.server` दस्तावेज़ीकरण](https://docs.python.org/3/library/http.server.html)
- [3] [goclone रिपॉज़िटरी](https://github.com/imthaghost/goclone)
- [4] [Social-Engineer Toolkit रिपॉज़िटरी](https://github.com/trustedsec/social-engineer-toolkit)
{{#include ../../banners/hacktricks-training.md}}
