# Website Cloning

{{#include ../../banners/hacktricks-training.md}}


phishing assessment를 수행할 때는 때때로 **웹사이트를 완전히 clone/dump**하는 것이 유용할 수 있습니다.

cloned website에 BeEF hook과 같은 payload를 추가하여 사용자의 탭을 "control"할 수도 있습니다.

이 목적에 사용할 수 있는 다양한 도구가 있습니다:

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
