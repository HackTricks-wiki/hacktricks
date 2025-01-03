{{#include ../../banners/hacktricks-training.md}}

피싱 평가를 위해 때때로 **웹사이트를 완전히 복제하는 것**이 유용할 수 있습니다.

복제된 웹사이트에 BeEF 훅과 같은 페이로드를 추가하여 사용자의 탭을 "제어"할 수도 있습니다.

이 목적을 위해 사용할 수 있는 다양한 도구가 있습니다:

## wget
```text
wget -mk -nH
```
## goclone
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## 소셜 엔지니어링 툴킷
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
