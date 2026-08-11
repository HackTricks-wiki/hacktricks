# Website 복제

{{#include ../../banners/hacktricks-training.md}}

phishing assessment를 위해 때로는 **웹사이트를 완전히 clone/dump**하는 것이 유용할 수 있습니다.

복제된 웹사이트에 BeEF hook과 같은 payloads를 추가하여 사용자의 탭을 "control"할 수도 있습니다.

이 용도로 사용할 수 있는 도구는 여러 가지가 있습니다.

## wget

다음 명령은 Wget의 mirroring, page-requisite, link-conversion 및 extension-adjustment 모드를 사용한 다음, Python의 `http.server` 모듈을 사용하여 현재 디렉터리에서 다운로드한 파일을 포트 8000으로 제공합니다.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone

goclone repository는 상대 링크 구조를 유지하면서 웹사이트를 로컬 디렉터리에 다운로드하는 utility로 설명하며, `goclone <url>` 실행 방법을 문서화합니다.<sup>[[3]](#references)</sup>
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Social Engineering Toolit

Social-Engineer Toolkit (SET) repository는 SET를 authorized social-engineering assessments를 위한 오픈 소스 penetration-testing framework로 식별합니다.<sup>[[4]](#references)</sup>
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
## References

- [1] [GNU Wget 매뉴얼](https://www.gnu.org/software/wget/manual/wget.html)
- [2] [Python `http.server` 문서](https://docs.python.org/3/library/http.server.html)
- [3] [goclone 저장소](https://github.com/imthaghost/goclone)
- [4] [Social-Engineer Toolkit 저장소](https://github.com/trustedsec/social-engineer-toolkit)
{{#include ../../banners/hacktricks-training.md}}
