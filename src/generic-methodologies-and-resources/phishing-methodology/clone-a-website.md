# WebsiteのClone

phishing assessmentでは、Websiteを完全に**clone/dump**すると便利な場合があります。

cloneしたWebsiteには、BeEF hookなどのpayloadsを追加して、ユーザーのtabを「control」することもできます。

この目的で使用できるtoolはいくつかあります。

## wget

次のcommandは、Wgetのmirroring、page-requisite、link-conversion、extension-adjustment modesを使用し、続いてPythonの`http.server` moduleで、downloadしたfilesをcurrent directoryからport 8000でserveします。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone

goclone repository は、この utility を相対リンク構造を維持したまま website をローカルディレクトリに download するものとして説明しており、`goclone <url>` の invocation を documentation しています。<sup>[[3]](#references)</sup>
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## ソーシャルエンジニアリング Toolit

Social-Engineer Toolkit (SET) リポジトリは、SETを、認可されたソーシャルエンジニアリング評価向けのオープンソースのpenetration-testing frameworkとして位置付けています。<sup>[[4]](#references)</sup>
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
## References

- [1] [GNU Wget マニュアル](https://www.gnu.org/software/wget/manual/wget.html)
- [2] [Python `http.server` ドキュメント](https://docs.python.org/3/library/http.server.html)
- [3] [goclone リポジトリ](https://github.com/imthaghost/goclone)
- [4] [Social-Engineer Toolkit リポジトリ](https://github.com/trustedsec/social-engineer-toolkit)
{{#include ../../banners/hacktricks-training.md}}
