# Websiteのクローン作成

{{#include ../../banners/hacktricks-training.md}}


phishing assessmentでは、**websiteを完全にclone/dump**すると便利な場合があります。

cloned websiteにBeEF hookなどのpayloadsを追加して、ユーザーのtabを「control」することもできます。

この目的には、さまざまなtoolsを使用できます。

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
## ソーシャルエンジニアリングツールキット
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
