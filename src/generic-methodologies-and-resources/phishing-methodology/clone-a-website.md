# WebsiteのClone

{{#include ../../banners/hacktricks-training.md}}

フィッシング評価では、Webサイトを完全に**clone/dump**すると便利な場合があります。

cloneしたWebサイトには、ユーザーのタブを「control」するためのBeEF hookなど、payloadsを追加することもできます。

この目的に使用できるツールはいくつかあります。

## wget

次のコマンドは、Wgetのmirroring、page-requisite、link-conversion、extension-adjustmentモードを使用し、その後、Pythonの`http.server`モジュールで現在のディレクトリからダウンロードしたファイルをポート8000で提供します。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone

goclone repository は、相対リンク構造を維持したまま Web サイトをローカルディレクトリにダウンロードする utility として説明されており、`goclone <url>` の実行方法を記載しています。<sup>[[3]](#references)</sup>
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## ソーシャルエンジニアリングツールキット

Social-Engineer Toolkit (SET) の repository では、SET を authorized な social-engineering assessments 向けの open-source penetration-testing framework と説明しています。<sup>[[4]](#references)</sup>
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
## References

- [1] [GNU Wget マニュアル](https://www.gnu.org/software/wget/manual/wget.html)
- [2] [Python `http.server` ドキュメント](https://docs.python.org/3/library/http.server.html)
- [3] [goclone リポジトリ](https://github.com/imthaghost/goclone)
- [4] [Social-Engineer Toolkit リポジトリ](https://github.com/trustedsec/social-engineer-toolkit)
{{#include ../../banners/hacktricks-training.md}}
