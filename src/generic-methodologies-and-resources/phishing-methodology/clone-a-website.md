{{#include ../../banners/hacktricks-training.md}}

フィッシング評価のために、時にはウェブサイトを完全に**クローン**することが有用です。

クローンしたウェブサイトに、ユーザーのタブを「制御」するためのBeEFフックなどのペイロードを追加することもできます。

この目的のために使用できるさまざまなツールがあります：

## wget
```text
wget -mk -nH
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
