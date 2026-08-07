# Eine Website klonen

{{#include ../../banners/hacktricks-training.md}}


Bei einem Phishing-Assessment kann es manchmal hilfreich sein, eine Website vollständig zu **klonen/zu dumpen**.

Beachte, dass du der geklonten Website auch einige Payloads hinzufügen kannst, beispielsweise einen BeEF-Hook, um den Tab des Benutzers zu „kontrollieren“.

Für diesen Zweck kannst du verschiedene Tools verwenden:

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
## Social Engineering Toolkit
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
