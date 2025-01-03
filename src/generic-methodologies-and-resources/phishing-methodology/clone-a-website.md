{{#include ../../banners/hacktricks-training.md}}

Für eine Phishing-Bewertung kann es manchmal nützlich sein, eine **Website vollständig zu klonen**.

Beachten Sie, dass Sie auch einige Payloads zur geklonten Website hinzufügen können, wie einen BeEF-Hook, um den Tab des Benutzers zu "steuern".

Es gibt verschiedene Tools, die Sie zu diesem Zweck verwenden können:

## wget
```text
wget -mk -nH
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
