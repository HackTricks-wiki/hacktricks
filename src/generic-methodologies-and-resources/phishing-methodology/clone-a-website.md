# Klonowanie strony internetowej

{{#include ../../banners/hacktricks-training.md}}


Podczas oceny phishingowej czasami przydatne może być całkowite **sklonowanie/zrzucenie strony internetowej**.

Pamiętaj, że do sklonowanej strony możesz również dodać payloady, takie jak BeEF hook, aby „kontrolować” kartę użytkownika.

Do tego celu możesz użyć różnych narzędzi:

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
## Narzędzia inżynierii społecznej
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
