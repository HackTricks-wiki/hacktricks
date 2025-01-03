{{#include ../../banners/hacktricks-training.md}}

Aby przeprowadzić ocenę phishingową, czasami może być przydatne całkowite **sklonowanie strony internetowej**.

Zauważ, że możesz również dodać do sklonowanej strony pewne ładunki, takie jak hak BeEF, aby "kontrolować" kartę użytkownika.

Istnieją różne narzędzia, które możesz wykorzystać do tego celu:

## wget
```text
wget -mk -nH
```
## goclone
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Narzędzie inżynierii społecznej
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
