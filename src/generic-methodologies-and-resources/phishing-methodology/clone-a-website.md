{{#include ../../banners/hacktricks-training.md}}

Phishing değerlendirmesi için bazen bir **web sitesini** tamamen kopyalamak faydalı olabilir.

Kopyalanan web sitesine, kullanıcının sekmesini "kontrol" etmek için bir BeEF hook'u gibi bazı payload'lar da ekleyebilirsiniz.

Bu amaçla kullanabileceğiniz farklı araçlar vardır:

## wget
```text
wget -mk -nH
```
## goclone
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Sosyal Mühendislik Araç Seti
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
