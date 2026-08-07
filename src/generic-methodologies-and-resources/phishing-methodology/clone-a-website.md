# Bir Web Sitesini Klonlama

{{#include ../../banners/hacktricks-training.md}}


Bir phishing değerlendirmesi sırasında bazen bir web sitesini tamamen **clone/dump** etmek faydalı olabilir.

Klonlanan web sitesine, kullanıcının sekmesini "kontrol etmek" için BeEF hook gibi bazı payload'lar da ekleyebileceğinizi unutmayın.

Bu amaçla kullanabileceğiniz farklı araçlar vardır:

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
## Sosyal Mühendislik Araç Seti
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
