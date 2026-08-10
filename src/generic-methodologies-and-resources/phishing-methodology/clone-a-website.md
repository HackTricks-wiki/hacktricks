# Bir Web Sitesini Clone'lama

Bir phishing assessment sırasında bazen bir web sitesini tamamen **clone/dump** etmek faydalı olabilir.

Clone'lanan web sitesine, kullanıcının sekmesini "kontrol etmek" için BeEF hook gibi bazı payload'lar da ekleyebileceğinizi unutmayın.

Bu amaçla kullanabileceğiniz farklı araçlar vardır:

## wget

Aşağıdaki komut Wget'in mirroring, page-requisite, link-conversion ve extension-adjustment modlarını kullanır, ardından indirilen dosyaları Python'un `http.server` modülüyle geçerli dizinden 8000 portunda sunar.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone

goclone repository, bir web sitesini göreli bağlantı yapısını koruyarak yerel bir dizine indiren bir araç olarak tanımlar ve `goclone <url>` kullanımını belgeler.<sup>[[3]](#references)</sup>
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Sosyal Mühendislik Toolit

Social-Engineer Toolkit (SET) repository, SET'i yetkili sosyal mühendislik değerlendirmeleri için açık kaynaklı bir penetration-testing framework olarak tanımlar.<sup>[[4]](#references)</sup>
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
## References

- [1] [GNU Wget Kullanım Kılavuzu](https://www.gnu.org/software/wget/manual/wget.html)
- [2] [Python `http.server` belgeleri](https://docs.python.org/3/library/http.server.html)
- [3] [goclone deposu](https://github.com/imthaghost/goclone)
- [4] [Social-Engineer Toolkit deposu](https://github.com/trustedsec/social-engineer-toolkit)
{{#include ../../banners/hacktricks-training.md}}
