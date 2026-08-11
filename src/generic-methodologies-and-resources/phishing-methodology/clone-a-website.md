# Bir Web Sitesini Klonlama

{{#include ../../banners/hacktricks-training.md}}

Bir phishing assessment sırasında bazen bir web sitesini tamamen **clone/dump** etmek faydalı olabilir.

Klonlanan web sitesine, kullanıcının sekmesini "kontrol etmek" için BeEF hook gibi bazı payload'lar da ekleyebileceğinizi unutmayın.

Bu amaçla kullanabileceğiniz farklı araçlar vardır:

## wget

Aşağıdaki komut Wget'in mirror oluşturma, sayfa gereksinimleri, link dönüştürme ve uzantı ayarlama modlarını kullanır; ardından indirilen dosyaları geçerli dizinden Python'ın `http.server` modülüyle 8000 portunda sunar.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone

goclone repository, yardımcı programı bir website'i göreli bağlantı yapısını koruyarak yerel bir dizine indirmek olarak tanımlar ve `goclone <url>` kullanımını belgeler.<sup>[[3]](#references)</sup>
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Sosyal Mühendislik Araç Seti

Social-Engineer Toolkit (SET) repository, SET'i yetkilendirilmiş sosyal mühendislik değerlendirmeleri için açık kaynaklı bir pentesting framework'ü olarak tanımlar.<sup>[[4]](#references)</sup>
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
## References

- [1] [GNU Wget Kılavuzu](https://www.gnu.org/software/wget/manual/wget.html)
- [2] [Python `http.server` belgeleri](https://docs.python.org/3/library/http.server.html)
- [3] [goclone deposu](https://github.com/imthaghost/goclone)
- [4] [Social-Engineer Toolkit deposu](https://github.com/trustedsec/social-engineer-toolkit)
{{#include ../../banners/hacktricks-training.md}}
