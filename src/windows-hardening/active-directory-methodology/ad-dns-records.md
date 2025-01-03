# AD DNS Kayıtları

{{#include ../../banners/hacktricks-training.md}}

Varsayılan olarak **herhangi bir kullanıcı** Active Directory'de **tüm DNS kayıtlarını** Alan veya Orman DNS alanlarında **listeleyebilir**, bu bir alan transferine benzer (kullanıcılar, bir AD ortamında bir DNS alanının alt nesnelerini listeleyebilir).

Araç [**adidnsdump**](https://github.com/dirkjanm/adidnsdump), iç ağların keşif amaçları için alan içindeki **tüm DNS kayıtlarının** **listelemesini** ve **dışa aktarılmasını** sağlar.
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

adidnsdump -u domain_name\\username ldap://10.10.10.10 -r
cat records.csv
```
Daha fazla bilgi için [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
