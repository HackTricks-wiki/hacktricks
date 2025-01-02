# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

Kwa default **mtumiaji yeyote** katika Active Directory anaweza **kuorodhesha rekodi zote za DNS** katika eneo la Domain au Forest DNS, sawa na uhamishaji wa eneo (watumiaji wanaweza orodhesha vitu vya watoto vya eneo la DNS katika mazingira ya AD).

Zana [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) inaruhusu **kuorodhesha** na **kutoa** **rekodi zote za DNS** katika eneo kwa madhumuni ya upelelezi wa mitandao ya ndani.
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

adidnsdump -u domain_name\\username ldap://10.10.10.10 -r
cat records.csv
```
Kwa maelezo zaidi soma [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
