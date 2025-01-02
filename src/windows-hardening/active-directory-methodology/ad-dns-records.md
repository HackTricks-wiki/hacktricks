# AD DNS Rekords

{{#include ../../banners/hacktricks-training.md}}

Standaard kan **enige gebruiker** in Active Directory **alle DNS rekords** in die Domein of Woud DNS sones **opnoem**, soortgelyk aan 'n sonetransfer (gebruikers kan die kindobjekte van 'n DNS son in 'n AD omgewing lys).

Die hulpmiddel [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) stel **opname** en **uitvoer** van **alle DNS rekords** in die son vir rekonsidering doeleindes van interne netwerke in staat.
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

adidnsdump -u domain_name\\username ldap://10.10.10.10 -r
cat records.csv
```
Vir meer inligting lees [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
