# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

Por defecto, **cualquier usuario** en Active Directory puede **enumerar todos los registros DNS** en las zonas DNS del Dominio o del Bosque, similar a una transferencia de zona (los usuarios pueden listar los objetos secundarios de una zona DNS en un entorno AD).

La herramienta [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) permite la **enumeración** y **exportación** de **todos los registros DNS** en la zona para fines de reconocimiento de redes internas.
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

adidnsdump -u domain_name\\username ldap://10.10.10.10 -r
cat records.csv
```
Para más información, lee [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
