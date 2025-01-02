# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

Standardmäßig kann **jeder Benutzer** in Active Directory **alle DNS-Einträge** in den DNS-Zonen der Domäne oder des Waldes auflisten, ähnlich wie bei einem Zonenübertrag (Benutzer können die untergeordneten Objekte einer DNS-Zone in einer AD-Umgebung auflisten).

Das Tool [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) ermöglicht die **Auflistung** und **Exportierung** **aller DNS-Einträge** in der Zone zu Recon-Zwecken interner Netzwerke.
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

adidnsdump -u domain_name\\username ldap://10.10.10.10 -r
cat records.csv
```
Für weitere Informationen lesen Sie [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
