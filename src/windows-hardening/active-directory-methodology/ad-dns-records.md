# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

Domyślnie **każdy użytkownik** w Active Directory może **enumerować wszystkie rekordy DNS** w strefach DNS domeny lub lasu, podobnie jak transfer strefy (użytkownicy mogą wylistować obiekty podrzędne strefy DNS w środowisku AD).

Narzędzie [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) umożliwia **enumerację** i **eksport** **wszystkich rekordów DNS** w strefie w celach rekonesansu wewnętrznych sieci.
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

adidnsdump -u domain_name\\username ldap://10.10.10.10 -r
cat records.csv
```
Aby uzyskać więcej informacji, przeczytaj [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
