# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

За замовчуванням **будь-який користувач** в Active Directory може **перерахувати всі DNS записи** в зонах DNS Домену або Лісу, подібно до передачі зони (користувачі можуть перерахувати дочірні об'єкти зони DNS в середовищі AD).

Інструмент [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) дозволяє **перерахування** та **експорт** **всіх DNS записів** у зоні для цілей розвідки внутрішніх мереж.
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

adidnsdump -u domain_name\\username ldap://10.10.10.10 -r
cat records.csv
```
Для отримання додаткової інформації прочитайте [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
