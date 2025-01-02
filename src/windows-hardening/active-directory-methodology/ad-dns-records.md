# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

Par défaut, **tout utilisateur** dans Active Directory peut **énumérer tous les enregistrements DNS** dans les zones DNS de domaine ou de forêt, similaire à un transfert de zone (les utilisateurs peuvent lister les objets enfants d'une zone DNS dans un environnement AD).

L'outil [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) permet **l'énumération** et **l'exportation** de **tous les enregistrements DNS** dans la zone à des fins de reconnaissance des réseaux internes.
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

adidnsdump -u domain_name\\username ldap://10.10.10.10 -r
cat records.csv
```
Pour plus d'informations, lisez [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
