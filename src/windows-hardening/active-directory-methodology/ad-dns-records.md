# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

Po default-u **bilo koji korisnik** u Active Directory može **enumerisati sve DNS zapise** u DNS zonama Domena ili Šume, slično prenosu zone (korisnici mogu da navedu podobjekte DNS zone u AD okruženju).

Alat [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) omogućava **enumeraciju** i **izvoz** **svi DNS zapisa** u zoni za svrhe rekognicije unutrašnjih mreža.
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

adidnsdump -u domain_name\\username ldap://10.10.10.10 -r
cat records.csv
```
Za više informacija pročitajte [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
