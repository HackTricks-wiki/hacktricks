# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

Per impostazione predefinita, **qualsiasi utente** in Active Directory può **enumerare tutti i record DNS** nelle zone DNS del Dominio o della Foresta, simile a un trasferimento di zona (gli utenti possono elencare gli oggetti figli di una zona DNS in un ambiente AD).

Lo strumento [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) consente **l'enumerazione** e **l'esportazione** di **tutti i record DNS** nella zona per scopi di ricognizione delle reti interne.
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

adidnsdump -u domain_name\\username ldap://10.10.10.10 -r
cat records.csv
```
Per ulteriori informazioni leggi [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
