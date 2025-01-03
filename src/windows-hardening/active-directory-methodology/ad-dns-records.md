# Registros DNS do AD

{{#include ../../banners/hacktricks-training.md}}

Por padrão, **qualquer usuário** no Active Directory pode **enumerar todos os registros DNS** nas zonas DNS do Domínio ou da Floresta, semelhante a uma transferência de zona (os usuários podem listar os objetos filhos de uma zona DNS em um ambiente AD).

A ferramenta [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) permite a **enumeração** e **exportação** de **todos os registros DNS** na zona para fins de reconhecimento de redes internas.
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

adidnsdump -u domain_name\\username ldap://10.10.10.10 -r
cat records.csv
```
Para mais informações, leia [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
