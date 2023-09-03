# DCSync

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Utilice [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y automatizar fácilmente flujos de trabajo con las herramientas comunitarias más avanzadas del mundo.\
Obtenga acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## DCSync

El permiso **DCSync** implica tener estos permisos sobre el propio dominio: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** y **Replicating Directory Changes In Filtered Set**.

**Notas importantes sobre DCSync:**

* El ataque **DCSync simula el comportamiento de un Controlador de Dominio y solicita a otros Controladores de Dominio que repliquen información** utilizando el Protocolo Remoto de Replicación de Directorio (MS-DRSR). Debido a que MS-DRSR es una función válida y necesaria de Active Directory, no se puede desactivar ni deshabilitar.
* Por defecto, solo los grupos **Domain Admins, Enterprise Admins, Administrators y Domain Controllers** tienen los privilegios necesarios.
* Si alguna contraseña de cuenta se almacena con cifrado reversible, Mimikatz ofrece la opción de devolver la contraseña en texto claro.

### Enumeración

Verifique quién tiene estos permisos utilizando `powerview`:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Explotar Localmente

DCSync is a technique that allows an attacker to impersonate a domain controller and request the replication of password data from the targeted domain controller. This technique can be used to extract password hashes from the Active Directory database without the need for administrative privileges.

To exploit DCSync locally, the attacker needs to have administrative access to a machine within the domain. Once access is obtained, the attacker can use the `mimikatz` tool to execute the DCSync command and retrieve the password hashes.

The following steps outline the process to exploit DCSync locally:

1. Launch an elevated command prompt on the compromised machine.

2. Download and execute the `mimikatz` tool on the compromised machine.

3. Load the `lsadump` module within `mimikatz` by running the command `privilege::debug` followed by `lsadump::dcsync /domain:<domain_name> /user:<username>`.

4. Replace `<domain_name>` with the name of the targeted domain and `<username>` with the username of the account whose password hash you want to retrieve.

5. If successful, `mimikatz` will retrieve the password hash and display it on the screen.

By exploiting DCSync locally, an attacker can gain access to password hashes, which can then be cracked to obtain the actual passwords. This technique highlights the importance of securing domain controllers and limiting administrative access to prevent unauthorized access and potential password leaks.
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Explotar de forma remota

DCSync is a technique that allows an attacker to impersonate a domain controller and request password data from the targeted domain controller. This technique takes advantage of the replication process in Active Directory to retrieve password hashes from the targeted domain controller without being detected.

To exploit this vulnerability remotely, the attacker needs to have remote access to a domain-joined machine or a compromised user account with sufficient privileges. The attacker can then use tools like Mimikatz or Impacket to execute the DCSync attack.

The DCSync attack can be executed in two ways: using the DRSUAPI method or the LDAP method. The DRSUAPI method is the preferred method as it allows the attacker to retrieve password hashes for all domain users, including the krbtgt account, which is used for Kerberos authentication.

To execute the DCSync attack remotely using the DRSUAPI method, the attacker needs to run the following command:

```
mimikatz # lsadump::dcsync /domain:<domain_name> /user:<username>
```

Replace `<domain_name>` with the name of the targeted domain and `<username>` with the username of the account for which the password hash is being retrieved.

The LDAP method can be used if the DRSUAPI method is not available. However, it has some limitations, such as not being able to retrieve the krbtgt account password hash.

To execute the DCSync attack remotely using the LDAP method, the attacker needs to run the following command:

```
mimikatz # lsadump::dcsync /user:<username> /domain:<domain_name> /dc:<dc_name>
```

Replace `<username>` with the username of the account for which the password hash is being retrieved, `<domain_name>` with the name of the targeted domain, and `<dc_name>` with the name of the domain controller.

It is important to note that the DCSync attack requires administrative privileges on the targeted domain controller. Additionally, the attack can be detected by monitoring for event ID 4662 in the Windows Security event logs.

By exploiting the DCSync vulnerability remotely, an attacker can retrieve password hashes from a domain controller and use them to perform offline password cracking or gain unauthorized access to other systems within the domain.
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` genera 3 archivos:

* uno con los **hashes NTLM**
* uno con las **claves Kerberos**
* uno con contraseñas en texto claro de NTDS para cualquier cuenta configurada con [**encriptación reversible**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) habilitada. Puedes obtener usuarios con encriptación reversible con el siguiente comando en PowerShell:

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistencia

Si eres un administrador de dominio, puedes otorgar estos permisos a cualquier usuario con la ayuda de `powerview`:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Entonces, puedes **verificar si al usuario se le asignaron correctamente** los 3 privilegios buscándolos en la salida de (deberías poder ver los nombres de los privilegios dentro del campo "ObjectType"):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigación

* Evento de seguridad ID 4662 (La política de auditoría para el objeto debe estar habilitada) - Se realizó una operación en un objeto.
* Evento de seguridad ID 5136 (La política de auditoría para el objeto debe estar habilitada) - Se modificó un objeto del servicio de directorio.
* Evento de seguridad ID 4670 (La política de auditoría para el objeto debe estar habilitada) - Se cambiaron los permisos en un objeto.
* AD ACL Scanner - Crea y compara informes de ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Referencias

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family).
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com).
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al repositorio [hacktricks](https://github.com/carlospolop/hacktricks) y al repositorio [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y automatizar fácilmente flujos de trabajo con las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
