# Metodología de Active Directory

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) en GitHub.

</details>

## Visión general básica

**Active Directory** sirve como una tecnología fundamental que permite a los **administradores de red** crear y gestionar eficientemente **dominios**, **usuarios** y **objetos** dentro de una red. Está diseñado para escalar, facilitando la organización de un gran número de usuarios en **grupos** y **subgrupos** manejables, al mismo tiempo que controla los **derechos de acceso** en varios niveles.

La estructura de **Active Directory** se compone de tres capas principales: **dominios**, **árboles** y **bosques**. Un **dominio** abarca una colección de objetos, como **usuarios** o **dispositivos**, que comparten una base de datos común. Los **árboles** son grupos de estos dominios vinculados por una estructura compartida, y un **bosque** representa la colección de múltiples árboles interconectados a través de **relaciones de confianza**, formando la capa superior de la estructura organizativa. Se pueden designar **derechos de acceso** y **comunicación específicos** en cada uno de estos niveles.

Conceptos clave dentro de **Active Directory** incluyen:

1. **Directorio** – Almacena toda la información relacionada con los objetos de Active Directory.
2. **Objeto** – Denota entidades dentro del directorio, incluyendo **usuarios**, **grupos** o **carpetas compartidas**.
3. **Dominio** – Sirve como contenedor para objetos de directorio, con la capacidad de que múltiples dominios coexistan dentro de un **bosque**, manteniendo cada uno su propia colección de objetos.
4. **Árbol** – Un grupo de dominios que comparten un dominio raíz común.
5. **Bosque** – El pináculo de la estructura organizativa en Active Directory, compuesto por varios árboles con **relaciones de confianza** entre ellos.

**Active Directory Domain Services (AD DS)** abarca una variedad de servicios críticos para la gestión centralizada y la comunicación dentro de una red. Estos servicios incluyen:

1. **Servicios de Dominio** – Centraliza el almacenamiento de datos y gestiona las interacciones entre **usuarios** y **dominios**, incluyendo funcionalidades de **autenticación** y **búsqueda**.
2. **Servicios de Certificados** – Supervisa la creación, distribución y gestión de **certificados digitales** seguros.
3. **Servicios de Directorio Ligero** – Admite aplicaciones habilitadas para directorios a través del protocolo **LDAP**.
4. **Servicios de Federación de Directorios** – Proporciona capacidades de **inicio de sesión único** para autenticar usuarios en múltiples aplicaciones web en una sola sesión.
5. **Gestión de Derechos** – Ayuda a proteger el material con derechos de autor regulando su distribución y uso no autorizado.
6. **Servicio DNS** – Crucial para la resolución de **nombres de dominio**.

Para obtener una explicación más detallada, consulta: [**TechTerms - Definición de Active Directory**](https://techterms.com/definition/active_directory)


### **Autenticación Kerberos**

Para aprender a **atacar un AD** necesitas **comprender** muy bien el proceso de **autenticación Kerberos**.\
[**Lee esta página si aún no sabes cómo funciona.**](kerberos-authentication.md)

## Hoja de trucos

Puedes acceder a [https://wadcoms.github.io/](https://wadcoms.github.io) para tener una vista rápida de los comandos que puedes ejecutar para enumerar/explotar un AD.

## Reconocimiento de Active Directory (Sin credenciales/sesiones)

Si solo tienes acceso a un entorno de AD pero no tienes credenciales/sesiones, podrías:

* **Realizar una prueba de penetración en la red:**
* Escanear la red, encontrar máquinas y puertos abiertos e intentar **explotar vulnerabilidades** o **extraer credenciales** de ellos (por ejemplo, [las impresoras podrían ser objetivos muy interesantes](ad-information-in-printers.md).
* Enumerar DNS podría proporcionar información sobre servidores clave en el dominio como web, impresoras, compartidos, vpn, medios, etc.
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* Echa un vistazo a la [**Metodología General de Pruebas de Penetración**](../../generic-methodologies-and-resources/pentesting-methodology.md) para obtener más información sobre cómo hacer esto.
* **Verificar el acceso nulo y de invitado en los servicios smb** (esto no funcionará en versiones modernas de Windows):
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* Se puede encontrar una guía más detallada sobre cómo enumerar un servidor SMB aquí:

{% content-ref url="../../network-services-pentesting/pentesting-smb.md" %}
[pentesting-smb.md](../../network-services-pentesting/pentesting-smb.md)
{% endcontent-ref %}

* **Enumerar Ldap**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* Se puede encontrar una guía más detallada sobre cómo enumerar LDAP aquí (presta **especial atención al acceso anónimo**):

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **Envenenar la red**
* Recopilar credenciales [**suplantando servicios con Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* Acceder al host mediante [**abusar del ataque de relé**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
* Recopilar credenciales **exponiendo** [**servicios UPnP falsos con evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology):
* Extraer nombres de usuario/nombres de documentos internos, redes sociales, servicios (principalmente web) dentro de los entornos de dominio y también de los disponibles públicamente.
* Si encuentras los nombres completos de los trabajadores de la empresa, podrías probar diferentes **convenciones de nombres de usuario de AD** ([**lee esto**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Las convenciones más comunes son: _NombreApellido_, _Nombre.Apellido_, _NamApe_ (3 letras de cada uno), _Nam.Ape_, _NApellido_, _N.Apellido_, _ApellidoNombre_, _Apellido.Nombre_, _ApellidoN_, _Apellido.N_, 3 _letras aleatorias y 3 números aleatorios_ (abc123).
* Herramientas:
* [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
* [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeración de usuarios

* **Enum. anónima SMB/LDAP:** Consulta las páginas de [**pentesting SMB**](../../network-services-pentesting/pentesting-smb.md) y [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
* **Enum. Kerbrute**: Cuando se solicita un **nombre de usuario no válido**, el servidor responderá utilizando el código de error de Kerberos _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_, lo que nos permite determinar que el nombre de usuario era inválido. Los **nombres de usuario válidos** provocarán la respuesta del **TGT en un AS-REP** o el error _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_, indicando que el usuario debe realizar una preautenticación.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **Servidor de OWA (Outlook Web Access)**

Si encuentras uno de estos servidores en la red, también puedes realizar **enumeración de usuarios contra él**. Por ejemplo, podrías usar la herramienta [**MailSniper**](https://github.com/dafthack/MailSniper):
```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```
{% hint style="warning" %}
Puedes encontrar listas de nombres de usuario en [**este repositorio de github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) y en este otro ([**nombres de usuario estadísticamente probables**](https://github.com/insidetrust/statistically-likely-usernames)).

Sin embargo, deberías tener el **nombre de las personas que trabajan en la empresa** del paso de reconocimiento que deberías haber realizado antes. Con el nombre y apellido, podrías usar el script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para generar posibles nombres de usuario válidos.
{% endhint %}

### Conocer uno o varios nombres de usuario

Ok, así que sabes que ya tienes un nombre de usuario válido pero no las contraseñas... Entonces intenta:

* [**ASREPRoast**](asreproast.md): Si un usuario **no tiene** el atributo _DONT\_REQ\_PREAUTH_ puedes **solicitar un mensaje AS\_REP** para ese usuario que contendrá algunos datos encriptados por una derivación de la contraseña del usuario.
* [**Password Spraying**](password-spraying.md): Intenta las contraseñas más **comunes** con cada uno de los usuarios descubiertos, tal vez algún usuario esté usando una contraseña débil (¡ten en cuenta la política de contraseñas!).
* Ten en cuenta que también puedes **rociar servidores de OWA** para intentar acceder a los servidores de correo de los usuarios.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### Envenenamiento LLMNR/NBT-NS

Podrías **obtener** algunos **hashes de desafío** para crackear **envenenando** algunos protocolos de la **red**:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### Relevo NTML

Si has logrado enumerar el directorio activo tendrás **más correos electrónicos y una mejor comprensión de la red**. Podrías ser capaz de forzar ataques de relevo NTML [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) para obtener acceso al entorno de AD.

### Robar credenciales NTLM

Si puedes **acceder a otras PCs o recursos compartidos** con el **usuario nulo o invitado** podrías **colocar archivos** (como un archivo SCF) que si se acceden de alguna manera desencadenarán una autenticación NTML contra ti para que puedas **robar** el **desafío NTLM** para crackearlo:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Enumeración de Active Directory CON credenciales/sesión

Para esta fase necesitas haber **comprometido las credenciales o una sesión de una cuenta de dominio válida**. Si tienes algunas credenciales válidas o una shell como usuario de dominio, **debes recordar que las opciones dadas anteriormente siguen siendo opciones para comprometer a otros usuarios**.

Antes de comenzar la enumeración autenticada debes saber cuál es el **problema de doble salto de Kerberos**.

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Enumeración

Haber comprometido una cuenta es un **gran paso para comenzar a comprometer todo el dominio**, porque vas a poder comenzar la **Enumeración de Active Directory:**

Respecto a [**ASREPRoast**](asreproast.md) ahora puedes encontrar cada posible usuario vulnerable, y respecto a [**Password Spraying**](password-spraying.md) puedes obtener una **lista de todos los nombres de usuario** y probar la contraseña de la cuenta comprometida, contraseñas vacías y nuevas contraseñas prometedoras.

* Podrías usar el [**CMD para realizar un reconocimiento básico**](../basic-cmd-for-pentesters.md#domain-info)
* También puedes usar [**powershell para reconocimiento**](../basic-powershell-for-pentesters/) que será más sigiloso
* También puedes [**usar powerview**](../basic-powershell-for-pentesters/powerview.md) para extraer información más detallada
* Otra herramienta increíble para el reconocimiento en un directorio activo es [**BloodHound**](bloodhound.md). No es muy sigilosa (dependiendo de los métodos de recolección que uses), pero **si no te importa** eso, deberías probarla totalmente. Encuentra dónde los usuarios pueden hacer RDP, encuentra el camino hacia otros grupos, etc.
* **Otras herramientas automatizadas de enumeración de AD son:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* [**Registros DNS del AD**](ad-dns-records.md) ya que podrían contener información interesante.
* Una **herramienta con GUI** que puedes usar para enumerar el directorio es **AdExplorer.exe** de **SysInternal** Suite.
* También puedes buscar en la base de datos LDAP con **ldapsearch** para buscar credenciales en los campos _userPassword_ y _unixUserPassword_, o incluso en _Description_. cf. [Contraseña en el comentario del usuario AD en PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para otros métodos.
* Si estás usando **Linux**, también podrías enumerar el dominio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
* También podrías probar herramientas automatizadas como:
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **Extrayendo todos los usuarios del dominio**

Es muy fácil obtener todos los nombres de usuario del dominio desde Windows (`net user /domain`, `Get-DomainUser` o `wmic useraccount get name,sid`). En Linux, puedes usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Aunque esta sección de Enumeración parezca pequeña, es la parte más importante de todas. Accede a los enlaces (principalmente el de cmd, powershell, powerview y BloodHound), aprende cómo enumerar un dominio y practica hasta que te sientas cómodo. Durante una evaluación, este será el momento clave para encontrar tu camino hacia DA o decidir que no se puede hacer nada.

### Kerberoast

Kerberoasting implica obtener **tickets TGS** utilizados por servicios vinculados a cuentas de usuario y crackear su encriptación, que se basa en las contraseñas de usuario, **fuera de línea**.

Más sobre esto en:

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### Conexión remota (RDP, SSH, FTP, Win-RM, etc)

Una vez que hayas obtenido algunas credenciales podrías verificar si tienes acceso a alguna **máquina**. Para ello, podrías usar **CrackMapExec** para intentar conectarte en varios servidores con diferentes protocolos, de acuerdo a tus escaneos de puertos.

### Escalada de privilegios local

Si has comprometido credenciales o una sesión como un usuario regular de dominio y tienes **acceso** con este usuario a **cualquier máquina en el dominio** deberías intentar encontrar la forma de **escalar privilegios localmente y saquear credenciales**. Esto se debe a que solo con privilegios de administrador local podrás **extraer hashes de otros usuarios** en memoria (LSASS) y localmente (SAM).

Hay una página completa en este libro sobre [**escalada de privilegios local en Windows**](../windows-local-privilege-escalation/) y una [**lista de verificación**](../checklist-windows-privilege-escalation.md). Además, no olvides usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets de sesión actuales

Es muy **poco probable** que encuentres **tickets** en el usuario actual **que te den permiso para acceder** a recursos inesperados, pero podrías verificar:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

Si has logrado enumerar el directorio activo, tendrás **más correos electrónicos y una mejor comprensión de la red**. Podrías ser capaz de forzar ataques de [**retransmisión NTML**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack).

### Buscar Credenciales en Comparticiones de Computadoras

Ahora que tienes algunas credenciales básicas, deberías verificar si puedes **encontrar** archivos **interesantes compartidos dentro del AD**. Podrías hacerlo manualmente, pero es una tarea muy aburrida y repetitiva (especialmente si encuentras cientos de documentos que necesitas revisar).

[**Sigue este enlace para aprender sobre las herramientas que podrías usar.**](../../network-services-pentesting/pentesting-smb.md#domain-shared-folders-search)

### Robar Credenciales NTLM

Si puedes **acceder a otras PCs o comparticiones**, podrías **colocar archivos** (como un archivo SCF) que, si son accedidos de alguna manera, **desencadenarán una autenticación NTML contra ti** para que puedas **robar** el **desafío NTLM** y crackearlo:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Esta vulnerabilidad permitía que cualquier usuario autenticado **comprometiera el controlador de dominio**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Escalada de privilegios en Active Directory CON credenciales/sesión privilegiadas

**Para las siguientes técnicas, un usuario de dominio regular no es suficiente, necesitas algunos privilegios/credenciales especiales para realizar estos ataques.**

### Extracción de Hash

Con suerte has logrado **comprometer alguna cuenta de administrador local** utilizando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluyendo retransmisión, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalando privilegios localmente](../windows-local-privilege-escalation/).\
Entonces, es hora de volcar todos los hashes en la memoria y localmente.\
[**Lee esta página sobre diferentes formas de obtener los hashes.**](broken-reference/)

### Pass the Hash

**Una vez que tengas el hash de un usuario**, puedes usarlo para **hacerte pasar por él**.\
Necesitas usar alguna **herramienta** que **realizará** la **autenticación NTLM usando** ese **hash**, **o** podrías crear un nuevo **sessionlogon** e **inyectar** ese **hash** dentro del **LSASS**, para que cuando se realice cualquier **autenticación NTLM**, se use ese **hash**. La última opción es lo que hace mimikatz.\
[**Lee esta página para más información.**](../ntlm/#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque tiene como objetivo **usar el hash NTLM del usuario para solicitar tickets Kerberos**, como alternativa al común Pass The Hash sobre el protocolo NTLM. Por lo tanto, esto podría ser especialmente **útil en redes donde el protocolo NTLM está deshabilitado** y solo se permite Kerberos como protocolo de autenticación.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Pass the Ticket

En el método de ataque **Pass The Ticket (PTT)**, los atacantes **roban el ticket de autenticación de un usuario** en lugar de sus contraseñas o valores de hash. Este ticket robado se utiliza luego para **hacerse pasar por el usuario**, obteniendo acceso no autorizado a recursos y servicios dentro de una red.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Reutilización de Credenciales

Si tienes el **hash** o **contraseña** de un **administrador local**, deberías intentar **iniciar sesión localmente** en otras **PCs** con él.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
Ten en cuenta que esto es bastante **ruidoso** y **LAPS** podría **mitigarlo**.
{% endhint %}

### Abuso de MSSQL y Enlaces de Confianza

Si un usuario tiene privilegios para **acceder a instancias de MSSQL**, podría usarlo para **ejecutar comandos** en el host de MSSQL (si se ejecuta como SA), **robar** el **hash** de NetNTLM o incluso realizar un **ataque de relay**.\
Además, si una instancia de MSSQL es confiable (enlace de base de datos) por una instancia de MSSQL diferente. Si el usuario tiene privilegios sobre la base de datos confiable, podrá **utilizar la relación de confianza para ejecutar consultas también en la otra instancia**. Estas confianzas pueden encadenarse y en algún momento el usuario podría encontrar una base de datos mal configurada donde puede ejecutar comandos.\
**Los enlaces entre bases de datos funcionan incluso a través de confianzas entre bosques.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Delegación sin Restricciones

Si encuentras algún objeto de Computadora con el atributo [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) y tienes privilegios de dominio en la computadora, podrás extraer TGTs de la memoria de todos los usuarios que inicien sesión en la computadora.\
Entonces, si un **Administrador de Dominio inicia sesión en la computadora**, podrás extraer su TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Gracias a la delegación restringida, incluso podrías **comprometer automáticamente un Servidor de Impresión** (con suerte será un DC).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Delegación Restringida

Si a un usuario o computadora se le permite la "Delegación Restringida", podrá **suplantar a cualquier usuario para acceder a algunos servicios en una computadora**.\
Entonces, si **comprometes el hash** de este usuario/computadora, podrás **suplantar a cualquier usuario** (incluso administradores de dominio) para acceder a algunos servicios.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Delegación basada en Recursos Restringidos

Tener privilegios de **ESCRITURA** en un objeto de Active Directory de una computadora remota permite la obtención de ejecución de código con **privilegios elevados**:

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### Abuso de ACLs

El usuario comprometido podría tener algunos **privilegios interesantes sobre algunos objetos de dominio** que podrían permitirte **moverte** lateralmente/**escalar** privilegios.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Abuso del servicio de Cola de Impresión

Descubrir un **servicio de Cola** escuchando dentro del dominio puede ser **abusado** para **adquirir nuevas credenciales** y **escalar privilegios**.

{% content-ref url="acl-persistence-abuse/" %}
[printers-spooler-service-abuse](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Abuso de sesiones de terceros

Si **otros usuarios** **acceden** a la **máquina comprometida**, es posible **recopilar credenciales de la memoria** e incluso **inyectar beacons en sus procesos** para suplantarlos.\
Normalmente, los usuarios accederán al sistema a través de RDP, así que aquí tienes cómo realizar un par de ataques sobre sesiones de RDP de terceros:

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** proporciona un sistema para gestionar la **contraseña del Administrador local** en computadoras unidas a un dominio, asegurando que sea **aleatoria**, única y se cambie con frecuencia. Estas contraseñas se almacenan en Active Directory y el acceso se controla a través de ACLs solo a usuarios autorizados. Con permisos suficientes para acceder a estas contraseñas, se vuelve posible pivotar hacia otras computadoras.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Robo de Certificados

**Recopilar certificados** de la máquina comprometida podría ser una forma de escalar privilegios dentro del entorno:

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Abuso de Plantillas de Certificados

Si se configuran **plantillas vulnerables**, es posible abusar de ellas para escalar privilegios:

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## Post-explotación con cuenta de alto privilegio

### Extracción de Credenciales de Dominio

Una vez que obtienes privilegios de **Administrador de Dominio** o incluso mejor, de **Administrador Empresarial**, puedes **extraer** la **base de datos del dominio**: _ntds.dit_.

[**Más información sobre el ataque DCSync se puede encontrar aquí**](dcsync.md).

[**Más información sobre cómo robar el NTDS.dit se puede encontrar aquí**](broken-reference/)

### Escalada de Privilegios como Persistencia

Algunas de las técnicas discutidas anteriormente se pueden utilizar para la persistencia.\
Por ejemplo, podrías:

*   Hacer que los usuarios sean vulnerables a [**Kerberoast**](kerberoast.md)

```powershell
Set-DomainObject -Identity <nombre de usuario> -Set @{serviceprincipalname="falso/NADA"}r
```
*   Hacer que los usuarios sean vulnerables a [**ASREPRoast**](asreproast.md)

```powershell
Set-DomainObject -Identity <nombre de usuario> -XOR @{UserAccountControl=4194304}
```
*   Conceder privilegios de [**DCSync**](./#dcsync) a un usuario

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMINIO,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Ticket de Plata

El ataque del **Ticket de Plata** crea un **legítimo ticket de concesión de servicio (TGS)** para un servicio específico utilizando el **hash NTLM** (por ejemplo, el **hash de la cuenta de PC**). Este método se emplea para **acceder a los privilegios del servicio**.

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Ticket de Oro

Un ataque de **Ticket de Oro** implica que un atacante obtiene acceso al **hash NTLM de la cuenta krbtgt** en un entorno de Active Directory (AD). Esta cuenta es especial porque se utiliza para firmar todos los **Tickets de Concesión de Tickets (TGT)**, que son esenciales para la autenticación dentro de la red de AD.

Una vez que el atacante obtiene este hash, puede crear **TGTs** para cualquier cuenta que elija (ataque de ticket de plata).

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Ticket de Diamante

Estos son como tickets de oro forjados de una manera que **burla los mecanismos de detección comunes de tickets de oro**.

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### **Persistencia de Cuenta de Certificados**

**Tener certificados de una cuenta o poder solicitarlos** es una muy buena manera de poder persistir en la cuenta de los usuarios (incluso si cambian la contraseña):

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **Persistencia de Dominio con Certificados**

**Usar certificados también es posible para persistir con altos privilegios dentro del dominio:**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### Grupo AdminSDHolder

El objeto **AdminSDHolder** en Active Directory garantiza la seguridad de los **grupos privilegiados** (como Administradores de Dominio y Administradores Empresariales) aplicando una **Lista de Control de Acceso (ACL)** estándar en estos grupos para evitar cambios no autorizados. Sin embargo, esta característica puede ser explotada; si un atacante modifica la ACL de AdminSDHolder para otorgar acceso total a un usuario regular, ese usuario obtiene un control extenso sobre todos los grupos privilegiados. Esta medida de seguridad, destinada a proteger, puede resultar contraproducente, permitiendo acceso no autorizado a menos que se monitoree de cerca.

[**Más información sobre el Grupo AdminDSHolder aquí.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Credenciales DSRM

Dentro de cada **Controlador de Dominio (DC)**, existe una cuenta de **administrador local**. Al obtener derechos de administrador en dicha máquina, se puede extraer el hash del Administrador local usando **mimikatz**. Después de esto, es necesaria una modificación del registro para **habilitar el uso de esta contraseña**, permitiendo el acceso remoto a la cuenta de Administrador local.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### Persistencia de ACL

Podrías **dar** algunos **permisos especiales** a un **usuario** sobre algunos objetos de dominio específicos que permitirán al usuario **escalar privilegios en el futuro**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Descriptores de Seguridad

Los **descriptores de seguridad** se utilizan para **almacenar** los **permisos** que un **objeto** tiene **sobre** un **objeto**. Si puedes **realizar** un **pequeño cambio** en el **descriptor de seguridad** de un objeto, puedes obtener privilegios muy interesantes sobre ese objeto sin necesidad de ser miembro de un grupo privilegiado.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Llave Esquelética

Alterar **LSASS** en memoria para establecer una **contraseña universal**, otorgando acceso a todas las cuentas de dominio.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### SSP Personalizado

[Aprende qué es un SSP (Proveedor de Soporte de Seguridad) aquí.](../authentication-credentials-uac-and-efs.md#security-support-provider-interface-sspi)\
Puedes crear tu **propio SSP** para **capturar** en **texto claro** las **credenciales** utilizadas para acceder a la máquina.\\

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

Registra un **nuevo Controlador de Dominio** en el AD y lo utiliza para **empujar atributos** (SIDHistory, SPNs...) en objetos especificados **sin** dejar ningún **registro** sobre las **modificaciones**. Necesitas privilegios de DA y estar dentro del **dominio raíz**.\
Ten en cuenta que si usas datos incorrectos, aparecerán registros bastante feos.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### Persistencia de LAPS

Anteriormente hemos discutido cómo escalar privilegios si tienes **suficientes permisos para leer contraseñas de LAPS**. Sin embargo, estas contraseñas también se pueden utilizar para **mantener la persistencia**.\
Revisa:

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## Escalada de Privilegios en el Bosque - Confianzas de Dominio

Microsoft considera el **Bosque** como el límite de seguridad. Esto implica que **comprometer un solo dominio podría potencialmente llevar a que todo el Bosque sea comprometido**.

### Información Básica

Un [**dominio de confianza**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx) es un mecanismo de seguridad que permite a un usuario de un **dominio** acceder a recursos en otro **dominio**. Básicamente crea un enlace entre los sistemas de autenticación de los dos dominios, permitiendo que las verificaciones de autenticación fluyan sin problemas. Cuando los dominios establecen una confianza, intercambian y retienen claves específicas en sus **Controladores de Dominio (DCs)**, que son cruciales para la integridad de la confianza.

En un escenario típico, si un usuario desea acceder a un servicio en un **dominio de confianza**, primero debe solicitar un ticket especial conocido como un **TGT inter-reino** de su propio DC de dominio. Este TGT está cifrado con una **clave compartida** en la que ambos dominios han acordado. El usuario luego presenta este TGT al **DC del dominio de confianza** para obtener un ticket de servicio (**TGS**). Tras la validación exitosa del TGT inter-reino por el DC del dominio de confianza, emite un TGS, otorgando al usuario acceso al servicio.

**Pasos**:

1. Un **equipo cliente** en **Dominio 1** inicia el proceso utilizando su **hash NTLM** para solicitar un **Ticket Granting Ticket (TGT)** de su **Controlador de Dominio (DC1)**.
2. DC1 emite un nuevo TGT si el cliente se autentica con éxito.
3. El cliente luego solicita un **TGT inter-reino** de DC1, que es necesario para acceder a recursos en **Dominio 2**.
4. El TGT inter-reino está cifrado con una **clave de confianza** compartida entre DC1 y DC2 como parte de la confianza de doble vía entre dominios.
5. El cliente lleva el TGT inter-reino al **Controlador de Dominio de Dominio 2 (DC2)**.
6. DC2 verifica el TGT inter-reino utilizando su clave de confianza compartida y, si es válido, emite un **Ticket Granting Service (TGS)** para el servidor en Dominio 2 al que el cliente desea acceder.
7. Finalmente, el cliente presenta este TGS al servidor, que está cifrado con el hash de la cuenta del servidor, para acceder al servicio en Dominio 2.


### Diferentes confianzas

Es importante notar que **una confianza puede ser de 1 vía o de 2 vías**. En las opciones de 2 vías, ambos dominios confiarán entre sí, pero en la relación de confianza de **1 vía** uno de los dominios será el dominio **confiable** y el otro el dominio **confiante**. En el último caso, **solo podrás acceder a recursos dentro del dominio confiante desde el confiable**.

Si el Dominio A confía en el Dominio B, A es el dominio confiante y B es el dominio confiable. Además, en **Dominio A**, esto sería una **confianza saliente**; y en **Dominio B**, sería una **confianza entrante**.

**Diferentes relaciones de confianza**

* **Confianzas Padre-Hijo**: Esta es una configuración común dentro del mismo bosque, donde un dominio hijo tiene automáticamente una confianza bidireccional transitiva con su dominio padre. Básicamente, esto significa que las solicitudes de autenticación pueden fluir sin problemas entre el padre y el hijo.
* **Confianzas de Enlace Cruzado**: Conocidas como "confianzas de acceso directo", se establecen entre dominios hijos para acelerar los procesos de referencia. En bosques complejos, las referencias de autenticación suelen tener que viajar hasta la raíz del bosque y luego descender al dominio de destino. Al crear enlaces cruzados, se acorta el viaje, lo que es especialmente beneficioso en entornos geográficamente dispersos.
* **Confianzas Externas**: Se establecen entre dominios diferentes y no relacionados y no son transitivas por naturaleza. Según la [documentación de Microsoft](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx), las confianzas externas son útiles para acceder a recursos en un dominio fuera del bosque
```
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
{% hint style="warning" %}
Hay **2 claves de confianza**, una para _Hijo --> Padre_ y otra para _Padre_ --> _Hijo_.\
Puedes la que se utiliza por el dominio actual con:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### Inyección de SID-History

Escalada como administrador de empresa al dominio hijo/padre abusando de la confianza con la inyección de SID-History:

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Explotar la NC de Configuración escribible

Es crucial entender cómo la NC de Configuración puede ser explotada. La NC de Configuración sirve como un repositorio central para datos de configuración en un bosque en entornos de Active Directory (AD). Estos datos se replican en cada Controlador de Dominio (DC) dentro del bosque, con DCs escribibles manteniendo una copia escribible de la NC de Configuración. Para explotar esto, uno debe tener **privilegios de SYSTEM en un DC**, preferiblemente un DC hijo.

**Vincular GPO al sitio del DC raíz**

El contenedor de Sitios de la NC de Configuración incluye información sobre todos los sitios de los equipos unidos al dominio dentro del bosque de AD. Al operar con privilegios de SYSTEM en cualquier DC, los atacantes pueden vincular GPOs a los sitios del DC raíz. Esta acción potencialmente compromete el dominio raíz al manipular las políticas aplicadas a estos sitios.

Para obtener información detallada, se puede explorar la investigación sobre [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Comprometer cualquier gMSA en el bosque**

Un vector de ataque implica apuntar a gMSAs privilegiadas dentro del dominio. La clave raíz de KDS, esencial para calcular las contraseñas de gMSAs, se almacena dentro de la NC de Configuración. Con privilegios de SYSTEM en cualquier DC, es posible acceder a la clave raíz de KDS y calcular las contraseñas para cualquier gMSA en todo el bosque.

Un análisis detallado se puede encontrar en la discusión sobre [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Ataque de cambio de esquema**

Este método requiere paciencia, esperando la creación de nuevos objetos AD privilegiados. Con privilegios de SYSTEM, un atacante puede modificar el Esquema AD para otorgar a cualquier usuario control completo sobre todas las clases. Esto podría llevar a un acceso no autorizado y control sobre los objetos AD recién creados.

Más información está disponible en [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**De DA a EA con ADCS ESC5**

La vulnerabilidad ADCS ESC5 apunta a controlar los objetos de Infraestructura de Clave Pública (PKI) para crear una plantilla de certificado que permite la autenticación como cualquier usuario dentro del bosque. Dado que los objetos PKI residen en la NC de Configuración, comprometer un DC hijo escribible permite la ejecución de ataques ESC5.

Más detalles sobre esto se pueden leer en [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). En escenarios sin ADCS, el atacante tiene la capacidad de configurar los componentes necesarios, como se discute en [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Dominio Forestal Externo - Unidireccional (Entrante) o bidireccional
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
En este escenario **su dominio es de confianza** por uno externo que le otorga **permisos indeterminados** sobre él. Deberá encontrar **qué principios de su dominio tienen qué acceso sobre el dominio externo** y luego intentar explotarlo:

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### Dominio del Bosque Externo - Unidireccional (Saliente)
```powershell
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
En este escenario **tu dominio** está **confiando** algunos **privilegios** a un principal de un **dominio diferente**.

Sin embargo, cuando un **dominio es confiado** por el dominio confiante, el dominio confiado **crea un usuario** con un **nombre predecible** que utiliza como **contraseña la contraseña confiada**. Lo que significa que es posible **acceder a un usuario del dominio confiante para ingresar al confiado** para enumerarlo e intentar escalar más privilegios:

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

Otra forma de comprometer el dominio confiado es encontrar un [**enlace de confianza SQL**](abusing-ad-mssql.md#mssql-trusted-links) creado en la **dirección opuesta** de la confianza del dominio (lo cual no es muy común).

Otra forma de comprometer el dominio confiado es esperar en una máquina a la que un **usuario del dominio confiado pueda acceder** para iniciar sesión a través de **RDP**. Luego, el atacante podría inyectar código en el proceso de sesión de RDP y **acceder al dominio de origen de la víctima** desde allí.\
Además, si la **víctima montó su disco duro**, desde el proceso de sesión de RDP el atacante podría almacenar **puertas traseras** en la **carpeta de inicio del disco duro**. Esta técnica se llama **RDPInception.**

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Mitigación del abuso de la confianza del dominio

### **Filtrado de SID:**

- El riesgo de ataques que aprovechan el atributo de historial de SID a través de las confianzas entre bosques se mitiga mediante el Filtrado de SID, que está activado de forma predeterminada en todas las confianzas entre bosques. Esto se basa en la suposición de que las confianzas dentro del bosque son seguras, considerando el bosque, en lugar del dominio, como el límite de seguridad según la postura de Microsoft.
- Sin embargo, hay un problema: el filtrado de SID podría interrumpir aplicaciones y el acceso de usuarios, lo que lleva a su desactivación ocasional.

### **Autenticación Selectiva:**

- Para las confianzas entre bosques, emplear la Autenticación Selectiva garantiza que los usuarios de los dos bosques no sean autenticados automáticamente. En su lugar, se requieren permisos explícitos para que los usuarios accedan a dominios y servidores dentro del dominio o bosque confiante.
- Es importante tener en cuenta que estas medidas no protegen contra la explotación del Contexto de Nombres de Configuración (NC) escribible o los ataques a la cuenta de confianza.

[**Más información sobre las confianzas de dominio en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Algunas Defensas Generales

[**Aprende más sobre cómo proteger credenciales aquí.**](../stealing-credentials/credentials-protections.md)\

### **Medidas Defensivas para la Protección de Credenciales**

- **Restricciones de Administradores de Dominio**: Se recomienda que los Administradores de Dominio solo puedan iniciar sesión en Controladores de Dominio, evitando su uso en otros hosts.
- **Privilegios de Cuenta de Servicio**: Los servicios no deben ejecutarse con privilegios de Administrador de Dominio (DA) para mantener la seguridad.
- **Limitación Temporal de Privilegios**: Para tareas que requieran privilegios de DA, su duración debe ser limitada. Esto se puede lograr mediante: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementación de Técnicas de Engaño**

- Implementar el engaño implica establecer trampas, como usuarios o computadoras señuelo, con características como contraseñas que no caducan o que están marcadas como Confiables para Delegación. Un enfoque detallado incluye crear usuarios con derechos específicos o agregarlos a grupos de alto privilegio.
- Un ejemplo práctico implica el uso de herramientas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Más información sobre la implementación de técnicas de engaño se puede encontrar en [Deploy-Deception en GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificación de Engaños**

- **Para Objetos de Usuario**: Los indicadores sospechosos incluyen ObjectSID atípicos, inicio de sesión poco frecuente, fechas de creación y recuentos bajos de contraseñas incorrectas.
- **Indicadores Generales**: Comparar atributos de objetos señuelo potenciales con los de objetos genuinos puede revelar inconsistencias. Herramientas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) pueden ayudar a identificar tales engaños.

### **Eludir Sistemas de Detección**

- **Eludir la Detección de Microsoft ATA**:
- **Enumeración de Usuarios**: Evitar la enumeración de sesiones en Controladores de Dominio para prevenir la detección de ATA.
- **Suplantación de Tickets**: Utilizar claves **aes** para la creación de tickets ayuda a evadir la detección al no degradarse a NTLM.
- **Ataques DCSync**: Se recomienda ejecutarlos desde un no-Controlador de Dominio para evitar la detección de ATA, ya que la ejecución directa desde un Controlador de Dominio generará alertas.


## Referencias

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
