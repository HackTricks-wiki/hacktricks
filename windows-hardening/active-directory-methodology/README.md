# Metodología de Active Directory

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Descripción general básica

Active Directory permite a los administradores de red crear y administrar dominios, usuarios y objetos dentro de una red. Por ejemplo, un administrador puede crear un grupo de usuarios y darles privilegios de acceso específicos a ciertos directorios en el servidor. A medida que una red crece, Active Directory proporciona una forma de organizar un gran número de usuarios en grupos y subgrupos lógicos, al tiempo que proporciona control de acceso en cada nivel.

La estructura de Active Directory incluye tres niveles principales: 1) dominios, 2) árboles y 3) bosques. Varios objetos (usuarios o dispositivos) que utilizan la misma base de datos pueden agruparse en un solo dominio. Múltiples dominios pueden combinarse en un solo grupo llamado árbol. Múltiples árboles pueden agruparse en una colección llamada bosque. Cada uno de estos niveles puede asignar derechos de acceso y privilegios de comunicación específicos.

Los conceptos principales de un Active Directory son:

1. **Directorio** - Contiene toda la información sobre los objetos del directorio activo.
2. **Objeto** - Un objeto hace referencia a casi cualquier cosa dentro del directorio (un usuario, grupo, carpeta compartida...)
3. **Dominio** - Los objetos del directorio se encuentran dentro del dominio. Dentro de un "bosque" pueden existir más de un dominio y cada uno tendrá su propia colección de objetos.
4. **Árbol** - Grupo de dominios con la misma raíz. Ejemplo: _dom.local, email.dom.local, www.dom.local_
5. **Bosque** - El bosque es el nivel más alto de la jerarquía de la organización y está compuesto por un grupo de árboles. Los árboles están conectados por relaciones de confianza.

Active Directory proporciona varios servicios diferentes, que se incluyen en el paraguas de "Active Directory Domain Services" o AD DS. Estos servicios incluyen:

1. **Servicios de dominio** - almacena datos centralizados y administra la comunicación entre usuarios y dominios; incluye autenticación de inicio de sesión y funcionalidad de búsqueda.
2. **Servicios de certificados** - crea, distribuye y administra certificados seguros.
3. **Servicios de directorio ligero** - admite aplicaciones habilitadas para directorios utilizando el protocolo abierto (LDAP).
4. **Servicios de federación de directorios** - proporciona inicio de sesión único (SSO) para autenticar a un usuario en múltiples aplicaciones web en una sola sesión.
5. **Gestión de derechos** - protege la información con derechos de autor al evitar el uso y distribución no autorizados de contenido digital.
6. **Servicio DNS** - se utiliza para resolver nombres de dominio.

AD DS se incluye con Windows Server (incluido Windows Server 10) y está diseñado para administrar sistemas cliente. Si bien los sistemas que ejecutan la versión regular de Windows no tienen las características administrativas de AD DS, admiten Active Directory. Esto significa que cualquier computadora con Windows puede conectarse a un grupo de trabajo de Windows, siempre que el usuario tenga las credenciales de inicio de sesión correctas.\
**De:** [**https://techterms.com/definition/active\_directory**](https://techterms.com/definition/active\_directory)

### **Autenticación Kerberos**

Para aprender a **atacar un AD** necesitas **entender** muy bien el proceso de **autenticación Kerberos**.\
[**Lee esta página si aún no sabes cómo funciona.**](kerberos-authentication.md)

## Hoja de trucos

Puedes acceder a [https://wadcoms.github.io/](https://wadcoms.github.io) para tener una vista rápida de los comandos que puedes ejecutar para enumerar/explotar un AD.

## Reconocimiento de Active Directory (sin credenciales/sesiones)

Si solo tienes acceso a un entorno de AD pero no tienes credenciales/sesiones, podrías:

* **Pentestear la red:**
  * Escanear la red, encontrar máquinas y puertos abiertos e intentar **explotar vulnerabilidades** o **extraer credenciales** de ellas (por ejemplo, [las impresoras podrían ser objetivos muy interesantes](ad-information-in-printers.md)).
  * Enumerar DNS podría dar información sobre los servidores clave en el dominio como web, impresoras, recursos compartidos, VPN, medios, etc.
    * `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  * Echa un vistazo a la [**Metodología de Pentesting General**](../../generic-methodologies-and-resources/pentesting-methodology.md) para obtener más información sobre cómo hacer esto.
* **Comprobar el acceso nulo y de invitado en los servicios SMB** (esto no funcionará en las versiones modernas de Windows):
  * `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **Servidor OWA (Outlook Web Access)**

Si encontraste uno de estos servidores en la red, también puedes realizar **enumeración de usuarios contra él**. Por ejemplo, podrías utilizar la herramienta [**MailSniper**](https://github.com/dafthack/MailSniper):
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
Puedes encontrar listas de nombres de usuario en [**este repositorio de Github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) y en este otro ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).

Sin embargo, deberías tener el **nombre de las personas que trabajan en la empresa** a partir del paso de reconocimiento que deberías haber realizado antes. Con el nombre y apellido, podrías usar el script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para generar posibles nombres de usuario válidos.
{% endhint %}

### Conociendo uno o varios nombres de usuario

Bien, ya sabes que tienes un nombre de usuario válido pero no tienes contraseñas... Entonces intenta:

* [**ASREPRoast**](asreproast.md): Si un usuario **no tiene** el atributo _DONT\_REQ\_PREAUTH_, puedes **solicitar un mensaje AS\_REP** para ese usuario que contendrá algunos datos cifrados por una derivación de la contraseña del usuario.
* [**Password Spraying**](password-spraying.md): Intenta las contraseñas **más comunes** con cada uno de los usuarios descubiertos, tal vez algún usuario esté usando una contraseña débil (¡ten en cuenta la política de contraseñas!).
  * Ten en cuenta que también puedes **probar en servidores OWA** para intentar acceder a los servidores de correo de los usuarios.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### Envenenamiento de LLMNR/NBT-NS

Es posible que puedas **obtener** algunos **hashes de desafío** para descifrar **envenenando** algunos protocolos de la **red**:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTML Relay

Si has logrado enumerar el directorio activo, tendrás **más correos electrónicos y una mejor comprensión de la red**. Podrías forzar ataques de **retransmisión NTML** \*\*\*\* para obtener acceso al entorno de AD.

### Robar credenciales NTLM

Si puedes **acceder a otros PCs o recursos compartidos** con el usuario **null o guest**, podrías **colocar archivos** (como un archivo SCF) que, si se acceden de alguna manera, **desencadenarán una autenticación NTML contra ti** para que puedas **robar el desafío NTLM** y descifrarlo:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Enumerando Active Directory CON credenciales/sesión

Para esta fase, necesitas haber **comprometido las credenciales o una sesión de una cuenta de dominio válida**. Si tienes algunas credenciales válidas o una shell como usuario de dominio, **debes recordar que las opciones dadas anteriormente siguen siendo opciones para comprometer a otros usuarios**.

Antes de comenzar la enumeración autenticada, debes saber cuál es el **problema de doble salto de Kerberos**.

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Enumeración

Haber comprometido una cuenta es un **gran paso para comenzar a comprometer todo el dominio**, porque podrás comenzar la **enumeración del Directorio Activo**:

Con respecto a [**ASREPRoast**](asreproast.md), ahora puedes encontrar todos los usuarios vulnerables posibles, y con respecto a [**Password Spraying**](password-spraying.md), puedes obtener una **lista de todos los nombres de usuario** y probar la contraseña de la cuenta comprometida, contraseñas vacías y nuevas contraseñas prometedoras.

* Podrías usar el [**CMD para realizar una recon básica**](../basic-cmd-for-pentesters.md#domain-info)
* También puedes usar [**powershell para la recon**](../basic-powershell-for-pentesters/) que será más sigiloso
* También puedes [**usar powerview**](../basic-powershell-for-pentesters/powerview.md) para extraer información más detallada
* Otra herramienta increíble para la recon en un directorio activo es [**BloodHound**](bloodhound.md). No es muy sigiloso (dependiendo de los métodos de recolección que uses), pero **si no te importa**, deberías probarlo. Encuentra dónde los usuarios pueden RDP, encuentra la ruta hacia otros grupos, etc.
  * **Otras herramientas automatizadas de enumeración de AD son:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* \*\*\*\*[**Registros DNS del AD**](ad-dns-records.md) \*\*\*\* ya que pueden contener información interesante.
* Una **herramienta con GUI** que puedes usar para enumerar el directorio es **AdExplorer.exe** de la **Suite SysInternal**.
* También puedes buscar en la base de datos LDAP con **ldapsearch** para buscar credenciales en los campos _userPassword_ y _unixUserPassword_, o incluso en _Description_. Consulta [Contraseña en el comentario del usuario de AD en PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para otros métodos.
* Si estás usando **Linux**, también puedes enumerar el dominio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
* También podrías probar herramientas automatizadas como:
  * [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  * [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **Extrayendo todos los usuarios del dominio**

    Es muy fácil obtener todos los nombres de usuario del dominio en Windows (`net user /domain`, `Get-DomainUser` o `wmic useraccount get name,sid`). En Linux, puedes usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Aunque esta sección de Enumeración parece pequeña, es la parte más importante de todas. Accede a los enlaces (principalmente el de cmd, powershell, powerview y BloodHound), aprende a enumerar un dominio y practica hasta que te sientas cómodo. Durante una evaluación, este será el momento clave para encontrar tu camino hacia DA o para decidir que no se puede hacer nada.

### Kerberoast

El objetivo de Kerberoasting es recopilar **tickets TGS para servicios que se ejecutan en nombre de cuentas de usuario de dominio**. Parte de estos tickets TGS están **cifrados con claves derivadas de las contraseñas de usuario**. Como consecuencia, sus credenciales podrían **descifrarse sin conexión**.\
Más sobre esto en:

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### Conexión remota (RDP, SSH, FTP, Win-RM, etc)

Una vez que hayas obtenido algunas credenciales, podrías comprobar si tienes acceso a alguna **máquina**. Para ello, podrías usar **CrackMapExec** para intentar conectarte a varios servidores con diferentes protocolos, según tus escaneos de puertos.

### Escalada de privilegios local

Si has comprometido credenciales o una sesión como usuario de domin
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

Si has logrado enumerar el directorio activo, tendrás **más correos electrónicos y una mejor comprensión de la red**. Podrías forzar ataques de **retransmisión NTML**.

### Buscar credenciales en recursos compartidos de computadoras

Ahora que tienes algunas credenciales básicas, deberías comprobar si puedes **encontrar** algún **archivo interesante compartido dentro del AD**. Podrías hacerlo manualmente, pero es una tarea muy aburrida y repetitiva (y más si encuentras cientos de documentos que necesitas revisar).

[**Sigue este enlace para conocer las herramientas que podrías usar.**](../../network-services-pentesting/pentesting-smb.md#domain-shared-folders-search)

### Robar credenciales NTLM

Si puedes **acceder a otras PCs o recursos compartidos**, podrías **colocar archivos** (como un archivo SCF) que, si se acceden de alguna manera, **desencadenarán una autenticación NTML contra ti** para que puedas **robar el desafío NTLM** y crackearlo:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Esta vulnerabilidad permitió a cualquier usuario autenticado **comprometer el controlador de dominio**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Escalada de privilegios en Active Directory CON credenciales/sesión privilegiadas

**Para las siguientes técnicas, un usuario de dominio regular no es suficiente, necesitas algunos privilegios/credenciales especiales para realizar estos ataques.**

### Extracción de hashes

Con suerte, has logrado **comprometer alguna cuenta de administrador local** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), incluyendo la retransmisión, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalando privilegios localmente](../windows-local-privilege-escalation/).\
Entonces, es hora de volcar todos los hashes en memoria y localmente.\
[**Lee esta página sobre diferentes formas de obtener los hashes.**](broken-reference)

### Pass the Hash

**Una vez que tienes el hash de un usuario**, puedes usarlo para **suplantarlo**.\
Necesitas usar alguna **herramienta** que **realice** la **autenticación NTLM usando** ese **hash**, **o** podrías crear un nuevo **sessionlogon** e **inyectar** ese **hash** dentro del **LSASS**, para que cuando se realice cualquier **autenticación NTLM**, se use ese **hash**. La última opción es lo que hace mimikatz.\
[**Lee esta página para obtener más información.**](../ntlm/#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque tiene como objetivo **usar el hash NTLM del usuario para solicitar tickets Kerberos**, como alternativa al común Pass The Hash sobre el protocolo NTLM. Por lo tanto, esto podría ser especialmente **útil en redes donde el protocolo NTLM está deshabilitado** y solo se permite Kerberos como protocolo de autenticación.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Pass the Ticket

Este ataque es similar a Pass the Key, pero en lugar de usar hashes para solicitar un ticket, se **roba el ticket en sí** y se usa para autenticarse como su propietario.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Reutilización de credenciales

Si tienes el **hash** o **contraseña** de un **administrador local**, deberías intentar **iniciar sesión localmente** en otras **PCs** con él.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
Tenga en cuenta que esto es bastante **ruidoso** y que **LAPS** lo **mitigará**.
{% endhint %}

### Abuso de MSSQL y enlaces de confianza

Si un usuario tiene privilegios para **acceder a instancias de MSSQL**, podría ser capaz de usarlo para **ejecutar comandos** en el host de MSSQL (si se ejecuta como SA), **robar** el **hash** de NetNTLM o incluso realizar un **ataque de relé**.\
Además, si una instancia de MSSQL es de confianza (enlace de base de datos) por una instancia de MSSQL diferente. Si el usuario tiene privilegios sobre la base de datos de confianza, podrá **usar la relación de confianza para ejecutar consultas también en la otra instancia**. Estas confianzas se pueden encadenar y en algún momento el usuario podría ser capaz de encontrar una base de datos mal configurada donde puede ejecutar comandos.\
**Los enlaces entre bases de datos funcionan incluso a través de confianzas forestales.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Delegación sin restricciones

Si encuentra algún objeto de equipo con el atributo [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) y tiene privilegios de dominio en el equipo, podrá volcar TGT de la memoria de todos los usuarios que inicien sesión en el equipo.\
Entonces, si un **administrador de dominio inicia sesión en el equipo**, podrá volcar su TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Gracias a la delegación restringida, incluso podría **comprometer automáticamente un servidor de impresión** (con suerte, será un DC).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Delegación restringida

Si se permite a un usuario o equipo la "Delegación restringida", podrá **suplantar a cualquier usuario para acceder a algunos servicios en un equipo**.\
Entonces, si **compromete el hash** de este usuario/equipo, podrá **suplantar a cualquier usuario** (incluso administradores de dominio) para acceder a algunos servicios.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Delegación restringida basada en recursos

Es posible obtener la ejecución de código con **privilegios elevados en un equipo remoto si tiene privilegios de ESCRITURA** en el objeto AD de ese equipo.

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### Abuso de ACLs

El usuario comprometido podría tener algunos **privilegios interesantes sobre algunos objetos de dominio** que le permitirían **moverse** lateralmente/**escalar** privilegios.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Abuso del servicio de cola de impresión

Si puede encontrar algún **servicio de cola de impresión escuchando** dentro del dominio, es posible que pueda **abusar** de él para **obtener nuevas credenciales** y **escalar privilegios**.\
[**Más información sobre cómo abusar de los servicios de cola de impresión aquí.**](printers-spooler-service-abuse.md)

### Abuso de sesiones de terceros

Si **otros usuarios** **acceden** a la **máquina comprometida**, es posible **recopilar credenciales de la memoria** e incluso **inyectar beacons en sus procesos** para suplantarlos.\
Por lo general, los usuarios accederán al sistema a través de RDP, así que aquí tiene cómo realizar un par de ataques sobre sesiones de RDP de terceros:

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** le permite **administrar la
### Diferentes confianzas

Es importante tener en cuenta que **una confianza puede ser de una vía o de dos vías**. En la opción de dos vías, ambos dominios confiarán entre sí, pero en la relación de confianza de **una vía**, uno de los dominios será el **confiado** y el otro el dominio **confiante**. En este último caso, **solo podrás acceder a los recursos dentro del dominio confiante desde el confiado**.

Si el Dominio A confía en el Dominio B, A es el dominio confiante y B es el dominio confiado. Además, en **el Dominio A**, esto sería una **confianza de salida**; y en **el Dominio B**, esto sería una **confianza de entrada**.

**Diferentes relaciones de confianza**

* **Padre-Hijo** - parte del mismo bosque - un dominio hijo mantiene una confianza transitoria implícita de dos vías con su padre. Este es probablemente el tipo de confianza más común que encontrarás.
* **Enlace cruzado** - también conocido como una "confianza de acceso directo" entre dominios hijos para mejorar los tiempos de referencia. Normalmente, las referencias en un bosque complejo tienen que filtrarse hasta la raíz del bosque y luego volver al dominio de destino, por lo que para un escenario geográficamente disperso, los enlaces cruzados pueden tener sentido para reducir los tiempos de autenticación.
* **Externo** - una confianza implícitamente no transitoria creada entre dominios dispares. "[Las confianzas externas proporcionan acceso a recursos en un dominio fuera del bosque que aún no se ha unido mediante una confianza de bosque.](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx)" Las confianzas externas hacen cumplir el filtrado de SID, una protección de seguridad que se cubrirá más adelante en esta publicación.
* **Raíz del árbol** - una confianza transitoria implícita de dos vías entre el dominio raíz del bosque y la nueva raíz del árbol que estás agregando. No he encontrado confianzas de raíz de árbol con demasiada frecuencia, pero según la [documentación de Microsoft](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx), se crean cuando creas un nuevo árbol de dominio en un bosque. Estas son confianzas intraforestales y [conservan la transitividad de dos vías](https://technet.microsoft.com/en-us/library/cc757352\(v=ws.10\).aspx) mientras permiten que el árbol tenga un nombre de dominio separado (en lugar de hijo.padre.com).
* **Bosque** - una confianza transitoria entre dos dominios raíz del bosque. Las confianzas de bosque también hacen cumplir el filtrado de SID.
* **MIT** - una confianza con un dominio Kerberos no Windows compatible con [RFC4120](https://tools.ietf.org/html/rfc4120). Espero profundizar más en las confianzas MIT en el futuro.

#### Otras diferencias en las **relaciones de confianza**

* Una relación de confianza también puede ser **transitoria** (A confía en B, B confía en C, entonces A confía en C) o **no transitoria**.
* Una relación de confianza puede configurarse como **confianza bidireccional** (ambos confían entre sí) o como **confianza de una vía** (solo uno de ellos confía en el otro).

### Ruta de ataque

1. **Enumerar** las relaciones de confianza
2. Verificar si algún **principal de seguridad** (usuario/grupo/ordenador) tiene **acceso** a recursos del **otro dominio**, tal vez por entradas ACE o por estar en grupos del otro dominio. Busca **relaciones entre dominios** (probablemente se creó la confianza para esto).
   1. En este caso, kerberoast podría ser otra opción.
3. **Compromete** las **cuentas** que pueden **pivotar** a través de los dominios.

Hay tres formas **principales** en que los principales de seguridad (usuarios/grupos/ordenadores) de un dominio pueden tener acceso a recursos en otro dominio confiado/externo:

* Pueden agregarse a **grupos locales** en máquinas individuales, es decir, el grupo local "Administradores" en un servidor.
* Pueden agregarse a **grupos en el dominio externo**. Hay algunas advertencias dependiendo del tipo de confianza y el ámbito del grupo, que se describen en breve.
* Pueden agregarse como principales en una **lista de control de acceso**, más interesante para nosotros como principales en **ACEs** en un **DACL**. Para obtener más información sobre ACL/DACL/ACE, consulte el documento blanco "[An ACE Up The Sleeve](https://specterops.io/assets/resources/an\_ace\_up\_the\_sleeve.pdf)".
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
Existen **2 claves de confianza**, una para _Hijo --> Padre_ y otra para _Padre_ --> _Hijo_.\
Puedes ver la que usa el dominio actual con:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### Inyección de SID-History

Escalada de privilegios a Enterprise admin en el dominio hijo/padre abusando de la confianza con la inyección de SID-History:

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Explotar Configuration NC escribible

Configuration NC es el repositorio principal de información de configuración para un bosque y se replica en cada DC del bosque. Además, cada DC escribible (no DC de solo lectura) en el bosque tiene una copia escribible de Configuration NC. Explotar esto requiere ejecutar como SYSTEM en un DC (hijo).

Es posible comprometer el dominio raíz de varias maneras. Ejemplos:

* [Vincular GPO al sitio del DC raíz](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)
* [Comprometer gMSA](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)
* [Ataque de esquema](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)
* Explotar ADCS - Crear/modificar plantilla de certificado para permitir la autenticación como cualquier usuario (por ejemplo, Enterprise Admins)

### Dominio de bosque externo - Unidireccional (entrante) o bidireccional
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
En este escenario, **su dominio es de confianza** para uno externo, lo que le otorga **permisos indeterminados** sobre él. Deberá encontrar **qué principios de su dominio tienen acceso sobre el dominio externo** y luego intentar explotarlo:

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### Dominio de Bosque Externo - Unidireccional (Saliente)
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
En este escenario, **su dominio** está **confiando** algunos **privilegios** a un principal de un **dominio diferente**.

Sin embargo, cuando un **dominio es confiado** por el dominio confiante, el dominio confiado **crea un usuario** con un **nombre predecible** que utiliza como **contraseña la contraseña confiada**. Lo que significa que es posible **acceder a un usuario del dominio confiante para ingresar al confiado** para enumerarlo e intentar escalar más privilegios:

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

Otra forma de comprometer el dominio confiado es encontrar un [**enlace de confianza SQL**](abusing-ad-mssql.md#mssql-trusted-links) creado en la **dirección opuesta** de la confianza del dominio (lo cual no es muy común).

Otra forma de comprometer el dominio confiado es esperar en una máquina donde un **usuario del dominio confiado pueda acceder** para iniciar sesión a través de **RDP**. Luego, el atacante podría inyectar código en el proceso de sesión de RDP y **acceder al dominio de origen de la víctima** desde allí.\
Además, si la **víctima montó su disco duro**, desde el proceso de sesión de **RDP** el atacante podría almacenar **puertas traseras** en la **carpeta de inicio del disco duro**. Esta técnica se llama **RDPInception.**

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Mitigación del abuso de confianza de dominio

**Filtrado de SID:**

* Evita ataques que abusan del atributo de historial de SID a través de la confianza entre bosques.
* Habilitado de forma predeterminada en todas las confianzas entre bosques. Se asume que las confianzas dentro del bosque están aseguradas de forma predeterminada (Microsoft considera que el bosque y no el dominio es una barrera de seguridad).
* Pero, dado que el filtrado de SID tiene el potencial de romper aplicaciones y el acceso de usuario, a menudo se deshabilita.
* Autenticación selectiva
  * En una confianza entre bosques, si se configura la autenticación selectiva, los usuarios entre las confianzas no se autenticarán automáticamente. Se debe dar acceso individual a los dominios y servidores en el dominio / bosque confiante.
* No evita la explotación de la NC de configuración escribible y el ataque de la cuenta de confianza.

[**Más información sobre la confianza de dominio en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Cloud & Cloud -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Algunas defensas generales

[**Aprenda más sobre cómo proteger las credenciales aquí.**](../stealing-credentials/credentials-protections.md)\
**Encuentre algunas migraciones contra cada técnica en la descripción de la técnica.**

* No permita que los administradores de dominio inicien sesión en ningún otro host aparte de los controladores de dominio.
* Nunca ejecute un servicio con privilegios de DA.
* Si necesita privilegios de administrador de dominio, limite el tiempo: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### Decepción

* La contraseña no caduca
* Confiable para la delegación
* Usuarios con SPN
* Contraseña en la descripción
* Usuarios que son miembros de grupos de alta privilegio
* Usuarios con derechos de ACL sobre otros usuarios, grupos o contenedores
* Objetos de computadora
* ...
* [https://github.com/samratashok/Deploy-Deception](https://github.com/samratashok/Deploy-Deception)
  * `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`

## Cómo identificar la decepción

**Para objetos de usuario:**

* ObjectSID (diferente del dominio)
* lastLogon, lastlogontimestamp
* Logoncount (un número muy bajo es sospechoso)
* whenCreated
* Badpwdcount (un número muy bajo es sospechoso)

**General:**

* Algunas soluciones llenan con información en todos los atributos posibles. Por ejemplo, compare los atributos de un objeto de computadora con el atributo de un objeto de computadora 100% real como DC. O usuarios contra el RID 500 (administrador predeterminado).
* Verifique si algo es demasiado bueno para ser verdad.
* [https://github.com/JavelinNetworks/HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)

### Bypassing Microsoft ATA detection

#### Enumeración de usuario

ATA solo se queja cuando intenta enumerar sesiones en el DC, por lo que si no busca sesiones en el DC sino en el resto de los hosts, probablemente no será detectado.

#### Creación de impersonación de tickets (sobre pasar el hash, golden ticket...)

Siempre cree los tickets usando las claves **aes** también porque lo que ATA identifica como malicioso es la degradación a NTLM.

#### DCSync

Si no ejecuta esto desde un controlador de dominio, ATA lo atrapará, lo siento.

## Más herramientas

* [Script de PowerShell para automatizar la auditoría de dominio](https://github.com/phillips321/adaudit)
* [Script de Python para enumerar Active Directory](https://github.com/ropnop/windapsearch)
* [Script de Python para enumerar Active Directory](https://github.com/CroweCybersecurity/ad-ldap-enum)

## Referencias

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabaja en una **empresa de ciberseguridad**? ¿Quiere ver su **empresa anunciada en HackTricks**? ¿O quiere tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulte los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos.
* Obtenga el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únase al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegramas**](https://t.me/peass) o **sígame** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparta sus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
