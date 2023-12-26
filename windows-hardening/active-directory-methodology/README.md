# Metodología de Active Directory

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? o ¿quieres acceder a la **última versión de PEASS o descargar HackTricks en PDF**? Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Visión general básica

Active Directory permite a los administradores de red crear y gestionar dominios, usuarios y objetos dentro de una red. Por ejemplo, un administrador puede crear un grupo de usuarios y otorgarles privilegios de acceso específicos a ciertos directorios en el servidor. A medida que una red crece, Active Directory proporciona una forma de organizar un gran número de usuarios en grupos lógicos y subgrupos, mientras proporciona control de acceso en cada nivel.

La estructura de Active Directory incluye tres niveles principales: 1) dominios, 2) árboles y 3) bosques. Varios objetos (usuarios o dispositivos) que utilizan la misma base de datos pueden agruparse en un solo dominio. Múltiples dominios pueden combinarse en un solo grupo llamado árbol. Varios árboles pueden agruparse en una colección llamada bosque. A cada uno de estos niveles se le pueden asignar derechos de acceso y privilegios de comunicación específicos.

Conceptos principales de un Active Directory:

1. **Directorio** – Contiene toda la información sobre los objetos del Active Directory
2. **Objeto** – Un objeto hace referencia a casi cualquier cosa dentro del directorio (un usuario, grupo, carpeta compartida...)
3. **Dominio** – Los objetos del directorio están contenidos dentro del dominio. Dentro de un "bosque" puede haber más de un dominio y cada uno de ellos tendrá su propia colección de objetos.
4. **Árbol** – Grupo de dominios con la misma raíz. Ejemplo: _dom.local, email.dom.local, www.dom.local_
5. **Bosque** – El bosque es el nivel más alto de la jerarquía de organización y está compuesto por un grupo de árboles. Los árboles están conectados por relaciones de confianza.

Active Directory proporciona varios servicios diferentes, que se engloban bajo el término "Servicios de Dominio de Active Directory" o AD DS. Estos servicios incluyen:

1. **Servicios de Dominio** – almacena datos centralizados y gestiona la comunicación entre usuarios y dominios; incluye autenticación de inicio de sesión y funcionalidad de búsqueda
2. **Servicios de Certificados** – crea, distribuye y gestiona certificados seguros
3. **Servicios de Directorio Ligero** – soporta aplicaciones habilitadas para directorio utilizando el protocolo abierto (LDAP)
4. **Servicios de Federación de Directorios** – proporciona inicio de sesión único (SSO) para autenticar a un usuario en múltiples aplicaciones web en una sola sesión
5. **Gestión de Derechos** – protege la información con derechos de autor previniendo el uso y distribución no autorizados de contenido digital
6. **Servicio DNS** – Utilizado para resolver nombres de dominio.

AD DS está incluido con Windows Server (incluyendo Windows Server 10) y está diseñado para gestionar sistemas cliente. Aunque los sistemas que ejecutan la versión regular de Windows no tienen las características administrativas de AD DS, sí soportan Active Directory. Esto significa que cualquier computadora con Windows puede conectarse a un grupo de trabajo de Windows, siempre que el usuario tenga las credenciales de inicio de sesión correctas.\
**Fuente:** [**https://techterms.com/definition/active\_directory**](https://techterms.com/definition/active\_directory)

### **Autenticación Kerberos**

Para aprender a **atacar un AD** necesitas **entender** muy bien el **proceso de autenticación Kerberos**.\
[**Lee esta página si aún no sabes cómo funciona.**](kerberos-authentication.md)

## Cheat Sheet

Puedes echar un vistazo a [https://wadcoms.github.io/](https://wadcoms.github.io) para tener una vista rápida de qué comandos puedes ejecutar para enumerar/explotar un AD.

## Reconocimiento de Active Directory (Sin credenciales/sesiones)

Si solo tienes acceso a un entorno de AD pero no tienes ninguna credencial/sesión, podrías:

* **Pentestear la red:**
* Escanear la red, encontrar máquinas y puertos abiertos e intentar **explotar vulnerabilidades** o **extraer credenciales** de ellas (por ejemplo, [las impresoras podrían ser objetivos muy interesantes](ad-information-in-printers.md).
* Enumerar DNS podría dar información sobre servidores clave en el dominio como web, impresoras, compartidos, vpn, medios, etc.
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* Echa un vistazo a la Metodología de [**Pentesting General**](../../generic-methodologies-and-resources/pentesting-methodology.md) para encontrar más información sobre cómo hacer esto.
* **Verificar acceso nulo e invitado en servicios smb** (esto no funcionará en versiones modernas de Windows):
* `enum4linux -a -u "" -p "" <IP DC> && enum4linux -a -u "guest" -p "" <IP DC>`
* `smbmap -u "" -p "" -P 445 -H <IP DC> && smbmap -u "guest" -p "" -P 445 -H <IP DC>`
* `smbclient -U '%' -L //<IP DC> && smbclient -U 'guest%' -L //`
* Una guía más detallada sobre cómo enumerar un servidor SMB se puede encontrar aquí:

{% content-ref url="../../network-services-pentesting/pentesting-smb.md" %}
[pentesting-smb.md](../../network-services-pentesting/pentesting-smb.md)
{% endcontent-ref %}

* **Enumerar Ldap**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <IP DC>`
* Una guía más detallada sobre cómo enumerar LDAP se puede encontrar aquí (presta **especial atención al acceso anónimo**):

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **Envenenar la red**
* Recopilar credenciales [**suplantando servicios con Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* Acceder al host [**abusando del ataque de retransmisión**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
* Recopilar credenciales **exponiendo** [**servicios UPnP falsos con evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology):
* Extraer nombres de usuario/nombres de documentos internos, redes sociales, servicios (principalmente web) dentro de los entornos de dominio y también de los disponibles públicamente.
* Si encuentras los nombres completos de los trabajadores de la empresa, podrías intentar diferentes convenciones de nombres de usuario de AD (**[**lee esto**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Las convenciones más comunes son: _NombreApellido_, _Nombre.Apellido_, _NomApe_ (3 letras de cada uno), _Nom.Ape_, _NApellido_, _N.Apellido_, _ApellidoNombre_, _Apellido.Nombre_, _ApellidoN_, _Apellido.N_, 3 _letras aleatorias y 3 números aleatorios_ (abc123).
* Herramientas:
* [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
* [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeración de usuarios

* **Enum SMB/LDAP anónimo:** Consulta las páginas de [**pentesting SMB**](../../network-services-pentesting/pentesting-smb.md) y [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
* **Kerbrute enum**: Cuando se solicita un **nombre de usuario no válido**, el servidor responderá con el código de error de **Kerberos** _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_, lo que nos permite determinar que el nombre de usuario era inválido. Los **nombres de usuario válidos** provocarán ya sea el **TGT en una respuesta AS-REP** o el error _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_, indicando que el usuario debe realizar una pre-autenticación.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **Servidor OWA (Outlook Web Access)**

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
Puedes encontrar listas de nombres de usuario en [**este repositorio de github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) \*\*\*\* y en este otro ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).

Sin embargo, deberías tener el **nombre de las personas que trabajan en la empresa** desde el paso de reconocimiento que deberías haber realizado antes. Con el nombre y apellido podrías usar el script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para generar posibles nombres de usuario válidos.
{% endhint %}

### Conocer uno o varios nombres de usuario

Ok, entonces sabes que ya tienes un nombre de usuario válido pero no contraseñas... Entonces intenta:

* [**ASREPRoast**](asreproast.md): Si un usuario **no tiene** el atributo _DONT\_REQ\_PREAUTH_ puedes **solicitar un mensaje AS\_REP** para ese usuario que contendrá datos cifrados por una derivación de la contraseña del usuario.
* [**Password Spraying**](password-spraying.md): Intentemos las contraseñas **más comunes** con cada uno de los usuarios descubiertos, tal vez algún usuario esté utilizando una mala contraseña (¡ten en cuenta la política de contraseñas!).
* Ten en cuenta que también puedes **rociar servidores OWA** para intentar obtener acceso a los servidores de correo de los usuarios.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### Envenenamiento de LLMNR/NBT-NS

Podrías ser capaz de **obtener** algunos **hashes de desafío** para descifrar **envenenando** algunos protocolos de la **red**:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### Relay de NTML

Si has logrado enumerar el directorio activo tendrás **más correos electrónicos y un mejor entendimiento de la red**. Podrías ser capaz de forzar ataques de [**relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) \*\*\*\* NTML para obtener acceso al entorno de AD.

### Robar credenciales NTLM

Si puedes **acceder a otros PCs o recursos compartidos** con el **usuario nulo o invitado** podrías **colocar archivos** (como un archivo SCF) que si se accede de alguna manera **desencadenará una autenticación NTML contra ti** para que puedas **robar** el **desafío NTLM** para descifrarlo:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Enumeración de Active Directory CON credenciales/sesión

Para esta fase necesitas haber **comprometido las credenciales o una sesión de una cuenta de dominio válida.** Si tienes algunas credenciales válidas o una shell como usuario de dominio, **deberías recordar que las opciones dadas antes siguen siendo opciones para comprometer a otros usuarios**.

Antes de comenzar la enumeración autenticada debes saber qué es el **problema de doble salto de Kerberos.**

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Enumeración

Haber comprometido una cuenta es un **gran paso para comenzar a comprometer todo el dominio**, porque vas a poder iniciar la **Enumeración de Active Directory:**

En cuanto a [**ASREPRoast**](asreproast.md), ahora puedes encontrar todos los usuarios posiblemente vulnerables, y en cuanto a [**Password Spraying**](password-spraying.md), puedes obtener una **lista de todos los nombres de usuario** e intentar la contraseña de la cuenta comprometida, contraseñas vacías y nuevas contraseñas prometedoras.

* Podrías usar [**CMD para realizar un reconocimiento básico**](../basic-cmd-for-pentesters.md#domain-info)
* También puedes usar [**powershell para reconocimiento**](../basic-powershell-for-pentesters/), que será más sigiloso
* También puedes [**usar powerview**](../basic-powershell-for-pentesters/powerview.md) para extraer información más detallada
* Otra herramienta increíble para el reconocimiento en un directorio activo es [**BloodHound**](bloodhound.md). **No es muy sigiloso** (dependiendo de los métodos de recolección que uses), pero **si no te importa**, definitivamente deberías probarlo. Encuentra dónde los usuarios pueden usar RDP, encuentra caminos a otros grupos, etc.
* **Otras herramientas automatizadas de enumeración de AD son:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* [**Registros DNS del AD**](ad-dns-records.md) ya que podrían contener información interesante.
* Una **herramienta con GUI** que puedes usar para enumerar el directorio es **AdExplorer.exe** de **SysInternal** Suite.
* También puedes buscar en la base de datos LDAP con **ldapsearch** para buscar credenciales en campos _userPassword_ & _unixUserPassword_, o incluso en _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para otros métodos.
* Si estás usando **Linux**, también podrías enumerar el dominio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
* También podrías intentar herramientas automatizadas como:
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **Extrayendo todos los usuarios del dominio**

Es muy fácil obtener todos los nombres de usuario del dominio desde Windows (`net user /domain` ,`Get-DomainUser` o `wmic useraccount get name,sid`). En Linux, puedes usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Aunque esta sección de Enumeración parece pequeña, es la parte más importante de todas. Accede a los enlaces (principalmente el de cmd, powershell, powerview y BloodHound), aprende cómo enumerar un dominio y practica hasta que te sientas cómodo. Durante una evaluación, este será el momento clave para encontrar tu camino a DA o para decidir que nada se puede hacer.

### Kerberoast

El objetivo de Kerberoasting es recolectar **tickets TGS para servicios que se ejecutan en nombre de cuentas de usuario de dominio**. Parte de estos tickets TGS están **cifrados con claves derivadas de las contraseñas de los usuarios**. Como consecuencia, sus credenciales podrían ser **descifradas sin conexión**.\
Más sobre esto en:

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### Conexión remota (RDP, SSH, FTP, Win-RM, etc)

Una vez que hayas obtenido algunas credenciales, podrías verificar si tienes acceso a alguna **máquina**. Para ello, podrías usar **CrackMapExec** para intentar conectarte en varios servidores con diferentes protocolos, de acuerdo a tus escaneos de puertos.

### Escalada de Privilegios Local

Si has comprometido credenciales o una sesión como un usuario de dominio regular y tienes **acceso** con este usuario a **cualquier máquina en el dominio** deberías intentar encontrar la manera de **escalar privilegios localmente y buscar credenciales**. Esto se debe a que solo con privilegios de administrador local podrás **volcar hashes de otros usuarios** en memoria (LSASS) y localmente (SAM).

Hay una página completa en este libro sobre [**escalada de privilegios local en Windows**](../windows-local-privilege-escalation/) y una [**lista de comprobación**](../checklist-windows-privilege-escalation.md). Además, no olvides usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets de la Sesión Actual

Es muy **improbable** que encuentres **tickets** en el usuario actual que te **den permiso para acceder** a recursos inesperados, pero podrías verificar:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

Si has logrado enumerar el active directory tendrás **más correos electrónicos y un mejor entendimiento de la red**. Podrías ser capaz de forzar ataques de [**relay NTML**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### **Busca Creds en Comparticiones de Computadoras**

Ahora que tienes algunas credenciales básicas deberías verificar si puedes **encontrar** archivos **interesantes compartidos dentro del AD**. Podrías hacerlo manualmente pero es una tarea muy aburrida y repetitiva (y más si encuentras cientos de documentos que necesitas revisar).

[**Sigue este enlace para aprender sobre herramientas que podrías usar.**](../../network-services-pentesting/pentesting-smb.md#domain-shared-folders-search)

### Robar Creds NTLM

Si puedes **acceder a otras PCs o comparticiones** podrías **colocar archivos** (como un archivo SCF) que si de alguna manera se accede **activará una autenticación NTML contra ti** para que puedas **robar** el **desafío NTLM** y descifrarlo:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Esta vulnerabilidad permitía a cualquier usuario autenticado **comprometer el controlador de dominio**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Escalada de privilegios en Active Directory CON credenciales/sesión privilegiadas

**Para las siguientes técnicas un usuario de dominio regular no es suficiente, necesitas algunos privilegios/credenciales especiales para realizar estos ataques.**

### Extracción de hashes

Esperemos que hayas logrado **comprometer alguna cuenta de administrador local** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluyendo relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalando privilegios localmente](../windows-local-privilege-escalation/).\
Entonces, es hora de volcar todos los hashes en memoria y localmente.\
[**Lee esta página sobre diferentes maneras de obtener los hashes.**](broken-reference/)

### Pass the Hash

**Una vez que tienes el hash de un usuario**, puedes usarlo para **personificarlo**.\
Necesitas usar alguna **herramienta** que **realice** la **autenticación NTLM usando** ese **hash**, **o** podrías crear un nuevo **sessionlogon** e **inyectar** ese **hash** dentro del **LSASS**, así cuando se realice cualquier **autenticación NTLM**, ese **hash será utilizado**. La última opción es lo que hace mimikatz.\
[**Lee esta página para más información.**](../ntlm/#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque tiene como objetivo **usar el hash NTLM del usuario para solicitar tickets de Kerberos**, como una alternativa al común Pass The Hash sobre el protocolo NTLM. Por lo tanto, esto podría ser especialmente **útil en redes donde el protocolo NTLM está deshabilitado** y solo **Kerberos está permitido** como protocolo de autenticación.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Pass the Ticket

Este ataque es similar a Pass the Key, pero en lugar de usar hashes para solicitar un ticket, el **ticket en sí es robado** y utilizado para autenticarse como su propietario.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Reutilización de Credenciales

Si tienes el **hash** o **contraseña** de un **administrador local** deberías intentar **iniciar sesión localmente** en otras **PCs** con ella.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
Tenga en cuenta que esto es bastante **ruidoso** y **LAPS** lo **mitigaría**.
{% endhint %}

### Abuso de MSSQL y Enlaces de Confianza

Si un usuario tiene privilegios para **acceder a instancias de MSSQL**, podría usarlo para **ejecutar comandos** en el host de MSSQL (si se ejecuta como SA), **robar** el **hash** de NetNTLM o incluso realizar un **ataque** de **relay**.\
Además, si una instancia de MSSQL es confiable (enlace de base de datos) por una instancia diferente de MSSQL. Si el usuario tiene privilegios sobre la base de datos confiable, podrá **usar la relación de confianza para ejecutar consultas también en la otra instancia**. Estas confianzas se pueden encadenar y en algún momento el usuario podría encontrar una base de datos mal configurada donde pueda ejecutar comandos.\
**Los enlaces entre bases de datos funcionan incluso a través de confianzas de bosque.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Delegación sin Restricciones

Si encuentra algún objeto de Computadora con el atributo [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) y tiene privilegios de dominio en la computadora, podrá volcar TGTs de la memoria de todos los usuarios que inicien sesión en la computadora.\
Entonces, si un **Administrador de Dominio inicia sesión en la computadora**, podrá volcar su TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Gracias a la delegación restringida, incluso podría **comprometer automáticamente un Servidor de Impresión** (con suerte será un DC).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Delegación Restringida

Si se permite a un usuario o computadora "Delegación Restringida", podrá **impersonar a cualquier usuario para acceder a algunos servicios en una computadora**.\
Luego, si **compromete el hash** de este usuario/computadora, podrá **impersonar a cualquier usuario** (incluso administradores de dominio) para acceder a algunos servicios.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Delegación Restringida Basada en Recursos

Es posible obtener ejecución de código con **privilegios elevados en una computadora remota si tiene privilegio de ESCRITURA** en el objeto de AD de esa computadora.

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### Abuso de ACLs

El usuario comprometido podría tener algunos **privilegios interesantes sobre algunos objetos de dominio** que podrían permitirle **moverse** lateralmente/**escalar** privilegios.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Abuso del servicio de Cola de Impresión

Si puede encontrar cualquier **servicio de Cola escuchando** dentro del dominio, puede ser capaz de **abusar** de él para **obtener nuevas credenciales** y **escalar privilegios**.\
[**Más información sobre cómo abusar de los servicios de Cola de Impresión aquí.**](printers-spooler-service-abuse.md)

### Abuso de sesiones de terceros

Si **otros usuarios** **acceden** a la máquina **comprometida**, es posible **recopilar credenciales de la memoria** e incluso **inyectar balizas en sus procesos** para impersonarlos.\
Por lo general, los usuarios accederán al sistema a través de RDP, así que aquí tiene cómo realizar un par de ataques sobre sesiones RDP de terceros:

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** le permite **administrar la contraseña del Administrador local** (que es **aleatoria**, única y se **cambia regularmente**) en computadoras unidas al dominio. Estas contraseñas se almacenan centralmente en Active Directory y están restringidas a usuarios autorizados mediante ACLs. Si tiene **suficiente permiso para leer estas contraseñas, podría moverse a otras computadoras**.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Robo de Certificados

Recopilar certificados de la máquina comprometida podría ser una forma de escalar privilegios dentro del entorno:

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Abuso de Plantillas de Certificados

Si se configuran plantillas vulnerables, es posible abusar de ellas para escalar privilegios:

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## Post-explotación con cuenta de alto privilegio

### Volcado de Credenciales de Dominio

Una vez que obtiene privilegios de **Administrador de Dominio** o incluso mejor de **Administrador de Empresa**, puede **volcar** la **base de datos de dominio**: _ntds.dit_.

[**Más información sobre el ataque DCSync se puede encontrar aquí**](dcsync.md).

[**Más información sobre cómo robar el NTDS.dit se puede encontrar aquí**](broken-reference/)

### Privesc como Persistencia

Algunas de las técnicas discutidas anteriormente se pueden usar para persistencia.\
Por ejemplo, podría:

*   Hacer que los usuarios sean vulnerables a [**Kerberoast**](kerberoast.md)

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```
*   Hacer que los usuarios sean vulnerables a [**ASREPRoast**](asreproast.md)

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
*   Otorgar privilegios de [**DCSync**](./#dcsync) a un usuario

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

El ataque de Silver ticket se basa en **crear un TGS válido para un servicio una vez que se posee el hash NTLM del servicio** (como el **hash de la cuenta de PC**). Por lo tanto, es posible **acceder a ese servicio** forjando un TGS personalizado **como cualquier usuario** (como acceso privilegiado a una computadora).

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Golden Ticket

Se puede crear un **TGT válido como cualquier usuario** **usando el hash NTLM de la cuenta krbtgt de AD**. La ventaja de forjar un TGT en lugar de un TGS es poder **acceder a cualquier servicio** (o máquina) en el dominio como el usuario suplantado.

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Diamond Ticket

Estos son como golden tickets forjados de manera que **evitan los mecanismos comunes de detección de golden tickets.**

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### **Persistencia de Cuenta con Certificados**

**Tener certificados de una cuenta o poder solicitarlos** es una muy buena manera de poder persistir en la cuenta del usuario (incluso si cambia la contraseña):

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **Persistencia de Dominio con Certificados**

**Usar certificados también es posible para persistir con altos privilegios dentro del dominio:**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### Grupo AdminSDHolder

La Lista de Control de Acceso (ACL) del objeto **AdminSDHolder** se utiliza como plantilla para **copiar** **permisos** a **todos los "grupos protegidos"** en Active Directory y sus miembros. Los grupos protegidos incluyen grupos privilegiados como Administradores de Dominio, Administradores, Administradores de Empresa y Administradores de Esquema, Operadores de Copia de Seguridad y krbtgt.\
Por defecto, la ACL de este grupo se copia dentro de todos los "grupos protegidos". Esto se hace para evitar cambios intencionales o accidentales en estos grupos críticos. Sin embargo, si un atacante **modifica la ACL** del grupo **AdminSDHolder**, por ejemplo, otorgando permisos completos a un usuario regular, este usuario tendrá permisos completos en todos los grupos dentro del grupo protegido (en una hora).\
Y si alguien intenta eliminar a este usuario de los Administradores de Dominio (por ejemplo) en una hora o menos, el usuario volverá al grupo.\
[**Más información sobre el Grupo AdminDSHolder aquí.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Credenciales DSRM

Hay una cuenta de **administrador local** dentro de cada **DC**. Teniendo privilegios de administrador en esta máquina, puede usar mimikatz para **volcar el hash del Administrador local**. Luego, modificando un registro para **activar esta contraseña** para que pueda acceder de forma remota a este usuario de Administrador local.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### Persistencia de ACL

Podría **otorgar** algunos **permisos especiales** a un **usuario** sobre algunos objetos de dominio específicos que permitirán al usuario **escalar privilegios en el futuro**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Descriptores de Seguridad

Los **descriptores de seguridad** se utilizan para **almacenar** los **permisos** que un **objeto** tiene **sobre** otro **objeto**. Si puede hacer **un pequeño cambio** en el **descriptor de seguridad** de un objeto, puede obtener privilegios muy interesantes sobre ese objeto sin necesidad de ser miembro de un grupo privilegiado.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Skeleton Key

**Modificar LSASS** en memoria para crear una **contraseña maestra** que funcionará para cualquier cuenta en el dominio.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### SSP Personalizado

[Aprenda qué es un SSP (Proveedor de Soporte de Seguridad) aquí.](../authentication-credentials-uac-and-efs.md#security-support-provider-interface-sspi)\
Puede crear su **propio SSP** para **capturar** en **texto claro** las **credenciales** utilizadas para acceder a la máquina.\\

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

Registra un **nuevo Controlador de Dominio** en el AD y lo utiliza para **empujar atributos** (SIDHistory, SPNs...) en objetos específicos **sin** dejar ningún **registro** sobre las **modificaciones**. **Necesita privilegios de DA** y estar dentro del **dominio raíz**.\
Tenga en cuenta que si usa datos incorrectos, aparecerán registros muy feos.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### Persistencia de LAPS

Anteriormente hemos discutido sobre cómo escalar privilegios si tiene **suficiente permiso para leer contraseñas de LAPS**. Sin embargo, estas contraseñas también se pueden usar para **mantener la persistencia**.\
Compruebe:

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## Escalada de Privilegios en el Bosque - Confianzas de Dominio

Microsoft considera que el **dominio no es un Límite de Seguridad**, el **Bosque es el Límite de Seguridad**. Esto significa que **si compromete un dominio dentro de un Bosque, podría ser capaz de comprometer todo el Bosque**.

### Información Básica

A un alto nivel, una [**confianza de dominio**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx) establece la capacidad para que **los usuarios de un dominio se autentiquen** en recursos o actúen como un [principal de seguridad](https://technet.microsoft.com/en-us/library/cc780957\(v=ws.10\).aspx) **en otro dominio**.

Esencialmente, todo lo que hace una confianza es **vincular los sistemas de autenticación de dos dominios** y permitir que el tráfico de autenticación fluya entre ellos a través de un sistema de referencias.\
Cuando **2 dominios se confían entre sí, intercambian claves**, estas **claves** se **guardarán** en los **DCs** de **cada dominio** (**2 claves por dirección de confianza, última y anterior**) y las claves serán la base de la confianza.

Cuando un **usuario** intenta **acceder** a un **servicio** en el **dominio confiante**, solicitará un **TGT inter-reino** al DC de su dominio. El DC servirá al cliente este **TGT** que estaría **cifrado/firmado** con la **clave inter-reino** (la clave que ambos dominios **intercambiaron**). Luego, el **cliente** **accederá** al **DC del otro dominio** y **solicitará** un **TGS** para el servicio utilizando el **TGT inter-reino**. El **DC** del dominio confiante **verificará** la **clave** utilizada, si está bien, **confiará en todo lo que esté en ese ticket** y servirá el TGS al cliente.

![](<../../.gitbook/assets/image (166) (1).png>)

### Diferentes confianzas

Es importante notar que **una confianza puede ser de 1 vía o de 2 vías**. En las opciones de 2 vías, ambos dominios se confiarán mutuamente, pero en la relación de confianza de **1 vía**, uno de los dominios será el **confiado** y el otro el **confiante**. En el último caso, **solo podrá acceder a recursos dentro del dominio confiante desde el dominio confiado**.

Si el Dominio A confía en el Dominio B, A es el dominio confiante y B es el confiado. Además, en **Dominio A**, esto sería una **confianza saliente**; y en **Dominio B**, esto sería una **confianza entrante**.

**Diferentes relaciones de confianza**

* **Padre-Hijo** – parte del mismo bosque – un dominio hijo mantiene una confianza transitoria bidireccional implícita con su padre. Esta es probablemente el tipo de confianza más común que encontrará.
* **Enlace cruzado** – también conocido como una "confianza de acceso directo" entre dominios hijos para mejorar los tiempos de referencia. Normalmente, las referencias en un bosque complejo tienen que filtrarse hasta la raíz del bosque y luego volver al dominio objetivo, por lo que para un escenario geográficamente disperso, los enlaces cruzados pueden tener sentido para reducir los tiempos de autenticación.
* **Externa** – una confianza implícitamente no transitoria creada entre dominios dispares. "[Las confianzas externas proporcionan acceso a recursos en un dominio fuera del bosque que no está ya unido por una confianza de bosque.](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx)" Las confianzas externas aplican filtrado de SID, una protección de seguridad cubierta más adelante en esta publicación.
* **Raíz de árbol** – una confianza transitoria bidireccional implícita entre el dominio raíz del bosque y la nueva raíz del árbol que está agregando. No he encontrado confianzas de raíz de árbol con demasiada frecuencia, pero según la [documentación de Microsoft](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx), se crean cuando se crea un nuevo árbol de dominio en un bosque. Estas son confianzas intra-bosque, y
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
Hay **2 claves de confianza**, una para _Child --> Parent_ y otra para _Parent_ --> _Child_.\
Puedes ver la que utiliza el dominio actual con:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
#### Inyección de SID-History

Escalar como administrador de la empresa al dominio hijo/padre abusando de la confianza con la inyección de SID-History:

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Explotar NC de Configuración escribible

El NC de Configuración es el repositorio principal para la información de configuración de un bosque y se replica en cada DC del bosque. Además, cada DC escribible (no solo de lectura) en el bosque tiene una copia escribible del NC de Configuración. Explotar esto requiere ejecutarse como SYSTEM en un DC (hijo).

Es posible comprometer el dominio raíz de varias maneras cubiertas a continuación.

**Vincular GPO al sitio del DC raíz**

El contenedor de Sitios en el NC de Configuración contiene todos los sitios de las computadoras unidas al dominio en el bosque de AD. Es posible vincular GPOs a sitios cuando se ejecuta como SYSTEM en cualquier DC del bosque, incluyendo el(los) sitio(s) de los DCs raíz del bosque, y de este modo comprometerlos.

Se pueden leer más detalles aquí [Investigación de Bypass SID filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Comprometer cualquier gMSA en el bosque**

El ataque depende de gMSAs privilegiados en el dominio objetivo.

La clave raíz de KDS, que se utiliza para calcular la contraseña de los gMSAs en el bosque, se almacena en el NC de Configuración. Cuando se ejecuta como SYSTEM en cualquier DC del bosque, se puede leer la clave raíz de KDS y calcular la contraseña de cualquier gMSA en el bosque.

Se pueden leer más detalles aquí: [Ataque de confianza Golden gMSA de hijo a padre](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Ataque de cambio de esquema**

El ataque requiere que el atacante espere a que se creen nuevos objetos AD privilegiados.

Cuando se ejecuta como SYSTEM en cualquier DC del bosque, se puede otorgar a cualquier usuario control total sobre todas las clases en el Esquema de AD. Ese control puede ser abusado para crear un ACE en el descriptor de seguridad predeterminado de cualquier objeto AD que otorgue control total a un principal comprometido. Todas las nuevas instancias de los tipos de objetos AD modificados tendrán este ACE.

Se pueden leer más detalles aquí: [Ataque de confianza de cambio de esquema de hijo a padre](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**De DA a EA con ADCS ESC5**

Los ataques ADCS ESC5 (Vulnerable PKI Object Access Control) abusan del control sobre los objetos PKI para crear una plantilla de certificado vulnerable que puede ser abusada para autenticarse como cualquier usuario en el bosque. Dado que todos los objetos PKI se almacenan en el NC de Configuración, se puede ejecutar ESC5 si se ha comprometido cualquier DC escribible (hijo) en el bosque.

Se pueden leer más detalles aquí: [De DA a EA con ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)

En caso de que el bosque de AD no tenga ADCS, el atacante puede crear los componentes necesarios como se describe aquí: [Escalando de los administradores del dominio hijo a los administradores de la empresa en 5 minutos abusando de AD CS, un seguimiento](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Dominio de Bosque Externo - Unidireccional (Entrante) o bidireccional
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
En este escenario **tu dominio es confiable** por uno externo otorgándote **permisos indeterminados** sobre él. Necesitarás encontrar **qué principios de tu dominio tienen qué acceso sobre el dominio externo** y luego intentar explotarlo:

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
En este escenario, **tu dominio** está **confiando** algunos **privilegios** a un principal de **diferentes dominios**.

Sin embargo, cuando un **dominio es confiado** por el dominio confiante, el dominio confiado **crea un usuario** con un **nombre predecible** que usa como **contraseña la contraseña confiada**. Lo que significa que es posible **acceder a un usuario del dominio confiante para entrar en el confiado** para enumerarlo e intentar escalar más privilegios:

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

Otra forma de comprometer el dominio confiado es encontrar un [**enlace SQL confiado**](abusing-ad-mssql.md#mssql-trusted-links) creado en la **dirección opuesta** de la confianza del dominio (lo cual no es muy común).

Otra forma de comprometer el dominio confiado es esperar en una máquina donde un **usuario del dominio confiado pueda acceder** para iniciar sesión a través de **RDP**. Entonces, el atacante podría inyectar código en el proceso de sesión de RDP y **acceder al dominio de origen de la víctima** desde allí.\
Además, si la **víctima montó su disco duro**, desde el proceso de **sesión RDP** el atacante podría almacenar **puertas traseras** en la **carpeta de inicio del disco duro**. Esta técnica se llama **RDPInception.**

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Mitigación del abuso de confianza de dominio

**Filtrado de SID:**

* Evitar ataques que abusan del atributo de historial de SID a través de la confianza entre bosques.
* Activado por defecto en todas las confianzas entre bosques. Se asume que las confianzas intra-bosque están seguras por defecto (MS considera al bosque y no al dominio como un límite de seguridad).
* Pero, dado que el filtrado de SID tiene el potencial de romper aplicaciones y acceso de usuarios, a menudo se desactiva.
* Autenticación Selectiva
* En una confianza entre bosques, si se configura la Autenticación Selectiva, los usuarios entre las confianzas no serán autenticados automáticamente. Se debe otorgar acceso individual a dominios y servidores en el dominio/bosque confiante.
* No previene la explotación de NC de Configuración escribible y el ataque de cuenta de confianza.

[**Más información sobre confianzas de dominio en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Cloud & Cloud -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Algunas Defensas Generales

[**Aprende más sobre cómo proteger credenciales aquí.**](../stealing-credentials/credentials-protections.md)\
**Por favor, encuentra algunas migraciones contra cada técnica en la descripción de la técnica.**

* No permitir que los Administradores de Dominio inicien sesión en otros hosts aparte de los Controladores de Dominio
* Nunca ejecutar un servicio con privilegios de DA
* Si necesitas privilegios de administrador de dominio, limita el tiempo: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### Engaño

* La contraseña no expira
* Confiado para Delegación
* Usuarios con SPN
* Contraseña en descripción
* Usuarios que son miembros de grupos de alto privilegio
* Usuarios con derechos ACL sobre otros usuarios, grupos o contenedores
* Objetos de computadora
* ...
* [https://github.com/samratashok/Deploy-Deception](https://github.com/samratashok/Deploy-Deception)
* `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`

## Cómo identificar el engaño

**Para objetos de usuario:**

* ObjectSID (diferente del dominio)
* lastLogon, lastlogontimestamp
* Logoncount (un número muy bajo es sospechoso)
* whenCreated
* Badpwdcount (un número muy bajo es sospechoso)

**General:**

* Algunas soluciones llenan con información todos los atributos posibles. Por ejemplo, compara los atributos de un objeto de computadora con el atributo de un objeto de computadora 100% real como DC. O usuarios contra el RID 500 (admin por defecto).
* Comprueba si algo es demasiado bueno para ser verdad
* [https://github.com/JavelinNetworks/HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)

### Evadiendo la detección de Microsoft ATA

#### Enumeración de usuarios

ATA solo se queja cuando intentas enumerar sesiones en el DC, así que si no buscas sesiones en el DC sino en el resto de los hosts, probablemente no serás detectado.

#### Creación de impersonación de Tickets (Over pass the hash, golden ticket...)

Siempre crea los tickets usando también las claves **aes** porque lo que ATA identifica como malicioso es la degradación a NTLM.

#### DCSync

Si no ejecutas esto desde un Controlador de Dominio, ATA te va a atrapar, lo siento.

## Más Herramientas

* [Script de Powershell para hacer automatización de auditoría de dominio](https://github.com/phillips321/adaudit)
* [Script de Python para enumerar active directory](https://github.com/ropnop/windapsearch)
* [Script de Python para enumerar active directory](https://github.com/CroweCybersecurity/ad-ldap-enum)

## Referencias

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? o ¿quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
