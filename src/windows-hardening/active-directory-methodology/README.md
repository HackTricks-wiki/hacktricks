# Metodología de Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Descripción básica

**Active Directory** sirve como una tecnología fundamental, permitiendo a los **administradores de red** crear y gestionar de forma eficiente **dominios**, **usuarios** y **objetos** dentro de una red. Está diseñado para escalar, facilitando la organización de un gran número de usuarios en **grupos** y **subgrupos** manejables, mientras controla los **derechos de acceso** en distintos niveles.

La estructura de **Active Directory** se compone de tres capas principales: **dominios**, **árboles** y **bosques**. Un **dominio** abarca una colección de objetos, como **usuarios** o **dispositivos**, que comparten una base de datos común. Los **árboles** son conjuntos de estos dominios enlazados por una estructura común, y un **bosque** representa la colección de varios árboles, interconectados mediante **trust relationships**, formando la capa superior de la estructura organizativa. Se pueden designar **derechos de acceso** y **comunicación** específicos en cada uno de estos niveles.

Conceptos clave dentro de **Active Directory** incluyen:

1. **Directory** – Aloja toda la información relativa a los objetos de Active Directory.
2. **Object** – Denota entidades dentro del directorio, incluyendo **usuarios**, **grupos** o **carpetas compartidas**.
3. **Domain** – Sirve como contenedor para objetos del directorio, pudiendo coexistir múltiples dominios dentro de un **forest**, cada uno manteniendo su propia colección de objetos.
4. **Tree** – Agrupación de dominios que comparten un dominio raíz común.
5. **Forest** – La cúspide de la estructura organizativa en Active Directory, compuesta por varios árboles con **trust relationships** entre ellos.

**Active Directory Domain Services (AD DS)** abarca una serie de servicios críticos para la gestión centralizada y la comunicación dentro de una red. Estos servicios comprenden:

1. **Domain Services** – Centraliza el almacenamiento de datos y gestiona las interacciones entre **usuarios** y **dominios**, incluyendo **authentication** y funcionalidades de **search**.
2. **Certificate Services** – Supervisa la creación, distribución y gestión de **digital certificates** seguras.
3. **Lightweight Directory Services** – Da soporte a aplicaciones habilitadas para directorio mediante el **LDAP protocol**.
4. **Directory Federation Services** – Proporciona capacidades de **single-sign-on** para autenticar usuarios en múltiples aplicaciones web en una sola sesión.
5. **Rights Management** – Ayuda a proteger material con derechos de autor regulando su distribución y uso no autorizados.
6. **DNS Service** – Crucial para la resolución de **domain names**.

Para una explicación más detallada consulta: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Para aprender a **atacar un AD** necesitas entender muy bien el proceso de **autenticación Kerberos**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Puedes visitar [https://wadcoms.github.io/](https://wadcoms.github.io) para obtener una vista rápida de qué comandos puedes ejecutar para enumerar/explotar un AD.

> [!WARNING]
> La comunicación Kerberos **requiere un nombre totalmente calificado (FQDN)** para realizar acciones. Si intentas acceder a una máquina por la dirección IP, **usará NTLM y no Kerberos**.

## Recon de Active Directory (sin credenciales/sesiones)

Si solo tienes acceso al entorno AD pero no dispones de credenciales/sesiones, podrías:

- **Pentest the network:**
- Escanear la red, encontrar máquinas y puertos abiertos e intentar **explotar vulnerabilidades** o **extraer credenciales** de ellas (por ejemplo, [las impresoras pueden ser objetivos muy interesantes](ad-information-in-printers.md)).
- Enumerar DNS puede dar información sobre servidores clave en el dominio como web, impresoras, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Echa un vistazo a la página general [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) para encontrar más información sobre cómo hacer esto.
- **Comprobar acceso null y Guest en servicios smb** (esto no funcionará en versiones modernas de Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Una guía más detallada sobre cómo enumerar un servidor SMB puede encontrarse aquí:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerar Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Una guía más detallada sobre cómo enumerar LDAP puede encontrarse aquí (presta **especial atención al acceso anónimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Recolectar credenciales [**suplantando servicios con Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Acceder a hosts [**abusando del relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Recolectar credenciales **exponiendo** [**fake UPnP services con evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extraer usernames/nombres de documentos internos, redes sociales, servicios (principalmente web) dentro de los entornos del dominio y también de lo disponible públicamente.
- Si encuentras los nombres completos de los empleados de la empresa, podrías probar diferentes convenciones de **username de AD** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Las convenciones más comunes son: _NameSurname_, _Name.Surname_, _NamSur_ (3 letras de cada uno), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Herramientas:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeración de usuarios

- **Anonymous SMB/LDAP enum:** Revisa las páginas de [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) y [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Cuando se solicita un **username inválido** el servidor responderá usando el código de error de **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permitiéndonos determinar que el username era inválido. Los **usernames válidos** provocarán o bien el **TGT en un AS-REP** o el error _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando que el usuario debe realizar pre-autenticación.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contra la interfaz MS-NRPC (Netlogon) en domain controllers. El método invoca la función `DsrGetDcNameEx2` tras enlazar la interfaz MS-NRPC para comprobar si el usuario o el equipo existe sin credenciales. La herramienta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa este tipo de enumeración. La investigación puede encontrarse [aquí](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Si encontraste uno de estos servidores en la red, también puedes realizar **enumeración de usuarios contra él**. Por ejemplo, podrías usar la herramienta [**MailSniper**](https://github.com/dafthack/MailSniper):
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

Si has logrado enumerar Active Directory tendrás **más correos electrónicos y una mejor comprensión de la red**. Podrías ser capaz de forzar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Busca Creds en Computer Shares | SMB Shares

Ahora que tienes algunas credenciales básicas deberías comprobar si puedes **encontrar** archivos **interesantes compartidos dentro del AD**. Podrías hacerlo manualmente pero es una tarea muy aburrida y repetitiva (y más aún si encuentras cientos de docs que necesitas revisar).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Si puedes **acceder a otros PCs o shares** podrías **colocar archivos** (como un archivo SCF) que si de alguna manera se acceden **dispararán una autenticación NTLM contra ti** para que puedas **steal** el **NTLM challenge** para crackearlo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Esta vulnerabilidad permitía a cualquier usuario autenticado **comprometer el controlador de dominio**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Para las siguientes técnicas un usuario de dominio normal no es suficiente, necesitas algunos privilegios/credenciales especiales para realizar estos ataques.**

### Hash extraction

Con suerte has logrado **comprometer alguna cuenta de administrador local** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluyendo relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Luego, es momento de volcar todos los hashes en memoria y localmente.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una vez que tengas el hash de un usuario**, puedes usarlo para **impersonate** it.\
Necesitas usar alguna **tool** que **perform** la **NTLM authentication using** ese **hash**, **or** podrías crear un nuevo **sessionlogon** e **inject** ese **hash** dentro de **LSASS**, así cuando se realice cualquier **NTLM authentication**, ese **hash será usado.** La última opción es lo que hace mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque tiene como objetivo **usar el hash NTLM del usuario para solicitar tickets Kerberos**, como alternativa al común Pass The Hash sobre el protocolo NTLM. Por tanto, esto podría ser especialmente **útil en redes donde el protocolo NTLM está deshabilitado** y solo **Kerberos está permitido** como protocolo de autenticación.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

En el método de ataque **Pass The Ticket (PTT)**, los atacantes **roban el ticket de autenticación de un usuario** en lugar de su contraseña o valores hash. Este ticket robado se usa luego para **impersonate the user**, obteniendo acceso no autorizado a recursos y servicios dentro de la red.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Si tienes el **hash** o la **contraseña** de un **administrador local** deberías intentar **login locally** en otros **PCs** con ella.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Tenga en cuenta que esto es bastante **ruidoso** y **LAPS** lo **mitigaría**.

### MSSQL Abuse & Trusted Links

Si un usuario tiene privilegios para **acceder a instancias MSSQL**, podría usarlas para **ejecutar comandos** en el host MSSQL (si corre como SA), **robar** el NetNTLM **hash** o incluso realizar un **relay** **attack**.\
Además, si una instancia MSSQL es trusted (database link) por otra instancia MSSQL diferente. Si el usuario tiene privilegios sobre la base de datos confiable, podrá **usar la relación de confianza para ejecutar consultas también en la otra instancia**. Estas confianzas pueden encadenarse y en algún punto el usuario podría encontrar una base de datos mal configurada donde pueda ejecutar comandos.\
**Los enlaces entre bases de datos funcionan incluso a través de forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Las suites de inventario y despliegue de terceros a menudo exponen caminos potentes hacia credenciales y ejecución de código. Ver:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Si encuentras cualquier objeto Computer con el atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) y tienes privilegios de dominio en el equipo, podrás volcar TGTs desde la memoria de todos los usuarios que inicien sesión en el equipo.\
Así, si un **Domain Admin** inicia sesión en el equipo, podrás volcar su TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Gracias a constrained delegation incluso podrías **comprometer automáticamente un Print Server** (con suerte será un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Si a un usuario o equipo se le permite "Constrained Delegation" podrá **suplantar a cualquier usuario para acceder a ciertos servicios en un equipo**.\
Entonces, si **comprometes el hash** de ese usuario/equipo podrás **suplantar a cualquier usuario** (incluso domain admins) para acceder a algunos servicios.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Tener privilegio **WRITE** sobre un objeto de Active Directory de un equipo remoto permite obtener ejecución de código con **privilegios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

El usuario comprometido podría tener algunos **privilegios interesantes sobre ciertos objetos del dominio** que podrían permitirte **moverte** lateralmente/**escalar** privilegios.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Descubrir un **servicio Spool escuchando** dentro del dominio puede ser **abusado** para **adquirir nuevas credenciales** y **escalar privilegios**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Si **otros usuarios** **acceden** a la máquina **comprometida**, es posible **recopilar credenciales desde la memoria** e incluso **inyectar beacons en sus procesos** para suplantarlos.\
Normalmente los usuarios acceden al sistema vía RDP, así que aquí tienes cómo realizar un par de ataques sobre sesiones RDP de terceros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** proporciona un sistema para gestionar la **contraseña del Administrador local** en equipos unidos al dominio, asegurando que sea **aleatoria**, única y se **cambie** con frecuencia. Estas contraseñas se almacenan en Active Directory y el acceso está controlado mediante ACLs a usuarios autorizados únicamente. Con permisos suficientes para acceder a estas contraseñas, es posible pivotar a otros equipos.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Recopilar certificados** desde la máquina comprometida podría ser una forma de escalar privilegios dentro del entorno:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Si se configuran **plantillas vulnerables** es posible abusar de ellas para escalar privilegios:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Una vez que obtienes privilegios de **Domain Admin** o, aún mejor, **Enterprise Admin**, puedes **volcar** la **base de datos del dominio**: _ntds.dit_.

[**Más información sobre el ataque DCSync puede encontrarse aquí**](dcsync.md).

[**Más información sobre cómo robar el NTDS.dit puede encontrarse aquí**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Algunas de las técnicas discutidas anteriormente pueden usarse para persistencia.\
Por ejemplo podrías:

- Hacer a usuarios vulnerables a [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Hacer a usuarios vulnerables a [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Conceder privilegios de [**DCSync**](#dcsync) a un usuario

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

El **ataque Silver Ticket** crea un **ticket TGS legítimo** para un servicio específico usando el **NTLM hash** (por ejemplo, el **hash de la cuenta del PC**). Este método se emplea para **acceder a los privilegios del servicio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un **Golden Ticket attack** implica que un atacante obtiene acceso al **NTLM hash de la cuenta krbtgt** en un entorno Active Directory (AD). Esta cuenta es especial porque se usa para firmar todos los **Ticket Granting Tickets (TGTs)**, que son esenciales para autenticarse dentro de la red AD.

Una vez que el atacante obtiene este hash, puede crear **TGTs** para cualquier cuenta que elija (ataque Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Son como golden tickets forjados de una manera que **evita los mecanismos comunes de detección de golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Tener los certificados de una cuenta o poder solicitarlos** es una muy buena forma de persistir en la cuenta de un usuario (incluso si cambia la contraseña):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Usar certificados también permite persistir con altos privilegios dentro del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

El objeto **AdminSDHolder** en Active Directory asegura la seguridad de **grupos privilegiados** (como Domain Admins y Enterprise Admins) aplicando una **ACL** estándar a través de estos grupos para prevenir cambios no autorizados. Sin embargo, esta característica puede ser explotada; si un atacante modifica la ACL del AdminSDHolder para dar acceso total a un usuario normal, ese usuario obtiene un control extenso sobre todos los grupos privilegiados. Esta medida de seguridad, destinada a proteger, puede volverse contraproducente y permitir acceso indebido a menos que se supervise de cerca.

[**Más información sobre AdminDSHolder Group aquí.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Dentro de cada **Domain Controller (DC)** existe una cuenta de **administrador local**. Al obtener permisos de admin en una máquina así, el hash del Administrador local puede extraerse usando **mimikatz**. A continuación, es necesario modificar el registro para **habilitar el uso de esta contraseña**, permitiendo el acceso remoto a la cuenta de Administrador local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Podrías **dar** algunos **permisos especiales** a un **usuario** sobre ciertos objetos del dominio que le permitan **escalar privilegios en el futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Los **descriptores de seguridad** se usan para **almacenar** los **permisos** que un **objeto** tiene **sobre** un **objeto**. Si puedes simplemente **hacer** un **pequeño cambio** en el **security descriptor** de un objeto, puedes obtener privilegios muy interesantes sobre ese objeto sin necesitar ser miembro de un grupo privilegiado.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Alterar **LSASS** en memoria para establecer una **contraseña universal**, otorgando acceso a todas las cuentas del dominio.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puedes crear tu **propio SSP** para **capturar** en **texto claro** las **credenciales** usadas para acceder a la máquina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra un **nuevo Domain Controller** en el AD y lo usa para **empujar atributos** (SIDHistory, SPNs...) sobre objetos especificados **sin** dejar registros sobre las **modificaciones**. Necesitas privilegios DA y estar dentro del **root domain**.\
Nota que si usas datos incorrectos, aparecerán registros bastante feos.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Antes discutimos cómo escalar privilegios si tienes **permiso suficiente para leer contraseñas LAPS**. Sin embargo, estas contraseñas también pueden usarse para **mantener persistencia**.\
Revisa:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considera el **Forest** como el límite de seguridad. Esto implica que **comprometer un solo dominio podría potencialmente llevar a comprometer todo el Bosque**.

### Basic Information

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) es un mecanismo de seguridad que permite a un usuario de un **dominio** acceder a recursos en otro **dominio**. Básicamente crea un enlace entre los sistemas de autenticación de ambos dominios, permitiendo que las verificaciones de autenticación fluyan de forma transparente. Cuando los dominios establecen una confianza, intercambian y almacenan ciertas **claves** dentro de sus **Domain Controllers (DCs)**, que son cruciales para la integridad de la confianza.

En un escenario típico, si un usuario desea acceder a un servicio en un **dominio confiable**, primero debe solicitar un ticket especial conocido como **inter-realm TGT** desde el DC de su propio dominio. Este TGT está cifrado con una **clave de confianza** compartida entre ambos dominios. El usuario presenta entonces este TGT al **DC del dominio confiable** para obtener un ticket de servicio (**TGS**). Tras la validación exitosa del inter-realm TGT por parte del DC del dominio confiable, este emite un TGS, otorgando al usuario acceso al servicio.

**Pasos**:

1. Una **máquina cliente** en **Domain 1** inicia el proceso usando su **NTLM hash** para solicitar un **Ticket Granting Ticket (TGT)** a su **Domain Controller (DC1)**.
2. DC1 emite un nuevo TGT si el cliente se autentica con éxito.
3. El cliente entonces solicita un **inter-realm TGT** a DC1, que es necesario para acceder a recursos en **Domain 2**.
4. El inter-realm TGT está cifrado con una **trust key** compartida entre DC1 y DC2 como parte de la confianza bidireccional entre dominios.
5. El cliente lleva el inter-realm TGT al **Domain Controller (DC2)** de **Domain 2**.
6. DC2 verifica el inter-realm TGT usando su clave de confianza compartida y, si es válido, emite un **Ticket Granting Service (TGS)** para el servidor en Domain 2 al que el cliente quiere acceder.
7. Finalmente, el cliente presenta este TGS al servidor, el cual está cifrado con el hash de la cuenta del servidor, para obtener acceso al servicio en Domain 2.

### Different trusts

Es importante notar que **una confianza puede ser unidireccional o bidireccional**. En la opción bidireccional, ambos dominios se confiarán mutuamente, pero en la relación de confianza **unidireccional** uno de los dominios será el **trusted** y el otro el **trusting**. En este último caso, **solo podrás acceder a recursos dentro del dominio trusting desde el trusted**.

Si Domain A confía en Domain B, A es el dominio trusting y B es el trusted. Además, en **Domain A**, esto sería una **Outbound trust**; y en **Domain B**, sería una **Inbound trust**.

**Diferentes relaciones de confianza**

- **Parent-Child Trusts**: Esta es una configuración común dentro del mismo bosque, donde un dominio hijo tiene automáticamente una confianza transitiva bidireccional con su dominio padre. Esencialmente, esto significa que las solicitudes de autenticación pueden fluir sin problemas entre el padre y el hijo.
- **Cross-link Trusts**: Conocidas como "shortcut trusts", se establecen entre dominios hijos para acelerar los procesos de referencia. En bosques complejos, las referencias de autenticación típicamente deben viajar hasta la raíz del bosque y luego bajar al dominio objetivo. Al crear cross-links, se acorta el recorrido, lo cual es especialmente útil en entornos geográficamente dispersos.
- **External Trusts**: Se configuran entre dominios diferentes y no relacionados y son no transitivos por naturaleza. Según la [documentación de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), las external trusts son útiles para acceder a recursos en un dominio fuera del bosque actual que no está conectado por una forest trust. La seguridad se refuerza mediante SID filtering con external trusts.
- **Tree-root Trusts**: Estas confianzas se establecen automáticamente entre el dominio raíz del bosque y una nueva tree root añadida. Aunque no son muy comunes, las tree-root trusts son importantes para añadir nuevos árboles de dominio a un bosque, permitiendo que mantengan un nombre de dominio único y asegurando transitividad bidireccional. Más información en la [guía de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Este tipo de trust es una confianza transitiva bidireccional entre dos dominios raíz de bosque, aplicando también SID filtering para mejorar la seguridad.
- **MIT Trusts**: Estas confianzas se establecen con dominios Kerberos no Windows que cumplen [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts son un poco más especializados y atienden entornos que requieren integración con sistemas basados en Kerberos fuera del ecosistema Windows.

#### Other differences in **trusting relationships**

- Una relación de confianza también puede ser **transitiva** (A confía en B, B confía en C, entonces A confía en C) o **no transitiva**.
- Una relación de confianza puede configurarse como **bidireccional** (ambos se confían mutuamente) o como **unidireccional** (solo uno confía en el otro).

### Attack Path

1. **Enumerar** las relaciones de confianza
2. Comprobar si algún **security principal** (user/group/computer) tiene **acceso** a recursos del **otro dominio**, quizá por entradas ACE o por pertenecer a grupos del otro dominio. Buscar **relaciones entre dominios** (probablemente la confianza se creó para esto).
1. kerberoast en este caso podría ser otra opción.
3. **Comprometer** las **cuentas** que pueden **pivotar** entre dominios.

Los atacantes podrían acceder a recursos en otro dominio mediante tres mecanismos principales:

- **Local Group Membership**: Principales que podrían agregarse a grupos locales en máquinas, como el grupo “Administrators” en un servidor, otorgándoles control significativo sobre esa máquina.
- **Foreign Domain Group Membership**: Principales que también pueden ser miembros de grupos dentro del dominio extranjero. Sin embargo, la efectividad de este método depende de la naturaleza de la confianza y del alcance del grupo.
- **Access Control Lists (ACLs)**: Principales que podrían estar especificados en una **ACL**, particularmente como entidades en **ACEs** dentro de una **DACL**, proporcionándoles acceso a recursos específicos. Para quienes quieran profundizar en la mecánica de ACLs, DACLs y ACEs, el whitepaper titulado “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” es un recurso invaluable.

### Find external users/groups with permissions

Puedes revisar **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** para encontrar foreign security principals en el dominio. Estos serán usuarios/grupos de **un dominio/bosque externo**.

Podrías comprobar esto en **Bloodhound** o usando powerview:
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
Otras formas de enumerar las relaciones de confianza entre dominios:
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
> Hay **2 trusted keys**, una para _Child --> Parent_ y otra para _Parent_ --> _Child_.\
> Puedes comprobar cuál usa el dominio actual con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalate as Enterprise admin to the child/parent domain abusing the trust with SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Entender cómo puede explotarse la Configuration Naming Context (NC) es crucial. La Configuration NC sirve como un repositorio central de datos de configuración a través de un forest en entornos Active Directory (AD). Estos datos se replican a todos los Domain Controller (DC) dentro del forest, y los writable DCs mantienen una copia escribible de la Configuration NC. Para explotarlo, se necesitan privilegios SYSTEM en un DC, preferiblemente un child DC.

**Link GPO to root DC site**

El contenedor Sites de la Configuration NC incluye información sobre los sites de todos los equipos unidos al dominio dentro del AD forest. Operando con privilegios SYSTEM en cualquier DC, un atacante puede link GPOs a los root DC sites. Esta acción potencialmente compromete el root domain manipulando las políticas aplicadas a esos sites.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vector de ataque implica dirigirse a gMSAs privilegiados dentro del domain. La KDS Root key, esencial para calcular las contraseñas de los gMSAs, está almacenada en la Configuration NC. Con privilegios SYSTEM en cualquier DC, es posible acceder a la KDS Root key y calcular las contraseñas de cualquier gMSA en todo el forest.

Un análisis detallado y una guía paso a paso pueden encontrarse en:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Este método requiere paciencia, esperar a la creación de nuevos objetos AD privilegiados. Con privilegios SYSTEM, un atacante puede modificar el AD Schema para conceder a cualquier usuario control completo sobre todas las clases. Esto podría derivar en acceso y control no autorizados sobre nuevos objetos AD.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnerabilidad ADCS ESC5 apunta a controlar objetos de Public Key Infrastructure (PKI) para crear una certificate template que permita autenticarse como cualquier usuario dentro del forest. Como los objetos PKI residen en la Configuration NC, comprometer un writable child DC permite ejecutar ataques ESC5.

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
En este escenario **tu dominio es confiado** por un dominio externo, lo que te otorga **permisos indeterminados** sobre él. Necesitarás encontrar **qué principales de tu dominio tienen qué acceso sobre el dominio externo** y luego intentar explotarlo:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Dominio de bosque externo - Unidireccional (Salida)
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
En este escenario **tu dominio** está **confiando** algunos **privilegios** a un principal de **un dominio diferente**.

Sin embargo, cuando un **dominio es confiado** por el dominio que confía, el dominio confiado **crea un usuario** con un **nombre predecible** que utiliza como **contraseña la contraseña confiada**. Lo que significa que es posible **acceder a un usuario del dominio que confía para entrar en el dominio confiado** para enumerarlo e intentar escalar más privilegios:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Otra forma de comprometer el dominio confiado es encontrar un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creado en la **dirección opuesta** de la confianza entre dominios (lo cual no es muy común).

Otra forma de comprometer el dominio confiado es esperar en una máquina a la que un **usuario del dominio confiado puede acceder** para iniciar sesión vía **RDP**. Entonces, el atacante podría inyectar código en el proceso de la sesión RDP y **acceder desde allí al dominio de origen de la víctima**.\
Además, si la **víctima montó su disco duro**, desde el proceso de la **sesión RDP** el atacante podría almacenar **backdoors** en la **carpeta de inicio del disco duro**. Esta técnica se llama **RDPInception.**

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigación del abuso de confianza entre dominios

### **Filtrado de SID:**

- El riesgo de ataques que aprovechan el atributo SID history a través de confianzas entre bosques se mitiga con el Filtrado de SID, que está activado por defecto en todas las confianzas entre bosques. Esto se basa en la suposición de que las confianzas intra-bosque son seguras, considerando el bosque, en lugar del dominio, como el límite de seguridad según la postura de Microsoft.
- Sin embargo, hay una trampa: el filtrado de SID puede interrumpir aplicaciones y el acceso de usuarios, lo que lleva a que a veces se desactive.

### **Autenticación selectiva:**

- Para las confianzas entre bosques, emplear la Autenticación Selectiva asegura que los usuarios de los dos bosques no sean autenticados automáticamente. En su lugar, se requieren permisos explícitos para que los usuarios accedan a dominios y servidores dentro del dominio o bosque que confía.
- Es importante notar que estas medidas no protegen contra la explotación del Configuration Naming Context (NC) escribible ni contra ataques a la cuenta de confianza.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algunas defensas generales

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Medidas defensivas para la protección de credenciales**

- **Domain Admins Restrictions**: Se recomienda que los Domain Admins solo puedan iniciar sesión en Domain Controllers, evitando su uso en otros hosts.
- **Service Account Privileges**: Los servicios no deberían ejecutarse con privilegios de Domain Admin (DA) para mantener la seguridad.
- **Temporal Privilege Limitation**: Para tareas que requieren privilegios DA, su duración debe ser limitada. Esto puede lograrse con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementación de técnicas de engaño**

- Implementar engaños implica colocar trampas, como usuarios o equipos señuelo, con características tales como contraseñas que no expiran o que están marcados como Trusted for Delegation. Un enfoque detallado incluye crear usuarios con derechos específicos o agregarlos a grupos de alto privilegio.
- Un ejemplo práctico implica usar herramientas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- More on deploying deception techniques can be found at [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificación de engaños**

- **For User Objects**: Indicadores sospechosos incluyen ObjectSID atípico, inicios de sesión poco frecuentes, fechas de creación y bajo recuento de contraseñas erróneas.
- **General Indicators**: Comparar atributos de posibles objetos señuelo con los de objetos genuinos puede revelar inconsistencias. Herramientas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) pueden ayudar a identificar tales engaños.

### **Evasión de sistemas de detección**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Evitar la enumeración de sesiones en Domain Controllers para prevenir la detección por ATA.
- **Ticket Impersonation**: Utilizar claves **aes** para la creación de tickets ayuda a evadir la detección al no degradar a NTLM.
- **DCSync Attacks**: Se recomienda ejecutar desde un equipo que no sea Domain Controller para evitar la detección por ATA, ya que la ejecución directa desde un Domain Controller disparará alertas.

## Referencias

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
