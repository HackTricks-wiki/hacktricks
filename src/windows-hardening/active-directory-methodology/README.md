# Metodología de Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Visión general básica

**Active Directory** sirve como una tecnología fundamental, permitiendo a los **administradores de red** crear y gestionar de forma eficiente **dominios**, **usuarios** y **objetos** dentro de una red. Está diseñado para escalar, facilitando la organización de un gran número de usuarios en **grupos** y **subgrupos** manejables, mientras controla los **derechos de acceso** en varios niveles.

La estructura de **Active Directory** se compone de tres capas principales: **dominios**, **árboles** y **bosques**. Un **dominio** abarca una colección de objetos, como **usuarios** o **dispositivos**, que comparten una base de datos común. Los **árboles** son grupos de estos dominios enlazados por una estructura compartida, y un **forest** representa la colección de múltiples árboles, interconectados mediante **relaciones de confianza**, formando la capa superior de la estructura organizativa. Se pueden designar **derechos de acceso** y **comunicación** específicos en cada uno de estos niveles.

Conceptos clave dentro de **Active Directory** incluyen:

1. **Directory** – Aloja toda la información relacionada con los objetos de Active Directory.
2. **Object** – Denota entidades dentro del directorio, incluidos **usuarios**, **grupos** o **carpetas compartidas**.
3. **Domain** – Sirve como un contenedor para los objetos del directorio, con la capacidad de que múltiples dominios coexistan dentro de un **forest**, cada uno manteniendo su propia colección de objetos.
4. **Tree** – Una agrupación de dominios que comparten un dominio raíz común.
5. **Forest** – La cúspide de la estructura organizativa en Active Directory, compuesta por varios trees con **relaciones de confianza** entre ellos.

**Active Directory Domain Services (AD DS)** abarca una serie de servicios críticos para la gestión centralizada y la comunicación dentro de una red. Estos servicios comprenden:

1. **Domain Services** – Centraliza el almacenamiento de datos y gestiona las interacciones entre **usuarios** y **dominios**, incluyendo **autenticación** y funcionalidades de **búsqueda**.
2. **Certificate Services** – Supervisa la creación, distribución y gestión de **certificados digitales** seguros.
3. **Lightweight Directory Services** – Da soporte a aplicaciones habilitadas para directorio a través del **protocolo LDAP**.
4. **Directory Federation Services** – Proporciona capacidades de **single-sign-on** para autenticar usuarios a través de múltiples aplicaciones web en una única sesión.
5. **Rights Management** – Ayuda a proteger material con derechos de autor regulando su distribución y uso no autorizados.
6. **DNS Service** – Crucial para la resolución de **nombres de dominio**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Autenticación Kerberos**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Hoja de referencia

Puedes usar [https://wadcoms.github.io/](https://wadcoms.github.io) para tener una vista rápida de qué comandos puedes ejecutar para enumerar/explotar un AD.

> [!WARNING]
> La comunicación Kerberos **requiere un nombre totalmente calificado (FQDN)** para realizar acciones. Si intentas acceder a una máquina por la dirección IP, **usará NTLM y no kerberos**.

## Recon Active Directory (Sin credenciales/sesiones)

Si solo tienes acceso a un entorno AD pero no tienes credenciales/sesiones podrías:

- **Pentest the network:**
- Escanear la red, encontrar máquinas y puertos abiertos e intentar **explotar vulnerabilidades** o **extraer credenciales** de ellas (por ejemplo, [printers could be very interesting targets](ad-information-in-printers.md)).
- La enumeración de DNS podría dar información sobre servidores clave en el dominio como web, impresoras, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Echa un vistazo a la guía general [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) para encontrar más información sobre cómo hacer esto.
- **Comprobar acceso null y Guest en servicios smb** (esto no funcionará en versiones modernas de Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Se puede encontrar una guía más detallada sobre cómo enumerar un servidor SMB aquí:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerar Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Se puede encontrar una guía más detallada sobre cómo enumerar LDAP aquí (presta **especial atención al acceso anónimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Envenenar la red**
- Recolectar credenciales **suplantando servicios con Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Acceder a hosts **abusando del relay attack** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Recolectar credenciales **exponiendo** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extraer nombres de usuario/nombres completos de documentos internos, redes sociales, servicios (principalmente web) dentro de los entornos de dominio y también de los disponibles públicamente.
- Si encuentras los nombres completos de empleados de la compañía, podrías probar diferentes convenciones de nombres de usuario de AD (**[read this](https://activedirectorypro.com/active-directory-user-naming-convention/)**). Las convenciones más comunes son: _NameSurname_, _Name.Surname_, _NamSur_ (3 letras de cada uno), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _letras aleatorias y 3 números aleatorios_ (abc123).
- Herramientas:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeración de usuarios

- **Anonymous SMB/LDAP enum:** Consulta las páginas de [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) y [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Cuando se solicita un **nombre de usuario inválido** el servidor responderá usando el código de error **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, lo que nos permite determinar que el nombre de usuario era inválido. Los **nombres de usuario válidos** provocarán bien el **TGT en un AS-REP** o el error _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando que al usuario se le requiere realizar pre-autenticación.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contra la interfaz MS-NRPC (Netlogon) en los domain controllers. El método llama a la función `DsrGetDcNameEx2` después de enlazar la interfaz MS-NRPC para comprobar si el usuario o equipo existe sin ninguna credencial. La herramienta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa este tipo de enumeración. La investigación puede encontrarse [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Si encuentras uno de estos servidores en la red, también puedes realizar **user enumeration against it**. Por ejemplo, podrías usar la herramienta [**MailSniper**](https://github.com/dafthack/MailSniper):
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

### Saber uno o varios nombres de usuario

Ok, entonces sabes que ya tienes un nombre de usuario válido pero ninguna contraseña... Entonces prueba:

- [**ASREPRoast**](asreproast.md): Si un usuario **no tiene** el atributo _DONT_REQ_PREAUTH_ puedes **solicitar un mensaje AS_REP** para ese usuario que contendrá algunos datos cifrados por una derivación de la contraseña del usuario.
- [**Password Spraying**](password-spraying.md): Probemos las contraseñas más **comunes** con cada uno de los usuarios descubiertos, quizá algún usuario esté usando una mala contraseña (¡ten en cuenta la política de contraseñas!).
- Ten en cuenta que también puedes **spray OWA servers** para intentar obtener acceso a los servidores de correo de los usuarios.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Podrías ser capaz de **obtener** algunos challenge hashes para crackear haciendo **poisoning** en algunos protocolos de la **red**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Si has logrado enumerar el active directory tendrás **más correos y una mejor comprensión de la red**. Podrías ser capaz de forzar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) para obtener acceso al entorno AD.

### Steal NTLM Creds

Si puedes **acceder a otros PCs o shares** con el **usuario null o guest** podrías **colocar archivos** (como un SCF file) que si de algún modo son accedidos **dispararán una autenticación NTLM contra ti** para que puedas **steal** el **NTLM challenge** para crackearlo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** trata cada NT hash que ya posees como una contraseña candidata para otros formatos más lentos cuyo material clave se deriva directamente del NT hash. En lugar de brute-forcear frases de contraseña largas en tickets Kerberos RC4, desafíos NetNTLM o credenciales en caché, alimentas los hashes NT en los modos NT-candidate de Hashcat y dejas que valide la reutilización de contraseñas sin llegar a conocer el texto claro. Esto es especialmente potente después de una compromisión de dominio donde puedes cosechar miles de NT hashes actuales e históricos.

Usa shucking cuando:

- Tienes un corpus NT obtenido por DCSync, volcados SAM/SECURITY o credenciales de vaults y necesitas probar reutilización en otros dominios/forests.
- Capturas material Kerberos basado en RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), respuestas NetNTLM o blobs DCC/DCC2.
- Quieres probar rápidamente reutilización para frases de contraseña largas e inquebrantables e inmediatamente pivotar vía Pass-the-Hash.

La técnica **no funciona** contra tipos de cifrado cuyos claves no son el NT hash (p. ej., Kerberos etype 17/18 AES). Si un dominio aplica solo AES, debes volver a los modos de contraseña regulares.

#### Building an NT hash corpus

- **DCSync/NTDS** – Use `secretsdump.py` with history to grab the largest possible set of NT hashes (and their previous values):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries dramatically widen the candidate pool because Microsoft can store up to 24 previous hashes per account. For more ways to harvest NTDS secrets see:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (or Mimikatz `lsadump::sam /patch`) extracts local SAM/SECURITY data and cached domain logons (DCC/DCC2). Deduplicate and append those hashes to the same `nt_candidates.txt` list.
- **Track metadata** – Keep the username/domain that produced each hash (even if the wordlist contains only hex). Matching hashes tell you immediately which principal is reusing a password once Hashcat prints the winning candidate.
- Prefer candidates from the same forest or a trusted forest; that maximizes the chance of overlap when shucking.

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

- NT-candidate inputs **must remain raw 32-hex NT hashes**. Disable rule engines (no `-r`, no hybrid modes) because mangling corrupts the candidate key material.
- These modes are not inherently faster, but the NTLM keyspace (~30,000 MH/s on an M3 Max) is ~100× quicker than Kerberos RC4 (~300 MH/s). Testing a curated NT list is far cheaper than exploring the entire password space in the slow format.
- Always run the **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) because modes 31500/31600/35300/35400 shipped recently.
- There is currently no NT mode for AS-REQ Pre-Auth, and AES etypes (19600/19700) require the plaintext password because their keys are derived via PBKDF2 from UTF-16LE passwords, not raw NT hashes.

#### Example – Kerberoast RC4 (mode 35300)

1. Capture an RC4 TGS for a target SPN with a low-privileged user (see the Kerberoast page for details):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Realiza el shucking del ticket con tu lista NT:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat deriva la clave RC4 de cada candidato NT y valida el `$krb5tgs$23$...` blob. Una coincidencia confirma que la cuenta de servicio usa uno de tus NT hashes existentes.

3. Pivot inmediatamente vía PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

You can optionally recover the plaintext later with `hashcat -m 1000 <matched_hash> wordlists/` if needed.

#### Example – Cached credentials (mode 31600)

1. Dump cached logons from a compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copy the DCC2 line for the interesting domain user into `dcc2_highpriv.txt` and shuck it:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. A successful match yields the NT hash already known in your list, proving that the cached user is reusing a password. Use it directly for PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) or brute-force it in fast NTLM mode to recover the string.

The exact same workflow applies to NetNTLM challenge-responses (`-m 27000/27100`) and DCC (`-m 31500`). Once a match is identified you can launch relay, SMB/WMI/WinRM PtH, or re-crack the NT hash with masks/rules offline.



## Enumeración de Active Directory CON credenciales/sesión

Para esta fase necesitas haber **comprometido las credenciales o una sesión de una cuenta de dominio válida.** Si tienes algunas credenciales válidas o un shell como usuario de dominio, **debes recordar que las opciones dadas antes siguen siendo opciones para comprometer a otros usuarios.**

Antes de empezar la enumeración autenticada deberías saber cuál es el **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeración

Haber comprometido una cuenta es un **gran paso para empezar a comprometer todo el dominio**, porque vas a poder iniciar la **Active Directory Enumeration:**

Respecto a [**ASREPRoast**](asreproast.md) ahora puedes encontrar todos los usuarios vulnerables posibles, y respecto a [**Password Spraying**](password-spraying.md) puedes obtener una **lista de todos los nombres de usuario** e intentar la contraseña de la cuenta comprometida, contraseñas vacías y nuevas contraseñas prometedoras.

- Podrías usar el [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- También puedes usar [**powershell for recon**](../basic-powershell-for-pentesters/index.html) que será más sigiloso
- También puedes [**use powerview**](../basic-powershell-for-pentesters/powerview.md) para extraer información más detallada
- Otra herramienta increíble para recon en un active directory es [**BloodHound**](bloodhound.md). No es **muy sigilosa** (dependiendo de los métodos de colección que uses), pero **si no te importa** eso, deberías probarla. Encuentra dónde los usuarios pueden RDP, encuentra caminos hacia otros grupos, etc.
- **Otras herramientas automatizadas de enumeración AD son:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) ya que pueden contener información interesante.
- Una **herramienta con GUI** que puedes usar para enumerar el directorio es **AdExplorer.exe** de la suite **SysInternal**.
- También puedes buscar en la base de datos LDAP con **ldapsearch** para buscar credenciales en los campos _userPassword_ & _unixUserPassword_, o incluso en _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para otros métodos.
- Si usas **Linux**, también podrías enumerar el dominio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- También podrías probar herramientas automatizadas como:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracción de todos los usuarios del dominio**

Es muy fácil obtener todos los nombres de usuario del dominio desde Windows (`net user /domain` ,`Get-DomainUser` o `wmic useraccount get name,sid`). En Linux, puedes usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Incluso si esta sección de Enumeración parece pequeña, es la parte más importante de todas. Accede a los enlaces (principalmente los de cmd, powershell, powerview y BloodHound), aprende a enumerar un dominio y practica hasta sentirte cómodo. Durante una evaluación, este será el momento clave para encontrar tu camino hacia DA o decidir que no se puede hacer nada.

### Kerberoast

Kerberoasting consiste en obtener **TGS tickets** usados por servicios vinculados a cuentas de usuario y crackear su cifrado —que se basa en las contraseñas de usuario— **offline**.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Conexión remota (RDP, SSH, FTP, Win-RM, etc)

Una vez que hayas obtenido algunas credenciales podrías comprobar si tienes acceso a alguna **máquina**. Para ello, podrías usar **CrackMapExec** para intentar conectarte a varios servidores con diferentes protocolos, según tus escaneos de puertos.

### Escalada de privilegios local

Si has comprometido credenciales o una sesión como usuario de dominio normal y tienes **acceso** con ese usuario a **cualquier máquina en el dominio** deberías intentar encontrar la forma de **escalar privilegios localmente y buscar credenciales**. Esto es porque solo con privilegios de administrador local podrás **volcar hashes de otros usuarios** en memoria (LSASS) y localmente (SAM).

Hay una página completa en este libro sobre [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) y una [**checklist**](../checklist-windows-privilege-escalation.md). Además, no olvides usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets de la sesión actual

Es muy **improbable** que encuentres **tickets** en el usuario actual que te den **permiso para acceder** a recursos inesperados, pero podrías comprobar:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Si has logrado enumerar Active Directory tendrás **más correos electrónicos y una mejor comprensión de la red**. Podrías ser capaz de forzar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Ahora que tienes algunas credenciales básicas deberías comprobar si puedes **encontrar** archivos **interesantes compartidos dentro del AD**. Podrías hacerlo manualmente pero es una tarea muy aburrida y repetitiva (y más si encuentras cientos de documentos que necesitas revisar).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Si puedes **acceder a otros PCs o shares** podrías **colocar archivos** (como un SCF file) que si de alguna forma son accedidos **trigger an NTLM authentication against you** para que puedas **steal** el **NTLM challenge** y crackearlo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Esta vulnerabilidad permitió a cualquier usuario autenticado **comprometer el controlador de dominio**.


{{#ref}}
printnightmare.md
{{#endref}}

## Escalada de privilegios en Active Directory CON credenciales/sesión privilegiada

**Para las siguientes técnicas un usuario de dominio regular no es suficiente; necesitas algunos privilegios/credenciales especiales para realizar estos ataques.**

### Extracción de hashes

Con suerte has logrado **comprometer alguna cuenta local admin** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).  
Entonces, es momento de volcar todos los hashes en memoria y localmente.  
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una vez que tengas el hash de un usuario**, puedes usarlo para **suplantarlo**.  
Necesitas usar alguna **herramienta** que **realice** la **autenticación NTLM usando** ese **hash**, **o** podrías crear un nuevo **sessionlogon** e **inyectar** ese **hash** dentro de **LSASS**, de modo que cuando se realice cualquier **autenticación NTLM**, ese **hash será usado.** La última opción es lo que hace mimikatz.  
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque tiene como objetivo **usar el hash NTLM del usuario para solicitar tickets de Kerberos**, como alternativa al común Pass The Hash sobre el protocolo NTLM. Por lo tanto, esto puede ser especialmente **útil en redes donde el protocolo NTLM está deshabilitado** y solo **Kerberos está permitido** como protocolo de autenticación.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

En el método de ataque **Pass The Ticket (PTT)**, los atacantes **roban el ticket de autenticación de un usuario** en lugar de su contraseña o valores hash. Este ticket robado se usa entonces para **suplantar al usuario**, obteniendo acceso no autorizado a recursos y servicios dentro de una red.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Si tienes el **hash** o la **contraseña** de un **administrador local** deberías intentar **iniciar sesión localmente** en otros **PCs** con ella.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Ten en cuenta que esto es bastante **ruidoso** y **LAPS** lo **mitigaría**.

### Abuso de MSSQL y enlaces de confianza

Si un usuario tiene privilegios para **access MSSQL instances**, podría usarlo para **execute commands** en el host MSSQL (si se ejecuta como SA), **steal** el NetNTLM **hash** o incluso realizar un **relay** **attack**.\
Además, si una instancia MSSQL es trusted (database link) por otra instancia MSSQL. Si el usuario tiene privilegios sobre la base de datos confiada, podrá **usar la relación de confianza para ejecutar consultas también en la otra instancia**. Estas trusts pueden encadenarse y en algún punto el usuario podría encontrar una base de datos mal configurada donde pueda ejecutar comandos.\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuso de plataformas de inventario y despliegue de TI

Las soluciones de inventario y despliegue de terceros a menudo exponen vías poderosas hacia credenciales y ejecución de código. Ver:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Delegación sin restricciones

Si encuentras cualquier objeto Computer con el atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) y tienes privilegios de dominio en el equipo, podrás volcar los TGTs desde la memoria de todos los usuarios que inicien sesión en el equipo.\
Así que, si un **Domain Admin logins onto the computer**, podrás volcar su TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Gracias a constrained delegation podrías incluso **automáticamente comprometer un Print Server** (esperemos que sea un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Delegación restringida

Si a un usuario o equipo se le permite "Constrained Delegation" podrá **impersonar a cualquier usuario para acceder a algunos servicios en un equipo**.\
Entonces, si **comprometes el hash** de este usuario/equipo podrás **impersonar a cualquier usuario** (incluso domain admins) para acceder a ciertos servicios.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Delegación restringida basada en recursos

Tener privilegio de **WRITE** sobre un objeto de Active Directory de un equipo remoto permite obtener ejecución de código con **privilegios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuso de Permisos/ACLs

El usuario comprometido podría tener algunos **privilegios interesantes sobre ciertos objetos del dominio** que podrían permitirte **moverte** lateralmente/**escalar** privilegios.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuso del servicio Printer Spooler

Descubrir un **Spool service listening** dentro del dominio puede ser **abusado** para **adquirir nuevas credenciales** y **escalar privilegios**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuso de sesiones de terceros

Si **otros usuarios** **access** la máquina **comprometida**, es posible **gather credentials from memory** e incluso **inject beacons in their processes** para suplantarlos.\
Usualmente los usuarios accederán al sistema vía RDP, así que aquí tienes cómo realizar un par de ataques sobre sesiones RDP de terceros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** proporciona un sistema para gestionar la **local Administrator password** en equipos unidos al dominio, asegurando que esté **randomized**, sea única y se **changed** frecuentemente. Estas contraseñas se almacenan en Active Directory y el acceso se controla mediante ACLs sólo a usuarios autorizados. Con permisos suficientes para acceder a estas contraseñas, es posible pivotar a otros equipos.


{{#ref}}
laps.md
{{#endref}}

### Robo de certificados

**Gathering certificates** desde la máquina comprometida podría ser una forma de escalar privilegios dentro del entorno:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuso de plantillas de certificados

Si se configuran **vulnerable templates** es posible abusar de ellas para escalar privilegios:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-explotación con cuenta de alto privilegio

### Volcado de credenciales de dominio

Una vez que obtengas privilegios de **Domain Admin** o, mejor aún, **Enterprise Admin**, puedes **dump** la **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

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

El ataque **Silver Ticket** crea un **legítimo Ticket Granting Service (TGS) ticket** para un servicio específico usando el **NTLM hash** (por ejemplo, el **hash de la cuenta del equipo**). Este método se emplea para **acceder a los privilegios del servicio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un **Golden Ticket attack** implica que un atacante obtenga acceso al **NTLM hash de la cuenta krbtgt** en un entorno Active Directory (AD). Esta cuenta es especial porque se usa para firmar todos los **Ticket Granting Tickets (TGTs)**, que son esenciales para la autenticación dentro de la red AD.

Una vez que el atacante obtiene este hash, puede crear **TGTs** para cualquier cuenta que elija (ataque Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Son como golden tickets forjados de una manera que **evita los mecanismos comunes de detección de golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistencia de cuenta mediante certificados**

**Tener certificados de una cuenta o poder solicitarlos** es una muy buena forma de persistir en la cuenta del usuario (incluso si cambia la contraseña):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistencia en el dominio mediante certificados**

**Usar certificados también permite persistir con altos privilegios dentro del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Grupo AdminSDHolder

El objeto **AdminSDHolder** en Active Directory asegura la protección de los **grupos privilegiados** (como Domain Admins y Enterprise Admins) aplicando una **Access Control List (ACL)** estándar sobre estos grupos para prevenir cambios no autorizados. Sin embargo, esta funcionalidad puede ser explotada; si un atacante modifica la ACL del AdminSDHolder para dar acceso completo a un usuario normal, ese usuario obtiene un control extenso sobre todos los grupos privilegiados. Esta medida de seguridad, diseñada para proteger, puede volverse contraproducente y permitir acceso indebido a menos que se supervise de cerca.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Credenciales DSRM

Dentro de cada **Domain Controller (DC)** existe una cuenta de **administrador local**. Al obtener permisos de administrador en dicha máquina, el hash del Administrator local puede extraerse usando **mimikatz**. Tras esto, es necesario modificar el registro para **habilitar el uso de esta contraseña**, permitiendo el acceso remoto a la cuenta de Administrator local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Persistencia vía ACL

Podrías **dar** algunos **permisos especiales** a un **usuario** sobre objetos específicos del dominio que le permitan **escalar privilegios en el futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Descriptores de seguridad

Los **security descriptors** se usan para **almacenar** los **permisos** que un **objeto** tiene **sobre** otro **objeto**. Si puedes hacer solo un **pequeño cambio** en el **security descriptor** de un objeto, puedes obtener privilegios muy interesantes sobre ese objeto sin necesitar ser miembro de un grupo privilegiado.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Alterar **LSASS** en memoria para establecer una **contraseña universal**, otorgando acceso a todas las cuentas del dominio.


{{#ref}}
skeleton-key.md
{{#endref}}

### SSP personalizado

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puedes crear tu **propio SSP** para **capturar** en **clear text** las **credenciales** usadas para acceder a la máquina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra un **nuevo Domain Controller** en el AD y lo usa para **push attributes** (SIDHistory, SPNs...) en objetos especificados **sin** dejar registros sobre las **modificaciones**. Necesitas privilegios DA y estar dentro del **root domain**.\
Nota que si usas datos incorrectos, aparecerán logs bastante feos.


{{#ref}}
dcshadow.md
{{#endref}}

### Persistencia con LAPS

Anteriormente discutimos cómo escalar privilegios si tienes **suficiente permiso para leer LAPS passwords**. Sin embargo, estas contraseñas también pueden usarse para **mantener persistencia**.\
Consulta:


{{#ref}}
laps.md
{{#endref}}

## Escalada de privilegios en Forest - Confianzas de dominio

Microsoft considera el **Forest** como el límite de seguridad. Esto implica que **comprometer un solo dominio podría potencialmente llevar a que todo el Forest sea comprometido**.

### Información básica

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) es un mecanismo de seguridad que permite a un usuario de un **dominio** acceder a recursos en otro **dominio**. Esencialmente crea un vínculo entre los sistemas de autenticación de ambos dominios, permitiendo que las verificaciones de autenticación fluyan sin problemas. Cuando los dominios establecen una trust, intercambian y retienen ciertas **keys** dentro de sus **Domain Controllers (DCs)**, que son cruciales para la integridad de la trust.

En un escenario típico, si un usuario pretende acceder a un servicio en un **dominio confiable**, primero debe solicitar un ticket especial conocido como **inter-realm TGT** desde el DC de su propio dominio. Este TGT se cifra con una **trust key** que ambos dominios comparten. Luego el usuario presenta este TGT al **DC del dominio confiable** para obtener un ticket de servicio (**TGS**). Tras la validación del inter-realm TGT por el DC del dominio confiable, este emite un TGS, otorgando al usuario acceso al servicio.

**Pasos**:

1. Un **cliente** en el **Dominio 1** inicia el proceso usando su **NTLM hash** para solicitar un **Ticket Granting Ticket (TGT)** a su **Domain Controller (DC1)**.
2. DC1 emite un nuevo TGT si el cliente se autentica correctamente.
3. El cliente solicita un **inter-realm TGT** a DC1, que se necesita para acceder a recursos en el **Dominio 2**.
4. El inter-realm TGT se cifra con una **trust key** compartida entre DC1 y DC2 como parte de la trust bidireccional.
5. El cliente lleva el inter-realm TGT al **Domain Controller (DC2)** del **Dominio 2**.
6. DC2 verifica el inter-realm TGT usando su trust key compartida y, si es válido, emite un **Ticket Granting Service (TGS)** para el servidor en el Dominio 2 al que el cliente quiere acceder.
7. Finalmente, el cliente presenta este TGS al servidor, que está cifrado con el hash de la cuenta del servidor, para obtener acceso al servicio en el Dominio 2.

### Diferentes trusts

Es importante notar que **una trust puede ser de 1 vía o de 2 vías**. En la opción de 2 vías, ambos dominios se confiarán mutuamente, pero en la relación de confianza **de 1 vía** uno de los dominios será el **trusted** y el otro el **trusting**. En este último caso, **solo podrás acceder a recursos dentro del trusting domain desde el trusted**.

Si Domain A confía en Domain B, A es el trusting domain y B es el trusted. Además, en **Domain A**, esto sería una **Outbound trust**; y en **Domain B**, esto sería una **Inbound trust**.

**Diferentes relaciones de confianza**

- **Parent-Child Trusts**: Esta es una configuración común dentro del mismo forest, donde un dominio hijo automáticamente tiene una confianza transitiva bidireccional con su dominio padre. Esencialmente, esto significa que las solicitudes de autenticación pueden fluir sin problemas entre el padre y el hijo.
- **Cross-link Trusts**: Conocidas como "shortcut trusts", se establecen entre dominios hijo para acelerar los procesos de referencia. En forests complejos, las referencias de autenticación típicamente tienen que viajar hasta la raíz del forest y luego bajar al dominio objetivo. Al crear cross-links se acorta el trayecto, lo cual es especialmente útil en entornos geográficamente dispersos.
- **External Trusts**: Se configuran entre dominios diferentes y no relacionados y son no transitivas por naturaleza. Según la documentación de Microsoft, las external trusts son útiles para acceder a recursos en un dominio fuera del forest actual que no esté conectado por una forest trust. La seguridad se refuerza mediante SID filtering con external trusts.
- **Tree-root Trusts**: Estas trusts se establecen automáticamente entre el root domain del forest y una nueva tree root añadida. Aunque no son comunes, las tree-root trusts son importantes para agregar nuevos domain trees a un forest, permitiéndoles mantener un nombre de dominio único y asegurando transitividad bidireccional.
- **Forest Trusts**: Este tipo de trust es una trust transitiva bidireccional entre dos forest root domains, también aplicando SID filtering para mejorar las medidas de seguridad.
- **MIT Trusts**: Estas trusts se establecen con dominios Kerberos no-Windows compatibles con [RFC4120](https://tools.ietf.org/html/rfc4120). Las MIT trusts son algo más especializadas y atienden a entornos que requieren integración con sistemas basados en Kerberos fuera del ecosistema Windows.

#### Otras diferencias en las **relaciones de confianza**

- Una relación de confianza también puede ser **transitiva** (A confía en B, B confía en C, entonces A confía en C) o **no transitiva**.
- Una relación de confianza puede configurarse como **bidireccional** (ambos se confían mutuamente) o como **unidireccional** (solo uno confía en el otro).

### Camino de ataque

1. **Enumerar** las relaciones de confianza
2. Comprobar si algún **security principal** (usuario/grupo/computadora) tiene **acceso** a recursos del **otro dominio**, quizá mediante entradas ACE o por pertenecer a grupos del otro dominio. Buscar **relaciones a través de dominios** (probablemente la trust fue creada para esto).
3. kerberoast en este caso podría ser otra opción.
4. **Comprometer** las **cuentas** que puedan **pivotar** entre dominios.

Los atacantes podrían acceder a recursos en otro dominio mediante tres mecanismos principales:

- **Local Group Membership**: Principales de seguridad podrían ser añadidos a grupos locales en máquinas, como el grupo “Administrators” en un servidor, otorgándoles control significativo sobre esa máquina.
- **Foreign Domain Group Membership**: Los principales también pueden ser miembros de grupos dentro del dominio extranjero. Sin embargo, la efectividad de este método depende de la naturaleza de la trust y del alcance del grupo.
- **Access Control Lists (ACLs)**: Los principales podrían estar especificados en una **ACL**, particularmente como entidades en **ACEs** dentro de una **DACL**, proporcionándoles acceso a recursos específicos. Para aquellos que quieran profundizar en la mecánica de ACLs, DACLs y ACEs, el whitepaper titulado “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” es un recurso invaluable.

### Encontrar usuarios/grupos externos con permisos

Puedes comprobar `CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com` para encontrar foreign security principals en el dominio. Estos serán usuarios/grupos de **un dominio/forest externo**.

Puedes comprobar esto con **Bloodhound** o usando powerview:
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
> Puedes identificar la que usa el dominio actual con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalar como Enterprise admin al child/parent domain abusando del trust con SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Entender cómo se puede explotar el Configuration Naming Context (NC) es crucial. El Configuration NC sirve como un repositorio central para los datos de configuración a lo largo de un bosque en entornos de Active Directory (AD). Estos datos se replican a cada Domain Controller (DC) dentro del bosque, y los DCs escribibles mantienen una copia escribible del Configuration NC. Para explotarlo, se necesita tener privilegios **SYSTEM en un DC**, preferiblemente un DC hijo.

**Link GPO to root DC site**

El contenedor Sites del Configuration NC incluye información sobre los sitios de todos los equipos unidos al dominio dentro del bosque de AD. Operando con privilegios SYSTEM en cualquier DC, los atacantes pueden vincular GPOs a los sitios root DC. Esta acción puede comprometer potencialmente el dominio raíz al manipular las políticas aplicadas a esos sitios.

Para información detallada, puede consultarse la investigación sobre [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vector de ataque consiste en apuntar a gMSAs privilegiadas dentro del dominio. La KDS Root key, esencial para calcular las contraseñas de las gMSAs, se almacena dentro del Configuration NC. Con privilegios SYSTEM en cualquier DC, es posible acceder a la KDS Root key y calcular las contraseñas de cualquier gMSA en todo el bosque.

El análisis detallado y la guía paso a paso pueden encontrarse en:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ataque complementario delegado a MSA (BadSuccessor – abusando de atributos de migración):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Investigación externa adicional: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Este método requiere paciencia, esperando la creación de nuevos objetos AD privilegiados. Con privilegios SYSTEM, un atacante puede modificar el AD Schema para otorgar a cualquier usuario control total sobre todas las clases. Esto podría derivar en acceso y control no autorizados sobre los nuevos objetos AD creados.

Más información en [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnerabilidad ADCS ESC5 apunta al control sobre objetos de Public Key Infrastructure (PKI) para crear una plantilla de certificado que permita autenticarse como cualquier usuario dentro del bosque. Dado que los objetos PKI residen en el Configuration NC, comprometer un DC hijo escribible permite ejecutar ataques ESC5.

Más detalles pueden leerse en [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). En escenarios sin ADCS, el atacante tiene la capacidad de configurar los componentes necesarios, como se discute en [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
En este escenario **tu dominio es confiado** por uno externo que te otorga **permisos indeterminados** sobre él. Necesitarás averiguar **qué principals de tu dominio tienen qué acceso sobre el dominio externo** y luego intentar explotarlo:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Dominio forestal externo - Unidireccional (Outbound)
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
En este escenario **your domain** está **trusting** algunos **privileges** a un principal de **different domains**.

Sin embargo, cuando un **domain is trusted** por el dominio que confía, el dominio confiado **creates a user** con un **predictable name** que usa como **password the trusted password**. Lo cual significa que es posible **access a user from the trusting domain to get inside the trusted one** para enumerarlo e intentar escalar más privilegios:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Otra manera de comprometer el dominio confiado es encontrar un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creado en la **opposite direction** de la confianza de dominio (lo cual no es muy común).

Otra forma de comprometer el dominio confiado es quedarse en una máquina donde un **user from the trusted domain can access** para iniciar sesión vía **RDP**. Entonces, el atacante podría inyectar código en el proceso de la sesión RDP y **access the origin domain of the victim** desde ahí.\
Además, si el **victim mounted his hard drive**, desde el proceso de la **RDP session** el atacante podría almacenar **backdoors** en la **startup folder of the hard drive**. Esta técnica se llama **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- El riesgo de ataques que aprovechan el atributo SID history a través de forest trusts se mitiga con SID Filtering, que está activado por defecto en todas las inter-forest trusts. Esto se basa en la suposición de que las intra-forest trusts son seguras, considerando el bosque, en lugar del dominio, como el límite de seguridad según la postura de Microsoft.
- Sin embargo, hay un inconveniente: SID filtering puede interrumpir aplicaciones y el acceso de usuarios, lo que lleva a su desactivación ocasional.

### **Selective Authentication:**

- Para inter-forest trusts, emplear Selective Authentication asegura que los usuarios de los dos bosques no se autentiquen automáticamente. En su lugar, se requieren permisos explícitos para que los usuarios accedan a dominios y servidores dentro del dominio o bosque que confía.
- Es importante notar que estas medidas no protegen frente a la explotación del writable Configuration Naming Context (NC) ni contra ataques a la trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Abuso de AD basado en LDAP desde On-Host Implants

La [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implementa las primitivas LDAP estilo bloodyAD como x64 Beacon Object Files que se ejecutan enteramente dentro de un on-host implant (por ejemplo, Adaptix C2). Los operadores compilan el paquete con `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, cargan `ldap.axs`, y luego llaman `ldap <subcommand>` desde el beacon. Todo el tráfico viaja con el contexto de seguridad del logon actual sobre LDAP (389) con signing/sealing o LDAPS (636) con confianza automática de certificados, por lo que no se requieren proxies socks ni artefactos en disco.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` resuelven nombres cortos/rutas de OU en DNs completos y vuelcan los objetos correspondientes.
- `get-object`, `get-attribute`, and `get-domaininfo` extraen atributos arbitrarios (incluyendo security descriptors) además de los metadatos del forest/dominio desde `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` exponen candidatos para roasting, configuración de delegación, y descriptores existentes de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) directamente desde LDAP.
- `get-acl` and `get-writable --detailed` analizan la DACL para listar trustees, derechos (GenericAll/WriteDACL/WriteOwner/attribute writes) y herencia, dando objetivos inmediatos para escalada de privilegios mediante ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitivas LDAP de escritura para escalada y persistencia

- Los BOFs de creación de objetos (`add-user`, `add-computer`, `add-group`, `add-ou`) permiten al operador preparar nuevos principals o cuentas de máquina donde exista derecho sobre OUs. `add-groupmember`, `set-password`, `add-attribute`, y `set-attribute` secuestran directamente objetivos una vez que se encuentran derechos de write-property.
- Comandos enfocados en ACL como `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, y `add-dcsync` traducen WriteDACL/WriteOwner en cualquier objeto AD a restablecimientos de contraseña, control de membresía de grupos, o privilegios DCSync sin dejar artefactos de PowerShell/ADSI. Los homólogos `remove-*` limpian los ACEs inyectados.

### Delegación, roasting, y abuso de Kerberos

- `add-spn`/`set-spn` hacen instantáneamente a un usuario comprometido Kerberoastable; `add-asreproastable` (toggle UAC) lo marca para AS-REP roasting sin tocar la contraseña.
- Macros de delegación (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) reescriben `msDS-AllowedToDelegateTo`, UAC flags, o `msDS-AllowedToActOnBehalfOfOtherIdentity` desde el beacon, habilitando rutas de ataque constrained/unconstrained/RBCD y eliminando la necesidad de PowerShell remoto o RSAT.

### Inyección de sidHistory, reubicación de OU y modelado de la superficie de ataque

- `add-sidhistory` inyecta SIDs privilegiados en el SID history de un principal controlado (ver [SID-History Injection](sid-history-injection.md)), proporcionando herencia de acceso sigilosa completamente vía LDAP/LDAPS.
- `move-object` cambia el DN/OU de equipos o usuarios, permitiendo a un atacante arrastrar activos a OUs donde ya existen derechos delegados antes de abusar de `set-password`, `add-groupmember`, o `add-spn`.
- Comandos de eliminación de alcance estrecho (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permiten una rápida reversión después de que el operador coseche credenciales o persistencia, minimizando la telemetría.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algunas defensas generales

[**Aprende más sobre cómo proteger las credenciales aquí.**](../stealing-credentials/credentials-protections.md)

### **Medidas defensivas para la protección de credenciales**

- **Domain Admins Restrictions**: Se recomienda que Domain Admins solo puedan iniciar sesión en Domain Controllers, evitando su uso en otros hosts.
- **Service Account Privileges**: Los servicios no deberían ejecutarse con privilegios Domain Admin (DA) para mantener la seguridad.
- **Temporal Privilege Limitation**: Para tareas que requieren privilegios DA, su duración debe limitarse. Esto puede lograrse con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Auditar Event IDs 2889/3074/3075 y luego aplicar LDAP signing más LDAPS channel binding en DCs/clients para bloquear intentos de LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementación de técnicas de engaño**

- La implementación de engaños implica colocar trampas, como usuarios o equipos señuelo, con características como contraseñas que no expiran o que están marcados como Trusted for Delegation. Un enfoque detallado incluye crear usuarios con derechos específicos o añadirlos a grupos de alto privilegio.
- Un ejemplo práctico implica usar herramientas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Más sobre desplegar técnicas de engaño en [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificando engaños**

- **Para objetos de usuario**: Indicadores sospechosos incluyen ObjectSID atípico, inicios de sesión infrecuentes, fechas de creación y bajo recuento de contraseñas incorrectas.
- **Indicadores generales**: Comparar atributos de objetos señuelo potenciales con los de los genuinos puede revelar inconsistencias. Herramientas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) pueden ayudar a identificar tales engaños.

### **Evasión de sistemas de detección**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Evitar la enumeración de sesiones en Domain Controllers para prevenir la detección por ATA.
- **Ticket Impersonation**: Utilizar claves **aes** para la creación de tickets ayuda a evadir la detección al no degradar a NTLM.
- **DCSync Attacks**: Se recomienda ejecutar desde un host que no sea Domain Controller para evitar la detección por ATA, ya que la ejecución directa desde un Domain Controller disparará alertas.

## Referencias

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
