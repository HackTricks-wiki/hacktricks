# Técnicas Anti-Forensic

## Marcas de tiempo

Un atacante puede estar interesado en **cambiar las marcas de tiempo de los archivos** para evitar ser detectado.\
Es posible encontrar las marcas de tiempo dentro de la MFT, en los atributos `$STANDARD_INFORMATION` \_\_ y \_\_ `$FILE_NAME`.

Ambos atributos tienen 4 marcas de tiempo: **modificación**, **acceso**, **creación** y **modificación del registro MFT** (MACE o MACB).

**Windows explorer** y otras herramientas muestran la información de **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensic Tool

Esta herramienta **modifica** la información de las marcas de tiempo dentro de **`$STANDARD_INFORMATION`**, **pero no** la información dentro de **`$FILE_NAME`**. Por lo tanto, es posible **identificar** actividad **sospechosa**.

### Usnjrnl

El **USN Journal** (Update Sequence Number Journal) es una función de NTFS (Windows NT file system) que realiza un seguimiento de los cambios del volumen. La herramienta [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) permite examinar estos cambios.

![TimeStomp - Anti-forensic Tool - Usnjrnl: El USN Journal (Update Sequence Number Journal) es una función de NTFS (Windows NT file system) que realiza un seguimiento de los cambios del volumen. La...](<../../images/image (801).png>)

La imagen anterior muestra la **salida** de la **herramienta**, donde se puede observar que se **realizaron algunos cambios** en el archivo.

### $LogFile

**Todos los cambios de metadatos en un sistema de archivos se registran** en un proceso conocido como [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Los metadatos registrados se almacenan en un archivo llamado `**$LogFile**`, ubicado en el directorio raíz de un sistema de archivos NTFS. Se pueden utilizar herramientas como [LogFileParser](https://github.com/jschicht/LogFileParser) para analizar este archivo e identificar cambios.

![Usnjrnl - $LogFile: Todos los cambios de metadatos en un sistema de archivos se registran en un proceso conocido como write-ahead logging. Los metadatos registrados se almacenan en un archivo llamado $LogFile, ubicado en el directorio raíz...](<../../images/image (137).png>)

Nuevamente, en la salida de la herramienta es posible observar que **se realizaron algunos cambios**.

Utilizando la misma herramienta es posible identificar **a qué hora se modificaron las marcas de tiempo**:

![Usnjrnl - $LogFile: Utilizando la misma herramienta es posible identificar a qué hora se modificaron las marcas de tiempo](<../../images/image (1089).png>)

- CTIME: Hora de creación del archivo
- ATIME: Hora de modificación del archivo
- MTIME: Modificación del registro MFT del archivo
- RTIME: Hora de acceso del archivo

### Comparación de `$STANDARD_INFORMATION` y `$FILE_NAME`

Otra forma de identificar archivos modificados sospechosos sería comparar la hora de ambos atributos en busca de **incoherencias**.

### Nanosegundos

Las marcas de tiempo de **NTFS** tienen una **precisión** de **100 nanosegundos**. Por lo tanto, encontrar archivos con marcas de tiempo como 2010-10-10 10:10:**00.000:0000 es muy sospechoso**.

### SetMace - Anti-forensic Tool

Esta herramienta puede modificar ambos atributos `$STARNDAR_INFORMATION` y `$FILE_NAME`. Sin embargo, desde Windows Vista, es necesario que un live OS modifique esta información.

## Ocultación de datos

NFTS utiliza un clúster y el tamaño mínimo de información. Esto significa que, si un archivo ocupa un clúster y medio, **la mitad restante nunca se utilizará** hasta que se elimine el archivo. Por lo tanto, es posible **ocultar datos en este slack space**.

Existen herramientas como slacker que permiten ocultar datos en este espacio "oculto". Sin embargo, un análisis de `$logfile` y `$usnjrnl` puede mostrar que se añadieron algunos datos:

![SetMace - Anti-forensic Tool - Ocultación de datos: Existen herramientas como slacker que permiten ocultar datos en este espacio "oculto". Sin embargo, un análisis de $logfile y $usnjrnl puede mostrar que...](<../../images/image (1060).png>)

Después, es posible recuperar el slack space utilizando herramientas como FTK Imager. Ten en cuenta que este tipo de herramientas puede guardar el contenido ofuscado o incluso cifrado.

## UsbKill

Esta es una herramienta que **apagará el equipo si detecta cualquier cambio en los puertos USB**.\
Una forma de descubrirlo sería inspeccionar los procesos en ejecución y **revisar cada script de Python en ejecución**.

## Live Linux Distributions

Estas distros se **ejecutan dentro de la memoria RAM**. La única forma de detectarlas es **si el sistema de archivos NTFS está montado con permisos de escritura**. Si se monta únicamente con permisos de lectura, no será posible detectar la intrusión.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Configuración de Windows

Es posible deshabilitar varios métodos de logging de Windows para dificultar mucho la investigación forense.

### Deshabilitar marcas de tiempo - UserAssist

Esta es una clave del registro que mantiene las fechas y horas en las que el usuario ejecutó cada archivo ejecutable.

Deshabilitar UserAssist requiere dos pasos:

1. Establecer las dos claves del registro, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` y `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, ambas a cero para indicar que queremos deshabilitar UserAssist.
2. Limpiar los subárboles del registro que tengan un aspecto como `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Deshabilitar marcas de tiempo - Prefetch

Esto guarda información sobre las aplicaciones ejecutadas con el objetivo de mejorar el rendimiento del sistema Windows. Sin embargo, también puede ser útil para las prácticas forenses.

- Ejecuta `regedit`
- Selecciona la ruta de archivo `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Haz clic derecho en `EnablePrefetcher` y `EnableSuperfetch`
- Selecciona Modify en cada una para cambiar el valor de 1 (o 3) a 0
- Reinicia

### Deshabilitar marcas de tiempo - Hora del último acceso

Cada vez que se abre una carpeta desde un volumen NTFS en un servidor Windows NT, el sistema registra la hora para **actualizar un campo de marca de tiempo en cada carpeta listada**, denominado hora del último acceso. En un volumen NTFS muy utilizado, esto puede afectar al rendimiento.

1. Abre el Registry Editor (Regedit.exe).
2. Ve a `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Busca `NtfsDisableLastAccessUpdate`. Si no existe, añade este DWORD y establece su valor a 1, lo que deshabilitará el proceso.
4. Cierra el Registry Editor y reinicia el servidor.

### Eliminar el historial de USB

Todas las **entradas de dispositivos USB** se almacenan en el Windows Registry, bajo la clave del registro **USBSTOR**, que contiene subclaves creadas cada vez que conectas un dispositivo USB a tu PC o portátil. Puedes encontrar esta clave aquí: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Al eliminarla**, borrarás el historial de USB.\
También puedes utilizar la herramienta [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) para asegurarte de haberlas eliminado (y eliminarlas).

Otro archivo que guarda información sobre los USB es `setupapi.dev.log`, dentro de `C:\Windows\INF`. Este también debería eliminarse.

### Deshabilitar Shadow Copies

**Lista** las Shadow Copies con `vssadmin list shadowstorage`\
**Elimínalas** ejecutando `vssadmin delete shadow`

También puedes eliminarlas mediante la GUI siguiendo los pasos propuestos en [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Para deshabilitar las Shadow Copies, [sigue estos pasos](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Abre el programa Services escribiendo "services" en el cuadro de búsqueda de texto después de hacer clic en el botón de inicio de Windows.
2. En la lista, busca "Volume Shadow Copy", selecciónalo y accede a Properties haciendo clic derecho.
3. Selecciona Disabled en el menú desplegable "Startup type" y confirma el cambio haciendo clic en Apply y OK.

También es posible modificar en el registro qué archivos se copiarán en la Shadow Copy, en `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Sobrescribir archivos eliminados

- Puedes utilizar una **herramienta de Windows**: `cipher /w:C`. Esto indicará a cipher que elimine cualquier dato del espacio de disco disponible no utilizado dentro de la unidad C.
- También puedes utilizar herramientas como [**Eraser**](https://eraser.heidi.ie)

### Eliminar los Windows event logs

- Windows + R --> eventvwr.msc --> Expande "Windows Logs" --> Haz clic derecho en cada categoría y selecciona "Clear Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Deshabilitar los Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- En la sección de servicios, deshabilita el servicio "Windows Event Log"
- `WEvtUtil.exec clear-log` o `WEvtUtil.exe cl`

### Deshabilitar $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Las versiones recientes de Windows 10/11 y Windows Server mantienen **artefactos forenses detallados de PowerShell** en
`Microsoft-Windows-PowerShell/Operational` (eventos 4104/4105/4106).
Los atacantes pueden deshabilitarlos o borrarlos sobre la marcha:
```powershell
# Turn OFF ScriptBlock & Module logging (registry persistence)
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine" \
-Name EnableScriptBlockLogging -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" \
-Name EnableModuleLogging -Value 0 -PropertyType DWord -Force

# In-memory wipe of recent PowerShell logs
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' |
Remove-WinEvent               # requires admin & Win11 23H2+
```
Los defensores deberían supervisar los cambios en esas claves del registro y la eliminación de eventos de PowerShell en grandes volúmenes.

### Parche de ETW (Event Tracing for Windows)

Los productos de seguridad de endpoints dependen en gran medida de ETW. Un método de evasión popular en 2024 consiste en aplicar un parche en memoria a `ntdll!EtwEventWrite`/`EtwEventWriteFull` para que cada llamada a ETW devuelva `STATUS_SUCCESS` sin emitir el evento:<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Los PoCs públicos (p. ej., `EtwTiSwallow`) implementan la misma primitiva en PowerShell o C++.
Como el parche es **local al proceso**, los EDR que se ejecutan dentro de otros procesos podrían no detectarlo.<sup>[[5]](#references)</sup>
Detección: comparar `ntdll` en memoria con la copia en disco, o aplicar el hook antes del user-mode.

### Resurgimiento de Alternate Data Streams (ADS)

En campañas de malware de 2023 (p. ej., loaders de **FIN12**), se ha observado que se preparan binarios de segunda etapa
dentro de ADS para mantenerse fuera del alcance de los scanners tradicionales:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Enumera los streams con `dir /R`, `Get-Item -Stream *` o Sysinternals `streams64.exe`.
Copiar el archivo host a FAT/exFAT o mediante SMB eliminará el stream oculto y puede ser utilizado
por los investigadores para recuperar el payload.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver se utiliza actualmente de forma rutinaria para **anti-forensics** en intrusiones de ransomware.
La herramienta open-source **AuKill** carga un driver firmado pero vulnerable (`procexp152.sys`) para
suspender o terminar EDR y sensores forenses **antes del cifrado y la destrucción de logs**:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
El driver se elimina posteriormente, dejando artefactos mínimos.<sup>[[1]](#references)</sup>
Mitigaciones: habilitar la lista de bloqueo de controladores vulnerables de Microsoft (HVCI/SAC)
y generar alertas ante la creación de servicios del kernel desde rutas en las que el usuario puede escribir.

---

## Anti-Forensics de Linux: Self-Patching y Cloud C2 (2023–2025)

### Self-patching de servicios comprometidos para reducir la detección (Linux)
Los adversarios hacen cada vez más “self-patching” de un servicio justo después de explotarlo, tanto para evitar su reexplotación como para suprimir las detecciones basadas en vulnerabilidades. La idea es reemplazar los componentes vulnerables por los últimos binarios/JARs legítimos del upstream, de modo que los scanners informen de que el host está parcheado mientras la persistencia y el C2 permanecen.<sup>[[3]](#references)</sup>

Ejemplo: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Tras la explotación, los atacantes descargaron JARs legítimos desde Maven Central (repo1.maven.org), eliminaron los JARs vulnerables de la instalación de ActiveMQ y reiniciaron el broker.
- Esto cerró la RCE inicial mientras mantenía otros footholds (cron, cambios en la configuración de SSH e implants de C2 independientes).

Ejemplo operativo (ilustrativo)
```bash
# ActiveMQ install root (adjust as needed)
AMQ_DIR=/opt/activemq
cd "$AMQ_DIR"/lib

# Fetch patched JARs from Maven Central (versions as appropriate)
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-client/5.18.3/activemq-client-5.18.3.jar
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-openwire-legacy/5.18.3/activemq-openwire-legacy-5.18.3.jar

# Remove vulnerable files and ensure the service uses the patched ones
rm -f activemq-client-5.18.2.jar activemq-openwire-legacy-5.18.2.jar || true
ln -sf activemq-client-5.18.3.jar activemq-client.jar
ln -sf activemq-openwire-legacy-5.18.3.jar activemq-openwire-legacy.jar

# Apply changes without removing persistence
systemctl restart activemq || service activemq restart
```
Consejos de análisis forense/hunting
- Revisa los directorios de servicios en busca de reemplazos de binarios/JAR no programados:
- Debian/Ubuntu: `dpkg -V activemq` y compara los hashes/rutas de los archivos con los mirrors del repositorio.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Busca versiones de JAR presentes en disco que no pertenezcan al package manager, o enlaces simbólicos actualizados fuera del proceso habitual.
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` para correlacionar ctime/mtime con la ventana del compromiso.
- Historial del shell/telemetría de procesos: evidencias de `curl`/`wget` a `repo1.maven.org` u otros CDN de artifacts inmediatamente después de la explotación inicial.
- Change management: valida quién aplicó el “patch” y por qué, no solo que haya una versión parcheada presente.

### Cloud-service C2 con bearer tokens y stagers anti-analysis
El tradecraft observado combinó múltiples rutas C2 de larga duración y packaging anti-analysis:<sup>[[3]](#references)</sup>
- Loaders ELF de PyInstaller protegidos con contraseña para dificultar el sandboxing y el análisis estático (p. ej., PYZ cifrado, extracción temporal en `/_MEI*`).
- Indicadores: coincidencias de `strings` como `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Artefacts de runtime: extracción a `/tmp/_MEI*` o rutas personalizadas `--runtime-tmpdir`.
- C2 respaldado por Dropbox mediante Bearer tokens de OAuth hardcodeados
- Marcadores de red: `api.dropboxapi.com` / `content.dropboxapi.com` con `Authorization: Bearer <token>`.
- Haz hunting en proxy/NetFlow/Zeek/Suricata para detectar HTTPS saliente a dominios de Dropbox desde workloads de servidores que normalmente no sincronizan archivos.
- C2 paralelo/de respaldo mediante tunneling (p. ej., Cloudflare Tunnel `cloudflared`), manteniendo el control si se bloquea un canal.
- IOCs del host: procesos/unidades `cloudflared`, configuración en `~/.cloudflared/*.json`, salida por 443 hacia los edges de Cloudflare.

### Persistencia y “hardening rollback” para mantener el acceso (ejemplos de Linux)
Los atacantes suelen combinar self-patching con rutas de acceso persistentes:<sup>[[3]](#references)</sup>
- Cron/Anacron: modificaciones al stub `0anacron` en cada directorio `/etc/cron.*/` para la ejecución periódica.
- Hunt:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- Hardening rollback de la configuración de SSH: habilitar los logins de root y modificar los shells predeterminados de cuentas con pocos privilegios.
- Hunt para detectar la habilitación del login de root:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# flag values like "yes" or overly permissive settings
```
- Hunt de shells interactivos sospechosos en cuentas del sistema (p. ej., `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Artefacts beacon aleatorios y con nombres cortos (8 caracteres alfabéticos) depositados en disco que también contactan con el C2 cloud:
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Los defensores deben correlacionar estos artefacts con la exposición externa y los eventos de patching de servicios para descubrir la auto-remediación anti-forensic utilizada para ocultar la explotación inicial.

## References

- [1] [Sophos X-Ops – AuKill: Un controlador vulnerable weaponized para deshabilitar EDR (marzo de 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching de EtwEventWrite para stealth: detección y hunting (junio de 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching para persistencia: cómo el malware DripDropper para Linux se mueve por el cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – RCE de Apache ActiveMQ OpenWire (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Ocultando tu .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
{{#include ../../banners/hacktricks-training.md}}
