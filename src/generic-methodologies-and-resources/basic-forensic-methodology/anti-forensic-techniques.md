# Técnicas Anti-Forensic

{{#include ../../banners/hacktricks-training.md}}

## Marcas de tiempo

Un atacante puede estar interesado en **cambiar las marcas de tiempo de los archivos** para evitar ser detectado.\
Es posible encontrar las marcas de tiempo dentro de la MFT, en los atributos `$STANDARD_INFORMATION` \_\_ y \_\_ `$FILE_NAME`.

Ambos atributos tienen 4 marcas de tiempo: **modificación**, **acceso**, **creación** y **modificación del registro MFT** (MACE o MACB).

**Windows explorer** y otras herramientas muestran la información de **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensic Tool

Esta herramienta **modifica** la información de las marcas de tiempo dentro de **`$STANDARD_INFORMATION`**, **pero no** la información dentro de **`$FILE_NAME`**. Por lo tanto, es posible **identificar** **actividad** **sospechosa**.

### Usnjrnl

El **USN Journal** (Update Sequence Number Journal) es una característica de NTFS (Windows NT file system) que realiza un seguimiento de los cambios del volumen. La herramienta [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) permite examinar estos cambios.

![TimeStomp - Anti-forensic Tool - Usnjrnl: El USN Journal (Update Sequence Number Journal) es una característica de NTFS (Windows NT file system) que realiza un seguimiento de los cambios del volumen. La...](<../../images/image (801).png>)

La imagen anterior muestra el **resultado** presentado por la **herramienta**, donde se puede observar que se **realizaron algunos cambios** en el archivo.

### $LogFile

**Todos los cambios de metadatos en un sistema de archivos se registran** en un proceso conocido como [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Los metadatos registrados se almacenan en un archivo llamado `**$LogFile**`, ubicado en el directorio raíz de un sistema de archivos NTFS. Se pueden utilizar herramientas como [LogFileParser](https://github.com/jschicht/LogFileParser) para analizar este archivo e identificar cambios.

![Usnjrnl - $LogFile: Todos los cambios de metadatos en un sistema de archivos se registran en un proceso conocido como write-ahead logging. Los metadatos registrados se almacenan en un archivo llamado $LogFile, ubicado en el directorio raíz...](<../../images/image (137).png>)

Nuevamente, en el resultado de la herramienta es posible ver que **se realizaron algunos cambios**.

Con la misma herramienta es posible identificar **a qué hora se modificaron las marcas de tiempo**:

![Usnjrnl - $LogFile: Con la misma herramienta es posible identificar a qué hora se modificaron las marcas de tiempo](<../../images/image (1089).png>)

- CTIME: Hora de creación del archivo
- ATIME: Hora de modificación del archivo
- MTIME: Modificación del registro MFT del archivo
- RTIME: Hora de acceso del archivo

### Comparación de `$STANDARD_INFORMATION` y `$FILE_NAME`

Otra forma de identificar archivos modificados sospechosos sería comparar la hora de ambos atributos en busca de **incongruencias**.

### Nanosegundos

Las marcas de tiempo de **NTFS** tienen una **precisión** de **100 nanosegundos**. Por lo tanto, encontrar archivos con marcas de tiempo como 2010-10-10 10:10:**00.000:0000 es muy sospechoso**.

### SetMace - Anti-forensic Tool

Esta herramienta puede modificar ambos atributos, `$STARNDAR_INFORMATION` y `$FILE_NAME`. Sin embargo, desde Windows Vista, es necesario que un sistema operativo en ejecución modifique esta información.

## Ocultación de datos

NFTS utiliza un clúster y el tamaño mínimo de información. Esto significa que, si un archivo ocupa un clúster y medio, **la mitad restante nunca se va a utilizar** hasta que se elimine el archivo. Por lo tanto, es posible **ocultar datos en este espacio residual**.

Existen herramientas como slacker que permiten ocultar datos en este espacio "oculto". Sin embargo, un análisis de `$logfile` y `$usnjrnl` puede mostrar que se añadieron algunos datos:

![SetMace - Anti-forensic Tool - Ocultación de datos: Existen herramientas como slacker que permiten ocultar datos en este espacio "oculto". Sin embargo, un análisis de $logfile y $usnjrnl puede mostrar que...](<../../images/image (1060).png>)

Por lo tanto, es posible recuperar el espacio residual utilizando herramientas como FTK Imager. Ten en cuenta que este tipo de herramientas puede guardar el contenido ofuscado o incluso cifrado.

## UsbKill

Esta es una herramienta que **apagará el ordenador si detecta algún cambio en los puertos USB**.\
Una forma de descubrirla sería inspeccionar los procesos en ejecución y **revisar cada script de Python en ejecución**.

## Distribuciones Live de Linux

Estas distribuciones se **ejecutan dentro de la memoria RAM**. La única forma de detectarlas es **si el sistema de archivos NTFS está montado con permisos de escritura**. Si se monta únicamente con permisos de lectura, no será posible detectar la intrusión.

## Eliminación segura

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Configuración de Windows

Es posible desactivar varios métodos de logging de Windows para dificultar mucho la investigación forense.

### Desactivar marcas de tiempo - UserAssist

Esta es una clave del registro que mantiene las fechas y horas en las que el usuario ejecutó cada ejecutable.

Desactivar UserAssist requiere dos pasos:

1. Establecer las dos claves del registro, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` y `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, ambas a cero para indicar que queremos desactivar UserAssist.
2. Limpiar los subárboles del registro que tengan el formato `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Desactivar marcas de tiempo - Prefetch

Esto guarda información sobre las aplicaciones ejecutadas con el objetivo de mejorar el rendimiento del sistema Windows. Sin embargo, también puede ser útil para las prácticas forenses.

- Ejecuta `regedit`
- Selecciona la ruta de archivo `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Haz clic derecho en `EnablePrefetcher` y `EnableSuperfetch`
- Selecciona Modify en cada una para cambiar el valor de 1 (o 3) a 0
- Reinicia

### Desactivar marcas de tiempo - Hora del último acceso

Cada vez que se abre una carpeta desde un volumen NTFS en un servidor Windows NT, el sistema registra la hora para **actualizar un campo de marca de tiempo en cada carpeta listada**, llamado hora del último acceso. En un volumen NTFS con mucho uso, esto puede afectar al rendimiento.

1. Abre el Editor del Registro (Regedit.exe).
2. Navega hasta `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Busca `NtfsDisableLastAccessUpdate`. Si no existe, añade este DWORD y establece su valor en 1, lo que desactivará el proceso.
4. Cierra el Editor del Registro y reinicia el servidor.

### Eliminar el historial USB

Todas las **entradas de dispositivos USB** se almacenan en el Registro de Windows, bajo la clave de registro **USBSTOR**, que contiene subclaves que se crean cada vez que conectas un dispositivo USB a tu PC o portátil. Puedes encontrar esta clave aquí: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Al eliminarla**, eliminarás el historial USB.\
También puedes utilizar la herramienta [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) para asegurarte de haberlas eliminado (y para eliminarlas).

Otro archivo que guarda información sobre los dispositivos USB es `setupapi.dev.log`, ubicado en `C:\Windows\INF`. Este también debería eliminarse.

### Desactivar Shadow Copies

**Lista** las Shadow Copies con `vssadmin list shadowstorage`\
**Elimínalas** ejecutando `vssadmin delete shadow`

También puedes eliminarlas mediante la GUI siguiendo los pasos propuestos en [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Para desactivar las Shadow Copies, [sigue estos pasos](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Abre el programa Services escribiendo "services" en el cuadro de búsqueda de texto después de hacer clic en el botón de inicio de Windows.
2. En la lista, busca "Volume Shadow Copy", selecciónalo y accede a Properties haciendo clic derecho.
3. Selecciona Disabled en el menú desplegable "Startup type" y confirma el cambio haciendo clic en Apply y OK.

También es posible modificar en el registro qué archivos se copiarán en la Shadow Copy, en `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Sobrescribir archivos eliminados

- Puedes utilizar una **herramienta de Windows**: `cipher /w:C`. Esto indicará a cipher que elimine cualquier dato del espacio de disco disponible y no utilizado dentro de la unidad C.
- También puedes utilizar herramientas como [**Eraser**](https://eraser.heidi.ie)

### Eliminar los logs de eventos de Windows

- Windows + R --> eventvwr.msc --> Expande "Windows Logs" --> Haz clic derecho en cada categoría y selecciona "Clear Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Desactivar los logs de eventos de Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- En la sección de servicios, desactiva el servicio "Windows Event Log"
- `WEvtUtil.exec clear-log` o `WEvtUtil.exe cl`

### Desactivar $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Manipulación avanzada de logs y trazas (2023-2025)

### PowerShell ScriptBlock/Module Logging

Las versiones recientes de Windows 10/11 y Windows Server conservan **artefactos forenses detallados de PowerShell** en
`Microsoft-Windows-PowerShell/Operational` (eventos 4104/4105/4106).
Los atacantes pueden desactivarlos o borrarlos sobre la marcha:
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

### ETW (Event Tracing for Windows) Patch

Los productos de seguridad de endpoints dependen en gran medida de ETW. Un método de evasión popular en 2024 consiste en aplicar un
parche en memoria a `ntdll!EtwEventWrite`/`EtwEventWriteFull` para que cada llamada a ETW devuelva `STATUS_SUCCESS`
sin emitir el evento:<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Los PoCs públicos (p. ej., `EtwTiSwallow`) implementan la misma primitiva en PowerShell o C++.
Debido a que el parche es **local al proceso**, los EDR que se ejecutan dentro de otros procesos pueden no detectarlo.<sup>[[5]](#references)</sup>
Detección: comparar `ntdll` en memoria con la versión en disco, o aplicar el hook antes del user-mode.

### Resurgimiento de Alternate Data Streams (ADS)

En 2023, se observaron campañas de malware (p. ej., loaders de **FIN12**) que almacenaban binarios de segunda fase
dentro de ADS para mantenerse fuera del alcance de los scanners tradicionales:
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

Bring-Your-Own-Vulnerable-Driver se utiliza ahora habitualmente para **anti-forensics** en intrusiones de ransomware.
La herramienta open-source **AuKill** carga un driver firmado pero vulnerable (`procexp152.sys`) para
suspender o terminar EDR y sensores forenses **antes del cifrado y la destrucción de logs**:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
El driver se elimina posteriormente, dejando artefactos mínimos.<sup>[[1]](#references)</sup>
Mitigaciones: habilitar la Microsoft vulnerable-driver blocklist (HVCI/SAC),
y generar alertas ante la creación de kernel-services desde rutas modificables por el usuario.

---

## Linux Anti-Forensics: Self-Patching and Cloud C2 (2023–2025)

### Self‑patching de servicios comprometidos para reducir la detección (Linux)
Los adversarios realizan cada vez más “self‑patching” de un servicio justo después de explotarlo, tanto para evitar su reexplotación como para suprimir las detecciones basadas en vulnerabilidades. La idea es reemplazar los componentes vulnerables por los últimos binarios/JARs legítimos del upstream, de modo que los scanners informen que el host está parcheado mientras la persistencia y el C2 permanecen.<sup>[[3]](#references)</sup>

Ejemplo: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Tras el post‑exploitation, los atacantes obtuvieron JARs legítimos desde Maven Central (repo1.maven.org), eliminaron los JARs vulnerables de la instalación de ActiveMQ y reiniciaron el broker.
- Esto cerró el RCE inicial mientras mantenía otros footholds (cron, cambios en la configuración de SSH e implants de C2 independientes).

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
- Debian/Ubuntu: `dpkg -V activemq` y comparar los hashes/rutas de archivos con los mirrors del repositorio.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Buscar versiones de JAR presentes en disco que no pertenezcan al package manager, o symbolic links actualizados fuera de banda.
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` para correlacionar ctime/mtime con la ventana del compromiso.
- Historial del shell/telemetría de procesos: evidencias de `curl`/`wget` a `repo1.maven.org` u otros artifact CDNs inmediatamente después de la explotación inicial.
- Gestión de cambios: validar quién aplicó el “parche” y por qué, no solo que haya una versión parcheada presente.

### C2 de cloud-service con bearer tokens y stagers anti-analysis
El tradecraft observado combinaba múltiples rutas C2 de larga duración y packaging anti-analysis:<sup>[[3]](#references)</sup>
- Loaders ELF de PyInstaller protegidos con contraseña para dificultar el sandboxing y el análisis estático (por ejemplo, PYZ cifrado y extracción temporal bajo `/_MEI*`).
- Indicadores: resultados de `strings` como `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Artefactos de runtime: extracción a `/tmp/_MEI*` o a rutas personalizadas mediante `--runtime-tmpdir`.
- C2 respaldado por Dropbox usando hardcoded OAuth Bearer tokens.
- Indicadores de red: `api.dropboxapi.com` / `content.dropboxapi.com` con `Authorization: Bearer <token>`.
- Buscar en proxy/NetFlow/Zeek/Suricata conexiones HTTPS salientes a dominios de Dropbox desde workloads de servidores que normalmente no sincronizan archivos.
- C2 paralelo/de respaldo mediante tunneling (por ejemplo, Cloudflare Tunnel `cloudflared`), manteniendo el control si un canal queda bloqueado.
- IOCs del host: procesos/unidades `cloudflared`, configuración en `~/.cloudflared/*.json`, conexiones salientes por 443 a los edges de Cloudflare.

### Persistencia y “hardening rollback” para mantener el acceso (ejemplos de Linux)
Los atacantes suelen combinar self-patching con rutas de acceso persistentes:<sup>[[3]](#references)</sup>
- Cron/Anacron: modificaciones del stub `0anacron` en cada directorio `/etc/cron.*/` para la ejecución periódica.
- Buscar:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- Reversión del hardening de la configuración de SSH: habilitar los inicios de sesión de root y modificar los shells predeterminados de las cuentas con pocos privilegios.
- Buscar la habilitación del inicio de sesión de root:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# marcar valores como "yes" o configuraciones excesivamente permisivas
```
- Buscar shells interactivos sospechosos en cuentas del sistema (por ejemplo, `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Artefactos beacon aleatorios y con nombres cortos (8 caracteres alfabéticos) dejados en disco que además contactan con cloud C2:
- Buscar:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Los defensores deben correlacionar estos artefactos con la exposición externa y los eventos de parcheado de servicios para descubrir la autorremediación anti-forense utilizada para ocultar la explotación inicial.

## References

- [1] [Sophos X-Ops – AuKill: Un driver vulnerable weaponized para deshabilitar EDR (marzo de 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching de EtwEventWrite para stealth: detección y hunting (junio de 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching para persistencia: cómo el malware Linux DripDropper se mueve por el cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – RCE de Apache ActiveMQ OpenWire (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Ocultando tu .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
{{#include ../../banners/hacktricks-training.md}}
