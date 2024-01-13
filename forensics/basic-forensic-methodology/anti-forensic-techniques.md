<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Sellos de tiempo

Un atacante puede estar interesado en **cambiar los sellos de tiempo de los archivos** para evitar ser detectado.\
Es posible encontrar los sellos de tiempo dentro del MFT en los atributos `$STANDARD_INFORMATION` __ y __ `$FILE_NAME`.

Ambos atributos tienen 4 sellos de tiempo: **Modificación**, **acceso**, **creación** y **modificación del registro MFT** (MACE o MACB).

**Windows explorer** y otras herramientas muestran la información de **`$STANDARD_INFORMATION`**.

## TimeStomp - Herramienta Anti-forense

Esta herramienta **modifica** la información del sello de tiempo dentro de **`$STANDARD_INFORMATION`** **pero** **no** la información dentro de **`$FILE_NAME`**. Por lo tanto, es posible **identificar** **actividad** **sospechosa**.

## Usnjrnl

El **USN Journal** (Update Sequence Number Journal), o Change Journal, es una característica del sistema de archivos Windows NT (NTFS) que **mantiene un registro de los cambios realizados en el volumen**.\
Es posible utilizar la herramienta [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) para buscar modificaciones en este registro.

![](<../../.gitbook/assets/image (449).png>)

La imagen anterior es el **resultado** mostrado por la **herramienta** donde se puede observar que se realizaron algunos **cambios** al archivo.

## $LogFile

Todos los cambios de metadatos en un sistema de archivos se registran para asegurar la recuperación consistente de estructuras críticas del sistema de archivos después de un fallo del sistema. Esto se llama [registro anticipado de escritura](https://en.wikipedia.org/wiki/Write-ahead_logging).\
Los metadatos registrados se almacenan en un archivo llamado “**$LogFile**”, que se encuentra en un directorio raíz de un sistema de archivos NTFS.\
Es posible utilizar herramientas como [LogFileParser](https://github.com/jschicht/LogFileParser) para analizar este archivo y encontrar cambios.

![](<../../.gitbook/assets/image (450).png>)

Nuevamente, en el resultado de la herramienta es posible ver que se realizaron **algunos cambios**.

Utilizando la misma herramienta es posible identificar **a qué hora se modificaron los sellos de tiempo**:

![](<../../.gitbook/assets/image (451).png>)

* CTIME: Hora de creación del archivo
* ATIME: Hora de modificación del archivo
* MTIME: Hora de modificación del registro MFT del archivo
* RTIME: Hora de acceso del archivo

## Comparación de `$STANDARD_INFORMATION` y `$FILE_NAME`

Otra forma de identificar archivos modificados sospechosos sería comparar el tiempo en ambos atributos buscando **inconsistencias**.

## Nanosegundos

Los sellos de tiempo de **NTFS** tienen una **precisión** de **100 nanosegundos**. Entonces, encontrar archivos con sellos de tiempo como 2010-10-10 10:10:**00.000:0000 es muy sospechoso**.

## SetMace - Herramienta Anti-forense

Esta herramienta puede modificar ambos atributos `$STARNDAR_INFORMATION` y `$FILE_NAME`. Sin embargo, desde Windows Vista, es necesario un sistema operativo en vivo para modificar esta información.

# Ocultamiento de Datos

NTFS utiliza un clúster y el tamaño mínimo de información. Eso significa que si un archivo ocupa un clúster y medio, la **mitad restante nunca se usará** hasta que se elimine el archivo. Entonces, es posible **ocultar datos en este espacio libre**.

Hay herramientas como slacker que permiten ocultar datos en este espacio "oculto". Sin embargo, un análisis de `$logfile` y `$usnjrnl` puede mostrar que se agregaron algunos datos:

![](<../../.gitbook/assets/image (452).png>)

Entonces, es posible recuperar el espacio libre utilizando herramientas como FTK Imager. Ten en cuenta que este tipo de herramienta puede guardar el contenido ofuscado o incluso encriptado.

# UsbKill

Esta es una herramienta que **apagará el ordenador si se detecta cualquier cambio en los puertos USB**.\
Una forma de descubrir esto sería inspeccionar los procesos en ejecución y **revisar cada script de python en ejecución**.

# Distribuciones Linux en Vivo

Estas distribuciones se **ejecutan dentro de la memoria RAM**. La única forma de detectarlas es **en caso de que el sistema de archivos NTFS esté montado con permisos de escritura**. Si está montado solo con permisos de lectura, no será posible detectar la intrusión.

# Eliminación Segura

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Configuración de Windows

Es posible desactivar varios métodos de registro de Windows para dificultar mucho la investigación forense.

## Desactivar Sellos de Tiempo - UserAssist

Esta es una clave de registro que mantiene fechas y horas de cuando cada ejecutable fue utilizado por el usuario.

Para desactivar UserAssist se requieren dos pasos:

1. Establecer dos claves de registro, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` y `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, ambas a cero para indicar que queremos desactivar UserAssist.
2. Limpiar tus subárboles de registro que parecen `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

## Desactivar Sellos de Tiempo - Prefetch

Esto guardará información sobre las aplicaciones ejecutadas con el objetivo de mejorar el rendimiento del sistema Windows. Sin embargo, esto también puede ser útil para prácticas forenses.

* Ejecutar `regedit`
* Seleccionar la ruta de archivo `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* Hacer clic derecho en `EnablePrefetcher` y `EnableSuperfetch`
* Seleccionar Modificar en cada uno de estos para cambiar el valor de 1 (o 3) a 0
* Reiniciar

## Desactivar Sellos de Tiempo - Último Tiempo de Acceso

Cada vez que se abre una carpeta desde un volumen NTFS en un servidor Windows NT, el sistema toma tiempo para **actualizar un campo de sello de tiempo en cada carpeta listada**, llamado el último tiempo de acceso. En un volumen NTFS muy utilizado, esto puede afectar el rendimiento.

1. Abrir el Editor de Registro (Regedit.exe).
2. Navegar a `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Buscar `NtfsDisableLastAccessUpdate`. Si no existe, agregar este DWORD y establecer su valor en 1, lo que desactivará el proceso.
4. Cerrar el Editor de Registro y reiniciar el servidor.

## Eliminar Historial de USB

Todas las **Entradas de Dispositivos USB** se almacenan en el Registro de Windows bajo la clave de registro **USBSTOR** que contiene subclaves que se crean cada vez que conectas un Dispositivo USB a tu PC o Laptop. Puedes encontrar esta clave aquí `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Eliminando esto** borrarás el historial de USB.\
También puedes usar la herramienta [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) para asegurarte de haberlos eliminado (y para eliminarlos).

Otro archivo que guarda información sobre los USB es el archivo `setupapi.dev.log` dentro de `C:\Windows\INF`. Esto también debe ser eliminado.

## Desactivar Copias de Sombra

**Listar** copias de sombra con `vssadmin list shadowstorage`\
**Eliminarlas** ejecutando `vssadmin delete shadow`

También puedes eliminarlas a través de la GUI siguiendo los pasos propuestos en [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Para desactivar copias de sombra:

1. Ir al botón de inicio de Windows y escribir "services" en el cuadro de búsqueda de texto; abrir el programa Servicios.
2. Localizar "Volume Shadow Copy" de la lista, resaltarla y luego hacer clic derecho > Propiedades.
3. Desde el menú desplegable "Tipo de inicio", seleccionar Desactivado y luego hacer clic en Aplicar y OK.

![](<../../.gitbook/assets/image (453).png>)

También es posible modificar la configuración de qué archivos van a ser copiados en la copia de sombra en el registro `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

## Sobrescribir archivos eliminados

* Puedes usar una **herramienta de Windows**: `cipher /w:C` Esto indicará a cipher que elimine cualquier dato del espacio disponible no utilizado en el disco dentro de la unidad C.
* También puedes usar herramientas como [**Eraser**](https://eraser.heidi.ie)

## Eliminar registros de eventos de Windows

* Windows + R --> eventvwr.msc --> Expandir "Registros de Windows" --> Hacer clic derecho en cada categoría y seleccionar "Borrar registro"
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Desactivar registros de eventos de Windows

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* Dentro de la sección de servicios desactivar el servicio "Registro de eventos de Windows"
* `WEvtUtil.exec clear-log` o `WEvtUtil.exe cl`

## Desactivar $UsnJrnl

* `fsutil usn deletejournal /d c:`


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
