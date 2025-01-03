# Claves de Registro de Windows Interesantes

### Claves de Registro de Windows Interesantes

{{#include ../../../banners/hacktricks-training.md}}

### **Información de Versión de Windows y Propietario**

- Ubicado en **`Software\Microsoft\Windows NT\CurrentVersion`**, encontrarás la versión de Windows, el Service Pack, la hora de instalación y el nombre del propietario registrado de manera sencilla.

### **Nombre del Computador**

- El nombre del host se encuentra en **`System\ControlSet001\Control\ComputerName\ComputerName`**.

### **Configuración de Zona Horaria**

- La zona horaria del sistema se almacena en **`System\ControlSet001\Control\TimeZoneInformation`**.

### **Seguimiento de Tiempo de Acceso**

- Por defecto, el seguimiento del último tiempo de acceso está desactivado (**`NtfsDisableLastAccessUpdate=1`**). Para habilitarlo, usa:
`fsutil behavior set disablelastaccess 0`

### Versiones de Windows y Service Packs

- La **versión de Windows** indica la edición (por ejemplo, Home, Pro) y su lanzamiento (por ejemplo, Windows 10, Windows 11), mientras que los **Service Packs** son actualizaciones que incluyen correcciones y, a veces, nuevas características.

### Habilitando el Tiempo de Último Acceso

- Habilitar el seguimiento del último tiempo de acceso te permite ver cuándo se abrieron por última vez los archivos, lo que puede ser crítico para el análisis forense o la supervisión del sistema.

### Detalles de Información de Red

- El registro contiene datos extensos sobre configuraciones de red, incluyendo **tipos de redes (inalámbrica, cable, 3G)** y **categorías de red (Pública, Privada/Hogar, Dominio/Trabajo)**, que son vitales para entender la configuración de seguridad de la red y los permisos.

### Caché del Lado del Cliente (CSC)

- **CSC** mejora el acceso a archivos sin conexión al almacenar copias de archivos compartidos. Diferentes configuraciones de **CSCFlags** controlan cómo y qué archivos se almacenan en caché, afectando el rendimiento y la experiencia del usuario, especialmente en entornos con conectividad intermitente.

### Programas de Inicio Automático

- Los programas listados en varias claves de registro `Run` y `RunOnce` se inician automáticamente al arrancar, afectando el tiempo de arranque del sistema y potencialmente siendo puntos de interés para identificar malware o software no deseado.

### Shellbags

- **Shellbags** no solo almacenan preferencias para vistas de carpetas, sino que también proporcionan evidencia forense de acceso a carpetas incluso si la carpeta ya no existe. Son invaluables para investigaciones, revelando la actividad del usuario que no es obvia a través de otros medios.

### Información y Forense de USB

- Los detalles almacenados en el registro sobre dispositivos USB pueden ayudar a rastrear qué dispositivos se conectaron a una computadora, potencialmente vinculando un dispositivo a transferencias de archivos sensibles o incidentes de acceso no autorizado.

### Número de Serie de Volumen

- El **Número de Serie de Volumen** puede ser crucial para rastrear la instancia específica de un sistema de archivos, útil en escenarios forenses donde se necesita establecer el origen de un archivo a través de diferentes dispositivos.

### **Detalles de Apagado**

- La hora de apagado y el conteo (este último solo para XP) se mantienen en **`System\ControlSet001\Control\Windows`** y **`System\ControlSet001\Control\Watchdog\Display`**.

### **Configuración de Red**

- Para información detallada de la interfaz de red, consulta **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**.
- Los tiempos de conexión de red primero y último, incluidas las conexiones VPN, se registran en varias rutas en **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`**.

### **Carpetas Compartidas**

- Las carpetas compartidas y configuraciones están bajo **`System\ControlSet001\Services\lanmanserver\Shares`**. Las configuraciones de Caché del Lado del Cliente (CSC) dictan la disponibilidad de archivos sin conexión.

### **Programas que Inician Automáticamente**

- Rutas como **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`** y entradas similares bajo `Software\Microsoft\Windows\CurrentVersion` detallan programas configurados para ejecutarse al inicio.

### **Búsquedas y Rutas Escritas**

- Las búsquedas de Explorer y las rutas escritas se rastrean en el registro bajo **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`** para WordwheelQuery y TypedPaths, respectivamente.

### **Documentos Recientes y Archivos de Office**

- Los documentos recientes y los archivos de Office accedidos se anotan en `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` y rutas específicas de versiones de Office.

### **Elementos Más Usados Recientemente (MRU)**

- Las listas MRU, que indican rutas de archivos y comandos recientes, se almacenan en varias subclaves de `ComDlg32` y `Explorer` bajo `NTUSER.DAT`.

### **Seguimiento de Actividad del Usuario**

- La función User Assist registra estadísticas detalladas de uso de aplicaciones, incluyendo el conteo de ejecuciones y la última hora de ejecución, en **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`**.

### **Análisis de Shellbags**

- Shellbags, que revelan detalles de acceso a carpetas, se almacenan en `USRCLASS.DAT` y `NTUSER.DAT` bajo `Software\Microsoft\Windows\Shell`. Usa **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** para el análisis.

### **Historial de Dispositivos USB**

- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`** y **`HKLM\SYSTEM\ControlSet001\Enum\USB`** contienen detalles ricos sobre dispositivos USB conectados, incluyendo fabricante, nombre del producto y marcas de tiempo de conexión.
- El usuario asociado con un dispositivo USB específico se puede identificar buscando en los registros `NTUSER.DAT` para el **{GUID}** del dispositivo.
- El último dispositivo montado y su número de serie de volumen se pueden rastrear a través de `System\MountedDevices` y `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`, respectivamente.

Esta guía condensa las rutas y métodos cruciales para acceder a información detallada del sistema, red y actividad del usuario en sistemas Windows, buscando claridad y usabilidad.

{{#include ../../../banners/hacktricks-training.md}}
