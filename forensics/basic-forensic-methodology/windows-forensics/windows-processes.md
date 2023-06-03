## smss.exe

**Administrador de sesión**.\
La sesión 0 inicia **csrss.exe** y **wininit.exe** (**servicios** **del** **SO**) mientras que la sesión 1 inicia **csrss.exe** y **winlogon.exe** (**sesión** **de** **usuario**). Sin embargo, solo debería haber **un proceso** de ese **binario** sin hijos en el árbol de procesos.

Además, sesiones aparte de 0 y 1 pueden significar que están ocurriendo sesiones de RDP.


## csrss.exe

**Proceso de subsistema de ejecución cliente/servidor**.\
Administra **procesos** y **hilos**, hace que la **API** de **Windows** esté disponible para otros procesos y también **mapea letras de unidad**, crea **archivos temporales** y maneja el **proceso** de **apagado**.

Hay uno **ejecutándose en la sesión 0 y otro en la sesión 1** (por lo que hay **2 procesos** en el árbol de procesos). Otro se crea **por cada nueva sesión**.


## winlogon.exe

**Proceso de inicio de sesión de Windows**.\
Es responsable de los **inicios**/**cierres** de sesión de usuario. Lanza **logonui.exe** para solicitar nombre de usuario y contraseña y luego llama a **lsass.exe** para verificarlos.

Luego lanza **userinit.exe**, que se especifica en **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** con la clave **Userinit**.

Además, el registro anterior debería tener **explorer.exe** en la clave **Shell** o podría ser utilizado como un **método de persistencia de malware**.

## wininit.exe

**Proceso de inicialización de Windows**.\
Lanza **services.exe**, **lsass.exe** y **lsm.exe** en la sesión 0. Solo debería haber 1 proceso.


## userinit.exe

**Aplicación de inicio de sesión de Userinit**.\
Carga **ntduser.dat en HKCU** e inicializa el **entorno** del **usuario** y ejecuta **scripts** de **inicio de sesión** y **GPO**.

Lanza **explorer.exe**.


## lsm.exe

**Administrador de sesión local**.\
Trabaja con smss.exe para manipular las sesiones de usuario: inicio/cierre de sesión, inicio de shell, bloqueo/desbloqueo de escritorio, etc.

Después de W7, lsm.exe se transformó en un servicio (lsm.dll).

Solo debería haber 1 proceso en W7 y de ellos un servicio que ejecuta la DLL.


## services.exe

**Administrador de control de servicios**.\
Carga los **servicios** configurados como **inicio automático** y los **controladores**.

Es el proceso principal de **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** y muchos más.

Los servicios se definen en `HKLM\SYSTEM\CurrentControlSet\Services` y este proceso mantiene una base de datos en memoria de información de servicios que puede ser consultada por sc.exe.

Tenga en cuenta que **algunos** **servicios** se ejecutarán en un **proceso propio** y otros se **compartirán en un proceso svchost.exe**.

Solo debería haber 1 proceso.


## lsass.exe

**Subsistema de autoridad de seguridad local**.\
Es responsable de la **autenticación** del usuario y crea los **tokens** de **seguridad**. Utiliza paquetes de autenticación ubicados en `HKLM\System\CurrentControlSet\Control\Lsa`.

Escribe en el **registro de eventos de seguridad** y solo debería haber 1 proceso.

Tenga en cuenta que este proceso es altamente atacado para extraer contraseñas.


## svchost.exe

**Proceso de host de servicio genérico**.\
Hospeda múltiples servicios DLL en un solo proceso compartido.

Por lo general, encontrará que **svchost.exe** se lanza con la bandera `-k`. Esto lanzará una consulta al registro **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** donde habrá una clave con el argumento mencionado en -k que contendrá los servicios para lanzar en el mismo proceso.

Por ejemplo: `-k UnistackSvcGroup` lanzará: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

Si también se usa la **bandera `-s`** con un argumento, entonces se le pide a svchost que **solo lance el servicio especificado** en este argumento.

Habrá varios procesos de `svchost.exe`. Si alguno de ellos **no está usando la bandera `-k`**, eso es muy sospechoso. Si encuentra que **services.exe no es el padre**, eso también es muy sospechoso.


## taskhost.exe

Este proceso actúa como anfitrión para procesos que se ejecutan desde DLL. También carga los servicios que se ejecutan desde DLL.

En W8 se llama taskhostex.exe y en W10 taskhostw.exe.


## explorer.exe

Este es el proceso responsable del **escritorio del usuario** y de lanzar archivos a través de extensiones de archivo.

Solo debería haber **1 proceso** generado **por usuario conectado**.

Se ejecuta desde **userinit.exe**, que debería terminarse, por lo que **no debería aparecer ningún proceso padre** para este proceso.


# Detectando procesos maliciosos

* ¿Se está ejecutando desde la ruta esperada? (Ningún binario de Windows se ejecuta desde una ubicación temporal)
* ¿Se está comunicando con IPs extrañas?
* Verifique las firmas digitales (los artefactos de Microsoft deberían estar firmados)
* ¿Está escrito correctamente?
* ¿Se está ejecutando bajo el SID esperado?
* ¿Es el proceso padre el esperado (si lo hay)?
* ¿Son los procesos secundarios los esperados? (¿no hay cmd.exe, wscript.exe, powershell.exe..?)
