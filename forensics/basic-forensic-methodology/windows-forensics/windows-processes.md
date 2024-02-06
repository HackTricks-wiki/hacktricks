<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red de HackTricks AWS)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>


## smss.exe

**Administrador de Sesiones**.\
La Sesión 0 inicia **csrss.exe** y **wininit.exe** (**servicios del SO**) mientras que la Sesión 1 inicia **csrss.exe** y **winlogon.exe** (**sesión de usuario**). Sin embargo, solo deberías ver **un proceso** de ese **binario** sin hijos en el árbol de procesos.

Además, sesiones aparte de 0 y 1 pueden indicar que están ocurriendo sesiones de RDP.


## csrss.exe

**Proceso de Subsistema de Ejecución Cliente/Servidor**.\
Administra **procesos** y **hilos**, hace que la **API de Windows** esté disponible para otros procesos y también **asigna letras de unidad**, crea **archivos temporales** y maneja el **proceso de apagado**.

Hay uno **ejecutándose en la Sesión 0 y otro en la Sesión 1** (por lo tanto, **2 procesos** en el árbol de procesos). Se crea otro por cada nueva Sesión.


## winlogon.exe

**Proceso de Inicio de Sesión de Windows**.\
Es responsable de los **inicios**/**cierres de sesión** de usuario. Inicia **logonui.exe** para solicitar nombre de usuario y contraseña y luego llama a **lsass.exe** para verificarlos.

Luego inicia **userinit.exe** que está especificado en **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** con la clave **Userinit**.

Además, el registro anterior debería tener **explorer.exe** en la clave **Shell** o podría ser abusado como un **método de persistencia de malware**.


## wininit.exe

**Proceso de Inicialización de Windows**. \
Inicia **services.exe**, **lsass.exe** y **lsm.exe** en la Sesión 0. Debería haber solo 1 proceso.


## userinit.exe

**Aplicación de Inicio de Sesión de Usuario**.\
Carga el **ntduser.dat en HKCU** e inicializa el **entorno de usuario** y ejecuta **scripts de inicio de sesión** y **GPO**.

Inicia **explorer.exe**.


## lsm.exe

**Administrador de Sesión Local**.\
Trabaja con smss.exe para manipular sesiones de usuario: inicio/cierre de sesión, inicio de shell, bloqueo/desbloqueo de escritorio, etc.

Después de W7, lsm.exe se transformó en un servicio (lsm.dll).

Debería haber solo 1 proceso en W7 y de ellos un servicio ejecutando el DLL.


## services.exe

**Administrador de Control de Servicios**.\
**Carga** **servicios** configurados como **inicio automático** y **controladores**.

Es el proceso padre de **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** y muchos más.

Los servicios están definidos en `HKLM\SYSTEM\CurrentControlSet\Services` y este proceso mantiene una base de datos en memoria de información de servicio que puede ser consultada por sc.exe.

Observa cómo **algunos** **servicios** se ejecutarán en un **proceso propio** y otros estarán **compartiendo un proceso svchost.exe**.

Debería haber solo 1 proceso.


## lsass.exe

**Subsistema de Autoridad de Seguridad Local**.\
Es responsable de la autenticación de usuario y crea los **tokens de seguridad**. Utiliza paquetes de autenticación ubicados en `HKLM\System\CurrentControlSet\Control\Lsa`.

Escribe en el **registro de eventos de seguridad** y debería haber solo 1 proceso.

Ten en cuenta que este proceso es altamente atacado para extraer contraseñas.


## svchost.exe

**Proceso de Host de Servicio Genérico**.\
Hospeda múltiples servicios DLL en un proceso compartido.

Por lo general, encontrarás que **svchost.exe** se inicia con la bandera `-k`. Esto lanzará una consulta al registro **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** donde habrá una clave con el argumento mencionado en -k que contendrá los servicios a iniciar en el mismo proceso.

Por ejemplo: `-k UnistackSvcGroup` lanzará: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

Si también se usa la **bandera `-s`** con un argumento, entonces se le pide a svchost que **solo inicie el servicio especificado** en este argumento.

Habrá varios procesos de `svchost.exe`. Si alguno de ellos **no está utilizando la bandera `-k`**, eso es muy sospechoso. Si encuentras que **services.exe no es el proceso padre**, eso también es muy sospechoso.


## taskhost.exe

Este proceso actúa como anfitrión para procesos que se ejecutan desde DLL. También carga los servicios que se ejecutan desde DLL.

En W8 se llama taskhostex.exe y en W10 taskhostw.exe.


## explorer.exe

Este es el proceso responsable del **escritorio del usuario** y de lanzar archivos a través de extensiones de archivo.

Debería generarse solo **1** proceso por **usuario conectado**.

Este se ejecuta desde **userinit.exe** que debería terminarse, por lo que **no debería aparecer ningún proceso padre** para este proceso.


# Detectando Procesos Maliciosos

* ¿Se está ejecutando desde la ruta esperada? (Ningún binario de Windows se ejecuta desde una ubicación temporal)
* ¿Se está comunicando con IPs extrañas?
* Verificar firmas digitales (los artefactos de Microsoft deberían estar firmados)
* ¿Está escrito correctamente?
* ¿Se está ejecutando bajo el SID esperado?
* ¿El proceso padre es el esperado (si lo hay)?
* ¿Los procesos hijos son los esperados? (¿no cmd.exe, wscript.exe, powershell.exe..?)

</details>
