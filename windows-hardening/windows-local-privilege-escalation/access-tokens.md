## Tokens de Acceso

Cada **usuario que ha iniciado sesión** en el sistema **tiene un token de acceso con información de seguridad** para esa sesión de inicio de sesión. El sistema crea un token de acceso cuando el usuario inicia sesión. **Cada proceso ejecutado** en nombre del usuario **tiene una copia del token de acceso**. El token identifica al usuario, los grupos del usuario y los privilegios del usuario. Un token también contiene un SID de inicio de sesión (Identificador de Seguridad) que identifica la sesión de inicio de sesión actual.

Puedes ver esta información ejecutando `whoami /all`.
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
o utilizando _Process Explorer_ de Sysinternals (selecciona el proceso y accede a la pestaña "Seguridad"):

![](<../../.gitbook/assets/image (321).png>)

### Administrador local

Cuando un administrador local inicia sesión, **se crean dos tokens de acceso**: uno con derechos de administrador y otro con derechos normales. **Por defecto**, cuando este usuario ejecuta un proceso, se utiliza el que tiene **derechos regulares** (no de administrador). Cuando este usuario intenta **ejecutar** algo **como administrador** ("Ejecutar como administrador", por ejemplo), se utilizará el **UAC** para solicitar permiso.\
Si quieres [**saber más sobre el UAC, lee esta página**](../authentication-credentials-uac-and-efs.md#uac)**.**

### Suplantación de credenciales de usuario

Si tienes las **credenciales válidas de cualquier otro usuario**, puedes **crear** una **nueva sesión de inicio de sesión** con esas credenciales:
```
runas /user:domain\username cmd.exe
```
El **token de acceso** también tiene una **referencia** de las sesiones de inicio de sesión dentro del **LSASS**, lo cual es útil si el proceso necesita acceder a algunos objetos de la red.\
Puedes lanzar un proceso que **utilice diferentes credenciales para acceder a servicios de red** usando:
```
runas /user:domain\username /netonly cmd.exe
```
Esto es útil si tienes credenciales para acceder a objetos en la red, pero esas credenciales no son válidas dentro del host actual ya que solo se usarán en la red (en el host actual se usarán los privilegios de usuario actuales).

### Tipos de tokens

Hay dos tipos de tokens disponibles:

* **Token primario**: Los tokens primarios solo se pueden **asociar a procesos**, y representan el sujeto de seguridad de un proceso. La creación de tokens primarios y su asociación a procesos son operaciones privilegiadas, que requieren dos privilegios diferentes en nombre de la separación de privilegios: el escenario típico ve al servicio de autenticación creando el token, y un servicio de inicio de sesión asociándolo al shell del sistema operativo del usuario. Los procesos heredan inicialmente una copia del token primario del proceso padre.
* **Token de suplantación**: La suplantación es un concepto de seguridad implementado en Windows NT que **permite** a una aplicación de servidor "**ser**" **temporalmente** "**el cliente**" en términos de acceso a objetos seguros. La suplantación tiene **cuatro posibles niveles**:

    * **anónimo**, dando al servidor el acceso de un usuario anónimo/no identificado
    * **identificación**, permitiendo al servidor inspeccionar la identidad del cliente pero no usar esa identidad para acceder a objetos
    * **suplantación**, permitiendo al servidor actuar en nombre del cliente
    * **delegación**, igual que la suplantación pero extendida a sistemas remotos a los que se conecta el servidor (a través de la preservación de credenciales).

    El cliente puede elegir el nivel máximo de suplantación (si lo hay) disponible para el servidor como parámetro de conexión. La delegación y la suplantación son operaciones privilegiadas (la suplantación inicialmente no lo era, pero la negligencia histórica en la implementación de las API de cliente al no restringir el nivel predeterminado a "identificación", permitiendo que un servidor no privilegiado suplante a un cliente privilegiado no dispuesto, lo requirió). **Los tokens de suplantación solo se pueden asociar a hilos**, y representan el sujeto de seguridad de un proceso de cliente. Los tokens de suplantación suelen crearse y asociarse al hilo actual implícitamente, mediante mecanismos IPC como DCE RPC, DDE y tuberías con nombre.

#### Suplantar Tokens

Usando el módulo _**incognito**_\*\* de Metasploit, si tienes suficientes privilegios, puedes **listar** y **suplantar** otros **tokens** fácilmente. Esto podría ser útil para realizar **acciones como si fueras el otro usuario**. También podrías **escalar privilegios** con esta técnica.

### Privilegios de Token

Aprende qué **privilegios de token se pueden abusar para escalar privilegios:**

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

Echa un vistazo a [**todos los posibles privilegios de token y algunas definiciones en esta página externa**](https://github.com/gtworek/Priv2Admin).

## Referencias

Aprende más sobre tokens en estos tutoriales: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) y [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos.
* Consigue el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
