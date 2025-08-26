# Protecciones de credenciales de Windows

{{#include ../../banners/hacktricks-training.md}}

## WDigest

The [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) protocol, introduced with Windows XP, is designed for authentication via the HTTP Protocol and is **enabled by default on Windows XP through Windows 8.0 and Windows Server 2003 to Windows Server 2012**. This default setting results in **plain-text password storage in LSASS** (Servicio del Subsistema de la Autoridad de Seguridad Local). An attacker can use Mimikatz to **extract these credentials** by executing:
```bash
sekurlsa::wdigest
```
Para **activar o desactivar esta característica**, las claves de registro _**UseLogonCredential**_ y _**Negotiate**_ dentro de _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ deben establecerse en "1". Si estas claves están **ausentes o establecidas en "0"**, WDigest está **deshabilitado**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Protección LSA (procesos protegidos PP y PPL)

**Protected Process (PP)** y **Protected Process Light (PPL)** son **protecciones a nivel kernel de Windows** diseñadas para evitar el acceso no autorizado a procesos sensibles como **LSASS**. Introducido en **Windows Vista**, el **modelo PP** se creó originalmente para la aplicación de **DRM** y solo permitía que binarios firmados con un **certificado especial de medios** fueran protegidos. Un proceso marcado como **PP** solo puede ser accedido por otros procesos que también sean **PP** y tengan un **nivel de protección igual o superior**, y aun así, **solo con derechos de acceso limitados** a menos que se permita específicamente.

**PPL**, introducido en **Windows 8.1**, es una versión más flexible de PP. Permite **casos de uso más amplios** (por ejemplo, LSASS, Defender) al introducir **"niveles de protección"** basados en el campo EKU (Enhanced Key Usage) de la firma digital. El nivel de protección se almacena en el `EPROCESS.Protection`, que es una estructura `PS_PROTECTION` con:
- **Type** (`Protected` or `ProtectedLight`)
- **Signer** (por ejemplo, `WinTcb`, `Lsa`, `Antimalware`, etc.)

Esta estructura está empaquetada en un solo byte y determina **quién puede acceder a quién**:
- **Valores de signer más altos pueden acceder a los más bajos**
- **PPLs no pueden acceder a PPs**
- **Procesos no protegidos no pueden acceder a ningún PPL/PP**

### Lo que necesitas saber desde una perspectiva ofensiva

- Cuando **LSASS corre como PPL**, los intentos de abrirlo usando `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` desde un contexto admin normal **fallan con `0x5 (Access Denied)`**, incluso si `SeDebugPrivilege` está habilitado.
- Puedes **comprobar el nivel de protección de LSASS** usando herramientas como Process Hacker o programáticamente leyendo el valor `EPROCESS.Protection`.
- LSASS típicamente tendrá `PsProtectedSignerLsa-Light` (`0x41`), que solo puede ser accedido **por procesos firmados con un signer de nivel superior**, como `WinTcb` (`0x61` o `0x62`).
- PPL es una **restricción solo en userland**; **el código a nivel kernel puede eludirla por completo**.
- Que LSASS sea PPL no **impide el volcado de credenciales** si puedes ejecutar shellcode en kernel o **aprovechar un proceso de alto privilegio con el acceso apropiado**.
- **Establecer o quitar PPL** requiere reinicio o configuraciones de Secure Boot/UEFI, las cuales pueden persistir el ajuste de PPL incluso después de revertir cambios en el registro.

### Crear un proceso PPL al lanzarlo (API documentada)

Windows expone una forma documentada para solicitar un nivel Protected Process Light para un proceso hijo durante su creación usando la lista extendida de atributos de startup. Esto no evita los requisitos de firma — la imagen objetivo debe estar firmada para la clase de signer solicitada.

Flujo mínimo en C/C++:
```c
// Request a PPL protection level for the child process at creation time
// Requires Windows 8.1+ and a properly signed image for the selected level
#include <windows.h>

int wmain(int argc, wchar_t **argv) {
STARTUPINFOEXW si = {0};
PROCESS_INFORMATION pi = {0};
si.StartupInfo.cb = sizeof(si);

SIZE_T attrSize = 0;
InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
if (!si.lpAttributeList) return 1;

if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize)) return 1;

DWORD level = PROTECTION_LEVEL_ANTIMALWARE_LIGHT; // or WINDOWS_LIGHT/LSA_LIGHT/WINTCB_LIGHT
if (!UpdateProcThreadAttribute(
si.lpAttributeList, 0,
PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
&level, sizeof(level), NULL, NULL)) {
return 1;
}

DWORD flags = EXTENDED_STARTUPINFO_PRESENT;
if (!CreateProcessW(L"C\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,
flags, NULL, NULL, &si.StartupInfo, &pi)) {
// If the image isn't signed appropriately for the requested level,
// CreateProcess will fail with ERROR_INVALID_IMAGE_HASH (577).
return 1;
}

// cleanup
DeleteProcThreadAttributeList(si.lpAttributeList);
HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
CloseHandle(pi.hThread);
CloseHandle(pi.hProcess);
return 0;
}
```
Notas y restricciones:
- Usar `STARTUPINFOEX` con `InitializeProcThreadAttributeList` y `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`, luego pasar `EXTENDED_STARTUPINFO_PRESENT` a `CreateProcess*`.
- El `DWORD` de protección puede configurarse en constantes como `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, o `PROTECTION_LEVEL_LSA_LIGHT`.
- El hijo solo se inicia como PPL si su imagen está firmada para esa clase de firmante; de lo contrario la creación del proceso falla, comúnmente con `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`.
- Esto no es un bypass — es una API soportada pensada para imágenes debidamente firmadas. Útil para endurecer herramientas o validar configuraciones protegidas por PPL.

Example CLI using a minimal loader:
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Opciones para eludir las protecciones PPL:**

Si quieres volcar LSASS a pesar de PPL, tienes 3 opciones principales:
1. **Use a signed kernel driver (e.g., Mimikatz + mimidrv.sys)** to **remove LSASS’s protection flag**:

![](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)** to run custom kernel code and disable the protection. Tools like **PPLKiller**, **gdrv-loader**, or **kdmapper** make this feasible.
3. **Steal an existing LSASS handle** from another process that has it open (e.g., an AV process), then **duplicate it** into your process. This is the basis of the `pypykatz live lsa --method handledup` technique.
4. **Abuse some privileged process** that will allow you to load arbitrary code into its address space or inside another privileged process, effectively bypassing the PPL restrictions. You can check an example of this in [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) or [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Check current status of LSA protection (PPL/PP) for LSASS**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
Cuando ejecutes **`mimikatz privilege::debug sekurlsa::logonpasswords`** probablemente falle con el código de error `0x00000005` por esto.

- Para más información sobre esta verificación [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)


## Credential Guard

**Credential Guard**, una característica exclusiva de **Windows 10 (ediciones Enterprise y Education)**, mejora la seguridad de las credenciales del equipo usando **Virtual Secure Mode (VSM)** y **Virtualization Based Security (VBS)**. Aprovecha las extensiones de virtualización del CPU para aislar procesos clave dentro de un espacio de memoria protegido, fuera del alcance del sistema operativo principal. Este aislamiento garantiza que incluso el kernel no pueda acceder a la memoria en VSM, protegiendo así las credenciales frente a ataques como **pass-the-hash**. La **Autoridad de seguridad local (LSA)** opera dentro de este entorno seguro como un trustlet, mientras que el proceso **LSASS** en el SO principal actúa únicamente como comunicador con la LSA del VSM.

Por defecto, **Credential Guard** no está activo y requiere activación manual en una organización. Es crucial para mejorar la seguridad frente a herramientas como **Mimikatz**, las cuales ven limitada su capacidad de extraer credenciales. Sin embargo, aún pueden explotarse vulnerabilidades mediante la adición de **Proveedores de soporte de seguridad (SSP)** personalizados para capturar credenciales en clear text durante los intentos de inicio de sesión.

Para verificar el estado de activación de **Credential Guard**, se puede inspeccionar la clave del registro _**LsaCfgFlags**_ bajo _**HKLM\System\CurrentControlSet\Control\LSA**_. Un valor de "**1**" indica activación con **UEFI lock**, "**2**" sin lock, y "**0**" indica que no está habilitado. Esta comprobación del registro, aunque es un indicador fuerte, no es el único paso para habilitar Credential Guard. Hay guías detalladas y un script de PowerShell para habilitar esta característica disponibles en línea.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Para una comprensión completa e instrucciones sobre cómo habilitar **Credential Guard** en Windows 10 y su activación automática en sistemas compatibles de **Windows 11 Enterprise and Education (versión 22H2)**, visite la [documentación de Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Detalles adicionales sobre la implementación de SSPs personalizados para la captura de credenciales se proporcionan en [esta guía](../active-directory-methodology/custom-ssp.md).

## Modo Restricted Admin de RDP

**Windows 8.1 y Windows Server 2012 R2** introdujeron varias nuevas características de seguridad, incluyendo el _**Restricted Admin mode for RDP**_. Este modo fue diseñado para mejorar la seguridad mitigando los riesgos asociados con los ataques [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/).

Tradicionalmente, al conectarse a un equipo remoto mediante RDP, sus credenciales se almacenan en la máquina de destino. Esto representa un riesgo de seguridad significativo, especialmente al usar cuentas con privilegios elevados. Sin embargo, con la introducción del _**Restricted Admin mode**_, este riesgo se reduce sustancialmente.

Al iniciar una conexión RDP usando el comando **mstsc.exe /RestrictedAdmin**, la autenticación al equipo remoto se realiza sin almacenar sus credenciales en él. Este enfoque garantiza que, en caso de una infección por malware o si un usuario malicioso obtiene acceso al servidor remoto, sus credenciales no se comprometan, ya que no se almacenan en el servidor.

Es importante notar que en **Restricted Admin mode**, los intentos de acceder a recursos de red desde la sesión RDP no usarán sus credenciales personales; en su lugar, se utiliza la **identidad de la máquina**.

Esta característica representa un avance significativo para asegurar las conexiones de escritorio remoto y proteger información sensible de exponerse en caso de una brecha de seguridad.

![](../../images/RAM.png)

Para obtener información más detallada visite [este recurso](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Credenciales en caché

Windows protege las **credenciales de dominio** a través de la **Local Security Authority (LSA)**, soportando procesos de inicio de sesión con protocolos de seguridad como **Kerberos** y **NTLM**. Una característica clave de Windows es su capacidad para almacenar en caché los **últimos diez inicios de sesión de dominio** para asegurar que los usuarios aún puedan acceder a sus equipos incluso si el **controlador de dominio está sin conexión**—algo útil para usuarios con laptops que frecuentemente están fuera de la red de la empresa.

El número de inicios de sesión en caché se puede ajustar mediante una clave de **registro** específica o una **directiva de grupo**. Para ver o cambiar esta configuración, se utiliza el siguiente comando:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
El acceso a estas credenciales en caché está estrictamente controlado, y solo la cuenta **SYSTEM** tiene los permisos necesarios para verlas. Los administradores que necesiten acceder a esta información deben hacerlo con privilegios de usuario SYSTEM. Las credenciales se almacenan en: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** puede emplearse para extraer estas credenciales en caché usando el comando `lsadump::cache`.

Para más detalles, la [source](http://juggernaut.wikidot.com/cached-credentials) original proporciona información completa.

## Protected Users

La pertenencia al **Protected Users group** introduce varias mejoras de seguridad para los usuarios, garantizando mayores niveles de protección contra el robo y el uso indebido de credenciales:

- **Credential Delegation (CredSSP)**: Incluso si la configuración de Group Policy **Allow delegating default credentials** está habilitada, las credenciales en texto plano de los Protected Users no serán almacenadas en caché.
- **Windows Digest**: A partir de **Windows 8.1 and Windows Server 2012 R2**, el sistema no almacenará en caché las credenciales en texto plano de los Protected Users, independientemente del estado de Windows Digest.
- **NTLM**: El sistema no almacenará en caché las credenciales en texto plano de los Protected Users ni las funciones unidireccionales NT (NTOWF).
- **Kerberos**: Para los Protected Users, la autenticación Kerberos no generará claves **DES** o **RC4**, ni almacenará en caché credenciales en texto plano o claves de largo plazo más allá de la adquisición inicial del Ticket-Granting Ticket (TGT).
- **Offline Sign-In**: A los Protected Users no se les creará un verificador en caché al iniciar sesión o desbloquear, lo que significa que el inicio de sesión sin conexión no está soportado para estas cuentas.

Estas protecciones se activan en el momento en que un usuario, que es miembro del **Protected Users group**, inicia sesión en el dispositivo. Esto asegura que medidas de seguridad críticas estén en marcha para proteger contra varios métodos de compromiso de credenciales.

Para más información detallada, consulte la [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Table from** [**the docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

## Referencias

- [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [STARTUPINFOEX structure (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [LSASS RunAsPPL – background and internals](https://itm4n.github.io/lsass-runasppl/)

{{#include ../../banners/hacktricks-training.md}}
