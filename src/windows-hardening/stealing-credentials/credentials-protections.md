# Protecciones de credenciales de Windows

{{#include ../../banners/hacktricks-training.md}}

## WDigest

El protocolo [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>), introducido con Windows XP, está diseñado para la autenticación mediante el protocolo HTTP y está **habilitado de forma predeterminada en Windows XP hasta Windows 8.0 y en Windows Server 2003 hasta Windows Server 2012**. Esta configuración predeterminada provoca el **almacenamiento de contraseñas en texto plano en LSASS** (Local Security Authority Subsystem Service). Un atacante puede usar Mimikatz para **extraer estas credenciales** ejecutando:<sup>[[8]](#references)</sup>
```bash
sekurlsa::wdigest
```
Para **activar o desactivar esta función**, las claves del registro _**UseLogonCredential**_ y _**Negotiate**_ dentro de _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ deben establecerse en "1". Si estas claves están **ausentes o establecidas en "0"**, WDigest está **deshabilitado**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection (procesos protegidos por PP y PPL)

**Protected Process (PP)** y **Protected Process Light (PPL)** son **protecciones a nivel del kernel de Windows** diseñadas para evitar el acceso no autorizado a procesos sensibles como **LSASS**. Introducido en **Windows Vista**, el **modelo PP** se creó originalmente para aplicar el cumplimiento de **DRM** y solo permitía proteger binarios firmados con un **certificado multimedia especial**. Un proceso marcado como **PP** solo puede ser accedido por otros procesos que también sean **PP** y tengan un **nivel de protección igual o superior**, e incluso en ese caso, **solo con derechos de acceso limitados**, a menos que se permita específicamente.

**PPL**, introducido en **Windows 8.1**, es una versión más flexible de PP. Permite **casos de uso más amplios** (por ejemplo, LSASS y Defender) mediante la introducción de **"niveles de protección"** basados en el campo **EKU (Enhanced Key Usage)** de la **firma digital**. El nivel de protección se almacena en el campo `EPROCESS.Protection`, que es una estructura `PS_PROTECTION` con:
- **Type** (`Protected` o `ProtectedLight`)
- **Signer** (por ejemplo, `WinTcb`, `Lsa`, `Antimalware`, etc.)

Esta estructura se empaqueta en un único byte y determina **quién puede acceder a quién**:
- **Los valores de signer superiores pueden acceder a los inferiores**
- **Los PPL no pueden acceder a los PP**
- **Los procesos no protegidos no pueden acceder a ningún PPL/PP**

### Lo que necesitas saber desde una perspectiva ofensiva

- Cuando **LSASS se ejecuta como PPL**, los intentos de abrirlo mediante `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` desde un contexto de administrador normal **fallan con `0x5 (Access Denied)`**, incluso si `SeDebugPrivilege` está habilitado.
- Puedes **comprobar el nivel de protección de LSASS** usando herramientas como Process Hacker o mediante programación, leyendo el valor `EPROCESS.Protection`.
- LSASS normalmente tendrá `PsProtectedSignerLsa-Light` (`0x41`), al que **solo pueden acceder procesos firmados con un signer de nivel superior**, como `WinTcb` (`0x61` o `0x62`).
- PPL es una **restricción exclusiva de Userland**; el **código a nivel del kernel puede omitirla completamente**.
- Que LSASS sea PPL **no impide el credential dumping** si puedes ejecutar shellcode en el kernel o **aprovechar un proceso con privilegios elevados y acceso adecuado**.
- **Establecer o eliminar PPL** requiere reiniciar el sistema o modificar la configuración de **Secure Boot/UEFI**, lo que puede mantener la configuración de PPL incluso después de revertir los cambios en el registro.

### Crear un proceso PPL durante el lanzamiento (API documentada)

Windows ofrece una forma documentada de solicitar un nivel de Protected Process Light para un proceso hijo durante su creación mediante la lista de atributos de inicio extendidos. Esto no omite los requisitos de firma: la imagen objetivo debe estar firmada para la clase de signer solicitada.

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
- Usa `STARTUPINFOEX` con `InitializeProcThreadAttributeList` y `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`, y después pasa `EXTENDED_STARTUPINFO_PRESENT` a `CreateProcess*`.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- El `DWORD` de protección se puede establecer con constantes como `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` o `PROTECTION_LEVEL_LSA_LIGHT`.
- El proceso hijo solo se inicia como PPL si su imagen está firmada para esa clase de signer; de lo contrario, la creación del proceso falla, normalmente con `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`.
- Esto no es un bypass; es una API compatible destinada a imágenes firmadas adecuadamente. Resulta útil para hardenizar herramientas o validar configuraciones protegidas por PPL.

Ejemplo de CLI usando un loader mínimo:<sup>[[1]](#references)</sup>
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Opciones para bypass de las protecciones PPL:**

Si quieres hacer dump de LSASS a pesar de PPL, tienes 3 opciones principales:
1. **Usar un signed kernel driver (por ejemplo, Mimikatz + mimidrv.sys)** para **eliminar el protection flag de LSASS**:

![Salida del driver mimidrv de Mimikatz mostrando la interacción con la protección de credenciales](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)** para ejecutar código de kernel personalizado y deshabilitar la protección. Herramientas como **PPLKiller**, **gdrv-loader** o **kdmapper** hacen esto posible.
3. **Robar un handle existente de LSASS** desde otro proceso que lo tenga abierto (por ejemplo, un proceso de AV) y después **duplicarlo** en tu proceso. Esta es la base de la técnica `pypykatz live lsa --method handledup`.
4. **Abusar de algún proceso privilegiado** que permita cargar código arbitrario en su espacio de direcciones o dentro de otro proceso privilegiado, evitando efectivamente las restricciones de PPL. Puedes consultar un ejemplo en [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) o [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Comprobar el estado actual de la protección LSA (PPL/PP) para LSASS**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
Al ejecutar **`mimikatz privilege::debug sekurlsa::logonpasswords`**, probablemente fallará con el código de error `0x00000005` debido a esta protección.

- Para obtener más información sobre esta comprobación, consulta [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)<sup>[[5]](#references)</sup>


## Credential Guard

**Credential Guard**, una función exclusiva de **Windows 10 (ediciones Enterprise y Education)**, mejora la seguridad de las credenciales de la máquina mediante **Virtual Secure Mode (VSM)** y **Virtualization Based Security (VBS)**. Utiliza las extensiones de virtualización de la CPU para aislar procesos clave dentro de un espacio de memoria protegido, fuera del alcance del sistema operativo principal. Este aislamiento garantiza que ni siquiera el kernel pueda acceder a la memoria en VSM, protegiendo eficazmente las credenciales frente a ataques como **pass-the-hash**. La **Local Security Authority (LSA)** se ejecuta dentro de este entorno seguro como un trustlet, mientras que el proceso **LSASS** del sistema operativo principal actúa únicamente como comunicador con la LSA de VSM.

De forma predeterminada, **Credential Guard** no está activo y requiere una activación manual dentro de una organización. Es fundamental para mejorar la seguridad frente a herramientas como **Mimikatz**, cuya capacidad para extraer credenciales se ve limitada. Sin embargo, las vulnerabilidades aún pueden explotarse mediante la adición de **Security Support Providers (SSP)** personalizados para capturar credenciales en texto claro durante los intentos de inicio de sesión.

Para verificar el estado de activación de **Credential Guard**, se puede inspeccionar la clave del registro _**LsaCfgFlags**_ en _**HKLM\System\CurrentControlSet\Control\LSA**_. Un valor de "**1**" indica que está activado con **UEFI lock**, "**2**" sin bloqueo, y "**0**" indica que no está habilitado. Esta comprobación del registro, aunque es un indicador sólido, no es el único paso necesario para habilitar Credential Guard. En Internet hay disponible orientación detallada y un script de PowerShell para habilitar esta función.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Para comprender de forma exhaustiva y consultar instrucciones sobre cómo habilitar **Credential Guard** en Windows 10 y su activación automática en sistemas compatibles de **Windows 11 Enterprise y Education (versión 22H2)**, visita la [documentación de Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).<sup>[[9]](#references)</sup>

En [esta guía](../active-directory-methodology/custom-ssp.md) se proporcionan más detalles sobre la implementación de SSPs personalizados para la captura de credenciales.

## Modo RDP RestrictedAdmin

**Windows 8.1 y Windows Server 2012 R2** introdujeron varias funciones de seguridad nuevas, incluido el _**modo Restricted Admin para RDP**_. Este modo se diseñó para mejorar la seguridad mitigando los riesgos asociados a los ataques de [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/).

Tradicionalmente, al conectarse a un equipo remoto mediante RDP, las credenciales se almacenan en el equipo de destino. Esto supone un riesgo de seguridad significativo, especialmente al utilizar cuentas con privilegios elevados. Sin embargo, con la introducción del _**modo Restricted Admin**_, este riesgo se reduce considerablemente.

Al iniciar una conexión RDP mediante el comando **mstsc.exe /RestrictedAdmin**, la autenticación en el equipo remoto se realiza sin almacenar las credenciales en él. Este enfoque garantiza que, en caso de una infección por malware o si un usuario malicioso obtiene acceso al servidor remoto, las credenciales no se vean comprometidas, ya que no se almacenan en el servidor.

Es importante tener en cuenta que, en el **modo Restricted Admin**, los intentos de acceder a recursos de red desde la sesión RDP no utilizarán las credenciales personales; en su lugar, se utilizará la **identidad del equipo**.

Esta función supone un avance significativo en la protección de las conexiones de escritorio remoto y de la información confidencial frente a una posible exposición en caso de una brecha de seguridad.

![Diagrama de la memoria RAM de Windows en el contexto de la extracción de credenciales](../../images/RAM.png)

Para obtener información más detallada, visita [este recurso](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).<sup>[[6]](#references)</sup>

## Credenciales almacenadas en caché

Windows protege las **credenciales de dominio** mediante la **Local Security Authority (LSA)**, que admite procesos de inicio de sesión con protocolos de seguridad como **Kerberos** y **NTLM**. Una función clave de Windows es su capacidad para almacenar en caché los **últimos diez inicios de sesión de dominio**, lo que garantiza que los usuarios puedan seguir accediendo a sus equipos incluso si el **controlador de dominio está desconectado**, algo especialmente útil para los usuarios de portátiles que suelen estar fuera de la red de su empresa.

El número de inicios de sesión almacenados en caché se puede ajustar mediante una **clave del registro o una directiva de grupo** específica. Para consultar o cambiar esta configuración, se utiliza el siguiente comando:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
El acceso a estas credenciales almacenadas en caché está estrictamente controlado; solo la cuenta **SYSTEM** tiene los permisos necesarios para verlas. Los administradores que necesiten acceder a esta información deben hacerlo con privilegios de usuario SYSTEM. Las credenciales se almacenan en: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** puede utilizarse para extraer estas credenciales almacenadas en caché mediante el comando `lsadump::cache`.

Para obtener más detalles, la [fuente original](http://juggernaut.wikidot.com/cached-credentials) proporciona información completa.<sup>[[7]](#references)</sup>

## Protected Users

La pertenencia al **Protected Users group** introduce varias mejoras de seguridad para los usuarios, garantizando mayores niveles de protección contra el robo y el uso indebido de credenciales:

- **Credential Delegation (CredSSP)**: Incluso si la configuración de Group Policy **Allow delegating default credentials** está habilitada, las credenciales de texto plano de los usuarios de Protected Users no se almacenarán en caché.
- **Windows Digest**: A partir de **Windows 8.1 y Windows Server 2012 R2**, el sistema no almacenará en caché las credenciales de texto plano de los usuarios de Protected Users, independientemente del estado de Windows Digest.
- **NTLM**: El sistema no almacenará en caché las credenciales de texto plano ni las funciones unidireccionales NT (NTOWF) de los usuarios de Protected Users.
- **Kerberos**: Para los usuarios de Protected Users, la autenticación Kerberos no generará claves **DES** ni **RC4**, ni almacenará en caché credenciales de texto plano o claves a largo plazo más allá de la adquisición inicial del Ticket-Granting Ticket (TGT).
- **Offline Sign-In**: No se creará un verificador almacenado en caché para los usuarios de Protected Users al iniciar sesión o desbloquear el dispositivo, lo que significa que el inicio de sesión sin conexión no es compatible con estas cuentas.

Estas protecciones se activan en el momento en que un usuario miembro del **Protected Users group** inicia sesión en el dispositivo. Esto garantiza que se implementen medidas de seguridad críticas para protegerse contra diversos métodos de compromiso de credenciales.

Para obtener información más detallada, consulta la [documentación oficial](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).<sup>[[10]](#references)</sup>

**Tabla de** [**la documentación**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**<sup>[[11]](#references)</sup>

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
| Schema Admins            | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators        | Server Operators                                                              | Server Operators             |

## References

- [1] [CreateProcessAsPPL – lanzador de procesos PPL minimalista](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [2] [Estructura STARTUPINFOEX (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [3] [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [4] [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [LSASS RunAsPPL – contexto e internals](https://itm4n.github.io/lsass-runasppl/)
- [6] [Restricted Admin Mode para RDP](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)
- [7] [Cached Credentials - Wiki AppSec de Juggernaut](http://juggernaut.wikidot.com/cached-credentials)
- [8] [Autenticación WDigest (Microsoft TechNet)](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>)
- [9] [Administrar Windows Defender Credential Guard (Microsoft Learn)](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
- [10] [Protected Users Security Group (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [11] [Apéndice C: cuentas y grupos protegidos en Active Directory (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
{{#include ../../banners/hacktricks-training.md}}
