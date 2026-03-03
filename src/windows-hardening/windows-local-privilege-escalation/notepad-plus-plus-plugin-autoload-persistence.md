# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ will **autoload every plugin DLL found under its `plugins` subfolders** on launch. Colocar un plugin malicioso en cualquier instalación de Notepad++ que sea escribible permite ejecución de código dentro de `notepad++.exe` cada vez que el editor se inicia, lo que puede aprovecharse para **persistence**, sigilosa **initial execution**, o como un **in-process loader** si el editor se lanza con privilegios elevados.

## Writable plugin locations
- Instalación estándar: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (usualmente requiere admin para escribir).
- Opciones escribibles para operadores con pocos privilegios:
- Use the **portable Notepad++ build** in a user-writable folder.
- Copia `C:\Program Files\Notepad++` a una ruta controlada por el usuario (por ejemplo, `%LOCALAPPDATA%\npp\`) y ejecuta `notepad++.exe` desde allí.
- Cada plugin obtiene su propia subcarpeta bajo `plugins` y se carga automáticamente al inicio; las entradas de menú aparecen bajo **Plugins**.

## Plugin load points (execution primitives)
Notepad++ espera funciones **exported functions** específicas. Todas se llaman durante la inicialización, ofreciendo múltiples superficies de ejecución:
- **`DllMain`** — se ejecuta inmediatamente al cargar la DLL (primer punto de ejecución).
- **`setInfo(NppData)`** — se llama una vez al cargar para proporcionar handles de Notepad++; lugar típico para registrar elementos del menú.
- **`getName()`** — devuelve el nombre del plugin que se muestra en el menú.
- **`getFuncsArray(int *nbF)`** — devuelve los comandos del menú; incluso si está vacío, se llama durante el arranque.
- **`beNotified(SCNotification*)`** — recibe eventos del editor (apertura/cambio de archivos, eventos de UI) para triggers continuos.
- **`messageProc(UINT, WPARAM, LPARAM)`** — manejador de mensajes, útil para intercambios de datos de mayor tamaño.
- **`isUnicode()`** — bandera de compatibilidad verificada al cargar.

La mayoría de los exports pueden implementarse como **stubs**; la ejecución puede ocurrir desde `DllMain` o cualquier callback anterior durante autoload.

## Minimal malicious plugin skeleton
Compila una DLL con los exports esperados y colócala en `plugins\\MyNewPlugin\\MyNewPlugin.dll` dentro de una carpeta de Notepad++ escribible:
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. Compilar la DLL (Visual Studio/MinGW).
2. Crear la subcarpeta plugin bajo `plugins` y colocar la DLL dentro.
3. Reiniciar Notepad++; la DLL se carga automáticamente, ejecutando `DllMain` y callbacks subsecuentes.

## Reflective loader plugin pattern
A weaponized plugin can turn Notepad++ into a **reflective DLL loader**:
- Presentar una entrada mínima de UI/menú (p. ej., "LoadDLL").
- Aceptar una **ruta de archivo** o **URL** para obtener una payload DLL.
- Mapear reflectivamente la DLL en el proceso actual e invocar un punto de entrada exportado (p. ej., una función loader dentro de la DLL obtenida).
- Beneficio: reutilizar un proceso GUI de apariencia benigno en lugar de crear un nuevo loader; el payload hereda la integridad de `notepad++.exe` (incluyendo contextos elevados).
- Contras: colocar una **DLL de plugin sin firmar** en disco es ruidoso; considerar piggybacking en plugins confiables existentes si están presentes.

## Notas de detección y hardening
- Bloquear o monitorizar **escrituras en los directorios de plugins de Notepad++** (incluyendo copias portables en perfiles de usuario); habilitar controlled folder access o application allowlisting.
- Alertar sobre **nuevas DLLs sin firmar** bajo `plugins` y sobre **procesos hijo/actividad de red** inusual de `notepad++.exe`.
- Forzar la instalación de plugins vía **Plugins Admin** únicamente, y restringir la ejecución de copias portables desde rutas no confiables.

## Referencias
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
