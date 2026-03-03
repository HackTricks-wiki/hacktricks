# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ cargará automáticamente cada DLL de plugin encontrada en sus subcarpetas `plugins` al iniciarse. Colocar un plugin malicioso en cualquier instalación de Notepad++ con permisos de escritura proporciona code execution dentro de `notepad++.exe` cada vez que se inicia el editor, lo que puede aprovecharse para **persistence**, stealthy **initial execution**, o como un **in-process loader** si el editor se ejecuta elevado.

## Writable plugin locations
- Instalación estándar: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (generalmente requiere privilegios de administrador para escribir).
- Opciones escribibles para operadores con pocos privilegios:
- Use the **portable Notepad++ build** en una carpeta escribible por el usuario.
- Copie `C:\Program Files\Notepad++` a una ruta controlada por el usuario (p. ej., `%LOCALAPPDATA%\npp\`) y ejecute `notepad++.exe` desde allí.
- Cada plugin obtiene su propia subcarpeta bajo `plugins` y se carga automáticamente al iniciar; las entradas del menú aparecen bajo **Plugins**.

## Plugin load points (execution primitives)
Notepad++ espera funciones exportadas específicas. Todas son llamadas durante la inicialización, ofreciendo múltiples superficies de ejecución:
- **`DllMain`** — se ejecuta inmediatamente al cargar la DLL (primer punto de ejecución).
- **`setInfo(NppData)`** — llamada una vez al cargar para proporcionar handles de Notepad++; lugar típico para registrar elementos de menú.
- **`getName()`** — devuelve el nombre del plugin que se muestra en el menú.
- **`getFuncsArray(int *nbF)`** — devuelve comandos de menú; incluso si está vacío, se llama durante el arranque.
- **`beNotified(SCNotification*)`** — recibe eventos del editor (apertura/cambio de archivos, eventos de UI) para desencadenadores continuos.
- **`messageProc(UINT, WPARAM, LPARAM)`** — manejador de mensajes, útil para intercambios de datos más grandes.
- **`isUnicode()`** — bandera de compatibilidad verificada al cargar.

La mayoría de los exports pueden implementarse como stubs; la ejecución puede producirse desde `DllMain` o cualquier callback anterior durante la autocarga.

## Minimal malicious plugin skeleton
Compila una DLL con los exports esperados y colócala en `plugins\\MyNewPlugin\\MyNewPlugin.dll` dentro de una carpeta de Notepad++ con permisos de escritura:
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
2. Crear la subcarpeta de plugin bajo `plugins` y colocar la DLL dentro.
3. Reiniciar Notepad++; la DLL se carga automáticamente, ejecutando `DllMain` y los callbacks subsecuentes.

## Reflective loader plugin pattern
Un plugin malicioso puede convertir Notepad++ en un **reflective DLL loader**:
- Presentar una entrada mínima de UI/menú (p. ej., "LoadDLL").
- Aceptar una **ruta de archivo** o **URL** para descargar una DLL payload.
- Mapear reflectivamente la DLL en el proceso actual e invocar un punto de entrada exportado (p. ej., una función loader dentro de la DLL obtenida).
- Beneficio: reutilizar un proceso GUI de aspecto benigno en lugar de crear un nuevo loader; el payload hereda la integridad de `notepad++.exe` (incluyendo contextos elevados).
- Compromisos: dejar una **DLL de plugin sin firmar** en disco es ruidoso; considerar aprovechar plugins confiables existentes si están presentes.

## Notas de detección y endurecimiento
- Bloquear o monitorizar **escrituras en los directorios de plugins de Notepad++** (incluidas las copias portátiles en perfiles de usuario); habilitar controlled folder access o application allowlisting.
- Generar alertas por **nuevas DLLs sin firmar** bajo `plugins` y actividad inusual de **procesos hijos/red** desde `notepad++.exe`.
- Forzar la instalación de plugins únicamente vía **Plugins Admin**, y restringir la ejecución de copias portátiles desde rutas no confiables.

## Referencias
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
