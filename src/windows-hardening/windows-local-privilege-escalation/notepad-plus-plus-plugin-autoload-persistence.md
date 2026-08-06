# Persistencia y ejecución mediante autoload de plugins de Notepad++

{{#include ../../banners/hacktricks-training.md}}

Notepad++ **carga automáticamente todos los DLL de plugins encontrados en sus subcarpetas `plugins`** al iniciarse. Colocar un plugin malicioso en cualquier **instalación de Notepad++ con permisos de escritura** proporciona code execution dentro de `notepad++.exe` cada vez que se inicia el editor, lo que puede abusarse para **persistence**, **initial execution** sigilosa o como **in-process loader** si el editor se inicia con privilegios elevados.<sup>[[1]](#references)</sup>

Desde **Notepad++ 7.6+**, el layout esperado para la instalación manual es **una subcarpeta por plugin** (`plugins\<PluginName>\<PluginName>.dll`). En **portable mode** (cuando existe `doLocalConf.xml` junto a `notepad++.exe`), todo el árbol de la aplicación permanece local a ese directorio, lo que a menudo convierte los bundles de herramientas copiados o administrativos en una superficie de ejecución fácilmente escribible por el usuario.<sup>[[2]](#references)</sup>

## Ubicaciones de plugins con permisos de escritura

- Instalación estándar: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (normalmente requiere permisos de administrador para escribir).<sup>[[1]](#references)</sup>
- Opciones con permisos de escritura para operadores con pocos privilegios:<sup>[[1]](#references)</sup>
- Usar la **portable Notepad++ build** en una carpeta con permisos de escritura para el usuario.
- Copiar `C:\Program Files\Notepad++` a una ruta controlada por el usuario (por ejemplo, `%LOCALAPPDATA%\npp\`) y ejecutar `notepad++.exe` desde allí.
- Buscar **admin tool bundles**, copias extraídas de archivos zip o toolkits de help desk que ya contengan `doLocalConf.xml` y estén fuera de `Program Files`.
- Cada plugin tiene su propia subcarpeta bajo `plugins` y se carga automáticamente al iniciar; las entradas del menú aparecen bajo **Plugins**.<sup>[[2]](#references)</sup>

Triage rápido:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Puntos de carga del plugin (primitivas de ejecución)
Notepad++ espera **funciones exportadas** específicas. Todas se llaman durante la inicialización, lo que proporciona múltiples superficies de ejecución:<sup>[[1]](#references)</sup>
- **`DllMain`** — se ejecuta inmediatamente al cargar la DLL (primer punto de ejecución).
- **`setInfo(NppData)`** — se llama una vez durante la carga para proporcionar los handles de Notepad++; lugar habitual para registrar elementos del menú.
- **`getName()`** — devuelve el nombre del plugin mostrado en el menú.
- **`getFuncsArray(int *nbF)`** — devuelve los comandos del menú; incluso si está vacío, se llama durante el inicio.
- **`beNotified(SCNotification*)`** — recibe eventos de Notepad++ / Scintilla (útil para aplazar los payloads hasta una acción del usuario o un evento del editor).
- **`messageProc(UINT, WPARAM, LPARAM)`** — controlador de mensajes, útil para intercambios de datos grandes.
- **`isUnicode()`** — indicador de compatibilidad que se comprueba durante la carga.

La mayoría de las funciones exportadas pueden implementarse como **stubs**; la ejecución puede producirse desde `DllMain` o desde cualquiera de los callbacks anteriores durante la carga automática.

## Esqueleto mínimo de un plugin malicioso
Compila una DLL con las funciones exportadas esperadas y colócala en `plugins\\MyNewPlugin\\MyNewPlugin.dll`, dentro de una carpeta de Notepad++ con permisos de escritura:<sup>[[1]](#references)</sup>
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
2. Crea la subcarpeta del plugin dentro de `plugins` y coloca la DLL en su interior.
3. Reinicia Notepad++; la DLL se carga automáticamente, ejecutando `DllMain` y los callbacks posteriores.

## Patrón de trigger de bajo ruido mediante `beNotified`
Para OPSEC, muchos payloads no deberían ejecutarse desde `DllMain`. Un patrón más discreto consiste en permitir que el plugin se cargue correctamente y ejecutar el código solo después de un evento realista del editor, como **la finalización del inicio**, **la activación del buffer** o **el primer carácter escrito**.
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
Esto coincide mejor con la investigación ofensiva pública que un beacon ruidoso en `DllMain`: la DLL sigue cargándose automáticamente al inicio, pero la acción maliciosa se retrasa hasta que Notepad++ parece estar realmente en uso.

## Uso del directorio de configuración del plugin como almacenamiento secundario
Notepad++ expone `NPPM_GETPLUGINSCONFIGDIR`, que devuelve el **directorio de configuración de plugins del usuario actual**.<sup>[[3]](#references)</sup> Un plugin malicioso puede usarlo para mantener mínima la DLL almacenada en disco y guardar configuración cifrada, payloads preparados o archivos de tasking en una ruta que se integre con el estado normal de los plugins.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operativamente, esto resulta útil cuando quieres:
- una DLL bootstrap pequeña cargada mediante autoload;
- tasking por usuario sin volver a tocar el binario principal del plugin;
- separar el **trigger de autoload** del second stage más pesado.

## Patrón de plugin reflective loader
Un plugin weaponized puede convertir Notepad++ en un **reflective DLL loader**:<sup>[[1]](#references)</sup>
- Presentar una entrada mínima en la UI/menú (por ejemplo, "LoadDLL").
- Aceptar una **ruta de archivo** o una **URL** desde la que obtener una DLL payload.
- Mapear reflectivamente la DLL en el proceso actual e invocar un entry point exportado (por ejemplo, una función loader dentro de la DLL obtenida).
- Ventaja: reutilizar un proceso GUI de apariencia benigna en lugar de iniciar un loader nuevo; el payload hereda la integridad de `notepad++.exe` (incluidos los contextos elevados).
- Compromisos: dejar una **DLL de plugin unsigned** en disco es ruidoso; una variación práctica consiste en usar el plugin cargado mediante autoload únicamente como stub y mantener el implant real cifrado/staged en otra ubicación.

## Notas de detección y hardening
- Bloquear o monitorizar las **escrituras en los directorios de plugins de Notepad++** (incluidas las copias portables en los perfiles de usuario); habilitar controlled folder access o application allowlisting.
- Generar alertas ante **nuevas DLL unsigned** bajo `plugins`, cambios en los árboles portables de Notepad++, y **child processes/actividad de red inusuales** procedentes de `notepad++.exe`.
- Establecer una baseline de los plugins legítimos e investigar cualquier DLL nueva que exporte la interfaz normal de plugins de Notepad++, pero que también inicie shells, PowerShell o network beacons.
- Aplicar la instalación de plugins únicamente mediante **Plugins Admin** y restringir la ejecución de copias portables desde rutas no confiables.

## Referencias

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
