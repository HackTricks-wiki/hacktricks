# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ lädt beim Start **jede Plugin-DLL, die in seinen `plugins`-Unterordnern gefunden wird, automatisch**. Das Ablegen eines bösartigen Plugins in einer beliebigen **schreibbaren Notepad++-Installation** ermöglicht Codeausführung innerhalb von `notepad++.exe` bei jedem Start des Editors. Das kann für **persistence**, unauffällige **initial execution** oder als **in-process loader** missbraucht werden, falls der Editor mit erhöhten Rechten gestartet wird.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (normalerweise sind Administratorrechte zum Schreiben erforderlich).
- Schreibbare Optionen für Benutzer mit geringen Rechten:
- Verwende die **portable Notepad++ build** in einem benutzerbeschreibbaren Ordner.
- Kopiere `C:\Program Files\Notepad++` in einen benutzerkontrollierten Pfad (z. B. `%LOCALAPPDATA%\npp\`) und starte `notepad++.exe` von dort.
- Jedes Plugin erhält einen eigenen Unterordner unter `plugins` und wird beim Start automatisch geladen; Menüpunkte erscheinen unter **Plugins**.

## Plugin load points (execution primitives)
Notepad++ erwartet bestimmte **exported functions**. Diese werden alle während der Initialisierung aufgerufen und bieten mehrere Ausführungsflächen:
- **`DllMain`** — läuft unmittelbar beim Laden der DLL (erster Ausführungspunkt).
- **`setInfo(NppData)`** — wird einmal beim Laden aufgerufen, um Notepad++-Handles bereitzustellen; typischer Ort, um Menüeinträge zu registrieren.
- **`getName()`** — gibt den im Menü angezeigten Plugin-Namen zurück.
- **`getFuncsArray(int *nbF)`** — gibt Menübefehle zurück; selbst wenn leer, wird es beim Start aufgerufen.
- **`beNotified(SCNotification*)`** — erhält Editor-Ereignisse (Datei öffnen/ändern, UI-Ereignisse) für fortlaufende Trigger.
- **`messageProc(UINT, WPARAM, LPARAM)`** — Nachrichten-Handler, nützlich für größere Datenaustausche.
- **`isUnicode()`** — Kompatibilitätsflag, das beim Laden geprüft wird.

Die meisten Exports können als **stubs** implementiert werden; die Ausführung kann in `DllMain` oder in einem der oben genannten Callbacks während des Autoloads erfolgen.

## Minimal malicious plugin skeleton
Kompiliere eine DLL mit den erwarteten Exports und lege sie in `plugins\\MyNewPlugin\\MyNewPlugin.dll` unter einem schreibbaren Notepad++-Ordner ab:
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. DLL erstellen (Visual Studio/MinGW).
2. Erstelle den Plugin-Unterordner unter `plugins` und lege die DLL dort ab.
3. Starte Notepad++ neu; die DLL wird automatisch geladen und `DllMain` sowie nachfolgende Callbacks ausgeführt.

## Reflective loader plugin pattern
Ein bösartiges Plugin kann Notepad++ in einen **reflective DLL loader** verwandeln:
- Biete eine minimale UI / einen Menüeintrag an (z. B. "LoadDLL").
- Akzeptiere einen **Dateipfad** oder eine **URL**, um eine Payload-DLL zu beziehen.
- Binde die DLL reflektiv in den aktuellen Prozess ein und rufe einen exportierten Entry-Point auf (z. B. eine Loader-Funktion in der geladenen DLL).
- Vorteil: Wiederverwendung eines harmlos wirkenden GUI-Prozesses statt das Starten eines neuen Loaders; die Payload erbt die Integrität von `notepad++.exe` (einschließlich erhöhter Kontexte).
- Nachteile: Das Ablegen einer **nicht signierten Plugin-DLL** auf der Festplatte ist auffällig; erwäge, vorhandene vertrauenswürdige Plugins zu missbrauchen (piggybacking), falls vorhanden.

## Erkennungs- und Härtungshinweise
- Blockiere oder überwache Schreibzugriffe in Notepad++-Plugin-Verzeichnisse (einschließlich portabler Kopien in Benutzerprofilen); aktiviere Controlled Folder Access oder Application Allowlisting.
- Melde neue **nicht signierte DLLs** unter `plugins` sowie ungewöhnliche **Child-Prozesse/Netzwerkaktivität** von `notepad++.exe`.
- Erzwinge die Installation von Plugins ausschließlich über **Plugins Admin** und beschränke die Ausführung portabler Kopien aus nicht vertrauenswürdigen Pfaden.

## Referenzen
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
