# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ wird beim Start **jede Plugin-DLL, die in seinen `plugins`-Unterordnern gefunden wird, autoloaden**. Das Ablegen eines bösartigen Plugins in einer **beschreibbaren Notepad++-Installation** ermöglicht Codeausführung innerhalb von `notepad++.exe` bei jedem Start des Editors, was für **persistence**, eine unauffällige **initial execution** oder als **in-process loader** missbraucht werden kann, falls der Editor erhöht gestartet wird.

## Writable plugin locations
- Standardinstall: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (erfordert normalerweise Adminrechte zum Schreiben).
- Schreibbare Optionen für niedrig privilegierte Operatoren:
- Verwende die **portable Notepad++ build** in einem benutzerschreibbaren Ordner.
- Kopiere `C:\Program Files\Notepad++` in einen benutzerkontrollierten Pfad (z. B. `%LOCALAPPDATA%\npp\`) und starte `notepad++.exe` von dort.
- Jedes Plugin erhält seinen eigenen Unterordner unter `plugins` und wird beim Start automatisch geladen; Menüeinträge erscheinen unter **Plugins**.

## Plugin load points (execution primitives)
Notepad++ erwartet bestimmte **exportierte Funktionen**. Diese werden alle während der Initialisierung aufgerufen und bieten mehrere Ausführungsflächen:
- **`DllMain`** — wird unmittelbar beim DLL-Load ausgeführt (erster Ausführungspunkt).
- **`setInfo(NppData)`** — wird einmal beim Laden aufgerufen, um Notepad++-Handles bereitzustellen; typischer Ort, um Menüeinträge zu registrieren.
- **`getName()`** — gibt den im Menü angezeigten Plugin-Namen zurück.
- **`getFuncsArray(int *nbF)`** — gibt Menübefehle zurück; selbst wenn leer, wird es beim Start aufgerufen.
- **`beNotified(SCNotification*)`** — empfängt Editor-Ereignisse (Datei öffnen/ändern, UI-Ereignisse) für fortlaufende Trigger.
- **`messageProc(UINT, WPARAM, LPARAM)`** — Nachrichten-Handler, nützlich für größere Datenaustausche.
- **`isUnicode()`** — Kompatibilitäts-Flag, das beim Laden geprüft wird.

Die meisten Exporte können als **Stubs** implementiert werden; Ausführung kann aus `DllMain` oder einem der oben genannten Callbacks während des Autoloads erfolgen.

## Minimal malicious plugin skeleton
Kompiliere eine DLL mit den erwarteten Exporten und platziere sie in `plugins\\MyNewPlugin\\MyNewPlugin.dll` in einem schreibbaren Notepad++-Ordner:
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. Erstelle die DLL (Visual Studio/MinGW).
2. Erstelle den Plugin-Unterordner unter `plugins` und lege die DLL hinein.
3. Starte Notepad++ neu; die DLL wird automatisch geladen, `DllMain` und nachfolgende Callbacks werden ausgeführt.

## Reflective loader plugin pattern
A weaponized plugin can turn Notepad++ into a **reflective DLL loader**:
- Stelle einen minimalen UI-/Menueintrag bereit (z. B. "LoadDLL").
- Akzeptiere einen **file path** oder **URL**, um eine payload DLL zu beziehen.
- Reflectively map the DLL into the current process and invoke an exported entry point (e.g., a loader function inside the fetched DLL).
- Vorteil: Wiederverwendung eines harmlos aussehenden GUI-Prozesses statt das Erzeugen eines neuen Loaders; die payload übernimmt die Integrität von `notepad++.exe` (einschließlich erhöhter Kontexte).
- Abwägungen: Das Ablegen einer **unsigned plugin DLL** auf der Festplatte ist auffällig; erwäge, auf vorhandenen vertrauenswürdigen Plugins zu piggybacken, falls vorhanden.

## Erkennungs- und Härtungshinweise
- Blockiere oder überwache **writes to Notepad++ plugin directories** (einschließlich portabler Kopien in Benutzerprofilen); aktiviere Controlled Folder Access oder Application Allowlisting.
- Alarmiere bei **new unsigned DLLs** unter `plugins` und ungewöhnlichen **child processes/network activity** von `notepad++.exe`.
- Erzwinge die Plugin-Installation ausschließlich über **Plugins Admin** und beschränke die Ausführung portabler Kopien aus nicht vertrauenswürdigen Pfaden.

## Referenzen
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
