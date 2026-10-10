# Notepad++ Plugin-Autoload-Persistenz & -Ausführung

{{#include ../../banners/hacktricks-training.md}}

Notepad++ lädt beim Start **automatisch jede Plugin-DLL aus seinen `plugins`-Unterordnern**. Eine schädliche Plugin-DLL in einem **beschreibbaren Notepad++-Installationsverzeichnis** abzulegen, ermöglicht bei jedem Start des Editors die Codeausführung innerhalb von `notepad++.exe`. Dies kann für **Persistenz**, eine unauffällige **Initialausführung** oder als **In-Process-Loader** missbraucht werden, wenn der Editor mit erhöhten Rechten gestartet wird.<sup>[[1]](#references)</sup>

Seit **Notepad++ 7.6+** erwartet die manuelle Installation **einen Unterordner pro Plugin** (`plugins\<PluginName>\<PluginName>.dll`). Im **Portable-Modus** (wenn `doLocalConf.xml` neben `notepad++.exe` vorhanden ist) bleibt der gesamte Anwendungsbaum in diesem Verzeichnis. Dadurch werden kopierte Tool-Bundles für Administratoren oft zu einer leicht beschreibbaren Ausführungsfläche für Benutzer.<sup>[[2]](#references)</sup>

## Beschreibbare Plugin-Verzeichnisse

- Standardinstallation: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (zum Schreiben sind normalerweise Administratorrechte erforderlich).<sup>[[1]](#references)</sup>
- Beschreibbare Optionen für Operatoren mit niedrigen Berechtigungen:<sup>[[1]](#references)</sup>
  - Den **portablen Notepad++-Build** in einem für Benutzer beschreibbaren Ordner verwenden.
  - `C:\Program Files\Notepad++` in einen benutzergesteuerten Pfad kopieren (z. B. `%LOCALAPPDATA%\npp\`) und `notepad++.exe` von dort ausführen.
  - Nach **Admin-Tool-Bundles**, entpackten ZIP-Kopien oder Helpdesk-Toolkits suchen, die bereits `doLocalConf.xml` enthalten und sich außerhalb von `Program Files` befinden.
- Jedes Plugin erhält einen eigenen Unterordner unter `plugins` und wird beim Start automatisch geladen; Menüeinträge erscheinen unter **Plugins**.<sup>[[2]](#references)</sup>

Schnelle Überprüfung:

```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```

## Plugin-Ladepunkte (Ausführungsprimitive)
Notepad++ erwartet bestimmte **exportierte Funktionen**. Diese werden alle während der Initialisierung aufgerufen und bieten dadurch mehrere Ausführungsflächen:<sup>[[1]](#references)</sup>
- **`DllMain`** — wird unmittelbar beim Laden der DLL ausgeführt (erster Ausführungspunkt).
- **`setInfo(NppData)`** — wird beim Laden einmal aufgerufen, um Notepad++-Handles bereitzustellen; typischerweise werden hier Menüeinträge registriert.
- **`getName()`** — gibt den im Menü angezeigten Plugin-Namen zurück.
- **`getFuncsArray(int *nbF)`** — gibt Menübefehle zurück; selbst wenn das Array leer ist, wird die Funktion beim Start aufgerufen.
- **`beNotified(SCNotification*)`** — empfängt Notepad++- / Scintilla-Ereignisse (nützlich, um Payloads bis zu einer Benutzeraktion oder einem Editorereignis zurückzustellen).
- **`messageProc(UINT, WPARAM, LPARAM)`** — Message-Handler, nützlich für umfangreichere Datenaustausche.
- **`isUnicode()`** — Kompatibilitäts-Flag, das beim Laden geprüft wird.

Die meisten Exporte können als **Stubs** implementiert werden; die Ausführung kann während des Autoloads über `DllMain` oder einen der oben genannten Callbacks erfolgen.

## Minimales bösartiges Plugin-Grundgerüst
Kompiliere eine DLL mit den erwarteten Exporten und lege sie unter `plugins\\MyNewPlugin\\MyNewPlugin.dll` in einem beschreibbaren Notepad++-Ordner ab:<sup>[[1]](#references)</sup>

```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```

1. Erstellen Sie die DLL (Visual Studio/MinGW).
2. Erstellen Sie den Plugin-Unterordner unter `plugins` und legen Sie die DLL darin ab.
3. Starten Sie Notepad++ neu; die DLL wird automatisch geladen und führt `DllMain` sowie nachfolgende Callbacks aus.

## Low-Noise-Trigger-Muster über `beNotified`
Aus OPSEC-Gründen sollten viele Payloads **nicht** in `DllMain` ausgelöst werden. Ein unauffälligeres Muster besteht darin, das Plugin fehlerfrei laden zu lassen und den Code erst nach einem realistischen Editor-Ereignis auszuführen, etwa nach dem **Abschluss des Starts**, der **Aktivierung eines Puffers** oder der **Eingabe des ersten Zeichens**.

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

Das entspricht der öffentlichen Offensive-Forschung besser als ein auffälliger `DllMain`-Beacon: Die DLL wird beim Start weiterhin automatisch geladen, aber die schädliche Aktion wird verzögert, bis Notepad++ tatsächlich in Gebrauch ist.

## Das Plugin-Konfigurationsverzeichnis als sekundären Speicher verwenden
Notepad++ stellt `NPPM_GETPLUGINSCONFIGDIR` bereit, das das **Plugin-Konfigurationsverzeichnis des aktuellen Benutzers** zurückgibt.<sup>[[3]](#references)</sup> Ein bösartiges Plugin kann dies nutzen, um die DLL auf dem Datenträger minimal zu halten und zugleich verschlüsselte Konfigurationen, gestaffelte Payloads oder Tasking-Dateien in einem Pfad abzulegen, der sich unauffällig in den normalen Plugin-Zustand einfügt.

```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```

Der Betrieb ist nützlich, wenn du Folgendes möchtest:
- eine kleine, automatisch geladene Bootstrap-DLL;
- Tasking pro Benutzer, ohne die Haupt-Plugin-Binärdatei erneut anzufassen;
- den **Autoload-Trigger** von der umfangreicheren zweiten Stufe trennen.

## Reflective loader plugin pattern
Ein weaponisiertes Plugin kann Notepad++ in einen **Reflective DLL loader** verwandeln:<sup>[[1]](#references)</sup>
- Eine minimale UI bzw. einen Menüeintrag anzeigen (z. B. „LoadDLL“).
- Einen **Dateipfad** oder eine **URL** akzeptieren, um eine Payload-DLL abzurufen.
- Die DLL reflective in den aktuellen Prozess laden und einen exportierten Einstiegspunkt aufrufen (z. B. eine Loader-Funktion in der abgerufenen DLL).
- Vorteil: einen harmlos wirkenden GUI-Prozess wiederverwenden, statt einen neuen Loader zu starten; die Payload übernimmt die Integrität von `notepad++.exe` (einschließlich erhöhter Kontexte).
- Nachteile: Das Ablegen einer **unsignierten Plugin-DLL** auf der Festplatte ist auffällig; eine praktische Variante besteht darin, das automatisch geladene Plugin nur als Stub zu verwenden und das eigentliche Implantat verschlüsselt bzw. gestaffelt an anderer Stelle bereitzuhalten.

## Hinweise zu Erkennung und Härtung
- Schreibzugriffe auf Notepad++-Plugin-Verzeichnisse blockieren oder überwachen (einschließlich portabler Kopien in Benutzerprofilen); Controlled Folder Access oder Application Allowlisting aktivieren.
- Bei **neuen unsignierten DLLs** unter `plugins`, Änderungen an portablen Notepad++-Verzeichnisbäumen sowie ungewöhnlichen **Child-Prozessen/Netzwerkaktivitäten** von `notepad++.exe` Alarm auslösen.
- Legitime Plugins als Baseline erfassen und alle neuen DLLs untersuchen, die zwar die normale Notepad++-Plugin-Schnittstelle exportieren, aber auch Shells oder PowerShell starten oder Netzwerk-Beacons senden.
- Die Plugin-Installation ausschließlich über **Plugins Admin** zulassen und die Ausführung portabler Kopien aus nicht vertrauenswürdigen Pfaden einschränken.

## References

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)
{{#include ../../banners/hacktricks-training.md}}
