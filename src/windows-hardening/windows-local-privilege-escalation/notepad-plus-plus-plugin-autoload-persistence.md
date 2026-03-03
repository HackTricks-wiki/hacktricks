# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ caricherà **automaticamente ogni plugin DLL trovata nelle sue sottocartelle `plugins`** all'avvio. Posizionare un plugin maligno in qualsiasi **installazione di Notepad++ scrivibile** consente code execution all'interno di `notepad++.exe` ogni volta che l'editor viene avviato, sfruttabile per **persistence**, una **initial execution** stealthy, o come **in-process loader** se l'editor viene eseguito con privilegi elevati.

## Posizioni plugin scrivibili
- Installazione standard: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (di solito richiede privilegi admin per scrivere).
- Opzioni scrivibili per operatori a basso privilegio:
- Usa la **portable Notepad++ build** in una cartella scrivibile dall'utente.
- Copia `C:\Program Files\Notepad++` in un percorso controllato dall'utente (es., `%LOCALAPPDATA%\npp\`) e avvia `notepad++.exe` da lì.
- Ogni plugin ottiene la propria sottocartella sotto `plugins` ed è caricato automaticamente all'avvio; le voci di menu appaiono sotto **Plugins**.

## Plugin load points (execution primitives)
Notepad++ si aspetta specifiche **exported functions**. Tutte vengono chiamate durante l'inizializzazione, offrendo multiple superfici di esecuzione:
- **`DllMain`** — viene eseguito immediatamente al caricamento della DLL (primo punto di esecuzione).
- **`setInfo(NppData)`** — chiamato una volta al load per fornire gli handle di Notepad++; punto tipico per registrare voci di menu.
- **`getName()`** — restituisce il nome del plugin mostrato nel menu.
- **`getFuncsArray(int *nbF)`** — restituisce i comandi di menu; anche se vuoto, viene chiamato all'avvio.
- **`beNotified(SCNotification*)`** — riceve eventi dell'editor (apertura/modifica file, eventi UI) per trigger continui.
- **`messageProc(UINT, WPARAM, LPARAM)`** — gestore di messaggi, utile per scambi di dati più ampi.
- **`isUnicode()`** — flag di compatibilità verificato al load.

La maggior parte delle export può essere implementata come **stubs**; l'esecuzione può avvenire da `DllMain` o da qualsiasi callback sopra durante l'autoload.

## Scheletro minimo di plugin malevolo
Compila una DLL con le exports attese e posizionala in `plugins\\MyNewPlugin\\MyNewPlugin.dll` sotto una cartella Notepad++ scrivibile:
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
2. Crea la sottocartella plugin sotto `plugins` e inserisci la DLL al suo interno.
3. Riavvia Notepad++; la DLL viene caricata automaticamente, eseguendo `DllMain` e le callback successive.

## Reflective loader plugin pattern
A weaponized plugin can turn Notepad++ into a **reflective DLL loader**:
- Presenta una voce UI/menu minima (e.g., "LoadDLL").
- Accetta un **file path** o **URL** per recuperare una payload DLL.
- Reflectively map the DLL nel processo corrente e invoca un exported entry point (e.g., una loader function all'interno della DLL recuperata).
- Benefit: riutilizzare un processo GUI dall'aspetto benigno invece di spawnare un nuovo loader; il payload eredita l'integrità di `notepad++.exe` (inclusi i contesti elevati).
- Trade-offs: lasciare su disco una **unsigned plugin DLL** è rumoroso; considera il piggybacking su trusted plugins esistenti se presenti.

## Note di rilevamento e hardening
- Blocca o monitora le **scritture nelle directory dei plugin di Notepad++** (incluse le copie portable nei profili utente); abilita Controlled Folder Access o application allowlisting.
- Genera alert su **nuove unsigned DLLs** nella cartella `plugins` e su attività insolite di **child processes/network** originate da `notepad++.exe`.
- Imporre l'installazione dei plugin solo tramite **Plugins Admin**, e limitare l'esecuzione delle copie portable da percorsi non trusted.

## Riferimenti
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
