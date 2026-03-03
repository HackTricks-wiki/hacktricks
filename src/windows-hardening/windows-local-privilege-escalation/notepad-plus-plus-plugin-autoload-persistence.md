# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ will **autoload every plugin DLL found under its `plugins` subfolders** on launch. Dropping a malicious plugin into any **writable Notepad++ installation** gives code execution inside `notepad++.exe` every time the editor starts, which can be abused for **persistence**, stealthy **initial execution**, or as an **in-process loader** if the editor is launched elevated.

## Posizioni dei plugin scrivibili
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (di solito richiede i privilegi di admin per la scrittura).
- Opzioni scrivibili per operatori a basso privilegio:
- Use the **portable Notepad++ build** in a user-writable folder.
- Copy `C:\Program Files\Notepad++` to a user-controlled path (e.g., `%LOCALAPPDATA%\npp\`) and run `notepad++.exe` from there.
- Each plugin gets its own subfolder under `plugins` and is loaded automatically at startup; menu entries appear under **Plugins**.

## Plugin load points (execution primitives)
Notepad++ expects specific **exported functions**. These are all called during initialization, giving multiple execution surfaces:
- **`DllMain`** — viene eseguito immediatamente al caricamento della DLL (primo punto di esecuzione).
- **`setInfo(NppData)`** — chiamata una volta al caricamento per fornire gli handle di Notepad++; luogo tipico per registrare voci di menu.
- **`getName()`** — restituisce il nome del plugin visualizzato nel menu.
- **`getFuncsArray(int *nbF)`** — restituisce i comandi del menu; anche se vuoto, viene chiamato durante l'avvio.
- **`beNotified(SCNotification*)`** — riceve eventi dell'editor (apertura/modifica file, eventi UI) per trigger continui.
- **`messageProc(UINT, WPARAM, LPARAM)`** — gestore dei messaggi, utile per scambi di dati più ampi.
- **`isUnicode()`** — flag di compatibilità verificato al caricamento.

La maggior parte delle export può essere implementata come **stubs**; l'esecuzione può avvenire da `DllMain` o qualsiasi callback sopra durante l'autoload.

## Scheletro minimo di plugin malevolo
Compile a DLL with the expected exports and place it in `plugins\\MyNewPlugin\\MyNewPlugin.dll` under a writable Notepad++ folder:
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

## Reflective loader plugin pattern
A weaponized plugin può trasformare Notepad++ in un **reflective DLL loader**:
- Presenta un'interfaccia minima/voce di menu (es., "LoadDLL").
- Accetta un **file path** o **URL** per recuperare una DLL payload.
- Reflectively mappa la DLL nel processo corrente e invoca un entry point esportato (es., una loader function all'interno della DLL recuperata).
- Vantaggi: riutilizzare un processo GUI dall'aspetto benigno invece di avviare un nuovo loader; la payload eredita l'integrità di `notepad++.exe` (inclusi contesti elevati).
- Svantaggi: droppare una **unsigned plugin DLL** su disco è rumoroso; considera il piggybacking su plugin attendibili esistenti se presenti.

## Note di rilevamento e hardening
- Bloccare o monitorare le **writes to Notepad++ plugin directories** (incluse le copie portable nei profili utente); abilitare controlled folder access o application allowlisting.
- Segnalare **new unsigned DLLs** sotto `plugins` e attività anomale di **child processes/network activity** da `notepad++.exe`.
- Forzare l'installazione dei plugin solo tramite **Plugins Admin**, e limitare l'esecuzione di copie portable da percorsi non attendibili.

## Riferimenti
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
