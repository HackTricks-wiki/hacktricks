# Persistence & εκτέλεση μέσω αυτόματης φόρτωσης plugin του Notepad++

{{#include ../../banners/hacktricks-training.md}}

Το Notepad++ **φορτώνει αυτόματα κάθε DLL plugin που βρίσκεται στους υποφακέλους `plugins`** κατά την εκκίνηση. Η τοποθέτηση ενός κακόβουλου plugin σε οποιαδήποτε **εγγράψιμη εγκατάσταση του Notepad++** επιτρέπει την εκτέλεση κώδικα μέσα στο `notepad++.exe` κάθε φορά που ξεκινά ο editor. Αυτό μπορεί να αξιοποιηθεί για **persistence**, stealthy **initial execution** ή ως **in-process loader**, αν ο editor εκκινηθεί με αυξημένα δικαιώματα.<sup>[[1]](#references)</sup>

Από το **Notepad++ 7.6+**, η αναμενόμενη διάταξη για χειροκίνητη εγκατάσταση είναι **ένας υποφάκελος ανά plugin** (`plugins\<PluginName>\<PluginName>.dll`). Σε **portable mode** (όταν υπάρχει το `doLocalConf.xml` δίπλα στο `notepad++.exe`), ολόκληρο το δέντρο της εφαρμογής παραμένει τοπικά σε αυτόν τον κατάλογο, με αποτέλεσμα τα αντιγραμμένα bundles εργαλείων διαχείρισης να αποτελούν συχνά μια εύκολα εγγράψιμη από τον χρήστη επιφάνεια εκτέλεσης.<sup>[[2]](#references)</sup>

## Εγγράψιμες τοποθεσίες plugin

- Τυπική εγκατάσταση: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (συνήθως απαιτούνται δικαιώματα διαχειριστή για εγγραφή).<sup>[[1]](#references)</sup>
- Εγγράψιμες επιλογές για χρήστες με χαμηλά δικαιώματα:<sup>[[1]](#references)</sup>
  - Χρησιμοποιήστε τη **portable έκδοση του Notepad++** σε φάκελο όπου έχετε δικαίωμα εγγραφής.
  - Αντιγράψτε το `C:\Program Files\Notepad++` σε μια διαδρομή που ελέγχετε (π.χ. `%LOCALAPPDATA%\npp\`) και εκτελέστε το `notepad++.exe` από εκεί.
  - Αναζητήστε **bundles εργαλείων διαχείρισης**, αποσυμπιεσμένα αντίγραφα zip ή toolkits του help desk που περιέχουν ήδη το `doLocalConf.xml` και βρίσκονται εκτός του `Program Files`.
- Κάθε plugin έχει τον δικό του υποφάκελο κάτω από το `plugins` και φορτώνεται αυτόματα κατά την εκκίνηση· οι καταχωρίσεις του μενού εμφανίζονται στην ενότητα **Plugins**.<sup>[[2]](#references)</sup>

Γρήγορος αρχικός έλεγχος:

```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```

## Σημεία φόρτωσης plugin (execution primitives)
Το Notepad++ αναμένει συγκεκριμένες **exported functions**. Όλες καλούνται κατά την αρχικοποίηση, παρέχοντας πολλαπλές επιφάνειες εκτέλεσης:<sup>[[1]](#references)</sup>
- **`DllMain`** — εκτελείται αμέσως κατά τη φόρτωση του DLL (πρώτο σημείο εκτέλεσης).
- **`setInfo(NppData)`** — καλείται μία φορά κατά τη φόρτωση για την παροχή των handles του Notepad· συνήθως εδώ καταχωρίζονται τα στοιχεία μενού.
- **`getName()`** — επιστρέφει το όνομα του plugin που εμφανίζεται στο μενού.
- **`getFuncsArray(int *nbF)`** — επιστρέφει τις εντολές του μενού· ακόμη κι αν είναι κενή, καλείται κατά την εκκίνηση.
- **`beNotified(SCNotification*)`** — λαμβάνει συμβάντα Notepad++ / Scintilla (χρήσιμο για την αναβολή των payloads μέχρι μια ενέργεια χρήστη ή ένα συμβάν του editor).
- **`messageProc(UINT, WPARAM, LPARAM)`** — χειριστής μηνυμάτων, χρήσιμος για μεγαλύτερες ανταλλαγές δεδομένων.
- **`isUnicode()`** — flag συμβατότητας που ελέγχεται κατά τη φόρτωση.

Τα περισσότερα exports μπορούν να υλοποιηθούν ως **stubs**· η εκτέλεση μπορεί να γίνει από το `DllMain` ή οποιοδήποτε callback κατά το autoload.

## Ελάχιστος σκελετός κακόβουλου plugin
Κάντε compile ένα DLL με τα αναμενόμενα exports και τοποθετήστε το στο `plugins\\MyNewPlugin\\MyNewPlugin.dll` μέσα σε έναν εγγράψιμο φάκελο του Notepad++:<sup>[[1]](#references)</sup>

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
2. Δημιουργήστε τον υποφάκελο του plugin μέσα στο `plugins` και τοποθετήστε εκεί το DLL.
3. Επανεκκινήστε το Notepad++; το DLL φορτώνεται αυτόματα, εκτελώντας το `DllMain` και τα επόμενα callbacks.

## Μοτίβο trigger χαμηλού θορύβου μέσω `beNotified`
Για λόγους OPSEC, πολλά payloads δεν πρέπει να ενεργοποιούνται από το `DllMain`. Μια πιο διακριτική προσέγγιση είναι να αφήσετε το plugin να φορτωθεί κανονικά και έπειτα να εκτελεστεί μόνο μετά από ένα ρεαλιστικό συμβάν του editor, όπως η **ολοκλήρωση της εκκίνησης**, η **ενεργοποίηση buffer** ή ο **πρώτος χαρακτήρας που πληκτρολογείται**.

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

Αυτό ταιριάζει καλύτερα με τη δημόσια έρευνα offensive hacking απ’ ό,τι ένα θορυβώδες beacon στο `DllMain`: η DLL εξακολουθεί να φορτώνεται αυτόματα κατά την εκκίνηση, αλλά η κακόβουλη ενέργεια καθυστερεί μέχρι να φαίνεται ότι το Notepad++ χρησιμοποιείται πραγματικά.

## Χρήση του καταλόγου ρυθμίσεων των plugin ως δευτερεύοντος αποθηκευτικού χώρου
Το Notepad++ εκθέτει το `NPPM_GETPLUGINSCONFIGDIR`, το οποίο επιστρέφει τον **κατάλογο ρυθμίσεων των plugin του τρέχοντος χρήστη**.<sup>[[3]](#references)</sup> Ένα κακόβουλο plugin μπορεί να το χρησιμοποιήσει ώστε το DLL που βρίσκεται στον δίσκο να παραμένει ελάχιστο, ενώ αποθηκεύει κρυπτογραφημένες ρυθμίσεις, payloads σε αναμονή ή αρχεία tasking σε μια διαδρομή που μοιάζει με τη συνηθισμένη κατάσταση των plugin.

```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```

Λειτουργικά, αυτό είναι χρήσιμο όταν θέλετε:
- μια μικροσκοπική DLL bootstrap που φορτώνεται αυτόματα·
- tasking ανά χρήστη χωρίς να χρειάζεται να τροποποιήσετε ξανά το κύριο binary του plugin·
- να διαχωρίσετε το **autoload trigger** από το βαρύτερο δεύτερο στάδιο.

## Μοτίβο plugin reflective loader
Ένα weaponized plugin μπορεί να μετατρέψει το Notepad++ σε **reflective DLL loader**:<sup>[[1]](#references)</sup>
- Παρουσιάζει ένα ελάχιστο UI/στοιχείο μενού (π.χ., "LoadDLL").
- Δέχεται μια **διαδρομή αρχείου** ή ένα **URL** για να λάβει ένα payload DLL.
- Κάνει reflective mapping της DLL στην τρέχουσα διεργασία και καλεί ένα exported entry point (π.χ., μια loader function μέσα στο DLL που λήφθηκε).
- Πλεονέκτημα: επαναχρησιμοποιεί μια φαινομενικά αθώα διεργασία GUI αντί να δημιουργήσει νέο loader· το payload κληρονομεί το επίπεδο ακεραιότητας του `notepad++.exe` (συμπεριλαμβανομένων των elevated contexts).
- Συμβιβασμοί: η εγγραφή μιας **unsigned plugin DLL** στον δίσκο είναι εμφανής· μια πρακτική παραλλαγή είναι να χρησιμοποιείται το plugin που φορτώνεται αυτόματα μόνο ως stub, ενώ το πραγματικό implant παραμένει κρυπτογραφημένο/σταδιακά αναπτυγμένο αλλού.

## Σημειώσεις εντοπισμού και ενίσχυσης ασφάλειας
- Αποκλείστε ή παρακολουθήστε **εγγραφές στους καταλόγους plugin του Notepad++** (συμπεριλαμβανομένων των portable αντιγράφων στα προφίλ χρηστών)· ενεργοποιήστε την ελεγχόμενη πρόσβαση σε φακέλους ή τη λίστα επιτρεπόμενων εφαρμογών.
- Ειδοποιηθείτε για **νέα unsigned DLL** στον φάκελο `plugins`, αλλαγές σε portable δέντρα Notepad++ και ασυνήθιστες **child processes/δραστηριότητα δικτύου** από το `notepad++.exe`.
- Καταγράψτε τα νόμιμα plugin ως baseline και διερευνήστε κάθε νέα DLL που εξάγει το κανονικό interface plugin του Notepad++ αλλά δημιουργεί επίσης shells, PowerShell ή network beacons.
- Επιβάλετε την εγκατάσταση plugin αποκλειστικά μέσω του **Plugins Admin** και περιορίστε την εκτέλεση portable αντιγράφων από μη έμπιστες διαδρομές.

## References

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)
{{#include ../../banners/hacktricks-training.md}}
