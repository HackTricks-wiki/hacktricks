# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Το Notepad++ θα **autoload every plugin DLL found under its `plugins` subfolders** κατά την εκκίνηση. Τοποθετώντας ένα κακόβουλο plugin σε οποιαδήποτε **writable Notepad++ installation** δίνει code execution μέσα στο `notepad++.exe` κάθε φορά που ανοίγει ο επεξεργαστής, κάτι που μπορεί να καταχραστεί για **persistence**, stealthy **initial execution**, ή ως **in-process loader** αν ο επεξεργαστής ξεκινήσει elevated.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (συνήθως απαιτεί admin για εγγραφή).
- Επιλογές εγγραφής για χρήστες με χαμηλά προνόμια:
- Χρησιμοποιήστε το **portable Notepad++ build** σε ένα φάκελο όπου ο χρήστης έχει δυνατότητα εγγραφής.
- Αντιγράψτε `C:\Program Files\Notepad++` σε ένα user-controlled path (π.χ., `%LOCALAPPDATA%\npp\`) και τρέξτε το `notepad++.exe` από εκεί.
- Κάθε plugin παίρνει τον δικό του υποφάκελο κάτω από το `plugins` και φορτώνεται αυτόματα κατά την εκκίνηση· οι καταχωρήσεις μενού εμφανίζονται κάτω από **Plugins**.

## Plugin load points (execution primitives)
Το Notepad++ περιμένει συγκεκριμένες **exported functions**. Αυτές καλούνται όλες κατά την αρχικοποίηση, παρέχοντας πολλαπλές επιφάνειες εκτέλεσης:
- **`DllMain`** — τρέχει αμέσως κατά τη φόρτωση της DLL (πρώτο σημείο εκτέλεσης).
- **`setInfo(NppData)`** — καλείται μία φορά κατά τη φόρτωση για να παρέχει Notepad++ handles; τυπικό σημείο για την εγγραφή καταχωρήσεων μενού.
- **`getName()`** — επιστρέφει το όνομα του plugin που εμφανίζεται στο μενού.
- **`getFuncsArray(int *nbF)`** — επιστρέφει τις εντολές μενού· ακόμα και αν είναι κενή, καλείται κατά την εκκίνηση.
- **`beNotified(SCNotification*)`** — λαμβάνει γεγονότα του editor (άνοιγμα/αλλαγή αρχείου, UI events) για συνεχή ενεργοποιήσεις.
- **`messageProc(UINT, WPARAM, LPARAM)`** — χειριστής μηνυμάτων, χρήσιμος για ανταλλαγές μεγαλύτερων δεδομένων.
- **`isUnicode()`** — flag συμβατότητας που ελέγχεται κατά τη φόρτωση.

Τα περισσότερα exports μπορούν να υλοποιηθούν ως **stubs**· η εκτέλεση μπορεί να συμβεί από το `DllMain` ή από οποιοδήποτε callback παραπάνω κατά το autoload.

## Minimal malicious plugin skeleton
Μεταγλωττίστε ένα DLL με τα αναμενόμενα exports και τοποθετήστε το στο `plugins\\MyNewPlugin\\MyNewPlugin.dll` κάτω από έναν writable Notepad++ φάκελο:
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
2. Δημιουργήστε τον υποφάκελο plugin κάτω από `plugins` και τοποθετήστε το DLL μέσα.
3. Επανεκκινήστε το Notepad++; το DLL φορτώνεται αυτόματα, εκτελώντας τη `DllMain` και τα επακόλουθα callbacks.

## Reflective loader plugin pattern
Ένα κακόβουλο plugin μπορεί να μετατρέψει το Notepad++ σε **reflective DLL loader**:
- Παρουσιάστε μια ελάχιστη εγγραφή UI/μενού (π.χ., "LoadDLL").
- Αποδεχτείτε ένα **file path** ή **URL** για να ανακτήσετε ένα payload DLL.
- Reflectively map the DLL into the current process and invoke an exported entry point (e.g., a loader function inside the fetched DLL).
- Πλεονέκτημα: επαναχρησιμοποίηση μιας GUI διεργασίας που φαίνεται ακίνδυνη αντί να ξεκινήσει ένας νέος loader· το payload κληρονομεί την ακεραιότητα του `notepad++.exe` (συμπεριλαμβανομένων περιβαλλόντων με αυξημένα προνόμια).
- Αντισταθμίσεις: η εγγραφή ενός **unsigned plugin DLL** στον δίσκο είναι θορυβώδης· σκεφτείτε να εκμεταλλευτείτε υπάρχοντα trusted plugins αν υπάρχουν.

## Σημειώσεις ανίχνευσης και σκληραγώγησης
- Αποκλείστε ή παρακολουθήστε **writes to Notepad++ plugin directories** (συμπεριλαμβανομένων portable αντιγράφων στα προφίλ χρηστών)· ενεργοποιήστε controlled folder access ή application allowlisting.
- Ειδοποιήστε για **new unsigned DLLs** κάτω από `plugins` και ασυνήθη **child processes/network activity** από `notepad++.exe`.
- Επιβάλετε την εγκατάσταση plugin μέσω **Plugins Admin** μόνο, και περιορίστε την εκτέλεση portable αντιγράφων από μη αξιόπιστες διαδρομές.

## References
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
