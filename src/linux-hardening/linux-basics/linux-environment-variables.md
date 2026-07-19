# Zmienne środowiskowe systemu Linux

{{#include ../../banners/hacktricks-training.md}}

## Zmienne globalne

Zmienne globalne **będą** dziedziczone przez **procesy potomne**.

Możesz utworzyć zmienną globalną dla bieżącej sesji, wykonując:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Ta zmienna będzie dostępna w bieżących sesjach i ich procesach potomnych.

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
Zawartość `/proc/*/environ` jest **rozdzielona znakami NUL**, dlatego te warianty są zwykle łatwiejsze do odczytania:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Jeśli szukasz **credentials** lub **interesującej konfiguracji usług** w odziedziczonych środowiskach, sprawdź również [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Typowe zmienne

Źródło: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – ekran używany przez **X**. Ta zmienna jest zwykle ustawiona na **:0.0**, co oznacza pierwszy ekran na bieżącym komputerze.
- **EDITOR** – preferowany edytor tekstu użytkownika.
- **HISTFILESIZE** – maksymalna liczba wierszy zawartych w pliku historii.
- **HISTSIZE** – liczba wierszy dodawanych do pliku historii po zakończeniu sesji użytkownika.
- **HOME** – katalog domowy użytkownika.
- **HOSTNAME** – nazwa hosta komputera.
- **LANG** – bieżący język.
- **MAIL** – lokalizacja spoola pocztowego użytkownika. Zwykle **/var/spool/mail/USER**.
- **MANPATH** – lista katalogów, w których należy szukać stron podręcznika.
- **OSTYPE** – typ systemu operacyjnego.
- **PS1** – domyślny prompt w bashu.
- **PATH** – przechowuje ścieżki wszystkich katalogów zawierających pliki binarne, które chcesz uruchamiać przez podanie samej nazwy pliku, a nie ścieżki względnej lub bezwzględnej.
- **PWD** – bieżący katalog roboczy.
- **SHELL** – ścieżka do bieżącej powłoki poleceń, na przykład **/bin/bash**.
- **TERM** – bieżący typ terminala, na przykład **xterm**.
- **TZ** – strefa czasowa użytkownika.
- **USER** – bieżąca nazwa użytkownika.

## Interesujące zmienne na potrzeby hacking

Nie każda zmienna jest równie użyteczna. Z perspektywy ofensywnej priorytetowo traktuj zmienne, które zmieniają **ścieżki wyszukiwania**, **pliki startowe**, **zachowanie dynamicznego linkera** lub **audytowanie/rejestrowanie**.

### **HISTFILESIZE**

Zmień **wartość tej zmiennej na 0**, aby po **zakończeniu sesji** **plik historii** (\~/.bash_history) został **obcięty do 0 wierszy**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Zmień **wartość tej zmiennej na 0**, aby polecenia **nie były przechowywane w historii w pamięci** i nie były zapisywane z powrotem w **pliku historii** (\~/.bash_history).
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

Wskaż **plik historii** na **`/dev/null`** lub całkowicie go usuń. Zwykle jest to bardziej niezawodne niż sama zmiana rozmiaru historii.
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

- `all_proxy`: domyślny proxy dla narzędzi/protokołów, które go respektują.
- `no_proxy`: lista wyjątków (hosty/domeny/CIDR), które powinny łączyć się bezpośrednio.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Można używać zarówno wariantów pisanych małymi, jak i wielkimi literami, zależnie od narzędzia (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Procesy będą ufać certyfikatom wskazanym w **tych zmiennych środowiskowych**. Jest to przydatne, aby narzędzia takie jak **`curl`**, **`git`**, klienci HTTP języka Python lub menedżery pakietów ufały CA kontrolowanemu przez atakującego (na przykład aby proxy przechwytujące wyglądało na legalne).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Jeśli uprzywilejowany wrapper/skrypt wykonuje polecenia **bez ścieżek bezwzględnych**, wygrywa **pierwszy katalog kontrolowany przez atakującego** w zmiennej `PATH`. To mechanizm stojący za wieloma **PATH hijacks** w `sudo`, zadaniach cron, wrapperach powłoki i niestandardowych helperach SUID. Szukaj `env_keep+=PATH`, słabego `secure_path` lub wrapperów, które wywołują `tar`, `service`, `cp`, `python` itd. po nazwie.
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

`HOME` to nie tylko odwołanie do katalogu: wiele narzędzi automatycznie ładuje **dotfiles**, **plugins** i **konfigurację użytkownika** z `$HOME` lub `$XDG_CONFIG_HOME`. Jeśli uprzywilejowany workflow zachowuje te wartości, **config injection** może być łatwiejszy niż binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Interesujące cele obejmują `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` oraz pliki specyficzne dla narzędzi, takie jak `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Zmienne te wpływają na **dynamic linker**:

- `LD_PRELOAD`: wymusza załadowanie dodatkowych shared objects w pierwszej kolejności.
- `LD_LIBRARY_PATH`: dodaje katalogi wyszukiwania bibliotek na początku listy.
- `LD_AUDIT`: ładuje biblioteki audytora, które monitorują ładowanie bibliotek i rozwiązywanie symboli.

Są niezwykle cenne w kontekście **hooking**, **instrumentation** i **privilege escalation**, jeśli uprzywilejowane polecenie zachowuje te zmienne. W trybie **secure-execution** (`AT_SECURE`, np. setuid/setgid/capabilities) loader usuwa lub ogranicza wiele z tych zmiennych. Jednak błędy parsera na tym wczesnym etapie działania loadera nadal mają duży wpływ, ponieważ występują **przed** uruchomieniem programu docelowego.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` zmienia wczesne zachowanie glibc (na przykład ustawienia allocator) i jest bardzo przydatne w laboratoriach exploitów. Ma również znaczenie z perspektywy bezpieczeństwa, ponieważ **dynamiczny loader parsuje ją bardzo wcześnie**. Luka **Looney Tunables** z 2023 roku była dobrym przypomnieniem, że pojedyncza zmienna środowiskowa parsowana przez loader może stać się **prymitywem lokalnej eskalacji uprawnień** przeciwko programom SUID.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Jeśli **Bash** jest uruchamiany **nieinteraktywnie**, sprawdza `BASH_ENV` i ładuje ten plik przed uruchomieniem docelowego skryptu. Gdy Bash jest wywoływany jako `sh` lub w interaktywnym trybie POSIX, może być również sprawdzana zmienna `ENV`. Jest to klasyczny sposób na przekształcenie wrappera powłoki w code execution, jeśli środowisko jest kontrolowane przez atakującego.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash sam wyłącza te pliki startowe, gdy **rzeczywiste/efektywne identyfikatory różnią się**, chyba że użyto `-p`, więc dokładne zachowanie zależy od sposobu, w jaki wrapper uruchamia powłokę.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Te zmienne zmieniają sposób uruchamiania Pythona:

- `PYTHONPATH`: dodaje ścieżki wyszukiwania importów na początku listy.
- `PYTHONHOME`: zmienia lokalizację drzewa biblioteki standardowej.
- `PYTHONSTARTUP`: wykonuje plik przed wyświetleniem interaktywnego promptu.
- `PYTHONINSPECT=1`: przełącza do trybu interaktywnego po zakończeniu działania skryptu.

Są przydatne w przypadku skryptów maintenance, debuggerów, powłok i wrapperów, które wywołują Pythona ze środowiskiem kontrolowanym przez użytkownika. `python -E` i `python -I` ignorują wszystkie zmienne `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT i PERL5LIB**

Perl ma równie przydatne zmienne uruchomieniowe:

- `PERL5LIB`: dodaje katalogi bibliotek na początku ścieżki.
- `PERL5OPT`: wstrzykuje przełączniki tak, jakby znajdowały się w każdym wierszu poleceń `perl`.

Może to wymusić **automatyczne ładowanie modułów** lub zmienić zachowanie interpretera, zanim docelowy skrypt wykona cokolwiek istotnego. Perl ignoruje te zmienne w kontekstach **taint / setuid / setgid**, ale nadal mają one duże znaczenie w przypadku zwykłych wrapperów uruchamianych jako root, zadań CI, installerów oraz niestandardowych reguł sudoers.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
Ta sama idea pojawia się w innych runtime'ach (`RUBYOPT`, `NODE_OPTIONS` itd.): za każdym razem, gdy interpreter jest uruchamiany przez uprzywilejowany wrapper, szukaj zmiennych środowiskowych, które modyfikują **ładowanie modułów** lub **zachowanie podczas uruchamiania**.

Z perspektywy post-exploitation pamiętaj również, że dziedziczone środowiska często zawierają **credentials**, **ustawienia proxy**, **service tokens** lub **cloud keys**. Sprawdź [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md), aby poznać sposoby wyszukiwania `/proc/<PID>/environ` oraz `Environment=` w `systemd`.

### PS1

Zmień wygląd swojego promptu.

[**To jest przykład**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: To jest przykład](<../images/image (897).png>)

Zwykły użytkownik:

![PERL5OPT & PERL5LIB - PS1: Jeden, dwa i trzy zadania uruchomione w tle](<../images/image (740).png>)

Jedno, dwa i trzy zadania uruchomione w tle:

![PERL5OPT & PERL5LIB - PS1: Jedno, dwa i trzy zadania uruchomione w tle](<../images/image (145).png>)

Jedno zadanie w tle, jedno zatrzymane, a ostatnie polecenie nie zakończyło się poprawnie:

![PERL5OPT & PERL5LIB - PS1: Jedno zadanie w tle, jedno zatrzymane, a ostatnie polecenie nie zakończyło się poprawnie](<../images/image (715).png>)

## References

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../../banners/hacktricks-training.md}}
