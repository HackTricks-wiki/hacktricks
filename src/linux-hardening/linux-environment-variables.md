# Zmienne środowiskowe Linux

{{#include ../banners/hacktricks-training.md}}

## Zmienne globalne

Zmienne globalne **będą** dziedziczone przez **procesy potomne**.

Możesz utworzyć zmienną globalną dla bieżącej sesji, wykonując:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Ta zmienna będzie dostępna w Twojej bieżącej sesji oraz procesach potomnych.

Możesz **usunąć** zmienną, wykonując:
```bash
unset MYGLOBAL
```
## Zmienne lokalne

**Zmienne lokalne** mogą być **dostępne** tylko przez **bieżącą powłokę/skrypt**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Lista bieżących variables
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
Zawartość `/proc/*/environ` jest **rozdzielona znakiem NUL**, więc te warianty są zwykle łatwiejsze do odczytania:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Jeśli szukasz **credentials** lub **interesting service configuration** we inherited environments, sprawdź też [Linux Post Exploitation](linux-post-exploitation/README.md).

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – display używany przez **X**. Ta zmienna jest zwykle ustawiona na **:0.0**, co oznacza pierwszy display na bieżącym komputerze.
- **EDITOR** – preferowany edytor tekstu użytkownika.
- **HISTFILESIZE** – maksymalna liczba linii zawartych w pliku historii.
- **HISTSIZE** – liczba linii dodawanych do pliku historii, gdy użytkownik kończy swoją sesję
- **HOME** – twój katalog domowy.
- **HOSTNAME** – nazwa hosta komputera.
- **LANG** – twój bieżący język.
- **MAIL** – lokalizacja spool mail użytkownika. Zwykle **/var/spool/mail/USER**.
- **MANPATH** – lista katalogów, w których należy szukać stron manuala.
- **OSTYPE** – typ systemu operacyjnego.
- **PS1** – domyślny prompt w bash.
- **PATH** – przechowuje path wszystkich katalogów, które zawierają pliki binarne, które chcesz uruchamiać, podając tylko nazwę pliku, a nie ścieżkę względną lub bezwzględną.
- **PWD** – bieżący katalog roboczy.
- **SHELL** – ścieżka do bieżącej powłoki poleceń (na przykład **/bin/bash**).
- **TERM** – bieżący typ terminala (na przykład **xterm**).
- **TZ** – twoja strefa czasowa.
- **USER** – twoja bieżąca nazwa użytkownika.

## Interesting variables for hacking

Nie każda zmienna jest równie użyteczna. Z ofensywnej perspektywy priorytetowo traktuj zmienne, które zmieniają **search paths**, **startup files**, **dynamic linker behavior** lub **audit/logging**.

### **HISTFILESIZE**

Zmień **wartość tej zmiennej na 0**, aby gdy **zakończysz sesję** plik **history file** (\~/.bash_history) został **obcięty do 0 linii**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Zmień **wartość tej zmiennej na 0**, aby polecenia **nie były przechowywane w historii w pamięci** i nie były zapisywane z powrotem do **pliku historii** (\~/.bash_history).
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

Skieruj **plik historii** do **`/dev/null`** lub usuń go całkowicie. Zwykle jest to bardziej niezawodne niż samo zmienianie rozmiaru historii.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Procesy będą używać **proxy** zadeklarowanego tutaj, aby łączyć się z internetem przez **http lub https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: domyślny proxy dla narzędzi/protokołów, które go honorują.
- `no_proxy`: lista obejść (hosty/domeny/CIDRy), które powinny łączyć się bezpośrednio.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Zarówno wersje małymi, jak i wielkimi literami mogą być używane w zależności od narzędzia (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Procesy będą ufać certyfikatom wskazanym w **tych zmiennych env**. Jest to przydatne, aby narzędzia takie jak **`curl`**, **`git`**, klienci HTTP Pythona lub menedżery pakietów ufały CA kontrolowanemu przez atakującego (na przykład, aby interception proxy wyglądał na legalny).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Jeśli uprzywilejowany wrapper/skrypt wykonuje polecenia **bez absolutnych ścieżek**, **pierwszy katalog kontrolowany przez atakującego** w `PATH` wygrywa. To jest prymityw stojący za wieloma **PATH hijacks** w `sudo`, cron jobs, shell wrappers i niestandardowych helperach SUID. Szukaj `env_keep+=PATH`, słabego `secure_path` albo wrapperów, które wywołują `tar`, `service`, `cp`, `python` itp. po nazwie.
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
Aby zobaczyć pełne łańcuchy privilege-escalation wykorzystujące `PATH`, sprawdź [Linux Privilege Escalation](privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` to nie tylko odwołanie do katalogu: wiele narzędzi automatycznie ładuje **dotfiles**, **plugins** i **konfigurację per-user** z `$HOME` lub `$XDG_CONFIG_HOME`. Jeśli uprzywilejowany workflow zachowa te wartości, **config injection** może być łatwiejsze niż binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Interesujące cele obejmują `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` oraz pliki specyficzne dla narzędzi, takie jak `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Te zmienne wpływają na **dynamic linker**:

- `LD_PRELOAD`: wymusza, aby dodatkowe shared objects zostały załadowane jako pierwsze.
- `LD_LIBRARY_PATH`: dodaje katalogi wyszukiwania bibliotek na początek.
- `LD_AUDIT`: ładuje biblioteki audytujące, które obserwują ładowanie bibliotek i rozwiązywanie symboli.

Są one niezwykle cenne do **hooking**, **instrumentation** oraz **privilege escalation**, jeśli uprzywilejowane polecenie je zachowuje. W trybie **secure-execution** (`AT_SECURE`, np. setuid/setgid/capabilities), loader usuwa lub ogranicza wiele z tych zmiennych. Jednak błędy parsera w tej wczesnej fazie loadera nadal mają duży wpływ, ponieważ wykonują się **przed** programem docelowym.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` zmienia wczesne zachowanie glibc (na przykład tunables allocatora) i jest bardzo przydatne w labach exploitów. Ma też znaczenie z perspektywy bezpieczeństwa, ponieważ **dynamic loader parsuje to bardzo wcześnie**. Błąd **Looney Tunables** z 2023 roku był dobrym przypomnieniem, że pojedyncza zmienna środowiskowa parsowana w loaderze może stać się **lokalnym primitive do privilege-escalation** przeciwko programom SUID.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Jeśli **Bash** jest uruchamiany **nieinteraktywnie**, sprawdza `BASH_ENV` i wczytuje ten plik przed uruchomieniem docelowego skryptu. Gdy Bash jest wywoływany jako `sh` albo w interaktywnym trybie zgodnym z POSIX, może być również sprawdzane `ENV`. To klasyczny sposób na przekształcenie shell wrapper w wykonanie kodu, jeśli środowisko jest kontrolowane przez atakującego.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Samo Bash wyłącza te pliki startowe, gdy **rzeczywiste/efektywne ID różnią się**, chyba że użyto `-p`, więc dokładne zachowanie zależy od tego, jak wrapper uruchamia shell.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Te zmienne zmieniają sposób uruchamiania Pythona:

- `PYTHONPATH`: dodaje prefiks do ścieżek wyszukiwania importów.
- `PYTHONHOME`: przenosi drzewo standardowej biblioteki.
- `PYTHONSTARTUP`: wykonuje plik przed interaktywnym promptem.
- `PYTHONINSPECT=1`: przechodzi do trybu interaktywnego po zakończeniu skryptu.

Są użyteczne przeciwko skryptom utrzymaniowym, debuggerom, shellom i wrapperom, które uruchamiają Pythona z kontrolowanym środowiskiem. `python -E` i `python -I` ignorują wszystkie zmienne `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl ma równie przydatne zmienne startowe:

- `PERL5LIB`: dodaje katalogi bibliotek na początek.
- `PERL5OPT`: wstrzykuje przełączniki tak, jakby były obecne w każdej linii poleceń `perl`.

To może wymusić **automatyczne ładowanie modułów** albo zmienić zachowanie interpretera, zanim docelowy skrypt zrobi cokolwiek interesującego. Perl ignoruje te zmienne w kontekstach **taint / setuid / setgid**, ale nadal mają duże znaczenie dla zwykłych wrapperów uruchamianych jako root, zadań CI, instalatorów i niestandardowych reguł sudoers.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
Ta sama idea pojawia się w innych runtime’ach (`RUBYOPT`, `NODE_OPTIONS`, itd.): zawsze gdy interpreter jest uruchamiany przez uprzywilejowany wrapper, szukaj env vars, które modyfikują **module loading** albo **startup behavior**.

Z perspektywy post-exploitation, pamiętaj też, że odziedziczone środowiska często zawierają **credentials**, ustawienia **proxy**, **service tokens** lub **cloud keys**. Sprawdź [Linux Post Exploitation](linux-post-exploitation/README.md) pod kątem polowania na `/proc/<PID>/environ` oraz `systemd` `Environment=`.

### PS1

Zmień wygląd swojego promptu.

[**To jest przykład**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../images/image (897).png>)

Regular user:

![](<../images/image (740).png>)

Jedno, dwa i trzy zadania w tle:

![](<../images/image (145).png>)

Jedno zadanie w tle, jedno zatrzymane, a ostatnie polecenie nie zakończyło się poprawnie:

![](<../images/image (715).png>)

## References

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../banners/hacktricks-training.md}}
