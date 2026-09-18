# Injection w aplikacjach powłoki macOS

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Gdy Bash uruchamia się w trybie nieinteraktywnym w celu wykonania skryptu lub polecenia `-c`, rozwija wartość `BASH_ENV` i pobiera wynikowy plik przed wykonaniem żądanego polecenia. Bash nie używa `PATH` do wyszukania tego pliku. Proces, który uruchamia nieinteraktywny Bash ze zmiennymi środowiskowymi kontrolowanymi przez atakującego, może zatem zostać zmuszony do wcześniejszego wykonania odczytywalnego shell payloadu.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
Hook jest uruchamiany tylko wtedy, gdy cel faktycznie uruchamia Bash; `/bin/sh` na innej platformie lub program wykonujący polecenie bez powłoki nie musi go respektować. Bash w trybie uprzywilejowanym ignoruje `BASH_ENV`. Gdy efektywne i rzeczywiste identyfikatory użytkownika/grupy różnią się, Bash pomija również pliki startowe i resetuje efektywne identyfikatory, chyba że podano `-p`; przy użyciu `-p` tryb uprzywilejowany pozostaje włączony, a `BASH_ENV` nadal jest ignorowane.<sup>[[1]](#references)[[2]](#references)</sup>

W macOS zadania `launchd` mogą definiować dziedziczone lub przypisane do zadania zmienne środowiskowe, dlatego należy sprawdzać pliki plist oraz konteksty uruchamiania, które dostarczają zmienne uprzywilejowanym skryptom. Nie należy polegać wyłącznie na SIP w celu oczyszczania zmiennych interpretera: używaj minimalnego środowiska (`env -i`), jawnie usuwaj `BASH_ENV`, uruchamiaj właściwy interpreter za pomocą ścieżki bezwzględnej i unikaj zapisywalnych plików startowych.

## zsh `ZDOTDIR`

zsh odczytuje `$ZDOTDIR/.zshenv` dla każdej zwykłej powłoki, w tym powłok nieinteraktywnych; jeśli `ZDOTDIR` nie jest ustawione, używa `HOME`. Przekierowanie `ZDOTDIR` do zapisywalnego katalogu powoduje zatem wykonanie jego `.zshenv` przed poleceniem lub skryptem `zsh -c`.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` wyłącza opcję `RCS` i pomija ten plik startowy użytkownika. Globalny `/etc/zshenv` jest nadal odczytywany, dlatego musi pozostać zaufany i minimalny.

## fish `XDG_CONFIG_HOME`

fish odczytuje `$XDG_CONFIG_HOME/fish/conf.d/*.fish` oraz `$XDG_CONFIG_HOME/fish/config.fish` podczas uruchamiania każdej powłoki, nie tylko powłok interaktywnych lub logowania. Wykonuje również pliki `fish/vendor_conf.d/*.fish` znajdujące się poniżej wpisów w `XDG_DATA_DIRS`. Atakujący, który kontroluje jedną z tych zmiennych oraz katalog z prawem odczytu, może w związku z tym uruchomić kod przed skryptem fish lub poleceniem `-c`.<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
Użyj `fish --no-config` dla zaufanego wywołania i wyczyść niezaufane zmienne ścieżek XDG.

## bash `PS4` + xtrace (`SHELLOPTS`)

Gdy Bash działa z opcją **xtrace**, przed każdym śledzonym poleceniem rozwija `PS4` i je wyświetla. `PS4` jest rozwijane tak jak każdy prompt, więc zawarte w nim **command substitution** zostaje wykonane. Zarówno wartość `PS4`, **jak i sposób włączenia xtrace** mogą pochodzić wyłącznie ze środowiska: wyeksportowanie `SHELLOPTS=xtrace` włącza xtrace dla zwykłego `bash script.sh` (nie jest potrzebna flaga `-x`). Dzięki temu dowolny Bash script uruchomiony przez ofiarę staje się wykonaniem kodu.<sup>[[5]](#references)</sup>
```bash
echo 'x=1; echo done' > /tmp/victim.sh

# Pure environment-variable injection (no -x on the command line)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a maintenance/CI job is run with debugging on
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` samo w sobie nic nie robi, dopóki xtrace nie zostanie włączone (przez `SHELLOPTS=xtrace`, `set -x` lub `bash -x`). Bash ignoruje `SHELLOPTS` w **trybie uprzywilejowanym** (różne rzeczywiste i efektywne identyfikatory bez obsługi `-p`), dlatego obowiązują te same zastrzeżenia dotyczące setuid co w przypadku `BASH_ENV`.

## POSIX `ENV`

Powłoki w stylu POSIX (`/bin/sh`, `dash`, `ksh`) odczytują zmienną `ENV`, rozwijają ją i wykonują wynikowy plik przy uruchamianiu **interaktywnej** powłoki. Jest to odpowiednik `BASH_ENV` w POSIX (który działa dla *nieinteraktywnego* Bash), więc kontrola nad `ENV` umożliwia wykonywanie kodu za każdym razem, gdy ofiara uruchomi interaktywną powłokę `sh`/`dash`.
```bash
echo 'touch /tmp/env-executed' > /tmp/env-hook.sh
echo 'exit' | ENV=/tmp/env-hook.sh dash -i
test -e /tmp/env-executed && echo 'ENV executed'
```
## References

- [1] [Pliki startowe Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Wywoływanie Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [Pliki startowe/wyłączania zsh](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [Pliki konfiguracyjne fish](https://fishshell.com/docs/current/language.html#configuration-files)
- [5] [Zmienne Bash — `PS4` i wbudowane polecenie Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
{{#include ../../../banners/hacktricks-training.md}}
