# Injection in Applications Using macOS Shell

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Gdy Bash uruchamia się nieinteraktywnie w celu wykonania skryptu lub polecenia `-c`, rozwija wartość `BASH_ENV` i ładuje wynikowy plik przed wykonaniem żądanego polecenia. Bash nie używa `PATH` do znalezienia tego pliku. Proces, który uruchamia nieinteraktywny Bash ze zmiennymi środowiskowymi kontrolowanymi przez atakującego, może więc zostać zmuszony do wcześniejszego wykonania odczytywalnego payloadu powłoki.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
Hook jest uruchamiany tylko wtedy, gdy cel faktycznie uruchamia Bash; `/bin/sh` na innej platformie lub program wykonujący polecenie bez shellu nie musi go respektować. Bash w trybie uprzywilejowanym ignoruje `BASH_ENV`. Gdy efektywne i rzeczywiste identyfikatory użytkownika/grupy różnią się, Bash pomija również pliki startowe i resetuje efektywne identyfikatory, chyba że podano `-p`; przy użyciu `-p` tryb uprzywilejowany pozostaje włączony, a `BASH_ENV` nadal jest ignorowane.<sup>[[1]](#references)[[2]](#references)</sup>

W macOS zadania `launchd` mogą definiować dziedziczone lub przypisane do konkretnego zadania zmienne środowiskowe, dlatego należy sprawdzić pliki plist i konteksty uruchamiania, które dostarczają skryptom uprzywilejowanym środowisko. Nie należy polegać wyłącznie na SIP w celu oczyszczenia zmiennych interpretera: używaj minimalnego środowiska (`env -i`), jawnie usuwaj `BASH_ENV`, wywołuj zamierzony interpreter za pomocą ścieżki bezwzględnej i unikaj zapisywalnych plików startowych.

## zsh `ZDOTDIR`

zsh odczytuje `$ZDOTDIR/.zshenv` dla każdej normalnej powłoki, w tym dla powłok nieinteraktywnych; jeśli `ZDOTDIR` nie jest ustawione, używa `HOME`. Przekierowanie `ZDOTDIR` do zapisywalnego katalogu powoduje zatem wykonanie jego `.zshenv` przed poleceniem lub skryptem `zsh -c`.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` wyłącza opcję `RCS` i pomija ten plik startowy użytkownika. Globalny `/etc/zshenv` jest nadal odczytywany, dlatego musi pozostać zaufany i minimalny.

## fish `XDG_CONFIG_HOME`

fish odczytuje `$XDG_CONFIG_HOME/fish/conf.d/*.fish` oraz `$XDG_CONFIG_HOME/fish/config.fish` podczas uruchamiania każdej powłoki, nie tylko powłok interaktywnych lub logowania. Wykonuje również `fish/vendor_conf.d/*.fish` znajdujące się poniżej wpisów w `XDG_DATA_DIRS`. Atakujący, który kontroluje jedną z tych zmiennych i katalog z prawem odczytu, może zatem uruchomić kod przed skryptem fish lub poleceniem `-c`.<sup>[[4]](#references)</sup>
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

## References

- [1] [Pliki startowe Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Wywoływanie Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [Pliki startowe/zamykające zsh](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [Pliki konfiguracyjne fish](https://fishshell.com/docs/current/language.html#configuration-files)
{{#include ../../../banners/hacktricks-training.md}}
