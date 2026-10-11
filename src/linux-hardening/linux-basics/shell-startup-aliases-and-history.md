# Uruchamianie powłoki, aliasy i historia

{{#include ../../banners/hacktricks-training.md}}

Polecenie powłoki może zachowywać się inaczej niż plik wykonywalny o tej samej nazwie, jeśli alias, funkcja, plik startowy lub zmienna środowiskowa zmienia sposób jego uruchamiania. Sprawdź te elementy, zanim zaufasz wynikowi polecenia lub założysz, że skrypt używa tej samej zmiennej PATH co sesja interaktywna.

## Sprawdź bieżącą powłokę

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` i `command -V` pokazują, czy dana nazwa wskazuje alias, funkcję, polecenie wbudowane czy plik. `command -v` i `which` mogą inaczej wskazywać aliasy i funkcje. Historia powłoki może ujawniać polecenia lub dane uwierzytelniające, ale może być niekompletna, wyłączona albo przechowywana w pamięci do zakończenia sesji.

## Przejrzyj pliki startowe i historię

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Plik startowy, do którego użytkownik ma prawa zapisu, może wykonywać polecenia przy kolejnym uruchomieniu powłoki. Plik startowy o zasięgu całego systemu lub plik startowy uprzywilejowanego użytkownika jest bardziej wrażliwy, jeśli konto o niższych uprawnieniach może go modyfikować. Bash w trybie nieinteraktywnym może również odczytywać plik wskazany przez `BASH_ENV`; strona o [zmiennych środowiskowych](linux-environment-variables.md#bash_env--env) objaśnia to zachowanie oraz inne punkty zaczepienia dla interpreterów. Zanim uznasz daną ścieżkę za mechanizm persistence, sprawdź, które pliki faktycznie odczytuje używana powłoka w sesjach logowania, interaktywnych i nieinteraktywnych.

Sprawdź również pliki dołączane przez globalny plik startowy. Na przykład dosłowne `source /opt/app/venv/bin/activate` w `/etc/bash.bashrc` wykonuje plik aktywacyjny jako kod powłoki, gdy powłoka faktycznie odczytuje ten plik startowy. Sprawdź plik aktywacyjny, uprawnienia do symlinka i katalogów nadrzędnych oraz ACL; użytkownik o niższych uprawnieniach może wpłynąć na uprzywilejowaną powłokę tylko wtedy, gdy ta powłoka lub uprzywilejowane zadanie później dołączy ten plik. Jeśli dostęp do zapisu zależy od `sudoedit`, najpierw sprawdź dokładną regułę sudoers i zainstalowany pakiet sudo z poprawkami dostawcy; sam numer wersji upstream nie potwierdza [podatności sudoedit na wstrzyknięcie argumentów](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Sprawdź historię poleceń, pliki dotfiles i kopie zapasowe pod kątem sekretów, zgodnie z opisem w sekcji [użytkownicy i sesje](../user-information/user-and-session-triage.md). Jeśli uprzywilejowany skrypt wyszukuje polecenia po nazwie, połącz tę analizę ze [wskazówkami dotyczącymi PATH hijacking](linux-environment-variables.md#path).
{{#include ../../banners/hacktricks-training.md}}
