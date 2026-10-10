# Uruchamianie powłoki, aliasy i historia

{{#include ../../banners/hacktricks-training.md}}

Polecenie powłoki może działać inaczej niż plik wykonywalny o tej samej nazwie, jeśli alias, funkcja, plik startowy lub zmienna środowiskowa zmienia sposób jego uruchamiania. Sprawdź te elementy, zanim zaufasz wynikowi polecenia lub założysz, że skrypt używa tej samej wartości PATH co sesja interaktywna.

## Sprawdź bieżącą powłokę

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` i `command -V` pokazują, czy nazwa jest rozpoznawana jako alias, funkcja, polecenie wbudowane czy plik. `command -v` i `which` mogą dawać różne wyniki w przypadku aliasów i funkcji. Historia powłoki może ujawnić polecenia lub dane uwierzytelniające, ale może być niekompletna, wyłączona lub przechowywana w pamięci do momentu zakończenia sesji.

## Przejrzyj pliki startowe i pliki historii

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Plik startowy, który użytkownik może modyfikować, może wykonywać polecenia przy kolejnym uruchomieniu powłoki. Systemowy plik startowy lub plik startowy użytkownika o podwyższonych uprawnieniach jest bardziej wrażliwy, jeśli może go modyfikować konto o niższych uprawnieniach. Nieinteraktywna powłoka Bash może też odczytywać plik wskazany przez `BASH_ENV`; strona o [zmiennych środowiskowych](linux-environment-variables.md#bash_env--env) opisuje to zachowanie i inne mechanizmy podpinania interpreterów. Zanim uznasz dany plik za możliwą ścieżkę utrzymania dostępu, sprawdź, które pliki faktycznie odczytuje dana powłoka podczas sesji logowania, interaktywnych i nieinteraktywnych.

Sprawdź też pliki wczytywane przez globalny plik startowy. Na przykład zapis `source /opt/app/venv/bin/activate` w `/etc/bash.bashrc` powoduje wykonanie pliku aktywacyjnego jako kodu powłoki, gdy powłoka faktycznie odczytuje ten plik startowy. Sprawdź plik aktywacyjny, uprawnienia do dowiązań symbolicznych i katalogów nadrzędnych oraz ACL; użytkownik o niższych uprawnieniach może wpłynąć na powłokę o podwyższonych uprawnieniach tylko wtedy, gdy ta powłoka lub uprzywilejowane zadanie później wczyta dany plik. Jeśli dostęp do zapisu zależy od `sudoedit`, najpierw zweryfikuj dokładną regułę sudoers i zainstalowany pakiet sudo z poprawkami dostawcy; sam numer wersji upstream nie potwierdza [podatności sudoedit na wstrzyknięcie argumentów](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Sprawdź historię poleceń, pliki dotfiles i kopie zapasowe pod kątem sekretów, zgodnie z opisem w sekcji [użytkownicy i sesje](../user-information/user-and-session-triage.md). Jeśli uprzywilejowany skrypt wyszukuje polecenia po nazwie, połącz tę analizę ze [wskazówkami dotyczącymi przejęcia PATH](linux-environment-variables.md#path).
{{#include ../../banners/hacktricks-training.md}}
