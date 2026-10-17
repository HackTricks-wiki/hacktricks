# Uruchamianie powłoki, aliasy i historia

{{#include ../../banners/hacktricks-training.md}}

Polecenie powłoki może zachowywać się inaczej niż plik wykonywalny o tej samej nazwie, jeśli alias, funkcja, plik startowy lub zmienna środowiskowa zmienia sposób jego działania. Sprawdź te elementy, zanim zaufasz wynikowi polecenia lub założysz, że skrypt używa tej samej wartości PATH co sesja interaktywna.

## Sprawdź bieżącą powłokę

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` i `command -V` pokazują, czy nazwa wskazuje na alias, funkcję, polecenie wbudowane czy plik. `command -v` i `which` mogą różnie wskazywać aliasy i funkcje. Historia powłoki może ujawniać polecenia lub dane uwierzytelniające, ale może być niekompletna, wyłączona lub przechowywana w pamięci do momentu zakończenia sesji.

## Przegląd plików startowych i historii

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Plik startowy, który użytkownik może zapisywać, może wykonywać polecenia przy kolejnym uruchomieniu powłoki. Plik startowy obejmujący cały system lub plik startowy uprzywilejowanego użytkownika jest bardziej wrażliwy, jeśli konto o niższych uprawnieniach może go modyfikować. Bash w trybie nieinteraktywnym może również odczytywać plik wskazany przez `BASH_ENV`; strona [zmienne środowiskowe](linux-environment-variables.md#bash_env--env) wyjaśnia to zachowanie i inne mechanizmy zaczepienia interpreterów. Zanim stwierdzisz, że dana ścieżka umożliwia utrwalenie dostępu, sprawdź, które pliki faktycznie odczytuje używana powłoka w sesjach logowania, interaktywnych i nieinteraktywnych.

Sprawdź też pliki dołączane przez globalny plik startowy. Na przykład dosłowne `source /opt/app/venv/bin/activate` w `/etc/bash.bashrc` wykonuje plik aktywacyjny jako kod powłoki, gdy powłoka faktycznie odczytuje ten plik startowy. Sprawdź plik aktywacyjny, uprawnienia do symlinka i katalogu nadrzędnego oraz ACL; użytkownik o niższych uprawnieniach może wpłynąć na uprzywilejowaną powłokę tylko wtedy, gdy ta powłoka lub uprzywilejowane zadanie później dołączy ten plik. Jeśli dostęp do zapisu zależy od `sudoedit`, najpierw zweryfikuj dokładną regułę sudoers i zainstalowany pakiet sudo z poprawkami dostawcy; sam numer wersji upstream nie potwierdza [podatności sudoedit na wstrzykiwanie argumentów](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Sprawdź historię, pliki dotfiles i kopie zapasowe pod kątem sekretów, zgodnie z opisem w sekcji [użytkownicy i sesje](../user-information/user-and-session-triage.md). Jeśli uprzywilejowany skrypt wyszukuje polecenia na podstawie ich nazw, połącz ten przegląd z [wskazówkami dotyczącymi PATH hijacking](linux-environment-variables.md#path).

## Przekierowanie plików startowych Zsh i pliki skompilowane

Przy domyślnych ustawieniach `RCS` zsh odczytuje `$ZDOTDIR/.zshenv` przed zwykłymi wywołaniami, w tym `zsh -c` i skryptami; jeśli `ZDOTDIR` nie jest ustawione, używa `$HOME`. Gdy runner poleceń przyjmuje mapę środowiska, sprawdź, czy przekazuje którąś z tych zmiennych do uprzywilejowanego procesu zsh. Zapisowalny `.zshenv` może wtedy wykonać kod **przed** treścią polecenia, którą runner sprawdza lub dopuszcza na liście. Wymaga to, aby uprzywilejowany proces odziedziczył przekierowany katalog; `zsh -f` pomija pliki startowe użytkownika, ale nie globalny `zshenv` (często `/etc/zshenv`, ale ścieżki różnią się w zależności od dystrybucji). Strona [wstrzykiwania Zsh w macOS](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) zawiera minimalny przykład `ZDOTDIR`.<sup>[[1]](#references)[[2]](#references)</sup>

Nowszy, prawidłowy plik `.zshenv.zwc` lub `.zshrc.zwc` jest wykonywany zamiast jego tekstowego pliku startowego. Jeśli możesz zapisywać w katalogu startowym, skompilowanie zmodyfikowanego pliku, a następnie przywrócenie niegroźnie wyglądającego pliku tekstowego może pozostawić wykonywalny kod w skompilowanej kopii. To zaciemnianie, a nie szyfrowanie. Poniższy test na plikach tymczasowych pokazuje, dlaczego samo sprawdzenie pliku tekstowego nie wystarcza; nie modyfikuje on prawdziwego katalogu domowego.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```bash
lab=$(mktemp -d)
printf '%s\n' 'print -r -- compiled > "$ZDOTDIR/result"' > "$lab/.zshenv"
zsh -f -c 'zcompile -R "$1"' _ "$lab/.zshenv"
printf '%s\n' 'print -r -- plaintext > "$ZDOTDIR/result"' > "$lab/.zshenv"
touch -d '2 minutes ago' "$lab/.zshenv"  # ensure the .zwc is newer
ZDOTDIR="$lab" zsh -c :
cat "$lab/result"  # compiled
zsh -f -c 'zcompile -t "$1"' _ "$lab/.zshenv.zwc"
```

W przypadku rzeczywistego celu ustal efektywne wartości `ZDOTDIR`/`HOME`, sprawdź zarówno pliki tekstowe, jak i `.zwc`, a także daty modyfikacji, właścicieli i uprawnienia do zapisu w katalogach nadrzędnych. Plik `.zwc` musi odpowiadać plikowi źródłowemu i być nowszy, aby miał pierwszeństwo.<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Pliki startowe i zamykające Zsh](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Ostrzeżenie dotyczące wstrzykiwania do środowiska startowego powłoki](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Wbudowane polecenia powłoki Zsh: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [Zapomniany plik .zshrc.zwc](https://dfir.ch/posts/compiled_zsh/)
{{#include ../../banners/hacktricks-training.md}}
