# Uruchamianie powłoki, aliasy i historia

{{#include ../../banners/hacktricks-training.md}}

Polecenie powłoki może działać inaczej niż plik wykonywalny o tej samej nazwie, jeśli alias, funkcja, plik startowy lub zmienna środowiskowa zmienia sposób jego uruchamiania. Sprawdź te elementy, zanim zaufasz wynikom polecenia lub założysz, że skrypt używa tej samej zmiennej PATH co sesja interaktywna.

## Sprawdź bieżącą powłokę

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` i `command -V` ujawniają, czy dana nazwa jest aliasem, funkcją, poleceniem wbudowanym czy plikiem. `command -v` i `which` mogą dawać różne wyniki w przypadku aliasów i funkcji. Historia powłoki może ujawniać polecenia lub dane uwierzytelniające, ale może być niekompletna, wyłączona albo przechowywana w pamięci do zakończenia sesji.

Zmodyfikowany plik `.bashrc` może definiować alias `sudo`, który naśladuje monit o hasło, zapisuje podaną wartość i przekazuje ją do prawdziwego polecenia. Może to ukryć przechwytywanie danych uwierzytelniających bez zmiany pliku wykonywalnego `sudo` ani `PATH`.<sup>[[5]](#references)</sup> Powłoka musi odczytać zmodyfikowany plik startowy i rozwinąć alias.<sup>[[7]](#references)</sup> Domyślnie nieinteraktywny Bash nie rozwija aliasów, chyba że włączono `expand_aliases`.<sup>[[6]](#references)</sup>

## Przegląd plików startowych i historii

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Plik startowy, do którego użytkownik może zapisywać, może wykonywać polecenia przy następnym uruchomieniu powłoki. Systemowy plik startowy lub plik startowy użytkownika z podwyższonymi uprawnieniami jest bardziej wrażliwy, jeśli konto o niższych uprawnieniach może go modyfikować. Bash w trybie nieinteraktywnym może też odczytywać plik wskazany przez `BASH_ENV`; strona [zmienne środowiskowe](linux-environment-variables.md#bash_env--env) opisuje to zachowanie i inne punkty zaczepienia interpreterów. Zanim uznasz dany plik za ścieżkę utrwalenia dostępu, sprawdź, które pliki rzeczywiście odczytuje używana powłoka w sesjach logowania, interaktywnych i nieinteraktywnych.

Sprawdź też pliki dołączane przez globalny plik startowy. Na przykład dosłowne `source /opt/app/venv/bin/activate` w `/etc/bash.bashrc` wykonuje plik aktywacyjny jako kod powłoki, gdy powłoka rzeczywiście odczytuje ten plik startowy. Sprawdź plik aktywacyjny, uprawnienia do symlinków i katalogów nadrzędnych oraz ACL; użytkownik o niższych uprawnieniach może wpłynąć na powłokę z podwyższonymi uprawnieniami tylko wtedy, gdy ta powłoka lub uprzywilejowane zadanie później dołączy ten plik. Jeśli dostęp do zapisu zależy od `sudoedit`, najpierw sprawdź dokładną regułę sudoers i zainstalowany pakiet sudo z poprawkami dostawcy; sam numer wersji upstream nie potwierdza [podatności sudoedit na wstrzykiwanie argumentów](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Sprawdź historię, pliki dot i kopie zapasowe pod kątem sekretów, zgodnie z opisem w sekcji [użytkownicy i sesje](../user-information/user-and-session-triage.md). Jeśli uprzywilejowany skrypt wyszukuje polecenia po nazwie, połącz ten przegląd ze wskazówkami dotyczącymi [PATH hijacking](linux-environment-variables.md#path).

## Przekierowanie plików startowych Zsh i skompilowane pliki

Przy domyślnych ustawieniach `RCS` zsh odczytuje `$ZDOTDIR/.zshenv` przed zwykłymi uruchomieniami, w tym przed `zsh -c` i skryptami; jeśli `ZDOTDIR` nie jest ustawione, używa `$HOME`. Gdy runner poleceń przyjmuje mapę środowiska, sprawdź, czy przekazuje którąś z tych zmiennych do procesu zsh z podwyższonymi uprawnieniami. Zapisywalny plik `.zshenv` może wtedy wykonać kod **przed** treścią polecenia sprawdzaną lub umieszczaną na allowliście przez runner. Wymaga to, aby uprzywilejowany proces dziedziczył przekierowany katalog; `zsh -f` pomija pliki startowe użytkownika, ale nie globalny plik `zshenv` (często `/etc/zshenv`, choć ścieżki zależą od dystrybucji). Strona [wstrzyknięć zsh w macOS](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) zawiera minimalny przykład użycia `ZDOTDIR`.<sup>[[1]](#references)[[2]](#references)</sup>

Nowszy, prawidłowy plik `.zshenv.zwc` lub `.zshrc.zwc` jest wykonywany zamiast jego tekstowego pliku startowego. Jeśli możesz zapisywać w katalogu startowym, skompilowanie zmodyfikowanego pliku, a następnie przywrócenie tekstowej wersji wyglądającej na nieszkodliwą może pozostawić wykonywalny kod w skompilowanej kopii. To zaciemnianie, a nie szyfrowanie. Poniższy test w środowisku tymczasowym pokazuje, dlaczego samo sprawdzenie pliku tekstowego nie wystarcza; nie dotyka prawdziwego katalogu domowego.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

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

W przypadku rzeczywistego celu ustal efektywne wartości `ZDOTDIR`/`HOME`, sprawdź zarówno pliki tekstowe, jak i pliki `.zwc`, a także ich znaczniki czasu, właścicieli i uprawnienia do zapisu w katalogach nadrzędnych. Plik `.zwc` musi odpowiadać plikowi źródłowemu i być nowszy, aby miał pierwszeństwo.<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Pliki startowe i zamykające Zsh](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Zalecenie dotyczące wstrzykiwania do środowiska startowego powłoki](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Wbudowane polecenia powłoki Zsh: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [`.zshrc.zwc`, którego nie sprawdziłeś](https://dfir.ch/posts/compiled_zsh/)
- [5] [Kampania szpiegowska oparta na AI wymierzona w rządową infrastrukturę Linux](https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/)
- [6] [Podręcznik Bash: Aliasy](https://www.gnu.org/software/bash/manual/html_node/Aliases.html)
- [7] [Podręcznik Bash: Pliki startowe Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
{{#include ../../banners/hacktricks-training.md}}
