# Injection in aplikacjach GNU Octave

{{#include ../../../banners/hacktricks-training.md}}

## `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave podczas uruchamiania wykonuje kilka plików zawierających prawidłowe polecenia Octave. `OCTAVE_SITE_INITFILE` zastępuje systemowy plik startowy, a `OCTAVE_VERSION_INITFILE` zastępuje plik właściwy dla danej wersji, umożliwiając każdej z tych zmiennych przekierowanie automatycznego wykonywania do pliku, który może być modyfikowany przez atakującego.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```
`--no-init-file` pomija tylko pliki użytkownika, takie jak `~/.octaverc`; **nie** zatrzymuje powyższego nadpisania pliku site. Użyj `--no-site-file` dla plików site albo `--norc` / `-f`, aby wyłączyć wszystkie pliki startowe.<sup>[[2]](#references)</sup>

## References

- [1] [Pliki startowe GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [2] [Opcje wiersza poleceń GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
