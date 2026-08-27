# macOS R Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `R_PROFILE_USER` / `R_PROFILE`

Podczas uruchamiania R odczytuje pliki profilu systemowego i użytkownika zawierające kod R. `R_PROFILE` wskazuje profil systemowy, a `R_PROFILE_USER` wskazuje profil użytkownika, umożliwiając odziedziczonemu środowisku przekierowanie dowolnego z tych odwołań do pliku odczytywanego przez attackera.<sup>[[1]](#references)</sup>
```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```
`--no-init-file` pomija profil użytkownika, `--no-site-file` pomija profil site, a `--vanilla` obejmuje obie ochrony. R najpierw przetwarza pliki środowiskowe wybrane przez `R_ENVIRON` i `R_ENVIRON_USER`, ale te pliki tylko ustawiają zmienne; zmienne profilu stanowią bezpośredni primitive arbitrary-code.

## `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` i ścieżki bibliotek

R podczas uruchamiania dołącza pakiety rozdzielone przecinkami znajdujące się w `R_DEFAULT_PACKAGES`. `Rscript` nadaje pierwszeństwo zmiennej `R_SCRIPT_DEFAULT_PACKAGES`. Połączenie którejkolwiek z tych zmiennych z `R_LIBS`, `R_LIBS_USER` lub `R_LIBS_SITE` może sprawić, że R znajdzie i załaduje zainstalowany pakiet kontrolowany przez attackera; jego hook `.onLoad` lub `.onAttach` zostanie wykonany automatycznie.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```
Wymaga to strukturalnie poprawnego, zainstalowanego pakietu R, a nie jedynie luźnego pliku `.R`. `--vanilla` nie czyści bezpośrednio dziedziczonych zmiennych, dlatego zaufany wrapper musi również usunąć lub zastąpić zmienne dotyczące domyślnego pakietu i ścieżki bibliotek, a także wyłączyć pliki profilu.

## References

- [1] [Inicjalizacja podczas uruchamiania sesji R](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [2] [Instalacja i administracja R: pakiety dodatkowe](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
{{#include ../../../banners/hacktricks-training.md}}
