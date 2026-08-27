# Ін’єкція в R Applications у macOS

{{#include ../../../banners/hacktricks-training.md}}

## `R_PROFILE_USER` / `R_PROFILE`

Під час запуску R завантажує файли профілів сайту та користувача, що містять код R. `R_PROFILE` вибирає профіль сайту, а `R_PROFILE_USER` — профіль користувача, що дає змогу успадкованому середовищу перенаправити будь-який із цих пошуків до файлу, доступного зловмиснику.<sup>[[1]](#references)</sup>
```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```
`--no-init-file` пропускає профіль користувача, `--no-site-file` пропускає профіль сайту, а `--vanilla` містить обидва захисти. Спочатку R обробляє файли середовища, вибрані через `R_ENVIRON` і `R_ENVIRON_USER`, але ці файли лише встановлюють змінні; змінні профілю є безпосереднім примітивом для виконання довільного коду.

## `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` і шляхи до бібліотек

Під час запуску R підключає пакети, перелічені через кому в `R_DEFAULT_PACKAGES`. `Rscript` надає `R_SCRIPT_DEFAULT_PACKAGES` пріоритет. Поєднання будь-якої з цих змінних із `R_LIBS`, `R_LIBS_USER` або `R_LIBS_SITE` може змусити R знайти та завантажити встановлений пакет, контрольований зловмисником; його hook `.onLoad` або `.onAttach` виконується автоматично.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```
Для цього потрібен структурно валідний встановлений R package, а не просто окремий файл `.R`. `--vanilla` не очищає безпосередньо успадковані змінні, тому довірений wrapper також має скасувати або замінити змінні default-package та library-path, а також вимкнути файли профілів.

## References

- [1] [Ініціалізація під час запуску сесії R](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [2] [Встановлення та адміністрування R: додаткові пакети](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
{{#include ../../../banners/hacktricks-training.md}}
