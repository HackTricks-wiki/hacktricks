# Ін'єкція в застосунки GNU Octave

{{#include ../../../banners/hacktricks-training.md}}

## `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave виконує під час запуску кілька файлів, що містять допустимі команди Octave. `OCTAVE_SITE_INITFILE` перевизначає загальносистемний файл запуску, а `OCTAVE_VERSION_INITFILE` — файл, специфічний для певної версії, що дає змогу кожній із цих змінних перенаправити автоматичне виконання до файлу, доступного для читання зловмиснику.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```
`--no-init-file` пропускає лише файли користувача, такі як `~/.octaverc`; він **не** зупиняє наведене вище перевизначення site-файлу. Використовуйте `--no-site-file` для site-файлів або `--norc` / `-f`, щоб вимкнути всі startup-файли.<sup>[[2]](#references)</sup>

## References

- [1] [Файли запуску GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [2] [Параметри командного рядка GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
