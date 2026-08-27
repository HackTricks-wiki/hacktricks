# macOS GNU Octave Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave voer tydens opstart verskeie lêers uit wat geldige Octave-opdragte bevat. `OCTAVE_SITE_INITFILE` vervang die werfwye opstartlêer, en `OCTAVE_VERSION_INITFILE` vervang die weergawe-spesifieke een, waardeur enige veranderlike outomatiese uitvoering na ’n lêer waartoe die aanvaller toegang het, kan herlei.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```
`--no-init-file` slaan slegs gebruikerslêers soos `~/.octaverc` oor; dit keer **nie** die site-file-oorheersing hierbo nie. Gebruik `--no-site-file` vir die site-lêers of `--norc` / `-f` om alle opstartlêers te deaktiveer.<sup>[[2]](#references)</sup>

## References

- [1] [GNU Octave-opstartlêers](https://docs.octave.org/latest/Startup-Files.html)
- [2] [GNU Octave-opdragreëlopsies](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
