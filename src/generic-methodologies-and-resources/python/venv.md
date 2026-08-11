# venv

{{#include ../../banners/hacktricks-training.md}}

Python의 표준 `venv` 모듈은 virtual environment를 생성하며, POSIX activation script는 `<venv>/bin/activate`입니다. 활성화된 environment를 종료하려면 `deactivate`를 입력합니다.<sup>[[1]](#references)</sup> Ubuntu에서는 기본 Python package에 포함되어 있지 않은 경우 `python3-venv` package가 해당 모듈을 제공합니다.<sup>[[2]](#references)</sup>
```bash
sudo apt-get install python3-venv
#Now, go to the folder you want to create the virtual environment
python3 -m venv <Dirname>
python3 -m venv pvenv #In this case the folder "pvenv" is going to be created
source <Dirname>/bin/activate
source pvenv/bin/activate #Activate the environment
#You can now install whatever python library you need
deactivate #To deactivate the virtual environment
```
구형 setuptools 기반 `setup.py bdist_wheel` workflow에서는 활성 환경에 `wheel`을 설치하면 `bdist_wheel` 명령을 사용할 수 있었습니다.<sup>[[3]](#references)</sup> 현재 setuptools 버전에서는 해당 명령에 `wheel`이 더 이상 필요하지 않으며, 최신 packaging 가이드에서는 `setup.py`를 직접 호출하는 대신 `python -m build --wheel`을 사용할 것을 권장합니다.<sup>[[4]](#references)[[5]](#references)</sup>
```text
error: invalid command 'bdist_wheel'
```

```bash
# Legacy workaround for older setuptools-based projects:
python3 -m pip install wheel

# Current build workflow:
python3 -m pip install build
python3 -m build --wheel
```
## References

- [1] [venv — 가상 환경 생성 — Python 3.14 문서](https://docs.python.org/3/library/venv.html)
- [2] [패키지: python3-venv — Ubuntu Packages](https://packages.ubuntu.com/noble/python/python3-venv)
- [3] [wheel 0.24.0 — PyPI](https://pypi.org/project/wheel/0.24.0/)
- [4] [wheel — PyPI](https://pypi.org/project/wheel/)
- [5] [setup.py는 deprecated 상태인가? — Python Packaging User Guide](https://packaging.python.org/en/latest/discussions/setup-py-deprecated/)
{{#include ../../banners/hacktricks-training.md}}
