# venv

Standardowy moduł Pythona `venv` tworzy środowiska wirtualne, których skrypt aktywacji POSIX znajduje się w `<venv>/bin/activate`; wpisz `deactivate`, aby opuścić aktywne środowisko.<sup>[[1]](#references)</sup> W systemie Ubuntu pakiet `python3-venv` dostarcza ten moduł, jeśli nie został zainstalowany wraz z bazowym pakietem Pythona.<sup>[[2]](#references)</sup>
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
W przypadku starszych przepływów pracy opartych na setuptools i `setup.py bdist_wheel` zainstalowanie `wheel` w aktywnym środowisku udostępniało polecenie `bdist_wheel`.<sup>[[3]](#references)</sup> Aktualne wersje setuptools nie wymagają już `wheel` dla tego polecenia, a obecne wytyczne dotyczące pakowania zalecają używanie `python -m build --wheel` zamiast bezpośredniego wywoływania `setup.py`.<sup>[[4]](#references)[[5]](#references)</sup>
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

- [1] [venv — Tworzenie środowisk wirtualnych — dokumentacja Python 3.14](https://docs.python.org/3/library/venv.html)
- [2] [Pakiet: python3-venv — pakiety Ubuntu](https://packages.ubuntu.com/noble/python/python3-venv)
- [3] [wheel 0.24.0 — PyPI](https://pypi.org/project/wheel/0.24.0/)
- [4] [wheel — PyPI](https://pypi.org/project/wheel/)
- [5] [Czy setup.py jest przestarzały? — Python Packaging User Guide](https://packaging.python.org/en/latest/discussions/setup-py-deprecated/)
{{#include ../../banners/hacktricks-training.md}}
