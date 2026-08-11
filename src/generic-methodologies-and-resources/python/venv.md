# venv

{{#include ../../banners/hacktricks-training.md}}

Das standardmäßige Python-Modul `venv` erstellt virtuelle Umgebungen. Das POSIX-Aktivierungsskript befindet sich unter `<venv>/bin/activate`; geben Sie `deactivate` ein, um die aktive Umgebung zu verlassen.<sup>[[1]](#references)</sup> Unter Ubuntu stellt das Paket `python3-venv` das Modul bereit, wenn es nicht mit dem Python-Basispaket installiert wurde.<sup>[[2]](#references)</sup>
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
Für ältere auf setuptools basierende `setup.py bdist_wheel`-Workflows stellte die Installation von `wheel` in der aktiven Umgebung den Befehl `bdist_wheel` bereit.<sup>[[3]](#references)</sup> Aktuelle setuptools-Versionen benötigen `wheel` für diesen Befehl nicht mehr, und die aktuellen Packaging-Empfehlungen raten dazu, `python -m build --wheel` zu verwenden, anstatt `setup.py` direkt aufzurufen.<sup>[[4]](#references)[[5]](#references)</sup>
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

- [1] [venv — Erstellung virtueller Umgebungen — Python-3.14-Dokumentation](https://docs.python.org/3/library/venv.html)
- [2] [Paket: python3-venv — Ubuntu-Pakete](https://packages.ubuntu.com/noble/python/python3-venv)
- [3] [wheel 0.24.0 — PyPI](https://pypi.org/project/wheel/0.24.0/)
- [4] [wheel — PyPI](https://pypi.org/project/wheel/)
- [5] [Ist setup.py veraltet? — Python Packaging User Guide](https://packaging.python.org/en/latest/discussions/setup-py-deprecated/)
{{#include ../../banners/hacktricks-training.md}}
