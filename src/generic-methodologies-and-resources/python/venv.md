# venv

Python se standaard `venv`-module skep virtuele omgewings, waarvan die POSIX-aktiveringskrip `<venv>/bin/activate` is; tik `deactivate` om die aktiewe omgewing te verlaat.<sup>[[1]](#references)</sup> Op Ubuntu verskaf die `python3-venv`-pakket die module wanneer dit nie saam met die basis-Python-pakket geïnstalleer is nie.<sup>[[2]](#references)</sup>
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
Vir ouer setuptools-gebaseerde `setup.py bdist_wheel`-werkvloeie het die installering van `wheel` in die aktiewe omgewing die `bdist_wheel`-opdrag verskaf.<sup>[[3]](#references)</sup> Huidige setuptools-weergawes benodig nie meer `wheel` vir daardie opdrag nie, en huidige packaging-riglyne beveel `python -m build --wheel` aan eerder as om `setup.py` direk aan te roep.<sup>[[4]](#references)[[5]](#references)</sup>
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

- [1] [venv — Skep van virtuele omgewings — Python 3.14-dokumentasie](https://docs.python.org/3/library/venv.html)
- [2] [Pakket: python3-venv — Ubuntu-pakkette](https://packages.ubuntu.com/noble/python/python3-venv)
- [3] [wheel 0.24.0 — PyPI](https://pypi.org/project/wheel/0.24.0/)
- [4] [wheel — PyPI](https://pypi.org/project/wheel/)
- [5] [Is setup.py verouderd? — Gebruikersgids vir Python-pakketbestuur](https://packaging.python.org/en/latest/discussions/setup-py-deprecated/)
{{#include ../../banners/hacktricks-training.md}}
