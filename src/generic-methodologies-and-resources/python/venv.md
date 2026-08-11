# venv

{{#include ../../banners/hacktricks-training.md}}

Le module standard `venv` de Python crée des environnements virtuels, dont le script d’activation POSIX est `<venv>/bin/activate` ; saisissez `deactivate` pour quitter l’environnement actif.<sup>[[1]](#references)</sup> Sur Ubuntu, le package `python3-venv` fournit le module lorsqu’il n’est pas installé avec le package Python de base.<sup>[[2]](#references)</sup>
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
Pour les anciens workflows `setup.py bdist_wheel` basés sur setuptools, l’installation de `wheel` dans l’environnement actif fournissait la commande `bdist_wheel`.<sup>[[3]](#references)</sup> Les versions actuelles de setuptools n’ont plus besoin de `wheel` pour cette commande, et les recommandations actuelles en matière de packaging préconisent `python -m build --wheel` plutôt que l’exécution directe de `setup.py`.<sup>[[4]](#references)[[5]](#references)</sup>
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

- [1] [venv — Création d’environnements virtuels — Documentation Python 3.14](https://docs.python.org/3/library/venv.html)
- [2] [Package : python3-venv — Packages Ubuntu](https://packages.ubuntu.com/noble/python/python3-venv)
- [3] [wheel 0.24.0 — PyPI](https://pypi.org/project/wheel/0.24.0/)
- [4] [wheel — PyPI](https://pypi.org/project/wheel/)
- [5] [setup.py est-il obsolète ? — Guide utilisateur du packaging Python](https://packaging.python.org/en/latest/discussions/setup-py-deprecated/)
{{#include ../../banners/hacktricks-training.md}}
