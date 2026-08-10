# venv

Moduli ya kawaida ya Python `venv` huunda mazingira pepe, ambayo script yake ya uanzishaji ya POSIX ni `<venv>/bin/activate`; chapa `deactivate` ili kuondoka kwenye mazingira yanayotumika.<sup>[[1]](#references)</sup> Kwenye Ubuntu, package ya `python3-venv` hutoa moduli hiyo ikiwa haijasakinishwa pamoja na package msingi ya Python.<sup>[[2]](#references)</sup>
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
Kwa workflows za zamani za `setup.py bdist_wheel` zinazotumia setuptools, kusakinisha `wheel` katika environment inayotumika kulitoa command ya `bdist_wheel`.<sup>[[3]](#references)</sup> Toleo za sasa za setuptools hazihitaji tena `wheel` kwa command hiyo, na mwongozo wa sasa wa packaging unapendekeza `python -m build --wheel` badala ya kuendesha `setup.py` moja kwa moja.<sup>[[4]](#references)[[5]](#references)</sup>
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

- [1] [venv — Uundaji wa mazingira pepe — Nyaraka za Python 3.14](https://docs.python.org/3/library/venv.html)
- [2] [Package: python3-venv — Vifurushi vya Ubuntu](https://packages.ubuntu.com/noble/python/python3-venv)
- [3] [wheel 0.24.0 — PyPI](https://pypi.org/project/wheel/0.24.0/)
- [4] [wheel — PyPI](https://pypi.org/project/wheel/)
- [5] [Je, setup.py imepitwa na wakati? — Mwongozo wa Mtumiaji wa Ufungashaji wa Python](https://packaging.python.org/en/latest/discussions/setup-py-deprecated/)
{{#include ../../banners/hacktricks-training.md}}
