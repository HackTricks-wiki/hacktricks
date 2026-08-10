# venv

Il modulo standard `venv` di Python crea ambienti virtuali, il cui script di attivazione POSIX è `<venv>/bin/activate`; digita `deactivate` per uscire dall'ambiente attivo.<sup>[[1]](#references)</sup> Su Ubuntu, il pacchetto `python3-venv` fornisce il modulo quando non è installato insieme al pacchetto Python di base.<sup>[[2]](#references)</sup>
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
Per i workflow meno recenti basati su setuptools che utilizzavano `setup.py bdist_wheel`, installare `wheel` nell'ambiente attivo forniva il comando `bdist_wheel`.<sup>[[3]](#references)</sup> Le versioni correnti di setuptools non richiedono più `wheel` per quel comando e le linee guida attuali per il packaging raccomandano `python -m build --wheel` invece di richiamare direttamente `setup.py`.<sup>[[4]](#references)[[5]](#references)</sup>
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

- [1] [venv — Creazione di ambienti virtuali — Documentazione di Python 3.14](https://docs.python.org/3/library/venv.html)
- [2] [Pacchetto: python3-venv — Pacchetti Ubuntu](https://packages.ubuntu.com/noble/python/python3-venv)
- [3] [wheel 0.24.0 — PyPI](https://pypi.org/project/wheel/0.24.0/)
- [4] [wheel — PyPI](https://pypi.org/project/wheel/)
- [5] [setup.py è deprecato? — Guida utente al packaging di Python](https://packaging.python.org/en/latest/discussions/setup-py-deprecated/)
{{#include ../../banners/hacktricks-training.md}}
