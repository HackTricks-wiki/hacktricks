# venv

Python-ov standardni modul `venv` kreira virtuelna okruženja, čija POSIX skripta za aktivaciju je `<venv>/bin/activate`; ukucajte `deactivate` da napustite aktivno okruženje.<sup>[[1]](#references)</sup> Na Ubuntu-u, paket `python3-venv` obezbeđuje modul kada nije instaliran zajedno sa osnovnim Python paketom.<sup>[[2]](#references)</sup>
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
Za starije tokove rada zasnovane na setuptools-u koji koriste `setup.py bdist_wheel`, instaliranje paketa `wheel` u aktivno okruženje omogućavalo je komandu `bdist_wheel`.<sup>[[3]](#references)</sup> Aktuelne verzije setuptools-a više ne zahtevaju `wheel` za tu komandu, a aktuelne smernice za packaging preporučuju `python -m build --wheel` umesto direktnog pozivanja `setup.py`.<sup>[[4]](#references)[[5]](#references)</sup>
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

- [1] [venv — Kreiranje virtuelnih okruženja — Python 3.14 dokumentacija](https://docs.python.org/3/library/venv.html)
- [2] [Paket: python3-venv — Ubuntu paketi](https://packages.ubuntu.com/noble/python/python3-venv)
- [3] [wheel 0.24.0 — PyPI](https://pypi.org/project/wheel/0.24.0/)
- [4] [wheel — PyPI](https://pypi.org/project/wheel/)
- [5] [Da li je setup.py zastareo? — Vodič za korisnike Python paketa](https://packaging.python.org/en/latest/discussions/setup-py-deprecated/)
{{#include ../../banners/hacktricks-training.md}}
