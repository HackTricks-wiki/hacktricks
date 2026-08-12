# venv

{{#include ../../banners/hacktricks-training.md}}

Python's standard `venv` module creates virtual environments, whose POSIX activation script is `<venv>/bin/activate`; type `deactivate` to leave the active environment.<sup>[[1]](#references)</sup> On Ubuntu, the `python3-venv` package supplies the module when it is not installed with the base Python package.<sup>[[2]](#references)</sup>


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

For older setuptools-based `setup.py bdist_wheel` workflows, installing `wheel` in the active environment provided the `bdist_wheel` command.<sup>[[3]](#references)</sup> Current setuptools versions no longer need `wheel` for that command, and current packaging guidance recommends `python -m build --wheel` rather than invoking `setup.py` directly.<sup>[[4]](#references)[[5]](#references)</sup>

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

- [1] [venv — Creation of virtual environments — Python 3.14 documentation](https://docs.python.org/3/library/venv.html)
- [2] [Package: python3-venv — Ubuntu Packages](https://packages.ubuntu.com/noble/python/python3-venv)
- [3] [wheel 0.24.0 — PyPI](https://pypi.org/project/wheel/0.24.0/)
- [4] [wheel — PyPI](https://pypi.org/project/wheel/)
- [5] [Is setup.py deprecated? — Python Packaging User Guide](https://packaging.python.org/en/latest/discussions/setup-py-deprecated/)

{{#include ../../banners/hacktricks-training.md}}
