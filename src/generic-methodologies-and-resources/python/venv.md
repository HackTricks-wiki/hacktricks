# venv

{{#include ../../banners/hacktricks-training.md}}

El módulo estándar `venv` de Python crea entornos virtuales; su script de activación POSIX es `<venv>/bin/activate`; escribe `deactivate` para salir del entorno activo.<sup>[[1]](#references)</sup> En Ubuntu, el paquete `python3-venv` proporciona el módulo cuando no está instalado con el paquete base de Python.<sup>[[2]](#references)</sup>
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
Para los flujos de trabajo antiguos basados en setuptools que usaban `setup.py bdist_wheel`, instalar `wheel` en el entorno activo proporcionaba el comando `bdist_wheel`.<sup>[[3]](#references)</sup> Las versiones actuales de setuptools ya no necesitan `wheel` para ese comando, y las recomendaciones actuales de packaging sugieren usar `python -m build --wheel` en lugar de invocar `setup.py` directamente.<sup>[[4]](#references)[[5]](#references)</sup>
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

- [1] [venv — Creación de entornos virtuales — Documentación de Python 3.14](https://docs.python.org/3/library/venv.html)
- [2] [Paquete: python3-venv — Paquetes de Ubuntu](https://packages.ubuntu.com/noble/python/python3-venv)
- [3] [wheel 0.24.0 — PyPI](https://pypi.org/project/wheel/0.24.0/)
- [4] [wheel — PyPI](https://pypi.org/project/wheel/)
- [5] [¿Está setup.py obsoleto? — Guía del usuario de empaquetado de Python](https://packaging.python.org/en/latest/discussions/setup-py-deprecated/)
{{#include ../../banners/hacktricks-training.md}}
