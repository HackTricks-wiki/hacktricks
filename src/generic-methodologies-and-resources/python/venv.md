# venv

{{#include ../../banners/hacktricks-training.md}}

O módulo padrão `venv` do Python cria ambientes virtuais, cujo script de ativação POSIX é `<venv>/bin/activate`; digite `deactivate` para sair do ambiente ativo.<sup>[[1]](#references)</sup> No Ubuntu, o pacote `python3-venv` fornece o módulo quando ele não está instalado com o pacote base do Python.<sup>[[2]](#references)</sup>
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
Para fluxos mais antigos baseados em setuptools que usavam `setup.py bdist_wheel`, instalar `wheel` no ambiente ativo disponibilizava o comando `bdist_wheel`.<sup>[[3]](#references)</sup> As versões atuais do setuptools não precisam mais de `wheel` para esse comando, e as orientações atuais de packaging recomendam `python -m build --wheel` em vez de invocar `setup.py` diretamente.<sup>[[4]](#references)[[5]](#references)</sup>
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

- [1] [venv — Criação de ambientes virtuais — documentação do Python 3.14](https://docs.python.org/3/library/venv.html)
- [2] [Pacote: python3-venv — Pacotes do Ubuntu](https://packages.ubuntu.com/noble/python/python3-venv)
- [3] [wheel 0.24.0 — PyPI](https://pypi.org/project/wheel/0.24.0/)
- [4] [wheel — PyPI](https://pypi.org/project/wheel/)
- [5] [setup.py está obsoleto? — Guia do usuário de empacotamento do Python](https://packaging.python.org/en/latest/discussions/setup-py-deprecated/)
{{#include ../../banners/hacktricks-training.md}}
