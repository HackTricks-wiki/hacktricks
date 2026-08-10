# venv

Python の標準 `venv` module は virtual environments を作成します。POSIX activation script は `<venv>/bin/activate` です。active environment を終了するには `deactivate` と入力します。<sup>[[1]](#references)</sup> Ubuntu では、base Python package とともにインストールされていない場合、`python3-venv` package が module を提供します。<sup>[[2]](#references)</sup>
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
古い setuptools ベースの `setup.py bdist_wheel` ワークフローでは、active environment に `wheel` をインストールすると `bdist_wheel` コマンドが提供されました。<sup>[[3]](#references)</sup> 現在の setuptools バージョンでは、そのコマンドに `wheel` は不要であり、現在の packaging ガイダンスでは `setup.py` を直接呼び出すのではなく、`python -m build --wheel` を使用することが推奨されています。<sup>[[4]](#references)[[5]](#references)</sup>
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

- [1] [venv — 仮想環境の作成 — Python 3.14 documentation](https://docs.python.org/3/library/venv.html)
- [2] [Package: python3-venv — Ubuntu Packages](https://packages.ubuntu.com/noble/python/python3-venv)
- [3] [wheel 0.24.0 — PyPI](https://pypi.org/project/wheel/0.24.0/)
- [4] [wheel — PyPI](https://pypi.org/project/wheel/)
- [5] [Is setup.py deprecated? — Python Packaging User Guide](https://packaging.python.org/en/latest/discussions/setup-py-deprecated/)
{{#include ../../banners/hacktricks-training.md}}
