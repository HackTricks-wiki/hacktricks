# venv

Python 的标准 `venv` 模块会创建虚拟环境，其 POSIX 激活脚本为 `<venv>/bin/activate`；输入 `deactivate` 可退出当前激活的环境。<sup>[[1]](#references)</sup> 在 Ubuntu 上，如果基础 Python 软件包未安装该模块，则由 `python3-venv` 软件包提供该模块。<sup>[[2]](#references)</sup>
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
对于较旧的基于 `setuptools` 的 `setup.py bdist_wheel` workflows，在 active environment 中安装 `wheel` 会提供 `bdist_wheel` command。<sup>[[3]](#references)</sup> 当前版本的 `setuptools` 已不再需要 `wheel` 来使用该 command，而当前的 packaging guidance 建议使用 `python -m build --wheel`，而不是直接调用 `setup.py`。<sup>[[4]](#references)[[5]](#references)</sup>
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

- [1] [venv — 虚拟环境的创建 — Python 3.14 文档](https://docs.python.org/3/library/venv.html)
- [2] [软件包：python3-venv — Ubuntu 软件包](https://packages.ubuntu.com/noble/python/python3-venv)
- [3] [wheel 0.24.0 — PyPI](https://pypi.org/project/wheel/0.24.0/)
- [4] [wheel — PyPI](https://pypi.org/project/wheel/)
- [5] [setup.py 已弃用吗？— Python Packaging User Guide](https://packaging.python.org/en/latest/discussions/setup-py-deprecated/)
{{#include ../../banners/hacktricks-training.md}}
