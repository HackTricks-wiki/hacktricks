# venv

Python'ın standart `venv` modülü, POSIX etkinleştirme betiği `<venv>/bin/activate` olan sanal ortamlar oluşturur; etkin ortamdan çıkmak için `deactivate` yazın.<sup>[[1]](#references)</sup> Ubuntu'da `python3-venv` paketi, temel Python paketiyle birlikte yüklenmediğinde bu modülü sağlar.<sup>[[2]](#references)</sup>
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
Daha eski setuptools tabanlı `setup.py bdist_wheel` iş akışlarında, etkin ortama `wheel` yüklemek `bdist_wheel` komutunu kullanılabilir hâle getiriyordu.<sup>[[3]](#references)</sup> Güncel setuptools sürümleri artık bu komut için `wheel` gerektirmiyor ve güncel paketleme yönergeleri, `setup.py`'yi doğrudan çağırmak yerine `python -m build --wheel` kullanılmasını öneriyor.<sup>[[4]](#references)[[5]](#references)</sup>
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

- [1] [venv — Sanal ortamların oluşturulması — Python 3.14 belgeleri](https://docs.python.org/3/library/venv.html)
- [2] [Paket: python3-venv — Ubuntu Paketleri](https://packages.ubuntu.com/noble/python/python3-venv)
- [3] [wheel 0.24.0 — PyPI](https://pypi.org/project/wheel/0.24.0/)
- [4] [wheel — PyPI](https://pypi.org/project/wheel/)
- [5] [setup.py kullanımdan kaldırıldı mı? — Python Paketleme Kullanıcı Kılavuzu](https://packaging.python.org/en/latest/discussions/setup-py-deprecated/)
{{#include ../../banners/hacktricks-training.md}}
