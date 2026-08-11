# venv

{{#include ../../banners/hacktricks-training.md}}

Python का standard `venv` module virtual environments बनाता है, जिनकी POSIX activation script `<venv>/bin/activate` होती है; active environment से बाहर निकलने के लिए `deactivate` टाइप करें।<sup>[[1]](#references)</sup> Ubuntu पर, `python3-venv` package यह module उपलब्ध कराता है, जब यह base Python package के साथ install न किया गया हो।<sup>[[2]](#references)</sup>
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
पुराने setuptools-आधारित `setup.py bdist_wheel` workflows के लिए, active environment में `wheel` install करने से `bdist_wheel` command उपलब्ध हो जाती थी।<sup>[[3]](#references)</sup> वर्तमान setuptools versions को उस command के लिए अब `wheel` की आवश्यकता नहीं होती, और वर्तमान packaging guidance सीधे `setup.py` invoke करने के बजाय `python -m build --wheel` की अनुशंसा करती है।<sup>[[4]](#references)[[5]](#references)</sup>
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

- [1] [venv — वर्चुअल एनवायरनमेंट का निर्माण — Python 3.14 documentation](https://docs.python.org/3/library/venv.html)
- [2] [Package: python3-venv — Ubuntu Packages](https://packages.ubuntu.com/noble/python/python3-venv)
- [3] [wheel 0.24.0 — PyPI](https://pypi.org/project/wheel/0.24.0/)
- [4] [wheel — PyPI](https://pypi.org/project/wheel/)
- [5] [क्या setup.py अप्रचलित है? — Python Packaging User Guide](https://packaging.python.org/en/latest/discussions/setup-py-deprecated/)
{{#include ../../banners/hacktricks-training.md}}
