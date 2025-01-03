# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## 기본 정보

[**Python Format Strings**](bypass-python-sandboxes/#python-format-string) 또는 [**Class Pollution**](class-pollution-pythons-prototype-pollution.md)와 같은 다양한 취약점은 **파이썬 내부 데이터를 읽을 수 있지만 코드를 실행할 수는 없습니다**. 따라서, 펜테스터는 이러한 읽기 권한을 최대한 활용하여 **민감한 권한을 얻고 취약점을 상승시켜야 합니다**.

### Flask - 비밀 키 읽기

Flask 애플리케이션의 메인 페이지에는 아마도 이 **비밀이 구성된** **`app`** 전역 객체가 있을 것입니다.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
이 경우, [**Python 샌드박스 우회 페이지**](bypass-python-sandboxes/)에서 **전역 객체에 접근하기 위해** 어떤 가젯을 사용하여 이 객체에 접근할 수 있습니다.

**취약점이 다른 파이썬 파일에 있는 경우**, 전역 객체 `app.secret_key`에 접근하기 위해 파일을 탐색할 수 있는 가젯이 필요하며, 이를 통해 Flask 비밀 키를 변경하고 이 키를 알고 [**권한 상승**을 할 수 있습니다](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

이와 같은 페이로드는 [이 작성물에서](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
이 페이로드를 사용하여 **`app.secret_key`** (귀하의 앱에서 이름이 다를 수 있음)를 변경하여 새로운 더 많은 권한의 플라스크 쿠키에 서명할 수 있습니다.

### Werkzeug - machine_id 및 node uuid

[**이 작성물에서 이 페이로드를 사용하여**](https://vozec.fr/writeups/tweedle-dum-dee/) **machine_id** 및 **uuid** 노드에 접근할 수 있으며, 이는 [**Werkzeug 핀을 생성하는 데 필요한**](../../network-services-pentesting/pentesting-web/werkzeug.md) **주요 비밀**입니다. **디버그 모드가 활성화된 경우** `/console`에서 파이썬 콘솔에 접근하는 데 사용할 수 있습니다.
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> **app.py**의 **서버 로컬 경로**를 얻으려면 웹 페이지에서 **오류**를 생성해야 하며, 이로 인해 **경로**를 **얻을 수 있습니다**.

취약점이 다른 파이썬 파일에 있는 경우, 메인 파이썬 파일에서 객체에 접근하기 위한 이전 Flask 트릭을 확인하세요.

{{#include ../../banners/hacktricks-training.md}}
