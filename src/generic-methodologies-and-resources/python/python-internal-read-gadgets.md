# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Informações Básicas

Diferentes vulnerabilidades, como [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) ou [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), podem permitir que você **leia dados internos do python, mas não permitirão que você execute código**. Portanto, um pentester precisará aproveitar ao máximo essas permissões de leitura para **obter privilégios sensíveis e escalar a vulnerabilidade**.

### Flask - Ler chave secreta

A página principal de uma aplicação Flask provavelmente terá o objeto global **`app`** onde esse **segredo é configurado**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Neste caso, é possível acessar esse objeto apenas usando qualquer gadget para **acessar objetos globais** da [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html).

No caso em que **a vulnerabilidade está em um arquivo python diferente**, você precisa de um gadget para percorrer arquivos até chegar ao principal para **acessar o objeto global `app.secret_key`** para alterar a chave secreta do Flask e ser capaz de [**escalate privileges** sabendo essa chave](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Um payload como este [from this writeup](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Use este payload para **alterar `app.secret_key`** (o nome no seu app pode ser diferente) para poder assinar novos flask cookies com mais privilégios.

### Werkzeug - machine_id e node uuid

[**Using these payload from this writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) you will be able to access the **machine_id** and the **uuid** node, which are the **main secrets** you need to [**generate the Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) you can use to access the python console in `/console` if the **debug mode is enabled:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Observe que você pode obter o **caminho local do servidor para o `app.py`** ao provocar algum **erro** na página web, o que irá **fornecer o caminho**.

Se a vulnerabilidade estiver em um arquivo python diferente, verifique o truque anterior do Flask para acessar os objetos do arquivo python principal.

### Django - SECRET_KEY e módulo settings

O objeto settings do Django é armazenado em cache em `sys.modules` assim que a aplicação inicia. Com apenas read primitives você pode leak a **`SECRET_KEY`**, credenciais do banco de dados ou signing salts:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.DATABASES, a.SIGNING_BACKEND)
```
Se o gadget vulnerável estiver em outro módulo, walk globals primeiro:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
Uma vez que a chave seja conhecida, você pode forjar Django signed cookies ou tokens de forma semelhante ao Flask.

### Variáveis de ambiente / credenciais de cloud via módulos carregados

Muitos jails ainda importam `os` ou `sys` em algum lugar. Você pode abusar de qualquer função acessível `__init__.__globals__` para pivotar para o módulo `os` já importado e extrair as **variáveis de ambiente** que contenham API tokens, cloud keys ou flags:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Se o índice da subclasse estiver filtrado, use loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Environment variables são frequentemente os únicos segredos necessários para passar de leitura para comprometimento total (cloud IAM keys, database URLs, signing keys, etc.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` (<0.62.0) permitia **class pollution** via crafted component requests. Ao definir um caminho de propriedade como `__init__.__globals__` um atacante conseguia alcançar os globals do módulo do componente e quaisquer módulos importados (ex.: `settings`, `os`, `sys`). A partir daí você pode leak `SECRET_KEY`, `DATABASES` ou credenciais de serviço sem execução de código. A cadeia de exploit é puramente read-based e usa os mesmos padrões dunder-gadget mencionados acima.

### Gadget collections for chaining

CTFs recentes (p.ex. jailCTF 2025) mostram read chains confiáveis construídas apenas com acesso a atributos e enumeração de subclasses. Listas mantidas pela comunidade, como [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker), catalogam centenas de gadgets mínimos que você pode combinar para atravessar objetos até `__globals__`, `sys.modules` e, finalmente, dados sensíveis. Use-os para se adaptar rapidamente quando índices ou nomes de classe diferirem entre versões menores do Python.



## References

- [Wiz analysis of django-unicorn class pollution (CVE-2025-24370)](https://www.wiz.io/vulnerability-database/cve/cve-2025-24370)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
