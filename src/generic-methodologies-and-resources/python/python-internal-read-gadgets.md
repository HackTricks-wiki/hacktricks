# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Informações Básicas

Vulnerabilidades diferentes, como [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) ou [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), podem permitir que você **leia dados internos do python, mas não permitirão que você execute código**. Portanto, um pentester precisará aproveitar ao máximo essas permissões de leitura para **obter privilégios sensíveis e escalar a vulnerabilidade**.

### Flask - Ler chave secreta

A página principal de uma aplicação Flask provavelmente terá o objeto global **`app`** onde esta **chave secreta está configurada**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Neste caso, é possível acessar este objeto apenas usando qualquer gadget para **acessar objetos globais** da [**página de Bypass Python sandboxes**](bypass-python-sandboxes/).

No caso em que **a vulnerabilidade está em um arquivo python diferente**, você precisa de um gadget para percorrer arquivos para chegar ao principal e **acessar o objeto global `app.secret_key`** para mudar a chave secreta do Flask e poder [**escalar privilégios** conhecendo esta chave](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Um payload como este [deste writeup](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Use este payload para **mudar `app.secret_key`** (o nome no seu app pode ser diferente) para poder assinar novos e mais privilegiados cookies do flask.

### Werkzeug - machine_id e node uuid

[**Usando esses payloads deste writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) você poderá acessar o **machine_id** e o **uuid** do node, que são os **principais segredos** que você precisa para [**gerar o pin do Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) que você pode usar para acessar o console python em `/console` se o **modo de depuração estiver ativado:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Note que você pode obter o **caminho local do servidor para o `app.py`** gerando algum **erro** na página da web que irá **te dar o caminho**.

Se a vulnerabilidade estiver em um arquivo python diferente, verifique o truque Flask anterior para acessar os objetos do arquivo python principal.

{{#include ../../banners/hacktricks-training.md}}
