# Python di base

{{#include ../../banners/hacktricks-training.md}}

## Ambienti virtuali e build dei wheel (`venv`)

Il modulo standard di Python `venv` crea ambienti virtuali, il cui script di attivazione POSIX è `<venv>/bin/activate`; digita `deactivate` per uscire dall'ambiente attivo.<sup>[[3]](#references)</sup> Su Ubuntu, il pacchetto `python3-venv` fornisce il modulo quando non è installato con il pacchetto Python di base.<sup>[[4]](#references)</sup>

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

Per i flussi di lavoro meno recenti basati su setuptools e `setup.py bdist_wheel`, installare `wheel` nell'ambiente attivo forniva il comando `bdist_wheel`.<sup>[[5]](#references)</sup> Le versioni attuali di setuptools non richiedono più `wheel` per quel comando e le indicazioni attuali sul packaging raccomandano `python -m build --wheel` invece di invocare direttamente `setup.py`.<sup>[[6]](#references)[[7]](#references)</sup>

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

## Fondamenti di Python

### Informazioni utili

Tutti gli esempi seguenti presuppongono **Python 3**, salvo indicazione esplicita.\
`range()` restituisce un oggetto iterabile in Python 3 (simile a `xrange()` in Python 2).\
La differenza tra una **tupla** e una **lista** è che la **posizione** di un valore in una tupla di solito ne determina il significato, mentre una lista è di solito solo una sequenza ordinata di valori.

### Operazioni principali

Per elevare un numero a potenza si usa: `3**2` (non `3^2`)\
`2/3 == 0.666666...` in Python 3, mentre `2//3 == 0` esegue una divisione intera.\
`i >= j`\
`i <= j`\
`i == j`\
`i != j`\
`a and b`\
`a or b`\
`not a`\
`float(a)`\
`int(a)`\
`str(d)`\
`ord("A") == 65`\
`chr(65) == 'A'`\
`hex(100) == '0x64'`\
`hex(100)[2:] == '64'`\
`isinstance(1, int) is True`\
`"a b".split(" ") == ['a', 'b']`\
`" ".join(['a', 'b']) == "a b"`\
`"abcdef".startswith("ab") is True`\
`"abc" in "abcdef"`\
`"abc\n".strip() == "abc"`\
`"apbc".replace("p", "") == "abc"`\
`dir(str)` = elenco dei metodi disponibili\
`help(str)` = definizione della classe `str`\
`"a".upper() == "A"`\
`"A".lower() == "a"`\
`"abc".capitalize() == "Abc"`\
`sum([1, 2, 3]) == 6`\
`sorted([1, 43, 5, 3, 21, 4]) == [1, 3, 4, 5, 21, 43]`

**Unire caratteri**\
`3 * 'a' == 'aaa'`\
`'a' + 'b' == 'ab'`\
`'a' + str(3) == 'a3'`\
`[1, 2, 3] + [4, 5] == [1, 2, 3, 4, 5]`

**Parti di una lista / stringa**\
`'abc'[0] == 'a'`\
`'abc'[-1] == 'c'`\
`'abc'[1:3] == 'bc'`\
`"qwertyuiop"[:-1] == 'qwertyuio'`

**Commenti**\
`# One line comment`\
`""" Several lines comment """`

**Cicli**

```python
if a:
    # something
elif b:
    # something
else:
    # something

while a:
    # something

for i in range(0, 100):
    # something from 0 to 99

for letter in "hola":
    # something with each letter
```

### Byte, esadecimale e codifiche

È molto comune nell'exploit-dev, nel reversing e nei CTF:

```python
b"ABC".hex() == "414243"
bytes.fromhex("414243") == b"ABC"
int.from_bytes(b"\x41\x42\x43", "big") == 0x414243
(0x414243).to_bytes(3, "big") == b"ABC"
"admin".encode() == b"admin"
b"admin".decode() == "admin"
```

### Tuple

`t1 = (1, '2', 'three')`\
`t2 = (5, 6)`\
`t3 = t1 + t2 == (1, '2', 'three', 5, 6)`\
`(4,)` = tupla con un solo elemento\
`d = ()` tupla vuota\
`d += (4,)` --> aggiungere a una tupla\
`# t1[1] = 'new value'` --> le tuple sono immutabili\
`list(t2) == [5, 6]` --> da tupla a lista

### Lista (array)

`d = []` vuota\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> da lista a tupla

### Dizionario

```python
month_numbers = {1: 'Jan', 2: 'Feb', 'Feb': 2}
month_numbers[1] == 'Jan'
month_numbers['Feb'] == 2
list(month_numbers) == [1, 2, 'Feb']
list(month_numbers.values()) == ['Jan', 'Feb', 2]
keys = [k for k in month_numbers]
a = {'9': 9}
month_numbers.update(a)
mn = month_numbers.copy()  # independent copy
month_numbers.get('key', 0)  # default value if key does not exist
```

### Insiemi

Negli insiemi non ci sono ripetizioni.\
`myset = set(['a', 'b']) == {'a', 'b'}`\
`myset.add('c')` --> `{'a', 'b', 'c'}`\
`myset.add('a')` --> nessuna modifica\
`myset.update([1, 2, 3])`\
`myset.discard(10)` --> se presente, lo rimuove; altrimenti non fa nulla\
`myset.remove(10)` --> se non è presente, genera un'eccezione\
`myset2 = set([1, 2, 3, 4])`\
`myset.union(myset2)`\
`myset.intersection(myset2)`\
`myset.difference(myset2)`\
`myset.symmetric_difference(myset2)`\
`myset.pop()` --> restituisce un elemento arbitrario e lo rimuove\
`myset.intersection_update(myset2)`\
`myset.difference_update(myset2)`\
`myset.symmetric_difference_update(myset2)`

### Classi

Il metodo in `__lt__` sarà quello usato da `sort()` / `sorted()` per confrontare gli oggetti.

```python
import datetime


class Person:
    def __init__(self, name):
        self.name = name
        self.last_name = name.split(" ")[-1]
        self.birthday = None

    def __lt__(self, other):
        if self.last_name == other.last_name:
            return self.name < other.name
        return self.last_name < other.last_name

    def set_birthday(self, month, day, year):
        self.birthday = datetime.date(year, month, day)

    def get_age(self):
        return (datetime.date.today() - self.birthday).days


class MITPerson(Person):
    next_id_num = 0  # class attribute

    def __init__(self, name):
        super().__init__(name)
        self.id_num = MITPerson.next_id_num
        MITPerson.next_id_num += 1

    def __lt__(self, other):
        return self.id_num < other.id_num
```

### map, zip, filter, lambda, sorted e one-liners

In **Python 3**, `map()` e `filter()` restituiscono iteratori, quindi convertili con `list()` se vuoi stampare tutti i valori in una volta.

**Map** è come `[f(x) for x in iterable]`:

```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```

**zip** si arresta quando termina l'iterabile più corto:

```python
for f, b in zip(foo, bar):
    print(f, b)
```

**Lambda** viene usata per definire una funzione:\
`(lambda x, y: x + y)(5, 3) == 8` --> usare lambda come funzione semplice\
`sorted(range(-5, 6), key=lambda x: x**2)` --> usare lambda per ordinare\
`list(filter(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9])) == [3, 6, 9]`\
`reduce(lambda x, y: x * y, [1, 2, 3, 4]) == 24`

```python
from functools import reduce


def make_adder(n):
    return lambda x: x + n


plus3 = make_adder(3)
plus3(4) == 7


class Car:
    crash = lambda self: print("Boom!")


my_car = Car()
my_car.crash()  # Boom!
```

`mult1 = [x for x in [1, 2, 3, 4, 5, 6, 7, 8, 9] if x % 3 == 0]`

### Eccezioni

```python
def divide(x, y):
    try:
        result = x / y
    except ZeroDivisionError as e:
        print("division by zero! " + str(e))
    except TypeError:
        divide(int(x), int(y))
    else:
        print("result is", result)
    finally:
        print("executing finally clause in any case")
```

### Assert()

Se la condizione è falsa, verrà stampata la stringa.\
Ricorda che le istruzioni `assert` possono essere disabilitate con `python -O`, quindi non usarle per il controllo degli accessi o la convalida degli input.

```python
def avg(grades, weights):
    assert len(grades) != 0, 'no grades data'
    assert len(grades) == len(weights), 'wrong number of grades'
```

### Generatori, yield

Un generatore, invece di restituire tutto in una volta, **produce** valori uno alla volta. È molto utile per wordlist enormi, strumenti di brute force o risposte di grandi dimensioni.

```python
def my_gen(n):
    yield n
    yield n + 1
```

`g = my_gen(6)`\
`next(g) == 6`\
`next(g) == 7`\
`next(g)` --> `StopIteration`

### Espressioni regolari

```python
import re

re.search(r"\w", "hola").group() == "h"
re.findall(r"\w", "hola") == ['h', 'o', 'l', 'a']
re.findall(r"\w+(la)", "hola caracola") == ['la', 'la']
```

**Significati speciali:**\
`.` --> qualsiasi carattere tranne il newline\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> cifra\
`\s` --> carattere di spazio bianco `[ \n\r\t\f]`\
`\S` --> carattere che non è uno spazio bianco\
`^` --> inizia con\
`$` --> termina con\
`+` --> uno o più\
`*` --> 0 o più\
`?` --> 0 o 1 occorrenze

**Opzioni:**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> consente al punto di corrispondere al newline\
`re.search(pat, string, re.MULTILINE)` --> consente a `^` e `$` di corrispondere su righe diverse

```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```

### IterTools

**product**\
`from itertools import product` --> prodotto cartesiano tra 1 o più iterabili

```python
list(product([1, 2, 3], [3, 4]))
# [(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]

list(product([1, 2, 3], repeat=2))
# [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]
```

**permutations**\
`from itertools import permutations` --> ogni possibile disposizione

```python
list(permutations(['1', '2', '3']))
list(permutations('123', 2))
```

**combinations**\
`from itertools import combinations` --> tutte le possibili combinazioni senza ripetizione

```python
list(combinations('123', 2))
# [('1', '2'), ('1', '3'), ('2', '3')]
```

**combinations_with_replacement**\
`from itertools import combinations_with_replacement`

```python
list(combinations_with_replacement('123', 2))
# [('1', '1'), ('1', '2'), ('1', '3'), ('2', '2'), ('2', '3'), ('3', '3')]
```

**batched**\
`from itertools import batched` --> disponibile in Python 3.12+, utile per suddividere in blocchi grandi liste di candidati per il bruteforce o file IOC.

```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```

### Decoratori

Decoratore che misura il tempo necessario per eseguire una funzione:

```python
from functools import wraps
import time


def timeme(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        print("Let's call our decorated function")
        start = time.time()
        result = func(*args, **kwargs)
        print(f"Execution time: {time.time() - start} seconds")
        return result

    return wrapper


@timeme
def decorated_func():
    print("Decorated func!")
```

Se lo esegui, vedrai qualcosa di simile a quanto segue:

```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```

### Helper utili della libreria standard per il pentesting

**Esplorazione del filesystem con `pathlib`** (`Path.walk()` è disponibile in Python 3.12+; usa `os.walk()` con gli interpreti più datati):

```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
    if ".git" in dirs:
        dirs.remove(".git")
    for name in files:
        if name.endswith((".py", ".env", ".bak")):
            print(root / name)
```

**Avvia i comandi in modo sicuro** (`shell=False` è solitamente l'impostazione predefinita che vuoi usare):

```python
import subprocess

cp = subprocess.run(
    ["id"],
    capture_output=True,
    text=True,
    check=True,
)
print(cp.stdout)
```

Se **devi** creare un comando shell, racchiudi prima tra virgolette ogni token controllato dall’attaccante:

```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```

**File / directory temporanei** (più sicuri dei percorsi `/tmp/foo` inseriti direttamente nel codice):

```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
    out = Path(tmp) / "loot.txt"
    out.write_text("secret\n")
    print(out.read_text())
```

Per l'automazione HTTP, consulta [questa altra pagina sulle richieste web in Python](web-requests.md).

### Insidie nell'estrazione di archivi (importante per gli strumenti e i parser di file)

A partire da **Python 3.14**, `tarfile.extract()` / `extractall()` usano per impostazione predefinita il filtro più sicuro `data`. Nelle versioni precedenti di Python, dovresti impostarlo esplicitamente quando gestisci archivi controllati da un utente malintenzionato.<sup>[[1]](#references)[[2]](#references)</sup>

```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
    with tarfile.open("sample.tar.gz") as tf:
        tf.extractall(out, filter="data")
```

Anche con `filter="data"`, estrai gli archivi non attendibili in una directory temporanea nuova e convalida ciò che è stato scritto prima di spostare i file in posizioni importanti.

`zipfile.Path` è diverso: **non sanifica i nomi dei file** per te, quindi convalida i percorsi prima di estrarre membri ZIP controllati da un utente malintenzionato:

```python
import os
import zipfile

base = os.path.abspath("/tmp/unzip")
with zipfile.ZipFile("sample.zip") as zf:
    for info in zf.infolist():
        final_path = os.path.abspath(os.path.join(base, info.filename))
        if os.path.commonpath([base, final_path]) != base:
            raise ValueError(f"Path traversal inside ZIP: {info.filename}")
        zf.extract(info, base)
```

### Primitive pericolose da ricordare

- `eval()` / `exec()` **non** sono sandbox.
- `ast.literal_eval()` **non** esegue codice Python, ma può comunque essere abusato per causare denial of service di memoria / CPU con input controllato dall'attaccante.
- `pickle.loads()` **non** è sicuro; non deserializzare mai byte controllati dall'attaccante con pickle.
- Per tecniche offensive più approfondite, consulta [Bypass Python sandboxes](bypass-python-sandboxes/README.md), [Python internal read gadgets](python-internal-read-gadgets.md) e [Python deserializations](../../pentesting-web/deserialization/README.md).

## References

- [1] [Documentazione Python di tarfile](https://docs.python.org/3/library/tarfile.html)
- [2] [PEP 706 – Filtro per tarfile.extractall()](https://peps.python.org/pep-0706/)
- [3] [venv — Creazione di ambienti virtuali — Documentazione Python 3.14](https://docs.python.org/3/library/venv.html)
- [4] [Pacchetto: python3-venv — Pacchetti Ubuntu](https://packages.ubuntu.com/noble/python/python3-venv)
- [5] [wheel 0.24.0 — PyPI](https://pypi.org/project/wheel/0.24.0/)
- [6] [wheel — PyPI](https://pypi.org/project/wheel/)
- [7] [setup.py è deprecato? — Guida utente al packaging Python](https://packaging.python.org/en/latest/discussions/setup-py-deprecated/)
{{#include ../../banners/hacktricks-training.md}}
