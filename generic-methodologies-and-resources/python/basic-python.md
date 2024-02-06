# Python Básico

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Conceptos Básicos de Python

### Información Útil

list(xrange()) == range() --> En python3 range es el xrange de python2 (no es una lista sino un generador)\
La diferencia entre una Tupla y una Lista es que la posición de un valor en una tupla le da significado, mientras que las listas son solo valores ordenados. Las tuplas tienen estructuras pero las listas tienen un orden.

### Operaciones Principales

Para elevar un número se utiliza: 3\*\*2 (no 3^2)\
Si haces 2/3 devuelve 1 porque estás dividiendo dos enteros (integers). Si quieres decimales debes dividir floats (2.0/3.0).\
i >= j\
i <= j\
i == j\
i != j\
a and b\
a or b\
not a\
float(a)\
int(a)\
str(d)\
ord("A") = 65\
chr(65) = 'A'\
hex(100) = '0x64'\
hex(100)\[2:] = '64'\
isinstance(1, int) = True\
"a b".split(" ") = \['a', 'b']\
" ".join(\['a', 'b']) = "a b"\
"abcdef".startswith("ab") = True\
"abcdef".contains("abc") = True\
"abc\n".strip() = "abc"\
"apbc".replace("p","") = "abc"\
dir(str) = Lista de todos los métodos disponibles\
help(str) = Definición de la clase str\
"a".upper() = "A"\
"A".lower() = "a"\
"abc".capitalize() = "Abc"\
sum(\[1,2,3]) = 6\
sorted(\[1,43,5,3,21,4])

**Unir caracteres**\
3 \* ’a’ = ‘aaa’\
‘a’ + ‘b’ = ‘ab’\
‘a’ + str(3) = ‘a3’\
\[1,2,3]+\[4,5]=\[1,2,3,4,5]

**Partes de una lista**\
‘abc’\[0] = ‘a’\
'abc’\[-1] = ‘c’\
'abc’\[1:3] = ‘bc’ de \[1] a \[2]\
"qwertyuiop"\[:-1] = 'qwertyuio'

**Comentarios**\
\# Comentario de una línea\
"""\
Comentario de varias líneas\
Otro\
"""

**Bucles**
```
if a:
#somethig
elif b:
#something
else:
#something

while(a):
#comething

for i in range(0,100):
#something from 0 to 99

for letter in "hola":
#something with a letter in "hola"
```
### Tuplas

t1 = (1, '2', 'tres')\
t2 = (5, 6)\
t3 = t1 + t2 = (1, '2', 'tres', 5, 6)\
(4,) = Singleton\
d = () tupla vacía\
d += (4,) --> Agregando a una tupla\
¡NO SE PUEDE! --> t1\[1] == 'Nuevo valor'\
list(t2) = \[5, 6] --> De tupla a lista

### Lista (array)

d = \[] vacía\
a = \[1, 2, 3]\
b = \[4, 5]\
a + b = \[1, 2, 3, 4, 5]\
b.append(6) = \[4, 5, 6]\
tuple(a) = (1, 2, 3) --> De lista a tupla

### Diccionario

d = {} vacío\
monthNumbers={1:'Ene', 2: 'feb','feb':2}--> monthNumbers ->{1:'Ene', 2: 'feb','feb':2}\
monthNumbers\[1] = 'Ene'\
monthNumbers\['feb'] = 2\
list(monthNumbers) = \[1, 2, 'feb']\
monthNumbers.values() = \['Ene', 'feb', 2]\
keys = \[k for k in monthNumbers]\
a={'9':9}\
monthNumbers.update(a) = {'9':9, 1:'Ene', 2: 'feb','feb':2}\
mN = monthNumbers.copy() #Copia independiente\
monthNumbers.get('key',0) #Verifica si la clave existe, devuelve el valor de monthNumbers\["key"] o 0 si no existe

### Conjunto

En los conjuntos no hay repeticiones\
myset = set(\['a', 'b']) = {'a', 'b'}\
myset.add('c') = {'a', 'b', 'c'}\
myset.add('a') = {'a', 'b', 'c'} #Sin repeticiones\
myset.update(\[1, 2, 3]) = set(\['a', 1, 2, 'b', 'c', 3])\
myset.discard(10) #Si está presente, elimínalo, si no, no hace nada\
myset.remove(10) #Si está presente, elimínalo, si no, genera una excepción\
myset2 = set(\[1, 2, 3, 4])\
myset.union(myset2) #Valores en myset O myset2\
myset.intersection(myset2) #Valores en myset Y myset2\
myset.difference(myset2) #Valores en myset pero no en myset2\
myset.symmetric\_difference(myset2) #Valores que no están en myset Y myset2 (no en ambos)\
myset.pop() #Obtener el primer elemento del conjunto y eliminarlo\
myset.intersection\_update(myset2) #myset = Elementos en ambos myset y myset2\
myset.difference\_update(myset2) #myset = Elementos en myset pero no en myset2\
myset.symmetric\_difference\_update(myset2) #myset = Elementos que no están en ambos

### Clases

El método en \_\_It\_\_ será el utilizado por sort para comparar si un objeto de esta clase es mayor que otro
```python
class Person(name):
def __init__(self,name):
self.name= name
self.lastName = name.split(‘ ‘)[-1]
self.birthday = None
def __It__(self, other):
if self.lastName == other.lastName:
return self.name < other.name
return self.lastName < other.lastName #Return True if the lastname is smaller

def setBirthday(self, month, day. year):
self.birthday = date tame.date(year,month,day)
def getAge(self):
return (date time.date.today() - self.birthday).days


class MITPerson(Person):
nextIdNum = 0	# Attribute of the Class
def __init__(self, name):
Person.__init__(self,name)
self.idNum = MITPerson.nextIdNum  —> Accedemos al atributo de la clase
MITPerson.nextIdNum += 1 #Attribute of the class +1

def __it__(self, other):
return self.idNum < other.idNum
```
### map, zip, filter, lambda, sorted y one-liners

**Map** es como: \[f(x) for x in iterable] --> map(tutple,\[a,b]) = \[(1,2,3),(4,5)]\
m = map(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) --> \[False, False, True, False, False, True, False, False, True]

**zip** se detiene cuando el más corto entre foo o bar se detiene:
```
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** se utiliza para definir una función\
(lambda x,y: x+y)(5,3) = 8 --> Usa lambda como una **función** simple\
**sorted**(range(-5,6), key=lambda x: x\*\* 2) = \[0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5] --> Usa lambda para ordenar una lista\
m = **filter**(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) = \[3, 6, 9] --> Usa lambda para filtrar\
**reduce** (lambda x,y: x\*y, \[1,2,3,4]) = 24
```
def make_adder(n):
return lambda x: x+n
plus3 = make_adder(3)
plus3(4) = 7 # 3 + 4 = 7

class Car:
crash = lambda self: print('Boom!')
my_car = Car(); my_car.crash() = 'Boom!'
```
```python
mult1 = [x for x in [1, 2, 3, 4, 5, 6, 7, 8, 9] if x%3 == 0 ]
```

### Excepciones
```
def divide(x,y):
try:
result = x/y
except ZeroDivisionError, e:
print “division by zero!” + str(e)
except TypeError:
divide(int(x),int(y))
else:
print “result i”, result
finally
print “executing finally clause in any case”
```
### Assert()

Si la condición es falsa, la cadena se imprimirá en la pantalla
```
def avg(grades, weights):
assert not len(grades) == 0, 'no grades data'
assert len(grades) == 'wrong number grades'
```
### Generadores, yield

Un generador, en lugar de devolver algo, "cede" algo. Cuando accedes a él, "devolverá" el primer valor generado, luego, puedes acceder a él nuevamente y devolverá el siguiente valor generado. Por lo tanto, no todos los valores se generan al mismo tiempo y se puede ahorrar mucha memoria utilizando esto en lugar de una lista con todos los valores.
```
def myGen(n):
yield n
yield n + 1
```
```markdown
g = myGen(6) --> 6\
next(g) --> 7\
next(g) --> Error

### Expresiones Regulares

import re\
re.search("\w","hola").group() = "h"\
re.findall("\w","hola") = \['h', 'o', 'l', 'a']\
re.findall("\w+(la)","hola caracola") = \['la', 'la']

**Significados especiales:**\
. --> Todo\
\w --> \[a-zA-Z0-9\_]\
\d --> Número\
\s --> Carácter de espacio en blanco\[ \n\r\t\f]\
\S --> Carácter que no es espacio en blanco\
^ --> Comienza con\
$ --> Termina con\
\+ --> Uno o más\
\* --> 0 o más\
? --> 0 o 1 ocurrencias

**Opciones:**\
re.search(pat,str,re.IGNORECASE)\
IGNORECASE\
DOTALL --> Permite que el punto coincida con saltos de línea\
MULTILINE --> Permite que ^ y $ coincidan en diferentes líneas

re.findall("<.\*>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>foo\</b>and\<i>so on\</i>']\
re.findall("<.\*?>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>', '\</b>', '\<i>', '\</i>']

IterTools\
**product**\
from **itertools** import product --> Genera combinaciones entre 1 o más listas, quizás repitiendo valores, producto cartesiano (propiedad distributiva)\
print list(**product**(\[1,2,3],\[3,4])) = \[(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]\
print list(**product**(\[1,2,3],repeat = 2)) = \[(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]

**permutations**\
from **itertools** import **permutations** --> Genera combinaciones de todos los caracteres en cada posición\
print list(permutations(\['1','2','3'])) = \[('1', '2', '3'), ('1', '3', '2'), ('2', '1', '3'),... Cada combinación posible\
print(list(permutations('123',2))) = \[('1', '2'), ('1', '3'), ('2', '1'), ('2', '3'), ('3', '1'), ('3', '2')] Cada combinación posible de longitud 2

**combinations**\
from itertools import **combinations** --> Genera todas las combinaciones posibles sin repetir caracteres (si existe "ab", no genera "ba")\
print(list(**combinations**('123',2))) --> \[('1', '2'), ('1', '3'), ('2', '3')]

**combinations\_with\_replacement**\
from itertools import **combinations\_with\_replacement** --> Genera todas las combinaciones posibles desde el carácter en adelante (por ejemplo, el 3ro se mezcla desde el 3ro en adelante pero no con el 2do o primero)\
print(list(**combinations\_with\_replacement**('1133',2))) = \[('1', '1'), ('1', '1'), ('1', '3'), ('1', '3'), ('1', '1'), ('1', '3'), ('1', '3'), ('3', '3'), ('3', '3'), ('3', '3')]

### Decoradores

Decorador que mide el tiempo que necesita una función para ejecutarse (de [aquí](https://towardsdatascience.com/decorating-functions-in-python-619cbbe82c74)):
```
```python
from functools import wraps
import time
def timeme(func):
@wraps(func)
def wrapper(*args, **kwargs):
print("Let's call our decorated function")
start = time.time()
result = func(*args, **kwargs)
print('Execution time: {} seconds'.format(time.time() - start))
return result
return wrapper

@timeme
def decorated_func():
print("Decorated func!")
```
Si lo ejecutas, verás algo como lo siguiente:
```
Let's call our decorated function
Decorated func!
Execution time: 4.792213439941406e-05 seconds
```
<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
