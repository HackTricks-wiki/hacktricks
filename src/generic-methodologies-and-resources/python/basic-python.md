# Python de base

{{#include ../../banners/hacktricks-training.md}}

## Bases de Python

### Informations utiles

list(xrange()) == range() --> Dans python3, range est l'xrange de python2 (ce n'est pas une liste mais un générateur)\
La différence entre un Tuple et une Liste est que la position d'une valeur dans un tuple lui donne un sens, mais les listes ne sont que des valeurs ordonnées. Les tuples ont des structures mais les listes ont un ordre.

### Opérations principales

Pour élever un nombre, vous utilisez : 3\*\*2 (pas 3^2)\
Si vous faites 2/3, cela retourne 1 car vous divisez deux entiers (ints). Si vous voulez des décimales, vous devez diviser des flottants (2.0/3.0).\
i >= j\
i <= j\
i == j\
i != j\
a et b\
a ou b\
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
dir(str) = Liste de toutes les méthodes disponibles\
help(str) = Définition de la classe str\
"a".upper() = "A"\
"A".lower() = "a"\
"abc".capitalize() = "Abc"\
sum(\[1,2,3]) = 6\
sorted(\[1,43,5,3,21,4])

**Joindre des caractères**\
3 \* ’a’ = ‘aaa’\
‘a’ + ‘b’ = ‘ab’\
‘a’ + str(3) = ‘a3’\
\[1,2,3]+\[4,5]=\[1,2,3,4,5]

**Parts d'une liste**\
‘abc’\[0] = ‘a’\
'abc’\[-1] = ‘c’\
'abc’\[1:3] = ‘bc’ de \[1] à \[2]\
"qwertyuiop"\[:-1] = 'qwertyuio'

**Commentaires**\
\# Commentaire sur une ligne\
"""\
Commentaire sur plusieurs lignes\
Un autre\
"""

**Boucles**
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
### Tuples

t1 = (1,'2,'three')\
t2 = (5,6)\
t3 = t1 + t2 = (1, '2', 'three', 5, 6)\
(4,) = Singelton\
d = () tuple vide\
d += (4,) --> Ajout dans un tuple\
CANT! --> t1\[1] == 'Nouvelle valeur'\
list(t2) = \[5,6] --> De tuple à liste

### Liste (tableau)

d = \[] vide\
a = \[1,2,3]\
b = \[4,5]\
a + b = \[1,2,3,4,5]\
b.append(6) = \[4,5,6]\
tuple(a) = (1,2,3) --> De liste à tuple

### Dictionnaire

d = {} vide\
monthNumbers={1:’Jan’, 2: ‘feb’,’feb’:2}—> monthNumbers ->{1:’Jan’, 2: ‘feb’,’feb’:2}\
monthNumbers\[1] = ‘Jan’\
monthNumbers\[‘feb’] = 2\
list(monthNumbers) = \[1,2,’feb’]\
monthNumbers.values() = \[‘Jan’,’feb’,2]\
keys = \[k for k in monthNumbers]\
a={'9':9}\
monthNumbers.update(a) = {'9':9, 1:’Jan’, 2: ‘feb’,’feb’:2}\
mN = monthNumbers.copy() #Copie indépendante\
monthNumbers.get('key',0) #Vérifier si la clé existe, Retourner la valeur de monthNumbers\["key"] ou 0 si elle n'existe pas

### Ensemble

Dans les ensembles, il n'y a pas de répétitions\
myset = set(\['a', 'b']) = {'a', 'b'}\
myset.add('c') = {'a', 'b', 'c'}\
myset.add('a') = {'a', 'b', 'c'} #Pas de répétitions\
myset.update(\[1,2,3]) = set(\['a', 1, 2, 'b', 'c', 3])\
myset.discard(10) #Si présent, le retirer, sinon, rien\
myset.remove(10) #Si présent, le retirer, sinon, lever une exception\
myset2 = set(\[1, 2, 3, 4])\
myset.union(myset2) #Valeurs dans myset OU myset2\
myset.intersection(myset2) #Valeurs dans myset ET myset2\
myset.difference(myset2) #Valeurs dans myset mais pas dans myset2\
myset.symmetric_difference(myset2) #Valeurs qui ne sont pas dans myset ET myset2 (pas dans les deux)\
myset.pop() #Obtenir le premier élément de l'ensemble et le retirer\
myset.intersection_update(myset2) #myset = Éléments dans myset et myset2\
myset.difference_update(myset2) #myset = Éléments dans myset mais pas dans myset2\
myset.symmetric_difference_update(myset2) #myset = Éléments qui ne sont pas dans les deux

### Classes

La méthode dans \_\_It\_\_ sera celle utilisée par sort pour comparer si un objet de cette classe est plus grand qu'un autre
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
### map, zip, filter, lambda, sorted et one-liners

**Map** est comme : \[f(x) for x in iterable] --> map(tutple,\[a,b]) = \[(1,2,3),(4,5)]\
m = map(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) --> \[False, False, True, False, False, True, False, False, True]

**zip** s'arrête lorsque le plus court de foo ou bar s'arrête :
```
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** est utilisé pour définir une fonction\
(lambda x,y: x+y)(5,3) = 8 --> Utilisez lambda comme une **fonction**\
**sorted**(range(-5,6), key=lambda x: x\*\* 2) = \[0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5] --> Utilisez lambda pour trier une liste\
m = **filter**(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) = \[3, 6, 9] --> Utilisez lambda pour filtrer\
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
mult1 = \[x for x in \[1, 2, 3, 4, 5, 6, 7, 8, 9] if x%3 == 0 ]

### Exceptions
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

Si la condition est fausse, la chaîne sera imprimée à l'écran.
```
def avg(grades, weights):
assert not len(grades) == 0, 'no grades data'
assert len(grades) == 'wrong number grades'
```
### Générateurs, yield

Un générateur, au lieu de retourner quelque chose, "produit" quelque chose. Lorsque vous y accédez, il "retourne" la première valeur générée, puis, vous pouvez y accéder à nouveau et il retournera la prochaine valeur générée. Ainsi, toutes les valeurs ne sont pas générées en même temps et beaucoup de mémoire peut être économisée en utilisant cela au lieu d'une liste avec toutes les valeurs.
```
def myGen(n):
yield n
yield n + 1
```
g = myGen(6) --> 6\
next(g) --> 7\
next(g) --> Erreur

### Expressions Régulières

import re\
re.search("\w","hola").group() = "h"\
re.findall("\w","hola") = \['h', 'o', 'l', 'a']\
re.findall("\w+(la)","hola caracola") = \['la', 'la']

**Significations spéciales :**\
. --> Tout\
\w --> \[a-zA-Z0-9\_]\
\d --> Nombre\
\s --> Caractère d'espace blanc\[ \n\r\t\f]\
\S --> Caractère non blanc\
^ --> Commence par\
$ --> Finit par\
\+ --> Un ou plusieurs\
\* --> 0 ou plusieurs\
? --> 0 ou 1 occurrence

**Options :**\
re.search(pat,str,re.IGNORECASE)\
IGNORECASE\
DOTALL --> Permet au point de correspondre à une nouvelle ligne\
MULTILINE --> Permet à ^ et $ de correspondre sur différentes lignes

re.findall("<.\*>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>foo\</b>and\<i>so on\</i>']\
re.findall("<.\*?>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>', '\</b>', '\<i>', '\</i>']

IterTools\
**produit**\
from **itertools** import product --> Génère des combinaisons entre 1 ou plusieurs listes, peut-être en répétant des valeurs, produit cartésien (propriété distributive)\
print list(**product**(\[1,2,3],\[3,4])) = \[(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]\
print list(**product**(\[1,2,3],repeat = 2)) = \[(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]

**permutations**\
from **itertools** import **permutations** --> Génère des combinaisons de tous les caractères à chaque position\
print list(permutations(\['1','2','3'])) = \[('1', '2', '3'), ('1', '3', '2'), ('2', '1', '3'),... Chaque combinaison possible\
print(list(permutations('123',2))) = \[('1', '2'), ('1', '3'), ('2', '1'), ('2', '3'), ('3', '1'), ('3', '2')] Chaque combinaison possible de longueur 2

**combinations**\
from itertools import **combinations** --> Génère toutes les combinaisons possibles sans répéter les caractères (si "ab" existe, ne génère pas "ba")\
print(list(**combinations**('123',2))) --> \[('1', '2'), ('1', '3'), ('2', '3')]

**combinations_with_replacement**\
from itertools import **combinations_with_replacement** --> Génère toutes les combinaisons possibles à partir du caractère (par exemple, le 3ème est mélangé à partir du 3ème mais pas avec le 2ème ou le premier)\
print(list(**combinations_with_replacement**('1133',2))) = \[('1', '1'), ('1', '1'), ('1', '3'), ('1', '3'), ('1', '1'), ('1', '3'), ('1', '3'), ('3', '3'), ('3', '3'), ('3', '3')]

### Décorateurs

Décorateur qui mesure le temps qu'une fonction met à s'exécuter (depuis [ici](https://towardsdatascience.com/decorating-functions-in-python-619cbbe82c74)):
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
Si vous l'exécutez, vous verrez quelque chose comme ce qui suit :
```
Let's call our decorated function
Decorated func!
Execution time: 4.792213439941406e-05 seconds
```
{{#include ../../banners/hacktricks-training.md}}
