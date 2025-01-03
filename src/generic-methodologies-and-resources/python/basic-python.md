# Grundlegendes Python

{{#include ../../banners/hacktricks-training.md}}

## Python Grundlagen

### Nützliche Informationen

list(xrange()) == range() --> In Python 3 ist range das xrange von Python 2 (es ist keine Liste, sondern ein Generator)\
Der Unterschied zwischen einem Tuple und einer Liste besteht darin, dass die Position eines Wertes in einem Tuple ihm Bedeutung verleiht, während Listen einfach geordnete Werte sind. Tuples haben Strukturen, aber Listen haben eine Reihenfolge.

### Hauptoperationen

Um eine Zahl zu potenzieren, verwendest du: 3\*\*2 (nicht 3^2)\
Wenn du 2/3 machst, gibt es 1 zurück, weil du zwei ints (Ganzzahlen) dividierst. Wenn du Dezimalzahlen möchtest, solltest du Floats dividieren (2.0/3.0).\
i >= j\
i <= j\
i == j\
i != j\
a und b\
a oder b\
nicht a\
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
dir(str) = Liste aller verfügbaren Methoden\
help(str) = Definition der Klasse str\
"a".upper() = "A"\
"A".lower() = "a"\
"abc".capitalize() = "Abc"\
sum(\[1,2,3]) = 6\
sorted(\[1,43,5,3,21,4])

**Zeichen verbinden**\
3 \* ’a’ = ‘aaa’\
‘a’ + ‘b’ = ‘ab’\
‘a’ + str(3) = ‘a3’\
\[1,2,3]+\[4,5]=\[1,2,3,4,5]

**Teile einer Liste**\
‘abc’\[0] = ‘a’\
'abc’\[-1] = ‘c’\
'abc’\[1:3] = ‘bc’ von \[1] bis \[2]\
"qwertyuiop"\[:-1] = 'qwertyuio'

**Kommentare**\
\# Einzeiliger Kommentar\
"""\
Mehrzeiliger Kommentar\
Ein weiterer\
"""

**Schleifen**
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
(4,) = Singleton\
d = () leeres Tuple\
d += (4,) --> Hinzufügen zu einem Tuple\
KANN NICHT! --> t1\[1] == 'Neuer Wert'\
list(t2) = \[5,6] --> Von Tuple zu Liste

### Liste (Array)

d = \[] leer\
a = \[1,2,3]\
b = \[4,5]\
a + b = \[1,2,3,4,5]\
b.append(6) = \[4,5,6]\
tuple(a) = (1,2,3) --> Von Liste zu Tuple

### Wörterbuch

d = {} leer\
monthNumbers={1:’Jan’, 2: ‘feb’,’feb’:2}—> monthNumbers ->{1:’Jan’, 2: ‘feb’,’feb’:2}\
monthNumbers\[1] = ‘Jan’\
monthNumbers\[‘feb’] = 2\
list(monthNumbers) = \[1,2,’feb’]\
monthNumbers.values() = \[‘Jan’,’feb’,2]\
keys = \[k for k in monthNumbers]\
a={'9':9}\
monthNumbers.update(a) = {'9':9, 1:’Jan’, 2: ‘feb’,’feb’:2}\
mN = monthNumbers.copy() #Unabhängige Kopie\
monthNumbers.get('key',0) #Überprüfen, ob der Schlüssel existiert, Rückgabewert von monthNumbers\["key"] oder 0, wenn er nicht existiert

### Menge

In Mengen gibt es keine Wiederholungen\
myset = set(\['a', 'b']) = {'a', 'b'}\
myset.add('c') = {'a', 'b', 'c'}\
myset.add('a') = {'a', 'b', 'c'} #Keine Wiederholungen\
myset.update(\[1,2,3]) = set(\['a', 1, 2, 'b', 'c', 3])\
myset.discard(10) #Wenn vorhanden, entfernen, wenn nicht, nichts\
myset.remove(10) #Wenn vorhanden, entfernen, wenn nicht, Ausnahme auslösen\
myset2 = set(\[1, 2, 3, 4])\
myset.union(myset2) #Werte in myset ODER myset2\
myset.intersection(myset2) #Werte in myset UND myset2\
myset.difference(myset2) #Werte in myset, aber nicht in myset2\
myset.symmetric_difference(myset2) #Werte, die nicht in myset UND myset2 sind (nicht in beiden)\
myset.pop() #Erhalte das erste Element der Menge und entferne es\
myset.intersection_update(myset2) #myset = Elemente in sowohl myset als auch myset2\
myset.difference_update(myset2) #myset = Elemente in myset, aber nicht in myset2\
myset.symmetric_difference_update(myset2) #myset = Elemente, die nicht in beiden sind

### Klassen

Die Methode in \_\_It\_\_ wird von sort verwendet, um zu vergleichen, ob ein Objekt dieser Klasse größer ist als ein anderes
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
### map, zip, filter, lambda, sorted und Einzeiler

**Map** ist wie: \[f(x) für x in iterable] --> map(tutple,\[a,b]) = \[(1,2,3),(4,5)]\
m = map(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) --> \[False, False, True, False, False, True, False, False, True]

**zip** stoppt, wenn das kürzere von foo oder bar stoppt:
```
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** wird verwendet, um eine Funktion zu definieren\
(lambda x,y: x+y)(5,3) = 8 --> Verwende lambda als einfache **Funktion**\
**sorted**(range(-5,6), key=lambda x: x\*\* 2) = \[0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5] --> Verwende lambda, um eine Liste zu sortieren\
m = **filter**(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) = \[3, 6, 9] --> Verwende lambda, um zu filtern\
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

### Ausnahmen
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

Wenn die Bedingung falsch ist, wird der String auf dem Bildschirm ausgegeben.
```
def avg(grades, weights):
assert not len(grades) == 0, 'no grades data'
assert len(grades) == 'wrong number grades'
```
### Generatoren, yield

Ein Generator gibt anstelle von etwas zurück, dass er etwas "yielded". Wenn Sie darauf zugreifen, gibt er den ersten generierten Wert "zurück", dann können Sie erneut darauf zugreifen und er gibt den nächsten generierten Wert zurück. So werden nicht alle Werte gleichzeitig generiert und es kann viel Speicher gespart werden, wenn man dies anstelle einer Liste mit allen Werten verwendet.
```
def myGen(n):
yield n
yield n + 1
```
g = myGen(6) --> 6\
next(g) --> 7\
next(g) --> Fehler

### Reguläre Ausdrücke

import re\
re.search("\w","hola").group() = "h"\
re.findall("\w","hola") = \['h', 'o', 'l', 'a']\
re.findall("\w+(la)","hola caracola") = \['la', 'la']

**Spezielle Bedeutungen:**\
. --> Alles\
\w --> \[a-zA-Z0-9\_]\
\d --> Zahl\
\s --> Leerzeichen-Zeichen\[ \n\r\t\f]\
\S --> Nicht-Leerzeichen-Zeichen\
^ --> Beginnt mit\
$ --> Endet mit\
\+ --> Eins oder mehr\
\* --> 0 oder mehr\
? --> 0 oder 1 Vorkommen

**Optionen:**\
re.search(pat,str,re.IGNORECASE)\
IGNORECASE\
DOTALL --> Erlaubt, dass Punkt Zeilenumbrüche übereinstimmt\
MULTILINE --> Erlaubt, dass ^ und $ in verschiedenen Zeilen übereinstimmen

re.findall("<.\*>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>foo\</b>and\<i>so on\</i>']\
re.findall("<.\*?>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>', '\</b>', '\<i>', '\</i>']

IterTools\
**product**\
from **itertools** import product --> Generiert Kombinationen zwischen 1 oder mehr Listen, möglicherweise wiederholte Werte, kartesisches Produkt (distributive Eigenschaft)\
print list(**product**(\[1,2,3],\[3,4])) = \[(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]\
print list(**product**(\[1,2,3],repeat = 2)) = \[(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]

**permutations**\
from **itertools** import **permutations** --> Generiert Kombinationen aller Zeichen in jeder Position\
print list(permutations(\['1','2','3'])) = \[('1', '2', '3'), ('1', '3', '2'), ('2', '1', '3'),... Jede mögliche Kombination\
print(list(permutations('123',2))) = \[('1', '2'), ('1', '3'), ('2', '1'), ('2', '3'), ('3', '1'), ('3', '2')] Jede mögliche Kombination der Länge 2

**combinations**\
from itertools import **combinations** --> Generiert alle möglichen Kombinationen ohne wiederholte Zeichen (wenn "ab" existiert, wird "ba" nicht generiert)\
print(list(**combinations**('123',2))) --> \[('1', '2'), ('1', '3'), ('2', '3')]

**combinations_with_replacement**\
from itertools import **combinations_with_replacement** --> Generiert alle möglichen Kombinationen ab dem Zeichen (zum Beispiel, die 3. wird ab der 3. gemischt, aber nicht mit der 2. oder 1.)\
print(list(**combinations_with_replacement**('1133',2))) = \[('1', '1'), ('1', '1'), ('1', '3'), ('1', '3'), ('1', '1'), ('1', '3'), ('1', '3'), ('3', '3'), ('3', '3'), ('3', '3')]

### Dekoratoren

Dekorator, der die Zeit misst, die eine Funktion benötigt, um ausgeführt zu werden (von [hier](https://towardsdatascience.com/decorating-functions-in-python-619cbbe82c74)):
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
Wenn Sie es ausführen, sehen Sie etwas wie das Folgende:
```
Let's call our decorated function
Decorated func!
Execution time: 4.792213439941406e-05 seconds
```
{{#include ../../banners/hacktricks-training.md}}
