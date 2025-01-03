# Basiese Python

{{#include ../../banners/hacktricks-training.md}}

## Python Basiese Beginsels

### Nuttige inligting

list(xrange()) == range() --> In python3 is range die xrange van python2 (dit is nie 'n lys nie, maar 'n generator)\
Die verskil tussen 'n Tuple en 'n Lys is dat die posisie van 'n waarde in 'n tuple dit betekenis gee, maar die lyste is net geordende waardes. Tuples het strukture, maar lyste het 'n volgorde.

### Hoofbedrywighede

Om 'n getal te verhef gebruik jy: 3\*\*2 (nie 3^2)\
As jy 2/3 doen, keer dit 1 terug omdat jy twee ints (heelgetalle) deel. As jy desimale wil hê, moet jy floats deel (2.0/3.0).\
i >= j\
i <= j\
i == j\
i != j\
a en b\
a of b\
nie a\
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
dir(str) = Lys van al die beskikbare metodes\
help(str) = Definisie van die klas str\
"a".upper() = "A"\
"A".lower() = "a"\
"abc".capitalize() = "Abc"\
sum(\[1,2,3]) = 6\
sorted(\[1,43,5,3,21,4])

**Voeg karakters saam**\
3 \* ’a’ = ‘aaa’\
‘a’ + ‘b’ = ‘ab’\
‘a’ + str(3) = ‘a3’\
\[1,2,3]+\[4,5]=\[1,2,3,4,5]

**Dele van 'n lys**\
‘abc’\[0] = ‘a’\
'abc’\[-1] = ‘c’\
'abc’\[1:3] = ‘bc’ van \[1] tot \[2]\
"qwertyuiop"\[:-1] = 'qwertyuio'

**Kommentaar**\
\# Eenlyn kommentaar\
"""\
Verskeie lyn kommentaar\
Nog een\
"""

**Lusse**
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
d = () leë tuple\
d += (4,) --> Voeg by 'n tuple\
KAN NIE! --> t1\[1] == 'Nuwe waarde'\
list(t2) = \[5,6] --> Van tuple na lys

### List (array)

d = \[] leë\
a = \[1,2,3]\
b = \[4,5]\
a + b = \[1,2,3,4,5]\
b.append(6) = \[4,5,6]\
tuple(a) = (1,2,3) --> Van lys na tuple

### Dictionary

d = {} leë\
monthNumbers={1:’Jan’, 2: ‘feb’,’feb’:2}—> monthNumbers ->{1:’Jan’, 2: ‘feb’,’feb’:2}\
monthNumbers\[1] = ‘Jan’\
monthNumbers\[‘feb’] = 2\
list(monthNumbers) = \[1,2,’feb’]\
monthNumbers.values() = \[‘Jan’,’feb’,2]\
keys = \[k for k in monthNumbers]\
a={'9':9}\
monthNumbers.update(a) = {'9':9, 1:’Jan’, 2: ‘feb’,’feb’:2}\
mN = monthNumbers.copy() #Onafhanklike kopie\
monthNumbers.get('key',0) #Kontroleer of sleutel bestaan, Teruggee waarde van monthNumbers\["key"] of 0 as dit nie bestaan nie

### Set

In stelle is daar geen herhalings\
myset = set(\['a', 'b']) = {'a', 'b'}\
myset.add('c') = {'a', 'b', 'c'}\
myset.add('a') = {'a', 'b', 'c'} #Geen herhalings\
myset.update(\[1,2,3]) = set(\['a', 1, 2, 'b', 'c', 3])\
myset.discard(10) #As dit teenwoordig is, verwyder dit, as nie, niks\
myset.remove(10) #As dit teenwoordig is, verwyder dit, as nie, gooi 'n uitsondering\
myset2 = set(\[1, 2, 3, 4])\
myset.union(myset2) #Waardes in myset OF myset2\
myset.intersection(myset2) #Waardes in myset EN myset2\
myset.difference(myset2) #Waardes in myset maar nie in myset2\
myset.symmetric_difference(myset2) #Waardes wat nie in myset EN myset2 is (nie in albei)\
myset.pop() #Kry die eerste element van die stel en verwyder dit\
myset.intersection_update(myset2) #myset = Elemente in beide myset en myset2\
myset.difference_update(myset2) #myset = Elemente in myset maar nie in myset2\
myset.symmetric_difference_update(myset2) #myset = Elemente wat nie in albei is nie

### Classes

Die metode in \_\_It\_\_ sal die een wees wat deur sort gebruik word om te vergelyk of 'n objek van hierdie klas groter is as 'n ander
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
### kaart, zip, filter, lambda, gesorteer en een-liners

**Kaart** is soos: \[f(x) vir x in iterable] --> map(tutple,\[a,b]) = \[(1,2,3),(4,5)]\
m = map(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) --> \[False, False, True, False, False, True, False, False, True]

**zip** stop wanneer die korter van foo of bar stop:
```
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** word gebruik om 'n funksie te definieer\
(lambda x,y: x+y)(5,3) = 8 --> Gebruik lambda as 'n eenvoudige **funksie**\
**sorted**(range(-5,6), key=lambda x: x\*\* 2) = \[0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5] --> Gebruik lambda om 'n lys te sorteer\
m = **filter**(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) = \[3, 6, 9] --> Gebruik lambda om te filter\
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

### Uitsonderings
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

As die voorwaarde vals is, sal die string op die skerm geprint word.
```
def avg(grades, weights):
assert not len(grades) == 0, 'no grades data'
assert len(grades) == 'wrong number grades'
```
### Generators, yield

'n Generator, in plaas daarvan om iets terug te gee, "gee" dit iets. Wanneer jy dit benader, sal dit die eerste waarde wat gegenereer is, "teruggee", dan kan jy dit weer benader en dit sal die volgende waarde wat gegenereer is, teruggee. So, al die waardes word nie terselfdertyd gegenereer nie en baie geheue kan bespaar word deur dit te gebruik in plaas van 'n lys met al die waardes.
```
def myGen(n):
yield n
yield n + 1
```
g = myGen(6) --> 6\
next(g) --> 7\
next(g) --> Fout

### Gereelde Uitdrukkings

import re\
re.search("\w","hola").group() = "h"\
re.findall("\w","hola") = \['h', 'o', 'l', 'a']\
re.findall("\w+(la)","hola caracola") = \['la', 'la']

**Spesiale betekenisse:**\
. --> Alles\
\w --> \[a-zA-Z0-9\_]\
\d --> Getal\
\s --> Witruimte karakter\[ \n\r\t\f]\
\S --> Nie-witruimte karakter\
^ --> Begin met\
$ --> Eindig met\
\+ --> Een of meer\
\* --> 0 of meer\
? --> 0 of 1 voorkoms

**Opsies:**\
re.search(pat,str,re.IGNORECASE)\
IGNORECASE\
DOTALL --> Laat kolletjie toe om nuwe lyn te pas\
MULTILINE --> Laat ^ en $ toe om in verskillende lyne te pas

re.findall("<.\*>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>foo\</b>and\<i>so on\</i>']\
re.findall("<.\*?>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>', '\</b>', '\<i>', '\</i>']

IterTools\
**produk**\
from **itertools** import product --> Genereer kombinasies tussen 1 of meer lyste, moontlik herhalende waardes, kartesiese produk (distributiewe eienskap)\
print list(**product**(\[1,2,3],\[3,4])) = \[(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]\
print list(**product**(\[1,2,3],repeat = 2)) = \[(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]

**permutasies**\
from **itertools** import **permutations** --> Genereer kombinasies van alle karakters in elke posisie\
print list(permutations(\['1','2','3'])) = \[('1', '2', '3'), ('1', '3', '2'), ('2', '1', '3'),... Elke moontlike kombinasie\
print(list(permutations('123',2))) = \[('1', '2'), ('1', '3'), ('2', '1'), ('2', '3'), ('3', '1'), ('3', '2')] Elke moontlike kombinasie van lengte 2

**kombinasies**\
from itertools import **combinations** --> Genereer alle moontlike kombinasies sonder om karakters te herhaal (as "ab" bestaan, genereer nie "ba")\
print(list(**combinations**('123',2))) --> \[('1', '2'), ('1', '3'), ('2', '3')]

**kombinasies_met_vervanging**\
from itertools import **combinations_with_replacement** --> Genereer alle moontlike kombinasies vanaf die karakter voort (byvoorbeeld, die 3de is gemeng vanaf die 3de voort, maar nie met die 2de of eerste)\
print(list(**combinations_with_replacement**('1133',2))) = \[('1', '1'), ('1', '1'), ('1', '3'), ('1', '3'), ('1', '1'), ('1', '3'), ('1', '3'), ('3', '3'), ('3', '3'), ('3', '3')]

### Dekorateurs

Dekorateur wat die tyd meet wat 'n funksie benodig om uitgevoer te word (van [hier](https://towardsdatascience.com/decorating-functions-in-python-619cbbe82c74)):
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
As jy dit uitvoer, sal jy iets soos die volgende sien:
```
Let's call our decorated function
Decorated func!
Execution time: 4.792213439941406e-05 seconds
```
{{#include ../../banners/hacktricks-training.md}}
