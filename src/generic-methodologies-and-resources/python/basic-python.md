# Basic Python

{{#include ../../banners/hacktricks-training.md}}

## Python Basics

### Useful information

list(xrange()) == range() --> Python3 में range, python2 का xrange है (यह एक सूची नहीं है बल्कि एक जनरेटर है)\
Tuple और List के बीच का अंतर यह है कि tuple में एक मान की स्थिति उसे अर्थ देती है लेकिन सूचियाँ केवल क्रमबद्ध मान हैं। Tuples में संरचनाएँ होती हैं लेकिन सूचियों में एक क्रम होता है।

### Main operations

एक संख्या बढ़ाने के लिए आप उपयोग करते हैं: 3\*\*2 (नहीं 3^2)\
यदि आप 2/3 करते हैं तो यह 1 लौटाता है क्योंकि आप दो ints (integers) को विभाजित कर रहे हैं। यदि आप दशमलव चाहते हैं तो आपको floats (2.0/3.0) को विभाजित करना चाहिए।\
i >= j\
i <= j\
i == j\
i != j\
a और b\
a या b\
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
dir(str) = उपलब्ध सभी विधियों की सूची\
help(str) = str वर्ग की परिभाषा\
"a".upper() = "A"\
"A".lower() = "a"\
"abc".capitalize() = "Abc"\
sum(\[1,2,3]) = 6\
sorted(\[1,43,5,3,21,4])

**Join chars**\
3 \* ’a’ = ‘aaa’\
‘a’ + ‘b’ = ‘ab’\
‘a’ + str(3) = ‘a3’\
\[1,2,3]+\[4,5]=\[1,2,3,4,5]

**Parts of a list**\
‘abc’\[0] = ‘a’\
'abc’\[-1] = ‘c’\
'abc’\[1:3] = ‘bc’ from \[1] to \[2]\
"qwertyuiop"\[:-1] = 'qwertyuio'

**Comments**\
\# One line comment\
"""\
Several lines comment\
Another one\
"""

**Loops**
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
### ट्यूपल्स

t1 = (1,'2,'three')\
t2 = (5,6)\
t3 = t1 + t2 = (1, '2', 'three', 5, 6)\
(4,) = सिंगलटन\
d = () खाली ट्यूपल\
d += (4,) --> ट्यूपल में जोड़ना\
CANT! --> t1\[1] == 'New value'\
list(t2) = \[5,6] --> ट्यूपल से सूची में

### सूची (array)

d = \[] खाली\
a = \[1,2,3]\
b = \[4,5]\
a + b = \[1,2,3,4,5]\
b.append(6) = \[4,5,6]\
tuple(a) = (1,2,3) --> सूची से ट्यूपल में

### शब्दकोश

d = {} खाली\
monthNumbers={1:’Jan’, 2: ‘feb’,’feb’:2}—> monthNumbers ->{1:’Jan’, 2: ‘feb’,’feb’:2}\
monthNumbers\[1] = ‘Jan’\
monthNumbers\[‘feb’] = 2\
list(monthNumbers) = \[1,2,’feb’]\
monthNumbers.values() = \[‘Jan’,’feb’,2]\
keys = \[k for k in monthNumbers]\
a={'9':9}\
monthNumbers.update(a) = {'9':9, 1:’Jan’, 2: ‘feb’,’feb’:2}\
mN = monthNumbers.copy() #स्वतंत्र प्रति\
monthNumbers.get('key',0) #जांचें कि कुंजी मौजूद है, monthNumbers\["key"] का मान लौटाएं या 0 यदि यह मौजूद नहीं है

### सेट

सेट में कोई पुनरावृत्ति नहीं होती\
myset = set(\['a', 'b']) = {'a', 'b'}\
myset.add('c') = {'a', 'b', 'c'}\
myset.add('a') = {'a', 'b', 'c'} #कोई पुनरावृत्ति नहीं\
myset.update(\[1,2,3]) = set(\['a', 1, 2, 'b', 'c', 3])\
myset.discard(10) #यदि मौजूद है, तो हटा दें, यदि नहीं, तो कुछ नहीं\
myset.remove(10) #यदि मौजूद है तो हटा दें, यदि नहीं, तो अपवाद उठाएं\
myset2 = set(\[1, 2, 3, 4])\
myset.union(myset2) #myset या myset2 में मान\
myset.intersection(myset2) #myset और myset2 में मान\
myset.difference(myset2) #myset में मान लेकिन myset2 में नहीं\
myset.symmetric_difference(myset2) #मान जो myset और myset2 में नहीं हैं (दोनों में नहीं)\
myset.pop() #सेट का पहला तत्व प्राप्त करें और हटा दें\
myset.intersection_update(myset2) #myset = दोनों myset और myset2 में तत्व\
myset.difference_update(myset2) #myset = myset में तत्व लेकिन myset2 में नहीं\
myset.symmetric_difference_update(myset2) #myset = दोनों में नहीं होने वाले तत्व

### कक्षाएँ

\_\_It\_\_ में विधि वह होगी जिसका उपयोग क्रमबद्ध करने के लिए किया जाएगा यह तुलना करने के लिए कि क्या इस कक्षा का एक वस्तु दूसरे से बड़ा है
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
### map, zip, filter, lambda, sorted और one-liners

**Map** इस तरह है: \[f(x) for x in iterable] --> map(tutple,\[a,b]) = \[(1,2,3),(4,5)]\
m = map(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) --> \[False, False, True, False, False, True, False, False, True]

**zip** तब रुकता है जब foo या bar में से छोटा रुकता है:
```
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** एक फ़ंक्शन को परिभाषित करने के लिए उपयोग किया जाता है\
(lambda x,y: x+y)(5,3) = 8 --> lambda का उपयोग सरल **function** के रूप में करें\
**sorted**(range(-5,6), key=lambda x: x\*\* 2) = \[0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5] --> एक सूची को क्रमबद्ध करने के लिए lambda का उपयोग करें\
m = **filter**(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) = \[3, 6, 9] --> फ़िल्टर करने के लिए lambda का उपयोग करें\
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

### अपवाद
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

यदि शर्त गलत है, तो स्ट्रिंग स्क्रीन पर प्रिंट की जाएगी।
```
def avg(grades, weights):
assert not len(grades) == 0, 'no grades data'
assert len(grades) == 'wrong number grades'
```
### जनरेटर, yield

एक जनरेटर, कुछ लौटाने के बजाय, "yield" करता है। जब आप इसे एक्सेस करते हैं, यह उत्पन्न किया गया पहला मान "return" करेगा, फिर, आप इसे फिर से एक्सेस कर सकते हैं और यह अगला उत्पन्न किया गया मान लौटाएगा। इसलिए, सभी मान एक ही समय में उत्पन्न नहीं होते हैं और सभी मानों के साथ एक सूची के बजाय इसका उपयोग करके बहुत सारी मेमोरी बचाई जा सकती है।
```
def myGen(n):
yield n
yield n + 1
```
g = myGen(6) --> 6\
next(g) --> 7\
next(g) --> Error

### नियमित अभिव्यक्तियाँ

import re\
re.search("\w","hola").group() = "h"\
re.findall("\w","hola") = \['h', 'o', 'l', 'a']\
re.findall("\w+(la)","hola caracola") = \['la', 'la']

**विशेष अर्थ:**\
. --> सब कुछ\
\w --> \[a-zA-Z0-9\_]\
\d --> संख्या\
\s --> व्हाइटस्पेस वर्ण\[ \n\r\t\f]\
\S --> गैर-व्हाइटस्पेस वर्ण\
^ --> से शुरू होता है\
$ --> से समाप्त होता है\
\+ --> एक या अधिक\
\* --> 0 या अधिक\
? --> 0 या 1 बार

**विकल्प:**\
re.search(pat,str,re.IGNORECASE)\
IGNORECASE\
DOTALL --> डॉट को नई पंक्ति से मेल खाने की अनुमति दें\
MULTILINE --> ^ और $ को विभिन्न पंक्तियों में मेल खाने की अनुमति दें

re.findall("<.\*>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>foo\</b>and\<i>so on\</i>']\
re.findall("<.\*?>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>', '\</b>', '\<i>', '\</i>']

IterTools\
**product**\
from **itertools** import product --> 1 या अधिक सूचियों के बीच संयोजन उत्पन्न करता है, शायद मानों को दोहराते हुए, कार्तेशियन उत्पाद (वितरण गुण)\
print list(**product**(\[1,2,3],\[3,4])) = \[(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]\
print list(**product**(\[1,2,3],repeat = 2)) = \[(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]

**permutations**\
from **itertools** import **permutations** --> हर स्थिति में सभी वर्णों के संयोजन उत्पन्न करता है\
print list(permutations(\['1','2','3'])) = \[('1', '2', '3'), ('1', '3', '2'), ('2', '1', '3'),... हर संभावित संयोजन\
print(list(permutations('123',2))) = \[('1', '2'), ('1', '3'), ('2', '1'), ('2', '3'), ('3', '1'), ('3', '2')] लंबाई 2 के हर संभावित संयोजन

**combinations**\
from itertools import **combinations** --> बिना वर्णों को दोहराए सभी संभावित संयोजन उत्पन्न करता है (यदि "ab" मौजूद है, तो "ba" उत्पन्न नहीं करता)\
print(list(**combinations**('123',2))) --> \[('1', '2'), ('1', '3'), ('2', '3')]

**combinations_with_replacement**\
from itertools import **combinations_with_replacement** --> वर्ण से आगे सभी संभावित संयोजन उत्पन्न करता है (उदाहरण के लिए, तीसरा तीसरे से मिलाया जाता है लेकिन दूसरे या पहले के साथ नहीं)\
print(list(**combinations_with_replacement**('1133',2))) = \[('1', '1'), ('1', '1'), ('1', '3'), ('1', '3'), ('1', '1'), ('1', '3'), ('1', '3'), ('3', '3'), ('3', '3'), ('3', '3')]

### डेकोरेटर

डेकोरेटर जो एक फ़ंक्शन को निष्पादित करने में लगने वाले समय को मापता है (from [here](https://towardsdatascience.com/decorating-functions-in-python-619cbbe82c74)):
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
यदि आप इसे चलाते हैं, तो आप निम्नलिखित जैसा कुछ देखेंगे:
```
Let's call our decorated function
Decorated func!
Execution time: 4.792213439941406e-05 seconds
```
{{#include ../../banners/hacktricks-training.md}}
