# Temel Python

{{#include ../../banners/hacktricks-training.md}}

## Python Temelleri

### Faydalı bilgiler

list(xrange()) == range() --> Python3'te range, python2'nin xrange'idir (bu bir liste değil, bir jeneratördür)\
Bir Tuple ile bir Liste arasındaki fark, bir tuple'daki bir değerin konumunun ona anlam katmasıdır, ancak listeler sadece sıralı değerlerdir. Tuple'lar yapıya sahiptir, ancak listeler bir sıraya sahiptir.

### Ana işlemler

Bir sayıyı yükseltmek için: 3\*\*2 kullanırsınız (3^2 değil)\
Eğer 2/3 yaparsanız, iki int (tam sayı) böldüğünüz için 1 döner. Ondalık istiyorsanız, float'ları bölmelisiniz (2.0/3.0).\
i >= j\
i <= j\
i == j\
i != j\
a ve b\
a veya b\
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
dir(str) = Mevcut tüm yöntemlerin listesi\
help(str) = str sınıfının tanımı\
"a".upper() = "A"\
"A".lower() = "a"\
"abc".capitalize() = "Abc"\
sum(\[1,2,3]) = 6\
sorted(\[1,43,5,3,21,4])

**Karakterleri birleştir**\
3 \* ’a’ = ‘aaa’\
‘a’ + ‘b’ = ‘ab’\
‘a’ + str(3) = ‘a3’\
\[1,2,3]+\[4,5]=\[1,2,3,4,5]

**Bir listenin parçaları**\
‘abc’\[0] = ‘a’\
'abc’\[-1] = ‘c’\
'abc’\[1:3] = ‘bc’ \[1]'den \[2]'ye kadar\
"qwertyuiop"\[:-1] = 'qwertyuio'

**Yorumlar**\
\# Tek satırlık yorum\
"""\
Birden fazla satırlık yorum\
Başka bir tane\
""" 

**Döngüler**
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
### Demetler

t1 = (1,'2,'three')\
t2 = (5,6)\
t3 = t1 + t2 = (1, '2', 'three', 5, 6)\
(4,) = Tekil\
d = () boş demet\
d += (4,) --> Bir demete ekleme\
OLMAZ! --> t1\[1] == 'Yeni değer'\
list(t2) = \[5,6] --> Demetten listeye

### Liste (dizi)

d = \[] boş\
a = \[1,2,3]\
b = \[4,5]\
a + b = \[1,2,3,4,5]\
b.append(6) = \[4,5,6]\
tuple(a) = (1,2,3) --> Listeden demete

### Sözlük

d = {} boş\
monthNumbers={1:’Jan’, 2: ‘feb’,’feb’:2}—> monthNumbers ->{1:’Jan’, 2: ‘feb’,’feb’:2}\
monthNumbers\[1] = ‘Jan’\
monthNumbers\[‘feb’] = 2\
list(monthNumbers) = \[1,2,’feb’]\
monthNumbers.values() = \[‘Jan’,’feb’,2]\
keys = \[k for k in monthNumbers]\
a={'9':9}\
monthNumbers.update(a) = {'9':9, 1:’Jan’, 2: ‘feb’,’feb’:2}\
mN = monthNumbers.copy() #Bağımsız kopya\
monthNumbers.get('key',0) #Anahtarın var olup olmadığını kontrol et, monthNumbers\["key"] değerini döndür veya yoksa 0 döndür

### Küme

Kümede tekrar yoktur\
myset = set(\['a', 'b']) = {'a', 'b'}\
myset.add('c') = {'a', 'b', 'c'}\
myset.add('a') = {'a', 'b', 'c'} #Tekrar yok\
myset.update(\[1,2,3]) = set(\['a', 1, 2, 'b', 'c', 3])\
myset.discard(10) #Varsa, kaldır, yoksa, hiçbir şey\
myset.remove(10) #Varsa kaldır, yoksa, istisna fırlat\
myset2 = set(\[1, 2, 3, 4])\
myset.union(myset2) #myset VEYA myset2 değerleri\
myset.intersection(myset2) #myset VE myset2 değerleri\
myset.difference(myset2) #myset'teki ama myset2'de olmayan değerler\
myset.symmetric_difference(myset2) #myset VE myset2'de olmayan değerler (her ikisinde de yok)\
myset.pop() #Kümenin ilk elemanını al ve kaldır\
myset.intersection_update(myset2) #myset = Hem myset hem de myset2'deki elemanlar\
myset.difference_update(myset2) #myset = myset'teki ama myset2'de olmayan elemanlar\
myset.symmetric_difference_update(myset2) #myset = Her ikisinde de olmayan elemanlar

### Sınıflar

\_\_It\_\_ içindeki yöntem, bu sınıfın bir nesnesinin diğerinden büyük olup olmadığını karşılaştırmak için sıralama tarafından kullanılacaktır.
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
### map, zip, filter, lambda, sorted ve tek satırlar

**Map** şöyle: \[f(x) for x in iterable] --> map(tutple,\[a,b]) = \[(1,2,3),(4,5)]\
m = map(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) --> \[False, False, True, False, False, True, False, False, True]

**zip** foo veya bar'ın daha kısa olanı durduğunda durur:
```
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda**, bir fonksiyonu tanımlamak için kullanılır\
(lambda x,y: x+y)(5,3) = 8 --> Lambda'yı basit bir **fonksiyon** olarak kullanın\
**sorted**(range(-5,6), key=lambda x: x\*\* 2) = \[0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5] --> Lambda'yı bir listeyi sıralamak için kullanın\
m = **filter**(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9]) = \[3, 6, 9] --> Lambda'yı filtrelemek için kullanın\
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

### İstisnalar
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

Eğer koşul yanlışsa, dize ekranda yazdırılacaktır.
```
def avg(grades, weights):
assert not len(grades) == 0, 'no grades data'
assert len(grades) == 'wrong number grades'
```
### Generatörler, yield

Bir generatör, bir şey döndürmek yerine, "yield" eder. Ona eriştiğinizde, üretilen ilk değeri "döndürür", ardından tekrar erişebilir ve bir sonraki üretilen değeri döndürebilir. Yani, tüm değerler aynı anda üretilmez ve bu yöntem, tüm değerlerin bulunduğu bir liste yerine kullanıldığında çok fazla bellek tasarrufu sağlayabilir.
```
def myGen(n):
yield n
yield n + 1
```
g = myGen(6) --> 6\
next(g) --> 7\
next(g) --> Hata

### Düzenli İfadeler

import re\
re.search("\w","hola").group() = "h"\
re.findall("\w","hola") = \['h', 'o', 'l', 'a']\
re.findall("\w+(la)","hola caracola") = \['la', 'la']

**Özel anlamlar:**\
. --> Her şey\
\w --> \[a-zA-Z0-9\_]\
\d --> Sayı\
\s --> Boşluk karakteri\[ \n\r\t\f]\
\S --> Boşluk olmayan karakter\
^ --> İle başlar\
$ --> İle biter\
\+ --> Bir veya daha fazla\
\* --> 0 veya daha fazla\
? --> 0 veya 1 kez

**Seçenekler:**\
re.search(pat,str,re.IGNORECASE)\
IGNORECASE\
DOTALL --> Noktanın yeni satırı eşleştirmesine izin ver\
MULTILINE --> ^ ve $'nın farklı satırlarda eşleşmesine izin ver

re.findall("<.\*>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>foo\</b>and\<i>so on\</i>']\
re.findall("<.\*?>", "\<b>foo\</b>and\<i>so on\</i>") = \['\<b>', '\</b>', '\<i>', '\</i>']

IterTools\
**product**\
from **itertools** import product --> 1 veya daha fazla liste arasında kombinasyonlar oluşturur, belki değerleri tekrar eder, kartesyen çarpımı (dağıtım özelliği)\
print list(**product**(\[1,2,3],\[3,4])) = \[(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]\
print list(**product**(\[1,2,3],repeat = 2)) = \[(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]

**permutations**\
from **itertools** import **permutations** --> Her pozisyondaki tüm karakterlerin kombinasyonlarını oluşturur\
print list(permutations(\['1','2','3'])) = \[('1', '2', '3'), ('1', '3', '2'), ('2', '1', '3'),... Her olası kombinasyon\
print(list(permutations('123',2))) = \[('1', '2'), ('1', '3'), ('2', '1'), ('2', '3'), ('3', '1'), ('3', '2')] Uzunluğu 2 olan her olası kombinasyon

**combinations**\
from itertools import **combinations** --> Tekrar eden karakterler olmadan tüm olası kombinasyonları oluşturur (eğer "ab" mevcutsa, "ba" oluşturmaz)\
print(list(**combinations**('123',2))) --> \[('1', '2'), ('1', '3'), ('2', '3')]

**combinations_with_replacement**\
from itertools import **combinations_with_replacement** --> Karakterden itibaren tüm olası kombinasyonları oluşturur (örneğin, 3. karakter 3. karakterden itibaren karışır ama 2. veya 1. ile değil)\
print(list(**combinations_with_replacement**('1133',2))) = \[('1', '1'), ('1', '1'), ('1', '3'), ('1', '3'), ('1', '1'), ('1', '3'), ('1', '3'), ('3', '3'), ('3', '3'), ('3', '3')]

### Dekoratörler

Bir fonksiyonun çalışması için gereken süreyi ölçen dekoratör (from [here](https://towardsdatascience.com/decorating-functions-in-python-619cbbe82c74)):
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
Eğer bunu çalıştırırsanız, aşağıdakine benzer bir şey göreceksiniz:
```
Let's call our decorated function
Decorated func!
Execution time: 4.792213439941406e-05 seconds
```
{{#include ../../banners/hacktricks-training.md}}
