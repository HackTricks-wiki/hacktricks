# Basic Python

## Python Basics

### Usefull information

It is an interpreted language  
list\(xrange\(\)\) == range\(\) --&gt; In python3 range is the xrange of python2 \(it is not a list but a generator\)  
The difference between a Tuple and a List is that the position of a value in a tuple gives it a meaning but the lists are just ordered values. Tuples have structures, lists have order

### Main operations

To raise a number you should do: 3\*\*2 \(it isn't 3^2\)  
If you do 2/3 it returns 1 because you are dividing two ints. If you want decimals you should divide floats \(2.0/3.0\).  
i &gt;= j  
i &lt;= j  
i == j  
i != j  
a and b  
a or b  
not a  
float\(a\)  
int\(a\)  
str\(d\)  
ord\("A"\) = 65  
chr\(65\) = 'A'  
hex\(100\) = '0x64'  
hex\(100\)\[2:\] = '64'  
isinstance\(1, int\) = True  
"a b".split\(" "\) = \['a', 'b'\]  
" ".join\(\['a', 'b'\]\) = "a b"  
"abcdef".startswith\("ab"\) = True  
"abcdef".contains\("abc"\) = True  
"abc\n".strip\(\) = "abc"  
"apbc".replace\("p",""\) = "abc"  
dir\(str\) = List of all the availble methods  
help\(str\) = Definition of the class str  
"a".upper\(\) = "A"  
"A".lower\(\) = "a"  
"abc".capitalize\(\) = "Abc"  
sum\(\[1,2,3\]\) = 6  
sorted\(\[1,43,5,3,21,4\]\)

**Join chars**  
3 \* ’a’ = ‘aaa’  
‘a’ + ‘b’ = ‘ab’  
‘a’ + str\(3\) = ‘a3’  
\[1,2,3\]+\[4,5\]=\[1,2,3,4,5\]

**Parts of a list**  
‘abc’\[0\] = ‘a’  
'abc’\[-1\] = ‘c’  
'abc’\[1:3\] = ‘bc’ from \[1\] to \[2\]  
"qwertyuiop"\[:-1\] = 'qwertyuio'

**Comments**  
\# One line comment  
"""  
Several lines comment  
Another one  
"""

**Loops**

```text
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
    #something with letter in "hola"
```

### Tuples

t1 = \(1,'2,'three'\)  
t2 = \(5,6\)  
t3 = t1 + t2 = \(1, '2', 'three', 5, 6\)  
\(4,\) = Singelton  
d = \(\) empty tuple  
d += \(4,\) --&gt; Adding into a tuple  
CANT! --&gt; t1\[1\] == 'New value'  
list\(t2\) = \[5,6\] --&gt; From tuple to list

### List \(array\)

d = \[\] empty  
a = \[1,2,3\]  
b = \[4,5\]  
a + b = \[1,2,3,4,5\]  
b.append\(6\) = \[4,5,6\]  
tuple\(a\) = \(1,2,3\) --&gt; From list to tuple

### Dictionary

d = {} empty  
monthNumbers={1:’Jan’, 2: ‘feb’,’feb’:2}—&gt; monthNumbers -&gt;{1:’Jan’, 2: ‘feb’,’feb’:2}  
monthNumbers\[1\] = ‘Jan’  
monthNumbers\[‘feb’\] = 2  
list\(monthNumbers\) = \[1,2,’feb’\]  
monthNumbers.values\(\) = \[‘Jan’,’feb’,2\]  
keys = \[k for k in monthNumbers\]  
a={'9':9}  
monthNumbers.update\(a\) = {'9':9, 1:’Jan’, 2: ‘feb’,’feb’:2}  
mN = monthNumbers.copy\(\) \#Independent copy  
monthNumbers.get\('key',0\) \#Check if key exists, Return value of monthNumbers\["key"\] or 0 if it does not exists

### Set

In the sets there are not repetitions  
myset = set\(\['a', 'b'\]\) = {'a', 'b'}  
myset.add\('c'\) = {'a', 'b', 'c'}  
myset.add\('a'\) = {'a', 'b', 'c'} \#No repetitions  
myset.update\(\[1,2,3\]\) = set\(\['a', 1, 2, 'b', 'c', 3\]\)  
myset.discard\(10\) \#If present, remove it, if not, nothing  
myset.remove\(10\) \#If present remove it, if not, rise exception  
myset2 = set\(\[1, 2, 3, 4\]\)  
myset.union\(myset2\) \#Values it myset OR myset2  
myset.intersection\(myset2\) \#Values in myset AND myset2  
myset.difference\(myset2\) \#Values in myset but not in myset2  
myset.symmetric\_difference\(myset2\) \#Values that are not in myset AND myset2 \(not in both\)  
myset.pop\(\) \#Get the first element of the set and remove it  
myset.intersection\_update\(myset2\) \#myset = Elements in both myset and myset2  
myset.difference\_update\(myset2\) \#myset = Elements in myset but not in myset2  
myset.symmetric\_difference\_update\(myset2\) \#myset = Elements that are not in both

### Classes

The method in \_\_It\_\_ will be the one used by sort in order to compare if an object of this class is bigger than other

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

### map, zip, filter, lambda, sorted and one-liners

**Map** is like: \[f\(x\) for x in iterable\] --&gt; map\(tutple,\[a,b\]\) = \[\(1,2,3\),\(4,5\)\]  
m = map\(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9\]\) --&gt; \[False, False, True, False, False, True, False, False, True\]

**zip** stops when the shorter of foo or bar stops:

```text
for f, b in zip(foo, bar):
    print(f, b)
```

**Lambda** is used to define a function  
\(lambda x,y: x+y\)\(5,3\) = 8 --&gt; Use lambda as simple **function**  
**sorted**\(range\(-5,6\), key=lambda x: x\*\* 2\) = \[0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5\] --&gt; Use lambda to sort a list  
m = **filter**\(lambda x: x % 3 == 0, \[1, 2, 3, 4, 5, 6, 7, 8, 9\]\) = \[3, 6, 9\] --&gt; Use lambda to filter  
**reduce** \(lambda x,y: x\*y, \[1,2,3,4\]\) = 24

```text
def make_adder(n):
	return lambda x: x+n
plus3 = make_adder(3)
plus3(4) = 7 # 3 + 4 = 7

class Car:
	crash = lambda self: print('Boom!')
my_car = Car(); my_car.crash() = 'Boom!'
```

mult1 = \[x for x in \[1, 2, 3, 4, 5, 6, 7, 8, 9\] if x%3 == 0 \]

### Exceptions

```text
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

### Assert\(\)

If the condition is false the string will by printed in the screen

```text
def avg(grades, weights):
	assert not len(grades) == 0, 'no grades data'
	assert len(grades) == 'wrong number grades'
```

### Generators, yield

A generator, instead of returning something, it "yields" something. When you access it, it will "return" the first value generated, then, you can access it again and it will return the next value generated. So, all the values are not generated at the same time and a lot of memory could be saved using this instead of a list with all the values.

```text
def myGen(n):
	yield n
	yield n + 1
```

g = myGen\(6\) --&gt; 6  
next\(g\) --&gt; 7  
next\(g\) --&gt; Error

### Regular Expresions

import re  
re.search\("\w","hola"\).group\(\) = "h"  
re.findall\("\w","hola"\) = \['h', 'o', 'l', 'a'\]  
re.findall\("\w+\(la\)","hola caracola"\) = \['la', 'la'\]

**Special meanings:**  
. --&gt; Everything  
\w --&gt; \[a-zA-Z0-9\_\]  
\d --&gt; Number  
\s --&gt; WhiteSpace char\[ \n\r\t\f\]  
\S --&gt; Non-whitespace char  
^ --&gt; Starts with  
$ --&gt; Ends with  
+ --&gt; One or more  
\* --&gt; 0 or more  
? --&gt; 0 or 1 occurrences

**Options:**  
re.search\(pat,str,re.IGNORECASE\)  
IGNORECASE  
DOTALL --&gt; Allow dot to match newline  
MULTILINE --&gt; Allow ^ and $ to match in different lines

re.findall\("&lt;.\*&gt;", "&lt;b&gt;foo&lt;/b&gt;and&lt;i&gt;so on&lt;/i&gt;"\) = \['&lt;b&gt;foo&lt;/b&gt;and&lt;i&gt;so on&lt;/i&gt;'\]  
re.findall\("&lt;.\*?&gt;", "&lt;b&gt;foo&lt;/b&gt;and&lt;i&gt;so on&lt;/i&gt;"\) = \['&lt;b&gt;', '&lt;/b&gt;', '&lt;i&gt;', '&lt;/i&gt;'\]

IterTools  
**product**  
from **itertools** import product --&gt; Generates combinations between 1 or more lists, perhaps repeating values, cartesian product \(distributive property\)  
print list\(**product**\(\[1,2,3\],\[3,4\]\)\) = \[\(1, 3\), \(1, 4\), \(2, 3\), \(2, 4\), \(3, 3\), \(3, 4\)\]  
print list\(**product**\(\[1,2,3\],repeat = 2\)\) = \[\(1, 1\), \(1, 2\), \(1, 3\), \(2, 1\), \(2, 2\), \(2, 3\), \(3, 1\), \(3, 2\), \(3, 3\)\]

**permutations**  
from **itertools** import **permutations** --&gt; Generates combinations of all characters in every position  
print list\(permutations\(\['1','2','3'\]\)\) = \[\('1', '2', '3'\), \('1', '3', '2'\), \('2', '1', '3'\),... Every posible combination  
print\(list\(permutations\('123',2\)\)\) = \[\('1', '2'\), \('1', '3'\), \('2', '1'\), \('2', '3'\), \('3', '1'\), \('3', '2'\)\] Every posible combination of lenght 2

**combinations**  
from itertools import **combinations** --&gt; Generates all possible combinations without repeating characters \(if "ab" existing, doesn't generate "ba"\)  
print\(list\(**combinations**\('123',2\)\)\) --&gt; \[\('1', '2'\), \('1', '3'\), \('2', '3'\)\]

**combinations\_with\_replacement**  
from itertools import **combinations\_with\_replacement** --&gt; Generates all possible combinations from the char onwards\(for example, the 3rd is mixed from the 3rd onwards but not with the 2nd o first\)  
print\(list\(**combinations\_with\_replacement**\('1133',2\)\)\) = \[\('1', '1'\), \('1', '1'\), \('1', '3'\), \('1', '3'\), \('1', '1'\), \('1', '3'\), \('1', '3'\), \('3', '3'\), \('3', '3'\), \('3', '3'\)\]

### Decorators

Decorator that size the time that a function needs to be executed \(from [here](https://towardsdatascience.com/decorating-functions-in-python-619cbbe82c74)\):

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

If you run it, you will see something like the following:

```text
Let's call our decorated function
Decorated func!
Execution time: 4.792213439941406e-05 seconds
```

