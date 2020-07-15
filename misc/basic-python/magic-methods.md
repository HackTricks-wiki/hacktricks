# Magic Methods

## Class Methods

You can access the **methods** of a **class** using **\_\_dict\_\_.**

![](../../.gitbook/assets/image%20%28275%29.png)

You can access the functions 

![](../../.gitbook/assets/image%20%28285%29.png)

## Object class

### **Attributes**

You can access the **attributes of an object** using **\_\_dict\_\_**. Example:

![](../../.gitbook/assets/image%20%28146%29.png)

### Class

You can access the **class** of an object using **\_\_class\_\_**

![](../../.gitbook/assets/image%20%28221%29.png)

You can access the **methods** of the **class** of an **object chainning** magic functions:

![](../../.gitbook/assets/image%20%28114%29.png)

## Server Side Template Injection

Interesting functions to exploit this vulnerability 

```text
__init__.__globals__
__class__.__init__.__globals__
```

Inside the response search for the application \(probably at the end?\)

Then **access the environment content** of the application where you will hopefully find **some passwords** of interesting information:

```text
__init__.__globals__[<name>].config
__init__.__globals__[<name>].__dict__
__init__.__globals__[<name>].__dict__.config
__class__.__init__.__globals__[<name>].config
__class__.__init__.__globals__[<name>].__dict__
__class__.__init__.__globals__[<name>].__dict__.config
```

## More Information

* [https://rushter.com/blog/python-class-internals/](https://rushter.com/blog/python-class-internals/)
* [https://docs.python.org/3/reference/datamodel.html](https://docs.python.org/3/reference/datamodel.html)
* [https://balsn.tw/ctf\_writeup/20190603-facebookctf/\#events](https://balsn.tw/ctf_writeup/20190603-facebookctf/#events)
* [https://medium.com/bugbountywriteup/solving-each-and-every-fb-ctf-challenge-part-1-4bce03e2ecb0](https://medium.com/bugbountywriteup/solving-each-and-every-fb-ctf-challenge-part-1-4bce03e2ecb0) \(events\)

