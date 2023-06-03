# Resumen del ataque

Imagina un servidor que está **firmando** algunos **datos** mediante la **concatenación** de un **secreto** a algunos datos de texto claro conocidos y luego hasheando esos datos. Si conoces:

* **La longitud del secreto** (esto también se puede obtener por fuerza bruta desde un rango de longitud dado)
* **Los datos de texto claro**
* **El algoritmo (y es vulnerable a este ataque)**
* **El relleno es conocido**
  * Por lo general, se utiliza uno predeterminado, por lo que si se cumplen los otros 3 requisitos, esto también lo es
  * El relleno varía según la longitud del secreto+datos, por lo que se necesita la longitud del secreto

Entonces, es posible para un **atacante** **agregar** **datos** y **generar** una **firma** válida para los **datos previos + datos agregados**.

## ¿Cómo?

Básicamente, los algoritmos vulnerables generan los hashes mediante la **hashing** de un **bloque de datos**, y luego, **a partir** del **hash creado previamente** (estado), **añaden el siguiente bloque de datos** y lo **hashean**.

Entonces, imagina que el secreto es "secreto" y los datos son "datos", el MD5 de "secretodata" es 6036708eba0d11f6ef52ad44e8b74d5b.\
Si un atacante quiere agregar la cadena "agregar" puede:

* Generar un MD5 de 64 "A"s
* Cambiar el estado del hash inicializado previamente a 6036708eba0d11f6ef52ad44e8b74d5b
* Agregar la cadena "agregar"
* Finalizar el hash y el hash resultante será un **válido para "secreto" + "datos" + "relleno" + "agregar"**

## **Herramienta**

{% embed url="https://github.com/iagox86/hash_extender" %}

# Referencias

Puedes encontrar este ataque bien explicado en [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
