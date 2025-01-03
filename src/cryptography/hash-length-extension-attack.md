{{#include ../banners/hacktricks-training.md}}

# Resumen del ataque

Imagina un servidor que está **firmando** algunos **datos** al **agregar** un **secreto** a algunos datos de texto claro conocidos y luego hasheando esos datos. Si sabes:

- **La longitud del secreto** (esto también se puede forzar mediante fuerza bruta desde un rango de longitud dado)
- **Los datos de texto claro**
- **El algoritmo (y es vulnerable a este ataque)**
- **El padding es conocido**
- Generalmente se usa uno por defecto, así que si se cumplen los otros 3 requisitos, este también lo es
- El padding varía dependiendo de la longitud del secreto+datos, por eso se necesita la longitud del secreto

Entonces, es posible que un **atacante** **agregue** **datos** y **genere** una **firma** válida para los **datos anteriores + datos agregados**.

## ¿Cómo?

Básicamente, los algoritmos vulnerables generan los hashes primero **hasheando un bloque de datos**, y luego, **desde** el **hash** (estado) **creado previamente**, **agregan el siguiente bloque de datos** y **lo hashean**.

Entonces, imagina que el secreto es "secreto" y los datos son "datos", el MD5 de "secretodata" es 6036708eba0d11f6ef52ad44e8b74d5b.\
Si un atacante quiere agregar la cadena "agregar", puede:

- Generar un MD5 de 64 "A"s
- Cambiar el estado del hash inicializado previamente a 6036708eba0d11f6ef52ad44e8b74d5b
- Agregar la cadena "agregar"
- Terminar el hash y el hash resultante será un **válido para "secreto" + "datos" + "padding" + "agregar"**

## **Herramienta**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Referencias

Puedes encontrar este ataque bien explicado en [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../banners/hacktricks-training.md}}
