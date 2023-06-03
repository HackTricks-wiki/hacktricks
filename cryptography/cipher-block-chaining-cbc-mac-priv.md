# CBC

Si la **cookie** es **sólo** el **nombre de usuario** (o la primera parte de la cookie es el nombre de usuario) y quieres hacerse pasar por el usuario "**admin**". Entonces, puedes crear el nombre de usuario **"bdmin"** y **bruteforce** el **primer byte** de la cookie.

# CBC-MAC

En criptografía, un **código de autenticación de mensajes de cifrado en cadena de bloques** (**CBC-MAC**) es una técnica para construir un código de autenticación de mensajes a partir de un cifrado de bloques. El mensaje se cifra con algún algoritmo de cifrado de bloques en modo CBC para crear una **cadena de bloques tal que cada bloque depende del cifrado adecuado del bloque anterior**. Esta interdependencia asegura que un **cambio** en **cualquier** de los **bits** del texto plano hará que el **último bloque cifrado** cambie de una manera que no se puede predecir o contrarrestar sin conocer la clave del cifrado de bloques.

Para calcular el CBC-MAC del mensaje m, se cifra m en modo CBC con un vector de inicialización cero y se guarda el último bloque. La siguiente figura esboza el cálculo del CBC-MAC de un mensaje que consta de bloques![m\_{1}\\|m\_{2}\\|\cdots \\|m\_{x}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) utilizando una clave secreta k y un cifrado de bloques E:

![CBC-MAC structure (en).svg](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# Vulnerabilidad

Con CBC-MAC, por lo general, el **IV utilizado es 0**.\
Esto es un problema porque 2 mensajes conocidos (`m1` y `m2`) generan independientemente 2 firmas (`s1` y `s2`). Así:

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

Entonces, un mensaje compuesto por m1 y m2 concatenados (m3) generará 2 firmas (s31 y s32):

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**Lo cual es posible de calcular sin conocer la clave del cifrado.**

Imagina que estás cifrando el nombre **Administrator** en bloques de **8 bytes**:

* `Administ`
* `rator\00\00\00`

Puedes crear un nombre de usuario llamado **Administ** (m1) y obtener la firma (s1).\
Luego, puedes crear un nombre de usuario llamado el resultado de `rator\00\00\00 XOR s1`. Esto generará `E(m2 XOR s1 XOR 0)` que es s32.\
Ahora, puedes usar s32 como la firma del nombre completo **Administrator**.

### Resumen

1. Obtén la firma del nombre de usuario **Administ** (m1) que es s1
2. Obtén la firma del nombre de usuario **rator\x00\x00\x00 XOR s1 XOR 0** que es s32**.**
3. Establece la cookie en s32 y será una cookie válida para el usuario **Administrator**.

# Ataque controlando el IV

Si puedes controlar el IV utilizado, el ataque podría ser muy fácil.\
Si la cookie es sólo el nombre de usuario cifrado, para hacerse pasar por el usuario "**administrator**" puedes crear el usuario "**Administrator**" y obtendrás su cookie.\
Ahora, si puedes controlar el IV, puedes cambiar el primer byte del IV para que **IV\[0] XOR "A" == IV'\[0] XOR "a"** y regenerar la cookie para el usuario **Administrator**. Esta cookie será válida para **hacerse pasar** por el usuario **administrator** con el IV inicial.

# Referencias

Más información en [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)
