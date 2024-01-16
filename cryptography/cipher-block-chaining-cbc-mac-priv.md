<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# CBC

Si la **cookie** es **solo** el **nombre de usuario** (o la primera parte de la cookie es el nombre de usuario) y quieres suplantar al usuario "**admin**". Entonces, puedes crear el nombre de usuario **"bdmin"** y **fuerza bruta** el **primer byte** de la cookie.

# CBC-MAC

En criptografía, un **código de autenticación de mensajes en modo de encadenamiento de bloques de cifrado** (**CBC-MAC**) es una técnica para construir un código de autenticación de mensajes a partir de un cifrado de bloque. El mensaje se cifra con algún algoritmo de cifrado de bloque en modo CBC para crear una **cadena de bloques de tal manera que cada bloque dependa de la correcta encriptación del bloque anterior**. Esta interdependencia asegura que un **cambio** en **cualquier** bit del texto plano provocará que el **bloque cifrado final** cambie de una manera que no se puede predecir o contrarrestar sin conocer la clave del cifrado de bloque.

Para calcular el CBC-MAC de un mensaje m, se cifra m en modo CBC con un vector de inicialización cero y se mantiene el último bloque. La siguiente figura esquematiza el cálculo del CBC-MAC de un mensaje compuesto por bloques![m\_{1}\\|m\_{2}\\|\cdots \\|m\_{x}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) utilizando una clave secreta k y un cifrado de bloque E:

![Estructura de CBC-MAC (en).svg](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# Vulnerabilidad

Con CBC-MAC usualmente el **IV utilizado es 0**.\
Esto es un problema porque 2 mensajes conocidos (`m1` y `m2`) independientemente generarán 2 firmas (`s1` y `s2`). Entonces:

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

Luego, un mensaje compuesto por m1 y m2 concatenados (m3) generará 2 firmas (s31 y s32):

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**Lo cual es posible calcular sin conocer la clave de la encriptación.**

Imagina que estás cifrando el nombre **Administrator** en bloques de **8bytes**:

* `Administ`
* `rator\00\00\00`

Puedes crear un nombre de usuario llamado **Administ** (m1) y obtener la firma (s1).\
Luego, puedes crear un nombre de usuario llamado el resultado de `rator\00\00\00 XOR s1`. Esto generará `E(m2 XOR s1 XOR 0)` que es s32.\
Ahora, puedes usar s32 como la firma del nombre completo **Administrator**.

### Resumen

1. Obtén la firma del nombre de usuario **Administ** (m1) que es s1
2. Obtén la firma del nombre de usuario **rator\x00\x00\x00 XOR s1 XOR 0** que es s32**.**
3. Establece la cookie a s32 y será una cookie válida para el usuario **Administrator**.

# Ataque Controlando IV

Si puedes controlar el IV utilizado, el ataque podría ser muy fácil.\
Si la cookie es solo el nombre de usuario cifrado, para suplantar al usuario "**administrator**" puedes crear el usuario "**Administrator**" y obtendrás su cookie.\
Ahora, si puedes controlar el IV, puedes cambiar el primer Byte del IV para que **IV\[0] XOR "A" == IV'\[0] XOR "a"** y regenerar la cookie para el usuario **Administrator.** Esta cookie será válida para **suplantar** al usuario **administrator** con el **IV** inicial.

# Referencias

Más información en [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
