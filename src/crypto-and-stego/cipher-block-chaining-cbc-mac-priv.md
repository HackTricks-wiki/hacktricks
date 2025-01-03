{{#include ../banners/hacktricks-training.md}}

# CBC

Si la **cookie** es **solo** el **nombre de usuario** (o la primera parte de la cookie es el nombre de usuario) y deseas suplantar el nombre de usuario "**admin**". Entonces, puedes crear el nombre de usuario **"bdmin"** y **bruteforce** el **primer byte** de la cookie.

# CBC-MAC

**Código de autenticación de mensaje de encadenamiento de bloques cifrados** (**CBC-MAC**) es un método utilizado en criptografía. Funciona tomando un mensaje y cifrándolo bloque por bloque, donde el cifrado de cada bloque está vinculado al anterior. Este proceso crea una **cadena de bloques**, asegurando que cambiar incluso un solo bit del mensaje original conducirá a un cambio impredecible en el último bloque de datos cifrados. Para hacer o revertir tal cambio, se requiere la clave de cifrado, asegurando la seguridad.

Para calcular el CBC-MAC del mensaje m, se cifra m en modo CBC con un vector de inicialización cero y se conserva el último bloque. La siguiente figura esboza el cálculo del CBC-MAC de un mensaje que comprende bloques![https://wikimedia.org/api/rest_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) utilizando una clave secreta k y un cifrador de bloques E:

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC_structure_(en).svg/570px-CBC-MAC_structure_(en).svg.png](<https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC_structure_(en).svg/570px-CBC-MAC_structure_(en).svg.png>)

# Vulnerabilidad

Con CBC-MAC, generalmente el **IV utilizado es 0**.\
Este es un problema porque 2 mensajes conocidos (`m1` y `m2`) generarán independientemente 2 firmas (`s1` y `s2`). Así que:

- `E(m1 XOR 0) = s1`
- `E(m2 XOR 0) = s2`

Entonces, un mensaje compuesto por m1 y m2 concatenados (m3) generará 2 firmas (s31 y s32):

- `E(m1 XOR 0) = s31 = s1`
- `E(m2 XOR s1) = s32`

**Lo cual es posible calcular sin conocer la clave del cifrado.**

Imagina que estás cifrando el nombre **Administrator** en bloques de **8bytes**:

- `Administ`
- `rator\00\00\00`

Puedes crear un nombre de usuario llamado **Administ** (m1) y recuperar la firma (s1).\
Luego, puedes crear un nombre de usuario llamado el resultado de `rator\00\00\00 XOR s1`. Esto generará `E(m2 XOR s1 XOR 0)` que es s32.\
Ahora, puedes usar s32 como la firma del nombre completo **Administrator**.

### Resumen

1. Obtén la firma del nombre de usuario **Administ** (m1) que es s1
2. Obtén la firma del nombre de usuario **rator\x00\x00\x00 XOR s1 XOR 0** que es s32**.**
3. Establece la cookie a s32 y será una cookie válida para el usuario **Administrator**.

# Ataque Controlando IV

Si puedes controlar el IV utilizado, el ataque podría ser muy fácil.\
Si la cookie es solo el nombre de usuario cifrado, para suplantar al usuario "**administrator**" puedes crear el usuario "**Administrator**" y obtendrás su cookie.\
Ahora, si puedes controlar el IV, puedes cambiar el primer byte del IV de modo que **IV\[0] XOR "A" == IV'\[0] XOR "a"** y regenerar la cookie para el usuario **Administrator.** Esta cookie será válida para **suplantar** al usuario **administrator** con el **IV** inicial.

## Referencias

Más información en [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)

{{#include ../banners/hacktricks-training.md}}
